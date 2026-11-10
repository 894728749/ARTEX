package main

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/collab"
	"github.com/Autumn-27/norma/llm"
)

type branchCountingProvider struct{ calls atomic.Int32 }

func (p *branchCountingProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(y func(llm.StreamEvent, error) bool) {
		_ = y(llm.StreamEvent{Type: llm.SETextDelta, Text: "fake"}, nil)
		_ = y(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil)
	}
}
func (p *branchCountingProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.calls.Add(1)
	return llm.Message{Role: "assistant", Content: []llm.ContentBlock{{Type: llm.BlockText, Text: "fake"}}}, "end_turn", llm.Usage{}, nil
}

type branchPlannerScript struct {
	calls        atomic.Int32
	guidanceSeen atomic.Bool
}

func (p *branchPlannerScript) Stream(_ context.Context, r llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(y func(llm.StreamEvent, error) bool) {
		n := p.calls.Add(1)
		raw, _ := json.Marshal(r)
		if strings.Contains(string(raw), "guidance-fixture") {
			p.guidanceSeen.Store(true)
		}
		if n <= 2 {
			input := fmt.Sprintf(`{"unit":{"key":"unit-%d","question":"Inspect independent fixture %d","role":"worker","asset_ids":[],"material_hashes":[],"capabilities":[],"contract":{"budget_seconds":30,"acceptance":["fixture checked"]}}}`, n, n)
			for _, ev := range []llm.StreamEvent{{Type: llm.SEToolUseStart, ToolID: fmt.Sprintf("call-%d", n), ToolName: "propose_work"}, {Type: llm.SEToolInputJSON, Text: input}, {Type: llm.SEMessageDelta, StopReason: "tool_use"}} {
				if !y(ev, nil) {
					return
				}
			}
			return
		}
		_ = y(llm.StreamEvent{Type: llm.SETextDelta, Text: "two independent fixture units proposed"}, nil)
		_ = y(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil)
	}
}
func (p *branchPlannerScript) Complete(ctx context.Context, r llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	acc := llm.NewAccumulator()
	for ev, err := range p.Stream(ctx, r) {
		if err != nil {
			return llm.Message{}, "", llm.Usage{}, err
		}
		acc.Add(ev)
	}
	return acc.Message(), acc.StopReason, acc.Usage, nil
}

func TestBranchConfigOptInAndPlannerIsolation(t *testing.T) {
	c := localExecutionConfig{Roles: map[string]localRoleConfig{"worker": {Model: "m"}}, Models: map[string]localModelConfig{"m": {Endpoint: "http://127.0.0.1", APIKeyEnv: "KEY", Model: "m", Format: "openai"}}}
	if err := c.validateBranches(); err != nil {
		t.Fatalf("disabled config should remain valid: %v", err)
	}
	c.Branches.Enabled = true
	c.Roles["planner"] = localRoleConfig{Model: "m", Capabilities: []string{"shell"}}
	if err := c.validateBranches(); err == nil {
		t.Fatal("planner tool capability must be rejected")
	}
}

func TestBranchJournalBlocksUnfinishedOperation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "journal.ndjson")
	if err := appendBranchJournal(p, map[string]any{"kind": "operation_start", "op": collab.BranchOperation{ID: "one"}}); err != nil {
		t.Fatal(err)
	}
	if ok, err := branchHasUnresolved(p); err != nil || !ok {
		t.Fatalf("unfinished operation should block replay: unresolved=%v err=%v", ok, err)
	}
	if err := appendBranchJournal(p, map[string]any{"kind": "operation_end", "op": "one", "state": "complete"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := branchHasUnresolved(p); err != nil || ok {
		t.Fatalf("completed operation should be safe: unresolved=%v err=%v", ok, err)
	}
}

func TestBranchCommandWritesDurableOutboxBeforeAck(t *testing.T) {
	b := &collab.ExecutionBranch{ID: 4, TaskID: 2, Epoch: 3, Revision: 1, State: "running"}
	path := filepath.Join(t.TempDir(), "journal.ndjson")
	registerBranchJournal(b, path)
	var got collab.BranchCommand
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		_ = json.NewEncoder(w).Encode(collab.BranchReply{Branch: b})
	}))
	defer srv.Close()
	cmd := collab.BranchCommand{Type: "checkpoint", Text: "durable test"}
	if _, err := postBranch(context.Background(), srv.Client(), srv.URL, "token", b, cmd); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var pending, ack bool
	for _, line := range strings.Split(string(raw), "\n") {
		var x struct {
			Kind      string               `json:"kind"`
			RequestID string               `json:"request_id"`
			Command   collab.BranchCommand `json:"command"`
		}
		if json.Unmarshal([]byte(line), &x) == nil && x.RequestID == got.RequestID {
			if x.Kind == "command_pending" && x.Command.Type == "checkpoint" {
				pending = true
			}
			if x.Kind == "command_ack" {
				ack = true
			}
		}
	}
	if !pending || !ack || got.RequestID == "" {
		t.Fatalf("outbox pending=%v ack=%v request_id=%q", pending, ack, got.RequestID)
	}
}

func TestBranchScopedInputsAndReviewerRequirement(t *testing.T) {
	assets := []collab.BranchAsset{{ID: "a", Target: "https://fixture.test"}}
	if err := validateScopeInput(json.RawMessage(`{"target":"https://fixture.test"}`), []string{"target"}, assets); err != nil {
		t.Fatal(err)
	}
	if err := validateScopeInput(json.RawMessage(`{"target":"https://outside.test"}`), []string{"target"}, assets); err == nil {
		t.Fatal("out-of-scope target accepted")
	}
	b := &collab.ExecutionBranch{Units: []collab.BranchUnit{{Spec: collab.BranchUnitSpec{Role: "worker"}, State: "complete"}}}
	if branchHasReviewerResult(b) {
		t.Fatal("worker result must not satisfy reviewer requirement")
	}
	b.Units[0].ID = 1
	b.Units = append(b.Units, collab.BranchUnit{ID: 2, Spec: collab.BranchUnitSpec{Role: "reviewer", DependsOn: []int64{1}}, State: "candidate", Result: &collab.ExecutionResult{Outcome: "candidate"}})
	if !branchHasReviewerResult(b) {
		t.Fatal("completed reviewer result should permit submit")
	}
}

func TestBranchProviderStartAuthorizationPrecedesFakeModel(t *testing.T) {
	var starts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { starts.Add(1); w.WriteHeader(http.StatusConflict) }))
	defer srv.Close()
	inner := &branchCountingProvider{}
	p := &branchMeteredProvider{inner: inner, ctx: context.Background(), origin: srv.URL, client: srv.Client(), branch: &collab.ExecutionBranch{ID: 2, TaskID: 1, Epoch: 3}, role: "planner", journal: filepath.Join(t.TempDir(), "journal.ndjson")}
	_, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{})
	if err == nil {
		t.Fatal("server budget denial must stop model call")
	}
	if inner.calls.Load() != 0 {
		t.Fatal("model ran before server authorization")
	}
	if starts.Load() != 1 {
		t.Fatalf("got %d authorization calls", starts.Load())
	}
}

func TestBranchProviderUsesOneOperationAndDurableJournal(t *testing.T) {
	var starts, ends atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var c collab.BranchCommand
		if json.NewDecoder(r.Body).Decode(&c) != nil {
			t.Fatal("bad command")
		}
		switch c.Type {
		case "start":
			starts.Add(1)
		case "end":
			ends.Add(1)
		}
		_ = json.NewEncoder(w).Encode(collab.BranchReply{Branch: &collab.ExecutionBranch{ID: 2, TaskID: 1, Epoch: 3}})
	}))
	defer srv.Close()
	inner := &branchCountingProvider{}
	path := filepath.Join(t.TempDir(), "journal.ndjson")
	p := &branchMeteredProvider{inner: inner, ctx: context.Background(), origin: srv.URL, client: srv.Client(), branch: &collab.ExecutionBranch{ID: 2, TaskID: 1, Epoch: 3}, role: "worker", journal: path}
	if _, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{}); err != nil {
		t.Fatal(err)
	}
	if starts.Load() != 1 || ends.Load() != 1 || inner.calls.Load() != 1 {
		t.Fatalf("start/end/model calls: %d/%d/%d", starts.Load(), ends.Load(), inner.calls.Load())
	}
	if unresolved, err := branchHasUnresolved(path); err != nil || unresolved {
		t.Fatalf("journal should be complete: %v %v", unresolved, err)
	}
}

func TestBranchRedaction(t *testing.T) {
	t.Setenv("BRANCH_TEST_SECRET", "secret-value")
	got := redactBranchText(localExecutionConfig{Branches: localBranchConfig{EnvSecretNames: []string{"BRANCH_TEST_SECRET"}, RedactStrings: []string{"literal-secret"}}}, "secret-value literal-secret")
	if got != "[redacted] [redacted]" {
		t.Fatalf("unexpected redaction %q", got)
	}
}

func TestBranchStrictFinalAndGuidanceGate(t *testing.T) {
	if outcome, summary, err := parseBranchUnitFinal(`{"outcome":"candidate","summary":"verified fixture"}`); err != nil || outcome != "candidate" || summary != "verified fixture" {
		t.Fatalf("valid final rejected: %q %q %v", outcome, summary, err)
	}
	for _, raw := range []string{"plain text", `{"outcome":"candidate","summary":"ok"} extra`, `{"outcome":"candidate"}`, `{"outcome":"unknown","summary":"ok"}`} {
		if _, _, err := parseBranchUnitFinal(raw); err == nil {
			t.Fatalf("invalid final accepted: %s", raw)
		}
	}
	b := &collab.ExecutionBranch{Guidance: []collab.BranchGuidance{{ID: 1, Status: "queued"}}}
	if !branchHasQueuedGuidance(b) {
		t.Fatal("queued guidance did not fence next operation")
	}
	b.Guidance[0].Status = "discussion"
	if branchHasQueuedGuidance(b) {
		t.Fatal("discussion was treated as guidance")
	}
}

func TestBranchPlannerProposesTwoUnitsAndAppliesGuidance(t *testing.T) {
	branch := &collab.ExecutionBranch{ID: 7, TaskID: 3, Epoch: 2, Revision: 1, State: "running", Spec: collab.BranchWorkSpec{Kind: "pentest", Roles: []string{"worker", "reviewer"}}}
	policy := collab.BranchPolicy{Version: 1, Goal: "inspect fixture", Budget: 20, MaxToolSeconds: 60, PlannerPrompts: map[string]string{"pentest": "fixture planner"}, Roles: map[string]collab.ExecutionConfig{"worker": {Version: 1, Kind: "pentest", Role: "worker", MaxTurns: 5, BudgetSeconds: 60}, "reviewer": {Version: 1, Kind: "pentest", Role: "reviewer", MaxTurns: 5, BudgetSeconds: 60}}}
	branch.Guidance = []collab.BranchGuidance{{ID: 9, Text: "guidance-fixture: inspect edge case", Status: "queued", Epoch: 2}}
	var mu sync.Mutex
	var types []string
	var starts, ends atomic.Int32
	nextUnit := int64(10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var c collab.BranchCommand
		if json.NewDecoder(r.Body).Decode(&c) != nil {
			http.Error(w, "bad", 400)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		types = append(types, c.Type)
		receipt := collab.BranchReceipt{BranchID: branch.ID}
		switch c.Type {
		case "start":
			if c.Operation == nil {
				t.Errorf("start missing operation")
			}
			starts.Add(1)
		case "end":
			ends.Add(1)
		case "plan":
			nextUnit++
			branch.Units = append(branch.Units, collab.BranchUnit{ID: nextUnit, Spec: *c.Unit, State: "planned"})
			receipt.UnitID = nextUnit
		case "guidance_received":
			branch.Guidance[0].Status = "received"
		case "guidance_applied":
			branch.Guidance[0].Status = "applied"
		}
		branch.Revision++
		_ = json.NewEncoder(w).Encode(collab.BranchReply{Branch: branch, Policy: policy, Receipt: receipt})
	}))
	defer srv.Close()
	provider := &branchPlannerScript{}
	old := branchProviderFactory
	branchProviderFactory = func(localModelConfig, string) (llm.Provider, error) { return provider, nil }
	defer func() { branchProviderFactory = old }()
	work := t.TempDir()
	journal := filepath.Join(work, "journal.ndjson")
	cfg := localExecutionConfig{WorkDir: work, Roles: map[string]localRoleConfig{"planner": {Model: "m"}}, Models: map[string]localModelConfig{"m": {Model: "m", APIKeyEnv: "BRANCH_FAKE_KEY"}}}
	reply := collab.BranchReply{Branch: branch, Policy: policy}
	for i := 0; i < 3; i++ {
		if err := runBranchPlanner(context.Background(), cfg, srv.URL, "token", srv.Client(), reply, map[string]string{}, work, journal); err != nil {
			t.Fatal(err)
		}
	}
	if got := provider.calls.Load(); got != 3 {
		t.Fatalf("fake planner calls=%d, want 3", got)
	}
	if len(branch.Units) != 2 {
		t.Fatalf("planned units=%d, want 2 types=%v revision=%d", len(branch.Units), types, branch.Revision)
	}
	if !provider.guidanceSeen.Load() {
		t.Fatal("planner prompt did not include guidance snapshot")
	}
	if starts.Load() != 3 || ends.Load() != 3 {
		t.Fatalf("authorized operation starts/ends=%d/%d, want 3/3", starts.Load(), ends.Load())
	}
	if branch.Guidance[0].Status != "applied" {
		t.Fatalf("guidance status=%q", branch.Guidance[0].Status)
	}
}

func TestBranchRecoveryUploadsEvidenceAndDoesNotReplay(t *testing.T) {
	work := t.TempDir()
	b := &collab.ExecutionBranch{ID: 8, TaskID: 4, Epoch: 9, State: "running"}
	dir := filepath.Join(work, "branches", "4-8")
	if err := os.MkdirAll(filepath.Join(dir), 0700); err != nil {
		t.Fatal(err)
	}
	if err := appendBranchJournal(filepath.Join(dir, "journal.ndjson"), map[string]any{"kind": "operation_start", "op": collab.BranchOperation{ID: "unresolved", Kind: "tool", Role: "worker"}}); err != nil {
		t.Fatal(err)
	}
	e := collab.ExecutionEvidence{ID: "ev-001", Tool: "inspect", Content: "fixture evidence", SHA256: collab.ContentHash([]byte("fixture evidence"))}
	if err := appendBranchJournal(filepath.Join(dir, "unit-2-evidence.ndjson"), e); err != nil {
		t.Fatal(err)
	}
	var types []string
	var evidenceCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var c collab.BranchCommand
		if json.NewDecoder(r.Body).Decode(&c) != nil {
			http.Error(w, "bad", 400)
			return
		}
		types = append(types, c.Type)
		if c.Event != nil && c.Event.Evidence != nil {
			evidenceCount++
		}
		_ = json.NewEncoder(w).Encode(collab.BranchReply{Branch: b})
	}))
	defer srv.Close()
	cfg := localExecutionConfig{WorkDir: work}
	if err := processBranch(context.Background(), cfg, srv.URL, "token", srv.Client(), collab.BranchReply{Branch: b}); err != nil {
		t.Fatal(err)
	}
	if len(types) != 2 || types[0] != "event" || types[1] != "checkpoint" || evidenceCount != 1 {
		t.Fatalf("recovery commands=%v evidence=%d", types, evidenceCount)
	}
}

func TestBranchJournalRepairsTornTailAndFailsClosedOnInteriorDamage(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "journal.ndjson")
	valid := []byte("{\"kind\":\"unit_start\",\"unit\":1,\"epoch\":2}\n{\"kind\":")
	if err := os.WriteFile(p, valid, 0600); err != nil {
		t.Fatal(err)
	}
	if err := repairBranchJournal(p); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if string(got) != "{\"kind\":\"unit_start\",\"unit\":1,\"epoch\":2}\n" {
		t.Fatalf("repaired journal=%q", got)
	}
	backups, err := filepath.Glob(p + ".torn-*")
	if err != nil || len(backups) != 1 {
		t.Fatalf("private audit backup paths=%v err=%v", backups, err)
	}
	if err := os.WriteFile(p, []byte("{broken}\n{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := repairBranchJournal(p); err == nil {
		t.Fatal("interior corruption must fail closed")
	}
	if err := os.WriteFile(p, []byte("{\"kind\":\"observed\"}\n{broken}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := repairBranchJournal(p); err == nil {
		t.Fatal("newline-terminated malformed record must fail closed")
	}
}

func TestBranchJournalAddsTerminatorToValidTail(t *testing.T) {
	p := filepath.Join(t.TempDir(), "journal.ndjson")
	if err := os.WriteFile(p, []byte(`{"kind":"observed"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := repairBranchJournal(p); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "{\"kind\":\"observed\"}\n" {
		t.Fatalf("journal=%q", b)
	}
}

func TestBranchOldPlannerFenceCanReconcileAfterEpochConfirmation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "journal.ndjson")
	if err := appendBranchJournal(p, map[string]any{"kind": "planner_start", "snapshot": "old-snapshot", "epoch": 3}); err != nil {
		t.Fatal(err)
	}
	b := &collab.ExecutionBranch{Epoch: 4}
	if !branchOldOperationsConfirmed(p, b) {
		t.Fatal("epoch-confirmed old planner fence should be recoverable")
	}
	b.Operations = []collab.BranchOperation{{ID: "still-active", State: "uncertain"}}
	if branchOldOperationsConfirmed(p, b) {
		t.Fatal("old planner fence must not override server-side active operation")
	}
	b.Operations = nil
	if err := branchReconcileConfirmedJournal(p, b.Epoch); err != nil {
		t.Fatal(err)
	}
	if unresolved, err := branchHasUnresolved(p); err != nil || unresolved {
		t.Fatalf("planner fence unresolved=%v err=%v", unresolved, err)
	}
}

func TestBranchOutboxObservesAcceptedUnitResultWithoutReexecution(t *testing.T) {
	p := filepath.Join(t.TempDir(), "journal.ndjson")
	result := &collab.ExecutionResult{Version: 1, Outcome: "candidate", Summary: "accepted", Role: "worker", Model: "fixture"}
	b := &collab.ExecutionBranch{ID: 3, TaskID: 2, Epoch: 4, Units: []collab.BranchUnit{{ID: 7, State: "candidate", Result: result}}}
	registerBranchJournal(b, p)
	if err := appendBranchJournal(p, map[string]any{"kind": "unit_start", "unit": 7, "epoch": 4}); err != nil {
		t.Fatal(err)
	}
	op := collab.BranchOperation{ID: "op-1"}
	if err := appendBranchJournal(p, map[string]any{"kind": "operation_start", "op": op}); err != nil {
		t.Fatal(err)
	}
	if err := appendBranchJournal(p, map[string]any{"kind": "operation_end", "op": "op-1", "state": "complete"}); err != nil {
		t.Fatal(err)
	}
	c := collab.BranchCommand{Type: "unit_result", BranchID: 3, Epoch: 4, UnitID: 7, Result: result}
	if err := appendBranchJournal(p, map[string]any{"kind": "command_pending", "request_id": "accepted-result", "epoch": 4, "command": c}); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "must not replay accepted result", 500)
	}))
	defer srv.Close()
	if _, err := replayBranchOutbox(context.Background(), srv.Client(), srv.URL, "token", b, p); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatal("accepted unit_result was replayed")
	}
	if unresolved, err := branchHasUnresolved(p); err != nil || unresolved {
		t.Fatalf("reconciled journal unresolved=%v err=%v", unresolved, err)
	}
	if err := branchJournalHasFinishedUnit(p, 7); err != nil {
		t.Fatal(err)
	}
}

func TestBranchOutboxRefusesMismatchedAcceptedUnitResult(t *testing.T) {
	p := filepath.Join(t.TempDir(), "journal.ndjson")
	local := &collab.ExecutionResult{Version: 1, Outcome: "candidate", Summary: "local", Role: "worker", Model: "m"}
	serverResult := &collab.ExecutionResult{Version: 1, Outcome: "candidate", Summary: "server", Role: "worker", Model: "m"}
	b := &collab.ExecutionBranch{ID: 3, TaskID: 2, Epoch: 4, Units: []collab.BranchUnit{{ID: 7, State: "candidate", Result: serverResult}}}
	c := collab.BranchCommand{Type: "unit_result", BranchID: 3, Epoch: 4, UnitID: 7, Result: local}
	if err := appendBranchJournal(p, map[string]any{"kind": "command_pending", "request_id": "mismatch", "epoch": 4, "command": c}); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) }))
	defer srv.Close()
	if _, err := replayBranchOutbox(context.Background(), srv.Client(), srv.URL, "token", b, p); err == nil {
		t.Fatal("mismatched accepted result should fail closed")
	}
	if requests.Load() != 0 {
		t.Fatal("mismatched unit_result was automatically replayed")
	}
}

func TestBranchRejectedCommandIsNotReplayed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "journal.ndjson")
	b := &collab.ExecutionBranch{ID: 3, TaskID: 2, Epoch: 4}
	registerBranchJournal(b, p)
	c := collab.BranchCommand{Type: "checkpoint", BranchID: 3, Epoch: 4, RequestID: "permanent-reject"}
	if err := appendBranchJournal(p, map[string]any{"kind": "command_pending", "request_id": c.RequestID, "epoch": 4, "command": c}); err != nil {
		t.Fatal(err)
	}
	if err := appendBranchJournal(p, map[string]any{"kind": "command_rejected", "request_id": c.RequestID, "epoch": 4, "status": 400}); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) }))
	defer srv.Close()
	if _, err := replayBranchOutbox(context.Background(), srv.Client(), srv.URL, "token", b, p); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatal("permanently rejected command was replayed")
	}
}

func TestBranchPermanentHTTPRejectionDuringOutboxReplayIsNotRetried(t *testing.T) {
	p := filepath.Join(t.TempDir(), "journal.ndjson")
	b := &collab.ExecutionBranch{ID: 3, TaskID: 2, Epoch: 4}
	registerBranchJournal(b, p)
	c := collab.BranchCommand{Type: "checkpoint", BranchID: 3, Epoch: 4, RequestID: "replay-403", Text: "unobserved checkpoint"}
	if err := appendBranchJournal(p, map[string]any{"kind": "command_pending", "request_id": c.RequestID, "epoch": 4, "command": c}); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "invalid command", http.StatusForbidden)
	}))
	defer srv.Close()
	for i := 0; i < 2; i++ {
		if _, err := replayBranchOutbox(context.Background(), srv.Client(), srv.URL, "token", b, p); err != nil {
			t.Fatal(err)
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("HTTP requests=%d, 403 pending command should be attempted once", requests.Load())
	}
}

func branchJournalHasFinishedUnit(path string, unit int64) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(b), "\n") {
		var r struct {
			Kind string `json:"kind"`
			Unit int64  `json:"unit"`
		}
		_ = json.Unmarshal([]byte(line), &r)
		if r.Kind == "unit_finished" && r.Unit == unit {
			return nil
		}
	}
	return fmt.Errorf("missing unit_finished for %d", unit)
}

func TestBranchAcceptedResultClosesFenceAcrossAckCrashWindows(t *testing.T) {
	for _, alreadyAcked := range []bool{false, true} {
		t.Run(fmt.Sprint(alreadyAcked), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "journal.ndjson")
			result := &collab.ExecutionResult{Version: 1, Role: "worker", Outcome: "candidate", Summary: "fixture"}
			b := &collab.ExecutionBranch{ID: 3, TaskID: 2, Epoch: 4, Units: []collab.BranchUnit{{ID: 7, State: "running"}}}
			c := collab.BranchCommand{Type: "unit_result", BranchID: 3, Epoch: 4, UnitID: 7, RequestID: "result-ack", Result: result}
			for _, row := range []any{
				map[string]any{"kind": "unit_start", "unit": 7, "epoch": 4},
				map[string]any{"kind": "command_pending", "request_id": c.RequestID, "command": c},
			} {
				if err := appendBranchJournal(path, row); err != nil {
					t.Fatal(err)
				}
			}
			if alreadyAcked {
				b.Units[0].Result = result
				b.Units[0].State = "candidate"
				if err := appendBranchJournal(path, map[string]any{"kind": "command_ack", "request_id": c.RequestID}); err != nil {
					t.Fatal(err)
				}
			}
			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				accepted := *b
				accepted.Units = []collab.BranchUnit{{ID: 7, State: "candidate", Result: result}}
				_ = json.NewEncoder(w).Encode(collab.BranchReply{Branch: &accepted})
			}))
			defer srv.Close()
			if _, err := replayBranchOutbox(context.Background(), srv.Client(), srv.URL, "fixture-token", b, path); err != nil {
				t.Fatal(err)
			}
			if unresolved, err := branchHasUnresolved(path); err != nil || unresolved {
				t.Fatalf("unresolved=%v err=%v", unresolved, err)
			}
			want := int32(1)
			if alreadyAcked {
				want = 0
			}
			if requests.Load() != want {
				t.Fatalf("requests=%d want=%d", requests.Load(), want)
			}
		})
	}
}
