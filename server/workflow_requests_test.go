package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

func workflowFixture(t *testing.T) (*Server, *Task, *Task) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	// The package's integration fixtures share a database. Keep only this test's
	// tasks in its Manager so other tests' retained tasks do not consume slots.
	m.mu.Lock()
	m.tasks = map[string]*Task{}
	m.active = ""
	m.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := New(ctx, m, t.TempDir(), m.dir, t.TempDir())
	m.mu.Lock()
	m.tasks = map[string]*Task{}
	m.active = ""
	m.mu.Unlock()
	p, err := m.CreateTaskWithOptions("owned workflow fixture", "check frame", db.TaskCreateOptions{Kind: "pentest"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := m.CreateTaskWithOptions("owned workflow fixture", "explain frame", db.TaskCreateOptions{Kind: "reverse"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, task := range []*Task{p, r} {
			id, _ := parseTaskID(task.ID)
			_ = m.pg.DeleteTask(id)
		}
		m.Close()
		agent.ToolResolve = nil
		agent.ToolAugment = nil
		agent.PromptOverride = nil
	})
	return s, p, r
}

func addWorkflowFact(t *testing.T, task *Task) db.EvidenceReference {
	t.Helper()
	id, err := task.Store.AddNode(db.KindFact, map[string]any{"summary": "local behavior observed", "evidence": "owned fixture request/response", "confidence": "observed"}, 5, "confirmed", "fixture", nil)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := task.Store.GetNode(id)
	return db.EvidenceReference{NodeID: id, Version: db.NodeEvidenceVersion(n)}
}

func TestWorkflowRequestRoundTripNarrowInputsAndIdempotency(t *testing.T) {
	s, p, r := workflowFixture(t)
	ctx := context.Background()
	dir := filepath.Join(s.m.dir, "tasks", p.ID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "client.js"), []byte("export const frame = s => 'demo:' + s.trim()"), 0600); err != nil {
		t.Fatal(err)
	}
	in := workflowHelpInput{RequestKey: "client-frame", TargetTaskID: mustTaskID(t, r.ID), Question: "explain selected client frame", Acceptance: []string{"cite local expression"}, Files: []string{"client.js"}, Evidence: []db.EvidenceReference{addWorkflowFact(t, p)}, BudgetSeconds: 120}
	request, err := s.requestWorkflowHelp(ctx, p, in)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := s.requestWorkflowHelp(ctx, p, in)
	if err != nil || repeated.ID != request.ID {
		t.Fatalf("duplicate: %+v %v", repeated, err)
	}
	if request.SourceIntentID == nil || request.TargetIntentID == nil {
		t.Fatalf("missing linked work: %+v", request)
	}
	wait, _ := p.Store.GetNode(*request.SourceIntentID)
	if wait.State != "waiting" {
		t.Fatal(wait.State)
	}
	claimed, err := p.Store.ClaimNextIntent(ctx, "fixture")
	if err != nil || claimed != nil {
		t.Fatalf("waiting request consumed worker: %v %v", claimed, err)
	}
	target, _ := r.Store.GetNode(*request.TargetIntentID)
	var versioned struct {
		Version int `json:"contract_version"`
	}
	_ = json.Unmarshal(target.Payload, &versioned)
	if versioned.Version != 1 {
		t.Fatal("delegated work bypasses evidence settlement")
	}
	c, _ := db.IntentContract(target)
	if c.ExecutionRole != "reverse_static" || c.WorkflowRequestID != request.ID {
		t.Fatalf("wrong role/ownership: %+v", c)
	}
	dependent, err := r.Store.AddWorkIntent(ctx, "review delegated input", 5, nil, nil, db.WorkContract{ExecutionRole: "reverse_reviewer", DependsOn: []int64{target.ID}, BudgetSeconds: 999})
	if err != nil {
		t.Fatal(err)
	}
	dep, _ := r.Store.GetNode(dependent)
	dc, _ := db.IntentContract(dep)
	if dc.WorkflowRequestID != request.ID || dc.BudgetSeconds > 120 {
		t.Fatalf("follow-up lost request ownership/budget: %+v", dc)
	}
	var relations int
	if err = s.m.pg.QueryRow(`SELECT count(*) FROM task_relations WHERE task_id=$1 OR task_id=$2`, mustTaskID(t, p.ID), mustTaskID(t, r.ID)).Scan(&relations); err != nil || relations != 0 {
		t.Fatalf("whole task context leaked: %d %v", relations, err)
	}
	artifacts, _ := s.m.pg.ListReverseArtifacts(mustTaskID(t, r.ID))
	if len(artifacts) != 1 || artifacts[0].SHA256 == "" {
		t.Fatalf("material copy missing: %v", artifacts)
	}
	if policy, err := s.m.pg.ReverseRuntimePolicy(mustTaskID(t, r.ID)); err != nil || policy.Enabled {
		t.Fatalf("runtime permission inherited: %+v %v", policy, err)
	}
	in.Files = []string{"../foreign.js"}
	in.RequestKey = "escape"
	if _, err = s.requestWorkflowHelp(ctx, p, in); err == nil {
		t.Fatal("path escaped source task")
	}
	in.Files = []string{"client.js"}
	in.Evidence = []db.EvidenceReference{addWorkflowFact(t, r)}
	if _, err = s.requestWorkflowHelp(ctx, p, in); err == nil {
		t.Fatal("foreign evidence escaped source task")
	}
	result := addWorkflowFact(t, r)
	if err = s.returnWorkflowResult(ctx, r, request.ID, "accepted", "guessed answer", "", []db.EvidenceReference{result}); err == nil {
		t.Fatal("unreviewed reverse accepted")
	}
	if err = s.returnWorkflowResult(ctx, r, request.ID, "unresolved", "material analyzed; key branch remains unknown", "requires additional evidence", []db.EvidenceReference{result}); err != nil {
		t.Fatal(err)
	}
	wait, _ = p.Store.GetNode(*request.SourceIntentID)
	if wait.State != "done" {
		t.Fatalf("parent not released: %s", wait.State)
	}
	request, _ = s.m.pg.GetWorkflowRequest(ctx, request.ID)
	if request.Status != "completed" {
		t.Fatal(request.Status)
	}
	if err = s.settleWorkflowRequest(ctx, request); err != nil {
		t.Fatal(err)
	}
	var facts int
	s.m.pg.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1 AND origin='workflow' AND kind='fact'`, p.Store.ID()).Scan(&facts)
	if facts != 1 {
		t.Fatalf("duplicate returned fact: %d", facts)
	}
	nodes, _ := p.Store.ListByKind(db.KindFact, 100)
	for _, n := range nodes {
		if n.Origin == "workflow" && !strings.Contains(string(n.Payload), `"inferred"`) {
			t.Fatal("return silently proved parent claim")
		}
	}
}

func TestWorkflowRequestReverseToPentestAndOwnedCancellation(t *testing.T) {
	s, p, r := workflowFixture(t)
	ctx := context.Background()
	request, err := s.requestWorkflowHelp(ctx, r, workflowHelpInput{RequestKey: "server-behavior", TargetTaskID: mustTaskID(t, p.ID), Question: "confirm actual local response", BudgetSeconds: 120})
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := p.Store.AddWorkIntent(ctx, "unrelated owned work", 5, nil, nil, db.WorkContract{Hypothesis: "unrelated", Acceptance: []string{"save observation"}})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.cancelWorkflowRequest(ctx, p, request.ID); err == nil {
		t.Fatal("recipient cancelled source request")
	}
	if err = s.cancelWorkflowRequest(ctx, r, request.ID); err != nil {
		t.Fatal(err)
	}
	owned, _ := p.Store.GetNode(*request.TargetIntentID)
	other, _ := p.Store.GetNode(unrelated)
	if owned.State != "stopped" || other.State != "open" {
		t.Fatalf("cancellation leaked: own=%s unrelated=%s", owned.State, other.State)
	}
	if _, err = s.requestWorkflowHelp(ctx, r, workflowHelpInput{RequestKey: "no-scope", Question: "test extracted address", BudgetSeconds: 120}); err == nil {
		t.Fatal("reverse expanded network authorization")
	}
	second, err := s.requestWorkflowHelp(ctx, r, workflowHelpInput{RequestKey: "real-response", TargetTaskID: mustTaskID(t, p.ID), Question: "confirm actual response", BudgetSeconds: 120})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.returnWorkflowResult(ctx, p, second.ID, "accepted", "owned fixture returned expected response", "applies only to the tested input", []db.EvidenceReference{addWorkflowFact(t, p)}); err != nil {
		t.Fatal(err)
	}
}

func TestReverseRolesConfigurationsAndToolBindingsAreIndependent(t *testing.T) {
	s, p, r := workflowFixture(t)
	normal, _ := s.m.pg.GetTool("record_fact")
	if normal == nil {
		t.Fatal("normal tools not seeded")
	}
	old := *normal
	t.Cleanup(func() { _ = s.m.pg.UpdateTool(old.Key, old.Description, old.Schema, mustJSON(old.Agents), old.Enabled) })
	if err := s.m.pg.UpdateTool(normal.Key, "pentest-only-description", normal.Schema, mustJSON(normal.Agents), false); err != nil {
		t.Fatal(err)
	}
	base := agent.NewToolSet(nil, "").WorkerTools()
	reverse := names(agent.ToolResolve(context.Background(), "reverse_static", base))
	pentest := names(agent.ToolResolve(context.Background(), "worker", base))
	if reverse["record_fact"] == nil || reverse["record_fact"].Description() == "pentest-only-description" || pentest["record_fact"] != nil {
		t.Fatal("tool configurations are coupled")
	}
	if _, err := r.Store.AddWorkIntent(context.Background(), "dynamic question", 5, nil, nil, db.WorkContract{ExecutionRole: "worker"}); err == nil {
		t.Fatal("reverse accepted pentest worker role")
	}
	if _, err := p.Store.AddWorkIntent(context.Background(), "static question", 5, nil, nil, db.WorkContract{ExecutionRole: "reverse_static"}); err == nil {
		t.Fatal("pentest accepted reverse role")
	}
	for _, key := range []string{"reverse_static", "reverse_dynamic", "reverse_reviewer"} {
		info := agent.RunInfo{TaskID: mustTaskID(t, r.ID), ExplorationID: r.Store.ID(), IntentID: 100}
		ctx := agent.WithWorkflow(agent.WithRunInfo(context.Background(), info), "reverse")
		tools, _, cleanup := agent.AugmentTools(ctx, key, append(base, actool.DefaultTools()...))
		cleanup()
		got := names(tools)
		if got["Bash"] != nil || got["report_finding"] != nil {
			t.Fatal("pentest tools leaked")
		}
		if (got["reverse_review_conclusion"] != nil) != (key == "reverse_reviewer") {
			t.Fatalf("wrong review boundary %s", key)
		}
		if (got["reverse_submit_conclusion"] != nil) != (key != "reverse_reviewer") {
			t.Fatalf("wrong submit boundary %s", key)
		}
		if key == "reverse_static" && got["reverse_observe_runtime"] != nil {
			t.Fatal("static has runtime execution")
		}
	}
	for _, key := range agent.BuiltinReverseAgentKeys {
		a, err := s.m.pg.GetAgentByKey(key)
		if err != nil || a == nil {
			t.Fatalf("role missing: %s %v", key, err)
		}
		prompt, _ := s.m.pg.CurrentPrompt(a.ID)
		if prompt == "" {
			t.Fatal("role prompt not editable")
		}
	}
	a, _ := s.m.pg.GetAgentByKey("reverse_dynamic")
	if _, err := s.m.pg.Exec(`UPDATE agents SET enabled=false WHERE key=$1`, a.Key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.pg.Exec(`UPDATE agents SET enabled=true WHERE key=$1`, a.Key) })
	if s.taskRuntimeAvailable(r, "reverse_dynamic") {
		t.Fatal("disabled role falls back to static")
	}
	if _, err := s.workerForIntent(r, &db.Node{Payload: json.RawMessage(`{"contract":{"execution_role":"reverse_dynamic"}}`)}); err == nil {
		t.Fatal("disabled worker role silently ran")
	}
}

func TestReverseRolesUseIndependentModels(t *testing.T) {
	s, _, r := workflowFixture(t)
	keys := append([]string{"worker", "planner", "mainagent", "goals"}, agent.BuiltinReverseAgentKeys...)
	ids := map[string]int64{}
	for _, key := range keys {
		a, _ := s.m.pg.GetAgentByKey(key)
		old := a.LLMProfileID
		id, err := s.m.pg.SaveProfile(&db.LLMProfile{Name: fmt.Sprintf("role-%s-%d", key, r.Store.ID()), Format: "openai", Model: "model-" + key, APIKey: "synthetic-no-network-key"})
		if err != nil {
			t.Fatal(err)
		}
		ids[key] = id
		if err = s.m.pg.SetAgentLLMProfile(key, &id); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.m.pg.SetAgentLLMProfile(key, old); _ = s.m.pg.DeleteProfile(id) })
	}
	for _, key := range agent.BuiltinReverseAgentKeys {
		got, err := s.resolveTaskRoleLLM(r, key)
		if err != nil || !got.Available || got.Model != "model-"+key {
			t.Fatalf("%s resolved %+v %v", key, got, err)
		}
		cfg, ok := (&taskLLMRuntime{s: s, taskID: r.ID, agentKey: key}).activeCfg()
		if !ok || cfg.Model != "model-"+key {
			t.Fatalf("runtime %s uses %s", key, cfg.Model)
		}
	}
	for legacy, want := range map[string]string{"worker": "reverse_static", "mainagent": "reverse_main", "planner": "reverse_planner", "goals": "reverse_goals"} {
		got, err := s.resolveTaskRoleLLM(r, legacy)
		if err != nil || got.ProfileID == nil || *got.ProfileID != ids[want] {
			t.Fatalf("legacy %s resolved %+v %v", legacy, got, err)
		}
	}
}

func TestWorkflowRequestHelperReleasesWaitingSlotAndRecoversDeletion(t *testing.T) {
	s, p, _ := workflowFixture(t)
	ctx := context.Background()
	s.llmOn = true
	s.llmProv = &scriptedLLMProvider{}
	on, limit := s.m.ConcurrencyLimit()
	if err := s.m.SetConcurrency(true, 1); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.m.SetConcurrency(on, limit) })
	if !s.occupiesConcurrencySlot(p) {
		t.Fatal("fixture source was not admitted")
	}
	dir := filepath.Join(s.m.dir, "tasks", p.ID)
	_ = os.MkdirAll(dir, 0700)
	_ = os.WriteFile(filepath.Join(dir, "client.js"), []byte("export const value=1;"), 0600)
	r, err := s.requestWorkflowHelp(ctx, p, workflowHelpInput{RequestKey: "helper-slot", Question: "explain exported value", Files: []string{"client.js"}, BudgetSeconds: 120})
	if err != nil {
		t.Fatal(err)
	}
	target, ok := s.m.Task(fmt.Sprint(r.TargetTaskID))
	if !ok {
		t.Fatal("missing helper")
	}
	t.Cleanup(func() { _ = s.m.pg.DeleteTask(r.TargetTaskID) })
	if s.occupiesConcurrencySlot(p) || target.lifecycleSnapshot().Queued || target.lifecycleSnapshot().Paused {
		t.Fatalf("waiting source deadlocked helper: %+v", target.lifecycleSnapshot())
	}
	if _, err = s.m.pg.QueueTaskArchive(mustTaskID(t, p.ID)); err == nil {
		t.Fatal("pending request allowed archive")
	}
	if err = s.m.pg.DeleteTask(r.TargetTaskID); err != nil {
		t.Fatal(err)
	}
	if err = s.reconcileWorkflowRequests(ctx); err != nil {
		t.Fatal(err)
	}
	wait, _ := p.Store.GetNode(*r.SourceIntentID)
	if wait.State != "blocked" || !strings.Contains(string(wait.Payload), "workflow_error") {
		t.Fatalf("peer deletion orphaned wait: %+v", wait)
	}
}

func TestWorkflowRequestExpiryStopsOnlyOwnedWork(t *testing.T) {
	s, p, r := workflowFixture(t)
	ctx := context.Background()
	request, err := s.requestWorkflowHelp(ctx, r, workflowHelpInput{RequestKey: "expire", TargetTaskID: mustTaskID(t, p.ID), Question: "local behavior", BudgetSeconds: 120})
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := p.Store.AddWorkIntent(ctx, "other work", 5, nil, nil, db.WorkContract{Hypothesis: "other"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.m.pg.Exec(`UPDATE workflow_requests SET expires_at=now()-interval '1 second' WHERE id=$1`, request.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.reconcileWorkflowRequests(ctx); err != nil {
		t.Fatal(err)
	}
	owned, _ := p.Store.GetNode(*request.TargetIntentID)
	other, _ := p.Store.GetNode(unrelated)
	wait, _ := r.Store.GetNode(*request.SourceIntentID)
	if owned.State != "stopped" || other.State != "open" || wait.State != "blocked" {
		t.Fatalf("expiry leaked: owned=%s other=%s wait=%s", owned.State, other.State, wait.State)
	}
	if err = s.reconcileWorkflowRequests(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestWorkflowRequestWaiterReentersFIFOAfterReturn(t *testing.T) {
	s, p, r := workflowFixture(t)
	ctx := context.Background()
	s.llmOn = true
	s.llmProv = &scriptedLLMProvider{}
	if err := s.m.SetTaskPaused(r.ID, false); err != nil {
		t.Fatal(err)
	}
	on, limit := s.m.ConcurrencyLimit()
	_ = s.m.SetConcurrency(true, 1)
	t.Cleanup(func() { _ = s.m.SetConcurrency(on, limit) })
	request, err := s.requestWorkflowHelp(ctx, r, workflowHelpInput{RequestKey: "fifo", TargetTaskID: mustTaskID(t, p.ID), Question: "bounded response", BudgetSeconds: 120})
	if err != nil {
		t.Fatal(err)
	}
	s.reconcileConcurrency()
	if !r.lifecycleSnapshot().Queued || !s.engine.IsPaused(r.ID) {
		t.Fatal("waiting task did not release its admission")
	}
	if err = s.returnWorkflowResult(ctx, p, request.ID, "accepted", "observed bounded response", "local fixture only", []db.EvidenceReference{addWorkflowFact(t, p)}); err != nil {
		t.Fatal(err)
	}
	s.reconcileConcurrency()
	if !r.lifecycleSnapshot().Queued {
		t.Fatal("return bypassed occupied concurrency slot")
	}
	_ = s.m.pg.SetStatus(mustTaskID(t, p.ID), "done")
	p.updateLifecycle(func(state *taskLifecycleState) { state.Status = "done" })
	s.reconcileConcurrency()
	if r.lifecycleSnapshot().Queued || s.engine.IsPaused(r.ID) {
		t.Fatal("returned result did not re-enter normal admission")
	}
}

func TestWorkflowRequestPreventsEarlyGoalFinalization(t *testing.T) {
	s, p, r := workflowFixture(t)
	ctx := context.Background()
	request, err := s.requestWorkflowHelp(ctx, r, workflowHelpInput{RequestKey: "goal-gate", TargetTaskID: mustTaskID(t, p.ID), Question: "bounded answer", BudgetSeconds: 120})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.m.pg.Exec(`UPDATE exploration_nodes SET state='met' WHERE exploration_id=$1 AND kind='goal'`, p.Store.ID()); err != nil {
		t.Fatal(err)
	}
	state, err := s.m.pg.AdvanceGoalFinalization(ctx, mustTaskID(t, p.ID), true)
	if err != nil || state == "finalizing" || state == "done" {
		t.Fatalf("pending answer lost at goal completion: %s %v", state, err)
	}
	if err = s.returnWorkflowResult(ctx, p, request.ID, "accepted", "bounded observation", "local fixture only", []db.EvidenceReference{addWorkflowFact(t, p)}); err != nil {
		t.Fatal(err)
	}
	state, err = s.m.pg.AdvanceGoalFinalization(ctx, mustTaskID(t, p.ID), true)
	if err != nil || state != "finalizing" {
		t.Fatalf("completed answer still blocks finalization: %s %v", state, err)
	}
}
