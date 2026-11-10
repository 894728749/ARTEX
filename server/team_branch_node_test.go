package server

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/collab"
	"github.com/Autumn-27/artex/db"
)

// Real node subprocesses, real TLS/DB transitions, fake model and owned bytes.
// Repeated process starts deliberately exercise persistence between each round.
func TestBranchRealNodeContinuousPlanningAndIndependentReview(t *testing.T) {
	binary := os.Getenv("ARTEX_NODE_ACCEPTANCE_BINARY")
	if binary == "" {
		t.Skip("ARTEX_NODE_ACCEPTANCE_BINARY is unset")
	}
	s, _, task := workflowFixture(t)
	ctx := context.Background()
	pg := s.m.pg
	tid := mustTaskID(t, task.ID)
	if _, e := pg.Exec(`UPDATE tasks SET paused=true,status='created',queued=false WHERE id=$1`, tid); e != nil {
		t.Fatal(e)
	}
	team, e := pg.CreateTeam(ctx, "isolated branch real node")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM teams WHERE id=$1`, team.ID) })
	operator, e := pg.CreateTeamMember(ctx, team.ID, "branch operator", "unused")
	if e != nil {
		t.Fatal(e)
	}
	reviewer, e := pg.CreateTeamMember(ctx, team.ID, "branch reviewer", "unused")
	if e != nil {
		t.Fatal(e)
	}
	for _, m := range []*db.TeamMember{operator, reviewer} {
		for _, permission := range []string{"read", "execute", "review", "manage"} {
			if e = pg.AttachTeamTask(ctx, team.ID, tid, m.ID, permission); e != nil {
				t.Fatal(e)
			}
		}
	}
	pair, e := pg.CreateTeamDevicePairing(ctx, team.ID, operator.ID, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	caps := json.RawMessage(`{"version":1,"branch_protocol":1,"execution_enabled":true,"roles":["reverse_planner","reverse_static","reverse_reviewer"],"capabilities":[],"role_capabilities":{}}`)
	device, token, e := pg.PairTeamDevice(ctx, pair, "isolated logical node", caps)
	if e != nil {
		t.Fatal(e)
	}
	material := []byte("branch owned fixture: exact source evidence\n")
	hash := collab.ContentHash(material)
	prefix := s.teamMaterialPrefix(team.ID, tid)
	if e = os.MkdirAll(filepath.Join(s.m.dir, prefix), 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(s.m.dir, prefix, hash), material, 0600); e != nil {
		t.Fatal(e)
	}
	policy := collab.BranchPolicy{Version: 1, Goal: "verify the owned fixture with independent evidence review", Budget: 80, MaxToolSeconds: 30, Kinds: []string{"reverse"}, Materials: []collab.Material{{ID: hash, SHA256: hash, Size: int64(len(material)), Name: "fixture.txt"}}, PlannerPrompts: map[string]string{"reverse": "branch-planner-fixture"}, Roles: map[string]collab.ExecutionConfig{}}
	for _, role := range []string{"reverse_static", "reverse_reviewer"} {
		policy.Roles[role] = collab.ExecutionConfig{Version: 1, Kind: "reverse", Role: role, SystemPrompt: "independent " + role, MaxTurns: 4, BudgetSeconds: 30}
	}
	admin := collab.BranchActor{Admin: true}
	owner := collab.BranchActor{MemberID: operator.ID}
	if _, e = pg.CreateBranchProject(ctx, team.ID, tid, admin, policy); e != nil {
		t.Fatal(e)
	}
	command := func(a collab.BranchActor, c collab.BranchCommand) *collab.BranchReply {
		t.Helper()
		r, err := pg.ApplyBranchCommand(ctx, team.ID, tid, a, c)
		if err != nil {
			t.Fatalf("%s: %v", c.Type, err)
		}
		return r
	}
	for _, m := range []*db.TeamMember{operator, reviewer} {
		for _, permission := range collab.BranchPermissions {
			command(admin, collab.BranchCommand{Type: "grant", RequestID: fmt.Sprintf("grant-%d-%s", m.ID, permission), MemberID: m.ID, Permission: permission})
		}
	}
	work := collab.BranchWorkSpec{Title: "fixture branch", Question: "cite exact bytes and independently review", Kind: "reverse", Roles: []string{"reverse_static", "reverse_reviewer"}, MaterialHashes: []string{hash}, Acceptance: []string{"cite exact fixture"}, Budget: 50}
	pub := command(admin, collab.BranchCommand{Type: "publish", RequestID: "publish", Work: &work})
	claim := command(owner, collab.BranchCommand{Type: "claim", RequestID: "claim", WorkID: pub.Receipt.WorkID, DeviceID: device.ID})
	snap, e := pg.BranchSnapshot(ctx, team.ID, tid, admin, 0, 0, 100, "")
	if e != nil {
		t.Fatal(e)
	}
	command(admin, collab.BranchCommand{Type: "project_resume", RequestID: "resume", Revision: snap.Project.Revision})
	var mu sync.Mutex
	plannerCalls, workerCalls, reviewCalls := 0, 0, 0
	reviewHadEvidence := false
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			Model string `json:"model"`
		}
		_ = json.Unmarshal(raw, &req)
		if r.Header.Get("Authorization") != "Bearer isolated-branch-model-key" {
			t.Error("node did not use its private test model key")
		}
		mu.Lock()
		defer mu.Unlock()
		name := ""
		var args any
		content := ""
		switch req.Model {
		case "branch-planner":
			plannerCalls++
			if plannerCalls <= 2 {
				role := "reverse_static"
				key := "observe"
				var deps []int64
				if plannerCalls == 2 {
					role = "reverse_reviewer"
					key = "verify"
					deps = []int64{1}
				}
				contract, _ := json.Marshal(db.WorkContract{ExecutionRole: role, Hypothesis: "supplied fixture is unchanged", Acceptance: []string{"cite exact fixture"}, BudgetSeconds: 20, DependsOn: deps})
				name = "propose_work"
				args = map[string]any{"unit": collab.BranchUnitSpec{Key: key, Question: "check the exact fixture and report uncertainty", Role: role, MaterialHashes: []string{hash}, Contract: contract, DependsOn: deps}}
			} else {
				name = "submit_branch"
				args = map[string]any{"outcome": "negative", "text": "fixture checked; no issue observed"}
			}
		case "branch-worker":
			workerCalls++
			if workerCalls == 1 {
				name = "read_material"
				args = map[string]any{"sha256": hash}
			} else {
				content = `{"outcome":"candidate","summary":"Owned fixture observed with exact source evidence; no issue in tested condition."}`
			}
		case "branch-reviewer":
			reviewCalls++
			reviewHadEvidence = bytes.Contains(raw, bytes.TrimSpace(material))
			content = `{"outcome":"candidate","summary":"Independent technical verification matched the exact source evidence and criterion."}`
		default:
			t.Errorf("unexpected model role %q", req.Model)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		if name != "" {
			argument, _ := json.Marshal(args)
			fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"fixture-call\",\"type\":\"function\",\"function\":{\"name\":%q,\"arguments\":%q}}]}}]}\n\n", name, string(argument))
			fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n")
		} else {
			fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":%q},\"finish_reason\":\"stop\"}]}\n\n", content)
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer model.Close()
	host := httptest.NewTLSServer(s.TeamHandler())
	defer host.Close()
	cert, e := x509.ParseCertificate(host.TLS.Certificates[0].Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	temp := t.TempDir()
	ca := filepath.Join(temp, "ca.pem")
	if e = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); e != nil {
		t.Fatal(e)
	}
	roles := map[string]any{}
	models := map[string]any{}
	for _, binding := range []struct{ role, model string }{{"reverse_planner", "branch-planner"}, {"reverse_static", "branch-worker"}, {"reverse_reviewer", "branch-reviewer"}} {
		roles[binding.role] = map[string]any{"model": binding.model, "capabilities": []string{}}
		models[binding.model] = map[string]any{"endpoint": model.URL, "api_key_env": "ARTEX_BRANCH_FAKE_KEY", "model": binding.model, "format": "openai"}
	}
	cfg := map[string]any{"coordinator_url": host.URL, "ca_file": ca, "server_name": "127.0.0.1", "execution": map[string]any{"work_dir": filepath.Join(temp, "work"), "outbox_dir": filepath.Join(temp, "outbox"), "branches": map[string]any{"enabled": true, "material_mode": "assigned"}, "roles": roles, "models": models, "commands": map[string]any{}}}
	cfgPath := filepath.Join(temp, "node.json")
	raw, _ := json.Marshal(cfg)
	if e = os.WriteFile(cfgPath, raw, 0600); e != nil {
		t.Fatal(e)
	}
	state := filepath.Join(temp, "identity.json")
	raw, _ = json.Marshal(map[string]any{"coordinator_url": host.URL, "device_token": token, "device": map[string]any{"id": device.ID, "name": device.Name}})
	if e = os.WriteFile(state, raw, 0600); e != nil {
		t.Fatal(e)
	}
	for round := 0; round < 7; round++ {
		runCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
		cmd := exec.CommandContext(runCtx, binary, "-config", cfgPath, "-state", state, "run-once")
		cmd.Env = append(os.Environ(), "ARTEX_BRANCH_FAKE_KEY=isolated-branch-model-key")
		out, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("real node round %d: %v\n%s", round, err, out)
		}
		snap, e = pg.BranchSnapshot(ctx, team.ID, tid, admin, 0, 0, 200, "")
		if e != nil {
			t.Fatal(e)
		}
		if snap.Project.Branches[0].State == "review_pending" {
			break
		}
	}
	b := snap.Project.Branches[0]
	if b.State != "review_pending" || len(b.Units) != 2 || b.Outcome != "negative" {
		raw, _ := json.Marshal(b)
		t.Fatalf("continuous planner did not produce reviewed branch: %s", raw)
	}
	mu.Lock()
	calls, worker, reviews, evidence := plannerCalls, workerCalls, reviewCalls, reviewHadEvidence
	mu.Unlock()
	if calls != 3 || worker != 2 || reviews != 1 || !evidence {
		t.Fatalf("role/model/evidence isolation failed planner=%d worker=%d reviewer=%d evidence=%v", calls, worker, reviews, evidence)
	}
	if _, e = pg.ApplyBranchCommand(ctx, team.ID, tid, owner, collab.BranchCommand{Type: "review", RequestID: "self-review", BranchID: claim.Branch.ID, Revision: b.Revision, State: "accept"}); e == nil {
		t.Fatal("executor accepted its own branch")
	}
	command(collab.BranchActor{MemberID: reviewer.ID}, collab.BranchCommand{Type: "review", RequestID: "independent", BranchID: b.ID, Revision: b.Revision, State: "accept", Text: "exact source receipt verified by separate member"})
	snap, e = pg.BranchSnapshot(ctx, team.ID, tid, admin, 0, 0, 200, "")
	if e != nil {
		t.Fatal(e)
	}
	if snap.Project.State != "running" || snap.Project.Branches[0].State != "accepted" {
		t.Fatal("branch acceptance incorrectly completed master")
	}
	if strings.Contains(fmt.Sprint(snap.Events), "isolated-branch-model-key") {
		t.Fatal("private node credential entered shared timeline")
	}
	t.Logf("real process accepted: %d planner requests, %d worker requests, %d reviewer requests, spent=%d, shared_events=%d", calls, worker, reviews, b.Spent, len(snap.Events))
}
