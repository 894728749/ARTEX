package collab

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func branchTestProject() BranchProject {
	return BranchProject{TeamID: 2, TaskID: 9, State: "running", Policy: BranchPolicy{
		Version: BranchProtocol, Goal: "fixture scope", Budget: 10, MaxToolSeconds: 60, Kinds: []string{"pentest"},
		Roles: map[string]ExecutionConfig{
			"worker":   {Version: 1, Kind: "pentest", Role: "worker", SystemPrompt: "work", BudgetSeconds: 60, Capabilities: []string{"read_material", "inspect"}},
			"reviewer": {Version: 1, Kind: "pentest", Role: "reviewer", SystemPrompt: "review", BudgetSeconds: 60, Capabilities: []string{"read_material"}},
		},
	}, Permissions: map[string][]string{"7": {"read", "process", "evidence", "discuss", "execute", "guide", "control", "review", "manage"}}}
}

func branchTestWork() BranchWorkSpec {
	return BranchWorkSpec{Title: "test", Question: "check fixture", Kind: "pentest", Roles: []string{"worker", "reviewer"}, Budget: 5}
}

func branchDo(t *testing.T, p *BranchProject, a BranchActor, c BranchCommand) (BranchReceipt, []BranchEvent) {
	t.Helper()
	r, e, err := ApplyBranchCommand(p, a, c, time.Unix(100, 0))
	if err != nil {
		t.Fatalf("ApplyBranchCommand(%s): %v", c.Type, err)
	}
	return r, e
}

func TestBranchPermissionsAreIndependentAndRestrictedScopeIsEnforced(t *testing.T) {
	p := branchTestProject()
	p.Branches = []ExecutionBranch{{ID: 1, Spec: BranchWorkSpec{Restricted: true, Members: []int64{7}}, Contributors: []int64{8}}}
	a := BranchActor{MemberID: 7}
	if err := CheckBranchAccess(&p, a, 1, "read"); err != nil {
		t.Fatal(err)
	}
	if err := CheckBranchAccess(&p, a, 1, "guide"); err != nil {
		t.Fatal(err)
	}
	p.Permissions["7"] = []string{"read", "execute"}
	if err := CheckBranchAccess(&p, a, 1, "guide"); !errors.Is(err, ErrBranchDenied) {
		t.Fatalf("guide must be independently granted, got %v", err)
	}
	if err := CheckBranchAccess(&p, BranchActor{MemberID: 9}, 1, "read"); !errors.Is(err, ErrBranchDenied) {
		t.Fatalf("restricted outsider access: %v", err)
	}
	if err := CheckBranchAccess(&p, BranchActor{Admin: true}, 1, "manage"); err != nil {
		t.Fatalf("admin management: %v", err)
	}
	branchDo(t, &p, BranchActor{Admin: true}, BranchCommand{Type: "grant", RequestID: "revoke-guide", MemberID: 7, Permission: "guide", Revoke: true})
	if err := CheckBranchAccess(&p, a, 1, "guide"); !errors.Is(err, ErrBranchDenied) {
		t.Fatalf("grant with revoke flag did not revoke: %v", err)
	}
}

func TestBranchReceiptIdempotencyAndConflictingReplay(t *testing.T) {
	p := branchTestProject()
	a := BranchActor{Admin: true}
	c := BranchCommand{Type: "publish", RequestID: "same", Work: func() *BranchWorkSpec { w := branchTestWork(); return &w }()}
	r1, events := branchDo(t, &p, a, c)
	if r1.WorkID != 1 || len(events) != 1 || events[0].Kind != "publish" {
		t.Fatalf("unexpected first publish receipt/events: %+v %v", r1, events)
	}
	r2, events, err := ApplyBranchCommand(&p, a, c, time.Unix(200, 0))
	if err != nil || r2 != r1 || len(events) != 0 {
		t.Fatalf("replay receipt=%+v events=%v err=%v", r2, events, err)
	}
	c.Work.Question = "changed"
	if _, _, err = ApplyBranchCommand(&p, a, c, time.Unix(200, 0)); !errors.Is(err, ErrBranchConflict) {
		t.Fatalf("changed replay accepted: %v", err)
	}
}

func TestBranchClaimPlanBudgetEndAndTechnicalReviewGate(t *testing.T) {
	p := branchTestProject()
	admin := BranchActor{Admin: true}
	work := branchTestWork()
	branchDo(t, &p, admin, BranchCommand{Type: "publish", RequestID: "publish", Work: &work})
	owner := BranchActor{MemberID: 7, Devices: map[int64]BranchDevice{11: {ID: 11, OwnerID: 7, Active: true, Online: true, Protocol: BranchProtocol, Roles: []string{"planner", "worker", "reviewer"}, RoleCapabilities: map[string][]string{"worker": {"inspect"}}}}}
	claim, _ := branchDo(t, &p, owner, BranchCommand{Type: "claim", RequestID: "claim", WorkID: 1, DeviceID: 11})
	if claim.BranchID != 1 || p.Branches[0].State != "waiting_ready" {
		t.Fatalf("claim did not establish waiting branch: %+v %+v", claim, p.Branches[0])
	}
	node := BranchActor{MemberID: 7, DeviceID: 11, Devices: owner.Devices}
	branchDo(t, &p, node, BranchCommand{Type: "ready", RequestID: "ready", BranchID: 1, Epoch: 1})
	for i, role := range []string{"worker", "reviewer"} {
		u := BranchUnitSpec{Key: role, Question: "inspect", Role: role, Contract: json.RawMessage(`{}`)}
		if i == 0 {
			u.Capabilities = []string{"inspect"}
		} else {
			u.DependsOn = []int64{1}
		}
		ur, _ := branchDo(t, &p, node, BranchCommand{Type: "plan", RequestID: "plan-" + role, BranchID: 1, Epoch: 1, Unit: &u})
		if ur.UnitID != int64(i+1) {
			t.Fatalf("unit id=%d", ur.UnitID)
		}
		if i == 0 {
			op := BranchOperation{ID: "op1", Epoch: 1, UnitID: ur.UnitID, Kind: "tool", Role: role, Tool: "inspect", InputHash: ContentHash([]byte("input"))}
			branchDo(t, &p, node, BranchCommand{Type: "start", RequestID: "start", BranchID: 1, Epoch: 1, Operation: &op})
			branchDo(t, &p, node, BranchCommand{Type: "end", RequestID: "end", BranchID: 1, Epoch: 1, Operation: &op})
		} else {
			op := BranchOperation{ID: "review-model", Epoch: 1, UnitID: ur.UnitID, Kind: "model", Role: role, InputHash: ContentHash([]byte("review"))}
			branchDo(t, &p, node, BranchCommand{Type: "start", RequestID: "review-start", BranchID: 1, Epoch: 1, Operation: &op})
			branchDo(t, &p, node, BranchCommand{Type: "end", RequestID: "review-end", BranchID: 1, Epoch: 1, Operation: &op})
		}
		res := &ExecutionResult{Version: 1, Outcome: "candidate", Summary: "checked", Role: role, Model: "fixture"}
		branchDo(t, &p, node, BranchCommand{Type: "unit_result", RequestID: "result-" + role, BranchID: 1, Epoch: 1, UnitID: ur.UnitID, Result: res})
	}
	if p.Branches[0].Spent != 4 {
		t.Fatalf("retry/tool spend count=%d", p.Branches[0].Spent)
	}
	branchDo(t, &p, node, BranchCommand{Type: "submit", RequestID: "submit", BranchID: 1, Epoch: 1, Outcome: "candidate", Text: "candidate"})
	if p.Branches[0].State != "review_pending" {
		t.Fatal("submit skipped independent review")
	}
	if _, _, err := ApplyBranchCommand(&p, node, BranchCommand{Type: "review", RequestID: "self-review", BranchID: 1, State: "accept"}, time.Now()); !errors.Is(err, ErrBranchDenied) {
		t.Fatalf("contributor self-review accepted: %v", err)
	}
	independent := BranchActor{MemberID: 8}
	_, _, err := ApplyBranchCommand(&p, independent, BranchCommand{Type: "review", RequestID: "review", BranchID: 1, State: "accept"}, time.Now())
	if !errors.Is(err, ErrBranchDenied) {
		t.Fatalf("unpermissioned reviewer accepted: %v", err)
	}
	p.Permissions["8"] = []string{"read", "review"}
	branchDo(t, &p, independent, BranchCommand{Type: "review", RequestID: "review-ok", BranchID: 1, Revision: p.Branches[0].Revision, State: "accept", Text: "independent"})
	if p.Branches[0].State != "accepted" {
		t.Fatal("independent review did not accept")
	}
}

func TestValidateBranchPolicyAllowsNewReviewerRoleWithoutLegacyValidator(t *testing.T) {
	p := branchTestProject().Policy
	if err := ValidateBranchPolicy(p); err != nil {
		t.Fatal(err)
	}
	p.Roles["reviewer"] = ExecutionConfig{Version: 1, Kind: "reverse", Role: "reverse_reviewer", SystemPrompt: "review", BudgetSeconds: 60}
	if err := ValidateBranchPolicy(p); err == nil {
		t.Fatal("role key/config mismatch accepted")
	}
	delete(p.Roles, "reviewer")
	p.Kinds = append(p.Kinds, "reverse")
	p.Roles["reverse_reviewer"] = ExecutionConfig{Version: 1, Kind: "reverse", Role: "reverse_reviewer", SystemPrompt: "review", BudgetSeconds: 60, Capabilities: []string{"read_material"}}
	if err := ValidateBranchPolicy(p); err != nil {
		t.Fatalf("new branch reviewer role rejected: %v", err)
	}
}

func TestBranchProjectPauseAndEvidenceRefInvalidation(t *testing.T) {
	p := branchTestProject()
	p.Branches = []ExecutionBranch{
		{ID: 1, State: "accepted", Spec: BranchWorkSpec{Kind: "pentest"}, Units: []BranchUnit{{ID: 1, State: "candidate", EvidenceVersion: "v1"}}},
		{ID: 2, State: "accepted", Spec: BranchWorkSpec{Kind: "pentest", DependsOn: []int64{1}}, Units: []BranchUnit{{ID: 1, State: "candidate", Spec: BranchUnitSpec{EvidenceRefs: []BranchEvidenceRef{{BranchID: 1, UnitID: 1, Version: "v1"}}}}}},
	}
	admin := BranchActor{Admin: true}
	branchDo(t, &p, admin, BranchCommand{Type: "project_pause", RequestID: "pause-project", Revision: p.Revision})
	if p.State != "paused" {
		t.Fatal("project did not pause")
	}
	branchDo(t, &p, admin, BranchCommand{Type: "project_resume", RequestID: "resume-project", Revision: p.Revision})
	if p.State != "running" {
		t.Fatal("project did not resume")
	}
	branchDo(t, &p, admin, BranchCommand{Type: "invalidate_evidence", RequestID: "invalidate", BranchID: 1, UnitID: 1, Text: "source changed"})
	if p.Branches[1].State != "needs_supplement" || p.Branches[1].Units[0].State != "stale" {
		t.Fatalf("dependent evidence was not invalidated: %+v", p.Branches[1])
	}
}
