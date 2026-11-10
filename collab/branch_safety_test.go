package collab

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func runningBranchFixture(t *testing.T) (*BranchProject, BranchActor, BranchActor) {
	t.Helper()
	p := branchTestProject()
	p.Policy.Budget = 100
	owner := BranchActor{MemberID: 7, Devices: map[int64]BranchDevice{11: {ID: 11, OwnerID: 7, Active: true, Online: true, Protocol: 1, Roles: []string{"planner", "worker", "reviewer"}, RoleCapabilities: map[string][]string{"worker": {"inspect"}}}, 12: {ID: 12, OwnerID: 8, Active: true, Online: true, Protocol: 1, Roles: []string{"planner", "worker", "reviewer"}, RoleCapabilities: map[string][]string{"worker": {"inspect"}}}}}
	p.Permissions["8"] = append([]string{}, BranchPermissions...)
	w := branchTestWork()
	w.Budget = 30
	branchDo(t, &p, BranchActor{Admin: true}, BranchCommand{Type: "publish", RequestID: "pub", Work: &w})
	branchDo(t, &p, owner, BranchCommand{Type: "claim", RequestID: "claim", WorkID: 1, DeviceID: 11})
	node := owner
	node.DeviceID = 11
	branchDo(t, &p, node, BranchCommand{Type: "ready", RequestID: "ready", BranchID: 1, Epoch: 1})
	return &p, owner, node
}
func safetyUnit(t *testing.T, p *BranchProject, node BranchActor) {
	u := BranchUnitSpec{Key: "observe", Question: "read fixture", Role: "worker", Capabilities: []string{"inspect"}, Contract: json.RawMessage(`{"resource_key":"fixture"}`)}
	branchDo(t, p, node, BranchCommand{Type: "plan", RequestID: "plan", BranchID: 1, Epoch: 1, Unit: &u})
}
func safetyOperation() BranchOperation {
	return BranchOperation{ID: "operation", Epoch: 1, UnitID: 1, Kind: "tool", Role: "worker", Tool: "inspect", InputHash: ContentHash([]byte("fixture"))}
}
func deniedBranch(t *testing.T, p *BranchProject, a BranchActor, c BranchCommand) {
	t.Helper()
	if _, _, err := ApplyBranchCommand(p, a, c, time.Unix(100, 0)); err == nil {
		t.Fatalf("unsafe command allowed: %+v", c)
	}
}

func TestBranchPauseBoundaryGuidanceAndUnknownOperation(t *testing.T) {
	p, owner, node := runningBranchFixture(t)
	safetyUnit(t, p, node)
	op := safetyOperation()
	branchDo(t, p, node, BranchCommand{Type: "start", RequestID: "start", BranchID: 1, Epoch: 1, Operation: &op})
	branchDo(t, p, owner, BranchCommand{Type: "discuss", RequestID: "discussion", BranchID: 1, Text: "suggestion only"})
	if len(p.Branches[0].Guidance) != 0 {
		t.Fatal("discussion became an instruction")
	}
	branchDo(t, p, owner, BranchCommand{Type: "guide", RequestID: "guide", BranchID: 1, Text: "next inspect the fixture"})
	for i, kind := range []string{"guidance_received", "guidance_applied"} {
		branchDo(t, p, node, BranchCommand{Type: kind, RequestID: fmt.Sprint("g", i), BranchID: 1, Epoch: 1, GuidanceIDs: []int64{1}})
	}
	if p.Branches[0].Guidance[0].Status != "applied" {
		t.Fatal("guidance not applied")
	}
	branchDo(t, p, owner, BranchCommand{Type: "pause", RequestID: "pause", BranchID: 1, Revision: p.Branches[0].Revision})
	if p.Branches[0].State != "pausing" {
		t.Fatal("bounded current operation must be allowed to finish")
	}
	other := op
	other.ID = "second"
	deniedBranch(t, p, node, BranchCommand{Type: "start", RequestID: "second", BranchID: 1, Epoch: 1, Operation: &other})
	branchDo(t, p, node, BranchCommand{Type: "end", RequestID: "end", BranchID: 1, Epoch: 1, Operation: &op})
	branchDo(t, p, node, BranchCommand{Type: "checkpoint", RequestID: "checkpoint", BranchID: 1, Epoch: 1, Text: "bounded operation ended"})
	branchDo(t, p, owner, BranchCommand{Type: "resume", RequestID: "resume", BranchID: 1, Revision: p.Branches[0].Revision})
	branchDo(t, p, node, BranchCommand{Type: "ready", RequestID: "ready-again", BranchID: 1, Epoch: 1})
	branchDo(t, p, node, BranchCommand{Type: "start", RequestID: "unknown-start", BranchID: 1, Epoch: 1, Operation: &other})
	branchDo(t, p, node, BranchCommand{Type: "checkpoint", RequestID: "crashed", BranchID: 1, Epoch: 1, Text: "process restarted; effect unknown"})
	if p.Branches[0].Operations[1].State != "uncertain" || p.Branches[0].State != "paused" {
		t.Fatal("unknown side effect lost its fence")
	}
	deniedBranch(t, p, owner, BranchCommand{Type: "resume", RequestID: "unsafe-resume", BranchID: 1, Revision: p.Branches[0].Revision})
	branchDo(t, p, owner, BranchCommand{Type: "confirm_stopped", RequestID: "confirmed", BranchID: 1, Revision: p.Branches[0].Revision, Text: "isolated child process verified stopped"})
	if p.Branches[0].Epoch != 2 || p.Branches[0].Units[0].State != "uncertain" || p.Branches[0].Spent != 3 {
		t.Fatal("confirmation reset history or budget")
	}
	deniedBranch(t, p, node, BranchCommand{Type: "heartbeat", RequestID: "old-epoch", BranchID: 1, Epoch: 1})
}

func TestBranchTransferFencesOldEpochAndRetainsHistory(t *testing.T) {
	p, owner, node := runningBranchFixture(t)
	safetyUnit(t, p, node)
	op := safetyOperation()
	branchDo(t, p, node, BranchCommand{Type: "start", RequestID: "start", BranchID: 1, Epoch: 1, Operation: &op})
	branchDo(t, p, owner, BranchCommand{Type: "transfer", RequestID: "transfer", BranchID: 1, Revision: p.Branches[0].Revision, MemberID: 8, DeviceID: 12})
	b := &p.Branches[0]
	if b.State != "transfer_wait" || b.DeviceID != 11 {
		t.Fatal("transferred while old tool live")
	}
	other := node
	other.MemberID = 8
	other.DeviceID = 12
	deniedBranch(t, p, other, BranchCommand{Type: "ready", RequestID: "early-ready", BranchID: 1, Epoch: 2})
	branchDo(t, p, node, BranchCommand{Type: "end", RequestID: "end", BranchID: 1, Epoch: 1, Operation: &op})
	branchDo(t, p, node, BranchCommand{Type: "checkpoint", RequestID: "stopped", BranchID: 1, Epoch: 1, Text: "stopped at tool boundary"})
	if b.ID != 1 || b.Epoch != 2 || b.OwnerID != 8 || b.Spent != 2 || len(b.Units) != 1 || !hasID(b.Contributors, 7) {
		t.Fatalf("history lost: %+v", b)
	}
	deniedBranch(t, p, node, BranchCommand{Type: "event", RequestID: "late-old", BranchID: 1, Epoch: 1, Event: &BranchEvent{Seq: 1, Kind: "message"}})
	branchDo(t, p, other, BranchCommand{Type: "ready", RequestID: "ready2", BranchID: 1, Epoch: 2})
	replacement := b.Units[0].Spec
	replacement.Key = "verify-unknown"
	replacement.Supersedes = 1
	replacement.Question = "verify effects without replay"
	branchDo(t, p, other, BranchCommand{Type: "plan", RequestID: "replacement", BranchID: 1, Epoch: 2, Unit: &replacement})
	if b.Units[0].State != "superseded" || b.Units[1].State != "planned" {
		t.Fatal("explicit supplement did not preserve old unit")
	}
}

func TestBranchBudgetScopeLeaseAndReplay(t *testing.T) {
	p, _, node := runningBranchFixture(t)
	safetyUnit(t, p, node)
	op := safetyOperation()
	bad := op
	bad.Tool = "ungranted"
	deniedBranch(t, p, node, BranchCommand{Type: "start", RequestID: "capability", BranchID: 1, Epoch: 1, Operation: &bad})
	unit := BranchUnitSpec{Key: "escape", Question: "escape scope", Role: "worker", AssetIDs: []string{"unknown"}}
	deniedBranch(t, p, node, BranchCommand{Type: "plan", RequestID: "scope", BranchID: 1, Epoch: 1, Unit: &unit})
	if _, _, err := ApplyBranchCommand(p, node, BranchCommand{Type: "start", RequestID: "expired", BranchID: 1, Epoch: 1, Operation: &op}, time.Unix(1000, 0)); err == nil {
		t.Fatal("expired authorization accepted")
	}
	p.Branches[0].Spec.Budget = 2
	start := BranchCommand{Type: "start", RequestID: "start", BranchID: 1, Epoch: 1, Operation: &op}
	branchDo(t, p, node, start)
	branchDo(t, p, node, start)
	if p.Branches[0].Spent != 2 {
		t.Fatal("receipt retry spent twice")
	}
	branchDo(t, p, node, BranchCommand{Type: "end", RequestID: "end", BranchID: 1, Epoch: 1, Operation: &op})
	op.ID = "attempt-two"
	deniedBranch(t, p, node, BranchCommand{Type: "start", RequestID: "budget-overrun", BranchID: 1, Epoch: 1, Operation: &op})
}

func TestBranchAssistanceReservesParentBudgetWithoutDeadlock(t *testing.T) {
	p, _, node := runningBranchFixture(t)
	p.Policy.Kinds = append(p.Policy.Kinds, "reverse")
	p.Policy.Roles["reverse_static"] = ExecutionConfig{Version: 1, Kind: "reverse", Role: "reverse_static", SystemPrompt: "reverse only", BudgetSeconds: 60}
	w := BranchWorkSpec{Title: "explain artifact", Question: "explain fixture", Kind: "reverse", Roles: []string{"reverse_static"}, Budget: 5}
	branchDo(t, p, node, BranchCommand{Type: "assist", RequestID: "assist", BranchID: 1, Epoch: 1, Work: &w})
	if totalBudget(p) != 30 || p.Branches[0].Spec.Budget != 25 || p.Pool[1].Spec.ParentBranchID != 1 || hasID(p.Pool[1].Spec.DependsOn, 1) {
		t.Fatal("assistance changed total allocation or caused circular wait")
	}
	if dependenciesAccepted(p, &p.Branches[0]) {
		t.Fatal("unclaimed assistance was ignored")
	}
	branchDo(t, p, node, BranchCommand{Type: "checkpoint", RequestID: "wait", BranchID: 1, Epoch: 1, State: "waiting_dependency", Text: "waiting for reverse explanation"})
	p.Pool[1].State = "accepted" // accepted assistant proof is checked independently by review tests
	branchDo(t, p, node, BranchCommand{Type: "heartbeat", RequestID: "dependency-ready", BranchID: 1, Epoch: 1})
	if p.Branches[0].State != "running" {
		t.Fatal("accepted assistance did not release waiting branch")
	}
	p.Branches = append(p.Branches, ExecutionBranch{ID: 2, Spec: BranchWorkSpec{DependsOn: []int64{1}}})
	if !dependencyCycle(p, 1, 2) {
		t.Fatal("dependency cycle missed")
	}
}

func TestBranchEvidenceInvalidationPropagatesTransitively(t *testing.T) {
	p := branchTestProject()
	p.State = "complete"
	for i := int64(1); i <= 3; i++ {
		u := BranchUnit{ID: 1, State: "candidate", EvidenceVersion: fmt.Sprint("v", i)}
		if i > 1 {
			u.Spec.EvidenceRefs = []BranchEvidenceRef{{BranchID: i - 1, UnitID: 1, Version: fmt.Sprint("v", i-1)}}
		}
		p.Branches = append(p.Branches, ExecutionBranch{ID: i, State: "accepted", Units: []BranchUnit{u}})
	}
	branchDo(t, &p, BranchActor{Admin: true}, BranchCommand{Type: "invalidate_evidence", RequestID: "invalidate", BranchID: 1, UnitID: 1, Text: "source withdrawn"})
	if p.State != "paused" {
		t.Fatal("completed master retained invalid completion")
	}
	for _, b := range p.Branches {
		if b.State != "needs_supplement" || b.Units[0].State != "stale" || b.Units[0].EvidenceVersion != "" {
			t.Fatalf("transitive proof retained: %+v", b)
		}
	}
}

func TestBranchRuntimeGrantIsExactDeviceProfileAndSingleUse(t *testing.T) {
	p, owner, node := runningBranchFixture(t)
	b := &p.Branches[0]
	b.Spec.Kind = "reverse"
	b.Spec.Roles = []string{"reverse_dynamic"}
	h := ContentHash([]byte("owned binary"))
	b.Spec.MaterialHashes = []string{h}
	p.Policy.Kinds = append(p.Policy.Kinds, "reverse")
	p.Policy.Materials = []Material{{ID: h, SHA256: h, Size: 12}}
	p.Policy.Roles["reverse_dynamic"] = ExecutionConfig{Version: 1, Kind: "reverse", Role: "reverse_dynamic", SystemPrompt: "observe only authorized runtime", BudgetSeconds: 30, Capabilities: []string{"reverse_observe_runtime"}}
	profile := RuntimeProfile{ID: "lab", Platform: "linux", Digest: ContentHash([]byte("profile")), MaxDurationMS: 1000}
	device := node.Devices[11]
	device.Roles = append(device.Roles, "reverse_dynamic")
	device.RuntimeProfiles = []RuntimeProfile{profile}
	node.Devices[11] = device
	owner.Devices = node.Devices
	u := BranchUnitSpec{Key: "runtime", Question: "observe owned binary once", Role: "reverse_dynamic", MaterialHashes: []string{h}, Capabilities: []string{"reverse_observe_runtime"}}
	branchDo(t, p, node, BranchCommand{Type: "plan", RequestID: "plan-runtime", BranchID: 1, Epoch: 1, Unit: &u})
	binding := RuntimeBinding{RuntimeProfile: profile, ArtifactHashes: []string{h}}
	binding.Digest = ContentHash([]byte("different profile"))
	c := BranchCommand{Type: "authorize_runtime", RequestID: "authorize-runtime", BranchID: 1, UnitID: 1, DeviceID: 11, Revision: b.Revision, Runtime: &binding}
	deniedBranch(t, p, owner, c)
	binding.Digest = profile.Digest
	branchDo(t, p, owner, c)
	op := BranchOperation{ID: "runtime-op", Epoch: 1, UnitID: 1, Kind: "tool", Role: "reverse_dynamic", Tool: "reverse_observe_runtime", InputHash: ContentHash([]byte("fixture"))}
	branchDo(t, p, node, BranchCommand{Type: "start", RequestID: "runtime-start", BranchID: 1, Epoch: 1, Operation: &op})
	branchDo(t, p, node, BranchCommand{Type: "end", RequestID: "runtime-end", BranchID: 1, Epoch: 1, Operation: &op})
	op.ID = "second-runtime"
	deniedBranch(t, p, node, BranchCommand{Type: "start", RequestID: "reuse-runtime", BranchID: 1, Epoch: 1, Operation: &op})
}

func TestBranchPolicyExtensionRequiresPauseAndPreservesSpent(t *testing.T) {
	p, owner, node := runningBranchFixture(t)
	safetyUnit(t, p, node)
	c := BranchCommand{Type: "extend_policy", RequestID: "extend", Revision: p.Revision, Policy: &BranchPolicy{Budget: 120, Assets: []BranchAsset{{ID: "new", Target: "https://owned.invalid", Version: "v1"}}}}
	deniedBranch(t, p, owner, c)
	branchDo(t, p, owner, BranchCommand{Type: "project_pause", RequestID: "pause", Revision: p.Revision})
	c.Revision = p.Revision
	branchDo(t, p, owner, c)
	if p.Policy.Version != 2 || p.Branches[0].PolicyVersion != 2 || p.Branches[0].Spent != 1 || p.Policy.Budget != 120 {
		t.Fatal("policy update reset usage or lost version fence")
	}
}
