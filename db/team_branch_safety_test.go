package db

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/collab"
)

func TestBranchDBArchiveKeepsHistoryWithoutRevivingAuthority(t *testing.T) {
	d, team, member, task, device := branchDBFixture(t)
	enableFixtureTool(t, d, task.ID, device.ID)
	if e := d.EnsureLLMRecordsTable(); e != nil {
		t.Fatal(e)
	}
	if e := d.EnsureLLMUsageTable(); e != nil {
		t.Fatal(e)
	}
	r := branchDBRunning(t, d, team, member, task, device, "archive")
	if _, e := d.QueueTaskArchive(task.ID); e == nil {
		t.Fatal("running branch was archived")
	}
	owner := collab.BranchActor{MemberID: member.ID}
	branchDBCommand(t, d, team.ID, task.ID, owner, collab.BranchCommand{Type: "pause", RequestID: "pause-archive", BranchID: r.Branch.ID, Revision: r.Branch.Revision})
	if e := d.SetPaused(task.ID, true); e != nil {
		t.Fatal(e)
	}
	a, e := d.QueueTaskArchive(task.ID)
	if e != nil {
		t.Fatal(e)
	}
	// Queue claiming is covered by archive tests. Select only this fixture's job
	// so unrelated interrupted jobs in the shared regression database stay put.
	if _, e = d.Exec(`UPDATE task_archives SET state=$2 WHERE id=$1`,a.ID,Archiving); e != nil {
		t.Fatal(e)
	}
	var records bytes.Buffer
	snap, e := d.SnapshotTaskArchiveWithLLMRecords(task.ID, &records)
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"team_branch_project", "team_branch_event"} {
		if !strings.Contains(string(snap.Tables["team_history_sources"]), want) {
			t.Fatal("archive missing " + want)
		}
	}
	if e = d.CompleteTaskArchive(a.ID, snap, "/tmp/isolated-branch-archive.tar.zst", "fixture", 1, 1); e != nil {
		t.Fatal(e)
	}
	if active, e := d.BranchMode(context.Background(), task.ID); e != nil || active {
		t.Fatalf("archive retained active authority: %v %v", active, e)
	}
	if _, e = d.QueueTaskArchiveRestore(a.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = d.Exec(`UPDATE task_archives SET state=$2 WHERE id=$1`,a.ID,Restoring); e != nil {
		t.Fatal(e)
	}
	if _, e = d.RestoreTaskArchiveWithLLMRecords(a.ID, snap, 600, bytes.NewReader(records.Bytes())); e != nil {
		t.Fatal(e)
	}
	if e = d.CompleteTaskArchiveRestore(a.ID); e != nil {
		t.Fatal(e)
	}
	var count int
	if e = d.QueryRow(`SELECT count(*) FROM task_team_history WHERE task_id=$1 AND kind LIKE 'team_branch_%'`, task.ID).Scan(&count); e != nil || count < 2 {
		t.Fatalf("history not restored: %d %v", count, e)
	}
	if active, e := d.BranchMode(context.Background(), task.ID); e != nil || active {
		t.Fatalf("restore revived leases or grants: %v %v", active, e)
	}
}

func branchDBCommand(t *testing.T, d *DB, team, task int64, a collab.BranchActor, c collab.BranchCommand) *collab.BranchReply {
	t.Helper()
	r, e := d.ApplyBranchCommand(context.Background(), team, task, a, c)
	if e != nil {
		t.Fatalf("%s: %v", c.Type, e)
	}
	return r
}
func branchDBRunning(t *testing.T, d *DB, team *Team, member *TeamMember, task *Task, device *TeamDevice, key string) *collab.BranchReply {
	t.Helper()
	ctx := context.Background()
	admin := collab.BranchActor{Admin: true}
	memberActor := collab.BranchActor{MemberID: member.ID}
	snap, e := d.BranchSnapshot(ctx, team.ID, task.ID, admin, 0, 0, 100, "")
	if e != nil {
		t.Fatal(e)
	}
	if snap.Project.State == "paused" {
		branchDBCommand(t, d, team.ID, task.ID, admin, collab.BranchCommand{Type: "project_resume", RequestID: "resume-project", Revision: snap.Project.Revision})
	}
	w := collab.BranchWorkSpec{Title: key, Question: "read owned fixture", Kind: "pentest", Roles: []string{"worker", "reviewer"}, AssetIDs: []string{"fixture"}, Budget: 20, ResourceKeys: []string{"shared-fixture"}}
	r := branchDBCommand(t, d, team.ID, task.ID, admin, collab.BranchCommand{Type: "publish", RequestID: "pub-" + key, Work: &w})
	r = branchDBCommand(t, d, team.ID, task.ID, memberActor, collab.BranchCommand{Type: "claim", RequestID: "claim-" + key, WorkID: r.Receipt.WorkID, DeviceID: device.ID})
	node := collab.BranchActor{MemberID: member.ID, DeviceID: device.ID}
	branchDBCommand(t, d, team.ID, task.ID, node, collab.BranchCommand{Type: "ready", RequestID: "ready-" + key, BranchID: r.Branch.ID, Epoch: 1})
	contract, _ := json.Marshal(WorkContract{ExecutionRole: "worker", Acceptance: []string{"raw fixture evidence"}, BudgetSeconds: 30, ResourceKey: "shared-fixture"})
	u := collab.BranchUnitSpec{Key: key, Question: "read synthetic data", Role: "worker", AssetIDs: []string{"fixture"}, Capabilities: []string{"inspect"}, Contract: contract}
	return branchDBCommand(t, d, team.ID, task.ID, node, collab.BranchCommand{Type: "plan", RequestID: "plan-" + key, BranchID: r.Branch.ID, Epoch: 1, Unit: &u})
}
func enableFixtureTool(t *testing.T, d *DB, task, device int64) {
	t.Helper()
	if _, e := d.Exec(`UPDATE team_branch_projects SET state=jsonb_set(state,'{policy,roles,worker,capabilities}','["inspect"]') WHERE task_id=$1`, task); e != nil {
		t.Fatal(e)
	}
	if _, e := d.Exec(`UPDATE team_devices SET capabilities=jsonb_set(capabilities,'{role_capabilities}','{"worker":["inspect"]}') WHERE id=$1`, device); e != nil {
		t.Fatal(e)
	}
}

func TestBranchDBSharedResourcesUnknownOperationAndLegacyAdmission(t *testing.T) {
	d, team, member, task, device := branchDBFixture(t)
	enableFixtureTool(t, d, task.ID, device.ID)
	r1 := branchDBRunning(t, d, team, member, task, device, "one")
	r2 := branchDBRunning(t, d, team, member, task, device, "two")
	node := collab.BranchActor{MemberID: member.ID, DeviceID: device.ID}
	owner := collab.BranchActor{MemberID: member.ID}
	op := collab.BranchOperation{ID: "side-effect", Epoch: 1, UnitID: 1, Kind: "tool", Role: "worker", Tool: "inspect", InputHash: collab.ContentHash([]byte("fixture"))}
	branchDBCommand(t, d, team.ID, task.ID, node, collab.BranchCommand{Type: "start", RequestID: "start1", BranchID: r1.Branch.ID, Epoch: 1, Operation: &op})
	ctx := context.Background()
	if _, e := d.ApplyBranchCommand(ctx, team.ID, task.ID, node, collab.BranchCommand{Type: "start", RequestID: "conflict", BranchID: r2.Branch.ID, Epoch: 1, Operation: &op}); e == nil {
		t.Fatal("overlapping branch resource allowed")
	}
	r := branchDBCommand(t, d, team.ID, task.ID, node, collab.BranchCommand{Type: "checkpoint", RequestID: "lost-result", BranchID: r1.Branch.ID, Epoch: 1, Text: "process disappeared"})
	if _, e := d.ApplyBranchCommand(ctx, team.ID, task.ID, node, collab.BranchCommand{Type: "start", RequestID: "still-conflict", BranchID: r2.Branch.ID, Epoch: 1, Operation: &op}); e == nil {
		t.Fatal("uncertain tool released shared resource")
	}
	branchDBCommand(t, d, team.ID, task.ID, owner, collab.BranchCommand{Type: "confirm_stopped", RequestID: "confirmed", BranchID: r1.Branch.ID, Revision: r.Branch.Revision, Text: "isolated process verified exited"})
	branchDBCommand(t, d, team.ID, task.ID, node, collab.BranchCommand{Type: "start", RequestID: "now-free", BranchID: r2.Branch.ID, Epoch: 1, Operation: &op})
	store := d.Exploration(task.ExplorationID)
	iid, e := store.AddWorkIntent(ctx, "legacy writer", 1, nil, nil, WorkContract{})
	if e != nil {
		t.Fatal(e)
	}
	claimed, e := store.ClaimIntent(iid, "legacy")
	if e != nil || claimed {
		t.Fatalf("branch mode admitted legacy pool: %v %v", claimed, e)
	}
}

func TestBranchDBAssistanceLedgerCancellationAndBudget(t *testing.T) {
	d, team, member, task, device := branchDBFixture(t)
	enableFixtureTool(t, d, task.ID, device.ID)
	r := branchDBRunning(t, d, team, member, task, device, "source")
	node := collab.BranchActor{MemberID: member.ID, DeviceID: device.ID}
	w := collab.BranchWorkSpec{Title: "reverse explanation", Question: "explain only the supplied artifact", Kind: "reverse", AssetIDs: []string{"fixture"}, Roles: []string{"reverse_static", "reverse_reviewer"}, Budget: 5}
	c := collab.BranchCommand{Type: "assist", RequestID: "assist", BranchID: r.Branch.ID, Epoch: 1, Work: &w}
	a := branchDBCommand(t, d, team.ID, task.ID, node, c)
	branchDBCommand(t, d, team.ID, task.ID, node, c)
	var count int
	var wid int64
	if e := d.QueryRow(`SELECT count(*),min(id) FROM team_branch_workflow_requests WHERE task_id=$1`, task.ID).Scan(&count, &wid); e != nil || count != 1 {
		t.Fatalf("assistance duplicate ledger: %d %v", count, e)
	}
	snap, e := d.BranchSnapshot(context.Background(), team.ID, task.ID, collab.BranchActor{Admin: true}, 0, 0, 100, "")
	if e != nil {
		t.Fatal(e)
	}
	if snap.Project.Pool[1].Spec.WorkflowRequestID != wid || a.Branch.Spec.Budget != 15 {
		t.Fatal("assistance attribution/budget mismatch")
	}
	branchDBCommand(t, d, team.ID, task.ID, collab.BranchActor{MemberID: member.ID}, collab.BranchCommand{Type: "stop", RequestID: "stop-source", BranchID: r.Branch.ID, Revision: a.Branch.Revision})
	var status string
	if e = d.QueryRow(`SELECT status FROM team_branch_workflow_requests WHERE id=$1`, wid).Scan(&status); e != nil || status != "cancelled" {
		t.Fatalf("orphaned assistance %q %v", status, e)
	}
}

func TestBranchDBCrossProjectResourceAndRateGate(t *testing.T) {
	d, team, member, task, device := branchDBFixture(t)
	enableFixtureTool(t, d, task.ID, device.ID)
	first := branchDBRunning(t, d, team, member, task, device, "one")
	second, e := d.CreateTaskWithOptions("second isolated master", "same team resource", TaskCreateOptions{Kind: "pentest"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM tasks WHERE id=$1`, second.ID)
		_, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, second.ExplorationID)
	})
	ctx := context.Background()
	for _, p := range []string{"read", "execute", "manage"} {
		if e = d.AttachTeamTask(ctx, team.ID, second.ID, member.ID, p); e != nil {
			t.Fatal(e)
		}
	}
	if e = d.SetPaused(second.ID, true); e != nil {
		t.Fatal(e)
	}
	policy := first.Policy
	policy.MinToolIntervalMS = 60000
	if _, e = d.CreateBranchProject(ctx, team.ID, second.ID, collab.BranchActor{MemberID: member.ID}, policy); e != nil {
		t.Fatal(e)
	}
	two := branchDBRunning(t, d, team, member, second, device, "two")
	node := collab.BranchActor{MemberID: member.ID, DeviceID: device.ID}
	op := collab.BranchOperation{ID: "resource-op", Epoch: 1, UnitID: 1, Kind: "tool", Role: "worker", Tool: "inspect", InputHash: collab.ContentHash([]byte("fixture"))}
	branchDBCommand(t, d, team.ID, task.ID, node, collab.BranchCommand{Type: "start", RequestID: "start", BranchID: first.Branch.ID, Epoch: 1, Operation: &op})
	try := func(key string) {
		t.Helper()
		if _, e = d.ApplyBranchCommand(ctx, team.ID, second.ID, node, collab.BranchCommand{Type: "start", RequestID: key, BranchID: two.Branch.ID, Epoch: 1, Operation: &op}); e == nil {
			t.Fatal("cross-project resource/rate guard bypassed")
		}
	}
	try("overlap")
	branchDBCommand(t, d, team.ID, task.ID, node, collab.BranchCommand{Type: "end", RequestID: "end", BranchID: first.Branch.ID, Epoch: 1, Operation: &op})
	try("rate")
	if _, e = d.Exec(`UPDATE team_branch_resource_clock SET last_started_at=$2 WHERE team_id=$1`, team.ID, time.Now().Add(-time.Minute*2)); e != nil {
		t.Fatal(e)
	}
	branchDBCommand(t, d, team.ID, second.ID, node, collab.BranchCommand{Type: "start", RequestID: fmt.Sprint("allowed", second.ID), BranchID: two.Branch.ID, Epoch: 1, Operation: &op})
}
