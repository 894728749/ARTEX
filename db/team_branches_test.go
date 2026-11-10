package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/Autumn-27/artex/collab"
)

func branchDBFixture(t *testing.T) (*DB, *Team, *TeamMember, *Task, *TeamDevice) {
	t.Helper()
	d, team, member, task := teamCollabFixture(t)
	ctx := context.Background()
	for _, p := range []string{"read", "execute", "manage", "review"} {
		if e := d.AttachTeamTask(ctx, team.ID, task.ID, member.ID, p); e != nil {
			t.Fatal(e)
		}
	}
	if e := d.SetPaused(task.ID, true); e != nil {
		t.Fatal(e)
	}
	policy := collab.BranchPolicy{Version: 1, Goal: "owned branch fixture", Budget: 80, MaxToolSeconds: 30, Kinds: []string{"pentest", "reverse"}, Assets: []collab.BranchAsset{{ID: "fixture", Target: "https://owned.invalid", Version: "v1"}}, PlannerPrompts: map[string]string{"pentest": "plan owned fixture", "reverse": "plan owned artifact"}, Roles: map[string]collab.ExecutionConfig{}}
	for _, role := range []string{"worker", "reviewer", "reverse_static", "reverse_reviewer"} {
		kind := "pentest"
		if strings.HasPrefix(role, "reverse_") {
			kind = "reverse"
		}
		policy.Roles[role] = collab.ExecutionConfig{Version: 1, Kind: kind, Role: role, SystemPrompt: "owned fixture role", MaxTurns: 8, BudgetSeconds: 30}
	}
	admin := collab.BranchActor{Admin: true}
	if _, e := d.CreateBranchProject(ctx, team.ID, task.ID, admin, policy); e != nil {
		t.Fatal(e)
	}
	for _, p := range collab.BranchPermissions {
		if _, e := d.ApplyBranchCommand(ctx, team.ID, task.ID, admin, collab.BranchCommand{Type: "grant", RequestID: "grant-" + p, MemberID: member.ID, Permission: p}); e != nil {
			t.Fatal(e)
		}
	}
	device, _ := teamCollabDevice(t, d, team, member)
	caps := `{"version":1,"branch_protocol":1,"execution_enabled":true,"roles":["planner","worker","reviewer","reverse_planner","reverse_static","reverse_reviewer"],"role_capabilities":{}}`
	if _, e := d.Exec(`UPDATE team_devices SET capabilities=$2,last_seen_at=NULL WHERE id=$1`, device.ID, caps); e != nil {
		t.Fatal(e)
	}
	return d, team, member, task, device
}

func TestBranchDBAtomicClaimsBudgetAndPrivateProjection(t *testing.T) {
	d, team, member, task, device := branchDBFixture(t)
	ctx := context.Background()
	admin := collab.BranchActor{Admin: true}
	actor := collab.BranchActor{MemberID: member.ID}
	work := collab.BranchWorkSpec{Title: "owned problem", Question: "verify only the owned fixture", Kind: "pentest", AssetIDs: []string{"fixture"}, Roles: []string{"worker", "reviewer"}, Acceptance: []string{"preserve evidence"}, Budget: 50}
	pub, e := d.ApplyBranchCommand(ctx, team.ID, task.ID, admin, collab.BranchCommand{Type: "publish", RequestID: "publish", Work: &work})
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	ids := make(chan int64, 8)
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, e := d.ApplyBranchCommand(ctx, team.ID, task.ID, actor, collab.BranchCommand{Type: "claim", RequestID: fmt.Sprintf("claim-%d", i), WorkID: pub.Receipt.WorkID, DeviceID: device.ID})
			if e != nil {
				errs <- e
				return
			}
			ids <- r.Receipt.BranchID
		}(i)
	}
	wg.Wait()
	close(ids)
	close(errs)
	for e := range errs {
		t.Errorf("idempotent own claim: %v", e)
	}
	var bid int64
	for id := range ids {
		if bid == 0 {
			bid = id
		}
		if id != bid {
			t.Fatalf("duplicate branches: %d %d", bid, id)
		}
	}
	snap, e := d.BranchSnapshot(ctx, team.ID, task.ID, actor, 0, 0, 100, "")
	if e != nil || len(snap.Project.Branches) != 1 {
		t.Fatalf("snapshot branches: %+v %v", snap, e)
	}
	if snap.Project.Branches[0].State != "waiting_ready" {
		t.Fatal("offline device must stay waiting_ready")
	}
	// A second pool work cannot reset the shared allocation.
	work.Title = "extra"
	r, e := d.ApplyBranchCommand(ctx, team.ID, task.ID, admin, collab.BranchCommand{Type: "publish", RequestID: "publish-extra", Work: &work})
	if e == nil {
		_, e = d.ApplyBranchCommand(ctx, team.ID, task.ID, actor, collab.BranchCommand{Type: "claim", RequestID: "claim-extra", WorkID: r.Receipt.WorkID, DeviceID: device.ID})
	}
	if e == nil {
		t.Fatal("over-reservation was accepted")
	}
	// A reader gets summaries, not process/evidence/role configuration.
	reader, e := d.CreateTeamMember(ctx, team.ID, "branch-reader", "unused")
	if e != nil {
		t.Fatal(e)
	}
	if e = d.AttachTeamTask(ctx, team.ID, task.ID, reader.ID, "read"); e != nil {
		t.Fatal(e)
	}
	if _, e = d.ApplyBranchCommand(ctx, team.ID, task.ID, admin, collab.BranchCommand{Type: "grant", RequestID: "reader", MemberID: reader.ID, Permission: "read"}); e != nil {
		t.Fatal(e)
	}
	view, e := d.BranchSnapshot(ctx, team.ID, task.ID, collab.BranchActor{MemberID: reader.ID}, 0, 0, 100, "")
	if e != nil {
		t.Fatal(e)
	}
	if len(view.Events) > 0 || len(view.Project.Policy.Roles) > 0 || len(view.Project.Policy.PlannerPrompts) > 0 || view.Project.Receipts != nil || view.Project.Permissions != nil {
		t.Fatal("private state escaped projection")
	}
	if _, e = d.BranchSnapshot(ctx, team.ID, task.ID, collab.BranchActor{MemberID: reader.ID}, bid, 1, 100, ""); e == nil {
		t.Fatal("reader replay permission bypass")
	}
	if _, e = d.ApplyBranchCommand(ctx, team.ID, task.ID, collab.BranchActor{MemberID: reader.ID}, collab.BranchCommand{Type: "guide", RequestID: "unauthorized-guide", BranchID: bid, Text: "do not execute"}); e == nil {
		t.Fatal("read implied guide permission")
	}
}

func TestBranchDBNodeSequencePermissionRevocationAndSingleMode(t *testing.T) {
	d, team, member, task, device := branchDBFixture(t)
	ctx := context.Background()
	admin := collab.BranchActor{Admin: true}
	owner := collab.BranchActor{MemberID: member.ID}
	node := collab.BranchActor{MemberID: member.ID, DeviceID: device.ID}
	call := func(a collab.BranchActor, c collab.BranchCommand) *collab.BranchReply {
		t.Helper()
		v, e := d.ApplyBranchCommand(ctx, team.ID, task.ID, a, c)
		if e != nil {
			t.Fatalf("%s: %v", c.Type, e)
		}
		return v
	}
	work := collab.BranchWorkSpec{Title: "events", Question: "observe fixture", Kind: "pentest", AssetIDs: []string{"fixture"}, Roles: []string{"worker", "reviewer"}, Acceptance: []string{"evidence"}, Budget: 30}
	pub := call(admin, collab.BranchCommand{Type: "publish", RequestID: "publish", Work: &work})
	claim := call(owner, collab.BranchCommand{Type: "claim", RequestID: "claim", WorkID: pub.Receipt.WorkID, DeviceID: device.ID})
	bid := claim.Branch.ID
	epoch := claim.Branch.Epoch
	beforeResume,e:=d.BranchSnapshot(ctx,team.ID,task.ID,admin,0,0,1,"");if e!=nil{t.Fatal(e)}
	call(admin, collab.BranchCommand{Type: "project_resume", RequestID: "resume-project",Revision:beforeResume.Project.Revision})
	call(node, collab.BranchCommand{Type: "ready", RequestID: "ready", BranchID: bid, Epoch: epoch})
	event := collab.BranchCommand{Type: "event", RequestID: "event-1", BranchID: bid, Epoch: epoch, Event: &collab.BranchEvent{Seq: 1, Kind: "message", Text: "owned observed message"}}
	call(node, event)
	call(node, event)
	bad := event
	bad.RequestID = "event-3"
	bad.Event = &collab.BranchEvent{Seq: 3, Kind: "message", Text: "out of order"}
	if _, e := d.ApplyBranchCommand(ctx, team.ID, task.ID, node, bad); e == nil {
		t.Fatal("out of order event accepted")
	}
	bad = event
	bad.RequestID = "stale"
	bad.Epoch--
	if _, e := d.ApplyBranchCommand(ctx, team.ID, task.ID, node, bad); e == nil {
		t.Fatal("old epoch accepted")
	}
	snap, e := d.BranchSnapshot(ctx, team.ID, task.ID, owner, bid, 0, 200, "")
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, ev := range snap.Events {
		if ev.Text == event.Event.Text {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("message count=%d", count)
	}
	// Discussion is stored but must never become pending machine guidance.
	call(owner, collab.BranchCommand{Type: "discuss", RequestID: "discuss", BranchID: bid, Text: "a suggestion, not a command"})
	poll, e := d.BranchDevicePoll(ctx, device)
	if e != nil || len(poll) != 1 || len(poll[0].Branch.Guidance) != 0 {
		t.Fatalf("discussion crossed instruction boundary: %+v %v", poll, e)
	}
	call(admin, collab.BranchCommand{Type: "grant", RequestID: "revoke", MemberID: member.ID, Permission: "execute", Revoke: true})
	if _, e = d.ApplyBranchCommand(ctx, team.ID, task.ID, node, collab.BranchCommand{Type: "heartbeat", RequestID: "revoked-heartbeat", BranchID: bid, Epoch: epoch}); e == nil {
		t.Fatal("revoked node still authorized")
	}
	enabled, e := d.BranchMode(ctx, task.ID)
	if e != nil || !enabled {
		t.Fatal("new mode not persisted")
	}
	enabled, e = d.BranchMode(ctx, 0)
	if e != nil || enabled {
		t.Fatal("legacy default changed")
	}
	raw, _ := json.Marshal(snap.Project)
	if strings.Contains(string(raw), "token_hash") || strings.Contains(string(raw), "password_hash") {
		t.Fatal("credential escaped snapshot")
	}
}
