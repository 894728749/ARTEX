package db

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Autumn-27/artex/collab"
)

func TestTeamMessagesFencingRetrySealAndProjection(t *testing.T) {
	d, team, member, task := teamCollabFixture(t)
	ctx := context.Background()
	for _, p := range []string{"read", "execute"} {
		if err := d.AttachTeamTask(ctx, team.ID, task.ID, member.ID, p); err != nil {
			t.Fatal(err)
		}
	}
	device, token := teamCollabDevice(t, d, team, member)
	es := d.Exploration(task.ExplorationID)
	iid, err := es.AddWorkIntent(ctx, "message fixture", 1, nil, nil, WorkContract{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := d.CreateTeamExecutionAssignment(ctx, team.ID, task.ID, iid, member.ID, device.ID, time.Hour, json.RawMessage(`{}`), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.ClaimTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch); err != nil {
		t.Fatal(err)
	}
	input := collab.MessageExchange{Epoch: a.Epoch, Messages: []collab.DeviceMessage{{Seq: 1, Text: "observed candidate"}}}
	if _, err = d.ExchangeTeamMessages(ctx, a.ID, device.ID, token, input); err != nil {
		t.Fatal(err)
	}
	if _, err = d.ExchangeTeamMessages(ctx, a.ID, device.ID, token, input); err != nil {
		t.Fatal(err)
	}
	changed := input
	changed.Messages = []collab.DeviceMessage{{Seq: 1, Text: "mutated"}}
	if _, err = d.ExchangeTeamMessages(ctx, a.ID, device.ID, token, changed); err == nil {
		t.Fatal("changed duplicate accepted")
	}
	if _, err = d.ExchangeTeamMessages(ctx, a.ID, device.ID, "wrong", input); err == nil {
		t.Fatal("wrong token accepted")
	}
	stale := input
	stale.Epoch++
	if _, err = d.ExchangeTeamMessages(ctx, a.ID, device.ID, token, stale); err == nil {
		t.Fatal("stale epoch accepted")
	}
	if err = d.QueueTeamGuidance(ctx, team.ID, task.ID, iid, a.ID, a.Epoch, member.ID, "request-1", "check the boundary"); err != nil {
		t.Fatal(err)
	}
	if err = d.QueueTeamGuidance(ctx, team.ID, task.ID, iid, a.ID, a.Epoch, member.ID, "request-1", "check the boundary"); err != nil {
		t.Fatal(err)
	}
	out, err := d.ExchangeTeamMessages(ctx, a.ID, device.ID, token, collab.MessageExchange{Epoch: a.Epoch, Seal: true})
	if err != nil || out.Sealed || len(out.Guidance) != 1 {
		t.Fatalf("seal lost pending guidance: %+v %v", out, err)
	}
	_, err = es.AppendActivity(Activity{NodeID: &iid, Kind: "tool_result", Summary: "MUST_NOT_SHARE_TOOL", Detail: "secret tool blob"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = es.AppendActivity(Activity{NodeID: &iid, Kind: "thinking", Summary: "MUST_NOT_SHARE_THINKING"})
	if err != nil {
		t.Fatal(err)
	}
	page, more, err := es.MessagePage(ctx, ActivitySessionFilter{NodeID: &iid}, 0, 100)
	if err != nil || more || len(page) != 2 || page[0].Text != "observed candidate" || page[1].GuidanceStatus != "pending" {
		t.Fatalf("projection %+v %v", page, err)
	}
	one, more, err := es.MessagePage(ctx, ActivitySessionFilter{NodeID: &iid}, 0, 1)
	if err != nil || !more || len(one) != 1 {
		t.Fatalf("page %+v %v", one, err)
	}
	older, more, err := es.MessagePage(ctx, ActivitySessionFilter{NodeID: &iid}, one[0].ID, 1)
	if err != nil || more || len(older) != 1 || older[0].ID != page[0].ID {
		t.Fatalf("older %+v %v", older, err)
	}
	forward, more, err := es.MessageSince(ctx, ActivitySessionFilter{NodeID: &iid}, 0, 1)
	if err != nil || !more || len(forward) != 1 || forward[0].ID != page[0].ID {
		t.Fatalf("forward %+v %v", forward, err)
	}
	forward, more, err = es.MessageSince(ctx, ActivitySessionFilter{NodeID: &iid}, forward[0].ID, 1)
	if err != nil || more || len(forward) != 1 || forward[0].ID != page[1].ID {
		t.Fatalf("forward catchup %+v %v", forward, err)
	}
	out, err = d.ExchangeTeamMessages(ctx, a.ID, device.ID, token, collab.MessageExchange{Epoch: a.Epoch, Delivered: []int64{out.Guidance[0].ID}, Seal: true})
	if err != nil || !out.Sealed {
		t.Fatalf("seal %+v %v", out, err)
	}
	if err = d.QueueTeamGuidance(ctx, team.ID, task.ID, iid, a.ID, a.Epoch, member.ID, "late", "too late"); err == nil {
		t.Fatal("late guidance acknowledged")
	}
	page, _, _ = es.MessagePage(ctx, ActivitySessionFilter{NodeID: &iid}, 0, 100)
	if page[1].GuidanceStatus != "delivered" {
		t.Fatalf("delivery state %+v", page)
	}
	if _, err = d.CompleteTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch, json.RawMessage(`{"outcome":"candidate"}`)); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteLocalQueuePreservesLeaseAndUserPause(t *testing.T) {
	d, team, member, task := teamCollabFixture(t)
	ctx := context.Background()
	if err := d.AttachTeamTask(ctx, team.ID, task.ID, member.ID, "execute"); err != nil {
		t.Fatal(err)
	}
	device, token := teamCollabDevice(t, d, team, member)
	iid, err := d.Exploration(task.ExplorationID).AddWorkIntent(ctx, "remote only", 1, nil, nil, WorkContract{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := d.CreateTeamExecutionAssignment(ctx, team.ID, task.ID, iid, member.ID, device.ID, time.Hour, json.RawMessage(`{}`), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	_, parked, err := d.ParkRemoteLocalEngine(ctx, task.ID)
	if err != nil || !parked {
		t.Fatalf("park=%v err=%v", parked, err)
	}
	assignments, err := d.PollTeamExecutionAssignments(ctx, device.ID, token, 1)
	if err != nil || len(assignments) != 1 {
		t.Fatalf("queued lost assignment %v %v", assignments, err)
	}
	if _, err = d.ClaimTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch); err != nil {
		t.Fatal(err)
	}
	if _, err = d.HeartbeatTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`UPDATE tasks SET queue_mode='resume' WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.HeartbeatTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch, time.Minute); err == nil {
		t.Fatal("ordinary queue bypassed")
	}
	if _, err = d.Exec(`UPDATE tasks SET queue_mode='remote_resume',paused=true WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.HeartbeatTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch, time.Minute); err == nil {
		t.Fatal("user pause bypassed")
	}
	if _, err = d.Exec(`UPDATE tasks SET paused=false WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.CompleteTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch, json.RawMessage(`{"outcome":"candidate"}`)); err != nil {
		t.Fatal(err)
	}
	only, err := d.OnlyRemoteWork(ctx, task.ID)
	if err != nil || !only {
		t.Fatal("pending review consumed local slot", err)
	}
	if _, err = d.Exploration(task.ExplorationID).AddWorkIntent(ctx, "local ready", 1, nil, nil, WorkContract{}); err != nil {
		t.Fatal(err)
	}
	only, err = d.OnlyRemoteWork(ctx, task.ID)
	if err != nil || only {
		t.Fatal("mixed work lost local admission", err)
	}
}
