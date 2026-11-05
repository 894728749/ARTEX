package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func teamCollabFixture(t *testing.T) (*DB, *Team, *TeamMember, *Task) {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTaskWithOptions("team fixture", "synthetic collaboration test", TaskCreateOptions{Kind: "pentest"})
	if err != nil {
		d.Close()
		t.Fatal(err)
	}
	team, err := d.CreateTeam(context.Background(), "synthetic team")
	if err != nil {
		d.Close()
		t.Fatal(err)
	}
	member, err := d.CreateTeamMember(context.Background(), team.ID, "alice", "test-password-hash")
	if err != nil {
		d.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM team_execution_assignments WHERE team_id=$1`, team.ID)
		_, _ = d.Exec(`DELETE FROM teams WHERE id=$1`, team.ID)
		_, _ = d.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID)
		_, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, task.ExplorationID)
		_ = d.Close()
	})
	return d, team, member, task
}

func teamCollabDevice(t *testing.T, d *DB, team *Team, member *TeamMember) (*TeamDevice, string) {
	t.Helper()
	ctx := context.Background()
	pair, err := d.CreateTeamDevicePairing(ctx, team.ID, member.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	device, token, err := d.PairTeamDevice(ctx, pair, "node", json.RawMessage(`{"os":"test"}`))
	if err != nil {
		t.Fatal(err)
	}
	return device, token
}

func TestTeamMemberSecretOmittedAndPairingOneTime(t *testing.T) {
	d, team, member, _ := teamCollabFixture(t)
	ctx := context.Background()
	got, err := d.GetTeamMember(ctx, team.ID, member.ID)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(got)
	if string(b) == "" || containsJSONKey(b, "password_hash") {
		t.Fatalf("member exposed secret: %s", b)
	}
	rows, err := d.ListTeamMembers(ctx, team.ID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("members=%d err=%v", len(rows), err)
	}
	pair, err := d.CreateTeamDevicePairing(ctx, team.ID, member.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	device, token, err := d.PairTeamDevice(ctx, pair, "node", json.RawMessage(`{"os":"linux"}`))
	if err != nil {
		t.Fatal(err)
	}
	if device.ID < 1 || token == "" {
		t.Fatal("pair did not return one-time device token")
	}
	authed, err := d.AuthenticateTeamDevice(ctx, token)
	if err != nil || authed.ID != device.ID {
		t.Fatalf("auth device=%v err=%v", authed, err)
	}
	if _, _, err = d.PairTeamDevice(ctx, pair, "second", json.RawMessage(`{}`)); !errors.Is(err, ErrTeamCollaborationDenied) {
		t.Fatalf("pair token reused: %v", err)
	}
	if err = d.RevokeTeamMember(ctx, team.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.AuthenticateTeamDevice(ctx, token); !errors.Is(err, ErrTeamCollaborationDenied) {
		t.Fatalf("revoked member device accepted: %v", err)
	}
}

func TestTeamTaskPermissionReadsAndResourceRespectRevocation(t *testing.T) {
	d, team, member, task := teamCollabFixture(t)
	ctx := context.Background()
	if err := d.AttachTeamTask(ctx, team.ID, task.ID, member.ID, "read"); err != nil {
		t.Fatal(err)
	}
	if err := d.AttachTeamTask(ctx, team.ID, task.ID, member.ID, "manage"); err != nil {
		t.Fatal(err)
	}
	if err := d.CheckTeamTaskPermission(ctx, team.ID, task.ID, member.ID, "read"); err != nil {
		t.Fatalf("authorized read permission rejected: %v", err)
	}
	if err := d.CheckTeamTaskPermission(ctx, team.ID, task.ID, member.ID, "manage"); err != nil {
		t.Fatalf("authorized manage permission rejected: %v", err)
	}
	if _, err := d.PutTeamResource(ctx, team.ID, task.ID, member.ID, "test-resource", json.RawMessage(`{"ok":true}`)); err != nil {
		t.Fatalf("put resource: %v", err)
	}
	resource, err := d.GetTeamResource(ctx, team.ID, task.ID, member.ID, "test-resource")
	if err != nil || resource == nil || string(resource.Value) != `{"ok": true}` {
		t.Fatalf("authorized resource read: resource=%+v err=%v", resource, err)
	}

	unauthorized, err := d.CreateTeamMember(ctx, team.ID, "bob", "test-password-hash")
	if err != nil {
		t.Fatal(err)
	}
	if err = d.CheckTeamTaskPermission(ctx, team.ID, task.ID, unauthorized.ID, "read"); !errors.Is(err, ErrTeamCollaborationDenied) {
		t.Fatalf("unauthorized member read permission: %v", err)
	}
	if _, err = d.GetTeamResource(ctx, team.ID, task.ID, unauthorized.ID, "test-resource"); !errors.Is(err, ErrTeamCollaborationDenied) {
		t.Fatalf("unauthorized member read resource: %v", err)
	}

	if err = d.RevokeTeamMember(ctx, team.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	if err = d.CheckTeamTaskPermission(ctx, team.ID, task.ID, member.ID, "read"); !errors.Is(err, ErrTeamCollaborationDenied) {
		t.Fatalf("revoked member retained read permission: %v", err)
	}
	if _, err = d.GetTeamResource(ctx, team.ID, task.ID, member.ID, "test-resource"); !errors.Is(err, ErrTeamCollaborationDenied) {
		t.Fatalf("revoked member read resource: %v", err)
	}
}

func TestTeamAssignmentRequiresPermissionAndCompletionIsCandidate(t *testing.T) {
	d, team, member, task := teamCollabFixture(t)
	ctx := context.Background()
	store := d.Exploration(task.ExplorationID)
	intentID, err := store.AddWorkIntent(ctx, "synthetic assigned work", 1, nil, nil, WorkContract{ResourceKey: "resource-A"})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := d.CreateTeamDevicePairing(ctx, team.ID, member.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	device, token, err := d.PairTeamDevice(ctx, pair, "node", json.RawMessage(`{"cap":"test"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.CreateTeamExecutionAssignment(ctx, team.ID, task.ID, intentID, member.ID, device.ID, time.Hour, json.RawMessage(`{}`), json.RawMessage(`{"target":"synthetic"}`)); !errors.Is(err, ErrTeamCollaborationDenied) {
		t.Fatalf("assignment without execute permission: %v", err)
	}
	if err = d.AttachTeamTask(ctx, team.ID, task.ID, member.ID, "execute"); err != nil {
		t.Fatal(err)
	}
	a, err := d.CreateTeamExecutionAssignment(ctx, team.ID, task.ID, intentID, member.ID, device.ID, time.Hour, json.RawMessage(`{"safe":true}`), json.RawMessage(`{"target":"synthetic"}`))
	if err != nil {
		t.Fatal(err)
	}
	if claimed, err := store.ClaimIntent(intentID, "local-worker"); err != nil || claimed {
		t.Fatalf("local worker claimed remote reservation: %v %v", claimed, err)
	}
	if _, err = d.CreateTeamExecutionAssignment(ctx, team.ID, task.ID, intentID, member.ID, device.ID, time.Hour, json.RawMessage(`{}`), json.RawMessage(`{}`)); !errors.Is(err, ErrTeamCollaborationConflict) {
		t.Fatalf("duplicate active intent: %v", err)
	}
	if _, err = d.ClaimTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch); err != nil {
		t.Fatal(err)
	}
	if changed, err := store.ResetRunningIntents(); err != nil || changed != 0 {
		t.Fatalf("restart reset remote worker: %d %v", changed, err)
	}
	if _, err = d.HeartbeatTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch+1, time.Hour); !errors.Is(err, ErrTeamCollaborationDenied) {
		t.Fatalf("wrong epoch accepted: %v", err)
	}
	if _, err = d.HeartbeatTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err = d.CompleteTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch, json.RawMessage(`{"outcome":"candidate"}`)); err != nil {
		t.Fatal(err)
	}
	var nodeState, assignmentState string
	var result []byte
	if err = d.QueryRow(`SELECT state FROM exploration_nodes WHERE id=$1`, intentID).Scan(&nodeState); err != nil {
		t.Fatal(err)
	}
	if err = d.QueryRow(`SELECT state,result FROM team_execution_assignments WHERE id=$1`, a.ID).Scan(&assignmentState, &result); err != nil {
		t.Fatal(err)
	}
	var resultObject map[string]string
	_ = json.Unmarshal(result, &resultObject)
	if nodeState != "paused" || assignmentState != "completed" || resultObject["outcome"] != "candidate" {
		t.Fatalf("unaccepted completion: intent=%s assignment=%s result=%s", nodeState, assignmentState, result)
	}
}

func TestTeamAssignmentDelegationLeaseAndStateFencing(t *testing.T) {
	d, team, member, target := teamCollabFixture(t)
	ctx := context.Background()
	source, err := d.CreateTaskWithOptions("delegation source", "synthetic", TaskCreateOptions{Kind: "reverse"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM tasks WHERE id=$1`, source.ID)
		_, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, source.ExplorationID)
	})
	request, _, err := d.CreateWorkflowRequest(ctx, workflowRequestInput(source.ID, target.ID, "team-delegate"))
	if err != nil {
		t.Fatal(err)
	}
	intentID, err := d.Exploration(target.ExplorationID).AddWorkIntent(ctx, "delegated synthetic work", 1, nil, nil, WorkContract{WorkflowRequestID: request.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err = d.AttachTeamTask(ctx, team.ID, target.ID, member.ID, "execute"); err != nil {
		t.Fatal(err)
	}
	device, token := teamCollabDevice(t, d, team, member)
	a, err := d.CreateTeamExecutionAssignment(ctx, team.ID, target.ID, intentID, member.ID, device.ID, 2*time.Hour, json.RawMessage(`{}`), json.RawMessage(`{"request":"synthetic"}`))
	if err != nil {
		t.Fatal(err)
	}
	if a.LeaseUntil.After(request.ExpiresAt) || a.LeaseUntil.Before(request.ExpiresAt.Add(-2*time.Second)) {
		t.Fatalf("lease not clamped to workflow deadline: lease=%s deadline=%s", a.LeaseUntil, request.ExpiresAt)
	}
	polled, err := d.PollTeamExecutionAssignments(ctx, device.ID, token, 10)
	if err != nil || len(polled) != 1 || polled[0].ID != a.ID {
		t.Fatalf("poll=%v err=%v", polled, err)
	}
	if _, err = d.HeartbeatTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch, time.Hour); !errors.Is(err, ErrTeamCollaborationConflict) {
		t.Fatalf("heartbeat bypassed claim: %v", err)
	}
	if _, err = d.ClaimTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch+1); !errors.Is(err, ErrTeamCollaborationDenied) {
		t.Fatalf("old epoch was accepted: %v", err)
	}
	claimed, err := d.ClaimTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch)
	if err != nil || claimed.State != "claimed" {
		t.Fatalf("claim=%v err=%v", claimed, err)
	}
	var intentState, intentOwner string
	var attempt int64
	if err = d.QueryRow(`SELECT state,owner,(payload->>'execution_attempt')::bigint FROM exploration_nodes WHERE id=$1`, intentID).Scan(&intentState, &intentOwner, &attempt); err != nil {
		t.Fatal(err)
	}
	if intentState != "running" || intentOwner != fmt.Sprint(device.ID) || attempt != a.Attempt {
		t.Fatalf("claim did not fence intent: state=%s owner=%s attempt=%d", intentState, intentOwner, attempt)
	}
	if again, err := d.ClaimTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch); err != nil || again.State != "claimed" {
		t.Fatalf("idempotent claim=%v err=%v", again, err)
	}
	if _, err = d.HeartbeatTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch, time.Hour); err != nil {
		t.Fatal(err)
	}
	if again, err := d.ClaimTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch); err != nil || again.State != "running" {
		t.Fatalf("repeat claim downgraded running state: assignment=%v err=%v", again, err)
	}
	if _, err = d.Exec(`UPDATE workflow_requests SET status='cancelled' WHERE id=$1`, request.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.HeartbeatTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch, time.Hour); !errors.Is(err, ErrTeamCollaborationDenied) {
		t.Fatalf("transition accepted cancelled delegation: %v", err)
	}
}

func TestTeamResourceLockIsTeamWideAcrossMembersAndTasks(t *testing.T) {
	d, team, memberA, taskA := teamCollabFixture(t)
	ctx := context.Background()
	memberB, err := d.CreateTeamMember(ctx, team.ID, "bob", "test-password-hash")
	if err != nil {
		t.Fatal(err)
	}
	taskB, err := d.CreateTaskWithOptions("team resource task B", "synthetic", TaskCreateOptions{Kind: "pentest"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM tasks WHERE id=$1`, taskB.ID)
		_, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, taskB.ExplorationID)
	})
	if err = d.AttachTeamTask(ctx, team.ID, taskA.ID, memberA.ID, "execute"); err != nil {
		t.Fatal(err)
	}
	if err = d.AttachTeamTask(ctx, team.ID, taskB.ID, memberB.ID, "execute"); err != nil {
		t.Fatal(err)
	}
	deviceA, _ := teamCollabDevice(t, d, team, memberA)
	deviceB, _ := teamCollabDevice(t, d, team, memberB)
	intentA, err := d.Exploration(taskA.ExplorationID).AddWorkIntent(ctx, "resource A", 1, nil, nil, WorkContract{ResourceKey: "shared-fixture"})
	if err != nil {
		t.Fatal(err)
	}
	intentB, err := d.Exploration(taskB.ExplorationID).AddWorkIntent(ctx, "resource B", 1, nil, nil, WorkContract{ResourceKey: "shared-fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.CreateTeamExecutionAssignment(ctx, team.ID, taskA.ID, intentA, memberA.ID, deviceA.ID, time.Hour, json.RawMessage(`{}`), json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err = d.CreateTeamExecutionAssignment(ctx, team.ID, taskB.ID, intentB, memberB.ID, deviceB.ID, time.Hour, json.RawMessage(`{}`), json.RawMessage(`{}`)); !errors.Is(err, ErrTeamCollaborationConflict) {
		t.Fatalf("same team resource assigned to different member/task: %v", err)
	}
}

func TestTeamAssignmentExpiryPausesIntentAndRetainsCandidate(t *testing.T) {
	d, team, member, task := teamCollabFixture(t)
	ctx := context.Background()
	if err := d.AttachTeamTask(ctx, team.ID, task.ID, member.ID, "execute"); err != nil {
		t.Fatal(err)
	}
	device, _ := teamCollabDevice(t, d, team, member)
	intentID, err := d.Exploration(task.ExplorationID).AddWorkIntent(ctx, "expires", 1, nil, nil, WorkContract{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := d.CreateTeamExecutionAssignment(ctx, team.ID, task.ID, intentID, member.ID, device.ID, time.Hour, json.RawMessage(`{}`), json.RawMessage(`{"candidate":"must-stay"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`UPDATE team_execution_assignments SET lease_until=now()-interval '1 second' WHERE id=$1`, a.ID); err != nil {
		t.Fatal(err)
	}
	count, err := d.ReconcileTeamExecutionAssignments(ctx, time.Now().Add(time.Second))
	if err != nil || count != 1 {
		t.Fatalf("reconcile=%d err=%v", count, err)
	}
	var state, intentState string
	var input []byte
	if err = d.QueryRow(`SELECT state,input_snapshot FROM team_execution_assignments WHERE id=$1`, a.ID).Scan(&state, &input); err != nil {
		t.Fatal(err)
	}
	if err = d.QueryRow(`SELECT state FROM exploration_nodes WHERE id=$1`, intentID).Scan(&intentState); err != nil {
		t.Fatal(err)
	}
	if state != "expired" || intentState != "paused" || !strings.Contains(string(input), "must-stay") {
		t.Fatalf("expired result state=%s intent=%s input=%s", state, intentState, input)
	}
}

func TestTeamCommandReceiptPayloadConflict(t *testing.T) {
	d, team, member, _ := teamCollabFixture(t)
	ctx := context.Background()
	first, err := d.RecordTeamCommandReceipt(ctx, team.ID, member.ID, "command-1", json.RawMessage(`{"x":1}`), json.RawMessage(`{"ok":true}`))
	if err != nil || string(first) != `{"ok":true}` {
		t.Fatalf("first=%s err=%v", first, err)
	}
	retry, err := d.RecordTeamCommandReceipt(ctx, team.ID, member.ID, "command-1", json.RawMessage(`{"x":1}`), json.RawMessage(`{"ok":false}`))
	if err != nil || !workflowPayloadEqual(retry, json.RawMessage(`{"ok":true}`)) {
		t.Fatalf("retry=%s err=%v", retry, err)
	}
	if _, err = d.RecordTeamCommandReceipt(ctx, team.ID, member.ID, "command-1", json.RawMessage(`{"x":2}`), json.RawMessage(`{}`)); !errors.Is(err, ErrTeamCollaborationConflict) {
		t.Fatalf("payload mismatch not rejected: %v", err)
	}
}

func containsJSONKey(b []byte, key string) bool {
	var v map[string]any
	_ = json.Unmarshal(b, &v)
	_, ok := v[key]
	return ok
}
