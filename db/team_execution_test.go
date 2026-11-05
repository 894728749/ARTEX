package db

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestTeamExecutionReceiptAndIndependentReview(t *testing.T) {
	d, team, submitter, task := teamCollabFixture(t)
	ctx := context.Background()
	reviewer, err := d.CreateTeamMember(ctx, team.ID, "reviewer", "test-password-hash")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct {
		member int64
		perm   string
	}{{submitter.ID, "read"}, {submitter.ID, "execute"}, {reviewer.ID, "read"}, {reviewer.ID, "review"}} {
		if err = d.AttachTeamTask(ctx, team.ID, task.ID, p.member, p.perm); err != nil {
			t.Fatal(err)
		}
	}
	device, token := teamCollabDevice(t, d, team, submitter)
	intent, err := d.Exploration(task.ExplorationID).AddWorkIntent(ctx, "review candidate", 1, nil, nil, WorkContract{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := d.CreateTeamExecutionAssignment(ctx, team.ID, task.ID, intent, submitter.ID, device.ID, time.Hour, json.RawMessage(`{}`), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.ClaimTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch); err != nil {
		t.Fatal(err)
	}
	if _, err = d.HeartbeatTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch, time.Hour); err != nil {
		t.Fatal(err)
	}
	result := json.RawMessage(`{"candidate":"not accepted"}`)
	if _, err = d.CompleteTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch, result); err != nil {
		t.Fatal(err)
	}
	if _, err = d.CompleteTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch, json.RawMessage(`{"candidate":"not accepted"}`)); err != nil {
		t.Fatalf("equivalent retry: %v", err)
	}
	if _, err = d.CompleteTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch, json.RawMessage(`{"candidate":"changed"}`)); !errors.Is(err, ErrTeamCollaborationConflict) {
		t.Fatalf("changed retry: %v", err)
	}
	if err = d.ReviewTeamExecutionAssignment(ctx, team.ID, a.ID, submitter.ID, "accept", "self review"); !errors.Is(err, ErrTeamCollaborationDenied) {
		t.Fatalf("submitter reviewed own result: %v", err)
	}
	if _, err = d.ExecContext(ctx, `DELETE FROM team_task_permissions WHERE team_id=$1 AND task_id=$2 AND member_id=$3 AND permission='review'`, team.ID, task.ID, reviewer.ID); err != nil {
		t.Fatal(err)
	}
	if err = d.ReviewTeamExecutionAssignment(ctx, team.ID, a.ID, reviewer.ID, "accept", "revoked"); !errors.Is(err, ErrTeamCollaborationDenied) {
		t.Fatalf("revoked reviewer accepted: %v", err)
	}
	if err = d.AttachTeamTask(ctx, team.ID, task.ID, reviewer.ID, "review"); err != nil {
		t.Fatal(err)
	}
	if err = d.ReviewTeamExecutionAssignment(ctx, team.ID, a.ID, reviewer.ID, "accept", "checked independently"); err != nil {
		t.Fatal(err)
	}
	if err = d.ReviewTeamExecutionAssignment(ctx, team.ID, a.ID, reviewer.ID, "accept", "checked independently"); err != nil {
		t.Fatalf("review retry: %v", err)
	}
	var nodeState, review string
	if err = d.QueryRowContext(ctx, `SELECT state FROM exploration_nodes WHERE id=$1`, intent).Scan(&nodeState); err != nil {
		t.Fatal(err)
	}
	if nodeState != "open" {
		t.Fatalf("accepted candidate auto-completed intent: %s", nodeState)
	}
	if err = d.QueryRowContext(ctx, `SELECT review_decision FROM team_execution_assignments WHERE id=$1`, a.ID).Scan(&review); err != nil {
		t.Fatal(err)
	}
	if review != "accept" {
		t.Fatalf("review decision=%s", review)
	}
	var facts int
	if err = d.QueryRowContext(ctx, `SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1 AND kind='fact' AND payload->'source'->>'assignment_id'=($2::bigint)::text`, task.ExplorationID, a.ID).Scan(&facts); err != nil {
		t.Fatal(err)
	}
	if facts != 1 {
		t.Fatalf("candidate fact count=%d", facts)
	}
}

func TestTeamExecutionReadRevocationAndCancellation(t *testing.T) {
	d, team, member, task := teamCollabFixture(t)
	ctx := context.Background()
	if err := d.AttachTeamTask(ctx, team.ID, task.ID, member.ID, "read"); err != nil {
		t.Fatal(err)
	}
	if err := d.AttachTeamTask(ctx, team.ID, task.ID, member.ID, "execute"); err != nil {
		t.Fatal(err)
	}
	if err := d.AttachTeamTask(ctx, team.ID, task.ID, member.ID, "manage"); err != nil {
		t.Fatal(err)
	}
	device, _ := teamCollabDevice(t, d, team, member)
	intent, err := d.Exploration(task.ExplorationID).AddWorkIntent(ctx, "cancel me", 1, nil, nil, WorkContract{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := d.CreateTeamExecutionAssignment(ctx, team.ID, task.ID, intent, member.ID, device.ID, time.Hour, json.RawMessage(`{}`), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := d.ListTeamExecutionAssignments(ctx, team.ID, member.ID, 0)
	if err != nil || len(rows) != 1 {
		t.Fatalf("list=%d err=%v", len(rows), err)
	}
	if _, err = d.ExecContext(ctx, `DELETE FROM team_task_permissions WHERE team_id=$1 AND task_id=$2 AND member_id=$3 AND permission='read'`, team.ID, task.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	rows, err = d.ListTeamExecutionAssignments(ctx, team.ID, member.ID, 0)
	if err != nil || len(rows) != 0 {
		t.Fatalf("revoked read still listed: %d %v", len(rows), err)
	}
	if err = d.CancelTeamExecutionByMember(ctx, team.ID, a.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	var state, intentState string
	if err = d.QueryRowContext(ctx, `SELECT state FROM team_execution_assignments WHERE id=$1`, a.ID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if err = d.QueryRowContext(ctx, `SELECT state FROM exploration_nodes WHERE id=$1`, intent).Scan(&intentState); err != nil {
		t.Fatal(err)
	}
	if state != "cancelled" || intentState != "paused" {
		t.Fatalf("cancel state=%s intent=%s", state, intentState)
	}
}
