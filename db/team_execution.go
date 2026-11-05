package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

func (d *DB) UpdateTeamDeviceCapabilities(ctx context.Context, deviceID int64, token string, caps json.RawMessage) error {
	if !validJSONSnapshot(caps) {
		return fmt.Errorf("invalid device capabilities")
	}
	r, err := d.ExecContext(ctx, `UPDATE team_devices SET capabilities=$3::jsonb,last_seen_at=now() WHERE id=$1 AND token_hash=$2 AND revoked_at IS NULL AND EXISTS(SELECT 1 FROM team_members m WHERE m.id=team_devices.owner_member_id AND m.revoked_at IS NULL)`, deviceID, teamHash(token), string(caps))
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return ErrTeamCollaborationDenied
	}
	return nil
}

func (d *DB) ListTeamExecutionAssignments(ctx context.Context, teamID, memberID, taskID int64) ([]TeamExecutionAssignment, error) {
	q := `SELECT a.id,a.team_id,a.task_id,a.intent_id,a.device_id,a.member_id,a.epoch,a.attempt,a.lease_until,a.state,jsonb_build_object('role',a.config_snapshot->>'role'),'{}'::jsonb,a.created_at,CASE WHEN a.result IS NULL THEN NULL ELSE (a.result-'evidence') || jsonb_build_object('evidence_count',jsonb_array_length(COALESCE(a.result->'evidence','[]'::jsonb))) END,a.review_member_id,a.review_decision,a.review_note,a.reviewed_at FROM team_execution_assignments a WHERE a.team_id=$1 AND ($2=0 OR (EXISTS(SELECT 1 FROM team_members m WHERE m.id=$2 AND m.team_id=a.team_id AND m.revoked_at IS NULL) AND EXISTS(SELECT 1 FROM team_task_permissions p JOIN team_members m ON m.id=p.member_id AND m.revoked_at IS NULL WHERE p.team_id=a.team_id AND p.task_id=a.task_id AND p.member_id=$2 AND p.permission='read'))) AND ($3=0 OR a.task_id=$3) ORDER BY a.id DESC LIMIT 100`
	rows, e := d.QueryContext(ctx, q, teamID, memberID, taskID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []TeamExecutionAssignment{}
	for rows.Next() {
		var a TeamExecutionAssignment
		var result []byte
		var reviewer sql.NullInt64
		var decision sql.NullString
		var note sql.NullString
		var reviewed sql.NullTime
		if e = rows.Scan(&a.ID, &a.TeamID, &a.TaskID, &a.IntentID, &a.DeviceID, &a.MemberID, &a.Epoch, &a.Attempt, &a.LeaseUntil, &a.State, &a.Config, &a.Input, &a.CreatedAt, &result, &reviewer, &decision, &note, &reviewed); e != nil {
			return nil, e
		}
		a.Result = result
		if reviewer.Valid {
			a.ReviewMemberID = &reviewer.Int64
		}
		if decision.Valid {
			a.ReviewDecision = decision.String
		}
		if note.Valid {
			a.ReviewNote = note.String
		}
		if reviewed.Valid {
			a.ReviewedAt = &reviewed.Time
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (d *DB) GetTeamExecutionAssignment(ctx context.Context, id, deviceID int64, token string, epoch int64) (*TeamExecutionAssignment, error) {
	return scanTeamAssignment(d.QueryRowContext(ctx, `SELECT `+teamAssignmentCols+` FROM team_execution_assignments a WHERE a.id=$1 AND a.device_id=$2 AND a.epoch=$3 AND EXISTS(SELECT 1 FROM team_devices d JOIN team_members m ON m.id=d.owner_member_id WHERE d.id=a.device_id AND d.token_hash=$4 AND d.revoked_at IS NULL AND m.revoked_at IS NULL) AND EXISTS(SELECT 1 FROM team_task_permissions p JOIN team_members m ON m.id=p.member_id AND m.revoked_at IS NULL WHERE p.team_id=a.team_id AND p.task_id=a.task_id AND p.member_id=a.member_id AND p.permission='execute') AND EXISTS(SELECT 1 FROM team_task_permissions p JOIN team_members m ON m.id=p.member_id AND m.revoked_at IS NULL WHERE p.team_id=a.team_id AND p.task_id=a.task_id AND p.member_id=a.member_id AND p.permission='read') AND EXISTS(SELECT 1 FROM tasks t WHERE t.id=a.task_id AND t.deleted_at IS NULL AND t.archived_at IS NULL)`, id, deviceID, epoch, teamHash(token)))
}

func (d *DB) GetTeamExecutionForMember(ctx context.Context, teamID, id, memberID int64) (*TeamExecutionAssignment, error) {
	return scanTeamAssignment(d.QueryRowContext(ctx, `SELECT `+teamAssignmentCols+` FROM team_execution_assignments a WHERE a.id=$1 AND a.team_id=$2 AND EXISTS(SELECT 1 FROM tasks t WHERE t.id=a.task_id AND t.deleted_at IS NULL AND t.archived_at IS NULL) AND ($3::bigint=0 OR EXISTS(SELECT 1 FROM team_task_permissions p JOIN team_members m ON m.id=p.member_id AND m.revoked_at IS NULL WHERE p.team_id=a.team_id AND p.task_id=a.task_id AND p.member_id=$3 AND p.permission='read'))`, id, teamID, memberID))
}

func (d *DB) ReviewTeamExecutionAssignment(ctx context.Context, teamID, assignmentID, reviewerID int64, decision, note string) error {
	if (decision != "accept" && decision != "reject") || strings.TrimSpace(note) == "" || len(note) > 8192 {
		return fmt.Errorf("invalid review decision")
	}
	tx, e := d.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var task, intent, assignee, device, epoch int64
	e = tx.QueryRowContext(ctx, `SELECT task_id,intent_id,member_id,device_id,epoch FROM team_execution_assignments WHERE id=$1 AND team_id=$2`, assignmentID, teamID).Scan(&task, &intent, &assignee, &device, &epoch)
	if e != nil {
		return ErrTeamCollaborationDenied
	}
	var exp int64
	e = tx.QueryRowContext(ctx, `SELECT exploration_id FROM tasks WHERE id=$1 AND deleted_at IS NULL AND archived_at IS NULL AND status NOT IN ('done','failed','timeout','finalizing') FOR UPDATE`, task).Scan(&exp)
	if e != nil {
		return ErrTeamCollaborationDenied
	}
	if _, e = tx.ExecContext(ctx, `SELECT id FROM explorations WHERE id=$1 FOR UPDATE`, exp); e != nil {
		return e
	}
	if reviewerID == assignee {
		return ErrTeamCollaborationDenied
	}
	for _, perm := range []string{"read", "review"} {
		if e = teamPermissionTx(ctx, tx, teamID, task, reviewerID, perm); e != nil {
			return e
		}
	}
	if _, e = tx.ExecContext(ctx, `SELECT id FROM team_devices WHERE id=$1 FOR UPDATE`, device); e != nil {
		return e
	}
	var state string
	var oldReviewer sql.NullInt64
	var oldDecision sql.NullString
	var oldNote string
	e = tx.QueryRowContext(ctx, `SELECT state,review_member_id,review_decision,review_note FROM team_execution_assignments WHERE id=$1 AND team_id=$2 AND epoch=$3 FOR UPDATE`, assignmentID, teamID, epoch).Scan(&state, &oldReviewer, &oldDecision, &oldNote)
	if e != nil {
		return e
	}
	if oldDecision.Valid {
		if oldReviewer.Int64 == reviewerID && oldDecision.String == decision && oldNote == note {
			return tx.Commit()
		}
		return ErrTeamCollaborationConflict
	}
	if state != "completed" {
		return ErrTeamCollaborationConflict
	}
	var n int64
	if e = tx.QueryRowContext(ctx, `SELECT COALESCE(max(epoch),0) FROM team_execution_assignments WHERE intent_id=$1`, intent).Scan(&n); e != nil {
		return e
	}
	if n != epoch {
		return ErrTeamCollaborationConflict
	}
	var payload []byte
	var nodeState string
	e = tx.QueryRowContext(ctx, `SELECT payload,state FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 AND kind='intent' FOR UPDATE`, intent, exp).Scan(&payload, &nodeState)
	if e != nil {
		return ErrTeamCollaborationDenied
	}
	if nodeState != "paused" && nodeState != "open" && nodeState != "waiting" {
		return ErrTeamCollaborationConflict
	}
	var candidate []byte
	if e = tx.QueryRowContext(ctx, `SELECT result FROM team_execution_assignments WHERE id=$1`, assignmentID).Scan(&candidate); e != nil {
		return e
	}
	if decision == "accept" {
		var resultObj map[string]any
		_ = json.Unmarshal(candidate, &resultObj)
		summary, _ := resultObj["summary"].(string)
		if summary == "" {
			summary = "Remote execution candidate awaiting intent acceptance"
		}
		fact := map[string]any{"summary": summary, "acceptance_status": "candidate_unaccepted", "team_result": json.RawMessage(candidate), "source": map[string]any{"kind": "team_execution_assignment", "assignment_id": assignmentID, "task_id": task, "intent_id": intent, "member_id": assignee, "device_id": device, "epoch": epoch}, "team_evidence": resultObj["evidence"], "confidence": "member_reviewed_candidate", "evidence": "See immutable team_result evidence and submission provenance; business acceptance remains pending"}
		var factID int64
		b, _ := json.Marshal(fact)
		if e = tx.QueryRowContext(ctx, `INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin) VALUES($1,'fact',$2::jsonb,0,'confirmed','team_review') RETURNING id`, exp, string(b)).Scan(&factID); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO exploration_edges(exploration_id,src_id,dst_id,rel) VALUES($1,$2,$3,'derived_from') ON CONFLICT DO NOTHING`, exp, factID, intent); e != nil {
			return e
		}
	}
	var current int64
	if e = tx.QueryRowContext(ctx, `SELECT COALESCE(max(epoch),0) FROM team_execution_assignments WHERE intent_id=$1`, intent).Scan(&current); e != nil {
		return e
	}
	if current != epoch {
		return ErrTeamCollaborationConflict
	}
	_, e = tx.ExecContext(ctx, `UPDATE team_execution_assignments SET review_member_id=$2,review_decision=$3,review_note=$4,reviewed_at=now() WHERE id=$1 AND review_decision IS NULL`, assignmentID, reviewerID, decision, note)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='open',owner=NULL,payload=payload||jsonb_build_object('remote_review_receipt',jsonb_build_object('assignment_id',$2::bigint,'decision',$3::text,'reviewer_id',$4::bigint)) WHERE id=$1 AND state='paused' AND payload->'contract'->>'remote_epoch' IS NULL`, intent, assignmentID, decision, reviewerID)
	if e != nil {
		return e
	}
	return tx.Commit()
}

func (d *DB) CancelTeamExecutionByMember(ctx context.Context, teamID, assignmentID, actorMemberID int64) error {
	tx, e := d.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var task, intent, device, epoch int64
	e = tx.QueryRowContext(ctx, `SELECT task_id,intent_id,device_id,epoch FROM team_execution_assignments WHERE id=$1 AND team_id=$2`, assignmentID, teamID).Scan(&task, &intent, &device, &epoch)
	if e != nil {
		return ErrTeamCollaborationDenied
	}
	var exp int64
	e = tx.QueryRowContext(ctx, `SELECT exploration_id FROM tasks WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, task).Scan(&exp)
	if e != nil {
		return ErrTeamCollaborationDenied
	}
	if _, e = tx.ExecContext(ctx, `SELECT id FROM explorations WHERE id=$1 FOR UPDATE`, exp); e != nil {
		return e
	}
	if actorMemberID != 0 {
		if e = teamPermissionTx(ctx, tx, teamID, task, actorMemberID, "manage"); e != nil {
			return e
		}
	}
	if _, e = tx.ExecContext(ctx, `SELECT id FROM team_devices WHERE id=$1 FOR UPDATE`, device); e != nil {
		return e
	}
	var currentState string
	e = tx.QueryRowContext(ctx, `SELECT state FROM team_execution_assignments WHERE id=$1 AND epoch=$2 FOR UPDATE`, assignmentID, epoch).Scan(&currentState)
	if e != nil {
		return e
	}
	if currentState == "cancelled" {
		return tx.Commit()
	}
	if currentState != "assigned" && currentState != "claimed" && currentState != "running" {
		return ErrTeamCollaborationConflict
	}
	if _, e = tx.ExecContext(ctx, `UPDATE team_execution_assignments SET state='cancelled',finished_at=now() WHERE id=$1 AND epoch=$2`, assignmentID, epoch); e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='paused',owner=NULL,payload=payload #- '{contract,remote_assignment_pending}' #- '{contract,remote_device_id}' #- '{contract,remote_epoch}' WHERE id=$1 AND state IN ('open','waiting','running') AND payload->'contract'->>'remote_device_id'=$2 AND payload->'contract'->>'remote_epoch'=$3`, intent, fmt.Sprint(device), fmt.Sprint(epoch))
	if e != nil {
		return e
	}
	return tx.Commit()
}
