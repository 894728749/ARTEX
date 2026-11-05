package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

type TeamDispatch struct {
	ID           int64           `json:"id"`
	TeamID       int64           `json:"team_id"`
	TaskID       int64           `json:"task_id"`
	IntentID     int64           `json:"intent_id"`
	RequestedBy  int64           `json:"requested_by"`
	Request      json.RawMessage `json:"request"`
	State        string          `json:"state"`
	AssignmentID *int64          `json:"assignment_id,omitempty"`
	LastError    string          `json:"last_error"`
	CreatedAt    time.Time       `json:"created_at"`
	ExpiresAt    time.Time       `json:"expires_at"`
}

func (d *DB) QueueTeamDispatch(ctx context.Context, team, task, intent, actor int64, request, expected json.RawMessage) (int64, error) {
	if !json.Valid(request) || len(request) > 128<<10 {
		return 0, fmt.Errorf("invalid dispatch request")
	}
	tx, e := d.BeginTx(ctx, nil)
	if e != nil {
		return 0, e
	}
	defer tx.Rollback()
	if e = LockTaskEvidenceTx(tx, task); e != nil {
		return 0, e
	}
	var exp int64
	if e = tx.QueryRowContext(ctx, `SELECT exploration_id FROM tasks WHERE id=$1 AND deleted_at IS NULL AND archived_at IS NULL AND status NOT IN ('done','failed','timeout','finalizing') FOR UPDATE`, task).Scan(&exp); e != nil {
		return 0, ErrTeamCollaborationDenied
	}
	if _, e = tx.ExecContext(ctx, `SELECT id FROM explorations WHERE id=$1 FOR UPDATE`, exp); e != nil {
		return 0, e
	}
	if actor != 0 {
		for _, p := range []string{"read", "manage"} {
			if e = teamPermissionTx(ctx, tx, team, task, actor, p); e != nil {
				return 0, e
			}
		}
	}
	var valid bool
	if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM team_tasks WHERE team_id=$1 AND task_id=$2)`, team, task).Scan(&valid); e != nil || !valid {
		return 0, ErrTeamCollaborationDenied
	}
	var raw []byte
	var state string
	if e = tx.QueryRowContext(ctx, `SELECT payload,state FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 AND kind='intent' FOR UPDATE`, intent, exp).Scan(&raw, &state); e != nil {
		return 0, e
	}
	var equal bool
	if e = tx.QueryRowContext(ctx, `SELECT $1::jsonb=$2::jsonb`, string(raw), string(expected)).Scan(&equal); e != nil {
		return 0, e
	}
	var payload map[string]any
	_ = json.Unmarshal(raw, &payload)
	contract, _ := payload["contract"].(map[string]any)
	if !equal || (state != "open" && state != "waiting") || contract["remote_assignment_pending"] == true || contract["remote_dispatch_pending"] == true {
		return 0, ErrTeamCollaborationConflict
	}
	var id int64
	e = tx.QueryRowContext(ctx, `INSERT INTO team_dispatch_queue(team_id,task_id,intent_id,requested_by,request) VALUES($1,$2,$3,$4,$5) RETURNING id`, team, task, intent, actor, string(request)).Scan(&id)
	if e != nil {
		return 0, e
	}
	if contract == nil {
		contract = map[string]any{}
	}
	contract["remote_dispatch_pending"] = true
	contract["remote_dispatch_id"] = id
	payload["contract"] = contract
	raw, e = json.Marshal(payload)
	if e != nil {
		return 0, e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE exploration_nodes SET payload=$2::jsonb WHERE id=$1`, intent, string(raw)); e != nil {
		return 0, e
	}
	return id, tx.Commit()
}

func (d *DB) ListTeamDispatch(ctx context.Context, team, task int64, queuedOnly bool) ([]TeamDispatch, error) {
	query := `SELECT id,team_id,task_id,intent_id,requested_by,request,state,assignment_id,last_error,created_at,expires_at FROM team_dispatch_queue WHERE ($1::bigint=0 OR team_id=$1) AND ($2::bigint=0 OR task_id=$2) ORDER BY created_at DESC,id DESC LIMIT 100`
	if queuedOnly {
		query = `SELECT id,team_id,task_id,intent_id,requested_by,request,state,assignment_id,last_error,created_at,expires_at FROM team_dispatch_queue WHERE ($1::bigint=0 OR team_id=$1) AND ($2::bigint=0 OR task_id=$2) AND state='queued' ORDER BY last_attempt_at,id LIMIT 100`
	}
	rows, e := d.QueryContext(ctx, query, team, task)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []TeamDispatch{}
	for rows.Next() {
		var v TeamDispatch
		if e = rows.Scan(&v.ID, &v.TeamID, &v.TaskID, &v.IntentID, &v.RequestedBy, &v.Request, &v.State, &v.AssignmentID, &v.LastError, &v.CreatedAt, &v.ExpiresAt); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (d *DB) CancelTeamDispatch(ctx context.Context, team, task, id, actor int64, blocked bool, note string) error {
	tx, e := d.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = LockTaskEvidenceTx(tx, task); e != nil {
		return e
	}
	var exp int64
	if e = tx.QueryRowContext(ctx, `SELECT exploration_id FROM tasks WHERE id=$1 FOR UPDATE`, task).Scan(&exp); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `SELECT id FROM explorations WHERE id=$1 FOR UPDATE`, exp); e != nil {
		return e
	}
	if actor != 0 {
		for _, p := range []string{"read", "manage"} {
			if e = teamPermissionTx(ctx, tx, team, task, actor, p); e != nil {
				return e
			}
		}
	}
	var intent int64
	if e = tx.QueryRowContext(ctx, `SELECT intent_id FROM team_dispatch_queue WHERE id=$1 AND team_id=$2 AND task_id=$3 AND state='queued' FOR UPDATE`, id, team, task).Scan(&intent); e != nil {
		return ErrTeamCollaborationConflict
	}
	state := "cancelled"
	if blocked {
		state = "blocked"
	}
	if _, e = tx.ExecContext(ctx, `UPDATE team_dispatch_queue SET state=$2,last_error=$3 WHERE id=$1`, id, state, note); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='paused',owner=NULL,payload=payload #- '{contract,remote_dispatch_pending}' #- '{contract,remote_dispatch_id}' WHERE id=$1 AND payload->'contract'->>'remote_dispatch_id'=$2`, intent, fmt.Sprint(id)); e != nil {
		return e
	}
	return tx.Commit()
}

func (d *DB) TeamAvailableDevices(ctx context.Context, team, task int64) ([]int64, error) {
	rows, e := d.QueryContext(ctx, `SELECT d.id FROM team_devices d JOIN team_members m ON m.id=d.owner_member_id AND m.revoked_at IS NULL WHERE d.team_id=$1 AND d.revoked_at IS NULL AND d.last_seen_at>now()-interval '30 seconds' AND d.capabilities->>'execution_enabled'='true' AND EXISTS(SELECT 1 FROM team_task_permissions p WHERE p.team_id=d.team_id AND p.task_id=$2 AND p.member_id=d.owner_member_id AND p.permission='read') AND EXISTS(SELECT 1 FROM team_task_permissions p WHERE p.team_id=d.team_id AND p.task_id=$2 AND p.member_id=d.owner_member_id AND p.permission='execute') AND NOT EXISTS(SELECT 1 FROM team_execution_assignments a WHERE a.device_id=d.id AND a.state IN ('assigned','claimed','running')) ORDER BY (SELECT count(*) FROM team_execution_assignments a WHERE a.device_id=d.id),d.id`, team, task)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []int64{}
	for rows.Next() {
		var id int64
		if e = rows.Scan(&id); e != nil {
			return nil, e
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
