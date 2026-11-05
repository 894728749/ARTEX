package db

import (
	"context"
	"database/sql"
)

func (d *DB) ListTeams(ctx context.Context, memberID int64) ([]Team, error) {
	rows, err := d.QueryContext(ctx, `SELECT t.id,t.name,t.created_at FROM teams t WHERE $1::bigint=0 OR EXISTS(SELECT 1 FROM team_members m WHERE m.id=$1 AND m.team_id=t.id AND m.revoked_at IS NULL) ORDER BY t.id`, memberID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Team{}
	for rows.Next() {
		var v Team
		if err = rows.Scan(&v.ID, &v.Name, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Credentials are used only for password verification, never workspace JSON.
func (d *DB) TeamMemberCredentials(ctx context.Context, teamID int64, login string) (int64, string, error) {
	var id int64
	var hash string
	err := d.QueryRowContext(ctx, `SELECT id,password_hash FROM team_members WHERE team_id=$1 AND login=$2 AND revoked_at IS NULL`, teamID, login).Scan(&id, &hash)
	return id, hash, err
}

type TeamWorkspaceTask struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
}

func (d *DB) TeamWorkspaceTasks(ctx context.Context, teamID, memberID int64) ([]TeamWorkspaceTask, error) {
	rows, err := d.QueryContext(ctx, `SELECT t.id,COALESCE(t.name,''),t.kind,t.status FROM tasks t JOIN team_tasks tt ON tt.task_id=t.id WHERE tt.team_id=$1 AND t.deleted_at IS NULL AND t.archived_at IS NULL AND ($2::bigint=0 OR EXISTS(SELECT 1 FROM team_task_permissions p JOIN team_members m ON m.id=p.member_id AND m.revoked_at IS NULL WHERE p.team_id=$1 AND p.task_id=t.id AND p.member_id=$2 AND p.permission='read')) ORDER BY t.id DESC`, teamID, memberID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TeamWorkspaceTask{}
	for rows.Next() {
		var v TeamWorkspaceTask
		if err = rows.Scan(&v.ID, &v.Name, &v.Kind, &v.Status); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (d *DB) TeamWorkspaceDevices(ctx context.Context, teamID, memberID int64) ([]TeamDevice, error) {
	rows, err := d.QueryContext(ctx, `SELECT id,team_id,owner_member_id,name,capabilities,revoked_at IS NOT NULL,created_at FROM team_devices WHERE team_id=$1 AND ($2::bigint=0 OR owner_member_id=$2) ORDER BY id`, teamID, memberID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TeamDevice{}
	for rows.Next() {
		var v TeamDevice
		if err = rows.Scan(&v.ID, &v.TeamID, &v.OwnerMemberID, &v.Name, &v.Capabilities, &v.Revoked, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// GetTeamDevice is metadata only. The secret digest is never exposed to callers.
func (d *DB) GetTeamDevice(ctx context.Context, teamID, deviceID int64) (*TeamDevice, error) {
	var v TeamDevice
	err := d.QueryRowContext(ctx, `SELECT id,team_id,owner_member_id,name,capabilities,revoked_at IS NOT NULL,created_at FROM team_devices WHERE team_id=$1 AND id=$2`, teamID, deviceID).Scan(&v.ID, &v.TeamID, &v.OwnerMemberID, &v.Name, &v.Capabilities, &v.Revoked, &v.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrTeamCollaborationDenied
	}
	return &v, err
}
