package db

import (
	"context"
	"fmt"
)

type TeamTaskPermission struct {
	TaskID     int64  `json:"task_id"`
	MemberID   int64  `json:"member_id"`
	Permission string `json:"permission"`
}

func (d *DB) ListTeamTaskPermissions(ctx context.Context, team int64) ([]TeamTaskPermission, error) {
	rows, err := d.QueryContext(ctx, `SELECT task_id,member_id,permission FROM team_task_permissions WHERE team_id=$1 ORDER BY task_id,member_id,permission`, team)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TeamTaskPermission{}
	for rows.Next() {
		var p TeamTaskPermission
		if err = rows.Scan(&p.TaskID, &p.MemberID, &p.Permission); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SetTeamTaskPermissions atomically applies exactly the administrator's selection.
// The task lock also serializes existing grant and protected execution paths.
func (d *DB) SetTeamTaskPermissions(ctx context.Context, team, task, member int64, permissions []string) error {
	seen := map[string]bool{}
	for _, p := range permissions {
		if (p != "read" && p != "execute" && p != "review" && p != "manage") || seen[p] {
			return fmt.Errorf("invalid team permission selection")
		}
		seen[p] = true
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = LockTaskEvidenceTx(tx, task); err != nil {
		return err
	}
	var id int64
	if err = tx.QueryRowContext(ctx, `SELECT id FROM team_members WHERE team_id=$1 AND id=$2 AND revoked_at IS NULL FOR SHARE`, team, member).Scan(&id); err != nil {
		return ErrTeamCollaborationDenied
	}
	var alive bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM tasks WHERE id=$1 AND deleted_at IS NULL AND archived_at IS NULL)`, task).Scan(&alive); err != nil {
		return err
	}
	if !alive {
		return ErrTeamCollaborationDenied
	}
	if len(permissions) > 0 {
		if _, err = tx.ExecContext(ctx, `INSERT INTO team_tasks(team_id,task_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, team, task); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM team_task_permissions WHERE team_id=$1 AND task_id=$2 AND member_id=$3`, team, task, member); err != nil {
		return err
	}
	for _, p := range permissions {
		if _, err = tx.ExecContext(ctx, `INSERT INTO team_task_permissions(team_id,task_id,member_id,permission) VALUES($1,$2,$3,$4)`, team, task, member, p); err != nil {
			return err
		}
	}
	return tx.Commit()
}
