package db

import (
	"context"
	"database/sql"
	"errors"
)

var ErrTeamLifecycleConflict = errors.New("team cannot be deleted while it has activity or history")

type TeamDeletionEligibility struct {
	Deletable bool     `json:"deletable"`
	Reasons   []string `json:"reasons"`
}

// teamDeletionEligibilityTx checks retained rows, including revoked credentials,
// because deleting them would erase audit history. The caller serializes against
// inserts through the teams row lock held for the transaction.
func teamDeletionEligibilityTx(ctx context.Context, tx *sql.Tx, teamID int64) (TeamDeletionEligibility, error) {
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM teams WHERE id=$1)`, teamID).Scan(&exists); err != nil {
		return TeamDeletionEligibility{}, err
	}
	if !exists {
		return TeamDeletionEligibility{}, sql.ErrNoRows
	}
	checks := []struct{ reason, query string }{
		{"团队已有成员记录", `SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id=$1)`},
		{"团队已有设备记录", `SELECT EXISTS(SELECT 1 FROM team_devices WHERE team_id=$1)`},
		{"团队已有配对记录", `SELECT EXISTS(SELECT 1 FROM team_device_pairings WHERE team_id=$1)`},
		{"团队已有共享任务", `SELECT EXISTS(SELECT 1 FROM team_tasks WHERE team_id=$1)`},
		{"团队已有执行记录", `SELECT EXISTS(SELECT 1 FROM team_execution_assignments WHERE team_id=$1)`},
		{"团队已有分支或共享资源历史", `SELECT EXISTS(SELECT 1 FROM team_branch_projects WHERE team_id=$1) OR EXISTS(SELECT 1 FROM team_branch_resource_clock WHERE team_id=$1) OR EXISTS(SELECT 1 FROM team_resources WHERE team_id=$1)`},
		{"团队已有协作消息或命令记录", `SELECT EXISTS(SELECT 1 FROM team_execution_messages m JOIN team_execution_assignments a ON a.id=m.assignment_id WHERE a.team_id=$1) OR EXISTS(SELECT 1 FROM team_command_receipts WHERE team_id=$1)`},
		{"团队已有派发记录", `SELECT EXISTS(SELECT 1 FROM team_dispatch_queue WHERE team_id=$1)`},
		{"团队已有任务审计历史", `SELECT EXISTS(SELECT 1 FROM task_team_history h JOIN team_tasks tt ON tt.task_id=h.task_id WHERE tt.team_id=$1)`},
		{"团队存在活动任务", `SELECT EXISTS(SELECT 1 FROM team_tasks tt JOIN tasks t ON t.id=tt.task_id WHERE tt.team_id=$1 AND (t.status IN ('created','running','finalizing') OR t.queued))`},
		{"团队存在活动执行", `SELECT EXISTS(SELECT 1 FROM team_execution_assignments WHERE team_id=$1 AND state IN ('assigned','claimed','running'))`},
	}
	out := TeamDeletionEligibility{Deletable: true, Reasons: []string{}}
	for _, check := range checks {
		var found bool
		if err := tx.QueryRowContext(ctx, check.query, teamID).Scan(&found); err != nil {
			return TeamDeletionEligibility{}, err
		}
		if found {
			out.Deletable = false
			out.Reasons = append(out.Reasons, check.reason)
		}
	}
	return out, nil
}

func (d *DB) TeamDeletionEligibility(ctx context.Context, teamID int64) (TeamDeletionEligibility, error) {
	tx, err := d.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return TeamDeletionEligibility{}, err
	}
	defer tx.Rollback()
	return teamDeletionEligibilityTx(ctx, tx, teamID)
}

func (d *DB) DeleteEmptyTeam(ctx context.Context, teamID int64) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var id int64
	if err = tx.QueryRowContext(ctx, `SELECT id FROM teams WHERE id=$1 FOR UPDATE`, teamID).Scan(&id); err != nil {
		return err
	}
	eligibility, err := teamDeletionEligibilityTx(ctx, tx, teamID)
	if err != nil {
		return err
	}
	if !eligibility.Deletable {
		return ErrTeamLifecycleConflict
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM teams WHERE id=$1`, teamID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return sql.ErrNoRows
	}
	return tx.Commit()
}
