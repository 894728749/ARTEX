package db

import (
	"context"
	"database/sql"
	"time"
)

// RemoteWaitQueueMode holds only the coordinator's local engine. User pause,
// ordinary FIFO admission and remote authorization retain their own semantics.
const RemoteWaitQueueMode = "remote_resume"

const onlyRemoteWorkSQL = `SELECT
 (EXISTS(SELECT 1 FROM team_execution_assignments WHERE task_id=$1 AND (state IN ('assigned','claimed','running') OR (state='completed' AND review_decision IS NULL)))
 OR EXISTS(SELECT 1 FROM team_dispatch_queue WHERE task_id=$1 AND state='queued'))
 AND NOT EXISTS(SELECT 1 FROM exploration_nodes n JOIN tasks t ON t.exploration_id=n.exploration_id WHERE t.id=$1 AND n.kind='intent' AND n.state IN ('open','running','waiting')
 AND COALESCE(n.payload->'contract'->>'remote_assignment_pending','false')<>'true'
 AND COALESCE(n.payload->'contract'->>'remote_dispatch_pending','false')<>'true')`

func (d *DB) OnlyRemoteWork(ctx context.Context, task int64) (bool, error) {
	var only bool
	err := d.QueryRowContext(ctx, onlyRemoteWorkSQL, task).Scan(&only)
	return only, err
}

// ParkRemoteLocalEngine checks under the same task/exploration locks used by
// review and dispatch; a returned local intent cannot race slot release.
func (d *DB) ParkRemoteLocalEngine(ctx context.Context, task int64) (time.Time, bool, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return time.Time{}, false, err
	}
	defer tx.Rollback()
	var exp int64
	err = tx.QueryRowContext(ctx, `SELECT exploration_id FROM tasks WHERE id=$1 AND NOT paused AND NOT queued AND deleted_at IS NULL AND archived_at IS NULL AND status NOT IN ('paused','done','failed','timeout','finalizing') FOR UPDATE`, task).Scan(&exp)
	if err == sql.ErrNoRows {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT id FROM explorations WHERE id=$1 FOR UPDATE`, exp); err != nil {
		return time.Time{}, false, err
	}
	var only bool
	if err = tx.QueryRowContext(ctx, onlyRemoteWorkSQL, task).Scan(&only); err != nil || !only {
		return time.Time{}, false, err
	}
	var at time.Time
	err = tx.QueryRowContext(ctx, `UPDATE tasks SET queued=true,queued_at=now(),queue_mode=$2 WHERE id=$1 RETURNING queued_at`, task, RemoteWaitQueueMode).Scan(&at)
	if err != nil {
		return time.Time{}, false, err
	}
	return at, true, tx.Commit()
}
