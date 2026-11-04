package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

// AdvanceGoalFinalization uses the same exploration lock as work admission and
// goal writes. Goal edits/additions can therefore reopen planning without racing
// a stale completion decision. Pauses and terminal transitions always win.
func (d *DB) AdvanceGoalFinalization(ctx context.Context, taskID int64, begin bool) (string, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var exp int64
	if err = tx.QueryRowContext(ctx, `SELECT exploration_id FROM tasks WHERE id=$1 AND deleted_at IS NULL`, taskID).Scan(&exp); err != nil {
		return "", err
	}
	s := d.Exploration(exp)
	if err = s.lockExploration(ctx, tx); err != nil {
		return "", err
	}
	var status string
	var paused bool
	if err = tx.QueryRowContext(ctx, `SELECT status,paused FROM tasks WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, taskID).Scan(&status, &paused); err != nil {
		return "", err
	}
	if paused || IsTerminal(status) {
		return status, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,payload->'proof' FROM exploration_nodes WHERE exploration_id=$1 AND kind='goal' AND state='met' AND payload ? 'proof' ORDER BY id FOR UPDATE`, exp)
	if err != nil {
		return "", err
	}
	type proofRow struct {
		id  int64
		raw []byte
	}
	var proofs []proofRow
	for rows.Next() {
		var p proofRow
		if err = rows.Scan(&p.id, &p.raw); err != nil {
			rows.Close()
			return "", err
		}
		proofs = append(proofs, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", err
	}
	stale := false
	for _, p := range proofs {
		var proof struct {
			Evidence EvidenceReference `json:"evidence"`
		}
		_ = json.Unmarshal(p.raw, &proof)
		ev, e := s.evidenceNodeTx(ctx, tx, proof.Evidence.NodeID)
		if e != nil && e != sql.ErrNoRows {
			return "", e
		}
		if e != nil || validEvidenceNode(ev) != nil || NodeEvidenceVersion(ev) != proof.Evidence.Version {
			if _, err = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='open',payload=payload-'proof',content_version=content_version+1 WHERE id=$1`, p.id); err != nil {
				return "", err
			}
			if _, err = tx.ExecContext(ctx, `DELETE FROM exploration_edges WHERE exploration_id=$1 AND dst_id=$2 AND rel='proves'`, exp, p.id); err != nil {
				return "", err
			}
			stale = true
		}
	}
	var open, goals, running int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE kind='goal' AND state='open'),count(*) FILTER(WHERE kind='goal'),count(*) FILTER(WHERE kind='intent' AND state='running') FROM exploration_nodes WHERE exploration_id=$1`, exp).Scan(&open, &goals, &running); err != nil {
		return "", err
	}
	next := status
	switch {
	case status == "finalizing" && open > 0:
		next = "running"
	case begin && status != "finalizing":
		if open > 0 || goals == 0 {
			if stale {
				return status, tx.Commit()
			}
			return status, fmt.Errorf("目标尚未完成，拒绝开始收尾")
		}
		next = "finalizing"
	case status == "finalizing" && running == 0:
		if _, err = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='stopped',completed_at=now(),content_version=content_version+1 WHERE exploration_id=$1 AND kind='intent' AND state IN ('open','waiting')`, exp); err != nil {
			return "", err
		}
		next = "done"
	}
	if next != status {
		if _, err = tx.ExecContext(ctx, `UPDATE tasks SET status=$2,completed_at=CASE WHEN $2='done' THEN now() ELSE NULL END WHERE id=$1`, taskID, next); err != nil {
			return "", err
		}
	}
	return next, tx.Commit()
}
