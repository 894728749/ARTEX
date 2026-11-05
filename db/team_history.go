package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// TaskTeamHistory is a read-only snapshot of a collaboration source preserved
// across cold archive/restore. Snapshot contains source identities and evidence,
// but never credentials or grants.
type TaskTeamHistory struct {
	ID        int64           `json:"id"`
	TaskID    int64           `json:"task_id"`
	Kind      string          `json:"kind"`
	SourceKey string          `json:"source_key"`
	Snapshot  json.RawMessage `json:"snapshot"`
	CreatedAt time.Time       `json:"created_at"`
}

// ListTaskTeamHistory returns archived collaboration history in stable order.
func (d *DB) ListTaskTeamHistory(ctx context.Context, taskID int64) ([]TaskTeamHistory, error) {
	rows, err := d.QueryContext(ctx, `SELECT id,task_id,kind,source_key,snapshot,created_at
FROM task_team_history WHERE task_id=$1 ORDER BY kind,created_at,id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []TaskTeamHistory{}
	for rows.Next() {
		var item TaskTeamHistory
		if err := rows.Scan(&item.ID, &item.TaskID, &item.Kind, &item.SourceKey, &item.Snapshot, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func restoreTaskTeamHistory(tx *sql.Tx, taskID int64, raw json.RawMessage) error {
	rows, err := decodeArchiveRows(raw)
	if err != nil {
		return err
	}
	for _, row := range rows {
		kind, _ := row["kind"].(string)
		sourceKey, _ := row["source_key"].(string)
		snapshot, err := json.Marshal(row["snapshot"])
		if err != nil {
			return err
		}
		if kind == "" || sourceKey == "" || len(snapshot) == 0 || string(snapshot) == "null" {
			return fmt.Errorf("invalid team history row")
		}
		if _, err := tx.Exec(`INSERT INTO task_team_history(task_id,kind,source_key,snapshot)
VALUES($1,$2,$3,$4::jsonb) ON CONFLICT(task_id,kind,source_key) DO UPDATE SET snapshot=EXCLUDED.snapshot`, taskID, kind, sourceKey, string(snapshot)); err != nil {
			return err
		}
	}
	return nil
}
