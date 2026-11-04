package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

type ReverseRuntimePolicy struct {
	Enabled       bool     `json:"enabled"`
	ProfileIDs    []string `json:"profile_ids"`
	ArtifactIDs   []int64  `json:"artifact_ids"`
	MaxDurationMS int      `json:"max_duration_ms"`
}

type ReverseRuntimeRun struct {
	ID         int64      `json:"id"`
	TaskID     int64      `json:"task_id"`
	ArtifactID int64      `json:"artifact_id"`
	IntentID   *int64     `json:"intent_id,omitempty"`
	ProfileID  string     `json:"profile_id"`
	Status     string     `json:"status"`
	ResultPath string     `json:"result_path,omitempty"`
	LastError  string     `json:"last_error,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

func (d *DB) ReverseRuntimePolicy(taskID int64) (ReverseRuntimePolicy, error) {
	p := ReverseRuntimePolicy{ProfileIDs: []string{}, ArtifactIDs: []int64{}, MaxDurationMS: 10000}
	if _, err := d.reverseTask(taskID); err != nil {
		return p, err
	}
	var profiles, artifacts []byte
	err := d.QueryRow(`SELECT enabled,profile_ids,artifact_ids,max_duration_ms FROM reverse_runtime_policies WHERE task_id=$1`, taskID).Scan(&p.Enabled, &profiles, &artifacts, &p.MaxDurationMS)
	if errors.Is(err, sql.ErrNoRows) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	if err = json.Unmarshal(profiles, &p.ProfileIDs); err != nil {
		return p, err
	}
	err = json.Unmarshal(artifacts, &p.ArtifactIDs)
	return p, err
}

func (d *DB) SetReverseRuntimePolicy(ctx context.Context, taskID int64, p ReverseRuntimePolicy) error {
	if p.MaxDurationMS < 100 || p.MaxDurationMS > 60000 || (p.Enabled && (len(p.ProfileIDs) == 0 || len(p.ArtifactIDs) == 0)) {
		return errors.New("请选择环境、材料和 100–60000ms 的观察窗口")
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var kind string
	var paused bool
	var status string
	if err = tx.QueryRowContext(ctx, `SELECT kind,paused,status FROM tasks WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, taskID).Scan(&kind, &paused, &status); err != nil {
		return err
	}
	if kind != "reverse" {
		return ErrReverseTaskRequired
	}
	if !paused && !IsTerminal(status) {
		return errors.New("请先暂停逆向任务再调整运行环境授权")
	}
	for _, id := range p.ArtifactIDs {
		var found bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM reverse_artifacts WHERE id=$1 AND task_id=$2)`, id, taskID).Scan(&found); err != nil {
			return err
		}
		if !found {
			return errors.New("授权材料不属于当前任务")
		}
	}
	profiles, _ := json.Marshal(p.ProfileIDs)
	artifacts, _ := json.Marshal(p.ArtifactIDs)
	_, err = tx.ExecContext(ctx, `INSERT INTO reverse_runtime_policies(task_id,enabled,profile_ids,artifact_ids,max_duration_ms) VALUES($1,$2,$3,$4,$5) ON CONFLICT(task_id) DO UPDATE SET enabled=EXCLUDED.enabled,profile_ids=EXCLUDED.profile_ids,artifact_ids=EXCLUDED.artifact_ids,max_duration_ms=EXCLUDED.max_duration_ms,updated_at=now()`, taskID, p.Enabled, profiles, artifacts, p.MaxDurationMS)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) BeginReverseRuntimeRun(ctx context.Context, taskID, artifactID, intentID int64, profile string, duration int) (int64, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var max int
	var enabled, profileOK, artifactOK bool
	err = tx.QueryRowContext(ctx, `SELECT enabled,profile_ids ? $2,artifact_ids @> jsonb_build_array($3::bigint),max_duration_ms FROM reverse_runtime_policies WHERE task_id=$1 FOR SHARE`, taskID, profile, artifactID).Scan(&enabled, &profileOK, &artifactOK, &max)
	if err != nil || !enabled || !profileOK || !artifactOK || duration < 100 || duration > max {
		return 0, errors.New("未授权该运行环境、材料或观察时长；请在分析档案配置")
	}
	var owner int64
	err = tx.QueryRowContext(ctx, `SELECT task_id FROM reverse_artifacts WHERE id=$1`, artifactID).Scan(&owner)
	if err != nil || owner != taskID {
		return 0, errors.New("材料不属于当前任务")
	}
	if intentID > 0 {
		var valid bool
		err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM exploration_nodes n JOIN tasks t ON t.exploration_id=n.exploration_id WHERE n.id=$1 AND t.id=$2 AND n.kind='intent' AND n.state='running')`, intentID, taskID).Scan(&valid)
		if err != nil || !valid {
			return 0, errors.New("运行时工作单未获得执行准入")
		}
	}
	var id int64
	err = tx.QueryRowContext(ctx, `INSERT INTO reverse_runtime_runs(task_id,artifact_id,intent_id,profile_id,status) VALUES($1,$2,NULLIF($3,0),$4,'running') RETURNING id`, taskID, artifactID, intentID, profile).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

func (d *DB) FinishReverseRuntimeRun(id int64, status, path, message string) error {
	if status != "completed" && status != "failed" && status != "cancelled" {
		return errors.New("invalid runtime outcome")
	}
	_, err := d.Exec(`UPDATE reverse_runtime_runs SET status=$2,result_path=$3,last_error=$4,finished_at=now() WHERE id=$1 AND status='running'`, id, status, path, message)
	return err
}

func (d *DB) ListReverseRuntimeRuns(taskID int64) ([]ReverseRuntimeRun, error) {
	out := []ReverseRuntimeRun{}
	rows, err := d.Query(`SELECT id,task_id,artifact_id,intent_id,profile_id,status,result_path,last_error,created_at,finished_at FROM reverse_runtime_runs WHERE task_id=$1 ORDER BY id DESC LIMIT 100`, taskID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var r ReverseRuntimeRun
		if err = rows.Scan(&r.ID, &r.TaskID, &r.ArtifactID, &r.IntentID, &r.ProfileID, &r.Status, &r.ResultPath, &r.LastError, &r.CreatedAt, &r.FinishedAt); err != nil {
			return out, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
