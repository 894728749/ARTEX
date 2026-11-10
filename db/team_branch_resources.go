package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/Autumn-27/artex/collab"
)

var errBranchResourceBusy = errors.New("共享资源忙或执行结果待确认")

// This lock is taken after the task lock by both assignment and branch writers.
// Resource checks only read other task rows; they never invert the task order.
func lockBranchResources(ctx context.Context, tx *sql.Tx, team int64) error {
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('artex-team-resources:' || $1::bigint::text,0))`, team)
	return err
}

func branchResourceKeys(p *collab.BranchProject, b *collab.ExecutionBranch, unit int64) []string {
	keys := append([]string{}, b.Spec.ResourceKeys...)
	for _, u := range b.Units {
		if u.ID != unit {
			continue
		}
		var c WorkContract
		_ = json.Unmarshal(u.Spec.Contract, &c)
		if c.ResourceKey != "" {
			keys = append(keys, c.ResourceKey)
		}
		for _, a := range p.Policy.Assets {
			if slices.Contains(u.Spec.AssetIDs, a.ID) {
				keys = append(keys, "asset:"+collab.ContentHash([]byte(strings.ToLower(strings.TrimSpace(a.Target)))))
			}
		}
		if u.Spec.Runtime != nil {
			keys = append(keys, fmt.Sprintf("runtime:%d:%s", b.DeviceID, u.Spec.Runtime.ID))
		}
	}
	slices.Sort(keys)
	return slices.Compact(keys)
}

func branchResourceBusy(ctx context.Context, tx *sql.Tx, team, skipTask, skipBranch int64, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT state FROM team_branch_projects WHERE team_id=$1`, team)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return err
		}
		var p collab.BranchProject
		if err = json.Unmarshal(raw, &p); err != nil {
			return err
		}
		for _, b := range p.Branches {
			if p.TaskID == skipTask && b.ID == skipBranch {
				continue
			}
			for _, op := range b.Operations {
				if op.Kind != "tool" || (op.State != "started" && op.State != "uncertain") {
					continue
				}
				for _, key := range branchResourceKeys(&p, &b, op.UnitID) {
					if slices.Contains(keys, key) {
						return fmt.Errorf("%w: %s", errBranchResourceBusy, key)
					}
				}
			}
		}
	}
	return rows.Err()
}

func reserveBranchOperation(ctx context.Context, tx *sql.Tx, p *collab.BranchProject, c collab.BranchCommand) error {
	if c.Type != "start" || c.Operation == nil || c.Operation.Kind != "tool" {
		return nil
	}
	var b *collab.ExecutionBranch
	for i := range p.Branches {
		if p.Branches[i].ID == c.BranchID {
			b = &p.Branches[i]
		}
	}
	if b == nil {
		return collab.ErrBranchDenied
	}
	for _, op := range b.Operations {
		if op.ID == c.Operation.ID {
			return nil
		}
	} // receipt replay does not reserve twice
	keys := branchResourceKeys(p, b, c.Operation.UnitID)
	if err := branchResourceBusy(ctx, tx, p.TeamID, p.TaskID, b.ID, keys); err != nil {
		return err
	}
	for _, key := range keys {
		var busy bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM team_execution_assignments WHERE team_id=$1 AND resource_key=$2 AND state IN ('assigned','claimed','running')) OR EXISTS(SELECT 1 FROM exploration_nodes n JOIN tasks t ON t.exploration_id=n.exploration_id JOIN team_tasks tt ON tt.task_id=t.id WHERE tt.team_id=$1 AND n.kind='intent' AND n.state='running' AND n.payload->'contract'->>'resource_key'=$2)`, p.TeamID, key).Scan(&busy); err != nil {
			return err
		}
		if busy {
			return fmt.Errorf("共享资源正在被已有工作单使用: %s", key)
		}
		if p.Policy.MinToolIntervalMS > 0 {
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM team_branch_resource_clock WHERE team_id=$1 AND resource_key=$2 AND last_started_at>now()-($3::bigint * interval '1 millisecond'))`, p.TeamID, key, p.Policy.MinToolIntervalMS).Scan(&busy); err != nil {
				return err
			}
			if busy {
				return fmt.Errorf("共享资源的工具调用间隔尚未到期: %s", key)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO team_branch_resource_clock(team_id,resource_key) VALUES($1,$2) ON CONFLICT(team_id,resource_key) DO UPDATE SET last_started_at=now()`, p.TeamID, key); err != nil {
			return err
		}
	}
	return nil
}

func syncBranchAssistance(ctx context.Context, tx *sql.Tx, p *collab.BranchProject) error {
	for i := range p.Pool {
		w := &p.Pool[i]
		if w.Spec.ParentBranchID == 0 {
			continue
		}
		raw, _ := json.Marshal(w.Spec)
		if w.Spec.WorkflowRequestID == 0 {
			if err := tx.QueryRowContext(ctx, `INSERT INTO team_branch_workflow_requests(task_id,work_id,source_branch_id,status,input_snapshot) VALUES($1,$2,$3,$4,$5) RETURNING id`, p.TaskID, w.ID, w.Spec.ParentBranchID, w.State, raw).Scan(&w.Spec.WorkflowRequestID); err != nil {
				return err
			}
		}
		var result any
		for j := range p.Branches {
			b := &p.Branches[j]
			if b.WorkID == w.ID {
				b.Spec.WorkflowRequestID = w.Spec.WorkflowRequestID
				r, _ := json.Marshal(b)
				result = r
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE team_branch_workflow_requests SET target_branch_id=NULLIF($2,0),status=$3,result=$4 WHERE id=$1`, w.Spec.WorkflowRequestID, w.BranchID, w.State, result); err != nil {
			return err
		}
	}
	return nil
}
