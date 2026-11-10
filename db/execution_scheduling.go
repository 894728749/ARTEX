package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// claimableSQL is shared by direct claims and frontier selection. Missing,
// deleted or unsuccessful predecessors never silently satisfy a dependency.
const claimableSQL = `n.kind='intent' AND n.state IN ('open','waiting')
 AND COALESCE(n.payload->'contract'->>'remote_assignment_pending','false')<>'true'
 AND COALESCE(n.payload->'contract'->>'remote_dispatch_pending','false')<>'true'
 AND NOT (n.payload ? 'workflow_wait_id')
 AND (COALESCE(n.payload->'contract'->>'workflow_request_id','0')='0' OR EXISTS(
 SELECT 1 FROM workflow_requests wr JOIN tasks wt ON wt.id=wr.target_task_id
 WHERE wr.id=(n.payload->'contract'->>'workflow_request_id')::bigint AND wt.exploration_id=n.exploration_id AND wr.status='pending' AND wr.expires_at>now()))
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(COALESCE(n.payload->'contract'->'depends_on','[]'::jsonb)) dep
 LEFT JOIN exploration_nodes p ON p.id=dep.value::bigint AND p.exploration_id=n.exploration_id AND p.kind='intent'
 WHERE p.id IS NULL OR p.state<>'done')
 AND (COALESCE(n.payload->'contract'->>'resource_key','')='' OR NOT EXISTS(
 SELECT 1 FROM exploration_nodes busy WHERE busy.exploration_id=n.exploration_id AND busy.kind='intent' AND busy.state='running'
 AND busy.payload->'contract'->>'resource_key'=n.payload->'contract'->>'resource_key'))`

func (s *ExplorationStore) claimIntent(ctx context.Context, id int64, owner string, paused bool) (*Node, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = s.lockExploration(ctx, tx); err != nil {
		return nil, err
	}
	var gated bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM tasks WHERE exploration_id=$1 AND (deleted_at IS NOT NULL OR paused OR queued OR status IN ('paused','finalizing','done','failed','timeout') OR EXISTS(SELECT 1 FROM team_branch_projects bp WHERE bp.task_id=tasks.id)))`, s.expID).Scan(&gated); err != nil {
		return nil, err
	}
	if gated {
		return nil, nil
	}
	if _, err = s.reconcileIntentDependenciesTx(ctx, tx); err != nil {
		return nil, err
	}
	// Serializing on the exploration makes the resource check and admission one
	// decision, including callers that bypass the in-process worker pool. Lock
	// the complete eligible frontier so a cross-task branch reservation cannot
	// make the highest-priority row hide unrelated work behind it.
	type intentCandidate struct {
		id  int64
		key string
	}
	candidates := []intentCandidate{}
	conditions := claimableSQL
	if paused {
		conditions = strings.Replace(conditions, "n.state IN ('open','waiting')", "n.state='paused'", 1)
	}
	rows, err := tx.QueryContext(ctx, `SELECT n.id,COALESCE(n.payload->'contract'->>'resource_key','') FROM exploration_nodes n WHERE n.exploration_id=$1 AND ($2::bigint=0 OR n.id=$2) AND `+conditions+`
	 ORDER BY n.priority + LEAST(10,FLOOR(EXTRACT(EPOCH FROM (now()-n.created_at))/600)) DESC,n.id FOR UPDATE OF n`, s.expID, id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var candidate intentCandidate
		if err = rows.Scan(&candidate.id, &candidate.key); err != nil {
			rows.Close()
			return nil, err
		}
		candidates = append(candidates, candidate)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	needsBranchLock := false
	for _, candidate := range candidates {
		if candidate.key != "" {
			needsBranchLock = true
			break
		}
	}
	teams := []int64{}
	if needsBranchLock {
		rows, e := tx.QueryContext(ctx, `SELECT tt.team_id FROM team_tasks tt JOIN tasks t ON t.id=tt.task_id WHERE t.exploration_id=$1 ORDER BY tt.team_id`, s.expID)
		if e != nil {
			return nil, e
		}
		for rows.Next() {
			var team int64
			if e = rows.Scan(&team); e != nil {
				rows.Close()
				return nil, e
			}
			teams = append(teams, team)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, e
		}
		for _, team := range teams {
			if err = lockBranchResources(ctx, tx, team); err != nil {
				return nil, err
			}
		}
	}
	picked := int64(0)
	for _, candidate := range candidates {
		busy := false
		if candidate.key != "" {
			for _, team := range teams {
				if err = branchResourceBusy(ctx, tx, team, 0, 0, []string{candidate.key}); err != nil {
					if errors.Is(err, errBranchResourceBusy) {
						busy = true
						break
					}
					return nil, err
				}
			}
		}
		if busy {
			// Explicit claims preserve their single-ID semantics; only frontier
			// selection may continue past an unavailable resource key.
			if id != 0 {
				return nil, nil
			}
			continue
		}
		picked = candidate.id
		break
	}
	if picked == 0 {
		return nil, nil
	}
	n, err := scanNode(tx.QueryRowContext(ctx, `UPDATE exploration_nodes SET state='running',owner=$3 WHERE exploration_id=$1 AND id=$2 RETURNING `+nodeCols, s.expID, picked, owner))
	if err != nil {
		return nil, err
	}
	return n, tx.Commit()
}

// ClaimNextIntent has no fixed recent/frontier window: a blocked high-priority
// entry cannot hide a ready dependency or unrelated resource behind it.
func (s *ExplorationStore) ClaimNextIntent(ctx context.Context, owner string) (*Node, error) {
	return s.claimIntent(ctx, 0, owner, false)
}

func (s *ExplorationStore) ClaimPausedIntent(ctx context.Context, id int64, owner string) (bool, error) {
	n, err := s.claimIntent(ctx, id, owner, true)
	return n != nil, err
}

type PlanningDecision struct {
	Kind              string    `json:"kind"`
	Reason            string    `json:"reason"`
	ResumeWhen        string    `json:"resume_when"`
	CheckAfterSeconds int       `json:"check_after_seconds"`
	Revision          string    `json:"revision"`
	RecordedAt        time.Time `json:"recorded_at"`
}

// Revision includes local/direct-source graph, constraints and evidence relation
// changes. It excludes activity and planner round counters so thinking alone
// cannot re-arm an otherwise unchanged wait.
func (s *ExplorationStore) planningRevision(ctx context.Context) (string, error) {
	var rev string
	err := s.db.QueryRowContext(ctx, `SELECT md5(concat_ws('|',
 (SELECT COALESCE(string_agg(concat_ws(':',id,kind,state,content_version,updated_at::text),'|' ORDER BY id),'') FROM exploration_nodes WHERE exploration_id=$1 OR exploration_id IN (SELECT source.exploration_id FROM tasks own JOIN task_relations r ON r.task_id=own.id JOIN tasks source ON source.id=r.source_task_id AND source.deleted_at IS NULL WHERE own.exploration_id=$1)),
 (SELECT COALESCE(string_agg(concat_ws(':',id,kind,text),'|' ORDER BY id),'') FROM task_constraints WHERE exploration_id=$1),
 (SELECT COALESCE(string_agg(row_to_json(r)::text,'|' ORDER BY r.id),'') FROM finding_relations r JOIN tasks t ON t.id=r.task_id WHERE t.exploration_id=$1),
 (SELECT COALESCE(string_agg(concat_ws(':',a.node_id,a.asset_id,assets.updated_at::text),'|' ORDER BY a.node_id,a.asset_id),'') FROM exploration_anchors a JOIN exploration_nodes n ON n.id=a.node_id JOIN assets ON assets.id=a.asset_id WHERE n.exploration_id=$1)))`, s.expID).Scan(&rev)
	return rev, err
}

func (s *ExplorationStore) RecordPlanningDecision(ctx context.Context, d PlanningDecision) error {
	if d.Kind != "waiting" && d.Kind != "no_progress" {
		return fmt.Errorf("kind 必须是 waiting/no_progress")
	}
	if strings.TrimSpace(d.Reason) == "" || strings.TrimSpace(d.ResumeWhen) == "" {
		return fmt.Errorf("reason 和 resume_when 必填")
	}
	if d.CheckAfterSeconds != 0 && (d.CheckAfterSeconds < 60 || d.CheckAfterSeconds > 86400) {
		return fmt.Errorf("复查间隔必须为 0 或 60–86400 秒")
	}
	var err error
	d.Revision, err = s.planningRevision(ctx)
	if err != nil {
		return err
	}
	d.RecordedAt = time.Now().UTC()
	raw, _ := json.Marshal(d)
	_, err = s.db.ExecContext(ctx, `UPDATE explorations SET planning_state=$2::jsonb WHERE id=$1`, s.expID, string(raw))
	return err
}
func (s *ExplorationStore) PlanningDecision() (*PlanningDecision, error) {
	var raw []byte
	if err := s.db.QueryRow(`SELECT planning_state FROM explorations WHERE id=$1`, s.expID).Scan(&raw); err != nil {
		return nil, err
	}
	var d PlanningDecision
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	if d.Kind == "" {
		return nil, nil
	}
	return &d, nil
}
func (s *ExplorationStore) PlanningWaitUnchanged(ctx context.Context) (bool, error) {
	d, err := s.PlanningDecision()
	if err != nil || d == nil {
		return false, err
	}
	if d.CheckAfterSeconds > 0 && time.Since(d.RecordedAt) >= time.Duration(d.CheckAfterSeconds)*time.Second {
		return false, nil
	}
	r, err := s.planningRevision(ctx)
	return err == nil && r == d.Revision, err
}

func (s *ExplorationStore) ListWaitingIntents() ([]*Node, error) {
	rows, err := s.db.Query(`SELECT `+nodeCols+` FROM exploration_nodes WHERE exploration_id=$1 AND kind='intent' AND state='waiting' ORDER BY priority DESC,id`, s.expID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodes(rows)
}

func (s *ExplorationStore) FindingRelations() ([]FindingRelation, error) {
	var taskID int64
	if err := s.db.QueryRow(`SELECT id FROM tasks WHERE exploration_id=$1 AND deleted_at IS NULL`, s.expID).Scan(&taskID); err == sql.ErrNoRows {
		return []FindingRelation{}, nil
	} else if err != nil {
		return nil, err
	}
	_, edges, err := s.db.FindingGraph(taskID)
	return edges, err
}

// Automatic planner retries are explicit and bounded. Human rerun controls keep
// their existing behavior. A new premise should become a new versioned work item.
func (s *ExplorationStore) RetryWorkIntent(ctx context.Context, id int64, reason string) error {
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("请说明续做依据、故障变化及接续点")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.lockExploration(ctx, tx); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='open',owner=NULL,blocked_reason=NULL,completed_at=NULL,payload=payload||jsonb_build_object('planner_retries',1,'retry_reason',$3::text) WHERE exploration_id=$1 AND id=$2 AND kind='intent' AND state IN ('blocked','exhausted') AND COALESCE((payload->>'planner_retries')::int,0)=0`, s.expID, id, reason)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("仅可续做本任务 blocked/exhausted 工作一次；请等待新证据或人工处理")
	}
	return tx.Commit()
}
