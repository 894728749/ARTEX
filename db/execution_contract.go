package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// WorkContract describes a bounded unit of work. Dependencies mean completed work;
// evidence references, not a dependency's status alone, establish a factual premise.
type WorkContract struct {
	ExecutionRole     string   `json:"execution_role,omitempty"`
	WorkflowRequestID int64    `json:"workflow_request_id,omitempty"`
	GoalIDs           []int64  `json:"goal_ids,omitempty"`
	Hypothesis        string   `json:"hypothesis,omitempty"`
	Acceptance        []string `json:"acceptance,omitempty"`
	DependsOn         []int64  `json:"depends_on,omitempty"`
	DirectionKey      string   `json:"direction_key,omitempty"`
	Novelty           string   `json:"novelty,omitempty"`
	ResourceKey       string   `json:"resource_key,omitempty"`
	BudgetSeconds     int      `json:"budget_seconds,omitempty"`
}

type EvidenceReference struct {
	NodeID  int64  `json:"node_id"`
	Version string `json:"version"`
}

type IntentResult struct {
	Outcome      string              `json:"outcome"`
	Summary      string              `json:"summary"`
	Evidence     []EvidenceReference `json:"evidence_refs"`
	Satisfied    []string            `json:"satisfied,omitempty"`
	SatisfiedIDs []string            `json:"satisfied_ids,omitempty"`
	Remaining    []string            `json:"remaining,omitempty"`
	Blocker      string              `json:"blocker,omitempty"`
	Checkpoint   string              `json:"checkpoint,omitempty"`
	Attempt      int64               `json:"attempt"`
	SubmittedAt  time.Time           `json:"submitted_at"`
}

type AcceptanceCriterion struct {
	ID          string `json:"criterion_id"`
	Description string `json:"description"`
}

// AcceptanceCriteria derives stable identifiers from the exact normalized
// acceptance text. Older contracts transparently receive the same derived IDs.
func AcceptanceCriteria(c WorkContract) []AcceptanceCriterion {
	out := make([]AcceptanceCriterion, 0, len(c.Acceptance))
	occurrences := map[string]int{}
	for _, description := range c.Acceptance {
		description = strings.TrimSpace(description)
		occurrences[description]++
		seed := description
		if occurrences[description] > 1 {
			seed += fmt.Sprintf("\noccurrence:%d", occurrences[description])
		}
		h := sha256.Sum256([]byte(seed))
		out = append(out, AcceptanceCriterion{ID: "ac_" + hex.EncodeToString(h[:]), Description: description})
	}
	return out
}

func validateSatisfied(c WorkContract, r IntentResult) error {
	criteria := AcceptanceCriteria(c)
	known := make(map[string]bool, len(criteria))
	for _, item := range criteria {
		known[item.ID] = true
	}
	got := make(map[string]bool)
	if len(r.SatisfiedIDs) > 0 {
		if len(r.Satisfied) > 0 {
			return fmt.Errorf("satisfied_ids 与旧版 satisfied 不能同时提交")
		}
		for _, id := range r.SatisfiedIDs {
			if !known[id] {
				return fmt.Errorf("未知验收 criterion_id：%s", id)
			}
			if got[id] {
				return fmt.Errorf("重复验收 criterion_id：%s", id)
			}
			got[id] = true
		}
	} else {
		// Legacy receipts used the full acceptance text. Keep this path for old
		// workers and stored contracts while new workers submit fixed IDs.
		for _, item := range criteria {
			for _, text := range r.Satisfied {
				if item.Description == text {
					got[item.ID] = true
					break
				}
			}
		}
	}
	missing := []string{}
	for _, item := range criteria {
		if !got[item.ID] {
			missing = append(missing, item.ID+" ("+item.Description+")")
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("未满足验收项：%s", strings.Join(missing, "; "))
	}
	return nil
}

func NodeEvidenceVersion(n *Node) string {
	if n == nil {
		return ""
	}
	h := sha256.Sum256([]byte(n.Kind + "\n" + n.State + "\n" + string(n.Payload)))
	return hex.EncodeToString(h[:])
}

func IntentContract(n *Node) (WorkContract, int64) {
	var p struct {
		Contract WorkContract `json:"contract"`
		Attempt  int64        `json:"execution_attempt"`
	}
	if n != nil {
		_ = json.Unmarshal(n.Payload, &p)
	}
	return p.Contract, p.Attempt
}

// lockExploration serializes admission and result transitions within this task.
func (s *ExplorationStore) lockExploration(ctx context.Context, tx *sql.Tx) error {
	var id int64
	return tx.QueryRowContext(ctx, `SELECT id FROM explorations WHERE id=$1 FOR UPDATE`, s.expID).Scan(&id)
}

func (s *ExplorationStore) evidenceNodeTx(ctx context.Context, tx *sql.Tx, id int64) (*Node, error) {
	return scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeCols+` FROM exploration_nodes WHERE id=$1 AND
 (exploration_id=$2 OR exploration_id IN (SELECT source.exploration_id FROM tasks owner JOIN task_relations r ON r.task_id=owner.id JOIN tasks source ON source.id=r.source_task_id AND source.deleted_at IS NULL WHERE owner.exploration_id=$2 AND owner.deleted_at IS NULL)) FOR SHARE`, id, s.expID))
}

func validEvidenceNode(n *Node) error {
	if n == nil || (n.Kind != KindFact && n.Kind != KindFinding) || n.State == "dismissed" || n.State == "origin" {
		return fmt.Errorf("证据必须是有效事实或漏洞，任务起点不能作证明")
	}
	var p map[string]any
	_ = json.Unmarshal(n.Payload, &p)
	if p["merged_into"] != nil {
		return fmt.Errorf("来源漏洞已归并，请读取规范漏洞及最新证据")
	}
	if n.Kind == KindFact && p["confidence"] == "inferred" {
		return fmt.Errorf("推断事实不能作为已验证结果，请先补证")
	}
	if strings.TrimSpace(fmt.Sprint(p["evidence"])) == "" || p["evidence"] == nil {
		return fmt.Errorf("证据节点缺少可核对的 evidence 内容")
	}
	return nil
}

// AddWorkIntent writes the intent, its anchors and lineage atomically. Same-key
// retries return the existing record; intentional new work requires new evidence
// parents or a new hypothesis key, not merely a different summary.
func uniqueWorkIDs(ids []int64) []int64 {
	out := []int64{}
	seen := map[int64]bool{}
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (s *ExplorationStore) AddWorkIntent(ctx context.Context, summary string, priority int, assets, parents []int64, c WorkContract) (int64, error) {
	summary = strings.TrimSpace(summary)
	if summary == "" {
		return 0, fmt.Errorf("summary 不能为空")
	}
	if len(c.DependsOn) > 32 || len(parents) > 32 || len(c.Acceptance) > 20 {
		return 0, fmt.Errorf("前置与验收项过多，请拆分工作")
	}
	if c.BudgetSeconds < 0 || c.BudgetSeconds > 86400 {
		return 0, fmt.Errorf("budget_seconds 必须在 0–86400 之间")
	}
	if priority < 0 || priority > 10 {
		return 0, fmt.Errorf("priority 必须在 0–10 之间")
	}
	if len(c.Acceptance) == 0 {
		c.Acceptance = []string{summary}
	}
	for i := range c.Acceptance {
		c.Acceptance[i] = strings.TrimSpace(c.Acceptance[i])
		if c.Acceptance[i] == "" {
			return 0, fmt.Errorf("验收项不能为空")
		}
	}
	parents, assets = uniqueWorkIDs(parents), uniqueWorkIDs(assets)
	c.DependsOn, c.GoalIDs = uniqueWorkIDs(c.DependsOn), uniqueWorkIDs(c.GoalIDs)
	direction := strings.TrimSpace(c.DirectionKey)
	if direction == "" {
		direction = strings.ToLower(strings.Join(strings.Fields(summary), " "))
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err = s.lockExploration(ctx, tx); err != nil {
		return 0, err
	}
	var kind string
	if err = tx.QueryRowContext(ctx, `SELECT kind FROM tasks WHERE exploration_id=$1 AND deleted_at IS NULL`, s.expID).Scan(&kind); err != nil && err != sql.ErrNoRows {
		return 0, err
	}
	if kind == "reverse" {
		if c.ExecutionRole == "" {
			c.ExecutionRole = "reverse_static"
		}
		switch c.ExecutionRole {
		case "reverse_static", "reverse_dynamic", "reverse_reviewer":
		default:
			return 0, fmt.Errorf("逆向工作必须指定 reverse_static/reverse_dynamic/reverse_reviewer")
		}
	} else if c.ExecutionRole != "" && c.ExecutionRole != "worker" {
		return 0, fmt.Errorf("渗透工作只能使用 worker")
	}
	// Carry ownership through evidence/dependency lineage even when a planner
	// omits the request ID on a follow-up review. Received results in the source
	// task are excluded: its independent validation belongs to the source task.
	inputs, _ := json.Marshal(uniqueWorkIDs(append(append(append([]int64{}, parents...), c.DependsOn...), c.GoalIDs...)))
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT r.id FROM workflow_requests r JOIN tasks task ON task.id=r.target_task_id WHERE task.exploration_id=$1 AND r.id IN (
 SELECT COALESCE(n.payload->'contract'->>'workflow_request_id',n.payload->>'workflow_request_id','0')::bigint FROM exploration_nodes n WHERE n.exploration_id=$1 AND n.id IN(SELECT value::bigint FROM jsonb_array_elements_text($2::jsonb))
 UNION SELECT COALESCE(work.payload->'contract'->>'workflow_request_id','0')::bigint FROM exploration_nodes n JOIN exploration_edges e ON (e.src_id=n.id AND e.rel='derived_from') OR (e.dst_id=n.id AND e.rel='yields') JOIN exploration_nodes work ON work.id=CASE WHEN e.src_id=n.id THEN e.dst_id ELSE e.src_id END AND work.kind='intent' AND work.exploration_id=$1 WHERE n.exploration_id=$1 AND n.id IN(SELECT value::bigint FROM jsonb_array_elements_text($2::jsonb)))`, s.expID, string(inputs))
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		if c.WorkflowRequestID != 0 && c.WorkflowRequestID != id {
			rows.Close()
			return 0, fmt.Errorf("不能混合多个委托的执行归属，请拆成独立工作")
		}
		c.WorkflowRequestID = id
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	if c.WorkflowRequestID > 0 {
		var budget int
		err = tx.QueryRowContext(ctx, `SELECT LEAST(budget_seconds,GREATEST(0,FLOOR(EXTRACT(EPOCH FROM (expires_at-now())))::int)) FROM workflow_requests r JOIN tasks t ON t.id=r.target_task_id WHERE r.id=$1 AND t.exploration_id=$2 AND r.status='pending' AND r.expires_at>now() FOR SHARE OF r`, c.WorkflowRequestID, s.expID).Scan(&budget)
		if err != nil || budget < 1 {
			return 0, fmt.Errorf("委托不存在、已结束或不属于本任务")
		}
		if c.BudgetSeconds == 0 || c.BudgetSeconds > budget {
			c.BudgetSeconds = budget
		}
	}
	inputVersions := []EvidenceReference{}
	for _, id := range parents {
		n, e := s.evidenceNodeTx(ctx, tx, id)
		if e != nil || n == nil || (n.Kind != KindFact && n.Kind != KindFinding) {
			return 0, fmt.Errorf("parent_id %d 必须是本任务或直接关联任务的事实/漏洞", id)
		}
		inputVersions = append(inputVersions, EvidenceReference{NodeID: id, Version: NodeEvidenceVersion(n)})
	}
	keyParts := []any{direction, assets, inputVersions, c.DependsOn, c.GoalIDs, c.Hypothesis}
	// Preserve the published pentest deduplication keys; reverse roles represent
	// different work even when the question and input evidence are identical.
	if kind == "reverse" {
		keyParts = append(keyParts, c.ExecutionRole)
	}
	if c.WorkflowRequestID > 0 {
		keyParts = append(keyParts, c.WorkflowRequestID)
	}
	keyData, _ := json.Marshal(keyParts)
	h := sha256.Sum256(keyData)
	key := hex.EncodeToString(h[:])
	var existing int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM exploration_nodes WHERE exploration_id=$1 AND kind='intent' AND state<>'deleted' AND payload->>'work_key'=$2 ORDER BY id LIMIT 1`, s.expID, key).Scan(&existing)
	if err == nil {
		return existing, tx.Commit()
	}
	if err != sql.ErrNoRows {
		return 0, err
	}
	for _, id := range c.GoalIDs {
		var ok bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM exploration_nodes WHERE exploration_id=$1 AND id=$2 AND kind='goal' AND state='open')`, s.expID, id).Scan(&ok); err != nil {
			return 0, err
		}
		if !ok {
			return 0, fmt.Errorf("goal_id %d 必须是本任务未完成目标", id)
		}
	}
	state := "open"
	for _, id := range c.DependsOn {
		var st string
		if err = tx.QueryRowContext(ctx, `SELECT state FROM exploration_nodes WHERE exploration_id=$1 AND id=$2 AND kind='intent' FOR SHARE`, s.expID, id).Scan(&st); err != nil {
			return 0, fmt.Errorf("depends_on %d 不属于本任务有效意图", id)
		}
		if st != "done" {
			state = "waiting"
		}
	}
	if len(parents) == 0 {
		var id int64
		err = tx.QueryRowContext(ctx, `SELECT id FROM exploration_nodes WHERE exploration_id=$1 AND kind='fact' AND state='origin' ORDER BY id LIMIT 1`, s.expID).Scan(&id)
		if err == nil {
			parents = []int64{id}
		} else if err != sql.ErrNoRows {
			return 0, err
		}
	}
	payload := map[string]any{"summary": summary, "asset_ids": assets, "contract": c, "contract_version": 1, "work_key": key, "input_evidence": inputVersions}
	raw, _ := json.Marshal(payload)
	var id int64
	if err = tx.QueryRowContext(ctx, `INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin) VALUES($1,'intent',$2,$3,$4,'planner') RETURNING id`, s.expID, string(jsonbClean(raw)), priority, state).Scan(&id); err != nil {
		return 0, err
	}
	for _, a := range assets {
		if _, err = tx.ExecContext(ctx, `INSERT INTO exploration_anchors(node_id,asset_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, id, a); err != nil {
			return 0, err
		}
	}
	for _, p := range parents {
		if _, err = tx.ExecContext(ctx, `INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, s.expID, p, RelDerivedFrom, id); err != nil {
			return 0, err
		}
	}
	return id, tx.Commit()
}

func (s *ExplorationStore) BeginIntentAttempt(ctx context.Context, id int64) (*Node, error) {
	return scanNode(s.db.QueryRowContext(ctx, `UPDATE exploration_nodes SET payload=jsonb_set(payload,'{execution_attempt}',to_jsonb(COALESCE((payload->>'execution_attempt')::bigint,0)+1)) WHERE exploration_id=$1 AND id=$2 AND kind='intent' AND state='running' RETURNING `+nodeCols, s.expID, id))
}

func (s *ExplorationStore) SubmitIntentResult(ctx context.Context, id, attempt int64, r IntentResult) error {
	if strings.TrimSpace(r.Summary) == "" {
		return fmt.Errorf("summary 必填")
	}
	complete := r.Outcome == "succeeded" || r.Outcome == "negative" || r.Outcome == "reused"
	if !complete && r.Outcome != "incomplete" && r.Outcome != "blocked" {
		return fmt.Errorf("outcome 必须是 succeeded/negative/reused/incomplete/blocked")
	}
	if complete && (len(r.Evidence) == 0 || len(r.Remaining) > 0) {
		return fmt.Errorf("完成结果必须有证据引用且无未完成项")
	}
	if !complete && strings.TrimSpace(r.Blocker) == "" && len(r.Remaining) == 0 {
		return fmt.Errorf("未完成结果须说明 blocker 或 remaining")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.lockExploration(ctx, tx); err != nil {
		return err
	}
	n, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeCols+` FROM exploration_nodes WHERE exploration_id=$1 AND id=$2 AND kind='intent' AND state='running' FOR UPDATE`, s.expID, id))
	if err != nil {
		return err
	}
	c, current := IntentContract(n)
	if current != attempt || attempt < 1 {
		return fmt.Errorf("执行代次已变化，拒绝旧执行者回写")
	}
	for _, ref := range r.Evidence {
		ev, e := s.evidenceNodeTx(ctx, tx, ref.NodeID)
		if e != nil {
			return e
		}
		if e = validEvidenceNode(ev); e != nil {
			return e
		}
		if ref.Version == "" || NodeEvidenceVersion(ev) != ref.Version {
			return fmt.Errorf("证据 %d 版本已变化，请重新读取", ref.NodeID)
		}
	}
	if complete {
		if err := validateSatisfied(c, r); err != nil {
			return err
		}
	}
	r.Attempt = attempt
	r.SubmittedAt = time.Now().UTC()
	raw, _ := json.Marshal(r)
	if _, err = tx.ExecContext(ctx, `UPDATE exploration_nodes SET payload=jsonb_set(payload,'{execution_result}',$3::jsonb) WHERE exploration_id=$1 AND id=$2`, s.expID, id, string(jsonbClean(raw))); err != nil {
		return err
	}
	return tx.Commit()
}

// FinishIntentAttempt verifies evidence and settles the exact running attempt in
// one transaction. An ordinary LLM return is not evidence of task completion.
func (s *ExplorationStore) FinishIntentAttempt(ctx context.Context, id, attempt int64, fallback string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if err = s.lockExploration(ctx, tx); err != nil {
		return "", err
	}
	n, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeCols+` FROM exploration_nodes WHERE exploration_id=$1 AND id=$2 AND kind='intent' AND state='running' FOR UPDATE`, s.expID, id))
	if err != nil {
		return "", err
	}
	c, current := IntentContract(n)
	if current != attempt || attempt < 1 {
		return "", fmt.Errorf("执行代次已变化")
	}
	var p struct {
		Version int          `json:"contract_version"`
		Result  IntentResult `json:"execution_result"`
	}
	_ = json.Unmarshal(n.Payload, &p)
	state, reason := fallback, ""
	var reverse bool
	if fallback == "exhausted" && p.Version > 0 {
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM tasks WHERE exploration_id=$1 AND kind='reverse')`, s.expID).Scan(&reverse); err != nil {
			return "", err
		}
	}
	// Reverse roles have bounded runs. A valid result submitted before the final
	// summary hit its turn budget still completed the work; dependencies should
	// not be stranded by that summary. Pentest settlement keeps its prior policy.
	if (state == "done" || reverse) && p.Version > 0 {
		if state == "done" {
			state = "blocked"
		}
		reason = "missing_or_invalid_result"
		r := p.Result
		if r.Attempt == attempt && r.Summary != "" {
			valid := true
			for _, ref := range r.Evidence {
				ev, e := s.evidenceNodeTx(ctx, tx, ref.NodeID)
				if e != nil && e != sql.ErrNoRows {
					return "", e
				}
				if validEvidenceNode(ev) != nil || NodeEvidenceVersion(ev) != ref.Version {
					valid = false
					reason = "stale_result_evidence"
				}
			}
			if valid {
				switch r.Outcome {
				case "succeeded", "negative", "reused":
					if len(r.Evidence) == 0 || len(r.Remaining) > 0 {
						valid = false
					}
					if validateSatisfied(c, r) != nil {
						valid = false
					}
					if valid {
						state = "done"
						reason = ""
					}
				case "incomplete":
					state = "exhausted"
					reason = ""
				case "blocked":
					state = "blocked"
					reason = "worker_reported_blocker"
				}
			}
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state=$3,blocked_reason=NULLIF($4,''),completed_at=now(),content_version=content_version+1 WHERE exploration_id=$1 AND id=$2`, s.expID, id, state, reason); err != nil {
		return "", err
	}
	return state, tx.Commit()
}

// ProveGoal commits proof, reason and goal transition together. Graph evidence
// must have been read at this exact content version; semantic quality still needs review.
func (s *ExplorationStore) ProveGoal(ctx context.Context, goal int64, ref EvidenceReference, reason, goalVersion string) (bool, error) {
	if strings.TrimSpace(reason) == "" || ref.Version == "" || goalVersion == "" {
		return false, fmt.Errorf("reason、goal_version 和 evidence_version 必填；请先 node_detail 读取目标与证据")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if err = s.lockExploration(ctx, tx); err != nil {
		return false, err
	}
	goalNode, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeCols+` FROM exploration_nodes WHERE exploration_id=$1 AND id=$2 FOR UPDATE`, s.expID, goal))
	if err != nil || goalNode.Kind != KindGoal {
		return false, fmt.Errorf("goal_id 必须是本任务目标")
	}
	if NodeEvidenceVersion(goalNode) != goalVersion {
		return false, fmt.Errorf("目标已修改，请重新读取并逐项验收")
	}
	ev, err := s.evidenceNodeTx(ctx, tx, ref.NodeID)
	if err != nil {
		return false, err
	}
	if err = validEvidenceNode(ev); err != nil {
		return false, err
	}
	if NodeEvidenceVersion(ev) != ref.Version {
		return false, fmt.Errorf("证据版本已变化，请重新读取并核对")
	}
	var taskKind string
	if err := tx.QueryRowContext(ctx, `SELECT kind FROM tasks WHERE exploration_id=$1 AND deleted_at IS NULL`, s.expID).Scan(&taskKind); err != nil && err != sql.ErrNoRows {
		return false, err
	}
	if taskKind == "reverse" {
		var accepted bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM reverse_conclusions c JOIN tasks t ON t.id=c.task_id WHERE t.exploration_id=$1 AND c.node_id=$2 AND c.state='accepted' AND c.reviewer_intent_id<>c.intent_id)`, s.expID, ref.NodeID).Scan(&accepted); err != nil {
			return false, err
		}
		if !accepted {
			return false, fmt.Errorf("逆向目标只能由另一条意图已接受的结论证明；调查元数据、提交记录和未核验候选解释不足以证明目标")
		}
	}
	proof, _ := json.Marshal(map[string]any{"evidence": ref, "reason": reason, "checked_at": time.Now().UTC()})
	if _, err = tx.ExecContext(ctx, `INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, s.expID, ref.NodeID, RelProves, goal); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='met',payload=jsonb_set(payload,'{proof}',$3::jsonb) WHERE exploration_id=$1 AND id=$2`, s.expID, goal, string(jsonbClean(proof))); err != nil {
		return false, err
	}
	var all bool
	err = tx.QueryRowContext(ctx, `SELECT NOT EXISTS(SELECT 1 FROM exploration_nodes WHERE exploration_id=$1 AND kind='goal' AND state='open')`, s.expID).Scan(&all)
	if err != nil {
		return false, err
	}
	if all {
		var pending bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM workflow_requests r JOIN tasks t ON t.id=r.source_task_id OR t.id=r.target_task_id WHERE t.exploration_id=$1 AND r.status='pending')`, s.expID).Scan(&pending); err != nil {
			return false, err
		}
		all = !pending
	}
	return all, tx.Commit()
}

// WorkInputNodes returns direct evidence parents.
// Data stays referenced to graph nodes so no local machine paths are needed.
func (s *ExplorationStore) WorkInputNodes(id int64) ([]*Node, error) {
	rows, err := s.db.Query(`SELECT src_id FROM exploration_edges WHERE exploration_id=$1 AND dst_id=$2 AND rel=$3 ORDER BY src_id`, s.expID, id, RelDerivedFrom)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var n int64
		if err = rows.Scan(&n); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, n)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	out := []*Node{}
	for _, n := range ids {
		v, e := s.GetNodeWithSources(n)
		if e != nil {
			return nil, e
		}
		if v != nil {
			out = append(out, v)
		}
	}
	return out, nil
}
