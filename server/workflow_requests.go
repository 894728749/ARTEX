package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

type workflowHelpInput struct {
	RequestKey      string                 `json:"request_key"`
	TargetTaskID    int64                  `json:"target_task_id"`
	Question        string                 `json:"question"`
	Acceptance      []string               `json:"acceptance"`
	Files           []string               `json:"files"`
	Evidence        []db.EvidenceReference `json:"evidence_refs"`
	BudgetSeconds   int                    `json:"budget_seconds"`
	ParentRequestID *int64                 `json:"parent_request_id,omitempty"`
}
type workflowFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type workflowSnapshot struct {
	Files    []workflowFile     `json:"files"`
	Evidence []workflowEvidence `json:"evidence"`
}
type workflowEvidence struct {
	NodeID  int64           `json:"node_id"`
	Version string          `json:"version"`
	Kind    string          `json:"kind"`
	Payload json.RawMessage `json:"payload"`
}
type workflowAnswer struct {
	Status      string             `json:"status"`
	Summary     string             `json:"summary"`
	Limitations string             `json:"limitations"`
	Evidence    []workflowEvidence `json:"evidence"`
}

func (s *Server) selectedWorkflowEvidence(task *Task, refs []db.EvidenceReference) ([]workflowEvidence, error) {
	if len(refs) > 20 {
		return nil, fmt.Errorf("一次最多选择20条证据")
	}
	out := []workflowEvidence{}
	for _, ref := range refs {
		n, err := task.Store.GetNode(ref.NodeID)
		if err != nil || n == nil || (n.Kind != db.KindFact && n.Kind != db.KindFinding) || n.State == "origin" || n.State == "dismissed" {
			return nil, fmt.Errorf("证据 %d 不属于本任务有效事实/发现", ref.NodeID)
		}
		if ref.Version == "" || db.NodeEvidenceVersion(n) != ref.Version {
			return nil, fmt.Errorf("证据 %d 版本已变化，请重读", ref.NodeID)
		}
		out = append(out, workflowEvidence{n.ID, ref.Version, n.Kind, n.Payload})
	}
	return out, nil
}

// Selection is confined to the caller's task directory. No task relation, full
// transcript or runtime authorization is inherited by the recipient.
func (s *Server) workflowInputSnapshot(task *Task, in workflowHelpInput) (workflowSnapshot, error) {
	snap := workflowSnapshot{Files: []workflowFile{}, Evidence: []workflowEvidence{}}
	if len(in.Files) > 8 {
		return snap, fmt.Errorf("一次最多选择8个材料")
	}
	var total int64
	for _, name := range in.Files {
		if name == "" || filepath.IsAbs(name) {
			return snap, fmt.Errorf("材料路径必须相对来源任务目录")
		}
		prefix := filepath.Join("tasks", task.ID)
		path, err := reverseLocalPath(s.m.dir, filepath.Join(prefix, name), prefix)
		if err != nil {
			return snap, err
		}
		f, err := os.Open(path)
		if err != nil {
			return snap, err
		}
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			f.Close()
			return snap, fmt.Errorf("材料必须是普通文件")
		}
		if info.Size() > 64<<20 || total+info.Size() > 128<<20 {
			f.Close()
			return snap, fmt.Errorf("单个材料上限64MiB，总计128MiB")
		}
		hash := sha256.New()
		n, err := io.Copy(hash, io.LimitReader(f, 64<<20+1))
		f.Close()
		if err != nil || n != info.Size() {
			return snap, fmt.Errorf("材料读取失败或已变化")
		}
		total += n
		snap.Files = append(snap.Files, workflowFile{filepath.ToSlash(filepath.Clean(name)), hex.EncodeToString(hash.Sum(nil)), n})
	}
	var err error
	snap.Evidence, err = s.selectedWorkflowEvidence(task, in.Evidence)
	return snap, err
}

func (s *Server) requestWorkflowHelp(ctx context.Context, source *Task, in workflowHelpInput) (*db.WorkflowRequest, error) {
	s.workflowMu.Lock()
	defer s.workflowMu.Unlock()
	sourceID, _ := strconv.ParseInt(source.ID, 10, 64)
	in.RequestKey = strings.TrimSpace(in.RequestKey)
	in.Question = strings.TrimSpace(in.Question)
	if in.BudgetSeconds == 0 {
		in.BudgetSeconds = 600
	}
	if len(in.Acceptance) == 0 {
		in.Acceptance = []string{in.Question}
	}
	// Validate cheap fields before creating any helper task or material copy.
	if strings.TrimSpace(in.RequestKey) == "" || len(in.RequestKey) > 160 || strings.TrimSpace(in.Question) == "" || len(in.Question) > 4000 || in.BudgetSeconds < 1 || in.BudgetSeconds > 3600 {
		return nil, fmt.Errorf("请求键、问题或预算无效")
	}
	snap, err := s.workflowInputSnapshot(source, in)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(snap)
	if err != nil || len(raw) > 64<<10 {
		return nil, fmt.Errorf("所选证据过大，请缩小范围")
	}
	existing, err := s.m.pg.ListWorkflowRequests(ctx, sourceID)
	if err != nil {
		return nil, err
	}

	for _, r := range existing {
		if r.SourceTaskID == sourceID && r.RequestKey == in.RequestKey {
			if in.ParentRequestID == nil {
				in.ParentRequestID = r.ParentRequestID
			}
			// Delegate to DB's canonical equality checks; no second helper is created.
			if in.TargetTaskID != 0 && in.TargetTaskID != r.TargetTaskID {
				return nil, db.ErrWorkflowRequestConflict
			}
			r, _, err = s.m.pg.CreateWorkflowRequest(ctx, db.WorkflowRequestInput{RequestKey: in.RequestKey, SourceTaskID: sourceID, TargetTaskID: r.TargetTaskID, Question: in.Question, Acceptance: in.Acceptance, InputSnapshot: raw, BudgetSeconds: in.BudgetSeconds, ParentRequestID: in.ParentRequestID})
			if err == nil && r.Status == "pending" {
				err = s.prepareWorkflowRequest(ctx, r)
			}
			return r, err
		}
	}
	if in.ParentRequestID == nil {
		for _, r := range existing {
			if r.TargetTaskID == sourceID && r.Status == "pending" {
				if in.ParentRequestID != nil {
					return nil, fmt.Errorf("当前收到多个委托，请指定 parent_request_id")
				}
				id := r.ID
				in.ParentRequestID = &id
			}
		}
	}
	if isTerminalStatus(source.lifecycleSnapshot().Status) {
		return nil, fmt.Errorf("来源任务已结束")
	}
	pending := 0
	for _, r := range existing {
		if r.SourceTaskID == sourceID && r.Status == "pending" {
			pending++
		}
	}
	if pending >= 8 {
		return nil, fmt.Errorf("当前最多同时等待8个跨流程委托，请先处理已有结果")
	}
	var target *Task
	helper := false
	if in.TargetTaskID == 0 {
		if source.Kind == "reverse" {
			return nil, fmt.Errorf("行为验证必须指定已有授权渗透任务，不会从客户端地址自动建立测试范围")
		}
		if len(snap.Files) == 0 {
			return nil, fmt.Errorf("创建逆向协助任务前至少选择一个本任务材料")
		}
		target, err = s.m.CreateTaskWithOptions("定向逆向协助；仅处理选定材料，问题："+in.Question, in.Question, db.TaskCreateOptions{Kind: "reverse", Name: "逆向协助", TimeoutSeconds: in.BudgetSeconds, LLMProfileIDs: source.llmStateSnapshot().ProfileIDs})
		if err != nil {
			return nil, err
		}
		in.TargetTaskID, _ = strconv.ParseInt(target.ID, 10, 64)
		helper = true
	} else {
		var ok bool
		target, ok = s.m.Task(strconv.FormatInt(in.TargetTaskID, 10))
		if !ok {
			return nil, fmt.Errorf("接收任务不存在")
		}
	}
	r, _, err := s.m.pg.CreateWorkflowRequest(ctx, db.WorkflowRequestInput{RequestKey: in.RequestKey, SourceTaskID: sourceID, TargetTaskID: in.TargetTaskID, Question: in.Question, Acceptance: in.Acceptance, InputSnapshot: raw, BudgetSeconds: in.BudgetSeconds, ParentRequestID: in.ParentRequestID})
	if err != nil {
		if helper {
			_, _ = s.m.DeleteTask(target.ID, DeleteTaskOptions{})
		}
		return nil, err
	}
	if err = s.prepareWorkflowRequest(ctx, r); err != nil {
		return r, fmt.Errorf("委托已保存，准备材料失败，可用相同请求键重试：%w", err)
	}
	if helper {
		s.seed(target, "")
		_, err = s.admitTask(target, "resume")
		if err != nil {
			return r, err
		}
	} else if !target.lifecycleSnapshot().Paused && !target.lifecycleSnapshot().Queued {
		s.engine.Run(s.ctx, target)
		target.Notify()
	}
	return s.m.pg.GetWorkflowRequest(ctx, r.ID)
}

func (s *Server) prepareWorkflowRequest(ctx context.Context, r *db.WorkflowRequest) error {
	source, ok := s.m.Task(strconv.FormatInt(r.SourceTaskID, 10))
	if !ok {
		return fmt.Errorf("来源任务不可用")
	}
	target, ok := s.m.Task(strconv.FormatInt(r.TargetTaskID, 10))
	if !ok {
		return fmt.Errorf("接收任务不可用")
	}
	var snap workflowSnapshot
	if err := json.Unmarshal(r.InputSnapshot, &snap); err != nil {
		return err
	}
	materialIndex := []map[string]any{}
	for i, f := range snap.Files {
		src, err := reverseLocalPath(s.m.dir, filepath.Join("tasks", source.ID, f.Path), filepath.Join("tasks", source.ID))
		if err != nil {
			return err
		}
		dir := filepath.Join("tasks", target.ID, "delegations", fmt.Sprint(r.ID))
		if target.Kind == "reverse" {
			dir = filepath.Join("tasks", target.ID, "reverse", "artifacts")
		}
		name := fmt.Sprintf("request-%d-%d-%s", r.ID, i, reverseName(f.Path))
		rel := filepath.Join(dir, name)
		dst := filepath.Join(s.m.dir, rel)
		if err = os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
			return err
		}
		data, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		h := sha256.Sum256(data)
		if int64(len(data)) != f.Size || hex.EncodeToString(h[:]) != f.SHA256 {
			return fmt.Errorf("材料已变化，须重新选择并使用新请求键")
		}
		if old, err := os.ReadFile(dst); err == nil {
			oh := sha256.Sum256(old)
			if oh != h {
				return fmt.Errorf("接收材料哈希冲突")
			}
		} else if !os.IsNotExist(err) {
			return err
		} else if err = os.WriteFile(dst, data, 0600); err != nil {
			return err
		}
		item := map[string]any{"source_path": f.Path, "local_path": filepath.ToSlash(rel), "sha256": f.SHA256}
		if target.Kind == "reverse" {
			artifacts, err := s.m.pg.ListReverseArtifacts(r.TargetTaskID)
			if err != nil {
				return err
			}
			var aid int64
			for _, a := range artifacts {
				if a.Path == rel {
					aid = a.ID
					break
				}
			}
			if aid == 0 {
				a, err := s.m.pg.AddReverseArtifact(r.TargetTaskID, db.ReverseArtifact{Name: reverseName(f.Path), Path: rel, Format: strings.TrimPrefix(strings.ToLower(filepath.Ext(f.Path)), "."), SizeBytes: f.Size, SHA256: f.SHA256, Source: fmt.Sprintf("workflow request %d, task %d", r.ID, r.SourceTaskID)})
				if err != nil {
					return err
				}
				aid = a.ID
			}
			item["artifact_id"] = aid
		}
		materialIndex = append(materialIndex, item)
	}
	if r.SourceIntentID != nil && r.TargetIntentID != nil {
		return nil
	}
	tx, err := s.m.pg.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var bound bool
	if err = tx.QueryRowContext(ctx, `SELECT source_intent_id IS NOT NULL AND target_intent_id IS NOT NULL FROM workflow_requests WHERE id=$1 AND status='pending' FOR UPDATE`, r.ID).Scan(&bound); err != nil {
		return err
	}
	if bound {
		return nil
	}
	waitPayload, _ := json.Marshal(map[string]any{"summary": "等待跨流程协助：" + r.Question, "workflow_wait_id": r.ID})
	var sid, tid int64
	if err = tx.QueryRowContext(ctx, `INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin) VALUES($1,'intent',$2,5,'waiting','workflow') RETURNING id`, source.Store.ID(), string(waitPayload)).Scan(&sid); err != nil {
		return err
	}
	role := "worker"
	if target.Kind == "reverse" {
		role = "reverse_static"
	}
	goalPayload, _ := json.Marshal(map[string]any{"text": r.Question, "workflow_request_id": r.ID})
	var goalID int64
	if err = tx.QueryRowContext(ctx, `INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin) VALUES($1,'goal',$2,5,'open','workflow') RETURNING id`, target.Store.ID(), string(goalPayload)).Scan(&goalID); err != nil {
		return err
	}
	contract := db.WorkContract{ExecutionRole: role, WorkflowRequestID: r.ID, GoalIDs: []int64{goalID}, Acceptance: r.Acceptance, BudgetSeconds: r.BudgetSeconds, DirectionKey: fmt.Sprintf("workflow-%d", r.ID)}
	payload, _ := json.Marshal(map[string]any{"summary": "处理跨流程委托：" + r.Question, "contract": contract, "contract_version": 1, "workflow_input": map[string]any{"materials": materialIndex, "evidence": snap.Evidence}, "workflow_request_id": r.ID})
	if err = tx.QueryRowContext(ctx, `INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin) VALUES($1,'intent',$2,7,'open','workflow') RETURNING id`, target.Store.ID(), string(payload)).Scan(&tid); err != nil {
		return err
	}
	for _, edge := range []struct {
		exp, node int64
		rel       string
	}{{source.Store.ID(), sid, db.RelDerivedFrom}, {target.Store.ID(), tid, db.RelDerivedFrom}, {target.Store.ID(), goalID, db.RelSpawns}} {
		if _, err = tx.ExecContext(ctx, `INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) SELECT exploration_id,id,$3,$2 FROM exploration_nodes WHERE exploration_id=$1 AND kind='fact' AND state='origin' ORDER BY id LIMIT 1 ON CONFLICT DO NOTHING`, edge.exp, edge.node, edge.rel); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE workflow_requests SET source_intent_id=$2,target_intent_id=$3 WHERE id=$1`, r.ID, sid, tid); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	source.Notify()
	target.Notify()
	return nil
}

func (s *Server) returnWorkflowResult(ctx context.Context, task *Task, id int64, status, summary, limitations string, refs []db.EvidenceReference) error {
	r, err := s.m.pg.GetWorkflowRequest(ctx, id)
	if err != nil {
		return err
	}
	targetID, _ := strconv.ParseInt(task.ID, 10, 64)
	if r.TargetTaskID != targetID {
		return db.ErrWorkflowRequestDenied
	}
	if status != "accepted" && status != "unresolved" {
		return fmt.Errorf("结果状态必须为 accepted/unresolved")
	}
	if strings.TrimSpace(summary) == "" || len(summary) > 12000 || len(limitations) > 8000 {
		return fmt.Errorf("结果摘要/局限无效")
	}
	evidence, err := s.selectedWorkflowEvidence(task, refs)
	if err != nil {
		return err
	}
	if len(evidence) == 0 {
		return fmt.Errorf("结果至少引用一条本任务持久证据；未解决也需说明尝试及缺口")
	}
	if status == "accepted" {
		for _, e := range evidence {
			var p map[string]any
			_ = json.Unmarshal(e.Payload, &p)
			if p["confidence"] == "inferred" || p["evidence"] == nil {
				return fmt.Errorf("推断或缺少原始证据的事实不能作为accepted答案")
			}
		}
	}
	if status == "accepted" && task.Kind == "reverse" {
		for _, e := range evidence {
			var p struct {
				ConclusionID int64 `json:"reverse_conclusion_id"`
			}
			_ = json.Unmarshal(e.Payload, &p)
			cs, err := s.m.pg.ListReverseConclusions(targetID)
			if err != nil {
				return err
			}
			valid := false
			for _, c := range cs {
				if c.ID == p.ConclusionID && c.NodeID != nil && *c.NodeID == e.NodeID && c.State == "accepted" && c.ReviewerIntentID != nil {
					valid = true
				}
			}
			if !valid {
				return fmt.Errorf("逆向accepted回传只能引用已独立核验接受的结论事实")
			}
		}
	}
	answer, _ := json.Marshal(workflowAnswer{status, summary, limitations, evidence})
	if err = s.m.pg.CompleteWorkflowRequest(ctx, id, targetID, answer); err != nil {
		return err
	}
	r, err = s.m.pg.GetWorkflowRequest(ctx, id)
	if err != nil {
		return err
	}
	return s.settleWorkflowRequest(ctx, r)
}

// Repeated settlement is safe after a restart. Imported results are hypotheses:
// they cannot prove a parent goal or become a confirmed vulnerability on arrival.
func (s *Server) settleWorkflowRequest(ctx context.Context, r *db.WorkflowRequest) error {
	if r.Status == "pending" {
		return fmt.Errorf("待处理委托不能发布终态结果")
	}
	tx, err := s.m.pg.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if r.SourceIntentID != nil {
		payload, _ := json.Marshal(map[string]any{"summary": fmt.Sprintf("跨流程协助 #%d：%s", r.ID, r.Status), "evidence": map[string]any{"request_id": r.ID, "result": r.Result, "input_snapshot": r.InputSnapshot}, "confidence": "inferred", "workflow_request_id": r.ID})
		if _, err = tx.ExecContext(ctx, `INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin) SELECT exploration_id,'fact',$2,5,'confirmed','workflow' FROM tasks WHERE id=$1 AND deleted_at IS NULL AND NOT EXISTS(SELECT 1 FROM exploration_nodes n WHERE n.exploration_id=tasks.exploration_id AND n.kind='fact' AND n.origin='workflow' AND n.payload->>'workflow_request_id'=$3)`, r.SourceTaskID, string(payload), fmt.Sprint(r.ID)); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) SELECT n.exploration_id,$1,'yields',n.id FROM exploration_nodes n JOIN tasks t ON t.exploration_id=n.exploration_id WHERE t.id=$2 AND n.kind='fact' AND n.origin='workflow' AND n.payload->>'workflow_request_id'=$3 ON CONFLICT DO NOTHING`, *r.SourceIntentID, r.SourceTaskID, fmt.Sprint(r.ID)); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state=$2 WHERE id=$1 AND state='waiting' AND payload->>'workflow_wait_id'=$3`, *r.SourceIntentID, map[bool]string{true: "done", false: "blocked"}[r.Status == "completed"], fmt.Sprint(r.ID)); err != nil {
			return err
		}
	}
	if r.Status != "completed" {
		if _, err = tx.ExecContext(ctx, `UPDATE exploration_nodes n SET state='stopped' FROM tasks t WHERE t.id=$1 AND n.exploration_id=t.exploration_id AND n.kind='intent' AND n.state IN ('open','waiting') AND n.payload->'contract'->>'workflow_request_id'=$2`, r.TargetTaskID, fmt.Sprint(r.ID)); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE exploration_nodes n SET state='abandoned' FROM tasks t WHERE t.id=$1 AND n.exploration_id=t.exploration_id AND n.kind='goal' AND n.origin='workflow' AND n.state='open' AND n.payload->>'workflow_request_id'=$2`, r.TargetTaskID, fmt.Sprint(r.ID)); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if r.Status != "completed" {
		rows, err := s.m.pg.QueryContext(ctx, `SELECT n.id FROM exploration_nodes n JOIN tasks t ON t.exploration_id=n.exploration_id WHERE t.id=$1 AND n.kind='intent' AND n.state='running' AND n.payload->'contract'->>'workflow_request_id'=$2`, r.TargetTaskID, fmt.Sprint(r.ID))
		if err != nil {
			return err
		}
		ids := []int64{}
		for rows.Next() {
			var id int64
			if err = rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		for _, id := range ids {
			_ = s.engine.KillWork(id)
		}
	}
	for _, tid := range []int64{r.SourceTaskID, r.TargetTaskID} {
		if t, ok := s.m.Task(fmt.Sprint(tid)); ok {
			t.Notify()
		}
	}
	return nil
}

func (s *Server) cancelWorkflowRequest(ctx context.Context, source *Task, id int64) error {
	tid, _ := strconv.ParseInt(source.ID, 10, 64)
	if err := s.m.pg.CancelWorkflowRequest(ctx, id, tid); err != nil {
		return err
	}
	r, err := s.m.pg.GetWorkflowRequest(ctx, id)
	if err != nil {
		return err
	}
	return s.settleWorkflowRequest(ctx, r)
}

func (s *Server) reconcileWorkflowRequests(ctx context.Context) error {
	if _, err := s.m.pg.ExpireWorkflowRequests(ctx); err != nil {
		return err
	}
	for _, query := range []string{
		`UPDATE workflow_requests wr SET status='expired' FROM tasks source,tasks target WHERE wr.source_task_id=source.id AND wr.target_task_id=target.id AND wr.status='pending' AND (source.deleted_at IS NOT NULL OR target.deleted_at IS NOT NULL OR source.status IN('done','failed','timeout') OR target.status IN('done','failed','timeout'))`,
		`UPDATE workflow_requests child SET status='expired' FROM workflow_requests parent WHERE child.parent_request_id=parent.id AND child.status='pending' AND parent.status<>'pending'`,
	} {
		if _, err := s.m.pg.ExecContext(ctx, query); err != nil {
			return err
		}
	}
	rows, err := s.m.pg.QueryContext(ctx, `SELECT id FROM workflow_requests WHERE status<>'pending' AND (source_intent_id IN(SELECT id FROM exploration_nodes WHERE state='waiting') OR target_intent_id IN(SELECT id FROM exploration_nodes WHERE state IN('open','waiting','running')))`)
	if err != nil {
		return err
	}
	ids := []int64{}
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		r, err := s.m.pg.GetWorkflowRequest(ctx, id)
		if err != nil {
			return err
		}
		if err = s.settleWorkflowRequest(ctx, r); err != nil {
			return err
		}
	}
	// A task deletion cascades the request row. Reconcile its remaining peer's
	// waiting/owned work even though the request can no longer be joined.
	rows, err = s.m.pg.QueryContext(ctx, `UPDATE exploration_nodes n SET state='blocked',payload=n.payload || '{"workflow_error":"委托或关联任务已删除；没有收到可用结果"}'::jsonb WHERE n.kind='intent' AND n.state='waiting' AND n.payload ? 'workflow_wait_id' AND NOT EXISTS(SELECT 1 FROM workflow_requests r WHERE r.id=(n.payload->>'workflow_wait_id')::bigint) RETURNING n.exploration_id`)
	if err != nil {
		return err
	}
	exps := map[int64]bool{}
	for rows.Next() {
		var exp int64
		if err = rows.Scan(&exp); err != nil {
			rows.Close()
			return err
		}
		exps[exp] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = s.m.pg.QueryContext(ctx, `UPDATE exploration_nodes n SET state='stopped' WHERE n.kind='intent' AND n.state IN('open','waiting') AND COALESCE(n.payload->'contract'->>'workflow_request_id','0')<>'0' AND NOT EXISTS(SELECT 1 FROM workflow_requests r WHERE r.id=(n.payload->'contract'->>'workflow_request_id')::bigint AND r.status='pending') RETURNING n.exploration_id`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var exp int64
		if err = rows.Scan(&exp); err != nil {
			rows.Close()
			return err
		}
		exps[exp] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = s.m.pg.QueryContext(ctx, `SELECT n.id FROM exploration_nodes n WHERE n.kind='intent' AND n.state='running' AND COALESCE(n.payload->'contract'->>'workflow_request_id','0')<>'0' AND NOT EXISTS(SELECT 1 FROM workflow_requests r WHERE r.id=(n.payload->'contract'->>'workflow_request_id')::bigint AND r.status='pending')`)
	if err != nil {
		return err
	}
	ids = nil
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		_ = s.engine.KillWork(id)
	}
	for _, task := range s.m.List() {
		if exps[task.Store.ID()] {
			task.Notify()
		}
	}
	return nil
}

func (s *Server) workflowRequestLoop() {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-tick.C:
			if err := s.reconcileWorkflowRequests(s.ctx); err != nil && s.ctx.Err() == nil {
				log.Printf("[workflow] reconciliation: %v", err)
			}
			s.reconcileConcurrency()
		}
	}
}

func (s *Server) onlyWaitingForWorkflow(t *Task) bool {
	if s.m == nil || s.m.pg == nil || t == nil || t.Store == nil {
		return false
	}
	var waiting bool
	err := s.m.pg.QueryRow(`SELECT EXISTS(SELECT 1 FROM exploration_nodes WHERE exploration_id=$1 AND kind='intent' AND state='waiting' AND payload ? 'workflow_wait_id') AND NOT EXISTS(SELECT 1 FROM exploration_nodes WHERE exploration_id=$1 AND kind='intent' AND state IN ('open','running') AND NOT(payload ? 'workflow_wait_id'))`, t.Store.ID()).Scan(&waiting)
	return err == nil && waiting
}

func (s *Server) workflowRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/tasks/{id}/workflow-requests", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeErr(w, 400, "invalid task")
			return
		}
		requests, err := s.m.pg.ListWorkflowRequests(r.Context(), id)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if requests == nil {
			requests = []*db.WorkflowRequest{}
		}
		writeJSON(w, 200, requests)
	})
	mux.HandleFunc("POST /api/tasks/{id}/workflow-requests", func(w http.ResponseWriter, r *http.Request) {
		t, ok := s.m.Task(r.PathValue("id"))
		if !ok {
			writeErr(w, 404, "task not found")
			return
		}
		var in workflowHelpInput
		if err := decode(r, &in); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		req, err := s.requestWorkflowHelp(r.Context(), t, in)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		writeJSON(w, 201, req)
	})
	mux.HandleFunc("POST /api/tasks/{id}/workflow-requests/{rid}/cancel", func(w http.ResponseWriter, r *http.Request) {
		t, ok := s.m.Task(r.PathValue("id"))
		if !ok {
			writeErr(w, 404, "task not found")
			return
		}
		id, err := strconv.ParseInt(r.PathValue("rid"), 10, 64)
		if err == nil {
			err = s.cancelWorkflowRequest(r.Context(), t, id)
		}
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
}

func (s *Server) workflowTools() []actool.CoreTool {
	object := func(props map[string]any, required ...string) map[string]any {
		return reverseObject(props, required...)
	}
	actor := func(ctx context.Context) (*Task, error) {
		id := agent.RunInfoFrom(ctx).TaskID
		t, ok := s.m.Task(fmt.Sprint(id))
		if !ok {
			return nil, fmt.Errorf("工具只能用于当前任务会话")
		}
		return t, nil
	}
	wrap := func(fn func(context.Context, json.RawMessage) (any, error)) func(context.Context, json.RawMessage) (actool.Result, error) {
		return func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			v, err := fn(ctx, in)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(v)
		}
	}
	refs := map[string]any{"type": "array", "items": object(map[string]any{"node_id": reverseInt(), "version": reverseString()}, "node_id", "version")}
	return []actool.CoreTool{
		wrTool("request_workflow_help", "向另一工作流发出有界委托。只复制选定文件与事实；不继承整任务和运行授权。渗透可省略target_task_id自动建立逆向协助；逆向必须指定已有授权渗透任务。相同请求重试沿用request_key。", object(map[string]any{"request_key": reverseString(), "target_task_id": reverseInt(), "question": reverseString(), "acceptance": map[string]any{"type": "array", "items": reverseString()}, "files": map[string]any{"type": "array", "items": reverseString()}, "evidence_refs": refs, "budget_seconds": reverseInt(), "parent_request_id": reverseInt()}, "request_key", "question", "acceptance", "budget_seconds"), wrap(func(ctx context.Context, in json.RawMessage) (any, error) {
			t, err := actor(ctx)
			if err != nil {
				return nil, err
			}
			var args workflowHelpInput
			if err = json.Unmarshal(in, &args); err != nil {
				return nil, err
			}
			return s.requestWorkflowHelp(ctx, t, args)
		})),
		roTool("list_workflow_requests", "读取当前任务发出和收到的定向委托，含选定输入、预算、状态与结果。收到委托后所有分析与复核工作沿用contract.workflow_request_id；验收后return_workflow_result，来源任务自行验证目标。", object(map[string]any{}), wrap(func(ctx context.Context, _ json.RawMessage) (any, error) {
			t, err := actor(ctx)
			if err != nil {
				return nil, err
			}
			id, _ := strconv.ParseInt(t.ID, 10, 64)
			return s.m.pg.ListWorkflowRequests(ctx, id)
		})),
		wrTool("return_workflow_result", "向来源任务回传已核对结果或未决原因。accepted逆向答案必须引用已独立核验接受的结论事实；回传不自动确认来源目标/漏洞。", object(map[string]any{"request_id": reverseInt(), "status": map[string]any{"type": "string", "enum": []string{"accepted", "unresolved"}}, "summary": reverseString(), "limitations": reverseString(), "evidence_refs": refs}, "request_id", "status", "summary", "limitations", "evidence_refs"), wrap(func(ctx context.Context, in json.RawMessage) (any, error) {
			t, err := actor(ctx)
			if err != nil {
				return nil, err
			}
			var a struct {
				ID                           int64 `json:"request_id"`
				Status, Summary, Limitations string
				Evidence                     []db.EvidenceReference `json:"evidence_refs"`
			}
			if err = json.Unmarshal(in, &a); err != nil {
				return nil, err
			}
			err = s.returnWorkflowResult(ctx, t, a.ID, a.Status, a.Summary, a.Limitations, a.Evidence)
			return map[string]bool{"ok": err == nil}, err
		})),
		wrTool("cancel_workflow_request", "取消当前任务发出的一个委托，仅停止带该请求编号的工作。", object(map[string]any{"request_id": reverseInt()}, "request_id"), wrap(func(ctx context.Context, in json.RawMessage) (any, error) {
			t, err := actor(ctx)
			if err != nil {
				return nil, err
			}
			var a struct {
				ID int64 `json:"request_id"`
			}
			if err = json.Unmarshal(in, &a); err != nil {
				return nil, err
			}
			err = s.cancelWorkflowRequest(ctx, t, a.ID)
			return map[string]bool{"ok": err == nil}, err
		})),
	}
}

func (s *Server) seedWorkflowTools() error {
	for _, t := range s.workflowTools() {
		schema, _ := json.Marshal(t.InputSchema())
		for _, reverse := range []bool{false, true} {
			key := t.Name()
			roles := []string{"planner", "mainagent"}
			if reverse {
				key = reverseToolPrefix + key
				roles = []string{"reverse_planner", "reverse_main"}
			}
			binds, _ := json.Marshal(roles)
			if err := s.m.pg.SeedTool(key, t.Description(), schema, binds); err != nil {
				return err
			}
		}
	}
	return nil
}
