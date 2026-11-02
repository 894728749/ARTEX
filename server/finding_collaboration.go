package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	actool "github.com/Autumn-27/norma/tool"
)

const findingReviewerKey = "finding_reviewer"

func (s *Server) trackFindingConversation(ctx context.Context, taskID int64, allowPaused bool) func() {
	c := agent.ControlFrom(ctx)
	if c == nil {
		return func() {}
	}
	tid := strconv.FormatInt(taskID, 10)
	s.engine.liveMu.Lock()
	if s.engine.liveRuns == nil {
		s.engine.liveRuns = map[*agent.LiveControl]string{}
	}
	s.engine.liveRuns[c] = tid
	if (!allowPaused && s.engine.IsPaused(tid)) || s.engine.IsDeleting(tid) {
		c.RequestPause()
	}
	s.engine.liveMu.Unlock()
	return func() { s.engine.liveMu.Lock(); delete(s.engine.liveRuns, c); s.engine.liveMu.Unlock() }
}

func (s *Server) findingTask(w http.ResponseWriter, r *http.Request) (int64, bool) {
	if s.pg(w) == nil {
		return 0, false
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad task id")
		return 0, false
	}
	if _, ok = s.m.Task(strconv.FormatInt(id, 10)); !ok {
		writeErr(w, 404, "task not found")
		return 0, false
	}
	return id, true
}

func (s *Server) registerFindingCollaboration(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/tasks/{id}/finding-relations", func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.findingTask(w, r)
		if !ok {
			return
		}
		nodes, edges, err := s.m.pg.FindingGraph(id)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"nodes": nodes, "edges": edges})
	})
	mux.HandleFunc("POST /api/tasks/{id}/finding-relations", func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.findingTask(w, r)
		if !ok {
			return
		}
		var edge db.FindingRelation
		if !decodeConversationRequest(w, r, &edge) {
			return
		}
		rid, err := s.m.pg.SaveFindingRelation(r.Context(), id, edge)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		writeJSON(w, 201, map[string]any{"id": rid})
	})
	mux.HandleFunc("DELETE /api/tasks/{id}/finding-relations/{rid}", func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.findingTask(w, r)
		if !ok {
			return
		}
		rid, ok := pathInt(r, "rid")
		if !ok {
			writeErr(w, 400, "bad relation id")
			return
		}
		// Use the same task-row lock as merge/relation creation.
		tx, err := s.m.pg.BeginTx(r.Context(), nil)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		defer tx.Rollback()
		if _, err = tx.Exec(`SELECT id FROM tasks WHERE id=$1 FOR UPDATE`, id); err == nil {
			_, err = tx.Exec(`DELETE FROM finding_relations WHERE id=$1 AND task_id=$2`, rid, id)
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"deleted": true})
	})
	mux.HandleFunc("GET /api/tasks/{id}/finding-review-status", func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.findingTask(w, r)
		if !ok {
			return
		}
		out, err := s.m.pg.FindingReviewStatus(id)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, out)
	})
	mux.HandleFunc("PATCH /api/tasks/{id}/finding-review-status", func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.findingTask(w, r)
		if !ok {
			return
		}
		var in struct {
			Enabled   *bool `json:"enabled"`
			BatchSize *int  `json:"batch_size"`
		}
		if !decodeConversationRequest(w, r, &in) {
			return
		}
		if in.BatchSize != nil && (*in.BatchSize < 2 || *in.BatchSize > 20) {
			writeErr(w, 400, "每批须为 2–20 个新漏洞")
			return
		}
		if _, err := s.m.pg.FindingReviewStatus(id); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if _, err := s.m.pg.Exec(`UPDATE finding_review_state SET enabled=COALESCE($2,enabled),batch_size=COALESCE($3,batch_size) WHERE task_id=$1`, id, in.Enabled, in.BatchSize); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		out, err := s.m.pg.FindingReviewStatus(id)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, out)
	})
	mux.HandleFunc("POST /api/tasks/{id}/finding-review", func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.findingTask(w, r)
		if !ok {
			return
		}
		cid, err := s.startFindingReview(r.Context(), id, true)
		if err != nil {
			writeErr(w, 409, err.Error())
			return
		}
		writeJSON(w, 202, map[string]any{"accepted": cid > 0, "conversation_id": cid})
	})
}

func (s *Server) findingAgentReady(key string) error {
	a, err := s.m.pg.GetAgentByKey(key)
	if err != nil {
		return err
	}
	if a == nil || !a.Enabled {
		return fmt.Errorf("请先启用并配置 %s Agent", key)
	}
	if s.resolveChatAgent(&db.Conversation{AgentKey: key}) == nil {
		return errors.New(s.chatUnavailableReason())
	}
	return nil
}

func (s *Server) startFindingReview(ctx context.Context, taskID int64, manual bool) (int64, error) {
	if s.ctx.Err() != nil {
		return 0, errors.New("服务正在停止")
	}
	if err := s.findingAgentReady(findingReviewerKey); err != nil {
		return 0, err
	}
	id, cutoff, err := s.m.pg.BeginFindingReview(ctx, taskID, manual)
	if err != nil || id == 0 {
		return 0, err
	}
	fail := func(err error) (int64, error) {
		_ = s.m.pg.FinishFindingReview(context.Background(), id, false, err.Error())
		return 0, err
	}
	c, err := s.m.pg.CreateConversation(findingReviewerKey, "漏洞归类与关联检查", nil)
	if err != nil {
		return fail(err)
	}
	if _, err = s.m.pg.Exec(`UPDATE finding_reviews SET conversation_id=$2 WHERE id=$1`, id, c.ID); err != nil {
		return fail(err)
	}
	key := s.convBusyKey(c.ID)
	s.chatMu.Lock()
	s.chatBusy[key] = true
	s.chatMu.Unlock()
	// Reserve the cancellation/mailbox before acknowledging the HTTP request.
	runCtx, cancel := s.conversationRunContext(c.ID, key)
	release := s.trackFindingConversation(runCtx, taskID, manual)
	go func() {
		defer release()
		s.runConversationTurn(runCtx, cancel, c, fmt.Sprintf("检查本会话关联任务的漏洞。先调用 get_finding_review_context，遍历全部分页；本批截止记录为 %d。完成后必须调用 finish_finding_review。", cutoff), key)
		// No completion tool means no watermark advance (including interruption).
		_ = s.m.pg.FinishFindingReview(context.Background(), id, false, "检查未保存完成结论或被中断，请手动重试")
	}()
	return c.ID, nil
}

// Durable batch watermarks avoid polling the model or repeating a failed batch.
// Existing tasks receive an upgrade watermark; only new findings/manual review
// start work. Report rewrites are persisted in the merge transaction.
func (s *Server) runFindingReviewScheduler() {
	if s.ctx.Err() != nil {
		return
	}
	rows, err := s.m.pg.Query(`SELECT id FROM finding_reviews WHERE status='running'`)
	if err == nil {
		var ids []int64
		for rows.Next() {
			var id int64
			if rows.Scan(&id) == nil {
				ids = append(ids, id)
			}
		}
		rows.Close()
		for _, id := range ids {
			_ = s.m.pg.FinishFindingReview(context.Background(), id, false, "服务中断，检查未完成，请手动重试")
		}
	}
	_, _ = s.m.pg.Exec(`UPDATE finding_report_rewrites SET status='failed',last_error='服务中断，请重新发起检查以重试报告' WHERE status='running'`)
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			tasks, err := s.m.pg.ListTasks()
			if err != nil {
				continue
			}
			for _, t := range tasks {
				if s.ctx.Err() != nil {
					return
				}
				// Pausing a task also prevents automatic background review admission.
				tid := strconv.FormatInt(t.ID, 10)
				if s.engine != nil && s.engine.IsPaused(tid) {
					continue
				}
				status, err := s.m.pg.FindingReviewStatus(t.ID)
				if err != nil || !status.Enabled || status.Running || status.PendingCount < status.BatchSize {
					continue
				}
				if _, err = s.startFindingReview(s.ctx, t.ID, false); err != nil {
					log.Printf("[finding review] task %d: %v", t.ID, err)
				}
			}
			go s.runPendingFindingRewrite()
		}
	}
}

func (s *Server) runPendingFindingRewrite() {
	if s.ctx.Err() != nil {
		return
	}
	if err := s.findingAgentReady("reporter"); err != nil {
		return
	}
	var jobID, findingID, version int64
	// One rewrite at a time; durable running state guards later ticks. Failed rewrites
	// require an explicit review retry, never an unbounded paid retry loop.
	err := s.m.pg.QueryRow(`UPDATE finding_report_rewrites SET status='running' WHERE NOT EXISTS(SELECT 1 FROM finding_report_rewrites WHERE status='running') AND id=(SELECT j.id FROM finding_report_rewrites j JOIN findings f ON f.id=j.finding_id JOIN tasks t ON t.id=f.task_id WHERE j.status='pending' AND f.merged_into IS NULL AND t.deleted_at IS NULL AND NOT t.paused ORDER BY j.id LIMIT 1) RETURNING id,finding_id,evidence_version`).Scan(&jobID, &findingID, &version)
	if err != nil {
		return
	}
	failure := ""
	defer func() {
		status := "completed"
		if failure != "" {
			status = "failed"
		}
		_, err := s.m.pg.Exec(`UPDATE finding_report_rewrites SET status=$2,last_error=$3 WHERE id=$1`, jobID, status, failure)
		if err != nil {
			log.Printf("[finding rewrite] finish: %v", err)
		}
	}()
	f, err := s.m.pg.GetFinding(findingID)
	if err != nil {
		failure = err.Error()
		return
	}
	if f == nil || f.NodeID == nil {
		failure = "漏洞缺少可写报告节点，请人工检查"
		return
	}
	if f.EvidenceVersion != version {
		if f.Report == "" || f.ReportEvidenceVersion != f.EvidenceVersion {
			_, err = s.m.pg.Exec(`INSERT INTO finding_report_rewrites(finding_id,evidence_version) VALUES($1,$2) ON CONFLICT DO NOTHING`, findingID, f.EvidenceVersion)
			if err != nil {
				failure = err.Error()
			}
		}
		return
	}
	c, err := s.m.pg.CreateConversation("reporter", "漏洞报告重写 · "+f.Name, nil)
	if err != nil {
		failure = err.Error()
		return
	}
	_, err = s.m.pg.Exec(`UPDATE finding_report_rewrites SET conversation_id=$2 WHERE id=$1`, jobID, c.ID)
	if err != nil {
		failure = err.Error()
		return
	}
	key := s.convBusyKey(c.ID)
	s.chatMu.Lock()
	s.chatBusy[key] = true
	s.chatMu.Unlock()
	msg := fmt.Sprintf("请读取并重写漏洞报告。平台查询用 finding_id=%d，写入 update_finding_report 用 finding_id（节点 ID）=%d。先读取最新证据和绑定流量，再提交对应 evidence_version=%d 的报告。将全部已验证影响作为一个整体漏洞说明，不描述归并过程，不以平台内部编号或执行机路径作为复现依据。保留证据限定、真实目标路径和操作步骤，使用相对附件引用与自包含必要证据，不新增网络测试。", findingID, *f.NodeID, version)
	if f.TaskID != nil {
		msg = fmt.Sprintf("所属 task_id=%d。\n", *f.TaskID) + msg
	}
	runCtx, cancel := s.conversationRunContext(c.ID, key)
	if f.TaskID != nil {
		release := s.trackFindingConversation(runCtx, *f.TaskID, false)
		defer release()
	}
	s.runConversationTurn(runCtx, cancel, c, msg, key)
	fresh, err := s.m.pg.GetFinding(findingID)
	if err != nil {
		failure = err.Error()
		return
	}
	if fresh == nil || strings.TrimSpace(fresh.Report) == "" || fresh.ReportEvidenceVersion != fresh.EvidenceVersion || fresh.EvidenceVersion < version {
		failure = "报告未写入最新证据版本，请在漏洞归类中手动重试"
	}
}

func (s *Server) findingReviewTools() []actool.CoreTool {
	scope := func(ctx context.Context) (int64, int64, int64, error) {
		return s.m.pg.FindingReviewContext(ctx, intercept.ConvIDFromContext(ctx))
	}
	return []actool.CoreTool{
		roTool("get_finding_review_context", "分页读取本次检查任务的漏洞（默认每页 10，最多 20）与现有关联；finding_id 指定时读取完整证据及流量快照。只能读取本次检查范围。", objSchema(map[string]any{"offset": map[string]any{"type": "integer", "minimum": 0}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 20}, "finding_id": map[string]any{"type": "integer"}, "binding_id": map[string]any{"type": "integer", "description": "读取本漏洞已绑定的证据正文；先读取 finding_id 取得绑定清单"}, "side": map[string]any{"type": "string", "enum": []string{"request", "response"}}, "body_offset": map[string]any{"type": "integer", "minimum": 0}, "length": map[string]any{"type": "integer", "minimum": 1}}), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			_, tid, cutoff, err := scope(ctx)
			if err != nil {
				return actool.Errorf("当前会话没有进行中的漏洞检查"), nil
			}
			var a struct {
				Offset, Limit int
				FindingID     int64  `json:"finding_id"`
				BindingID     int64  `json:"binding_id"`
				Side          string `json:"side"`
				BodyOffset    int64  `json:"body_offset"`
				Length        int64  `json:"length"`
			}
			if err = json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if a.Offset < 0 {
				a.Offset = 0
			}
			if a.Limit < 1 || a.Limit > 20 {
				a.Limit = 10
			}
			if a.FindingID > 0 {
				var raw string
				err = s.m.pg.QueryRowContext(ctx, `SELECT to_jsonb(f)::text FROM findings f WHERE id=$1 AND task_id=$2 AND id<=$3 AND merged_into IS NULL`, a.FindingID, tid, cutoff).Scan(&raw)
				if err != nil {
					return actool.Errorf("漏洞不属于本次检查范围"), nil
				}
				if a.BindingID > 0 {
					if a.Side == "" {
						a.Side = "response"
					}
					store := s.evidenceStore()
					var body any
					err = store.WithBinding(ctx, a.FindingID, a.BindingID, func(b db.FindingTrafficBinding) error {
						preview, err := readEvidencePreview(store, b.Snapshot, a.Side, a.BodyOffset, a.Length)
						if err != nil {
							return err
						}
						head := b.Snapshot.RespHead
						if a.Side == "request" {
							head = b.Snapshot.ReqHead
						}
						body = map[string]any{"head": head, "body": preview}
						return nil
					})
					if err != nil {
						return actool.Errorf(err.Error()), nil
					}
					return jsonResult(body)
				}
				traffic, err := s.m.pg.GetFindingTraffic(ctx, a.FindingID)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				return jsonResult(map[string]any{"finding": json.RawMessage(raw), "traffic": traffic})
			}
			rows, err := s.m.pg.QueryContext(ctx, `SELECT jsonb_build_object('id',id,'name',name,'vulnclass',vulnclass,'summary',summary,'severity',severity,'asset_ids',asset_ids,'evidence_version',evidence_version,'merged_into',merged_into)::text FROM findings WHERE task_id=$1 AND id<=$2 ORDER BY id LIMIT $3 OFFSET $4`, tid, cutoff, a.Limit+1, a.Offset)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			items := []json.RawMessage{}
			for rows.Next() {
				var raw string
				if err = rows.Scan(&raw); err != nil {
					break
				}
				items = append(items, json.RawMessage(raw))
			}
			if err == nil {
				err = rows.Err()
			}
			rows.Close()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			more := len(items) > a.Limit
			if more {
				items = items[:a.Limit]
			}
			_, edges, err := s.m.pg.FindingGraph(tid)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"task_id": tid, "cutoff": cutoff, "findings": items, "has_more": more, "next_offset": a.Offset + len(items), "relations": edges})
		}),
		wrTool("consolidate_findings", "将确认为同一具体根因的记录整理为一个漏洞，保存原证据审计并排队重写报告。必须先读取各项完整证据。不同根因或有前置关系的记录不能归并。", objSchema(map[string]any{
			"canonical_id": map[string]any{"type": "integer"}, "source_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}}, "name": strParam("统一漏洞名称，不写归并过程"), "summary": strParam("整体漏洞与已验证影响"), "severity": map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low"}}, "reason": strParam("具体同根因、修复边界与等级依据，仅存内部审计"), "versions": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "integer"}},
		}, "canonical_id", "source_ids", "name", "summary", "severity", "reason", "versions"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			rid, tid, cutoff, err := scope(ctx)
			if err != nil {
				return actool.Errorf("当前会话没有进行中的漏洞检查"), nil
			}
			var a db.ConsolidateFindingsInput
			if err = json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			for _, id := range append([]int64{a.CanonicalID}, a.SourceIDs...) {
				if id > cutoff {
					return actool.Errorf("候选超出本批范围，请留待下一批检查"), nil
				}
			}
			if err = s.findingAgentReady("reporter"); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if err = s.m.pg.ConsolidateFindings(ctx, tid, rid, a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"canonical_id": a.CanonicalID, "report_rewrite": "pending", "message": "已保留原始证据与审计，统一报告已排队重写"})
		}),
		wrTool("link_findings", "保存漏洞间有证据或明确待验证理由的关系。方向 source → target：前置条件/提供能力/支持证据/证据矛盾。", objSchema(map[string]any{"source": map[string]any{"type": "integer"}, "target": map[string]any{"type": "integer"}, "kind": map[string]any{"type": "string", "enum": []string{"prerequisite", "enables", "supports", "contradicts"}}, "rationale": strParam("关系成立的机制与理由"), "evidence": strParam("证据或具体待验证项"), "status": map[string]any{"type": "string", "enum": []string{"proposed", "verified"}}}, "source", "target", "kind", "rationale", "evidence", "status"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			_, tid, cutoff, err := scope(ctx)
			if err != nil {
				return actool.Errorf("当前会话没有进行中的漏洞检查"), nil
			}
			var a db.FindingRelation
			if err = json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if a.Source > cutoff || a.Target > cutoff {
				return actool.Errorf("关系超出本批范围"), nil
			}
			id, err := s.m.pg.SaveFindingRelation(ctx, tid, a)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"id": id})
		}),
		wrTool("finish_finding_review", "检查完本批全部记录后保存结论，推进批次水位。无可归并项也要说明依据；歧义项保留原记录。", objSchema(map[string]any{"summary": strParam("本批检查范围、处理结果与待确认事项")}, "summary"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			id, tid, _, err := scope(ctx)
			if err != nil {
				return actool.Errorf("当前会话没有进行中的漏洞检查"), nil
			}
			var a struct{ Summary string }
			if err = json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if err = s.m.pg.FinishFindingReview(ctx, id, true, a.Summary); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			// An explicit manual review also provides a bounded retry for failed
			// rewrites of the latest canonical evidence, without re-merging sources.
			_, _ = s.m.pg.Exec(`UPDATE finding_report_rewrites j SET status='pending',last_error='' FROM findings f WHERE j.finding_id=f.id AND f.task_id=$1 AND f.merged_into IS NULL AND j.evidence_version=f.evidence_version AND j.status='failed'`, tid)
			return jsonResult(map[string]any{"saved": true})
		}),
	}
}

func (s *Server) seedFindingReviewer() error {
	for _, t := range s.findingReviewTools() {
		schema, _ := json.Marshal(t.InputSchema())
		bindings, _ := json.Marshal([]string{findingReviewerKey})
		if err := s.m.pg.SeedTool(t.Name(), t.Description(), schema, bindings); err != nil {
			return err
		}
	}
	tx, err := s.m.pg.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`SELECT pg_advisory_xact_lock(7337741012)`); err != nil {
		return err
	}
	var done bool
	if err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM settings WHERE key='finding_reviewer_seed_v1')`).Scan(&done); err != nil {
		return err
	}
	if done {
		return nil
	}
	var id int64
	err = tx.QueryRow(`INSERT INTO agents(key,name,description,role,builtin,enabled,max_turns) VALUES($1,'漏洞归类与关联检查','每批检查同根因漏洞、证据边界及前置依赖，只处理已保存证据。','assistant',false,true,50) ON CONFLICT(key) DO NOTHING RETURNING id`, findingReviewerKey).Scan(&id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if id > 0 {
		var pid int64
		if err = tx.QueryRow(`INSERT INTO agent_prompts(agent_id,version,template_text,note,updated_by) VALUES($1,1,$2,'内置默认','system') RETURNING id`, id, agent.FindingReviewerPrompt).Scan(&pid); err != nil {
			return err
		}
		if _, err = tx.Exec(`UPDATE agents SET current_prompt_id=$1 WHERE id=$2`, pid, id); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(`INSERT INTO settings(key,value) VALUES('finding_reviewer_seed_v1','true') ON CONFLICT DO NOTHING`); err != nil {
		return err
	}
	return tx.Commit()
}
