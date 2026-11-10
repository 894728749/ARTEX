package server

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/collab"
	"github.com/Autumn-27/artex/db"
)

func (s *Server) teamMessageRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/teams/{team}/tasks/{task}/sessions", s.teamSessions)
	m.HandleFunc("GET /api/teams/{team}/tasks/{task}/messages", s.teamMessages)
	m.HandleFunc("POST /api/teams/{team}/tasks/{task}/messages", s.teamSendMessage)
	m.HandleFunc("GET /api/tasks/{id}/collaboration/sessions", s.taskCollaborationSessions)
	m.HandleFunc("POST /api/collaboration/device/assignments/{assignment}/messages", s.teamDeviceMessages)
}

type teamSession struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	State        string `json:"state"`
	ExecutorID   int64  `json:"executor_id"`
	ExecutorName string `json:"executor_name"`
	TeamID       int64  `json:"team_id"`
	AssignmentID int64  `json:"assignment_id"`
	Epoch        int64  `json:"epoch"`
	CanMessage   bool   `json:"can_message"`
	Reason       string `json:"reason,omitempty"`
}

func (s *Server) sharedSessions(ctx context.Context, t *db.Task, team int64, steer bool) ([]teamSession, error) {
	es := s.m.pg.Exploration(t.ExplorationID)
	main, err := es.ListMainSessions()
	if err != nil {
		return nil, err
	}
	items := []teamSession{}
	for _, v := range main {
		items = append(items, teamSession{ID: fmt.Sprintf("main:%d", v.Seq), Title: fmt.Sprintf("主 Agent · 会话 #%d", v.Seq+1), ExecutorName: "本机", State: t.Status})
	}
	items = append(items, teamSession{ID: "plan", Title: "规划 Planner", ExecutorName: "本机", State: t.Status})
	// Latest assignment identifies historical executor too, until this intent is
	// actually reclaimed locally. Pagination of messages is independent of tools.
	rows, err := s.m.pg.QueryContext(ctx, `SELECT n.id,COALESCE(n.payload->>'title',n.payload->>'summary',n.payload->>'text',n.payload->>'task',n.payload->>'description','Work'),n.state,
	 COALESCE(a.device_id,0),COALESCE(d.name,''),COALESCE(a.team_id,0),COALESCE(a.id,0),COALESCE(a.epoch,0),
	 COALESCE(a.messages_ready AND NOT a.messages_closed AND a.state IN ('claimed','running') AND a.lease_until>now() AND d.revoked_at IS NULL,false)
	 FROM exploration_nodes n LEFT JOIN LATERAL (SELECT * FROM team_execution_assignments a WHERE a.intent_id=n.id ORDER BY a.epoch DESC LIMIT 1) a ON COALESCE(n.payload->'execution_attempt','0'::jsonb)<=to_jsonb(a.attempt)
	 LEFT JOIN team_devices d ON d.id=a.device_id
	 WHERE n.exploration_id=$1 AND n.kind='intent' AND n.state<>'deleted' ORDER BY n.id DESC`, t.ExplorationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var v teamSession
		var iid int64
		var ready bool
		if err = rows.Scan(&iid, &v.Title, &v.State, &v.ExecutorID, &v.ExecutorName, &v.TeamID, &v.AssignmentID, &v.Epoch, &ready); err != nil {
			return nil, err
		}
		v.ID = fmt.Sprintf("intent:%d", iid)
		s.engine.workMu.Lock()
		run := s.engine.work[iid]
		local := run != nil && run.control != nil
		s.engine.workMu.Unlock()
		if local {
			v.ExecutorID = 0
			v.ExecutorName = "本机"
			v.AssignmentID = 0
			v.Epoch = 0
			ready = true
		}
		if v.ExecutorID == 0 {
			v.ExecutorName = "本机"
			if v.TeamID == 0 {
				v.TeamID = team
			}
		}
		v.CanMessage = steer && ready && !t.Paused && (!t.Queued || (v.ExecutorID > 0 && t.QueueMode == db.RemoteWaitQueueMode)) && t.Status != "finalizing" && !isTerminalStatus(t.Status)
		if !v.CanMessage {
			switch {
			case !steer:
				v.Reason = "需要此任务的执行权限"
			case t.Paused || t.Queued:
				v.Reason = "任务已暂停或正在排队"
			case v.ExecutorID > 0:
				v.Reason = "执行端未开放消息通道，或本轮已结束"
			default:
				v.Reason = "本机 Work 当前未运行"
			}
		}
		items = append(items, v)
	}
	return items, rows.Err()
}

func (s *Server) teamSessions(w http.ResponseWriter, r *http.Request) {
	p, team, t, ok := s.teamTaskScope(w, r, "read")
	if !ok {
		return
	}
	steer := p.Admin || s.m.pg.CheckTeamTaskPermission(r.Context(), team, t.ID, p.MemberID, "execute") == nil
	items, err := s.sharedSessions(r.Context(), t, team, steer)
	if err != nil {
		writeErr(w, 500, "无法读取共享会话")
		return
	}
	writeJSON(w, 200, map[string]any{"sessions": items, "can_steer": steer})
}

func (s *Server) taskCollaborationSessions(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "任务编号无效")
		return
	}
	t, err := s.m.pg.GetTask(id)
	if err != nil {
		writeErr(w, 404, "任务不存在")
		return
	}
	items, err := s.sharedSessions(r.Context(), t, 0, true)
	if err != nil {
		writeErr(w, 500, "无法读取执行端")
		return
	}
	writeJSON(w, 200, map[string]any{"sessions": items, "can_steer": true})
}

func (s *Server) teamMessages(w http.ResponseWriter, r *http.Request) {
	_, _, t, ok := s.teamTaskScope(w, r, "read")
	if !ok {
		return
	}
	f, valid := parseActivitySession(r.URL.Query().Get("session"))
	if !valid {
		writeErr(w, 400, "会话编号无效")
		return
	}
	es := s.m.pg.Exploration(t.ExplorationID)
	if f.NodeID != nil {
		n, e := es.GetNode(*f.NodeID)
		if e != nil || n == nil || n.Kind != "intent" {
			writeErr(w, 404, "会话不属于此任务")
			return
		}
	}
	if f.Main && f.MainSeg == nil {
		seg, e := es.CurrentMainSeg()
		if e != nil {
			writeErr(w, 500, "无法读取会话")
			return
		}
		f.MainSeg = &seg
	}
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	var items []db.TeamMessage
	var more bool
	var err error
	if r.URL.Query().Has("after") {
		after, e := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
		if e != nil || after < 0 {
			writeErr(w, 400, "消息游标无效")
			return
		}
		items, more, err = es.MessageSince(r.Context(), f, after, limit)
	} else {
		items, more, err = es.MessagePage(r.Context(), f, before, limit)
	}
	if err != nil {
		writeErr(w, 500, "无法读取共享消息")
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "has_more": more})
}

func (s *Server) teamSendMessage(w http.ResponseWriter, r *http.Request) {
	p, team, t, ok := s.teamTaskScope(w, r, "execute")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	var in struct {
		IntentID     int64  `json:"intent_id"`
		AssignmentID int64  `json:"assignment_id"`
		Epoch        int64  `json:"epoch"`
		RequestID    string `json:"request_id"`
		Message      string `json:"message"`
	}
	if decode(r, &in) != nil || !validWorkerMessageRequestID(in.RequestID) || strings.TrimSpace(in.Message) == "" || len([]rune(in.Message)) > 4000 || strings.ContainsRune(in.Message, 0) {
		writeErr(w, 400, "消息或请求编号无效")
		return
	}
	if in.AssignmentID > 0 {
		if err := s.m.pg.QueueTeamGuidance(r.Context(), team, t.ID, in.IntentID, in.AssignmentID, in.Epoch, p.MemberID, in.RequestID, in.Message); err != nil {
			teamExecutionError(w, err)
			return
		}
		writeJSON(w, 202, map[string]any{"accepted": true, "status": "pending", "request_id": in.RequestID})
		return
	}
	// Shared members send plain guidance to an already-running local Work. They
	// cannot use this scoped route to expand global mentions or start extra work.
	if t.Paused || t.Queued || t.Status == "finalizing" || isTerminalStatus(t.Status) {
		writeErr(w, 409, "任务当前不能接收引导")
		return
	}
	node, err := s.m.pg.Exploration(t.ExplorationID).GetNode(in.IntentID)
	if err != nil || node == nil || node.Kind != "intent" || node.State != "running" {
		writeErr(w, 409, "此本机 Work 当前未运行")
		return
	}
	s.engine.workMu.Lock()
	run := s.engine.work[in.IntentID]
	if run == nil || run.control == nil {
		s.engine.workMu.Unlock()
		writeErr(w, 409, "Work 已交接或本轮已结束，请刷新会话")
		return
	}
	dup, err := run.control.Enqueue(fmt.Sprintf("team:%d:%d:%s", team, p.MemberID, in.RequestID), in.Message)
	s.engine.workMu.Unlock()
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	if !dup {
		if runtime, exists := s.m.Task(strconv.FormatInt(t.ID, 10)); exists {
			s.engine.emitActivity(runtime, db.Activity{NodeID: &in.IntentID, Worker: node.Owner, Kind: "user", Summary: in.Message, Detail: in.Message})
		}
	}
	writeJSON(w, 202, map[string]any{"accepted": true, "status": "steering", "request_id": in.RequestID})
}

func (s *Server) teamDeviceMessages(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	var in collab.MessageExchange
	if decode(r, &in) != nil {
		writeErr(w, 400, "消息格式无效")
		return
	}
	a, token, ok := s.deviceAssignment(w, r, in.Epoch)
	if !ok {
		return
	}
	if err := s.teamSnapshotCurrent(r.Context(), a); err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	out, err := s.m.pg.ExchangeTeamMessages(r.Context(), a.ID, a.DeviceID, token, in)
	if err != nil {
		teamExecutionError(w, err)
		return
	}
	writeJSON(w, 200, out)
}
