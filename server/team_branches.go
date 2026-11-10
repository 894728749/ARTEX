package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/collab"
	"github.com/Autumn-27/artex/db"
)

func (s *Server) teamBranchRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /api/teams/{team}/tasks/{task}/branches/enable", s.branchEnable)
	m.HandleFunc("GET /api/teams/{team}/tasks/{task}/branches", s.branchSnapshot)
	m.HandleFunc("POST /api/teams/{team}/tasks/{task}/branches/command", s.branchCommand)
	m.HandleFunc("GET /api/teams/{team}/tasks/{task}/branches/events", s.branchSnapshot)
	m.HandleFunc("GET /api/teams/{team}/tasks/{task}/branches/stream", s.branchStream)
	m.HandleFunc("GET /api/teams/{team}/tasks/{task}/branches/export", s.branchSnapshot)
	m.HandleFunc("GET /api/teams/{team}/tasks/{task}/branches/{branch}/materials/{material}", s.branchMaterial)
	m.HandleFunc("GET /api/collaboration/device/branches", s.branchDevicePoll)
	m.HandleFunc("POST /api/collaboration/device/branches/{task}/{branch}/command", s.branchDeviceCommand)
	m.HandleFunc("GET /api/collaboration/device/branches/{task}/{branch}/materials/{material}", s.branchMaterial)
}

func branchError(w http.ResponseWriter, err error) {
	code := 409
	if errors.Is(err, sql.ErrNoRows) {
		code = 404
	}
	if errors.Is(err, collab.ErrBranchDenied) || errors.Is(err, db.ErrTeamCollaborationDenied) {
		code = 403
	}
	if errors.Is(err, collab.ErrBranchInvalid) {
		code = 400
	}
	writeErr(w, code, err.Error())
}

func (s *Server) branchTaskMode(id string) (bool, error) {
	// Pure in-memory tests and callers without a configured Manager retain the
	// legacy non-branch behavior. A configured database lookup must surface errors.
	if s == nil || s.m == nil || s.m.pg == nil {
		return false, nil
	}
	task, e := strconv.ParseInt(id, 10, 64)
	if e != nil {
		return false, nil
	}
	return s.m.pg.BranchMode(context.Background(), task)
}

// isBranchTask fails closed for task-level writes: a database error cannot
// authorize a legacy path whose scope may be owned by branch mode.
func (s *Server) isBranchTask(id string) bool {
	on, err := s.branchTaskMode(id)
	return err != nil || on
}

// isBranchTaskForConcurrencySlot only releases a local task's slot when branch
// mode is positively confirmed. A lookup error must keep the slot occupied.
func (s *Server) isBranchTaskForConcurrencySlot(id string) bool {
	on, err := s.branchTaskMode(id)
	return err == nil && on
}

// Legacy task-level writers cannot start a second, unbudgeted engine or change
// the frozen authorization scope behind the shared branch workspace.
func (s *Server) guardBranchLegacyMutation(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions || !strings.HasPrefix(r.URL.Path, "/api/tasks/") {
		return true
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/tasks/"), "/")
	if len(parts) == 0 {
		return true
	}
	on, err := s.branchTaskMode(parts[0])
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "无法确认任务执行模式，请稍后重试")
		return false
	}
	if !on {
		return true
	}
	if len(parts) == 2 && (parts[1] == "archive" || parts[1] == "category") {
		return true
	}
	writeErr(w, 409, "此任务已启用共享分支，请在团队执行分支工作台调整范围、指导和控制")
	return false
}

func (s *Server) branchActor(w http.ResponseWriter, r *http.Request) (int64, int64, collab.BranchActor, bool) {
	p, team, t, ok := s.teamTaskScope(w, r, "read")
	if !ok {
		return 0, 0, collab.BranchActor{}, false
	}
	return team, t.ID, collab.BranchActor{Admin: p.Admin, MemberID: p.MemberID}, true
}

func (s *Server) branchEnable(w http.ResponseWriter, r *http.Request) {
	p, team, t, ok := s.teamTaskScope(w, r, "manage")
	if !ok {
		return
	}
	var in struct {
		Policy           collab.BranchPolicy `json:"policy"`
		ArtifactIDs      []int64             `json:"artifact_ids"`
		RoleCapabilities map[string][]string `json:"role_capabilities"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if decode(r, &in) != nil {
		writeErr(w, 400, "分支模式策略无效")
		return
	}
	s.concMu.Lock()
	defer s.concMu.Unlock()
	id := strconv.FormatInt(t.ID, 10)
	s.engine.deleteMu.Lock()
	defer s.engine.deleteMu.Unlock()
	s.chatMu.Lock()
	defer s.chatMu.Unlock()
	if s.chatBusy[id] {
		writeErr(w, 409, "当前主 Agent 会话尚未结束")
		return
	}
	if !t.Paused || s.engine.inflightCount(id) > 0 || s.engine.ActiveLLMCalls(id) > 0 {
		writeErr(w, 409, "请先暂停任务并等待当前本机操作完成")
		return
	}
	s.engine.liveMu.Lock()
	busy := false
	for _, task := range s.engine.liveRuns {
		if task == id {
			busy = true
			break
		}
	}
	s.engine.liveMu.Unlock()
	if busy {
		writeErr(w, 409, "当前主 Agent 会话尚未结束")
		return
	}
	// Reuse role-specific configured prompts; never fall back across workflows.
	// The new local reviewer has a separate, non-executing policy by default.
	if in.Policy.Version == 0 {
		in.Policy.Version = collab.BranchProtocol
	}
	if in.Policy.Goal == "" {
		in.Policy.Goal = t.Goal
	}
	if in.Policy.MaxToolSeconds == 0 {
		in.Policy.MaxToolSeconds = 60
	}
	if in.Policy.PlannerPrompts == nil {
		in.Policy.PlannerPrompts = map[string]string{}
	}
	for _, kind := range in.Policy.Kinds {
		key := "planner"
		if kind == "reverse" {
			key = "reverse_planner"
		}
		if in.Policy.PlannerPrompts[kind] == "" {
			v, e := s.m.pg.GetAgentByKey(key)
			if e != nil || v == nil || !v.Enabled {
				writeErr(w, 409, "所需规划角色未启用："+key)
				return
			}
			prompt, e := s.m.pg.CurrentPrompt(v.ID)
			if e != nil {
				writeErr(w, 409, "无法读取规划角色提示词")
				return
			}
			in.Policy.PlannerPrompts[kind] = v.Description + "\n" + prompt
		}
	}
	if in.Policy.Roles == nil {
		in.Policy.Roles = map[string]collab.ExecutionConfig{}
	}
	for _, kind := range in.Policy.Kinds {
		roles := []string{"worker", "reviewer"}
		if kind == "reverse" {
			roles = []string{"reverse_static", "reverse_reviewer"}
			if _, requested := in.RoleCapabilities["reverse_dynamic"]; requested {
				roles = append(roles, "reverse_dynamic")
			}
		}
		for _, role := range roles {
			if _, exists := in.Policy.Roles[role]; exists {
				continue
			}
			prompt := "你是渗透分支的独立技术核验员。只核对授权材料、原始证据和验收标准。区分阴性结果、未验证及反证。不能替代成员独立复核或确认主目标完成。"
			if role != "reviewer" {
				v, e := s.m.pg.GetAgentByKey(role)
				if e != nil || v == nil || !v.Enabled {
					writeErr(w, 409, "所需执行角色未启用："+role)
					return
				}
				saved, e := s.m.pg.CurrentPrompt(v.ID)
				if e != nil {
					writeErr(w, 409, "无法读取执行角色提示词")
					return
				}
				prompt = v.Description + "\n" + saved
			}
			in.Policy.Roles[role] = collab.ExecutionConfig{Version: 1, Kind: kind, Role: role, SystemPrompt: prompt, MaxTurns: 16, BudgetSeconds: in.Policy.MaxToolSeconds, Capabilities: []string{}}
		}
	}
	for role, caps := range in.RoleCapabilities {
		cfg, exists := in.Policy.Roles[role]
		if !exists {
			writeErr(w, 400, "未授权的执行角色："+role)
			return
		}
		cfg.Capabilities = caps
		in.Policy.Roles[role] = cfg
	}
	// Materials must be registered in THIS master task, then frozen by hash.
	in.Policy.Materials = nil
	if len(in.ArtifactIDs) > 16 {
		writeErr(w, 400, "材料数量超过上限")
		return
	}
	var artifacts []db.ReverseArtifact
	// Pentest tasks have no reverse-artifact collection. An empty selection must
	// not call the reverse-only API and prevent their branch mode from enabling.
	if len(in.ArtifactIDs) > 0 {
		if t.Kind != "reverse" {
			writeErr(w, 403, "渗透主任务不能引用逆向任务材料，请通过跨流程协助绑定材料")
			return
		}
		var err error
		artifacts, err = s.m.pg.ListReverseArtifacts(t.ID)
		if err != nil {
			writeErr(w, 500, "无法读取材料")
			return
		}
	}
	for _, aid := range in.ArtifactIDs {
		var found *db.ReverseArtifact
		for i := range artifacts {
			if artifacts[i].ID == aid {
				found = &artifacts[i]
				break
			}
		}
		if found == nil {
			writeErr(w, 403, "材料不属于此主任务")
			return
		}
		mat, e := s.snapshotTeamMaterial(team, t.ID, found)
		if e != nil {
			branchError(w, e)
			return
		}
		in.Policy.Materials = append(in.Policy.Materials, mat)
	}
	project, e := s.m.pg.CreateBranchProject(r.Context(), team, t.ID, collab.BranchActor{Admin: p.Admin, MemberID: p.MemberID}, in.Policy)
	if e != nil {
		branchError(w, e)
		return
	}
	s.engine.paused.Store(id, true)
	project.Policy.PlannerPrompts = nil
	project.Policy.Roles = nil
	project.Receipts = nil
	writeJSON(w, 201, project)
}

func (s *Server) branchSnapshot(w http.ResponseWriter, r *http.Request) {
	team, task, a, ok := s.branchActor(w, r)
	if !ok {
		return
	}
	branch, _ := strconv.ParseInt(r.URL.Query().Get("branch"), 10, 64)
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	v, e := s.m.pg.BranchSnapshot(r.Context(), team, task, a, branch, after, limit, r.URL.Query().Get("q"))
	if e != nil {
		branchError(w, e)
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	if strings.HasSuffix(r.URL.Path, "/export") {
		w.Header().Set("Content-Disposition", `attachment; filename="branch-process.json"`)
	}
	writeJSON(w, 200, v)
}

var memberBranchCommands = []string{"grant", "publish", "approve", "claim", "discuss", "guide", "pause", "resume", "stop", "control_takeover", "transfer", "confirm_stopped", "review", "dependency", "invalidate_evidence", "close", "project_pause", "project_resume", "authorize_runtime", "cancel_work", "extend_policy"}
var deviceBranchCommands = []string{"ready", "not_ready", "heartbeat", "plan", "start", "end", "unit_result", "event", "guidance_received", "guidance_applied", "checkpoint", "submit", "assist", "propose", "publish", "dependency"}

func (s *Server) branchCommand(w http.ResponseWriter, r *http.Request) {
	team, task, a, ok := s.branchActor(w, r)
	if !ok {
		return
	}
	var cmd collab.BranchCommand
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if decode(r, &cmd) != nil || !slices.Contains(memberBranchCommands, cmd.Type) {
		writeErr(w, 400, "成员命令无效")
		return
	}
	result, e := s.m.pg.ApplyBranchCommand(r.Context(), team, task, a, cmd)
	if e != nil {
		branchError(w, e)
		return
	}
	if cmd.Type == "project_pause" || cmd.Type == "project_resume" {
		if t, exists := s.m.Task(strconv.FormatInt(task, 10)); exists {
			t.updateLifecycle(func(v *taskLifecycleState) {
				v.Paused = cmd.Type == "project_pause"
				v.Queued = false
				v.QueueMode = ""
			})
		}
	}
	// Use the same projection as reads, never expose a raw mutable state document
	// through successful command responses to a less privileged caller.
	snap, e := s.m.pg.BranchSnapshot(r.Context(), team, task, a, cmd.BranchID, 0, 100, "")
	if e != nil {
		branchError(w, e)
		return
	}
	writeJSON(w, 200, map[string]any{"receipt": result.Receipt, "snapshot": snap})
}

func (s *Server) branchDevicePoll(w http.ResponseWriter, r *http.Request) {
	dev, ok := r.Context().Value(teamIdentityKey{}).(*db.TeamDevice)
	if !ok {
		writeErr(w, 401, "设备身份无效")
		return
	}
	_, _ = s.m.pg.ExecContext(r.Context(), `UPDATE team_devices SET last_seen_at=now() WHERE id=$1`, dev.ID)
	items, e := s.m.pg.BranchDevicePoll(r.Context(), dev)
	if e != nil {
		branchError(w, e)
		return
	}
	writeJSON(w, 200, map[string]any{"branches": items})
}
func (s *Server) branchDeviceCommand(w http.ResponseWriter, r *http.Request) {
	dev, ok := r.Context().Value(teamIdentityKey{}).(*db.TeamDevice)
	if !ok {
		writeErr(w, 401, "设备身份无效")
		return
	}
	task, e1 := strconv.ParseInt(r.PathValue("task"), 10, 64)
	branch, e2 := strconv.ParseInt(r.PathValue("branch"), 10, 64)
	var cmd collab.BranchCommand
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if e1 != nil || e2 != nil || decode(r, &cmd) != nil || cmd.BranchID != branch || !slices.Contains(deviceBranchCommands, cmd.Type) {
		writeErr(w, 400, "设备分支命令无效")
		return
	}
	reply, e := s.m.pg.ApplyBranchCommand(r.Context(), dev.TeamID, task, collab.BranchActor{MemberID: dev.OwnerMemberID, DeviceID: dev.ID}, cmd)
	if e != nil {
		branchError(w, e)
		return
	}
	writeJSON(w, 200, reply)
}

func (s *Server) branchStream(w http.ResponseWriter, r *http.Request) {
	team, task, a, ok := s.branchActor(w, r)
	if !ok {
		return
	}
	branch, _ := strconv.ParseInt(r.URL.Query().Get("branch"), 10, 64)
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	if h := r.Header.Get("Last-Event-ID"); h != "" {
		if n, e := strconv.ParseInt(h, 10, 64); e == nil && n > after {
			after = n
		}
	}
	first, e := s.m.pg.BranchSnapshot(r.Context(), team, task, a, branch, after, 100, "")
	if e != nil {
		branchError(w, e)
		return
	}
	if !slices.Contains(first.Permissions, "process") {
		writeErr(w, 403, "需要过程查看权限")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "不支持实时流")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	page := first
	for {
		// Recheck the authenticated member and process permission for every batch.
		// No cached subscription membership survives revocation.
		if _, valid := s.teamPrincipal(r); !valid {
			return
		}
		for _, ev := range page.Events {
			raw, _ := json.Marshal(ev)
			if _, e = fmt.Fprintf(w, "id: %d\nevent: branch\ndata: %s\n\n", ev.ID, raw); e != nil {
				return
			}
		}
		after = page.Cursor
		if _, e = fmt.Fprintf(w, "event: sync\ndata: {\"cursor\":%d}\n\n", after); e != nil {
			return
		}
		flusher.Flush()
		if !page.HasMore {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
			}
		}
		page, e = s.m.pg.BranchSnapshot(r.Context(), team, task, a, branch, after, 100, "")
		if e != nil || !slices.Contains(page.Permissions, "process") {
			return
		}
	}
}

func (s *Server) branchMaterial(w http.ResponseWriter, r *http.Request) {
	task, _ := strconv.ParseInt(r.PathValue("task"), 10, 64)
	bid, _ := strconv.ParseInt(r.PathValue("branch"), 10, 64)
	hash := r.PathValue("material")
	var team int64
	var policy collab.BranchPolicy
	var b *collab.ExecutionBranch
	if dev, ok := r.Context().Value(teamIdentityKey{}).(*db.TeamDevice); ok {
		items, e := s.m.pg.BranchDevicePoll(r.Context(), dev)
		if e != nil {
			branchError(w, e)
			return
		}
		epoch, _ := strconv.ParseInt(r.URL.Query().Get("epoch"), 10, 64)
		for _, item := range items {
			if item.Branch != nil && item.Branch.TaskID == task && item.Branch.ID == bid && item.Branch.Epoch == epoch {
				team = dev.TeamID
				policy = item.Policy
				b = item.Branch
				break
			}
		}
	} else {
		var a collab.BranchActor
		var ok bool
		team, task, a, ok = s.branchActor(w, r)
		if !ok {
			return
		}
		snap, e := s.m.pg.BranchSnapshot(r.Context(), team, task, a, bid, 0, 1, "")
		if e != nil {
			branchError(w, e)
			return
		}
		if !slices.Contains(snap.Permissions, "evidence") {
			writeErr(w, 403, "需要证据读取权限")
			return
		}
		policy = snap.Project.Policy
		for i := range snap.Project.Branches {
			if snap.Project.Branches[i].ID == bid {
				b = &snap.Project.Branches[i]
				break
			}
		}
	}
	if b == nil || !slices.Contains(b.Spec.MaterialHashes, hash) {
		writeErr(w, 403, "材料未获此分支授权")
		return
	}
	var mat *collab.Material
	for i := range policy.Materials {
		if policy.Materials[i].SHA256 == hash {
			mat = &policy.Materials[i]
			break
		}
	}
	if mat == nil {
		writeErr(w, 404, "材料不存在")
		return
	}
	prefix := s.teamMaterialPrefix(team, task)
	path, e := reverseLocalPath(s.m.dir, filepath.Join(prefix, hash), prefix)
	if e != nil {
		writeErr(w, 404, "材料不存在")
		return
	}
	f, e := os.Open(path)
	if e != nil {
		writeErr(w, 404, "材料不存在")
		return
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() != mat.Size {
		writeErr(w, 409, "材料内容已变化")
		return
	}
	// Each separately authorized transfer is bounded, including downloads from
	// browsers. Revocation is rechecked before the next chunk.
	if h := r.Header.Get("Range"); h != "" {
		var start, end int64
		n, _ := fmt.Sscanf(h, "bytes=%d-%d", &start, &end)
		if n != 2 || h != fmt.Sprintf("bytes=%d-%d", start, end) || start < 0 || end < start || end-start+1 > 4<<20 || end >= mat.Size {
			writeErr(w, 416, "请使用不超过 4 MiB 的明确范围")
			return
		}
	} else if mat.Size > 4<<20 {
		writeErr(w, 416, "大材料请分段下载")
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("ETag", `"`+hash+`"`)
	http.ServeContent(w, r, mat.Name, time.Time{}, f)
}
