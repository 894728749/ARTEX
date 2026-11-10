package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/Autumn-27/artex/collab"
	"github.com/Autumn-27/artex/db"
)

type teamRequestError struct {
	Code    int
	Message string
}

func (e *teamRequestError) Error() string { return e.Message }
func writeTeamBuildError(w http.ResponseWriter, e error) {
	var v *teamRequestError
	if errors.As(e, &v) {
		writeErr(w, v.Code, v.Message)
	} else {
		teamExecutionError(w, e)
	}
}

func teamRuntimeProfile(raw json.RawMessage, id string) (collab.RuntimeProfile, error) {
	var caps struct {
		Profiles []collab.RuntimeProfile `json:"runtime_profiles"`
	}
	if json.Unmarshal(raw, &caps) != nil {
		return collab.RuntimeProfile{}, fmt.Errorf("设备运行环境声明无效")
	}
	for _, p := range caps.Profiles {
		if p.ID == id && p.Validate() == nil {
			return p, nil
		}
	}
	return collab.RuntimeProfile{}, fmt.Errorf("设备未开放所选运行环境")
}

type teamQueuedInput struct {
	Assignment teamAssignInput `json:"assignment"`
	ScopeHash  string          `json:"scope_hash"`
}

func (s *Server) teamDispatchScope(t *db.Task, in teamAssignInput) (string, json.RawMessage, error) {
	n, e := s.m.pg.Exploration(t.ExplorationID).GetNode(in.IntentID)
	if e != nil || n == nil || n.Kind != "intent" {
		return "", nil, fmt.Errorf("工作单不存在")
	}
	var intent map[string]any
	if json.Unmarshal(n.Payload, &intent) != nil {
		return "", nil, fmt.Errorf("工作单格式无效")
	}
	if c, ok := intent["contract"].(map[string]any); ok {
		delete(c, "remote_dispatch_pending")
		delete(c, "remote_dispatch_id")
	}
	constraints, e := s.m.pg.Exploration(t.ExplorationID).ListConstraints()
	if e != nil {
		return "", nil, e
	}
	materials := []string{}
	seen := map[int64]bool{}
	for _, id := range in.ArtifactIDs {
		if seen[id] {
			return "", nil, fmt.Errorf("重复材料")
		}
		seen[id] = true
		a, e := s.m.pg.GetReverseArtifact(t.ID, id)
		if e != nil || a == nil {
			return "", nil, fmt.Errorf("材料不属于任务")
		}
		materials = append(materials, fmt.Sprintf("%d:%s:%d", id, a.SHA256, a.SizeBytes))
	}
	raw, e := json.Marshal(map[string]any{"kind": t.Kind, "goal": t.Goal, "intent": intent, "constraints": constraints, "materials": materials})
	return collab.ContentHash(raw), n.Payload, e
}

func (s *Server) teamQueue(w http.ResponseWriter, r *http.Request) {
	p, team, t, ok := s.teamTaskScope(w, r, "manage")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	var in teamAssignInput
	if decode(r, &in) != nil || len(in.Context) > 64<<10 || len(in.ArtifactIDs) > 16 || len(in.Capabilities) > 32 {
		writeErr(w, 400, "排队参数无效")
		return
	}
	if in.AuthorizeRuntime {
		if in.DeviceID < 1 || in.RuntimeProfileID == "" {
			writeErr(w, 400, "动态工作排队必须先选定设备和环境")
			return
		}
		d, e := s.m.pg.GetTeamDevice(r.Context(), team, in.DeviceID)
		if e != nil {
			writeErr(w, 403, "设备不属于团队")
			return
		}
		profile, e := teamRuntimeProfile(d.Capabilities, in.RuntimeProfileID)
		if e != nil {
			writeErr(w, 400, e.Error())
			return
		}
		if in.RuntimeDigest != "" && in.RuntimeDigest != profile.Digest {
			writeErr(w, 409, "设备环境已变化，请重新确认动态授权")
			return
		}
		in.RuntimeDigest = profile.Digest
	}
	hash, payload, e := s.teamDispatchScope(t, in)
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	raw, _ := json.Marshal(teamQueuedInput{in, hash})
	id, e := s.m.pg.QueueTeamDispatch(r.Context(), team, t.ID, in.IntentID, p.MemberID, raw, payload)
	if e != nil {
		teamExecutionError(w, e)
		return
	}
	writeJSON(w, 201, map[string]any{"id": id, "state": "queued"})
}

func (s *Server) teamCancelQueue(w http.ResponseWriter, r *http.Request) {
	p, team, t, ok := s.teamTaskScope(w, r, "manage")
	if !ok {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("dispatch"), 10, 64)
	if e := s.m.pg.CancelTeamDispatch(r.Context(), team, t.ID, id, p.MemberID, false, "成员取消排队"); e != nil {
		teamExecutionError(w, e)
		return
	}
	writeJSON(w, 200, map[string]bool{"cancelled": true})
}

func (s *Server) runTeamDispatcher(ctx context.Context) {
	timer := time.NewTicker(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			s.dispatchTeamOnce(ctx)
		}
	}
}

func (s *Server) dispatchTeamOnce(ctx context.Context) {
	_, _ = s.m.pg.ReconcileTeamExecutionAssignments(ctx, time.Now())
	items, e := s.m.pg.ListTeamDispatch(ctx, 0, 0, true)
	if e != nil {
		return
	}
	for _, q := range items {
		if ctx.Err() != nil {
			return
		}
		// Move each attempted request behind untouched queued requests so a fixed
		// first page cannot starve work beyond the dispatcher batch limit.
		_, _ = s.m.pg.ExecContext(ctx, `UPDATE team_dispatch_queue SET last_attempt_at=now() WHERE id=$1 AND state='queued'`, q.ID)
		block := func(message string) { _ = s.m.pg.CancelTeamDispatch(ctx, q.TeamID, q.TaskID, q.ID, 0, true, message) }
		wait := func(message string) {
			if len(message) > 1500 {
				message = message[:1500]
			}
			_, _ = s.m.pg.ExecContext(ctx, `UPDATE team_dispatch_queue SET last_error=$2 WHERE id=$1 AND state='queued'`, q.ID, message)
		}
		if time.Now().After(q.ExpiresAt) {
			block("预约已到期，请重新派发")
			continue
		}
		if q.RequestedBy != 0 && (s.m.pg.CheckTeamTaskPermission(ctx, q.TeamID, q.TaskID, q.RequestedBy, "read") != nil || s.m.pg.CheckTeamTaskPermission(ctx, q.TeamID, q.TaskID, q.RequestedBy, "manage") != nil) {
			block("派发成员授权已失效")
			continue
		}
		t, e := s.m.pg.GetTask(q.TaskID)
		if e != nil || t == nil {
			block("任务不可用")
			continue
		}
		if db.IsTerminal(t.Status) || t.Status == "finalizing" {
			block("任务已结束")
			continue
		}
		var input teamQueuedInput
		if json.Unmarshal(q.Request, &input) != nil {
			block("排队记录格式无效")
			continue
		}
		scope, _, e := s.teamDispatchScope(t, input.Assignment)
		if e != nil || scope != input.ScopeHash {
			block("任务范围、工作单或材料已变化，请重新确认交接")
			continue
		}
		if input.Assignment.AuthorizeRuntime {
			device, de := s.m.pg.GetTeamDevice(ctx, q.TeamID, input.Assignment.DeviceID)
			if de != nil || device == nil || device.Revoked {
				block("所选设备或运行环境已失效，请重新确认交接")
				continue
			}
			profile, pe := teamRuntimeProfile(device.Capabilities, input.Assignment.RuntimeProfileID)
			if pe != nil || profile.Digest != input.Assignment.RuntimeDigest {
				block("所选运行环境已变化，请重新确认交接")
				continue
			}
		}
		if t.Paused || t.Queued {
			wait("等待任务恢复")
			continue
		}
		candidates, e := s.m.pg.TeamAvailableDevices(ctx, q.TeamID, q.TaskID)
		if e != nil {
			continue
		}
		last := "等待在线且空闲、具备所需角色和权限的设备"
		for _, id := range candidates {
			if input.Assignment.DeviceID > 0 && input.Assignment.DeviceID != id {
				continue
			}
			in := input.Assignment
			in.DeviceID = id
			_, e = s.prepareTeamAssignment(ctx, q.TeamID, t, in, q.RequestedBy)
			if e == nil {
				last = ""
				break
			}
			last = e.Error()
		}
		if last != "" {
			wait(last)
		}
	}
}

func (s *Server) teamHistory(w http.ResponseWriter, r *http.Request) {
	p, _, t, ok := s.teamTaskScope(w, r, "read")
	if !ok {
		return
	}
	rows, e := s.m.pg.ListTaskTeamHistory(r.Context(), t.ID)
	if e != nil {
		writeErr(w, 500, "无法读取协作历史")
		return
	}
	if !p.Admin {
		filtered := make([]db.TaskTeamHistory, 0, len(rows))
		for _, row := range rows {
			if row.Kind != "team_branch_project" && row.Kind != "team_branch_event" && row.Kind != "team_branch_workflow" {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}
	writeJSON(w, 200, rows)
}
