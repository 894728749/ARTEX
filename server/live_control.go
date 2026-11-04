package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strconv"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

type chatLiveRun struct {
	control *agent.LiveControl
	seg     int
}

func (e *Engine) liveRun(ctx context.Context, taskID string, cancel context.CancelCauseFunc, allowPaused bool) (context.Context, *agent.LiveControl, func()) {
	c := agent.NewLiveControl(cancel)
	e.liveMu.Lock()
	if e.liveRuns == nil {
		e.liveRuns = map[*agent.LiveControl]string{}
	}
	e.liveRuns[c] = taskID
	if !allowPaused && e.IsPaused(taskID) {
		c.RequestPause()
	} else if !allowPaused && e.m.TaskStatus(taskID) == "finalizing" {
		c.RequestStopAfterTool(agent.AbortGoalMet)
	}
	e.liveMu.Unlock()
	return agent.WithLiveControl(ctx, c), c, func() {
		c.Close()
		e.liveMu.Lock()
		delete(e.liveRuns, c)
		e.liveMu.Unlock()
	}
}

func (e *Engine) PauseAfterTool(taskID string) {
	e.liveMu.Lock()
	defer e.liveMu.Unlock()
	e.paused.Store(taskID, true)
	for c, id := range e.liveRuns {
		if id == taskID {
			c.RequestPause()
		}
	}
}

func (e *Engine) IsDraining(taskID string) bool {
	e.liveMu.Lock()
	defer e.liveMu.Unlock()
	for c, id := range e.liveRuns {
		if id == taskID && c.IsStopping() {
			return true
		}
	}
	return false
}

func (s *Server) queueMainGuidance(t *Task, seg int, message, agentMessage string, attachments []chatAttachment) error {
	run, ok := s.chatLive.Load(t.ID)
	if !ok {
		return fmt.Errorf("主 Agent 正在启动或结束，请稍后重发")
	}
	live := run.(chatLiveRun)
	if live.seg != seg {
		return fmt.Errorf("另一主会话正在运行，请在该会话发送引导")
	}
	full := composeAgentMessage(agentMessage, attachments, filepath.Join(s.m.dir, "tasks", t.ID))
	if _, err := live.control.Enqueue("", full); err != nil {
		return err
	}
	a := userActivityWithAttachments("mainagent", message, attachments)
	a.MainSeg = &seg
	s.engine.emitActivity(t, a)
	return nil
}

func (s *Server) queueConversationGuidance(c *db.Conversation, message, agentMessage string, attachments []chatAttachment) error {
	key := s.convBusyKey(c.ID)
	run, ok := s.chatLive.Load(key)
	if !ok {
		return fmt.Errorf("会话正在启动或结束，请稍后重发")
	}
	full := composeAgentMessage(agentMessage, attachments, filepath.Join(s.m.dir, "sessions", key))
	if _, err := run.(chatLiveRun).control.Enqueue("", full); err != nil {
		return err
	}
	a := userActivityWithAttachments(c.AgentKey, message, attachments)
	_, err := s.m.pg.AppendConvActivity(c.ID, a)
	if err != nil {
		log.Printf("[steering] conversation %d activity: %v", c.ID, err)
	}
	// Once accepted by the run, do not return a rejection that invites a duplicate.
	return nil
}

func (s *Server) toolPauseTaskAfterTool() actool.CoreTool {
	return wrTool("pause_task_after_tool", "温和停止整个任务：立即禁止新规划和排队 Worker 启动，当前工具调用结束即暂停，不继续整个 Worker。用户要求停止/暂停任务时优先使用本工具，不能只 kill_work。",
		objSchema(map[string]any{"task_id": strParam("任务 ID；任务内对话可省略使用当前任务")}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID string `json:"task_id"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if a.TaskID == "" {
				if id := agent.RunInfoFrom(ctx).TaskID; id > 0 {
					a.TaskID = strconv.FormatInt(id, 10)
				}
			}
			t, ok := s.m.Task(a.TaskID)
			if !ok {
				return actool.Errorf("task 不存在"), nil
			}
			out, err := s.applyTaskControl(t, "pause_after_tool")
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(out)
		})
}

func steeringAccepted(w http.ResponseWriter) {
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "steering", "accepted": true})
}
