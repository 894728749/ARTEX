package server

import (
	"context"
	"log"
	"strconv"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func (m *Manager) advanceGoalFinalization(ctx context.Context, t *Task, begin bool) (string, error) {
	m.taskStateMu.Lock()
	defer m.taskStateMu.Unlock()
	id, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		return "", err
	}
	status, err := m.pg.AdvanceGoalFinalization(ctx, id, begin)
	if err != nil {
		return "", err
	}
	t.updateLifecycle(func(state *taskLifecycleState) {
		state.Status = status
		if status == "done" && state.CompletedAt == 0 {
			state.CompletedAt = time.Now().Unix()
		}
	})
	return status, nil
}

func (e *Engine) advanceGoalFinalization(ctx context.Context, t *Task, begin bool) {
	e.liveMu.Lock()
	if e.IsPaused(t.ID) || e.IsDeleting(t.ID) {
		e.liveMu.Unlock()
		return
	}
	before := t.lifecycleSnapshot().Status
	status, err := e.m.advanceGoalFinalization(ctx, t, begin)
	e.liveMu.Unlock()
	if err != nil {
		log.Printf("[finalizing] task %s: %v", t.ID, err)
		return
	}
	if status == "finalizing" {
		nodes, err := t.Store.ListRunningIntents()
		if err != nil {
			log.Printf("[finalizing] task %s workers: %v", t.ID, err)
			return
		}
		e.workMu.Lock()
		for _, n := range nodes {
			if run := e.work[n.ID]; run != nil && run.control != nil {
				run.control.RequestStopAfterTool(agent.AbortGoalMet)
			}
		}
		e.workMu.Unlock()
	}
	if status != before {
		summary := "目标已验收，停止领取新工作，等待当前工具调用结束后收尾"
		if status == "done" {
			summary = "当前工具已结束，任务完成；已保留证据与执行记录"
		}
		if status == "running" {
			summary = "目标发生变化，已退出收尾并恢复规划"
		}
		e.emitActivity(t, db.Activity{Worker: "system", Kind: "text", Summary: summary})
	}
	if status == "running" && (before == "finalizing" || begin) {
		t.Notify()
	}
}
