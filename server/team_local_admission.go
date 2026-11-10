package server

import (
	"context"
	"strconv"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func (s *Server) onlyWaitingForRemote(t *Task) bool {
	if t == nil || s.m.pg == nil {
		return false
	}
	id, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		return false
	}
	only, err := s.m.pg.OnlyRemoteWork(context.Background(), id)
	return err == nil && only
}

// Caller holds concMu. This barrier is local only: it neither cancels remote
// assignments nor changes their lease/epoch. No active local tool is interrupted.
func (s *Server) parkRemoteLocalEngine(t *Task) bool {
	e := s.engine
	e.deleteMu.Lock()
	defer e.deleteMu.Unlock()
	if e.IsDeleting(t.ID) || e.IsPaused(t.ID) || e.inflightCount(t.ID) > 0 || e.ActiveLLMCalls(t.ID) > 0 {
		return false
	}
	e.liveMu.Lock()
	for _, id := range e.liveRuns {
		if id == t.ID {
			e.liveMu.Unlock()
			return false
		}
	}
	e.paused.Store(t.ID, true)
	e.liveMu.Unlock()
	id, _ := strconv.ParseInt(t.ID, 10, 64)
	s.m.taskStateMu.Lock()
	at, parked, err := s.m.pg.ParkRemoteLocalEngine(context.Background(), id)
	if err == nil && parked {
		t.updateLifecycle(func(v *taskLifecycleState) {
			v.Queued = true
			v.QueueMode = db.RemoteWaitQueueMode
			v.QueuedAt = at.UnixNano()
		})
	}
	s.m.taskStateMu.Unlock()
	if err != nil || !parked {
		e.paused.Delete(t.ID)
		return false
	}
	e.cancelExec(t.ID, agent.Causef("remote_wait_queued", "本机等待远端执行或复核", "远端继续执行；本机工作返回后按 FIFO 获取运行名额"))
	return true
}
