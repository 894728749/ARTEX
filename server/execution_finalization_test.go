package server

import (
	"context"
	"fmt"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func TestExecutionFinalizationBlocksClaimsAndDrainsAtToolBoundary(t *testing.T) {
	s, f, _ := trafficEvidenceServer(t)
	row, _ := s.m.pg.GetFinding(f.FindingID)
	task, _ := s.m.Task(fmt.Sprint(*row.TaskID))
	goals, err := task.Store.ListByKind(db.KindGoal, 100)
	if err != nil {
		t.Fatal(err)
	}
	refID, err := task.Store.AddNode(db.KindFact, map[string]any{"summary": "fixture", "evidence": "synthetic test only", "confidence": "observed"}, 0, "confirmed", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := task.Store.GetNode(refID)
	for _, g := range goals {
		if _, err = task.Store.ProveGoal(t.Context(), g.ID, db.EvidenceReference{NodeID: refID, Version: ref.EvidenceVersion}, "synthetic goal proof", g.EvidenceVersion); err != nil {
			t.Fatal(err)
		}
	}
	if len(goals) == 0 {
		g, _ := task.Store.AddGoal(map[string]any{"text": "fixture"}, "test")
		gn, _ := task.Store.GetNode(g)
		if _, err = task.Store.ProveGoal(t.Context(), g, db.EvidenceReference{NodeID: refID, Version: ref.EvidenceVersion}, "synthetic goal proof", gn.EvidenceVersion); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.m.SetTaskStatus(task.ID, "running"); err != nil {
		t.Fatal(err)
	}
	running, _ := task.Store.AddIntent(map[string]any{"summary": "active fixture"}, 5, nil, "test")
	if ok, err := task.Store.ClaimIntent(running, "worker"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	queued, _ := task.Store.AddIntent(map[string]any{"summary": "queued fixture"}, 5, nil, "test")
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	ctx, control, release := s.engine.liveRun(ctx, task.ID, cancel, false)
	defer release()
	s.engine.registerWork(running, cancel)
	s.engine.workMu.Lock()
	s.engine.work[running].control = control
	s.engine.workMu.Unlock()
	defer func() { _, finish := s.engine.detachWork(running); finish(nil) }()
	hooks := control.Hooks(nil)
	if b, _, _ := hooks.PreToolUse(ctx, "fixture", nil); b {
		t.Fatal("initial tool blocked")
	}
	s.engine.advanceGoalFinalization(t.Context(), task, true)
	if status := task.lifecycleSnapshot().Status; status != "finalizing" {
		t.Fatal(status)
	}
	if ctx.Err() != nil {
		t.Fatal("current tool cancelled early")
	}
	if in := s.engine.claimNext(task, "new worker"); in != nil {
		t.Fatal("queued work started", in.ID, queued)
	}
	s.engine.advanceGoalFinalization(t.Context(), task, false)
	if task.lifecycleSnapshot().Status != "finalizing" {
		t.Fatal("completed over a running tool")
	}
	hooks.PostToolUse(ctx, "fixture", nil, []byte("preserved evidence"), false)
	if context.Cause(ctx) != agent.AbortGoalMet {
		t.Fatal(context.Cause(ctx))
	}
	_ = task.Store.SetIntentState(running, "stopped")
	s.engine.advanceGoalFinalization(t.Context(), task, false)
	if task.lifecycleSnapshot().Status != "done" {
		t.Fatal(task.lifecycleSnapshot().Status)
	}
	n, _ := task.Store.GetNode(queued)
	if n.State != "stopped" {
		t.Fatal(n.State)
	}
}
