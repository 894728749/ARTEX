package agent

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
)

func TestConstraintRefreshBlocksWholeOldBatchUntilModelReadsSnapshot(t *testing.T) {
	rows := []db.Constraint{{ID: 1, Kind: "rule", Text: "old"}}
	opts := agentcore.Options{Provider: captureUsageProvider{stream: func(_ context.Context, y func(llm.StreamEvent, error) bool) {
		y(llm.StreamEvent{Type: llm.SETextDelta, Text: "read"}, nil)
	}}}
	installConstraintRefresh(&opts, rows, func(context.Context) ([]db.Constraint, error) { return rows, nil })
	rows = []db.Constraint{{ID: 1, Kind: "deny", Text: "new"}}
	var wg sync.WaitGroup
	blocked := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, _, _ := opts.Hooks.PreToolUse(t.Context(), "old proposal", nil)
			blocked <- b
		}()
	}
	wg.Wait()
	close(blocked)
	for b := range blocked {
		if !b {
			t.Fatal("another call from the old batch crossed the constraint boundary")
		}
	}
	if _, _, _, err := opts.Provider.Complete(t.Context(), llm.CompletionRequest{System: []string{"base"}}); err != nil {
		t.Fatal(err)
	}
	if b, msg, _ := opts.Hooks.PreToolUse(t.Context(), "new proposal", nil); b {
		t.Fatal("fresh model decision blocked", msg)
	}
}

type constraintHookFunc struct{ pre func() }

func (f constraintHookFunc) PreToolUse(context.Context, string, []byte) (bool, string, []byte) {
	if f.pre != nil {
		f.pre()
	}
	return false, "", []byte("approved")
}
func (constraintHookFunc) PostToolUse(context.Context, string, []byte, []byte, bool) {}
func (constraintHookFunc) Stop(context.Context, []llm.Message) (bool, []string, string) {
	return false, nil, ""
}

func TestConstraintRefreshBetweenToolsAndDeleteAll(t *testing.T) {
	ctx := context.Background()
	rows := []db.Constraint{{ID: 1, Kind: "deny", Text: "禁止 A"}}
	h := NewConstraintRefreshHooks(nil, rows, func(context.Context) ([]db.Constraint, error) { return rows, nil })
	if block, _, _ := h.PreToolUse(ctx, "A", nil); block {
		t.Fatal("unchanged snapshot blocked")
	}
	rows = []db.Constraint{{ID: 2, Kind: "allow", Text: "只允许 B"}, {ID: 3, Kind: "rule", Text: "间隔两秒"}}
	block, msg, _ := h.PreToolUse(ctx, "A", nil)
	if !block || !strings.Contains(msg, "只允许 B") || !strings.Contains(msg, "间隔两秒") || !strings.Contains(msg, "覆盖") {
		t.Fatalf("updated snapshot not delivered: %q", msg)
	}
	rows = nil
	block, msg, _ = h.PreToolUse(ctx, "A", nil)
	if !block || !strings.Contains(msg, "没有登记") || !strings.Contains(msg, "授权范围") {
		t.Fatalf("empty snapshot not handled: %q", msg)
	}
}

func TestConstraintRefreshAfterApprovalWaitAndStopGuidanceDoesNotPause(t *testing.T) {
	ctx := context.Background()
	rows := []db.Constraint{{ID: 1, Kind: "allow", Text: "初始"}}
	h := NewConstraintRefreshHooks(constraintHookFunc{pre: func() { rows = []db.Constraint{{ID: 1, Kind: "deny", Text: "等待审批时更新"}} }}, []db.Constraint{{ID: 1, Kind: "allow", Text: "初始"}}, func(context.Context) ([]db.Constraint, error) { return rows, nil })
	block, msg, _ := h.PreToolUse(ctx, "A", nil)
	if !block || !strings.Contains(msg, "等待审批时更新") {
		t.Fatalf("tool crossed stale approval boundary: %q", msg)
	}
	stop, blocking, _ := h.Stop(ctx, nil)
	if stop || len(blocking) != 1 {
		t.Fatalf("refresh should keep old batch blocked without pausing: stop=%v blocking=%v", stop, blocking)
	}
}

func TestConstraintRefreshStopAndLoaderErrorFailClosed(t *testing.T) {
	ctx := context.Background()
	rows := []db.Constraint{{ID: 1, Kind: "rule", Text: "old"}}
	h := NewConstraintRefreshHooks(nil, rows, func(context.Context) ([]db.Constraint, error) { return rows, nil })
	rows = []db.Constraint{{ID: 1, Kind: "rule", Text: "new"}}
	stop, blocking, _ := h.Stop(ctx, nil)
	if stop || len(blocking) != 1 || !strings.Contains(blocking[0], "new") {
		t.Fatalf("Stop did not nudge with latest snapshot: %v %v", stop, blocking)
	}
	h = NewConstraintRefreshHooks(nil, rows, func(context.Context) ([]db.Constraint, error) { return nil, errors.New("db offline") })
	block, msg, _ := h.PreToolUse(ctx, "A", nil)
	if !block || !strings.Contains(msg, "db offline") || !strings.Contains(msg, "重试") {
		t.Fatalf("loader error not fail closed: %q", msg)
	}
}
