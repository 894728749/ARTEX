package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/tool"
)

func TestLiveControlPauseWaitsForCurrentToolAndPersistsResult(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	control := NewLiveControl(cancel)
	ctx = WithLiveControl(ctx, control)
	entered, release := make(chan struct{}), make(chan struct{})
	turns, calls := 0, 0
	p := captureUsageProvider{stream: func(_ context.Context, y func(llm.StreamEvent, error) bool) {
		turns++
		for _, ev := range []llm.StreamEvent{{Type: llm.SEToolUseStart, ToolID: "one", ToolName: "Probe"}, {Type: llm.SEToolInputJSON, Text: `{}`}, {Type: llm.SEMessageDelta, StopReason: "tool_use"}} {
			if !y(ev, nil) {
				return
			}
		}
	}}
	probe := tool.Build(tool.Spec{Name: "Probe", Schema: map[string]any{"type": "object"}, Run: func(ctx context.Context, _ json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
		calls++
		close(entered)
		<-release
		if ctx.Err() != nil {
			return tool.Errorf("cancelled before tool ended"), nil
		}
		return tool.Text("completed-tool-evidence"), nil
	}})
	session := agentcore.NewSession(agentcore.Options{Provider: p, Tools: []tool.CoreTool{probe}, Hooks: control.Hooks(nil), PermissionMode: permission.ModeBypass, WorkingDir: t.TempDir(), MaxTurns: 5})
	defer session.Close()
	var activities []db.Activity
	done := make(chan error, 1)
	go func() {
		_, _, err := captureRunSession(ctx, session, "start", func(a db.Activity) { activities = append(activities, a) })
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("tool did not start")
	}
	control.RequestPause()
	if ctx.Err() != nil {
		t.Fatal("current tool was cancelled")
	}
	if _, err := control.Enqueue("late", "continue"); err == nil {
		t.Fatal("stopping run accepted guidance")
	}
	close(release)
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pause did not finish")
	}
	if turns != 1 || calls != 1 {
		t.Fatalf("continued after pause: turns=%d calls=%d", turns, calls)
	}
	if !errors.Is(context.Cause(ctx), AbortPausedAfterTool) {
		t.Fatal(context.Cause(ctx))
	}
	raw, _ := json.Marshal(session.Messages())
	if !strings.Contains(string(raw), "completed-tool-evidence") {
		t.Fatalf("tool result lost from session: %s", raw)
	}
	found := false
	for _, a := range activities {
		if a.Kind == "tool_result" && strings.Contains(a.Detail, "completed-tool-evidence") {
			found = true
		}
	}
	if !found {
		t.Fatalf("tool result lost from activity: %+v", activities)
	}
}

func TestLiveControlGuidanceFinalAnswerAndToolBoundary(t *testing.T) {
	for _, atTool := range []bool{false, true} {
		t.Run(map[bool]string{true: "tool", false: "final"}[atTool], func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			control := NewLiveControl(cancel)
			ctx = WithLiveControl(ctx, control)
			turns, executions := 0, 0
			p := captureUsageProvider{stream: func(_ context.Context, y func(llm.StreamEvent, error) bool) {
				turns++
				if turns == 1 {
					if _, err := control.Enqueue("a", "first guidance"); err != nil {
						t.Error(err)
					}
					if dup, err := control.Enqueue("a", "duplicate"); err != nil || !dup {
						t.Error("dedup failed")
					}
					_, _ = control.Enqueue("b", "second guidance")
				}
				events := []llm.StreamEvent{{Type: llm.SETextDelta, Text: "answer"}, {Type: llm.SEMessageDelta, StopReason: "end_turn"}}
				if atTool && turns == 1 {
					events = []llm.StreamEvent{{Type: llm.SEToolUseStart, ToolID: "probe", ToolName: "Probe"}, {Type: llm.SEToolInputJSON, Text: `{}`}, {Type: llm.SEMessageDelta, StopReason: "tool_use"}}
				}
				for _, ev := range events {
					if !y(ev, nil) {
						return
					}
				}
			}}
			probe := tool.Build(tool.Spec{Name: "Probe", Schema: map[string]any{"type": "object"}, Run: func(context.Context, json.RawMessage, *tool.ToolContext) (tool.Result, error) {
				executions++
				return tool.Text("unexpected"), nil
			}})
			session := agentcore.NewSession(agentcore.Options{Provider: p, Tools: []tool.CoreTool{probe}, Hooks: control.Hooks(nil), PermissionMode: permission.ModeBypass, WorkingDir: t.TempDir(), MaxTurns: 6})
			defer session.Close()
			_, _, err := captureRunSession(ctx, session, "start", nil)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(session.Messages())
			text := string(raw)
			if turns != 2 || executions != 0 || !strings.Contains(text, "first guidance") || !strings.Contains(text, "second guidance") || strings.Contains(text, "duplicate") {
				t.Fatalf("guidance lost/duplicated: turns=%d calls=%d messages=%s", turns, executions, text)
			}
			if strings.Index(text, "first guidance") > strings.Index(text, "second guidance") {
				t.Fatal("guidance order changed")
			}
			if _, err = control.Enqueue("late", "too late"); err == nil {
				t.Fatal("sealed session accepted guidance")
			}
		})
	}
}
