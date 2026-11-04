package agent

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

// LiveControl owns one running conversation, never the reusable Agent object.
// Hooks deliver guidance only at execution boundaries. No goroutine mutates a
// Session's message slice while Prompt is running.
type LiveControl struct {
	mu        sync.Mutex
	queue     []string
	seen      map[string]bool
	closed    bool
	stopping  bool
	stopCause error
	active    int
	cancel    context.CancelCauseFunc
}

type liveControlKey struct{}

func NewLiveControl(cancel context.CancelCauseFunc) *LiveControl {
	return &LiveControl{cancel: cancel, seen: map[string]bool{}}
}

func WithLiveControl(ctx context.Context, control *LiveControl) context.Context {
	return context.WithValue(ctx, liveControlKey{}, control)
}

func ControlFrom(ctx context.Context) *LiveControl {
	c, _ := ctx.Value(liveControlKey{}).(*LiveControl)
	return c
}

// Enqueue returns duplicate=true for an already accepted request. Failed enqueue
// is explicit so callers never acknowledge a message after the session sealed.
func (c *LiveControl) Enqueue(id, message string) (duplicate bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if id != "" && c.seen[id] {
		return true, nil
	}
	if c.closed || c.stopping {
		return false, errors.New("本轮正在结束或暂停，请在结束后重发引导")
	}
	if len(c.queue) >= 32 {
		return false, errors.New("待处理引导过多，请等待当前消息处理")
	}
	if strings.TrimSpace(message) == "" {
		return false, errors.New("引导消息不能为空")
	}
	c.queue = append(c.queue, message)
	if id != "" {
		c.seen[id] = true
	}
	return false, nil
}

func (c *LiveControl) drainLocked() string {
	if len(c.queue) == 0 {
		return ""
	}
	text := "【用户在运行中补充的引导，按发送顺序处理】\n" + strings.Join(c.queue, "\n\n")
	c.queue = nil
	return text
}

// NextOrSeal closes the final-answer/enqueue race. If the SDK skipped its Stop
// hook (e.g. a second text-only response), pending inputs get a new Prompt on the
// same session before it can close.
func (c *LiveControl) NextOrSeal() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.stopping {
		if text := c.drainLocked(); text != "" {
			return text
		}
	}
	c.closed = true
	return ""
}

func (c *LiveControl) Close() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	left := append([]string(nil), c.queue...)
	c.queue = nil
	return left
}

// RequestPause blocks all future tools atomically with tool admission. An active
// tool retains its context until PostToolUse; an idle/model-only run stops now.
func (c *LiveControl) RequestPause() {
	c.RequestStopAfterTool(AbortPausedAfterTool)
}

func (c *LiveControl) RequestStopAfterTool(cause error) {
	c.mu.Lock()
	if c.stopping && !errors.Is(cause, AbortPausedAfterTool) {
		c.mu.Unlock()
		return
	}
	c.stopping = true
	c.stopCause = cause
	if c.active == 0 && c.cancel != nil {
		c.cancel(c.stopCause)
	}
	c.mu.Unlock()
}

func (c *LiveControl) IsStopping() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stopping
}

// Cancel is the immediate-stop counterpart to RequestPause.
func (c *LiveControl) Cancel(cause error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopping = true
	c.stopCause = cause
	if c.cancel != nil {
		c.cancel(cause)
	}
}

func (c *LiveControl) Hooks(inner harness.HookRunner) harness.HookRunner {
	return liveHooks{control: c, inner: inner}
}

type liveHooks struct {
	control *LiveControl
	inner   harness.HookRunner
}

func (h liveHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	c := h.control
	c.mu.Lock()
	if c.stopping || ctx.Err() != nil {
		c.mu.Unlock()
		return true, "任务已请求暂停，本次工具未执行", nil
	}
	if text := c.drainLocked(); text != "" {
		c.mu.Unlock()
		return true, text + "\n本次工具未执行，请根据引导重新决定下一步。", nil
	}
	c.mu.Unlock()
	var updated []byte
	if h.inner != nil {
		block, msg, in := h.inner.PreToolUse(ctx, name, input)
		if block {
			return block, msg, in
		}
		updated = in
	}
	// The inner guard may wait for approval. Check again before allowing execution.
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopping || ctx.Err() != nil {
		return true, "任务已请求暂停，本次工具未执行", nil
	}
	if text := c.drainLocked(); text != "" {
		return true, text + "\n本次工具未执行，请根据引导重新决定下一步。", nil
	}
	c.active++
	return false, "", updated
}

func (h liveHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	if h.inner != nil {
		h.inner.PostToolUse(ctx, name, input, result, isErr)
	}
	c := h.control
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active > 0 {
		c.active--
	}
	if c.stopping && c.active == 0 && c.cancel != nil {
		c.cancel(c.stopCause)
	}
}

func (h liveHooks) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	c := h.control
	c.mu.Lock()
	if c.stopping {
		goalMet := errors.Is(c.stopCause, AbortGoalMet)
		c.mu.Unlock()
		if goalMet {
			return true, nil, "目标已验收，当前工具调用已结束，正在收尾"
		}
		return true, nil, "当前工具调用已结束，任务已温和暂停"
	}
	text := c.drainLocked()
	c.mu.Unlock()
	if text != "" {
		return false, []string{text}, ""
	}
	if h.inner != nil {
		return h.inner.Stop(ctx, messages)
	}
	return false, nil, ""
}
