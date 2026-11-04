package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"iter"
	"strings"
	"sync"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

// ConstraintSnapshotLoader reloads a run's current task constraints. A loader
// error is a fail-closed condition: the wrapped hooks block execution.
type ConstraintSnapshotLoader func(context.Context) ([]db.Constraint, error)

// NewConstraintRefreshHooks wraps the run's hook chain. initial must be the
// snapshot used to build that run's system prompt; load should read the current
// snapshot (normally ExplorationStore.ListConstraints).
func NewConstraintRefreshHooks(inner harness.HookRunner, initial []db.Constraint, load ConstraintSnapshotLoader) harness.HookRunner {
	return &constraintRefreshHooks{inner: inner, load: load, version: constraintVersion(initial)}
}

type constraintRefreshHooks struct {
	inner   harness.HookRunner
	load    ConstraintSnapshotLoader
	mu      sync.Mutex
	version string
}

func constraintVersion(rows []db.Constraint) string {
	// IDs and content capture edits/deletions/additions without relying on DB
	// timestamps or a schema migration. Empty and nil snapshots are equivalent.
	type item struct {
		ID         int64
		Kind, Text string
	}
	items := make([]item, 0, len(rows))
	for _, row := range rows {
		items = append(items, item{row.ID, row.Kind, row.Text})
	}
	b, _ := json.Marshal(items)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (h *constraintRefreshHooks) refresh(ctx context.Context) (bool, string) {
	if h.load == nil {
		return false, "约束刷新未配置，工具执行已安全阻断；请重试本轮"
	}
	rows, err := h.load(ctx)
	if err != nil {
		return false, fmt.Sprintf("读取最新操作约束失败（%v），工具执行已安全阻断；请重试本轮", err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	v := constraintVersion(rows)
	if v == h.version {
		return false, ""
	}
	block := renderConstraints(rows)
	if strings.TrimSpace(block) == "" {
		block = "\n\n【当前没有登记的操作约束】仍必须遵守任务授权范围；未明确授权的目标或操作不得执行。"
	}
	return true, "【操作约束已更新】以下是最新完整约束，覆盖本轮启动时的旧约束。请基于它重新判断下一步；当前工具尚未执行。\n" + strings.TrimSpace(block)
}

// Each model request receives a fresh snapshot. Only this boundary advances the
// acknowledged version: every outstanding tool from an older response remains
// blocked, even when the SDK executes that response's calls concurrently.
func installConstraintRefresh(opts *agentcore.Options, initial []db.Constraint, load ConstraintSnapshotLoader) {
	h := NewConstraintRefreshHooks(opts.Hooks, initial, load).(*constraintRefreshHooks)
	opts.Hooks = h
	opts.Provider = &constraintProvider{Provider: opts.Provider, h: h}
}

type constraintProvider struct {
	llm.Provider
	h *constraintRefreshHooks
}

func (p *constraintProvider) prepare(ctx context.Context, req llm.CompletionRequest) (llm.CompletionRequest, error) {
	rows, err := p.h.load(ctx)
	if err != nil {
		return req, fmt.Errorf("读取最新操作约束: %w", err)
	}
	block := renderConstraints(rows)
	if strings.TrimSpace(block) == "" {
		block = "当前没有登记的操作约束；仍须遵守原始任务授权范围。"
	}
	req.System = append(append([]string(nil), req.System...), "【本次决策的最新完整操作约束，覆盖此前快照】\n"+block)
	p.h.mu.Lock()
	p.h.version = constraintVersion(rows)
	p.h.mu.Unlock()
	return req, nil
}
func (p *constraintProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		r, err := p.prepare(ctx, req)
		if err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		for ev, e := range p.Provider.Stream(ctx, r) {
			if !yield(ev, e) {
				return
			}
		}
	}
}
func (p *constraintProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	r, err := p.prepare(ctx, req)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	return p.Provider.Complete(ctx, r)
}

func (h *constraintRefreshHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	if changed, msg := h.refresh(ctx); changed {
		return true, msg + "\n请重新判断后再发起工具调用。", nil
	} else if msg != "" {
		return true, msg, nil
	}
	var updated []byte
	if h.inner != nil {
		block, msg, in := h.inner.PreToolUse(ctx, name, input)
		if block {
			return block, msg, in
		}
		updated = in
	}
	// The inner guard may have waited for approval. Refresh again before allowing
	// this tool across the execution boundary.
	if changed, msg := h.refresh(ctx); changed {
		return true, msg + "\n请重新判断后再发起工具调用。", nil
	} else if msg != "" {
		return true, msg, nil
	}
	return false, "", updated
}

func (h *constraintRefreshHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	if h.inner != nil {
		h.inner.PostToolUse(ctx, name, input, result, isErr)
	}
}

func (h *constraintRefreshHooks) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	if changed, msg := h.refresh(ctx); changed {
		return false, []string{msg + "\n请重新判断后继续任务。"}, ""
	} else if msg != "" {
		return false, []string{msg}, ""
	}
	if h.inner != nil {
		return h.inner.Stop(ctx, messages)
	}
	return false, nil, ""
}
