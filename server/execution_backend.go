package server

import (
	"context"
	"fmt"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/harness"
)

// IntentExecutor is the existing agent runtime. Keeping this boundary explicit
// lets transports change independently of task admission, control and settlement.
type IntentExecutor interface {
	Execute(context.Context, string, int64, *db.AssetStore, *db.ExplorationStore, *db.Node, harness.HookRunner, func(db.Activity), agent.EnrichTrigger, func(int64, string)) (harness.TerminalReason, agent.WriteCounts, error)
	ExecuteWithMessage(context.Context, string, int64, *db.AssetStore, *db.ExplorationStore, *db.Node, harness.HookRunner, func(db.Activity), agent.EnrichTrigger, func(int64, string), string, string) (harness.TerminalReason, agent.WriteCounts, error)
}

// LocalExecution contains process-local handles, never a network payload.
// Remote executions require a versioned input/configuration snapshot and their
// own authenticated backend; they must not serialize these database pointers.
type LocalExecution struct {
	Executor      IntentExecutor
	Name          string
	TaskID        int64
	Assets        *db.AssetStore
	Store         *db.ExplorationStore
	Intent        *db.Node
	Hooks         harness.HookRunner
	Emit          func(db.Activity)
	Enrich        agent.EnrichTrigger
	NotifyFinding func(int64, string)
	RequestID     string
	Message       string
}

type ExecutionBackend interface {
	Execute(context.Context, LocalExecution) (harness.TerminalReason, agent.WriteCounts, error)
}

type LocalExecutionBackend struct{}

func (LocalExecutionBackend) Execute(ctx context.Context, run LocalExecution) (harness.TerminalReason, agent.WriteCounts, error) {
	if err := ctx.Err(); err != nil {
		return "", agent.WriteCounts{}, err
	}
	if run.Executor == nil || run.Intent == nil {
		return "", agent.WriteCounts{}, fmt.Errorf("missing intent runtime")
	}
	if run.Message != "" {
		return run.Executor.ExecuteWithMessage(ctx, run.Name, run.TaskID, run.Assets, run.Store, run.Intent, run.Hooks, run.Emit, run.Enrich, run.NotifyFinding, run.RequestID, run.Message)
	}
	return run.Executor.Execute(ctx, run.Name, run.TaskID, run.Assets, run.Store, run.Intent, run.Hooks, run.Emit, run.Enrich, run.NotifyFinding)
}

func (e *Engine) executeLocalIntent(ctx context.Context, run LocalExecution) (harness.TerminalReason, agent.WriteCounts, error) {
	backend := e.executionBackend
	if backend == nil {
		backend = LocalExecutionBackend{}
	}
	return backend.Execute(ctx, run)
}
