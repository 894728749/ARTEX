package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/harness"
)

func TestCalculateReverseBudget(t *testing.T) {
	tests := []struct {
		name     string
		role     time.Duration
		contract int
		task     time.Duration
		hasTask  bool
		want     time.Duration
		bound    bool
	}{
		{name: "zero unlimited", want: 0},
		{name: "contract clamps role", role: 90 * time.Second, contract: 40, want: 40 * time.Second},
		{name: "task clamps contract and role", role: 90 * time.Second, contract: 60, task: 25 * time.Second, hasTask: true, want: 25 * time.Second, bound: true},
		{name: "contract binds before task", role: 30 * time.Second, contract: 20, task: 25 * time.Second, hasTask: true, want: 20 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateReverseBudget(tt.role, tt.contract, tt.task, tt.hasTask)
			if got.effective != tt.want || got.taskBound != tt.bound {
				t.Fatalf("got effective=%s taskBound=%v; want %s %v", got.effective, got.taskBound, tt.want, tt.bound)
			}
		})
	}
}

func TestRenderReverseContinuationAndBudgetSettlement(t *testing.T) {
	intent := &db.Node{Payload: []byte(`{"retry_reason":"provider recovered; continue saved check","execution_result":{"checkpoint":"method foo was inspected","remaining":["verify call site","submit reviewer receipt"]}}`)}
	got := renderReverseContinuation(intent)
	for _, want := range []string{"provider recovered; continue saved check", "method foo was inspected", "verify call site", "不要重新全量分析"} {
		if !strings.Contains(got, want) {
			t.Fatalf("continuation omitted %q: %s", want, got)
		}
	}
	budget := calculateReverseBudget(90*time.Second, 60, 25*time.Second, true)
	prompt := renderReverseBudget(13, budget)
	for _, want := range []string{"max_turns=13", "role_run_seconds=90", "contract_budget_seconds=60", "task_remaining_seconds=25", "实际 run_seconds=25"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("budget prompt omitted %q: %s", want, prompt)
		}
	}
	settlement := &harness.Settlement{Prompt: "old settlement"}
	appendReverseSettlementInstructions(settlement, "reverse_static")
	if !strings.Contains(settlement.Prompt, "complete_intent") || !strings.Contains(settlement.Prompt, "不要启动新取证") {
		t.Fatalf("settlement incomplete: %s", settlement.Prompt)
	}
	appendReverseSettlementInstructions(settlement, "reverse_reviewer")
	if !strings.Contains(settlement.Prompt, "不得提交候选结论") {
		t.Fatalf("reviewer boundary missing: %s", settlement.Prompt)
	}
}
