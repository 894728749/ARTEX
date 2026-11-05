package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/harness"
)

type reverseBudget struct {
	role, contract, task, effective time.Duration
	taskBound                       bool
}

func minPositiveBudget(values ...time.Duration) time.Duration {
	var min time.Duration
	for _, value := range values {
		if value > 0 && (min == 0 || value < min) {
			min = value
		}
	}
	return min
}

func calculateReverseBudget(role time.Duration, contractSeconds int, task time.Duration, taskBound bool) reverseBudget {
	contract := time.Duration(contractSeconds) * time.Second
	if contractSeconds < 0 {
		contract = 0
	}
	if taskBound && task < time.Second {
		task = time.Second // matches clampMaxDuration's runner safety floor
	}
	base := minPositiveBudget(role, contract)
	effective := base
	if taskBound {
		effective = minPositiveBudget(base, task)
	}
	return reverseBudget{role: role, contract: contract, task: task, effective: effective, taskBound: taskBound && (base == 0 || task <= base)}
}

func remainingTaskBudget(deadlineUnix int64, now time.Time) (time.Duration, bool) {
	if deadlineUnix <= 0 {
		return 0, false
	}
	remaining := time.Until(time.Unix(deadlineUnix, 0))
	if !now.IsZero() {
		remaining = time.Unix(deadlineUnix, 0).Sub(now)
	}
	if remaining < time.Second {
		remaining = time.Second
	}
	return remaining, true
}

func secondsLabel(d time.Duration) string {
	if d <= 0 {
		return "unlimited (0)"
	}
	return fmt.Sprintf("%d", int((d+time.Second-1)/time.Second))
}

func renderReverseBudget(maxTurns int, b reverseBudget) string {
	task := "unlimited (no task deadline)"
	if b.taskBound || b.task > 0 {
		task = secondsLabel(b.task)
	}
	effective := secondsLabel(b.effective)
	return fmt.Sprintf("\n\n【本次逆向执行预算】max_turns=%d（0 表示该角色配置不限制轮次）；role_run_seconds=%s，contract_budget_seconds=%s，task_remaining_seconds=%s；实际 run_seconds=%s（正预算取角色、合同、任务剩余时间中的最小值；到达轮次或时间预算后进入系统收尾阶段）。", maxTurns, secondsLabel(b.role), secondsLabel(b.contract), task, effective)
}

func renderReverseContinuation(intent *db.Node) string {
	if intent == nil {
		return ""
	}
	var p struct {
		RetryReason string `json:"retry_reason"`
		Result      struct {
			Checkpoint string   `json:"checkpoint"`
			Remaining  []string `json:"remaining"`
		} `json:"execution_result"`
	}
	if json.Unmarshal(intent.Payload, &p) != nil {
		return ""
	}
	if strings.TrimSpace(p.RetryReason) == "" && strings.TrimSpace(p.Result.Checkpoint) == "" && len(p.Result.Remaining) == 0 {
		return ""
	}
	b, err := json.Marshal(map[string]any{"retry_reason": p.RetryReason, "checkpoint": p.Result.Checkpoint, "remaining": p.Result.Remaining})
	if err != nil {
		return ""
	}
	return "\n\n【续接点（来自已保存的工作结果）】以下内容是当前接续依据；从 checkpoint 和 remaining 继续，不要重新全量分析：\n" + string(b)
}

func appendReverseSettlementInstructions(st *harness.Settlement, role string) {
	if st == nil {
		return
	}
	perRun := "逆向预算收尾：只保存本轮已经获得的事实与证据；提交已有候选结论或独立复核回执，并调用 complete_intent 保存 succeeded/negative/incomplete/blocked 及 remaining/checkpoint。不要启动新取证、扩大材料/目标范围或重新分析。"
	if role == "reverse_reviewer" {
		perRun = "逆向预算收尾：只保存本轮已经完成的独立复核回执，并调用 complete_intent 保存结果及 remaining/checkpoint。不得提交候选结论。不要启动新取证、扩大材料/目标范围或重新全量分析。"
	}
	st.Prompt = strings.TrimSpace(st.Prompt + "\n\n" + perRun)
	for reason, prompt := range st.PromptByReason {
		st.PromptByReason[reason] = strings.TrimSpace(prompt + "\n\n" + perRun)
	}
}
