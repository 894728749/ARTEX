package agent

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

type factNotifierKey struct{}

func WithFactNotifier(ctx context.Context, fn func(int64, string)) context.Context {
	return context.WithValue(ctx, factNotifierKey{}, fn)
}

func stringItems(description string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": description}
}
func workContractSchema() map[string]any {
	ids := func(desc string) map[string]any {
		return map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": desc}
	}
	return obj(map[string]any{
		"workflow_request_id": intp("执行跨工作流委托时必须传该请求编号；后续分析/复核工作继续沿用，以便统一预算和取消，仅目标任务可用"),
		"execution_role":      map[string]any{"type": "string", "enum": []string{"worker", "reverse_static", "reverse_dynamic", "reverse_reviewer"}, "description": "渗透工作使用 worker；逆向按工作内容指定静态/动态/独立核验角色，核验不得交给提交者"},
		"goal_ids":            ids("本任务目标节点"), "hypothesis": str("待证实或推翻的具体假设"),
		"acceptance":    stringItems("可核对的验收条件，必须说明预期证据；省略时使用 summary"),
		"depends_on":    ids("先完成的本任务意图 ID；未满足时等待，不占 Worker 槽。done 只表示验收完成，不代表假设为真"),
		"direction_key": str("同一具体方向使用稳定键，避免换措辞重复派工"), "novelty": str("与既有工作相比的新证据或不同假设"),
		"resource_key": str("本任务内互斥资源键，同键意图不同时运行"), "budget_seconds": intp("该工作的墙钟预算，0 使用 Worker 配置；不得超过任务剩余预算"),
	})
}

func hasTool(tools []actool.CoreTool, name string) bool {
	for _, t := range tools {
		if t.Name() == name {
			return true
		}
	}
	return false
}

func executionPlannerGuidance(tools []actool.CoreTool) string {
	s := "\n\n【执行协议，以本节和实际工具参数为准】新意图要写 contract：假设、目标、验收条件、依赖、方向键与预算。parent_ids 引用已存在证据；depends_on 引用前置工作。先检查前置的实际证据，完成状态不能代替事实。相同方向和输入不重复创建；改变策略须说明 novelty。不得为了维持运行而反复派相同方向。"
	if hasTool(tools, "record_planning_decision") {
		s += " 无法推进时调用 record_planning_decision，记录 waiting/no_progress、原因及恢复条件；无图变化时不反复调用模型。"
	}
	if hasTool(tools, "retry_intent") {
		s += " 已有工作因外部故障或预算中断时，先读 execution_result/checkpoint，再用 retry_intent 明确续做一次；失败后等待条件变化，不循环派工。"
	}
	s += " prove_goal 必须先 node_detail 分别读取目标和证据，使用目标的 evidence_version 作 goal_version、证据的 evidence_version 作 evidence_version，再核对目标全部条件；严禁仅凭摘要和完成状态盖章。旧提示中要求强制产出意图或直接 goal_met 的条款不再适用。"
	s += " dependency_failed 时先读取 dependency_failures 清单；续做前置工作，或基于已保存版本证据创建不同合同的替代工作，并说明替代来源。不得复制不带依赖的工作单绕过失败前置。"
	return s + workflowHelpGuidance(tools)
}

func workflowHelpGuidance(tools []actool.CoreTool) string {
	if !hasTool(tools, "list_workflow_requests") {
		return ""
	}
	return "\n\n【跨流程协助】每轮先读取 list_workflow_requests，按问题、选定输入和验收条件处理收到的委托，后续工作合同沿用 workflow_request_id。证据不足时调用 request_workflow_help 定向求助；静态客户端逻辑不能证明服务端行为，逆向请求行为验证必须指定已有授权渗透任务。重复请求沿用 request_key；接续委托填写 parent_request_id。完成后必须 return_workflow_result 回传证据与局限，再判任务目标；答案缺失如实回传 unresolved。发出请求后等待，不生成相同工作抢跑。回传结果只作为本任务的候选依据，本任务负责最终验证，不直接把收到的解释登记成已确认漏洞。"
}

func executionWorkerGuidance(ts *db.ExplorationStore, n *db.Node, tools []actool.CoreTool) string {
	c, _ := db.IntentContract(n)
	raw, _ := json.Marshal(c)
	s := "\n\n【本次工作验收合同】\n" + string(raw)
	if inputs, err := ts.WorkInputNodes(n.ID); err == nil && len(inputs) > 0 {
		// Keep full evidence on demand rather than truncating a proof and treating it
		// as complete. Summaries and versions locate the exact source to read.
		brief := []map[string]any{}
		for _, v := range inputs {
			var p map[string]any
			_ = json.Unmarshal(v.Payload, &p)
			brief = append(brief, map[string]any{"id": v.ID, "kind": v.Kind, "state": v.State, "summary": p["summary"], "evidence_version": v.EvidenceVersion})
		}
		b, _ := json.Marshal(brief)
		s += "\n直接上游证据索引（细节用 node_detail 核对）：" + string(b)
	}
	if len(c.DependsOn) > 0 {
		s += "\n先用 node_detail 读取 depends_on 的 execution_result 和证据；前置 done 可能是证伪结果，不代表假设成立。"
	}
	if hasTool(tools, "complete_intent") {
		criteria, _ := json.Marshal(db.AcceptanceCriteria(c))
		s += "\n停止前必须调用 complete_intent。先 record_fact/report_finding 保存证据，再 node_detail 读取 evidence_version。使用本合同 criterion_id 填写 satisfied_ids（优先）；旧工作单仍可用完整原文 satisfied。验收清单：" + string(criteria) + "。证伪也可完成，但须证据和验收条件成立。未完成则写 incomplete/blocked、remaining、blocker 和 checkpoint。自然语言总结不是验收结果。"
	} else {
		s += "\ncomplete_intent 当前未启用，无法提交结构化验收；在结论中明确说明配置阻塞，不要声称验收完成。"
	}
	return s
}

func (t *ToolSet) completeIntent() actool.CoreTool {
	return t.writeExpTool("complete_intent", "提交当前 Worker 的结构化结果。验收条件和证据版本由系统检查；提交后结束本轮。无法完成也须保存明确阻塞与续做点。", obj(map[string]any{
		"outcome": map[string]any{"type": "string", "enum": []string{"succeeded", "negative", "reused", "incomplete", "blocked"}}, "summary": str("已验证结果及其边界"),
		"evidence_refs": map[string]any{"type": "array", "items": obj(map[string]any{"node_id": idp("事实/漏洞节点"), "version": str("node_detail 的 evidence_version")}, "node_id", "version")},
		"satisfied_ids": stringItems("优先填写合同验收清单中已满足的 criterion_id；必须覆盖每个 ID，不可重复或提交未知 ID"),
		"satisfied":     stringItems("旧版兼容：逐字列出已满足的完整合同 acceptance 原文；新提交优先使用 satisfied_ids"), "remaining": stringItems("未完成条件"), "blocker": str("阻塞原因"), "checkpoint": str("已做到哪里、下次从哪里继续；避免仅引用本机路径"),
	}, "outcome", "summary"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		if t.ts == nil || t.ownerNode < 1 || t.executionAttempt < 1 {
			return actool.Errorf("没有正在执行的 Worker 工作单"), nil
		}
		var r db.IntentResult
		if err := json.Unmarshal(in, &r); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		if err := t.ts.SubmitIntentResult(ctx, t.ownerNode, t.executionAttempt, r); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		return actool.Text("验收结果已保存；请简要总结后结束本轮。运行结束时系统会再次核对证据与执行代次。"), nil
	})
}

func (t *ToolSet) planningDecision() actool.CoreTool {
	return t.writeExpTool("record_planning_decision", "记录当前等待或无进展原因，等待图变化/用户引导后再规划；可设置有界的复查间隔。不会暂停其它可执行工作。", obj(map[string]any{
		"kind": map[string]any{"type": "string", "enum": []string{"waiting", "no_progress"}}, "reason": str("当前不能继续的具体原因"), "resume_when": str("什么新证据、前置产出或用户信息能解除阻塞"), "check_after_seconds": intp("0 只等图变化；非零最少 60 秒，最多 86400 秒，在后续心跳复查"),
	}, "kind", "reason", "resume_when"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var d db.PlanningDecision
		if err := json.Unmarshal(in, &d); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		d.Reason = strings.TrimSpace(d.Reason)
		if err := t.ts.RecordPlanningDecision(ctx, d); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		return actool.Text("规划决策已保存；等待恢复条件，不需要反复生成同义意图。"), nil
	})
}

func (t *ToolSet) retryIntent() actool.CoreTool {
	return t.writeExpTool("retry_intent", "明确续做 blocked/exhausted 工作，每条工作最多自动续做一次。先查看 execution_result/checkpoint 和真实工具输出，说明故障变化或剩余工作；禁止换措辞重复建单。", obj(map[string]any{"intent_id": idp("本任务待续做意图"), "reason": str("故障变化、续做依据和接续点")}, "intent_id", "reason"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			ID     int64  `json:"intent_id"`
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(in, &a); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		if err := t.ts.RetryWorkIntent(ctx, a.ID, a.Reason); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		return actool.Text("续做已排队；系统仍会核对前置与资源互斥条件。"), nil
	})
}
