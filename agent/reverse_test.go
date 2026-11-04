package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

func TestReverseWorkflowPolicies(t *testing.T) {
	if IsReverse(context.Background()) || !IsReverse(WithWorkflow(context.Background(), "reverse")) {
		t.Fatal("workflow must be selected explicitly")
	}
	var tools []actool.CoreTool
	for _, name := range []string{"report_finding", "upsert_asset", "traffic_search", "Bash", "rea_call", "reverse_workspace", "complete_intent", "prove_goal", "get_worker_output"} {
		tools = append(tools, actool.Build(actool.Spec{Name: name}))
	}
	got := reverseTools(tools)
	for _, bad := range []string{"report_finding", "upsert_asset", "traffic_search", "Bash"} {
		if hasTool(got, bad) {
			t.Fatalf("pentest tool leaked: %s", bad)
		}
	}
	for _, want := range []string{"rea_call", "reverse_workspace", "complete_intent", "prove_goal", "get_worker_output"} {
		if !hasTool(got, want) {
			t.Fatalf("missing reverse tool: %s", want)
		}
	}
	for _, role := range []string{"planner", "worker", "mainagent", "goals"} {
		system := reverseSystem(role, "解释本地编码过程", "/tmp/sample")
		if !strings.Contains(system, "逆向") || !strings.Contains(system, "不要求发现漏洞") || !strings.Contains(system, "reverse_review_conclusion") {
			t.Fatalf("missing reverse evidence policy for %s", role)
		}
	}
}

func TestReverseRoleNamespacesAndPromptSeeds(t *testing.T) {
	want := map[string]string{"mainagent": "reverse_main", "goals": "reverse_goals", "planner": "reverse_planner", "worker": "reverse_static"}
	for role, key := range want {
		if got := WorkflowAgentKey("reverse", role); got != key {
			t.Fatalf("WorkflowAgentKey(%q)=%q, want %q", role, got, key)
		}
		if got := WorkflowAgentKey("pentest", role); got != role {
			t.Fatalf("legacy key changed for %q: %q", role, got)
		}
	}
	for _, key := range BuiltinReverseAgentKeys {
		if got := WorkflowAgentKey("reverse", key); got != key {
			t.Fatalf("concrete reverse key %q remapped to %q", key, got)
		}
		if WrapupDefault(key) == genericWrapUpDefault || WrapupTurnsDefault(key) != 8 || TaskTimeoutWrapupDefault(key) == "" {
			t.Fatalf("reverse role %q lacks isolated wrap-up defaults", key)
		}
	}
	for role, key := range map[string]string{"static": "reverse_static", "dynamic": "reverse_dynamic", "reviewer": "reverse_reviewer"} {
		got, err := ReverseWorkerKey(role)
		if err != nil || got != key {
			t.Fatalf("ReverseWorkerKey(%q)=(%q,%v)", role, got, err)
		}
		if _, ok := BuiltinPromptSeeds()[key]; !ok {
			t.Fatalf("missing builtin prompt seed %q", key)
		}
	}
	if _, err := ReverseWorkerKey("unknown"); err == nil {
		t.Fatal("unknown role accepted")
	}
	if got, err := ReverseWorkerKey(""); err != nil || got != "reverse_static" {
		t.Fatalf("empty historical role=(%q,%v)", got, err)
	}
	if !strings.Contains(reverseSystemKey("reverse_reviewer", "worker", "goal", "/tmp/run"), "不得提交结论") {
		t.Fatal("reviewer system policy missing")
	}
	if !strings.Contains(reverseSystemKey("reverse_planner", "planner", "goal", "/tmp/run"), "contract.execution_role") {
		t.Fatal("planner role routing guidance missing")
	}
}

func TestReverseToolAllowlist(t *testing.T) {
	for _, name := range []string{"mcp__demo__read", "Skill", "request_workflow_help", "list_workflow_requests", "return_workflow_result", "cancel_workflow_request", "reverse_review_conclusion"} {
		if !ReverseToolAllowed(name) {
			t.Fatalf("expected allowed tool %q", name)
		}
	}
	for _, name := range []string{"Bash", "report_finding", "traffic_search", "SkillEvil", "not_mcp__demo"} {
		if ReverseToolAllowed(name) {
			t.Fatalf("unexpected allowed tool %q", name)
		}
	}
}

func TestReverseGraphRejectsArtifactAsAssetBeforeWrites(t *testing.T) {
	writes := 0
	base := actool.Build(actool.Spec{Name: "record_fact", Schema: map[string]any{"properties": map[string]any{"asset_ids": map[string]any{"type": "array"}}}, Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
		writes++
		return actool.Text("saved"), nil
	}})
	tool := reverseTools([]actool.CoreTool{base})[0]
	for _, input := range []string{`{"asset_ids":[1]}`, `{"facts":[{"asset_ids":[4]}]}`} {
		result, err := tool.Call(context.Background(), json.RawMessage(input), nil)
		if err != nil || !result.IsError || writes != 0 {
			t.Fatalf("artifact incorrectly anchored: result=%+v err=%v writes=%d", result, err, writes)
		}
	}
	result, err := tool.Call(context.Background(), json.RawMessage(`{"summary":"observed","asset_ids":[]}`), nil)
	if err != nil || result.IsError || writes != 1 {
		t.Fatalf("valid fact rejected: result=%+v err=%v writes=%d", result, err, writes)
	}
}
