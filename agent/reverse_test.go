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
