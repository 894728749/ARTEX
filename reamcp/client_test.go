package reamcp

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestREAHelperProcess(t *testing.T) {
	if os.Getenv("ARTEX_REA_HELPER") != "1" {
		return
	}
	s := bufio.NewScanner(os.Stdin)
	for s.Scan() {
		var req struct {
			ID     int64
			Method string
			Params struct{ Name string }
		}
		_ = json.Unmarshal(s.Bytes(), &req)
		if req.ID == 0 {
			continue
		}
		var result any
		switch req.Method {
		case "initialize":
			result = map[string]any{"serverInfo": map[string]any{"version": "fixture"}}
		case "tools/list":
			result = map[string]any{"tools": []any{map[string]any{"name": "inspect", "inputSchema": map[string]any{"type": "object"}}}}
		case "tools/call":
			if req.Params.Name == "wait" {
				time.Sleep(10 * time.Second)
			}
			result = map[string]any{"content": []any{map[string]any{"type": "text", "text": "preview"}}, "structuredContent": map[string]any{"evidence_id": "fixture-123", "raw_result": strings.Repeat("x", 40000)}}
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}
	os.Exit(0)
}

func TestREARetainsStructuredEvidenceAndCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := New(ctx, os.Args[0], []string{"-test.run=TestREAHelperProcess"}, t.TempDir(), []string{"ARTEX_REA_HELPER=1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tools, err := c.Tools(ctx)
	if err != nil || len(tools) != 1 {
		t.Fatalf("tools: %+v %v", tools, err)
	}
	raw, err := c.Call(ctx, "inspect", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "fixture-123") || len(raw) < 40000 {
		t.Fatal("structured evidence lost or truncated")
	}
	short, stop := context.WithTimeout(ctx, 50*time.Millisecond)
	defer stop()
	start := time.Now()
	_, err = c.Call(short, "wait", nil)
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("cancellation failed: %v", err)
	}
	select {
	case <-c.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("owned process did not terminate")
	}
}

func TestREAInstalledJavaScript(t *testing.T) {
	command := os.Getenv("ARTEX_REA_COMMAND")
	if command == "" {
		t.Skip("REA not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/sample.js", []byte("export function frame(input) { return 'demo:' + input.trim().toUpperCase(); }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := New(ctx, command, []string{"mcp"}, dir, []string{"REA_MCP_TOOL_FAMILIES=application,session"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tools, err := c.Tools(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range tools {
		if tool.Name == "analyze_javascript_application" {
			t.Logf("REA version=%s schema=%s", c.Version, mustJSON(tool.InputSchema))
		}
	}
	raw, err := c.Call(ctx, "analyze_javascript_application", map[string]any{"input_path": dir})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		IsError    bool           `json:"isError"`
		Structured map[string]any `json:"structuredContent"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("REA tool failed: %.2000s", raw)
	}
	if len(result.Structured) == 0 {
		t.Fatalf("missing structured evidence: %.1000s", raw)
	}
	t.Logf("REA analysis returned %d bytes of complete MCP evidence", len(raw))
}
func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
