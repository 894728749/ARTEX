package main

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/collab"
)

func TestNodeMCPFixtureProcess(t *testing.T) {
	if os.Getenv("ARTEX_NODE_MCP_HELPER") != "1" {
		return
	}
	s := bufio.NewScanner(os.Stdin)
	for s.Scan() {
		var req struct {
			ID     int64  `json:"id"`
			Method string `json:"method"`
			Params struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			} `json:"params"`
		}
		if json.Unmarshal(s.Bytes(), &req) != nil || req.ID == 0 {
			continue
		}
		var result any
		switch req.Method {
		case "initialize":
			result = map[string]any{"serverInfo": map[string]any{"version": os.Getenv("ARTEX_NODE_MCP_SECRET")}}
		case "tools/list":
			result = map[string]any{"tools": []any{
				map[string]any{"name": "inspect", "description": "inspect assigned fixture", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"value": map[string]any{"type": "string"}}}},
				map[string]any{"name": "hidden", "description": "not assigned", "inputSchema": map[string]any{"type": "object"}},
				map[string]any{"name": "wait", "description": "wait for cancellation", "inputSchema": map[string]any{"type": "object"}},
				map[string]any{"name": "failure", "description": "server error fixture", "inputSchema": map[string]any{"type": "object"}},
				map[string]any{"name": "read_localfile", "description": "read one assignment-local file", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"path": map[string]any{"type": "string"}}, "required": []string{"path"}}},
			}}
		case "tools/call":
			if req.Params.Name == "wait" {
				time.Sleep(10 * time.Second)
			}
			isError := req.Params.Name == "failure"
			structured := map[string]any{"fixture": "local-only", "ambient_secret": os.Getenv("ARTEX_NODE_MCP_SECRET")}
			if req.Params.Name == "read_localfile" {
				path, _ := req.Params.Arguments["path"].(string)
				if filepath.IsAbs(path) || strings.HasPrefix(filepath.Clean(path), "..") {
					isError = true
				} else if data, err := os.ReadFile(path); err != nil {
					isError = true
				} else {
					structured["file_content"] = string(data)
				}
			}
			result = map[string]any{"isError": isError, "content": []any{map[string]any{"type": "text", "text": "this text contains the word error but may still succeed"}}, "structuredContent": structured}
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}
	os.Exit(0)
}

func nodeMCPFixtureConfig(t *testing.T, role string, capabilities []string, toolMappings map[string]localMCPTool) localExecutionConfig {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return localExecutionConfig{
		Models:     map[string]localModelConfig{"m": {Endpoint: "http://127.0.0.1", APIKeyEnv: "ARTEX_TEST_KEY", Model: "m", Format: "openai"}},
		Roles:      map[string]localRoleConfig{role: {Model: "m", Capabilities: capabilities}},
		MCPServers: map[string]localMCPServer{"fixture": {Command: exe, Args: []string{"-test.run=TestNodeMCPFixtureProcess"}, EnvAllowlist: []string{"ARTEX_NODE_MCP_HELPER"}}},
		MCPTools:   toolMappings,
	}
}

func TestNodeMCPAssemblyFiltersAndJournalsByAlias(t *testing.T) {
	t.Setenv("ARTEX_NODE_MCP_HELPER", "1")
	t.Setenv("ARTEX_NODE_MCP_SECRET", "must-not-inherit")
	config := nodeMCPFixtureConfig(t, "worker", []string{"inspect_alias", "failure_alias", "localfile_alias"}, map[string]localMCPTool{
		"inspect_alias":   {Server: "fixture", Tool: "inspect", ReadOnly: true},
		"failure_alias":   {Server: "fixture", Tool: "failure", ReadOnly: true},
		"localfile_alias": {Server: "fixture", Tool: "read_localfile", ReadOnly: true},
		"hidden_alias":    {Server: "fixture", Tool: "hidden", ReadOnly: true},
	})
	material := []byte("owner-selected local material")
	materialHash := collab.ContentHash(material)
	assignment := collab.Assignment{Config: collab.ExecutionConfig{Role: "worker", Capabilities: []string{"inspect_alias", "failure_alias", "localfile_alias"}}, Input: collab.ExecutionInput{Materials: []collab.Material{{ID: materialHash, SHA256: materialHash, Name: "fixture.txt", Size: int64(len(material))}}}}
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, "materials"), 0700); err != nil {
		t.Fatal(err)
	}
	materialPath := filepath.Join(work, "materials", materialHash)
	if err := os.WriteFile(materialPath, material, 0600); err != nil {
		t.Fatal(err)
	}
	evidence := &nodeEvidence{journal: filepath.Join(work, "evidence.ndjson")}
	gateCount := 0
	set, err := buildAssignmentMCP(context.Background(), config, assignment, work, evidence, func(context.Context) error { gateCount++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer set.close()
	if len(set.tools) != 3 {
		t.Fatalf("assignment exposed unexpected MCP tools: %d", len(set.tools))
	}
	if set.tools[0].Name() != "inspect_alias" || !set.tools[0].IsReadOnly(json.RawMessage(`{}`)) {
		t.Fatalf("MCP alias/read-only metadata missing: %s", set.tools[0].Name())
	}
	if !strings.Contains(set.tools[0].Description(), "inspect assigned fixture") || !strings.Contains(set.tools[0].Description(), "not an OS sandbox") || set.tools[0].InputSchema()["type"] != "object" {
		t.Fatal("MCP schema/description or runtime boundary was not passed through")
	}
	if len(set.clients) != 1 || set.clients[0].Version != "" {
		t.Fatalf("MCP session was not isolated: %#v", set.clients)
	}
	input := json.RawMessage(`{"value":"fixture"}`)
	success, err := set.tools[0].Call(context.Background(), input, nil)
	if err != nil || success.IsError || !strings.Contains(success.Flatten(), "contains the word error") {
		t.Fatalf("MCP result was inferred from text instead of isError: %v %#v", err, success)
	}
	failure, err := set.tools[1].Call(context.Background(), input, nil)
	if err != nil || !failure.IsError {
		t.Fatalf("MCP isError flag was not preserved: %v %#v", err, failure)
	}
	rendered := renderAssignmentInput(assignment, map[string]string{materialHash: materialPath})
	var renderedInput struct {
		Localfiles map[string]string `json:"localfiles"`
	}
	jsonPart := rendered[strings.Index(rendered, "\n")+1:]
	if err := json.Unmarshal([]byte(jsonPart), &renderedInput); err != nil {
		t.Fatal(err)
	}
	localPath := renderedInput.Localfiles[materialHash]
	if localPath != "materials/"+materialHash || strings.Contains(rendered, work) {
		t.Fatalf("localfiles path is missing or exposed an absolute path: %q", localPath)
	}
	localfileInput, _ := json.Marshal(map[string]any{"path": localPath})
	localfileResult, err := set.tools[2].Call(context.Background(), localfileInput, nil)
	if err != nil || localfileResult.IsError || !strings.Contains(localfileResult.Flatten(), string(material)) {
		t.Fatalf("MCP fixture could not open the rendered localfile: %v %s", err, localfileResult.Flatten())
	}
	if gateCount != 10 {
		t.Fatalf("expected setup and per-call fresh heartbeats, got %d", gateCount)
	}
	rows, err := loadNodeEvidence(evidence.journal)
	if err != nil || len(rows) != 3 || rows[0].Tool != "inspect_alias" || rows[1].Tool != "failure_alias" || rows[2].Tool != "localfile_alias" || rows[0].IsError || !rows[1].IsError || rows[2].IsError {
		t.Fatalf("MCP evidence alias/error status not durable: %#v %v", rows, err)
	}
	if strings.Contains(rows[0].Content, "must-not-inherit") {
		t.Fatal("ambient environment secret reached MCP session")
	}
}

func TestNodeMCPCallCancellationClosesAssignmentClient(t *testing.T) {
	t.Setenv("ARTEX_NODE_MCP_HELPER", "1")
	config := nodeMCPFixtureConfig(t, "worker", []string{"wait_alias"}, map[string]localMCPTool{"wait_alias": {Server: "fixture", Tool: "wait", ReadOnly: true}})
	assignment := collab.Assignment{Config: collab.ExecutionConfig{Role: "worker", Capabilities: []string{"wait_alias"}}}
	work := t.TempDir()
	evidence := &nodeEvidence{journal: filepath.Join(work, "evidence.ndjson")}
	set, err := buildAssignmentMCP(context.Background(), config, assignment, work, evidence, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = set.tools[0].Call(ctx, json.RawMessage(`{}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-set.clients[0].Done():
	case <-time.After(time.Second):
		t.Fatal("cancelled MCP process remained open")
	}
	set.close()
	rows, readErr := loadNodeEvidence(evidence.journal)
	if readErr != nil || len(rows) != 1 || !rows[0].IsError {
		t.Fatalf("cancelled MCP call was not journaled: %#v %v", rows, readErr)
	}
}

func TestNodeMCPConfigEnforcesRoleReadonlyAndKeyIsolation(t *testing.T) {
	config := nodeMCPFixtureConfig(t, "reverse_static", []string{"write_alias"}, map[string]localMCPTool{"write_alias": {Server: "fixture", Tool: "mutate", ReadOnly: false}})
	if err := config.validate(); err == nil || !strings.Contains(err.Error(), "must be read-only") {
		t.Fatalf("static role accepted mutating MCP tool: %v", err)
	}
	config = nodeMCPFixtureConfig(t, "worker", []string{"inspect_alias"}, map[string]localMCPTool{"inspect_alias": {Server: "fixture", Tool: "inspect", ReadOnly: true}})
	config.MCPServers["fixture"] = localMCPServer{Command: config.MCPServers["fixture"].Command, Args: config.MCPServers["fixture"].Args, EnvAllowlist: []string{"artEx_test_key"}}
	if err := config.validate(); err == nil || !strings.Contains(err.Error(), "model credential") {
		t.Fatalf("case-variant MCP environment key accepted: %v", err)
	}
}
