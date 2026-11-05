package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/Autumn-27/artex/collab"
	"github.com/Autumn-27/artex/reamcp"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

const maxMCPToolsPerServer = 512
const maxMCPToolWireOutput = 48 << 10

type localMCPServer struct {
	Command      string   `json:"command"`
	Args         []string `json:"args"`
	EnvAllowlist []string `json:"env_allowlist"`
}

type localMCPTool struct {
	Server   string `json:"server"`
	Tool     string `json:"tool"`
	ReadOnly bool   `json:"read_only"`
}

type assignmentMCP struct {
	clients []*reamcp.Client
	tools   []actool.CoreTool
}

func (m *assignmentMCP) close() {
	for _, client := range m.clients {
		_ = client.Close()
	}
}

func envForAllowlist(keys []string) []string {
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	return env
}

func buildAssignmentMCP(ctx context.Context, cfg localExecutionConfig, a collab.Assignment, work string, evidence *nodeEvidence, gate func(context.Context) error) (*assignmentMCP, error) {
	set := &assignmentMCP{}
	clients := map[string]*reamcp.Client{}
	toolLists := map[string][]reamcp.Tool{}
	closeOnError := func(err error) (*assignmentMCP, error) { set.close(); return nil, err }
	role, ok := cfg.Roles[a.Config.Role]
	if !ok {
		return closeOnError(errors.New("assignment MCP role is not configured locally"))
	}
	roleAllowed := map[string]bool{}
	for _, alias := range role.Capabilities {
		roleAllowed[alias] = true
	}
	seenAliases := map[string]bool{}
	for _, alias := range a.Config.Capabilities {
		mapping, ok := cfg.MCPTools[alias]
		if !ok {
			continue
		}
		if !roleAllowed[alias] || seenAliases[alias] {
			return closeOnError(fmt.Errorf("MCP capability %q is not allowed by this role", alias))
		}
		seenAliases[alias] = true
		client := clients[mapping.Server]
		if client == nil {
			if err := ctx.Err(); err != nil {
				return closeOnError(err)
			}
			if gate != nil {
				if err := gate(ctx); err != nil {
					return closeOnError(err)
				}
			}
			if err := ctx.Err(); err != nil {
				return closeOnError(err)
			}
			server := cfg.MCPServers[mapping.Server]
			if info, err := os.Lstat(work); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return closeOnError(errors.New("assignment MCP work directory is not private"))
			}
			var err error
			client, err = reamcp.NewIsolated(ctx, server.Command, server.Args, work, envForAllowlist(server.EnvAllowlist), nil)
			if err != nil {
				return closeOnError(err)
			}
			clients[mapping.Server] = client
			set.clients = append(set.clients, client)
		}
		if err := ctx.Err(); err != nil {
			return closeOnError(err)
		}
		if gate != nil {
			if err := gate(ctx); err != nil {
				return closeOnError(err)
			}
		}
		if err := ctx.Err(); err != nil {
			return closeOnError(err)
		}
		listed, listedAlready := toolLists[mapping.Server]
		if !listedAlready {
			var listErr error
			listed, listErr = client.Tools(ctx)
			if listErr != nil {
				return closeOnError(listErr)
			}
			if len(listed) > maxMCPToolsPerServer {
				return closeOnError(errors.New("MCP server tool list exceeds the local limit"))
			}
			toolLists[mapping.Server] = listed
		}
		var found *reamcp.Tool
		for i := range listed {
			if listed[i].Name == mapping.Tool {
				if found != nil {
					return closeOnError(errors.New("MCP server returned an ambiguous tool name"))
				}
				found = &listed[i]
			}
		}
		if found == nil {
			return closeOnError(fmt.Errorf("MCP server %q does not expose configured tool %q", mapping.Server, mapping.Tool))
		}
		if len(found.Description) > 16<<10 {
			return closeOnError(fmt.Errorf("MCP tool %q description exceeds the local limit", mapping.Tool))
		}
		if found.InputSchema == nil {
			return closeOnError(fmt.Errorf("MCP tool %q has no input schema", mapping.Tool))
		}
		schemaBytes, err := json.Marshal(found.InputSchema)
		if err != nil || len(schemaBytes) > 64<<10 {
			return closeOnError(fmt.Errorf("MCP tool %q schema is invalid or too large", mapping.Tool))
		}
		set.tools = append(set.tools, mcpCoreTool(alias, mapping.Tool, found.Description, found.InputSchema, client, mapping.ReadOnly, evidence, gate))
	}
	return set, nil
}

func boundedMCPOutput(raw []byte) ([]byte, bool) {
	if len(raw) <= maxMCPToolWireOutput {
		return append([]byte(nil), raw...), false
	}
	const prefix = 6 << 10
	if len(raw) < prefix {
		return append([]byte(nil), raw...), false
	}
	wrapper, _ := json.Marshal(map[string]any{"truncated": true, "original_bytes": len(raw), "raw_prefix": string(raw[:prefix])})
	return wrapper, true
}

func mcpCoreTool(alias, remoteName, description string, schema map[string]any, client *reamcp.Client, readOnly bool, evidence *nodeEvidence, gate func(context.Context) error) actool.CoreTool {
	if description == "" {
		description = "Call the explicitly assigned local MCP tool."
	}
	description += " MCP runs under the node account in an assignment-specific working directory; this is not an OS sandbox. Assigned files are available using relative paths such as materials/<sha256>."
	return actool.Build(actool.Spec{Name: alias, Description: description, Schema: schema, ReadOnly: func(json.RawMessage) bool { return readOnly }, Concurrent: func(json.RawMessage) bool { return false }, Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
		return permission.Allowed()
	}, Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
		if err := gate(ctx); err != nil {
			if json.Valid(input) && len(input) <= 64<<10 {
				evidence.add(alias, input, "fresh assignment heartbeat failed before MCP call", true, false)
			}
			return actool.Errorf("fresh assignment heartbeat failed before MCP call"), nil
		}
		if err := evidence.canStart(input); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		if err := evidence.beginTool(); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		defer evidence.endTool()
		var args map[string]any
		if err := json.Unmarshal(input, &args); err != nil {
			evidence.add(alias, input, "invalid MCP tool input", true, false)
			return actool.Errorf("invalid MCP tool input"), nil
		}
		if args == nil {
			args = map[string]any{}
		}
		if err := gate(ctx); err != nil {
			evidence.add(alias, input, "fresh assignment heartbeat failed before MCP call", true, false)
			return actool.Errorf("fresh assignment heartbeat failed before MCP call"), nil
		}
		raw, err := client.Call(ctx, remoteName, args)
		if err != nil {
			body, _ := json.Marshal(map[string]any{"error": err.Error()})
			evidence.add(alias, input, string(body), true, false)
			return actool.Errorf("local MCP tool call failed; durable evidence recorded"), nil
		}
		var response map[string]json.RawMessage
		if json.Unmarshal(raw, &response) != nil || response == nil {
			evidence.add(alias, input, "MCP server returned invalid JSON", true, false)
			return actool.Errorf("local MCP returned invalid JSON"), nil
		}
		isError := false
		if flag, exists := response["isError"]; exists {
			if err := json.Unmarshal(flag, &isError); err != nil {
				evidence.add(alias, input, "MCP server returned an invalid isError flag", true, false)
				return actool.Errorf("local MCP returned an invalid error flag"), nil
			}
		}
		bounded, truncated := boundedMCPOutput(raw)
		evidence.add(alias, input, string(bounded), isError, truncated)
		if isError {
			return actool.Errorf(string(bounded)), nil
		}
		return actool.Text(string(bounded)), nil
	}})
}
