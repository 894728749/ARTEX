package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/collab"
	"github.com/Autumn-27/norma/llm"
)

type nodeScriptProvider struct {
	turns     int
	toolInput string
}

type nodeMessageScriptProvider struct {
	turns           int
	toolInput       string
	tools           []string
	prefixFragments int
	finalFragments  int
	finalText       string
}

type nodeStopContinuationProvider struct{ turns int }

func (p *nodeStopContinuationProvider) Stream(_ context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(y func(llm.StreamEvent, error) bool) {
		p.turns++
		events := []llm.StreamEvent{}
		switch p.turns {
		case 1:
			events = []llm.StreamEvent{{Type: llm.SETextDelta, Text: "first-final"}, {Type: llm.SEMessageDelta, StopReason: "end_turn"}}
		case 2:
			events = []llm.StreamEvent{{Type: llm.SETextDelta, Text: "second-prefix"}, {Type: llm.SEToolUseStart, ToolID: "continued-call", ToolName: "safe_tool"}, {Type: llm.SEToolInputJSON, Text: `{"probe":"after-guidance"}`}, {Type: llm.SEMessageDelta, StopReason: "tool_use"}}
		default:
			events = []llm.StreamEvent{{Type: llm.SETextDelta, Text: "last-final"}, {Type: llm.SEMessageDelta, StopReason: "end_turn"}}
		}
		for _, event := range events {
			if !y(event, nil) {
				return
			}
		}
	}
}

func (p *nodeStopContinuationProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	acc := llm.NewAccumulator()
	for event, err := range p.Stream(ctx, req) {
		if err != nil {
			return llm.Message{}, "", llm.Usage{}, err
		}
		acc.Add(event)
	}
	return acc.Message(), acc.StopReason, acc.Usage, nil
}

func (p *nodeMessageScriptProvider) Stream(_ context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(y func(llm.StreamEvent, error) bool) {
		p.turns++
		if p.turns <= len(p.tools) {
			if p.turns == 1 {
				for i := 0; i < p.prefixFragments; i++ {
					if !y(llm.StreamEvent{Type: llm.SETextDelta, Text: "prefix"}, nil) {
						return
					}
				}
			}
			for _, event := range []llm.StreamEvent{{Type: llm.SEToolUseStart, ToolID: fmt.Sprintf("call-%d", p.turns), ToolName: p.tools[p.turns-1]}, {Type: llm.SEToolInputJSON, Text: p.toolInput}, {Type: llm.SEMessageDelta, StopReason: "tool_use"}} {
				if !y(event, nil) {
					return
				}
			}
			return
		}
		for i := 0; i < p.finalFragments; i++ {
			if !y(llm.StreamEvent{Type: llm.SETextDelta, Text: "final"}, nil) {
				return
			}
		}
		if p.finalText != "" {
			_ = y(llm.StreamEvent{Type: llm.SETextDelta, Text: p.finalText}, nil)
		}
		_ = y(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil)
	}
}

func (p *nodeMessageScriptProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	acc := llm.NewAccumulator()
	for event, err := range p.Stream(ctx, req) {
		if err != nil {
			return llm.Message{}, "", llm.Usage{}, err
		}
		acc.Add(event)
	}
	return acc.Message(), acc.StopReason, acc.Usage, nil
}

func (p *nodeScriptProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(y func(llm.StreamEvent, error) bool) {
		p.turns++
		if p.turns == 1 {
			for _, ev := range []llm.StreamEvent{{Type: llm.SEToolUseStart, ToolID: "call-1", ToolName: "echo_tool"}, {Type: llm.SEToolInputJSON, Text: p.toolInput}, {Type: llm.SEMessageDelta, StopReason: "tool_use"}} {
				if !y(ev, nil) {
					return
				}
			}
			return
		}
		_ = y(llm.StreamEvent{Type: llm.SETextDelta, Text: "candidate evidence collected"}, nil)
		_ = y(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil)
	}
}
func (p *nodeScriptProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	acc := llm.NewAccumulator()
	for ev, e := range p.Stream(ctx, req) {
		if e != nil {
			return llm.Message{}, "", llm.Usage{}, e
		}
		acc.Add(ev)
	}
	return acc.Message(), acc.StopReason, acc.Usage, nil
}

func TestNodeCommandHelper(t *testing.T) {
	if os.Getenv("ARTEX_NODE_COMMAND_HELPER") != "1" && os.Getenv("ARTEX_TEST_KEY") == "" {
		return
	}
	if key := os.Getenv("ARTEX_TEST_KEY"); key != "" {
		fmt.Fprint(os.Stdout, "MODEL_KEY_LEAK:", key)
	}
	if path := os.Getenv("ARTEX_NODE_SIDE_EFFECT"); path != "" {
		_ = os.WriteFile(path, []byte("ran"), 0600)
	}
	_, _ = io.Copy(os.Stdout, os.Stdin)
	os.Exit(0)
}

func TestNodeToolHeartbeatCancellationStopsCommand(t *testing.T) {
	assignment := collab.Assignment{ID: 22, TaskID: 3, IntentID: 9, DeviceID: 4, Epoch: 1, State: "assigned", Config: collab.ExecutionConfig{Version: 1, Kind: "pentest", Role: "worker", SystemPrompt: "inspect", Capabilities: []string{"echo_tool"}, MaxTurns: 3, BudgetSeconds: 30}, Input: collab.ExecutionInput{Version: 1, Intent: "run only while authorized"}}
	var hb int
	var result collab.ExecutionResult
	sentinel := filepath.Join(t.TempDir(), "command-ran")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/collaboration/device/capabilities":
			w.WriteHeader(204)
		case "/api/collaboration/device/assignments":
			_ = json.NewEncoder(w).Encode([]collab.Assignment{assignment})
		case "/api/collaboration/device/assignments/22/claim":
			assignment.State = "claimed"
			_ = json.NewEncoder(w).Encode(assignment)
		case "/api/collaboration/device/assignments/22/heartbeat":
			hb++
			if hb == 2 {
				http.Error(w, "lease lost", 403)
				return
			}
			assignment.State = "running"
			_ = json.NewEncoder(w).Encode(assignment)
		case "/api/collaboration/device/assignments/22/result":
			var body struct {
				Result collab.ExecutionResult `json:"result"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			result = body.Result
			_ = json.NewEncoder(w).Encode(map[string]bool{"accepted": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	statePath := filepath.Join(t.TempDir(), "identity.json")
	stateRaw, _ := json.Marshal(deviceState{CoordinatorURL: server.URL, Token: "lease-test"})
	_ = os.WriteFile(statePath, stateRaw, 0600)
	exe, _ := os.Executable()
	t.Setenv("ARTEX_NODE_COMMAND_HELPER", "1")
	t.Setenv("ARTEX_NODE_SIDE_EFFECT", sentinel)
	t.Setenv("ARTEX_TEST_KEY", "never-pass-this")
	cfg := localExecutionConfig{WorkDir: filepath.Join(t.TempDir(), "work"), OutboxDir: filepath.Join(t.TempDir(), "outbox"), Roles: map[string]localRoleConfig{"worker": {Model: "m", Capabilities: []string{"echo_tool"}}}, Models: map[string]localModelConfig{"m": {Endpoint: "http://127.0.0.1/unused", APIKeyEnv: "ARTEX_TEST_KEY", Model: "fake", Format: "openai"}}, Commands: map[string]localCommandConfig{"echo_tool": {Description: "fixture command", Schema: map[string]any{"type": "object"}, Command: exe, FixedArgs: []string{"-test.run=TestNodeCommandHelper"}, EnvAllowlist: []string{"ARTEX_NODE_COMMAND_HELPER", "ARTEX_NODE_SIDE_EFFECT"}}}}
	prior := deviceProviderFactory
	deviceProviderFactory = func(localModelConfig, string) (llm.Provider, error) {
		return &nodeScriptProvider{toolInput: `{"x":1}`}, nil
	}
	defer func() { deviceProviderFactory = prior }()
	if err := runAssignments(t.Context(), cfg, statePath, server.URL, server.Client(), io.Discard, true); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("permanent authorization loss did not stop the node: %v", err)
	}
	if hb != 2 || result.Outcome != "" {
		t.Fatalf("node proceeded after heartbeat rejection: heartbeats=%d result=%#v", hb, result)
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("command ran after heartbeat rejection: %v", err)
	}
}

func TestRunOnceBuildsBoundedSessionAndSendsReceipt(t *testing.T) {
	commandInput := `{"probe":"fixture"}`
	assignment := collab.Assignment{ID: 21, TaskID: 3, IntentID: 8, DeviceID: 4, Epoch: 2, Attempt: 1, State: "assigned", Config: collab.ExecutionConfig{Version: 1, Kind: "pentest", Role: "worker", SystemPrompt: "only inspect fixture", Capabilities: []string{"echo_tool"}, MaxTurns: 3, BudgetSeconds: 30}, Input: collab.ExecutionInput{Version: 1, Intent: "echo the fixture"}}
	var got collab.ExecutionResult
	var gotInput map[string]any
	var heartbeatCount int
	var messageCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/collaboration/device/assignments/21/messages" {
			messageCalls++
			http.Error(w, "old assignment must not use messages", http.StatusNotFound)
			return
		}
		if r.URL.Path == "/api/collaboration/device/capabilities" && r.Method == http.MethodPost {
			var body struct {
				Capabilities struct {
					MessageProtocol int `json:"message_protocol"`
				} `json:"capabilities"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Capabilities.MessageProtocol != 1 {
				t.Errorf("node did not advertise message protocol 1: body=%+v err=%v", body, err)
			}
			w.WriteHeader(204)
			return
		}
		if r.URL.Path == "/api/collaboration/device/assignments" && r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode([]collab.Assignment{assignment})
			return
		}
		if r.URL.Path == "/api/collaboration/device/assignments/21/claim" || r.URL.Path == "/api/collaboration/device/assignments/21/heartbeat" {
			if r.Method != http.MethodPost {
				t.Errorf("unexpected method %s", r.Method)
			}
			_ = json.NewDecoder(r.Body).Decode(&gotInput)
			if gotInput["epoch"] != float64(2) {
				t.Errorf("epoch not fenced: %v", gotInput)
			}
			if strings.HasSuffix(r.URL.Path, "heartbeat") {
				heartbeatCount++
			}
			assignment.State = "running"
			_ = json.NewEncoder(w).Encode(assignment)
			return
		}
		if r.URL.Path == "/api/collaboration/device/assignments/21/result" {
			var req struct {
				Epoch  int64                  `json:"epoch"`
				Result collab.ExecutionResult `json:"result"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
			}
			if req.Epoch != 2 {
				t.Errorf("wrong result epoch %d", req.Epoch)
			}
			got = req.Result
			_ = json.NewEncoder(w).Encode(map[string]bool{"accepted": true})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	statePath := filepath.Join(t.TempDir(), "identity.json")
	stateRaw, _ := json.Marshal(deviceState{CoordinatorURL: server.URL, Token: "private-device-token"})
	if err := os.WriteFile(statePath, stateRaw, 0600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_NODE_COMMAND_HELPER", "1")
	cfg := localExecutionConfig{WorkDir: filepath.Join(t.TempDir(), "work"), OutboxDir: filepath.Join(t.TempDir(), "outbox"), Roles: map[string]localRoleConfig{"worker": {Model: "local", Capabilities: []string{"echo_tool"}}}, Models: map[string]localModelConfig{"local": {Endpoint: "http://127.0.0.1/unreachable", APIKeyEnv: "ARTEX_TEST_KEY", Model: "fake", Format: "openai"}}, Commands: map[string]localCommandConfig{"echo_tool": {Description: "echo raw input", Schema: map[string]any{"type": "object"}, Command: exe, FixedArgs: []string{"-test.run=TestNodeCommandHelper"}, EnvAllowlist: []string{"ARTEX_NODE_COMMAND_HELPER"}, ReadOnly: true}}}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_TEST_KEY", "local-only-test-key")
	prior := deviceProviderFactory
	provider := &nodeScriptProvider{toolInput: commandInput}
	deviceProviderFactory = func(localModelConfig, string) (llm.Provider, error) { return provider, nil }
	defer func() { deviceProviderFactory = prior }()
	var output strings.Builder
	if err := runAssignments(t.Context(), cfg, statePath, server.URL, server.Client(), &output, true); err != nil {
		t.Fatal(err)
	}
	if got.Outcome != "candidate" || got.Role != "worker" || got.Model != "fake" || !strings.Contains(got.Summary, "candidate evidence") {
		t.Fatalf("unexpected result: %#v", got)
	}
	if len(got.Evidence) != 1 || got.Evidence[0].Tool != "echo_tool" || string(got.Evidence[0].Input) != commandInput || !strings.Contains(got.Evidence[0].Content, "fixture") || strings.Contains(got.Evidence[0].Content, "MODEL_KEY_LEAK") {
		t.Fatalf("tool evidence missing input/output: %#v", got.Evidence)
	}
	if got.Evidence[0].SHA256 != collab.ContentHash([]byte(got.Evidence[0].Content)) || heartbeatCount < 2 {
		t.Fatalf("evidence hash/heartbeat invalid: count=%d", heartbeatCount)
	}
	if strings.Contains(output.String(), "error") {
		t.Fatalf("run output indicates an error: %s", output.String())
	}
	if messageCalls != 0 {
		t.Fatalf("legacy assignment unexpectedly used the message protocol: %d calls", messageCalls)
	}
}

func TestNodeMessageGuidanceBlocksToolAndSealsAfterFinalText(t *testing.T) {
	assignment := collab.Assignment{ID: 33, TaskID: 3, IntentID: 8, DeviceID: 4, Epoch: 5, Attempt: 1, State: "assigned", Config: collab.ExecutionConfig{Version: 1, MessageProtocol: 1, Kind: "pentest", Role: "worker", SystemPrompt: "inspect", Capabilities: []string{"danger_tool", "safe_tool"}, MaxTurns: 6, BudgetSeconds: 30}, Input: collab.ExecutionInput{Version: 1, Intent: "follow the shared message channel"}}
	var got collab.ExecutionResult
	var messageCalls int
	var received []collab.DeviceMessage
	var delivered []int64
	var provider *nodeMessageScriptProvider
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/collaboration/device/assignments/33/claim", "/api/collaboration/device/assignments/33/heartbeat":
			assignment.State = "running"
			_ = json.NewEncoder(w).Encode(assignment)
		case "/api/collaboration/device/assignments/33/messages":
			messageCalls++
			var exchange collab.MessageExchange
			if err := json.NewDecoder(r.Body).Decode(&exchange); err != nil || exchange.Epoch != assignment.Epoch {
				t.Errorf("invalid message exchange: %#v err=%v", exchange, err)
			}
			received = append(received, exchange.Messages...)
			delivered = append(delivered, exchange.Delivered...)
			switch messageCalls {
			case 1: // activate the channel before the first model request
				if exchange.Seal || len(exchange.Messages) != 0 {
					t.Errorf("unexpected initial message exchange: %#v", exchange)
				}
				_ = json.NewEncoder(w).Encode(collab.MessageExchangeReply{})
			case 2: // guidance arrives at the first execution boundary
				if len(exchange.Messages) != 1 || exchange.Messages[0].Seq != 1 || exchange.Messages[0].Text != strings.Repeat("prefix", 40) {
					t.Errorf("text deltas were not coalesced before exchange: %#v", exchange.Messages)
				}
				_ = json.NewEncoder(w).Encode(collab.MessageExchangeReply{Guidance: []collab.Guidance{{ID: 71, Text: "Do not run the requested command; run the safe alternative."}}})
			case 3:
				if exchange.Seal || len(exchange.Delivered) != 1 || exchange.Delivered[0] != 71 {
					t.Errorf("next tool boundary did not confirm delivered guidance: %#v", exchange)
				}
				_ = json.NewEncoder(w).Encode(collab.MessageExchangeReply{})
			case 4:
				if !exchange.Seal || len(exchange.Messages) != 1 || exchange.Messages[0].Seq != 2 || exchange.Messages[0].Text != strings.Repeat("final", 40) {
					t.Errorf("final response was not persisted before sealing: %#v", exchange)
				}
				_ = json.NewEncoder(w).Encode(collab.MessageExchangeReply{Sealed: true})
			default:
				t.Errorf("unexpected message exchange %d: %#v", messageCalls, exchange)
				_ = json.NewEncoder(w).Encode(collab.MessageExchangeReply{Sealed: true})
			}
		case "/api/collaboration/device/assignments/33/result":
			var body struct {
				Result collab.ExecutionResult `json:"result"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			got = body.Result
			_ = json.NewEncoder(w).Encode(map[string]bool{"accepted": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	work := t.TempDir()
	sentinel := filepath.Join(work, "command-ran")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_NODE_COMMAND_HELPER", "1")
	t.Setenv("ARTEX_NODE_SIDE_EFFECT", sentinel)
	t.Setenv("ARTEX_TEST_KEY", "test-only")
	cfg := localExecutionConfig{WorkDir: filepath.Join(work, "runs"), OutboxDir: filepath.Join(work, "outbox"), Roles: map[string]localRoleConfig{"worker": {Model: "m", Capabilities: []string{"danger_tool", "safe_tool"}}}, Models: map[string]localModelConfig{"m": {Model: "fake", APIKeyEnv: "ARTEX_TEST_KEY", Format: "openai"}}, Commands: map[string]localCommandConfig{
		"danger_tool": {Description: "blocked fixture command", Schema: map[string]any{"type": "object"}, Command: exe, FixedArgs: []string{"-test.run=TestNodeCommandHelper"}, EnvAllowlist: []string{"ARTEX_NODE_COMMAND_HELPER", "ARTEX_NODE_SIDE_EFFECT"}},
		"safe_tool":   {Description: "safe fixture command", Schema: map[string]any{"type": "object"}, Command: exe, FixedArgs: []string{"-test.run=TestNodeCommandHelper"}, EnvAllowlist: []string{"ARTEX_NODE_COMMAND_HELPER"}},
	}}
	provider = &nodeMessageScriptProvider{toolInput: `{"probe":"fixture"}`, tools: []string{"danger_tool", "safe_tool"}, prefixFragments: 40, finalFragments: 40}
	prior := deviceProviderFactory
	deviceProviderFactory = func(localModelConfig, string) (llm.Provider, error) { return provider, nil }
	defer func() { deviceProviderFactory = prior }()
	err = executeAssignment(context.Background(), cfg, assignment, server.URL, "token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if provider.turns != 3 || messageCalls != 4 || got.Outcome != "candidate" || !strings.Contains(got.Summary, strings.Repeat("final", 40)) {
		t.Fatalf("guidance did not continue in one session and complete: turns=%d messages=%d result=%+v", provider.turns, messageCalls, got)
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("tool ran despite coordinator guidance: statErr=%v", err)
	}
	if len(received) != 2 || received[0].Seq != 1 || received[0].Text != strings.Repeat("prefix", 40) || received[1].Seq != 2 || received[1].Text != strings.Repeat("final", 40) || len(delivered) != 1 || delivered[0] != 71 {
		t.Fatalf("message exchange was not sequenced/acknowledged: received=%+v delivered=%v", received, delivered)
	}
	if len(got.Evidence) != 1 || got.Evidence[0].Tool != "safe_tool" {
		t.Fatalf("guidance did not block the original tool and allow the new one: evidence=%+v", got.Evidence)
	}
	journal := filepath.Join(cfg.WorkDir, "exec-33-5", "messages.ndjson")
	raw, err := os.ReadFile(journal)
	if err != nil || !strings.Contains(string(raw), `"direction":"guidance"`) || !strings.Contains(string(raw), "Do not run the requested command") || !strings.Contains(string(raw), `"direction":"outbound"`) {
		t.Fatalf("message journal missing durable exchange events: err=%v journal=%s", err, raw)
	}
}

func TestNodeMessageStopContinuationDoesNotRepeatFinalText(t *testing.T) {
	assignment := collab.Assignment{ID: 35, TaskID: 3, IntentID: 8, DeviceID: 4, Epoch: 5, Attempt: 1, State: "assigned", Config: collab.ExecutionConfig{Version: 1, MessageProtocol: 1, Kind: "pentest", Role: "worker", SystemPrompt: "inspect", Capabilities: []string{"safe_tool"}, MaxTurns: 6, BudgetSeconds: 30}, Input: collab.ExecutionInput{Version: 1, Intent: "continue after guidance"}}
	var got collab.ExecutionResult
	var messageCalls int
	var received []collab.DeviceMessage
	var provider *nodeStopContinuationProvider
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/collaboration/device/assignments/35/claim", "/api/collaboration/device/assignments/35/heartbeat":
			assignment.State = "running"
			_ = json.NewEncoder(w).Encode(assignment)
		case "/api/collaboration/device/assignments/35/messages":
			messageCalls++
			var exchange collab.MessageExchange
			if err := json.NewDecoder(r.Body).Decode(&exchange); err != nil {
				t.Error(err)
			}
			received = append(received, exchange.Messages...)
			switch messageCalls {
			case 1:
				_ = json.NewEncoder(w).Encode(collab.MessageExchangeReply{})
			case 2:
				if !exchange.Seal || len(exchange.Messages) != 1 || exchange.Messages[0].Text != "first-final" {
					t.Errorf("first Stop did not send its authoritative final text: %+v", exchange)
				}
				_ = json.NewEncoder(w).Encode(collab.MessageExchangeReply{Guidance: []collab.Guidance{{ID: 81, Text: "continue with the safe tool"}}})
			case 3:
				if exchange.Seal || len(exchange.Delivered) != 1 || exchange.Delivered[0] != 81 || len(exchange.Messages) != 1 || exchange.Messages[0].Text != "second-prefix" {
					t.Errorf("continued tool boundary duplicated the prior final text: %+v", exchange)
				}
				_ = json.NewEncoder(w).Encode(collab.MessageExchangeReply{})
			case 4:
				if !exchange.Seal || len(exchange.Messages) != 1 || exchange.Messages[0].Text != "last-final" {
					t.Errorf("last Stop did not send only its final text: %+v", exchange)
				}
				_ = json.NewEncoder(w).Encode(collab.MessageExchangeReply{Sealed: true})
			default:
				t.Errorf("unexpected message exchange %d", messageCalls)
				_ = json.NewEncoder(w).Encode(collab.MessageExchangeReply{Sealed: true})
			}
		case "/api/collaboration/device/assignments/35/result":
			var body struct {
				Result collab.ExecutionResult `json:"result"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			got = body.Result
			_ = json.NewEncoder(w).Encode(map[string]bool{"accepted": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	work := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_NODE_COMMAND_HELPER", "1")
	t.Setenv("ARTEX_TEST_KEY", "test-only")
	cfg := localExecutionConfig{WorkDir: filepath.Join(work, "runs"), OutboxDir: filepath.Join(work, "outbox"), Roles: map[string]localRoleConfig{"worker": {Model: "m", Capabilities: []string{"safe_tool"}}}, Models: map[string]localModelConfig{"m": {Model: "fake", APIKeyEnv: "ARTEX_TEST_KEY", Format: "openai"}}, Commands: map[string]localCommandConfig{"safe_tool": {Description: "safe fixture command", Schema: map[string]any{"type": "object"}, Command: exe, FixedArgs: []string{"-test.run=TestNodeCommandHelper"}, EnvAllowlist: []string{"ARTEX_NODE_COMMAND_HELPER"}}}}
	provider = &nodeStopContinuationProvider{}
	prior := deviceProviderFactory
	deviceProviderFactory = func(localModelConfig, string) (llm.Provider, error) { return provider, nil }
	defer func() { deviceProviderFactory = prior }()
	if err = executeAssignment(context.Background(), cfg, assignment, server.URL, "token", server.Client()); err != nil {
		t.Fatal(err)
	}
	if provider.turns != 3 || messageCalls != 4 || got.Outcome != "candidate" || len(got.Evidence) != 1 || got.Evidence[0].Tool != "safe_tool" {
		t.Fatalf("Stop continuation did not run the new tool and finish: turns=%d exchanges=%d result=%+v", provider.turns, messageCalls, got)
	}
	if len(received) != 3 || received[0].Seq != 1 || received[0].Text != "first-final" || received[1].Seq != 2 || received[1].Text != "second-prefix" || received[2].Seq != 3 || received[2].Text != "last-final" {
		t.Fatalf("outbound messages contain a repeated or missing turn: %+v", received)
	}
}

func TestNodeMessageExchangeFailureStopsBeforeTool(t *testing.T) {
	assignment := collab.Assignment{ID: 44, TaskID: 3, IntentID: 9, DeviceID: 4, Epoch: 2, State: "assigned", Config: collab.ExecutionConfig{Version: 1, MessageProtocol: 1, Kind: "pentest", Role: "worker", SystemPrompt: "inspect", Capabilities: []string{"echo_tool"}, MaxTurns: 3, BudgetSeconds: 30}, Input: collab.ExecutionInput{Version: 1, Intent: "run only if authorized"}}
	var got collab.ExecutionResult
	var messageCalls int
	var provider *nodeMessageScriptProvider
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/collaboration/device/assignments/44/claim", "/api/collaboration/device/assignments/44/heartbeat":
			assignment.State = "running"
			_ = json.NewEncoder(w).Encode(assignment)
		case "/api/collaboration/device/assignments/44/messages":
			messageCalls++
			if messageCalls == 1 {
				_ = json.NewEncoder(w).Encode(collab.MessageExchangeReply{}) // activate before the model starts
				return
			}
			http.Error(w, "denied", http.StatusForbidden)
		case "/api/collaboration/device/assignments/44/result":
			var body struct {
				Result collab.ExecutionResult `json:"result"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			got = body.Result
			_ = json.NewEncoder(w).Encode(map[string]bool{"accepted": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	work := t.TempDir()
	sentinel := filepath.Join(work, "command-ran")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_NODE_COMMAND_HELPER", "1")
	t.Setenv("ARTEX_NODE_SIDE_EFFECT", sentinel)
	t.Setenv("ARTEX_TEST_KEY", "test-only")
	cfg := localExecutionConfig{WorkDir: filepath.Join(work, "runs"), OutboxDir: filepath.Join(work, "outbox"), Roles: map[string]localRoleConfig{"worker": {Model: "m", Capabilities: []string{"echo_tool"}}}, Models: map[string]localModelConfig{"m": {Model: "fake", APIKeyEnv: "ARTEX_TEST_KEY", Format: "openai"}}, Commands: map[string]localCommandConfig{"echo_tool": {Description: "fixture", Schema: map[string]any{"type": "object"}, Command: exe, FixedArgs: []string{"-test.run=TestNodeCommandHelper"}, EnvAllowlist: []string{"ARTEX_NODE_COMMAND_HELPER", "ARTEX_NODE_SIDE_EFFECT"}}}}
	provider = &nodeMessageScriptProvider{toolInput: `{"probe":"must-not-run"}`, tools: []string{"echo_tool"}, prefixFragments: 2}
	prior := deviceProviderFactory
	deviceProviderFactory = func(localModelConfig, string) (llm.Provider, error) { return provider, nil }
	defer func() { deviceProviderFactory = prior }()
	if err = executeAssignment(context.Background(), cfg, assignment, server.URL, "token", server.Client()); err != nil {
		t.Fatal(err)
	}
	if provider.turns != 1 || messageCalls != 2 || got.Outcome != "blocked" || !strings.Contains(got.Summary, "Team message exchange failed") || !strings.Contains(got.Checkpoint, "messages.ndjson") {
		t.Fatalf("message failure was not reported as blocked: turns=%d messages=%d result=%+v", provider.turns, messageCalls, got)
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("tool ran after message exchange failure: statErr=%v", err)
	}
	journal := filepath.Join(cfg.WorkDir, "exec-44-2", "messages.ndjson")
	raw, err := os.ReadFile(journal)
	if err != nil || !strings.Contains(string(raw), `"direction":"outbound"`) || !strings.Contains(string(raw), "prefixprefix") {
		t.Fatalf("failed message exchange was not retained in local journal: err=%v journal=%s", err, raw)
	}
}

func TestReverseStaticCannotUseConfiguredMutatingCapability(t *testing.T) {
	a := collab.Assignment{ID: 1, TaskID: 1, IntentID: 1, Epoch: 1, State: "assigned", Config: collab.ExecutionConfig{Version: 1, Kind: "reverse", Role: "reverse_static", SystemPrompt: "inspect", Capabilities: []string{"mutate"}, MaxTurns: 1, BudgetSeconds: 10}, Input: collab.ExecutionInput{Version: 1, Intent: "inspect"}}
	cfg := localExecutionConfig{Roles: map[string]localRoleConfig{"reverse_static": {Model: "m", Capabilities: []string{"mutate"}}}, Models: map[string]localModelConfig{"m": {Model: "m"}}, Commands: map[string]localCommandConfig{"mutate": {ReadOnly: false}}}
	err := executeAssignment(context.Background(), cfg, a, "https://coordinator.invalid", "token", http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "cannot use mutating") {
		t.Fatalf("expected mutating capability rejection, got %v", err)
	}
}

func TestEvidenceBudgetStopsBeforeFurtherToolsAndMarksTruncation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := &nodeEvidence{stop: cancel}
	input := json.RawMessage(`{"x":1}`)
	e.add("probe", input, strings.Repeat("x", 70<<10), false, false)
	rows := e.list()
	if len(rows) != 1 || !rows[0].Truncated || rows[0].Input == nil || rows[0].SHA256 != collab.ContentHash([]byte(rows[0].Content)) {
		t.Fatalf("bad truncated evidence: %#v", rows)
	}
	if err := e.canStart(input); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 9; i++ {
		e.add(fmt.Sprintf("tool%d", i), input, strings.Repeat("y", 64<<10), false, false)
	}
	if err := e.canStart(input); err == nil {
		t.Fatal("expected exhausted evidence budget")
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("budget exhaustion did not cancel agent")
	}
}

func TestNodeProcessLockAndBinaryOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker.lock")
	first, err := acquireNodeLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = acquireNodeLock(path); err == nil {
		t.Fatal("expected same-process second lock to fail")
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := acquireNodeLock(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = second.Close()
	got, truncated := formatDeviceOutput([]byte{0, 0xff, 0x7f})
	if truncated || !strings.HasPrefix(got, "encoding=base64\n") {
		t.Fatalf("binary output was not represented safely: %q", got)
	}
}

func TestEmptyCommandEnvAllowlistDoesNotInheritModelKey(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_TEST_KEY", "local-model-secret")
	evidence := &nodeEvidence{}
	result, err := runLocalCommand(t.Context(), "probe", localCommandConfig{Command: exe, FixedArgs: []string{"-test.run=TestNodeCommandHelper"}, Schema: map[string]any{"type": "object"}, EnvAllowlist: nil}, json.RawMessage(`{"x":1}`), t.TempDir(), evidence)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result.Flatten(), "local-model-secret") {
		t.Fatal("model credential inherited by command")
	}
}
