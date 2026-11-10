package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/teamsetup"
)

type setupTestServer struct {
	server     *httptest.Server
	join       string
	dir        string
	configPath string
	statePath  string
	pairs      atomic.Int32
	badPair    atomic.Bool
	cancel     context.CancelFunc
	caps       atomic.Int32
}

func newSetupTestServer(t *testing.T) *setupTestServer {
	t.Helper()
	f := &setupTestServer{}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/health":
			_, _ = fmt.Fprint(w, `{"ok":true,"service":"artex","version":"dev"}`)
		case "/api/collaboration/pair":
			f.pairs.Add(1)
			var in map[string]any
			_ = json.NewDecoder(r.Body).Decode(&in)
			if f.badPair.Load() {
				http.Error(w, "pairing rejected", 403)
				return
			}
			if in["pairing_token"] != "fixture-code" {
				http.Error(w, "bad code", 403)
				return
			}
			_, _ = fmt.Fprint(w, `{"device":{"id":8,"team_id":1,"name":"fixture"},"device_token":"private-token"}`)
		case "/api/collaboration/device":
			if r.Header.Get("Authorization") != "Bearer private-token" && r.Header.Get("Authorization") != "Bearer existing-token" {
				http.Error(w, "unauthorized", 401)
				return
			}
			_, _ = fmt.Fprint(w, `{"device":{"id":8,"team_id":1,"name":"fixture"},"protocol_version":1,"remote_execution_available":false}`)
		case "/api/collaboration/device/capabilities":
			f.caps.Add(1)
			if f.cancel != nil {
				f.cancel()
			}
			w.WriteHeader(204)
		case "/api/collaboration/device/assignments":
			_, _ = fmt.Fprint(w, `{"assignments":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)
	f.dir = t.TempDir()
	f.configPath = filepath.Join(f.dir, "node.json")
	f.statePath = filepath.Join(f.dir, "state", "identity.json")
	ca := filepath.Join(f.dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(f.server.URL)
	sum := sha256.Sum256(f.server.Certificate().Raw)
	j := teamsetup.JoinConfig{Schema: 1, TeamID: 1, Version: "dev", CoordinatorURL: f.server.URL, ServerName: u.Hostname(), CAFile: "ca.pem", CertificateSHA256: hex.EncodeToString(sum[:]), LANAddresses: []string{u.Host}, RelayURL: "wss://relay.example", RelayRoom: "room", RelayPeer: "peer", RelaySecretEnv: "ARTEX_RELAY_SECRET"}
	b, _ := json.Marshal(j)
	f.join = filepath.Join(f.dir, "join.json")
	if err := os.WriteFile(f.join, b, 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func runSetupFixture(f *setupTestServer, t *testing.T, input string, cancel context.CancelFunc) (error, string, string, string) {
	t.Helper()
	ctx := context.Background()
	if cancel != nil {
		ctx, cancel = context.WithCancel(ctx)
		f.cancel = cancel
	}
	cfg := f.configPath
	state := f.statePath
	var out strings.Builder
	err := run(ctx, []string{"-join", f.join, "-config", cfg, "-state", state, "setup"}, strings.NewReader(input), &out)
	return err, out.String(), cfg, state
}

func TestSetupConnectionOnlyAndRepeatSameIdentity(t *testing.T) {
	f := newSetupTestServer(t)
	err, out, cfg, state := runSetupFixture(f, t, "yes\n1\nfixture-code\n", nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.pairs.Load() != 1 || !strings.Contains(out, "device 8") || !strings.Contains(out, "no execution roles") {
		t.Fatalf("unexpected setup result: %s", out)
	}
	b, _ := os.ReadFile(cfg)
	if strings.Contains(string(b), "fixture-code") || strings.Contains(string(b), "private-token") {
		t.Fatal("pair secret persisted in config")
	}
	raw, _ := os.ReadFile(state)
	var ds deviceState
	_ = json.Unmarshal(raw, &ds)
	if ds.TeamID != 1 || ds.Token != "private-token" {
		t.Fatalf("identity not saved: %+v", ds)
	}
	err, out, _, _ = runSetupFixture(f, t, "yes\n", nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.pairs.Load() != 1 || !strings.Contains(out, "device 8") {
		t.Fatalf("repeat setup did not reuse identity: %s", out)
	}
	// States written by the original pair command only have Device.team_id.
	ds.TeamID = 0
	legacy, _ := json.Marshal(ds)
	if err = os.WriteFile(state, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	err, _, _, _ = runSetupFixture(f, t, "yes\n", nil)
	if err != nil || f.pairs.Load() != 1 {
		t.Fatalf("legacy identity could not resume: %v", err)
	}
}

func TestSetupRejectsWrongTeamAndIdentityWithoutConfig(t *testing.T) {
	f := newSetupTestServer(t)
	cfg := f.configPath
	state := f.statePath
	c, _ := setupHTTPClient(teamsetup.JoinConfig{CAFile: "ca.pem"}, f.join)
	_ = c
	prior := nodeConfig{CoordinatorURL: f.server.URL, ServerName: "127.0.0.1", CAFile: filepath.Join(f.dir, "ca.pem")}
	b, _ := json.Marshal(prior)
	_ = os.WriteFile(cfg, b, 0600)
	d, _ := json.Marshal(deviceState{CoordinatorURL: f.server.URL, TeamID: 2, Token: "existing-token", Device: json.RawMessage(`{"id":8}`)})
	_ = os.WriteFile(state, d, 0600)
	err, _, _, _ := runSetupFixture(f, t, "yes\n", nil)
	if err == nil || f.pairs.Load() != 0 {
		t.Fatal("wrong-team identity was accepted")
	}
	_ = os.Remove(state)
	_ = os.Remove(cfg)
	_, _, cfg, state = runSetupFixture(f, t, "yes\n1\nfixture-code\n", nil)
	if err = os.Remove(cfg); err != nil {
		t.Fatal(err)
	}
	d, _ = json.Marshal(deviceState{CoordinatorURL: f.server.URL, TeamID: 1, Token: "existing-token", Device: json.RawMessage(`{"id":8}`)})
	_ = os.WriteFile(state, d, 0600)
	err, _, _, _ = runSetupFixture(f, t, "yes\n", nil)
	if err == nil || f.pairs.Load() != 1 {
		t.Fatal("identity without matching config should stop before pairing")
	}
}

func TestSetupLocalValidationPrecedesPairingAndRejectsUnsafeCredentialEnv(t *testing.T) {
	f := newSetupTestServer(t)
	input := "yes\n2\nmodel\nhttps://model.example/v1\nmodel-x\nbad-format\n"
	err, _, _, _ := runSetupFixture(f, t, input, nil)
	if err == nil || f.pairs.Load() != 0 {
		t.Fatal("invalid model config reached pairing")
	}
	if validSetupKeyEnv("PATH") || validSetupKeyEnv("HOME") || validSetupKeyEnv("LD_PRELOAD") || validSetupKeyEnv("HTTPS_PROXY") || !validSetupKeyEnv("ARTEX_NODE_MODEL_KEY") || !validSetupKeyEnv("ARTEX_NODE_LAB_API_KEY") {
		t.Fatal("credential env allowlist is incorrect")
	}
}

func TestSetupPairFailureCanRetryWithoutRewritingConfig(t *testing.T) {
	f := newSetupTestServer(t)
	f.badPair.Store(true)
	err, _, cfg, _ := runSetupFixture(f, t, "yes\n1\nbad-code\n", nil)
	if err == nil || f.pairs.Load() != 1 {
		t.Fatal("expected first pairing to fail")
	}
	before, e := os.ReadFile(cfg)
	if e != nil {
		t.Fatal("config should survive recoverable pair failure")
	}
	f.badPair.Store(false)
	err, _, _, _ = runSetupFixture(f, t, "yes\nfixture-code\n", nil)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(cfg)
	if string(before) != string(after) || f.pairs.Load() != 2 {
		t.Fatal("retry rewrote config or failed to pair")
	}
}

func TestSetupRoleTemplatesNoSecretPersistenceAndRunDefaultNo(t *testing.T) {
	for _, kind := range []string{"pentest", "reverse"} {
		t.Run(kind, func(t *testing.T) {
			const env = "ARTEX_NODE_MODEL_KEY"
			old, had := os.LookupEnv(env)
			_ = os.Unsetenv(env)
			t.Cleanup(func() {
				if had {
					_ = os.Setenv(env, old)
				} else {
					_ = os.Unsetenv(env)
				}
			})
			f := newSetupTestServer(t)
			input := "yes\n2\nshared\nhttp://127.0.0.1:9090/v1\nlocal-model\nopenai\nARTEX_NODE_MODEL_KEY\nfixture-model-secret\n" + kind + "\nfixture-code\n\n"
			err, out, cfg, _ := runSetupFixture(f, t, input, nil)
			if err != nil {
				t.Fatal(err)
			}
			if f.pairs.Load() != 1 || f.caps.Load() != 0 || !strings.Contains(out, "Run was not started") {
				t.Fatalf("unexpected default run behavior: %s", out)
			}
			b, _ := os.ReadFile(cfg)
			if strings.Contains(string(b), "fixture-model-secret") {
				t.Fatal("model secret persisted")
			}
			var c nodeConfig
			_ = json.Unmarshal(b, &c)
			if c.Execution == nil || !c.Execution.Branches.Enabled || c.Execution.WorkDir == "" || c.Execution.OutboxDir == "" {
				t.Fatal("execution template incomplete")
			}
			want := []string{"planner", "worker", "reviewer"}
			if kind == "reverse" {
				want = []string{"reverse_planner", "reverse_static", "reverse_reviewer"}
			}
			if len(c.Execution.Roles) != len(want) {
				t.Fatalf("unexpected roles: %#v", c.Execution.Roles)
			}
			for _, role := range want {
				r, ok := c.Execution.Roles[role]
				if !ok || len(r.Capabilities) != 0 {
					t.Fatalf("missing tool-free role %s", role)
				}
			}
		})
	}
}

func TestSetupExplicitRunDispatchesCapabilities(t *testing.T) {
	f := newSetupTestServer(t)
	old, had := os.LookupEnv("ARTEX_NODE_MODEL_KEY")
	_ = os.Setenv("ARTEX_NODE_MODEL_KEY", "fixture-key")
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("ARTEX_NODE_MODEL_KEY", old)
		} else {
			_ = os.Unsetenv("ARTEX_NODE_MODEL_KEY")
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	defer cancel()
	// Existing matching local config avoids consuming a pairing code; execution uses a fixture worker role.
	cfg := nodeConfig{CoordinatorURL: f.server.URL, ServerName: "127.0.0.1", CAFile: filepath.Join(f.dir, "ca.pem"), Execution: &localExecutionConfig{Roles: map[string]localRoleConfig{"worker": {Model: "m", Capabilities: []string{}}}, Models: map[string]localModelConfig{"m": {Endpoint: "http://127.0.0.1:9090", APIKeyEnv: "ARTEX_NODE_MODEL_KEY", Model: "fixture", Format: "openai"}}, Commands: map[string]localCommandConfig{}, WorkDir: filepath.Join(f.dir, "work"), OutboxDir: filepath.Join(f.dir, "outbox")}}
	b, _ := json.Marshal(cfg)
	cfgpath := filepath.Join(f.dir, "node.json")
	_ = os.WriteFile(cfgpath, b, 0600)
	state := deviceState{CoordinatorURL: f.server.URL, TeamID: 1, Token: "existing-token", Device: json.RawMessage(`{"id":8}`)}
	sb, _ := json.Marshal(state)
	statepath := filepath.Join(f.dir, "identity.json")
	_ = os.WriteFile(statepath, sb, 0600)
	var out strings.Builder
	err := run(ctx, []string{"-join", f.join, "-config", cfgpath, "-state", statepath, "setup"}, strings.NewReader("yes\nyes\n"), &out)
	if err == nil || f.caps.Load() != 1 {
		t.Fatalf("explicit run did not enter runAssignments: caps=%d err=%v", f.caps.Load(), err)
	}
}

func TestSetupCAPathMustStayBesideJoin(t *testing.T) {
	f := newSetupTestServer(t)
	j, err := readJoinConfig(f.join)
	if err != nil {
		t.Fatal(err)
	}
	j.CAFile = "../ca.pem"
	b, _ := json.Marshal(j)
	_ = os.WriteFile(f.join, b, 0600)
	if _, err = setupHTTPClient(j, f.join); err == nil {
		t.Fatal("path traversal CA path accepted")
	}
}
