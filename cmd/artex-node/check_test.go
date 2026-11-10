package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNodeCheckTLSWithoutPairingOrExecution(t *testing.T) {
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/api/health" || r.Header.Get("Authorization") != "" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"service":"artex","version":"0.5.0"}`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(srv.URL)
	config := nodeConfig{CoordinatorURL: srv.URL, ServerName: "example.com", LANAddresses: []string{u.Host}, CAFile: ca}
	path := filepath.Join(dir, "node.json")
	state := filepath.Join(dir, "state.json")
	check := func() (string, error) {
		t.Helper()
		raw, _ := json.Marshal(config)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		err := run(context.Background(), []string{"-config", path, "-state", state, "check"}, nil, &out)
		return out.String(), err
	}
	out, err := check()
	if err != nil || !strings.Contains(out, "TLS verified; route: lan") {
		t.Fatalf("out=%s err=%v", out, err)
	}
	if _, err = os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("check wrote device identity")
	}
	config.CAFile = ""
	if _, err = check(); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
	config.CAFile = ca
	config.ServerName = "wrong.invalid"
	if _, err = check(); err == nil {
		t.Fatal("wrong coordinator hostname accepted")
	}
	config.ServerName = "example.com"
	config.Execution = &localExecutionConfig{Branches: localBranchConfig{Enabled: true}, Models: map[string]localModelConfig{"fixture": {Endpoint: "https://never-called.invalid", Model: "fixture", APIKeyEnv: "ARTEX_CHECK_TEST_SECRET", Format: "openai"}}, Roles: map[string]localRoleConfig{"worker": {Model: "fixture"}, "planner": {Model: "fixture"}, "reviewer": {Model: "fixture"}}}
	t.Setenv("ARTEX_CHECK_TEST_SECRET", "")
	if _, err = check(); err == nil || !strings.Contains(err.Error(), "credential") {
		t.Fatalf("missing credential err=%v", err)
	}
	t.Setenv("ARTEX_CHECK_TEST_SECRET", "fixture-secret-never-print")
	out, err = check()
	if err != nil || strings.Contains(out, "fixture-secret-never-print") || !strings.Contains(out, "Models and tools were not invoked") {
		t.Fatalf("out=%s err=%v", out, err)
	}
	if calls != 2 {
		t.Fatalf("only successful checks reach health, calls=%d", calls)
	}
	delete(config.Execution.Roles, "planner")
	if _, err = check(); err == nil || !strings.Contains(err.Error(), "planner") {
		t.Fatalf("missing planner err=%v", err)
	}
}

func TestNodeVersionDoesNotNeedConfig(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"-config", filepath.Join(t.TempDir(), "missing"), "-version"}, nil, &out); err != nil || !strings.Contains(out.String(), "branch protocol 1") {
		t.Fatalf("%s %v", out.String(), err)
	}
}
