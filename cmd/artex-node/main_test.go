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
	"runtime"
	"strings"
	"testing"
)

func TestNodePairStatusRevocationAndPrivateIdentity(t *testing.T) {
	revoked := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/collaboration/pair" {
			var request map[string]any
			if json.NewDecoder(r.Body).Decode(&request) != nil || request["pairing_token"] != "one-time-code" {
				http.Error(w, "denied", 403)
				return
			}
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"device":{"id":4,"name":"node"},"device_token":"never-print-this-secret"}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer never-print-this-secret" || revoked {
			http.Error(w, "revoked", 401)
			return
		}
		_, _ = w.Write([]byte(`{"device":{"id":4,"name":"node"},"protocol_version":1,"remote_execution_available":false}`))
	}))
	defer server.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(server.URL)
	cfg := nodeConfig{CoordinatorURL: server.URL, CAFile: ca, ServerName: "example.com", LANAddresses: []string{u.Host}}
	data, _ := json.Marshal(cfg)
	config := filepath.Join(dir, "node.json")
	state := filepath.Join(dir, "identity.json")
	_ = os.WriteFile(config, data, 0600)
	args := []string{"-config", config, "-state", state, "-name", "node"}
	var out bytes.Buffer
	if err := run(context.Background(), append(args, "pair"), strings.NewReader("one-time-code\n"), &out); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), append(args, "status"), nil, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "never-print-this-secret") || strings.Contains(out.String(), "one-time-code") {
		t.Fatal("credential printed")
	}
	info, _ := os.Stat(state)
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("mode %v", info.Mode())
	}
	before, _ := os.ReadFile(state)
	if err := run(context.Background(), append(args, "pair"), strings.NewReader("new-code\n"), &out); err == nil {
		t.Fatal("replaced existing identity")
	}
	after, _ := os.ReadFile(state)
	if !bytes.Equal(before, after) {
		t.Fatal("identity changed")
	}
	revoked = true
	if err := run(context.Background(), append(args, "status"), nil, &out); err == nil {
		t.Fatal("revoked device accepted")
	}
}

func TestNodeRejectsPlaintextCoordinator(t *testing.T) {
	if _, _, err := clientFor(nodeConfig{CoordinatorURL: "http://127.0.0.1:8787"}); err == nil {
		t.Fatal("plaintext device token transport allowed")
	}
}
