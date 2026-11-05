package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/collab"
)

// The subprocess is a local fixture, not Frida and not a target program.
func TestNodeRuntimeBridgeHelper(t *testing.T) {
	if os.Getenv("ARTEX_RUNTIME_BRIDGE_HELPER") != "1" {
		return
	}
	var req runtimeObservationRequest
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		os.Exit(31)
	}
	cancelled := false
	if hold, _ := req.Profile["hold"].(bool); hold {
		s := bufio.NewScanner(os.Stdin)
		if s.Scan() {
			var control map[string]bool
			_ = json.Unmarshal(s.Bytes(), &control)
			cancelled = control["cancel"]
		}
	}
	scriptHash := sha256.Sum256([]byte(req.Script))
	cleanup := map[string]bool{"script_unloaded": true, "session_detached": true, "owned_process_terminated": true, "staging_removed": true}
	if req.Profile["platform"] == "android" {
		cleanup["package_removed"] = true
	}
	response := map[string]any{"platform": req.Profile["platform"], "artifact_sha256": req.SHA256, "script_sha256": hex.EncodeToString(scriptHash[:]), "cleanup": cleanup, "errors": []string{}, "cancelled": cancelled, "environment_secret": os.Getenv("ARTEX_TEST_MODEL_KEY")}
	_ = json.NewEncoder(os.Stdout).Encode(response)
	os.Exit(0)
}

func fakeLocalRuntime(t *testing.T, platform string, settings map[string]any) localRuntimeProfile {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return localRuntimeProfile{Name: "fixture " + platform, Platform: platform, Command: exe, Args: []string{"-test.run=TestNodeRuntimeBridgeHelper"}, Settings: settings, EnvAllowlist: []string{"ARTEX_RUNTIME_BRIDGE_HELPER"}, MaxDurationMS: 1500}
}

func TestRuntimeProfileDigestAndBindingAreDeviceSpecific(t *testing.T) {
	p := fakeLocalRuntime(t, "linux", map[string]any{"lab": "one"})
	cfg := localExecutionConfig{RuntimeProfiles: map[string]localRuntimeProfile{"linux-lab": p}, Roles: map[string]localRoleConfig{"reverse_dynamic": {RuntimeProfiles: []string{"linux-lab"}}}}
	advertised, err := cfg.runtimeProfile("linux-lab")
	if err != nil {
		t.Fatal(err)
	}
	changed := p
	changed.Settings = map[string]any{"lab": "two"}
	cfg.RuntimeProfiles["linux-lab"] = changed
	changedAdvertised, err := cfg.runtimeProfile("linux-lab")
	if err != nil {
		t.Fatal(err)
	}
	if advertised.Digest == changedAdvertised.Digest {
		t.Fatal("profile digest did not bind local settings")
	}
	sha := strings.Repeat("a", 64)
	bind := collab.RuntimeBinding{RuntimeProfile: advertised, ArtifactHashes: []string{sha}}
	config := collab.ExecutionConfig{Role: "reverse_dynamic", DynamicAllowed: true, Runtime: &bind}
	if _, err = cfg.matchRuntimeBinding(config, []collab.Material{{SHA256: sha}}); err == nil {
		t.Fatal("accepted a changed local profile digest")
	}
	cfg.RuntimeProfiles["linux-lab"] = p
	if _, err = cfg.matchRuntimeBinding(config, []collab.Material{{SHA256: strings.Repeat("b", 64)}}); err == nil {
		t.Fatal("accepted a bound hash outside the assignment")
	}
	if _, err = cfg.matchRuntimeBinding(config, []collab.Material{{SHA256: sha}}); err != nil {
		t.Fatalf("valid profile binding rejected: %v", err)
	}
}

func TestDynamicLocalRoleRejectsMutatingOrdinaryCommands(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p := fakeLocalRuntime(t, "linux", nil)
	cfg := localExecutionConfig{
		Models:          map[string]localModelConfig{"m": {Endpoint: "http://127.0.0.1", APIKeyEnv: "TEST_KEY", Model: "m", Format: "openai"}},
		Roles:           map[string]localRoleConfig{"reverse_dynamic": {Model: "m", Capabilities: []string{"mutate"}, RuntimeProfiles: []string{"lab"}}},
		Commands:        map[string]localCommandConfig{"mutate": {Description: "test", Schema: map[string]any{"type": "object"}, Command: exe}},
		RuntimeProfiles: map[string]localRuntimeProfile{"lab": p},
	}
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "must be read-only") {
		t.Fatalf("expected mutating capability rejection, got %v", err)
	}
}

func TestRuntimeEnvAllowlistCannotAliasModelKeyCase(t *testing.T) {
	p := fakeLocalRuntime(t, "linux", nil)
	p.EnvAllowlist = []string{"test_key"}
	cfg := localExecutionConfig{Models: map[string]localModelConfig{"m": {Endpoint: "http://127.0.0.1", APIKeyEnv: "TEST_KEY", Model: "m", Format: "openai"}}, Roles: map[string]localRoleConfig{"worker": {Model: "m"}}, RuntimeProfiles: map[string]localRuntimeProfile{"lab": p}}
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "configured model credential") {
		t.Fatalf("credential alias accepted: %v", err)
	}
}

func TestCapabilitiesAdvertiseOnlyAllowedRuntimeSummaries(t *testing.T) {
	allowed := fakeLocalRuntime(t, "linux", map[string]any{"private_setting": "visible-in-digest-only"})
	other := fakeLocalRuntime(t, "android", map[string]any{"private_setting": "not-advertised"})
	allowedPath, otherPath := allowed.Command, other.Command
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/collaboration/device/capabilities" {
			var body struct {
				Capabilities map[string]json.RawMessage `json:"capabilities"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
				return
			}
			var profiles []collab.RuntimeProfile
			var roleCaps map[string][]string
			if err := json.Unmarshal(body.Capabilities["role_capabilities"], &roleCaps); err != nil || len(roleCaps["reverse_dynamic"]) != 1 || roleCaps["reverse_dynamic"][0] != reverseRuntimeCapability {
				t.Errorf("dynamic role capabilities missing: %+v %v", roleCaps, err)
			}
			if err := json.Unmarshal(body.Capabilities["runtime_profiles"], &profiles); err != nil {
				t.Error(err)
				return
			}
			if len(profiles) != 1 || profiles[0].ID != "allowed" || profiles[0].Platform != "linux" || profiles[0].Digest == "" {
				t.Errorf("unexpected advertised profiles: %#v", profiles)
			}
			if strings.Contains(string(body.Capabilities["runtime_profiles"]), allowedPath) || strings.Contains(string(body.Capabilities["runtime_profiles"]), otherPath) {
				t.Error("local runner command leaked through capabilities")
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path == "/api/collaboration/device/assignments" {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	state := filepath.Join(t.TempDir(), "identity.json")
	raw, _ := json.Marshal(deviceState{CoordinatorURL: server.URL, Token: "node-token"})
	if err := os.WriteFile(state, raw, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := localExecutionConfig{WorkDir: filepath.Join(t.TempDir(), "work"), Models: map[string]localModelConfig{"m": {Endpoint: "http://127.0.0.1", APIKeyEnv: "TEST_KEY", Model: "m", Format: "openai"}}, Roles: map[string]localRoleConfig{"reverse_dynamic": {Model: "m", RuntimeProfiles: []string{"allowed"}}}, RuntimeProfiles: map[string]localRuntimeProfile{"allowed": allowed, "other": other}}
	if err := runAssignments(context.Background(), cfg, state, server.URL, server.Client(), io.Discard, true); err != nil {
		t.Fatal(err)
	}
}

func TestDynamicRuntimeFakeBridgeThreePlatformsAndDurableEvidence(t *testing.T) {
	for _, platform := range []string{"linux", "windows", "android"} {
		t.Run(platform, func(t *testing.T) {
			profile := fakeLocalRuntime(t, platform, map[string]any{"fixture": true})
			cfg := localExecutionConfig{RuntimeProfiles: map[string]localRuntimeProfile{"lab": profile}, Roles: map[string]localRoleConfig{"reverse_dynamic": {RuntimeProfiles: []string{"lab"}}}}
			advertised, err := cfg.runtimeProfile("lab")
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "sample.bin")
			artifact := []byte("non-executable fixture material")
			if err := os.WriteFile(file, artifact, 0600); err != nil {
				t.Fatal(err)
			}
			hash := collab.ContentHash(artifact)
			binding := collab.RuntimeBinding{RuntimeProfile: advertised, ArtifactHashes: []string{hash}}
			selected, err := cfg.matchRuntimeBinding(collab.ExecutionConfig{Role: "reverse_dynamic", DynamicAllowed: true, Runtime: &binding}, []collab.Material{{SHA256: hash}})
			if err != nil {
				t.Fatal(err)
			}
			journal := filepath.Join(t.TempDir(), "evidence.ndjson")
			evidence := &nodeEvidence{journal: journal}
			gateCount := 0
			tool := reverseObserveRuntimeTool(selected, binding, map[string]string{hash: file}, evidence, func(context.Context) error { gateCount++; return nil })
			input, _ := json.Marshal(map[string]any{"sha256": hash, "script": "send('fixture')", "argv": []string{"--fixture"}, "package_name": "org.example.fixture", "duration_ms": 300})
			_ = os.Setenv("ARTEX_RUNTIME_BRIDGE_HELPER", "1")
			defer os.Unsetenv("ARTEX_RUNTIME_BRIDGE_HELPER")
			_ = os.Setenv("ARTEX_TEST_MODEL_KEY", "must-not-leak")
			defer os.Unsetenv("ARTEX_TEST_MODEL_KEY")
			result, err := tool.Call(context.Background(), input, nil)
			if err != nil || result.IsError {
				t.Fatalf("fake bridge failed: %v %s", err, result.Flatten())
			}
			if gateCount != 2 {
				t.Fatalf("expected fresh heartbeat, got %d", gateCount)
			}
			rows, err := loadNodeEvidence(journal)
			if err != nil || len(rows) != 1 || rows[0].Tool != reverseRuntimeCapability || rows[0].IsError {
				t.Fatalf("runtime output was not durably journaled: %#v %v", rows, err)
			}
			if strings.Contains(rows[0].Content, "must-not-leak") {
				t.Fatal("model key reached runtime bridge")
			}
			badInput := []byte(fmt.Sprintf(`{"sha256":%q,"script":"x","duration_ms":100,"artifact_path":"/etc/passwd"}`, hash))
			bad, err := tool.Call(context.Background(), badInput, nil)
			if err != nil || !bad.IsError {
				t.Fatal("runtime tool accepted a remote path field")
			}
			if gateCount != 3 {
				t.Fatalf("invalid request unexpectedly passed fresh heartbeat gate: %d", gateCount)
			}
		})
	}
}

func TestRuntimeMaterialRechecksAuthorizationAndHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.bin")
	content := []byte("approved")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	hash := collab.ContentHash(content)
	binding := collab.RuntimeBinding{ArtifactHashes: []string{hash}}
	if _, err := runtimeMaterialAllowed(binding, map[string]string{hash: path}, strings.Repeat("f", 64)); err == nil {
		t.Fatal("accepted an unbound hash")
	}
	if _, err := runtimeMaterialAllowed(binding, map[string]string{hash: path}, hash); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := runtimeMaterialAllowed(binding, map[string]string{hash: path}, hash); err == nil {
		t.Fatal("accepted changed local material")
	}
}

func TestRuntimeBridgeCancellationIsBoundedAndReturnsCleanupEvidence(t *testing.T) {
	p := fakeLocalRuntime(t, "linux", map[string]any{"hold": true})
	_ = os.Setenv("ARTEX_RUNTIME_BRIDGE_HELPER", "1")
	defer os.Unsetenv("ARTEX_RUNTIME_BRIDGE_HELPER")
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	script := "send('cancel fixture')"
	h := sha256.Sum256([]byte(script))
	raw, err := invokeNodeRuntime(ctx, p, runtimeObservationRequest{ArtifactPath: "local-fixture", SHA256: strings.Repeat("a", 64), Script: script, DurationMS: 100})
	if err == nil {
		t.Fatal("expected bounded cancellation error")
	}
	if len(raw) == 0 || !strings.Contains(string(raw), hex.EncodeToString(h[:])) || !strings.Contains(string(raw), `"staging_removed":true`) {
		t.Fatalf("cleanup evidence missing after cancellation: %s", raw)
	}
}
