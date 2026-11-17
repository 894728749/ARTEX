package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/jackc/pgx/v5"
)

// Opt-in, synthetic fixture only. A caller must supply both the explicitly
// isolated PostgreSQL DSN and an immutable local image. No downloads or installs.
func TestNativeRealPythonDockerChain(t *testing.T) {
	image := os.Getenv("ARTEX_NATIVE_CHAIN_IMAGE")
	if image == "" {
		t.Skip("real native chain requires an explicit immutable local image")
	}
	dsn := os.Getenv("ARTEX_PG_DSN")
	if err := validateNativeChainTestDB(dsn, os.Getenv("ARTEX_NATIVE_CHAIN_ALLOW_TEST_DB")); err != nil {
		t.Fatal(err)
	}
	// Resolve local tags to immutable IDs without pulling.
	resolve := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", image)
	resolved, err := resolve.CombinedOutput()
	if err != nil {
		t.Fatalf("inspect local image: %v %s", err, resolved)
	}
	selected := image
	image = strings.TrimSpace(string(resolved))
	if !db.NativeImageDigest(image) {
		t.Fatalf("invalid local image ID: %q", image)
	}
	t.Logf("selected image=%s resolved=%s", selected, image)
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	task, err := pg.CreateTaskWithOptions("synthetic real native chain", "owned C fixture only", db.TaskCreateOptions{Kind: "reverse"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pg.DeleteTask(task.ID); err != nil {
			t.Errorf("cleanup task: %v", err)
		}
	})
	dir := t.TempDir()
	relative := filepath.Join("tasks", fmt.Sprint(task.ID), "reverse", "artifacts", "fixture.elf")
	binary := filepath.Join(dir, relative)
	if err := os.MkdirAll(filepath.Dir(binary), 0700); err != nil {
		t.Fatal(err)
	}
	compileNativeChainFixture(t, image, filepath.Join(root, "testdata", "reverse", "native", "integration_fixture.c"), binary)

	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	a, err := pg.AddReverseArtifact(task.ID, db.ReverseArtifact{Name: "fixture.elf", Format: "elf", Path: relative, SizeBytes: int64(len(data)), SHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	var intent int64
	if err := pg.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,state,payload) VALUES($1,'intent','running','{}') RETURNING id`, task.ExplorationID).Scan(&intent); err != nil {
		t.Fatal(err)
	}
	profile := reverseRuntimeProfile{ID: "real-native-chain", Platform: "linux", Engine: "docker-native", Command: python, Args: []string{filepath.Join(root, "scripts", "native_runtime.py")}, Settings: map[string]any{"image": image, "seccomp_profile": "deploy/native-lab/seccomp-debug.json", "enabled": true}}
	profiles, err := json.Marshal([]reverseRuntimeProfile{profile})
	if err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(dir, "profiles.json")
	if err := os.WriteFile(profilePath, profiles, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_REVERSE_RUNTIME_PROFILES", profilePath)
	if err := pg.SetReverseRuntimePolicy(t.Context(), task.ID, db.ReverseRuntimePolicy{Enabled: true, ProfileIDs: []string{profile.ID}, ArtifactIDs: []int64{a.ID}, MaxDurationMS: 30000}); err != nil {
		t.Fatal(err)
	}
	doctor, err := nativeDoctor(t.Context(), profile)
	if err != nil || doctor["available"] != true {
		t.Fatalf("real doctor: %v %#v", err, doctor)
	}
	t.Logf("real image=%s artifact=%s doctor_available=true", image, digest)

	exitZero, signal11 := 0, 11
	for _, tc := range []struct {
		name                         string
		argv                         []string
		expectedExit, expectedSignal *int
		state                        string
		payload                      []byte
	}{
		{"replay_echo", nil, &exitZero, nil, "exit", []byte{0, 255, 'A'}},
		{"replay_signal", []string{"segv"}, nil, &signal11, "crashed", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := pg.CreateNativeCase(t.Context(), db.NativeCase{TaskID: task.ID, ArtifactID: a.ID, IntentID: intent, ProfileID: profile.ID, Title: tc.name, Argv: tc.argv, InputBase64: base64.StdEncoding.EncodeToString(tc.payload), ExpectedExit: tc.expectedExit, ExpectedSignal: tc.expectedSignal})
			if err != nil {
				t.Fatal(err)
			}
			result, err := nativeReplay(t.Context(), pg, task, agent.RunInfo{IntentID: intent}, dir, c, 10000)
			if err != nil {
				t.Fatalf("real replay: %v %#v", err, result)
			}
			obs := result["observation"].(map[string]any)
			if obs["matches_expectation"] != true || obs["target_state"] != tc.state {
				t.Fatalf("replay mismatch: %#v", obs)
			}
			if tc.payload != nil && obs["output_base64"] != base64.StdEncoding.EncodeToString(tc.payload) {
				t.Fatalf("echo mismatch: %#v", obs)
			}
			if _, err := os.Stat(filepath.Join(dir, result["result_path"].(string))); err != nil {
				t.Fatalf("evidence missing: %v", err)
			}
		})
	}
	m := &nativeSessionManager{ctx: t.Context(), pg: pg, task: task, info: agent.RunInfo{TaskID: task.ID, IntentID: intent}, dir: dir, sessions: map[string]*nativeSession{}}
	t.Cleanup(m.close)
	request := func(t *testing.T, s *nativeSession, id string, frame map[string]any) map[string]any {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		out, err := s.request(ctx, id, frame)
		if err != nil {
			t.Fatalf("%s: %v %#v", id, err, out)
		}
		return out
	}
	t.Run("exec_session_eof", func(t *testing.T) {
		ready, err := m.start(t.Context(), a.ID, profile.ID, "exec", nil, 20000)
		if err != nil {
			for _, session := range m.sessions {
				t.Logf("failed startup frames=%#v last=%#v", session.frames, session.last)
			}
			t.Fatal(err)
		}
		s := m.sessions[ready["session_id"].(string)]
		defer s.stop()
		payload := base64.StdEncoding.EncodeToString([]byte{0, 255, 'B'})
		request(t, s, "send", map[string]any{"action": "send", "data_base64": payload})
		recv := request(t, s, "recv", map[string]any{"action": "recv", "max_bytes": 3, "timeout_ms": 3000})
		if recv["data_base64"] != payload {
			t.Fatalf("session echo mismatch: %#v", recv)
		}
		request(t, s, "eof", map[string]any{"action": "close_stdin"})
		select {
		case <-s.done:
		case <-time.After(12 * time.Second):
			t.Fatal("natural EOF did not finish")
		}
		if s.fail != "" {
			t.Fatalf("session failure=%s last=%#v frames=%#v", s.fail, s.last, s.frames)
		}
		obs := s.last["observation"].(map[string]any)
		if obs["target_state"] != "exit" {
			t.Fatalf("EOF state: %#v", obs)
		}
	})
	t.Run("debug_signal_registers_stack", func(t *testing.T) {
		ready, err := m.start(t.Context(), a.ID, profile.ID, "debug", []string{"segv"}, 30000)
		if err != nil {
			t.Fatal(err)
		}
		s := m.sessions[ready["session_id"].(string)]
		defer s.stop()
		run := request(t, s, "run", map[string]any{"action": "debug", "timeout_ms": 6000, "command": map[string]any{"action": "run"}})
		if run["target_state"] != "stopped" {
			t.Fatalf("expected signal stop: %#v", run)
		}
		regs := request(t, s, "registers", map[string]any{"action": "debug", "timeout_ms": 4000, "command": map[string]any{"action": "registers"}})
		if values, ok := regs["registers"].(map[string]any); !ok || len(values) == 0 {
			t.Fatalf("missing real registers: %#v", regs)
		}
		stack := request(t, s, "stack", map[string]any{"action": "debug", "timeout_ms": 4000, "command": map[string]any{"action": "stack", "count": 8}})
		if frames, ok := stack["stack"].([]any); !ok || len(frames) == 0 {
			t.Fatalf("missing real stack: %#v", stack)
		}
		s.stop()
		if s.fail != "" {
			t.Fatalf("session failure=%s last=%#v frames=%#v", s.fail, s.last, s.frames)
		}
		obs := s.last["observation"].(map[string]any)
		if obs["target_state"] != "crashed" || obs["signal"] != "SIGSEGV" {
			t.Fatalf("debug final: %#v", obs)
		}
	})
	runs, err := pg.NativeRuns(task.ID)
	if err != nil || len(runs) != 4 {
		t.Fatalf("persisted native runs=%d err=%v", len(runs), err)
	}
	for _, run := range runs {
		if run.ResultPath == "" {
			t.Fatalf("run %d has no persisted evidence", run.RunID)
		}
		evidencePath := filepath.Join(dir, run.ResultPath)
		relativePath, err := filepath.Rel(dir, evidencePath)
		if err != nil || relativePath == ".." || strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) {
			t.Fatalf("run %d evidence escapes test directory", run.RunID)
		}
		evidence, err := os.ReadFile(evidencePath)
		if err != nil {
			t.Fatalf("run %d evidence missing: %v", run.RunID, err)
		}
		var document map[string]any
		if err := json.Unmarshal(evidence, &document); err != nil || len(document) == 0 {
			t.Fatalf("run %d evidence is not a nonempty JSON object: %v", run.RunID, err)
		}
	}
}

// compileNativeChainFixture avoids host glibc contamination when the selected
// image supplies a compiler. Host fallback is only for the compiler-free local
// acceptance image and is explicit in the evidence log.
func compileNativeChainFixture(t *testing.T, image, source, binary string) {
	t.Helper()
	run := func(args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
		defer cancel()
		return exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	}
	limits := []string{"run", "--rm", "--pull=never", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=64", "--memory=512m", "--cpus=1", "--tmpfs=/tmp:rw,nosuid,nodev,size=64m"}
	probe := append(append([]string{}, limits...), "--entrypoint=/bin/sh", image, "-c", "if command -v gcc >/dev/null 2>&1; then exit 0; else exit 42; fi")
	out, err := run(probe...)
	if err != nil {
		// The probe must distinguish an absent compiler from Docker/runtime errors.
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 42 || len(strings.TrimSpace(string(out))) != 0 {
			t.Fatalf("compiler probe failed: %v %s", err, out)
		}
		if os.Getenv("ARTEX_NATIVE_CHAIN_ALLOW_HOST_GCC") != "1" {
			t.Fatal("selected image has no gcc; host fallback disabled (explicit ARTEX_NATIVE_CHAIN_ALLOW_HOST_GCC=1 required; caller must verify libc compatibility)")
		}
		t.Logf("fixture compiler=host gcc fallback (selected image has no gcc): %s", image)
		ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
		defer cancel()
		out, err = exec.CommandContext(ctx, "gcc", "-O0", "-g", "-fno-pie", "-no-pie", source, "-o", binary).CombinedOutput()
	} else {
		t.Logf("fixture compiler=selected image gcc: %s", image)
		args := append(append([]string{}, limits...), "--mount", "type=bind,src="+source+",dst=/input/fixture.c,readonly", "--mount", "type=bind,src="+filepath.Dir(binary)+",dst=/output", "--entrypoint=gcc", image, "-O0", "-g", "-fno-pie", "-no-pie", "/input/fixture.c", "-o", "/output/"+filepath.Base(binary))
		out, err = run(args...)
	}
	if err != nil {
		t.Fatalf("synthetic fixture build: %v %s", err, out)
	}
}

// This is a guardrail, not proof of isolation. The caller must create a disposable
// cluster/database and must never point this test at business data.
func validateNativeChainTestDB(dsn, approval string) error {
	if approval != "1" {
		return fmt.Errorf("set ARTEX_NATIVE_CHAIN_ALLOW_TEST_DB=1 only for a disposable test database")
	}
	if strings.TrimSpace(dsn) == "" {
		return fmt.Errorf("explicit disposable test DSN required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("invalid test DSN")
	}
	if !regexp.MustCompile("^artex_[a-z0-9_]+_(test|review)$").MatchString(cfg.Database) {
		return fmt.Errorf("test database name must match artex_*_test or artex_*_review")
	}
	return nil
}

func TestNativeChainTestDBGuard(t *testing.T) {
	for _, tc := range []struct {
		name, dsn, approval string
		valid               bool
	}{
		{"no_optin", "dbname=artex_native_review", "", false},
		{"wrong_optin", "dbname=artex_native_review", "true", false},
		{"empty", "", "1", false},
		{"business", "dbname=artex", "1", false},
		{"misleading", "dbname=artex_native_review_prod", "1", false},
		{"url_business", "postgres://localhost/business", "1", false},
		{"valid_keyword", "host=/tmp/isolated dbname=artex_native_review", "1", true},
		{"valid_url", "postgres://localhost/artex_native_test", "1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateNativeChainTestDB(tc.dsn, tc.approval)
			if (err == nil) != tc.valid {
				t.Fatalf("guard valid=%v err=%v", tc.valid, err)
			}
		})
	}
}
