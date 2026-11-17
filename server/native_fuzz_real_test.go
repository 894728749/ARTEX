package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func fuzzDockerNames(t *testing.T) map[string]bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "ps", "-a", "--format", "{{.Names}}").Output()
	if err != nil {
		t.Fatalf("list docker containers: %v", err)
	}
	names := map[string]bool{}
	for _, name := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if name != "" {
			names[name] = true
		}
	}
	return names
}

func compileFuzzFixture(t *testing.T, image, source, binary string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	args := []string{"run", "--rm", "--pull=never", "--network=none", "--read-only",
		"--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"--pids-limit=128", "--memory=512m", "--cpus=1",
		"--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m,nr_inodes=2048",
		"--mount", "type=bind,src=" + source + ",dst=/input/fixture.c,readonly",
		"--mount", "type=bind,src=" + filepath.Dir(binary) + ",dst=/output",
		"--entrypoint", "/usr/bin/afl-clang-fast", image,
		"-O0", "-g", "-fno-pie", "-no-pie", "/input/fixture.c",
		"-o", "/output/" + filepath.Base(binary)}
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("synthetic fixture compile: %v %s", err, out)
	}
	if stat, err := os.Stat(binary); err != nil || !stat.Mode().IsRegular() {
		t.Fatalf("fixture binary missing: %v", err)
	}
}

// Opt-in real container test. It uses only the synthetic fuzz fixture and an
// explicitly selected local immutable image.
func TestNativeFuzzRealContainerClosedLoop(t *testing.T) {
	if os.Getenv("ARTEX_FUZZ_REAL_DOCKER") != "1" {
		t.Skip("set ARTEX_FUZZ_REAL_DOCKER=1 for the real container chain")
	}
	imageTag := strings.TrimSpace(os.Getenv("ARTEX_FUZZ_REAL_IMAGE"))
	if imageTag == "" {
		t.Skip("set ARTEX_FUZZ_REAL_IMAGE to the local signed AFL++ image")
	}
	dsn := requireFuzzTestDB(t)
	inspectCtx, inspectCancel := context.WithTimeout(t.Context(), 20*time.Second)
	rawID, err := exec.CommandContext(inspectCtx, "docker", "image", "inspect", "--format", "{{.Id}}", imageTag).Output()
	inspectCancel()
	if err != nil {
		t.Fatalf("inspect local image: %v", err)
	}
	image := strings.TrimSpace(string(rawID))
	if !db.NativeImageDigest(image) {
		t.Fatalf("local image ID is not immutable: %q", image)
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
	task, err := pg.CreateTaskWithOptions("synthetic real fuzz loop", "owned C fixture only", db.TaskCreateOptions{Kind: "reverse"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(task.ID) })
	dir := t.TempDir()
	relative := filepath.Join("tasks", fmt.Sprint(task.ID), "reverse", "artifacts", "fuzz_fixture.elf")
	binary := filepath.Join(dir, relative)
	if err = os.MkdirAll(filepath.Dir(binary), 0700); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	compileFuzzFixture(t, image, filepath.Join(root, "testdata", "reverse", "native", "fuzz_fixture.c"), binary)
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	artifact, err := pg.AddReverseArtifact(task.ID, db.ReverseArtifact{Name: "fuzz_fixture.elf", Format: "elf", Path: relative, SizeBytes: int64(len(data)), SHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	var intent int64
	if err = pg.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,state,payload) VALUES($1,'intent','running','{}') RETURNING id`, task.ExplorationID).Scan(&intent); err != nil {
		t.Fatal(err)
	}
	profile := reverseRuntimeProfile{ID: "real-fuzz", Platform: "linux", Engine: "docker-native",
		Command: python, Args: []string{filepath.Join(root, "scripts", "native_runtime.py")},
		Settings: map[string]any{"image": image, "fuzz_enabled": true, "enabled": true,
			"platform": "linux", "network": "none", "read_only_root": true,
			"max_duration_ms": 60000}}
	profiles, _ := json.Marshal([]reverseRuntimeProfile{profile})
	profilePath := filepath.Join(dir, "profiles.json")
	if err = os.WriteFile(profilePath, profiles, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_REVERSE_RUNTIME_PROFILES", profilePath)
	if err = pg.SetReverseRuntimePolicy(t.Context(), task.ID, db.ReverseRuntimePolicy{
		Enabled: true, ProfileIDs: []string{profile.ID},
		ArtifactIDs: []int64{artifact.ID}, MaxDurationMS: 60000}); err != nil {
		t.Fatal(err)
	}
	before := fuzzDockerNames(t)
	seed := []byte("ZX")
	seedSum := sha256.Sum256(seed)
	request := nativeFuzzRequest{Action: "run", ArtifactID: artifact.ID, ProfileID: profile.ID,
		InputMode: "stdin", Duration: 10000, MaxExecutions: 2000, MaxCrashes: 2,
		Seeds: []nativeFuzzInput{{SHA256: hex.EncodeToString(seedSum[:]),
			DataBase64: "Wlg="}}}
	result, err := nativeFuzzRun(t.Context(), pg, task, agent.RunInfo{TaskID: task.ID, IntentID: intent}, dir, request)
	if err != nil {
		t.Fatalf("real fuzz campaign: %v %#v", err, result)
	}
	observation := result["observation"].(map[string]any)
	if observation["target_state"] != "completed" || observation["cleanup_verified"] != true {
		t.Fatalf("real fuzz observation: %#v", observation)
	}
	crashes, _ := observation["crashes"].([]any)
	if len(crashes) == 0 {
		t.Fatalf("real fuzz campaign produced no crash candidate: %#v", observation)
	}
	candidate := crashes[0].(map[string]any)["sha256"].(string)
	runID := result["run_id"].(int64)
	after := fuzzDockerNames(t)
	for name := range after {
		if strings.HasPrefix(name, "artex-afl-") && !before[name] {
			t.Fatalf("owned fuzz container was not removed: %s", name)
		}
	}
	signal := 6
	replayed, err := nativeFuzzCandidate(t.Context(), pg, task, agent.RunInfo{TaskID: task.ID, IntentID: intent}, dir,
		nativeFuzzRequest{Action: "replay_candidate", RunID: runID, CandidateSHA256: candidate,
			ExpectedSignal: &signal, Duration: 10000})
	if err != nil {
		t.Fatalf("real candidate replay: %v %#v", err, replayed)
	}
	replay := replayed["replay"].(map[string]any)
	if replay["observation"].(map[string]any)["matches_expectation"] != true {
		t.Fatalf("real replay did not match: %#v", replay)
	}
	runs, err := pg.NativeRuns(task.ID)
	if err != nil || len(runs) != 2 {
		t.Fatalf("real fuzz ledger: %+v %v", runs, err)
	}
	var modes []string
	for _, run := range runs {
		modes = append(modes, run.Mode)
	}
	if !strings.Contains(strings.Join(modes, ","), "fuzz") || !strings.Contains(strings.Join(modes, ","), "replay") {
		t.Fatalf("real ledger modes: %v", modes)
	}
	for _, run := range runs {
		raw, err := os.ReadFile(filepath.Join(dir, run.ResultPath))
		if err != nil {
			t.Fatalf("real evidence %d missing: %v", run.RunID, err)
		}
		var document struct {
			StructuredContent struct {
				Authority string `json:"authority"`
			} `json:"structuredContent"`
		}
		if json.Unmarshal(raw, &document) != nil || document.StructuredContent.Authority == "" {
			t.Fatalf("real evidence %d has no authority", run.RunID)
		}
		if run.Mode == "fuzz" && document.StructuredContent.Authority != "candidate-only" {
			t.Fatalf("fuzz evidence authority=%q", document.StructuredContent.Authority)
		}
		if run.Mode == "replay" && document.StructuredContent.Authority != "controlled-replay" {
			t.Fatalf("replay evidence authority=%q", document.StructuredContent.Authority)
		}
	}
}
