package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/jackc/pgx/v5"
)

func fuzzTestInput(s string) nativeFuzzInput {
	b := []byte(s)
	h := sha256.Sum256(b)
	return nativeFuzzInput{hex.EncodeToString(h[:]), base64.StdEncoding.EncodeToString(b)}
}

func fuzzTestRequest() nativeFuzzRequest {
	return nativeFuzzRequest{Action: "run", Duration: 1000, MaxExecutions: 100,
		MaxCrashes: 1, InputMode: "stdin", Seeds: []nativeFuzzInput{fuzzTestInput("ZX")}}
}

func TestNativeFuzzRequestBounds(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*nativeFuzzRequest)
	}{
		{"duration_low", func(r *nativeFuzzRequest) { r.Duration = 999 }},
		{"duration_high", func(r *nativeFuzzRequest) { r.Duration = 60001 }},
		{"exec_low", func(r *nativeFuzzRequest) { r.MaxExecutions = 99 }},
		{"exec_high", func(r *nativeFuzzRequest) { r.MaxExecutions = 1000001 }},
		{"crashes_low", func(r *nativeFuzzRequest) { r.MaxCrashes = 0 }},
		{"crashes_high", func(r *nativeFuzzRequest) { r.MaxCrashes = 9 }},
		{"empty_seeds", func(r *nativeFuzzRequest) { r.Seeds = nil }},
		{"seed_hash", func(r *nativeFuzzRequest) { r.Seeds[0].SHA256 = strings.Repeat("0", 64) }},
		{"seed_size", func(r *nativeFuzzRequest) { r.Seeds = []nativeFuzzInput{fuzzTestInput(strings.Repeat("A", 4097))} }},
		{"empty_seed", func(r *nativeFuzzRequest) { r.Seeds = []nativeFuzzInput{fuzzTestInput("")} }},
		{"noncanonical", func(r *nativeFuzzRequest) {
			r.Seeds[0].DataBase64 = r.Seeds[0].DataBase64 + "\n"
		}},
		{"seed_total", func(r *nativeFuzzRequest) {
			r.Seeds = make([]nativeFuzzInput, 17)
			for i := range r.Seeds {
				r.Seeds[i] = fuzzTestInput(strings.Repeat("A", 4096))
			}
		}},
		{"seed_count", func(r *nativeFuzzRequest) { r.Seeds = make([]nativeFuzzInput, 33) }},
		{"bad_mode", func(r *nativeFuzzRequest) { r.InputMode = "pipe" }},
		{"missing_mode", func(r *nativeFuzzRequest) { r.InputMode = "" }},
		{"file_missing", func(r *nativeFuzzRequest) { r.InputMode = "file" }},
		{"file_twice", func(r *nativeFuzzRequest) { r.InputMode = "file"; r.Argv = []string{"{input}", "{input}"} }},
		{"stdin_placeholder", func(r *nativeFuzzRequest) { r.Argv = []string{"{input}"} }},
		{"embedded_placeholder", func(r *nativeFuzzRequest) { r.Argv = []string{"--file={input}"} }},
		{"afl_placeholder", func(r *nativeFuzzRequest) { r.Argv = []string{"@@"} }},
		{"argv_nul", func(r *nativeFuzzRequest) { r.Argv = []string{"a\x00b"} }},
		{"argv_long", func(r *nativeFuzzRequest) { r.Argv = []string{strings.Repeat("A", 4097)} }},
		{"too_many_argv", func(r *nativeFuzzRequest) { r.Argv = make([]string, 65) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := fuzzTestRequest()
			tc.edit(&r)
			if validateFuzzRequest(&r) == nil {
				t.Fatal("accepted invalid request")
			}
		})
	}
	r := fuzzTestRequest()
	if err := validateFuzzRequest(&r); err != nil || r.Argv == nil {
		t.Fatalf("valid stdin: %v", err)
	}
	r.InputMode = "file"
	r.Argv = []string{"{input}"}
	if err := validateFuzzRequest(&r); err != nil {
		t.Fatal(err)
	}
}

func TestNativeFuzzActionFieldShape(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		ok   bool
	}{
		{"run_min", `{"action":"run"}`, true},
		{"run_extra", `{"action":"run","candidate_sha256":"x"}`, false},
		{"list_min", `{"action":"list"}`, true},
		{"list_extra", `{"action":"list","artifact_id":1}`, false},
		{"import_min", `{"action":"import_candidate"}`, true},
		{"import_duration", `{"action":"import_candidate","duration_ms":1000}`, false},
		{"replay_min", `{"action":"replay_candidate"}`, true},
		{"replay_duration", `{"action":"replay_candidate","duration_ms":1000}`, true},
		{"unknown_action", `{"action":"hack"}`, false},
		{"missing_action", `{}`, false},
		{"not_object", `[]`, false},
		{"unknown_field", `{"action":"list","target":"x"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateFuzzActionFields([]byte(tc.raw))
			if (err == nil) != tc.ok {
				t.Fatalf("ok=%v err=%v", tc.ok, err)
			}
		})
	}
}

func fuzzTestObservation() map[string]any {
	in := fuzzTestInput("candidate")
	seed := fuzzTestInput("ZX")
	raw, _ := json.Marshal(map[string]any{
		"engine":       "afl++",
		"target_state": "completed",
		"manifest": map[string]any{
			"engine": "afl++", "artifact_sha256": "hash", "image": "image",
			"input_mode": "stdin", "afl_version": "4.04c", "showmap_version": "4.04c",
			"options_verified": true, "probe_edges": 2, "probe_executions": 1,
			"output_disk_limit_bytes": 67108864, "single_worker": true,
		},
		"cleanup": map[string]any{"owned_process_terminated": true,
			"container_removed": true, "staging_removed": true},
		"cleanup_verified": true, "stats_trusted": false, "coverage_claimed": false,
		"candidate_status": "unverified_requires_replay",
		"truncated":        false, "limited": false, "reason": nil,
		"errors":  []string{},
		"stats":   map[string]any{"execs_done": 9},
		"corpus":  []nativeFuzzInput{seed},
		"crashes": []nativeFuzzInput{in},
	})
	var o map[string]any
	_ = json.Unmarshal(raw, &o)
	return o
}

func TestNativeFuzzEvidenceValidation(t *testing.T) {
	if err := fuzzObservation(fuzzTestObservation(), "hash", "image", 1); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"identity", func(o map[string]any) { o["manifest"].(map[string]any)["artifact_sha256"] = "wrong" }},
		{"image", func(o map[string]any) { o["manifest"].(map[string]any)["image"] = "wrong" }},
		{"cleanup", func(o map[string]any) { o["cleanup"].(map[string]any)["container_removed"] = false }},
		{"cleanup_verified", func(o map[string]any) { o["cleanup_verified"] = false }},
		{"errors", func(o map[string]any) { o["errors"] = []any{"oops"} }},
		{"state", func(o map[string]any) { o["target_state"] = "exit" }},
		{"failed", func(o map[string]any) { o["target_state"] = "failed" }},
		{"null_list", func(o map[string]any) { o["crashes"] = nil }},
		{"hash", func(o map[string]any) { o["crashes"].([]any)[0].(map[string]any)["sha256"] = "wrong" }},
		{"too_many", func(o map[string]any) {
			o["crashes"] = []nativeFuzzInput{fuzzTestInput("1"), fuzzTestInput("2")}
		}},
		{"unknown", func(o map[string]any) { o["trusted_coverage"] = "yes" }},
		{"manifest_unknown", func(o map[string]any) { o["manifest"].(map[string]any)["coverage"] = 99 }},
		{"no_options", func(o map[string]any) { o["manifest"].(map[string]any)["options_verified"] = false }},
		{"no_edges", func(o map[string]any) { o["manifest"].(map[string]any)["probe_edges"] = 0 }},
		{"probe_budget", func(o map[string]any) { o["manifest"].(map[string]any)["probe_executions"] = 2 }},
		{"disk_limit", func(o map[string]any) { o["manifest"].(map[string]any)["output_disk_limit_bytes"] = 1 << 30 }},
		{"stats_trusted", func(o map[string]any) { o["stats_trusted"] = true }},
		{"coverage_claim", func(o map[string]any) { o["coverage_claimed"] = true }},
		{"bad_stat", func(o map[string]any) { o["stats"].(map[string]any)["execs_done"] = -1 }},
		{"unknown_stat", func(o map[string]any) { o["stats"].(map[string]any)["coverage"] = 1 }},
		{"no_corpus", func(o map[string]any) { o["corpus"] = []nativeFuzzInput{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := fuzzTestObservation()
			tc.edit(o)
			if fuzzObservation(o, "hash", "image", 1) == nil {
				t.Fatal("accepted invalid evidence")
			}
		})
	}
}

func TestNativeFuzzProfileAndRoleBoundary(t *testing.T) {
	profile := reverseRuntimeProfile{ID: "fuzz", Platform: "linux", Engine: "docker-native",
		Settings: map[string]any{"image": "sha256:" + strings.Repeat("a", 64), "fuzz_enabled": true}}
	if _, err := validateFuzzProfile(profile); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*reverseRuntimeProfile){
		"disabled": func(p *reverseRuntimeProfile) { p.Settings["fuzz_enabled"] = false },
		"mutable":  func(p *reverseRuntimeProfile) { p.Settings["image"] = "image:latest" },
		"secret":   func(p *reverseRuntimeProfile) { p.Settings["secrets"] = []string{"x"} },
		"network":  func(p *reverseRuntimeProfile) { p.Settings["network"] = "bridge" },
		"platform": func(p *reverseRuntimeProfile) { p.Platform = "windows" },
	} {
		t.Run(name, func(t *testing.T) {
			p := profile
			p.Settings = map[string]any{}
			for k, v := range profile.Settings {
				p.Settings[k] = v
			}
			edit(&p)
			if _, err := validateFuzzProfile(p); err == nil {
				t.Fatal("accepted invalid fuzz profile")
			}
		})
	}
	if !permittedReverseRoleTool("reverse_dynamic", "native_fuzz") ||
		permittedReverseRoleTool("reverse_static", "native_fuzz") ||
		permittedReverseRoleTool("reverse_reviewer", "native_fuzz") ||
		permittedReverseRoleTool("reverse_dynamic", "native_unknown") {
		t.Fatal("native_fuzz role boundary failed")
	}
	for _, role := range []string{"reverse_static", "reverse_main", "reverse_reviewer"} {
		for _, tool := range nativeTools(nil, &db.Task{}, agent.RunInfo{}, t.TempDir(), role, &nativeSessionManager{}) {
			if tool.Name() == "native_fuzz" {
				t.Fatalf("native_fuzz exposed to %s", role)
			}
		}
	}
	found := false
	for _, tool := range nativeTools(nil, &db.Task{}, agent.RunInfo{}, t.TempDir(), "reverse_dynamic", &nativeSessionManager{}) {
		if tool.Name() == "native_fuzz" {
			found = true
		}
	}
	if !found {
		t.Fatal("native_fuzz missing from dynamic role")
	}
}

func TestNativeReverseRoleToolMatrix(t *testing.T) {
	roles := []string{"reverse_main", "reverse_goals", "reverse_planner",
		"reverse_static", "reverse_dynamic", "reverse_reviewer"}
	allowed := map[string][]string{
		"native_inspect":            {"reverse_static", "reverse_dynamic", "reverse_reviewer"},
		"native_fuzz":               {"reverse_dynamic"},
		"native_session":            {"reverse_dynamic", "reverse_reviewer"},
		"native_case":               {"reverse_dynamic", "reverse_reviewer"},
		"native_review":             {"reverse_reviewer"},
		"native_publish_finding":    {"reverse_reviewer"},
		"native_unknown":            {},
		"reverse_submit_conclusion": {"reverse_static", "reverse_dynamic"},
		"reverse_review_conclusion": {"reverse_reviewer"},
		"reverse_prepare_apk":       {"reverse_static", "reverse_dynamic"},
		"reverse_inspect_hermes":    {"reverse_static", "reverse_dynamic", "reverse_reviewer"},
		"reverse_read_derived":      {"reverse_static", "reverse_dynamic", "reverse_reviewer"},
		"reverse_workspace":         roles,
		"reverse_observe_runtime":   {"reverse_dynamic", "reverse_reviewer"},
		"reverse_runtime_session":   {"reverse_dynamic", "reverse_reviewer"},
		"reverse_browser_scenario":  {"reverse_dynamic", "reverse_reviewer"},
		"non_native_regular_tool":   roles,
	}
	for tool, want := range allowed {
		for _, role := range roles {
			expect := false
			for _, item := range want {
				if item == role {
					expect = true
					break
				}
			}
			if got := permittedReverseRoleTool(role, tool); got != expect {
				t.Errorf("permittedReverseRoleTool(%s, %s)=%v want %v", role, tool, got, expect)
			}
		}
	}
	// The concrete tool list must expose native_inspect to the original
	// static/dynamic/reviewer roles, while native_fuzz stays dynamic-only.
	for _, role := range []string{"reverse_static", "reverse_dynamic", "reverse_reviewer"} {
		found := false
		for _, tool := range nativeTools(nil, &db.Task{}, agent.RunInfo{}, t.TempDir(), role, &nativeSessionManager{}) {
			if tool.Name() == "native_inspect" {
				found = true
			}
			if tool.Name() == "native_fuzz" && role != "reverse_dynamic" {
				t.Fatalf("native_fuzz exposed to %s", role)
			}
		}
		if !found {
			t.Fatalf("native_inspect missing from %s", role)
		}
	}
	for _, role := range []string{"reverse_main", "reverse_goals", "reverse_planner"} {
		for _, tool := range nativeTools(nil, &db.Task{}, agent.RunInfo{}, t.TempDir(), role, &nativeSessionManager{}) {
			if tool.Name() == "native_fuzz" {
				t.Fatalf("%s exposed to %s", tool.Name(), role)
			}
		}
	}
}

func TestNativeSaveEvidenceAuthority(t *testing.T) {
	dir := t.TempDir()
	a := &db.ReverseArtifact{Name: "fixture.elf", SHA256: strings.Repeat("a", 64)}
	for _, tc := range []struct{ authority, operation string }{
		{"candidate-only", "native_fuzz"},
		{"controlled-replay", "native_replay"},
		{"static-inspection", "native_inspect"},
	} {
		path, err := nativeSaveEvidenceWithAuthority(dir, 7, a, tc.operation, tc.authority, map[string]any{"ok": true}, nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(dir, path))
		if err != nil {
			t.Fatal(err)
		}
		var document struct {
			StructuredContent struct {
				Authority string `json:"authority"`
				Operation string `json:"operation"`
			} `json:"structuredContent"`
		}
		if json.Unmarshal(raw, &document) != nil || document.StructuredContent.Authority != tc.authority || document.StructuredContent.Operation != tc.operation {
			t.Fatalf("evidence authority mismatch: %s", raw)
		}
	}
	if _, err := nativeSaveEvidenceWithAuthority(dir, 7, a, "native_fuzz", "controlled-replay", map[string]any{}, nil); err == nil {
		t.Fatal("mismatched fuzz authority accepted")
	}
}

func TestNativeEvidenceSizeContracts(t *testing.T) {
	dir := t.TempDir()
	a := &db.ReverseArtifact{Name: "fixture.elf", SHA256: strings.Repeat("a", 64)}
	// Legacy native sessions accept up to a 3 MiB stream. Evidence just above
	// the old 512 KiB fuzz cap must still be accepted and remain bounded.
	transcript := strings.Repeat("A", 2<<20)
	path, err := nativeSaveEvidence(dir, 11, a, "native_session",
		map[string]any{"target_state": "exit"}, transcript)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, path))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= 512<<10 || len(raw) >= 3<<20 {
		t.Fatalf("legacy session evidence size=%d is outside the expected range", len(raw))
	}
	if _, err = nativeSaveEvidence(dir, 11, a, "native_session",
		map[string]any{"target_state": "exit"}, strings.Repeat("A", 5<<20)); err == nil {
		t.Fatal("legacy session evidence accepted beyond the bounded envelope")
	}
	// Fuzz campaigns retain their own tighter cap instead of inheriting the
	// larger legacy session contract.
	if _, err = nativeSaveEvidenceWithAuthority(dir, 11, a, "native_fuzz", "candidate-only",
		map[string]any{"data": strings.Repeat("A", maxFuzzEvidenceFile)}, nil); err == nil {
		t.Fatal("fuzz evidence accepted beyond the fuzz-specific cap")
	}
}

func TestNativeFuzzCombinedEvidenceBoundary(t *testing.T) {
	request := nativeFuzzRequest{Action: "run", ArtifactID: 1, ProfileID: "fuzz",
		Duration: 1000, MaxExecutions: 100, MaxCrashes: 8, InputMode: "stdin"}
	request.Argv = make([]string, 40)
	for index := range request.Argv {
		request.Argv[index] = strings.Repeat("A", 3000)
	}
	request.Seeds = make([]nativeFuzzInput, 16)
	for index := range request.Seeds {
		request.Seeds[index] = fuzzTestInput(strings.Repeat(string(rune('a'+index)), 4096))
	}
	observation := fuzzTestObservation()
	corpus := make([]nativeFuzzInput, 16)
	for index := range corpus {
		corpus[index] = fuzzTestInput(strings.Repeat(string(rune('A'+index)), 4096))
	}
	observation["corpus"] = corpus
	crashes := make([]nativeFuzzInput, 8)
	for index := range crashes {
		crashes[index] = fuzzTestInput(strings.Repeat(string(rune('a'+index)), 4096))
	}
	observation["crashes"] = crashes
	observation["fuzz_request"] = request
	observation["profile_id"] = "fuzz"
	observation["artifact_sha256"] = "hash"
	observation["image"] = "image"
	observation["policy_revision"] = 1
	observation["candidate_only"] = true
	observation["authority"] = "candidate-only"
	observation["validated_campaign"] = false
	if err := fuzzObservation(observation, "hash", "image", 8); err != nil {
		t.Fatalf("large fixture is not a legal observation: %v", err)
	}
	raw, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= maxFuzzEvidence {
		t.Fatalf("combined request+observation=%d should exceed %d", len(raw), maxFuzzEvidence)
	}
	t.Logf("legal combined request+observation=%d > limit=%d", len(raw), maxFuzzEvidence)
	if _, err = encodeFuzzEvidence(observation); !errors.Is(err, errFuzzEvidenceLimit) {
		t.Fatalf("combined evidence was not rejected: %v", err)
	}
	compact := compactFuzzFailure(observation, errFuzzEvidenceLimit.Error())
	encoded, err := encodeFuzzEvidence(compact)
	if err != nil {
		t.Fatalf("compact failure is not bounded: %v", err)
	}
	if len(encoded) > maxFuzzEvidence || compact["validated_campaign"] != false {
		t.Fatalf("invalid compact failure: size=%d validated=%v", len(encoded), compact["validated_campaign"])
	}
	if _, ok := compact["fuzz_request"]; ok {
		t.Fatal("compact failure must not retain the oversized request")
	}
	// A normal, small request/observation pair stays within the same cap.
	small := fuzzTestObservation()
	small["fuzz_request"] = fuzzTestRequest()
	small["validated_campaign"] = true
	if _, err = encodeFuzzEvidence(small); err != nil {
		t.Fatalf("small evidence rejected: %v", err)
	}
}

func TestNativeFuzzProtocolHelper(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-1] != "fuzz-protocol-helper" {
		return
	}
	var req map[string]any
	if json.NewDecoder(os.Stdin).Decode(&req) != nil {
		os.Exit(2)
	}
	profile := req["profile"].(map[string]any)
	o := fuzzTestObservation()
	o["manifest"] = map[string]any{
		"engine": "afl++", "artifact_sha256": req["sha256"], "image": profile["image"],
		"input_mode": "stdin", "afl_version": "4.04c", "showmap_version": "4.04c",
		"options_verified": true, "probe_edges": 2, "probe_executions": 1,
		"output_disk_limit_bytes": 67108864, "single_worker": true,
	}
	if argv, ok := req["argv"].([]any); ok && len(argv) == 40 && req["operation"] == "fuzz" {
		corpus := make([]nativeFuzzInput, 16)
		for index := range corpus {
			corpus[index] = fuzzTestInput(strings.Repeat(string(rune('A'+index)), 4096))
		}
		crashes := make([]nativeFuzzInput, 8)
		for index := range crashes {
			crashes[index] = fuzzTestInput(strings.Repeat(string(rune('a'+index)), 4096))
		}
		o["corpus"] = corpus
		o["crashes"] = crashes
	}
	if req["operation"] == "replay" {
		o = map[string]any{"target_state": "crashed", "signal": "SIGSEGV", "exit_code": 139,
			"manifest": map[string]any{"engine": "docker-native", "artifact_sha256": req["sha256"]},
			"cleanup":  map[string]any{"owned_process_terminated": true, "container_removed": true, "staging_removed": true},
			"errors":   []string{}}
	}
	_ = json.NewEncoder(os.Stdout).Encode(reverseSessionFrame{Kind: "final", Observation: o})
	os.Exit(0)
}

func requireFuzzTestDB(t *testing.T) string {
	t.Helper()
	if os.Getenv("ARTEX_FUZZ_TEST_DB") != "1" {
		t.Skip("explicit disposable fuzz test DB required")
	}
	dsn := os.Getenv("ARTEX_PG_DSN")
	if strings.TrimSpace(dsn) == "" {
		t.Fatal("ARTEX_PG_DSN is required when ARTEX_FUZZ_TEST_DB=1")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || !regexp.MustCompile(`^artex_[a-z0-9_]+_(test|review)$`).MatchString(cfg.Database) {
		t.Fatal("unsafe test database name")
	}
	return dsn
}

func TestNativeFuzzLedgerAndCandidate(t *testing.T) {
	dsn := requireFuzzTestDB(t)
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	// The protocol helper is a child of this test binary. It must not try to
	// acquire the parent's advisory lock; it only speaks JSON over stdio.
	t.Setenv("ARTEX_PG_DSN", "")
	task, err := pg.CreateTaskWithOptions("synthetic fuzz protocol", "owned fixture", db.TaskCreateOptions{Kind: "reverse"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := pg.DeleteTask(task.ID); e != nil {
			t.Error(e)
		}
	})
	dir := t.TempDir()
	relative := filepath.Join("tasks", fmtNativeID(task.ID), "reverse", "artifacts", "fixture.elf")
	if err = os.MkdirAll(filepath.Dir(filepath.Join(dir, relative)), 0700); err != nil {
		t.Fatal(err)
	}
	b := nativeELFFixture()
	if err = os.WriteFile(filepath.Join(dir, relative), b, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	artifact, err := pg.AddReverseArtifact(task.ID, db.ReverseArtifact{Name: "fixture.elf", Format: "elf", Path: relative, SizeBytes: int64(len(b)), SHA256: hex.EncodeToString(sum[:])})
	if err != nil {
		t.Fatal(err)
	}
	var intent int64
	if err = pg.QueryRow("INSERT INTO exploration_nodes(exploration_id,kind,state,payload) VALUES($1,'intent','running','{}') RETURNING id", task.ExplorationID).Scan(&intent); err != nil {
		t.Fatal(err)
	}
	executable, _ := os.Executable()
	profilePath := filepath.Join(dir, "profiles.json")
	profile := reverseRuntimeProfile{ID: "fuzz-test", Platform: "linux", Engine: "docker-native", Command: executable, Args: []string{"-test.run=^TestNativeFuzzProtocolHelper$", "--", "fuzz-protocol-helper"}, Settings: map[string]any{"image": "sha256:" + strings.Repeat("a", 64), "fuzz_enabled": false}}
	save := func() {
		raw, _ := json.Marshal([]reverseRuntimeProfile{profile})
		if err := os.WriteFile(profilePath, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	save()
	t.Setenv("ARTEX_REVERSE_RUNTIME_PROFILES", profilePath)
	info := agent.RunInfo{TaskID: task.ID, IntentID: intent}
	r := fuzzTestRequest()
	r.ArtifactID = artifact.ID
	r.ProfileID = profile.ID
	if _, err = nativeFuzzRun(t.Context(), pg, task, info, dir, r); err == nil {
		t.Fatal("disabled fuzz accepted")
	}
	profile.Settings["fuzz_enabled"] = true
	save()
	if _, err = nativeFuzzRun(t.Context(), pg, task, info, dir, r); err == nil {
		t.Fatal("unauthorized fuzz accepted")
	}
	policy := db.ReverseRuntimePolicy{Enabled: true, ProfileIDs: []string{profile.ID}, ArtifactIDs: []int64{artifact.ID}, MaxDurationMS: 2000}
	if err = pg.SetReverseRuntimePolicy(t.Context(), task.ID, policy); err != nil {
		t.Fatal(err)
	}
	over := r
	over.Duration = 3000
	if _, err = nativeFuzzRun(t.Context(), pg, task, info, dir, over); err == nil {
		t.Fatal("over budget accepted")
	}
	result, err := nativeFuzzRun(t.Context(), pg, task, info, dir, r)
	if err != nil {
		t.Fatal(err)
	}
	evidencePath := filepath.Join(dir, result["result_path"].(string))
	rawEvidence, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	var evidence struct {
		StructuredContent struct {
			Authority string `json:"authority"`
		} `json:"structuredContent"`
	}
	if json.Unmarshal(rawEvidence, &evidence) != nil || evidence.StructuredContent.Authority != "candidate-only" {
		t.Fatalf("campaign evidence authority: %s", rawEvidence)
	}
	runs, err := pg.NativeRuns(task.ID)
	if err != nil || len(runs) != 1 || runs[0].Mode != "fuzz" || runs[0].TargetState != "completed" {
		t.Fatalf("ledger: %+v %v", runs, err)
	}
	signal := 11
	imported := nativeFuzzRequest{Action: "import_candidate", RunID: runs[0].RunID,
		CandidateSHA256: fuzzTestInput("candidate").SHA256, ExpectedSignal: &signal}
	importedResult, err := nativeFuzzCandidate(t.Context(), pg, task, info, dir, imported)
	if err != nil {
		t.Fatalf("import candidate: %v", err)
	}
	if importedResult["candidate_only"] != true || importedResult["replayed"] != false {
		t.Fatalf("import result: %#v", importedResult)
	}
	runs, err = pg.NativeRuns(task.ID)
	if err != nil || len(runs) != 1 {
		t.Fatalf("import unexpectedly replayed: %+v %v", runs, err)
	}
	replayed := imported
	replayed.Action = "replay_candidate"
	replayed.Duration = 1000
	replay, err := nativeFuzzCandidate(t.Context(), pg, task, info, dir, replayed)
	if err != nil {
		t.Fatal(err)
	}
	ro := replay["replay"].(map[string]any)["observation"].(map[string]any)
	if ro["matches_expectation"] != true {
		t.Fatalf("candidate not replayed: %+v", ro)
	}
	replayPath := replay["replay"].(map[string]any)["result_path"].(string)
	rawReplay, err := os.ReadFile(filepath.Join(dir, replayPath))
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(rawReplay, &evidence) != nil || evidence.StructuredContent.Authority != "controlled-replay" {
		t.Fatalf("replay evidence authority: %s", rawReplay)
	}
	runs, err = pg.NativeRuns(task.ID)
	if err != nil || len(runs) != 2 || runs[0].Mode != "replay" {
		t.Fatalf("replay ledger: %+v %v", runs, err)
	}
	bad := imported
	bad.CandidateSHA256 = strings.Repeat("0", 64)
	if _, err = nativeFuzzCandidate(t.Context(), pg, task, info, dir, bad); err == nil {
		t.Fatal("unknown candidate accepted")
	}
	policy.Revision = 0
	if err = pg.SetReverseRuntimePolicy(t.Context(), task.ID, policy); err != nil {
		t.Fatal(err)
	}
	if _, err = nativeFuzzCandidate(t.Context(), pg, task, info, dir, imported); err == nil {
		t.Fatal("stale campaign policy accepted")
	}

	// A legal request plus a legal final observation can still exceed the
	// combined 256 KiB evidence budget. It must produce exactly one compact,
	// failed, validated_campaign=false evidence file and a matching ledger row.
	resultsDir := filepath.Join(dir, "tasks", fmt.Sprint(task.ID), "reverse", "results")
	beforeFiles, _ := filepath.Glob(filepath.Join(resultsDir, "native-*.json"))
	big := r
	big.MaxExecutions = 100000
	big.MaxCrashes = 8
	big.Argv = make([]string, 40)
	for index := range big.Argv {
		big.Argv[index] = strings.Repeat("A", 3000)
	}
	big.Seeds = make([]nativeFuzzInput, 16)
	for index := range big.Seeds {
		big.Seeds[index] = fuzzTestInput(strings.Repeat(string(rune('a'+index)), 4096))
	}
	rawBigRequest, marshalErr := json.Marshal(big)
	if marshalErr != nil || len(rawBigRequest) > maxFuzzRequest {
		t.Fatalf("large request is not a legal tool request: %d %v", len(rawBigRequest), marshalErr)
	}
	if _, err = nativeFuzzRun(t.Context(), pg, task, info, dir, big); err == nil {
		t.Fatal("combined oversized evidence accepted")
	}
	runs, err = pg.NativeRuns(task.ID)
	if err != nil || len(runs) != 3 || runs[0].Mode != "fuzz" || runs[0].TargetState != "failed" {
		t.Fatalf("combined limit ledger: %+v %v", runs, err)
	}
	if len(runs[0].Observation) > maxFuzzEvidence {
		t.Fatalf("oversized observation written to ledger: %d", len(runs[0].Observation))
	}
	var compact map[string]any
	if json.Unmarshal(runs[0].Observation, &compact) != nil {
		t.Fatalf("compact ledger observation is invalid: %s", runs[0].Observation)
	}
	if compact["validated_campaign"] != false || compact["target_state"] != "failed" {
		t.Fatalf("combined limit state: %#v", compact)
	}
	if _, ok := compact["fuzz_request"]; ok {
		t.Fatal("oversized request retained in compact evidence")
	}
	if !strings.Contains(fmt.Sprint(compact["errors"]), "size limit") {
		t.Fatalf("combined limit reason missing: %#v", compact["errors"])
	}
	normalized, err := nativeLoadFuzzEvidence(dir, task.ID, &runs[0])
	if err != nil {
		t.Fatalf("compact evidence/ledger mismatch: %v", err)
	}
	if normalized["validated_campaign"] != false {
		t.Fatalf("compact evidence validated: %#v", normalized)
	}
	stat, statErr := os.Stat(filepath.Join(dir, runs[0].ResultPath))
	if statErr != nil || stat.Size() > int64(maxFuzzEvidenceFile) {
		t.Fatalf("compact evidence file bound: %v %v", stat, statErr)
	}
	afterFiles, _ := filepath.Glob(filepath.Join(resultsDir, "native-*.json"))
	if len(afterFiles) != len(beforeFiles)+1 {
		t.Fatalf("expected one consistent failure file, before=%d after=%d", len(beforeFiles), len(afterFiles))
	}
}
