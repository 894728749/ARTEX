package server

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func nativeELFFixture() []byte {
	b := make([]byte, 64)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(b[16:], 2)
	binary.LittleEndian.PutUint16(b[18:], 62)
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint16(b[52:], 64)
	return b
}
func TestNativeELFAndCapabilityBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample")
	b := nativeELFFixture()
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	o, e := inspectNativeELF(path)
	if e != nil || o["architecture"] != "x86_64" || o["nx"] != "unknown" {
		t.Fatal(o, e)
	}
	b[18] = 3
	_ = os.WriteFile(path, b, 0600)
	if _, e = inspectNativeELF(path); e == nil {
		t.Fatal("x86 accepted as x64")
	}
	for _, name := range []string{"Bash", "mcp__external__exec", "Skill", "reverse_observe_runtime", "reverse_runtime_session"} {
		if agent.NativeToolAllowed(name) {
			t.Fatalf("native escape tool %s", name)
		}
	}
	if permittedReverseRoleTool("reverse_static", "native_session") || permittedReverseRoleTool("reverse_dynamic", "native_publish_finding") {
		t.Fatal("role isolation failed")
	}
}
func TestNativeObservationRejectsMissingCleanupAndIdentity(t *testing.T) {
	o := map[string]any{"manifest": map[string]any{"engine": "docker-native", "artifact_sha256": "hash"}, "cleanup": map[string]any{"owned_process_terminated": true, "container_removed": true, "staging_removed": true}, "errors": []any{}, "target_state": "crashed"}
	if e := nativeObservationError(o, "hash"); e != nil {
		t.Fatal(e)
	}
	if nativeObservationError(o, "other") == nil {
		t.Fatal("wrong specimen accepted")
	}
	o["cleanup"].(map[string]any)["container_removed"] = false
	if nativeObservationError(o, "hash") == nil {
		t.Fatal("unconfirmed cleanup accepted")
	}
}

// A separate process exercises framing and ownership without running a specimen.
func TestNativeRunnerHelper(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-1] != "native-test-helper" {
		return
	}
	scan := bufio.NewScanner(os.Stdin)
	var first map[string]any
	if !scan.Scan() {
		os.Exit(2)
	}
	_ = json.Unmarshal(scan.Bytes(), &first)
	// Match the real Python contract so protocol fixtures catch null argv.
	if _, ok := first["argv"].([]any); !ok {
		os.Exit(3)
	}
	emit := func(id, kind string, o map[string]any) {
		_ = json.NewEncoder(os.Stdout).Encode(reverseSessionFrame{RequestID: id, Kind: kind, Observation: o})
	}
	observation := map[string]any{"manifest": map[string]any{"engine": "docker-native", "artifact_sha256": first["sha256"]}, "cleanup": map[string]any{"owned_process_terminated": true, "container_removed": true, "staging_removed": true}, "errors": []any{}, "target_state": "exit", "exit_code": 0}
	if first["operation"] == "replay" {
		observation["received_input_mode"] = first["input_mode"]
		observation["received_expected_exit"] = first["expected_exit"]
		observation["received_expected_signal"] = first["expected_signal"]
		if args, ok := first["argv"].([]any); ok && len(args) > 0 {
			switch args[0] {
			case "fixture-signal":
				observation["target_state"] = "crashed"
				observation["exit_code"] = 139
			case "fixture-fractional":
				observation["exit_code"] = 0.5
			case "fixture-missing":
				delete(observation, "exit_code")
			}
		}
		observation["matches_expectation"] = true
		emit("replay", "result", observation)
		os.Exit(0)
	}
	emit("start", "ready", map[string]any{"engine": "docker-native", "platform": "linux/x86_64", "artifact_sha256": first["sha256"], "protocol_version": 1})
	for scan.Scan() {
		var frame map[string]any
		_ = json.Unmarshal(scan.Bytes(), &frame)
		id, _ := frame["request_id"].(string)
		if frame["action"] == "stop" {
			break
		}
		emit(id, "result", map[string]any{"ok": true})
	}
	observation["target_state"] = "cancelled"
	emit("final", "final", observation)
	os.Exit(0)
}

func TestNativeSessionOwnershipPolicyReplayAndFinding(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated test database required")
	}
	pg, e := db.Open(dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer pg.Close()
	t.Setenv("ARTEX_PG_DSN", "postgres://127.0.0.1:1/fixture?connect_timeout=1&sslmode=disable")
	task, e := pg.CreateTaskWithOptions("native synthetic protocol", "verify native evidence", db.TaskCreateOptions{Kind: "reverse"})
	if e != nil {
		t.Fatal(e)
	}
	defer pg.DeleteTask(task.ID)
	dir := t.TempDir()
	relative := filepath.Join("tasks", fmtNativeID(task.ID), "reverse", "artifacts", "fixture.elf")
	_ = os.MkdirAll(filepath.Dir(filepath.Join(dir, relative)), 0700)
	b := nativeELFFixture()
	_ = os.WriteFile(filepath.Join(dir, relative), b, 0600)
	h := sha256.Sum256(b)
	a, e := pg.AddReverseArtifact(task.ID, db.ReverseArtifact{Name: "fixture.elf", Format: "elf", Path: relative, SizeBytes: int64(len(b)), SHA256: hex.EncodeToString(h[:])})
	if e != nil {
		t.Fatal(e)
	}
	var source, reviewer int64
	for _, id := range []*int64{&source, &reviewer} {
		if e = pg.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,state,payload) VALUES($1,'intent','running','{}') RETURNING id`, task.ExplorationID).Scan(id); e != nil {
			t.Fatal(e)
		}
	}
	executable, _ := os.Executable()
	profile := filepath.Join(t.TempDir(), "profiles.json")
	data, _ := json.Marshal([]reverseRuntimeProfile{{ID: "native-test", Platform: "linux", Engine: "docker-native", Command: executable, Args: []string{"-test.run=^TestNativeRunnerHelper$", "--", "native-test-helper"}}})
	_ = os.WriteFile(profile, data, 0600)
	t.Setenv("ARTEX_REVERSE_RUNTIME_PROFILES", profile)
	m := &nativeSessionManager{ctx: t.Context(), pg: pg, task: task, info: agent.RunInfo{TaskID: task.ID, IntentID: source}, dir: dir, sessions: map[string]*nativeSession{}}
	defer m.close()
	if _, e = m.start(t.Context(), a.ID, "native-test", "exec", nil, 1000); e == nil {
		t.Fatal("unauthorized sample execution")
	}
	if e = pg.SetReverseRuntimePolicy(t.Context(), task.ID, db.ReverseRuntimePolicy{Enabled: true, ProfileIDs: []string{"native-test"}, ArtifactIDs: []int64{a.ID}, MaxDurationMS: 5000}); e != nil {
		t.Fatal(e)
	}
	ready, e := m.start(t.Context(), a.ID, "native-test", "exec", nil, 1000)
	if e != nil {
		t.Fatal(e)
	}
	session := m.sessions[ready["session_id"].(string)]
	if _, e = session.request(t.Context(), "status-1", map[string]any{"action": "status"}); e != nil {
		t.Fatal(e)
	}
	session.stop()
	runs, e := pg.NativeRuns(task.ID)
	if e != nil || len(runs) != 1 || runs[0].TargetState != "cancelled" {
		t.Fatal(runs, e)
	}
	exit := 0
	c, e := pg.CreateNativeCase(t.Context(), db.NativeCase{TaskID: task.ID, ArtifactID: a.ID, IntentID: source, ProfileID: "native-test", Title: "normal return", ExpectedExit: &exit})
	if e != nil {
		t.Fatal(e)
	}
	replay, e := nativeReplay(t.Context(), pg, task, agent.RunInfo{IntentID: reviewer}, dir, c, 1000)
	if e != nil {
		t.Fatal(e)
	}
	rid := replay["run_id"].(int64)
	conclusion, e := pg.CreateReverseConclusion(task.ID, db.ReverseConclusionInput{IntentID: source, Question: "test question", Answer: "synthetic finding only", Evidence: []db.ReverseEvidence{{ArtifactID: a.ID, Locator: "entry", Observation: "fixture"}}})
	if e != nil {
		t.Fatal(e)
	}
	_, e = pg.ReviewReverseConclusion(task.ID, conclusion.ID, reviewer, "accepted", "independently replayed")
	if e != nil {
		t.Fatal(e)
	}
	input := db.RecordFindingInput{Name: "synthetic", VulnClass: "test", Severity: "info", Summary: "protocol fixture"}
	snapshot := json.RawMessage(`{"version":1,"input":"AA=="}`)
	if _, e = pg.PublishNativeFinding(t.Context(), task.ID, conclusion.ID, c.ID, rid, source, input, snapshot); e == nil {
		t.Fatal("self review publication accepted")
	}
	finding, e := pg.PublishNativeFinding(t.Context(), task.ID, conclusion.ID, c.ID, rid, reviewer, input, snapshot)
	if e != nil {
		t.Fatal(e)
	}
	again, e := pg.PublishNativeFinding(t.Context(), task.ID, conclusion.ID, c.ID, rid, reviewer, input, snapshot)
	if e != nil || again.FindingID != finding.FindingID {
		t.Fatal("publication not idempotent", e)
	}
	defer pg.Exec(`DELETE FROM findings WHERE id=$1`, finding.FindingID)
	// Expected assertions are evaluated by the server, regardless of runner claim.
	wrong := 23
	c2 := *c
	c2.ExpectedExit = &wrong
	if e = db.ValidateNativeCase(&c2); e != nil {
		t.Fatal(e)
	}
	result, e := nativeReplay(context.Background(), pg, task, agent.RunInfo{IntentID: reviewer}, dir, &c2, 1000)
	if e != nil {
		t.Fatal(e)
	}
	if result["observation"].(map[string]any)["matches_expectation"] != false {
		t.Fatal("trusted runner assertion without checking exit")
	}
	creator := workflowTool(t, nativeTools(pg, task, agent.RunInfo{IntentID: source}, dir, "reverse_dynamic", m), "native_case")
	replayer := workflowTool(t, nativeTools(pg, task, agent.RunInfo{IntentID: reviewer}, dir, "reverse_reviewer", m), "native_case")
	var planCaseID int64
	for _, tc := range []struct {
		name, kind, arg string
		value           int
		matches         bool
	}{
		{"plan exit", "exit_code", "", 0, true},
		{"plan wrong exit", "exit_code", "", 23, false},
		{"plan signal", "signal", "fixture-signal", 11, true},
		{"plan wrong signal", "signal", "fixture-signal", 6, false},
		{"plan fractional code", "exit_code", "fixture-fractional", 0, false},
		{"plan missing code", "exit_code", "fixture-missing", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			created := workflowCall(t, t.Context(), creator, map[string]any{
				"action": "create", "artifact_id": a.ID, "profile_id": "native-test", "title": tc.name,
				"input_base64": "AP8=", "argv": []string{tc.arg},
				"replay_plan": map[string]any{"version": 1, "assertion": map[string]any{"type": tc.kind, "value": tc.value}},
			}, false)
			var saved db.NativeCase
			if e := json.Unmarshal([]byte(created), &saved); e != nil || saved.ReplayPlan == nil || saved.ReplayPlan.InputMode != "stdin" {
				t.Fatalf("tool lost plan: %s err=%v", created, e)
			}
			planCaseID = saved.ID
			raw := workflowCall(t, t.Context(), replayer, map[string]any{"action": "replay", "case_id": saved.ID, "duration_ms": 1000}, false)
			var response struct {
				ResultPath  string         `json:"result_path"`
				Observation map[string]any `json:"observation"`
			}
			if e := json.Unmarshal([]byte(raw), &response); e != nil {
				t.Fatal(e)
			}
			o := response.Observation
			if o["matches_expectation"] != tc.matches || o["case_sha256"] != saved.SHA256 || o["received_input_mode"] != "stdin" {
				t.Fatalf("wrong replay result: %s", raw)
			}
			key, other := "received_expected_exit", "received_expected_signal"
			if tc.kind == "signal" {
				key, other = other, key
			}
			if o[key] != float64(tc.value) || o[other] != nil {
				t.Fatalf("plan was not translated to runner protocol: %+v", o)
			}
			if _, e := os.Stat(filepath.Join(dir, response.ResultPath)); e != nil {
				t.Fatalf("replay evidence missing: %v", e)
			}
		})
	}
	// State API is also the source for the existing team read-only view.
	s := &Server{m: &Manager{pg: pg, dir: dir, tasks: map[string]*Task{fmtNativeID(task.ID): {Kind: "reverse"}}}}
	request := httptest.NewRequest("GET", "/api/tasks/"+fmtNativeID(task.ID)+"/reverse/native", nil)
	request.SetPathValue("id", fmtNativeID(task.ID))
	response := httptest.NewRecorder()
	s.nativeState(response, request)
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"replay_plan"`) {
		t.Fatalf("state omitted plan: %d %s", response.Code, response.Body.String())
	}
	// A changed plan with the old hash must fail before allocating a run.
	before, _ := pg.NativeRuns(task.ID)
	if _, e := pg.Exec(`UPDATE reverse_native_cases SET replay_plan=jsonb_set(replay_plan,'{assertion,value}','23') WHERE id=$1`, planCaseID); e != nil {
		t.Fatal(e)
	}
	text := workflowCall(t, t.Context(), replayer, map[string]any{"action": "replay", "case_id": planCaseID}, true)
	after, _ := pg.NativeRuns(task.ID)
	if !strings.Contains(text, "hash mismatch") || len(after) != len(before) {
		t.Fatalf("tampered plan ran: %s; run count %d -> %d", text, len(before), len(after))
	}
}

func TestNativeCaseRejectsUnsupportedPlanBeforeDB(t *testing.T) {
	tool := workflowTool(t, nativeTools(nil, &db.Task{}, agent.RunInfo{}, "", "reverse_dynamic", &nativeSessionManager{}), "native_case")
	for _, extra := range []string{
		`"replay_plan":{"version":1,"dependencies":[]}`,
		`"replay_plan":{"version":1,"input_mode":"file"}`,
		`"replay_plan":{"version":2}`,
		`"replay_plan":{"version":1,"assertion":{"type":"stdout_contains_base64","value":0}}`,
		`"replay_plan":{"version":1,"assertion":{"type":"exit_code","value":0,"unknown":true}}`,
		`"harness_id":1`,
	} {
		raw := json.RawMessage(`{"action":"create","title":"invalid","profile_id":"test","expected_exit":0,` + extra + `}`)
		result, err := tool.Call(t.Context(), raw, nil)
		if err != nil || !result.IsError {
			t.Fatalf("unsupported plan accepted: %s result=%s err=%v", raw, result.Flatten(), err)
		}
	}
}
func fmtNativeID(id int64) string { b, _ := json.Marshal(id); return strings.TrimSpace(string(b)) }
