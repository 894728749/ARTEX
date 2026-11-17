package server

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestNativeMatchV2TargetOutputAssertions(t *testing.T) {
	caseWith := func(plan *db.NativeReplayPlan) *db.NativeCase {
		return &db.NativeCase{ReplayPlan: plan}
	}
	plan := func(target *db.NativeTarget) *db.NativeReplayPlan {
		return &db.NativeReplayPlan{Version: 2, Assertion: &db.NativeReplayAssertion{Type: "stdout_contains_base64", DataBase64: "bWFya2Vy"}, Target: target}
	}
	base := map[string]any{"target_state": "exit", "output_source": "target_stdout", "output_base64": base64.StdEncoding.EncodeToString([]byte("prefix marker suffix"))}
	if !nativeMatch(caseWith(plan(nil)), base) {
		t.Fatal("valid target stdout marker did not match")
	}
	for name, mutate := range map[string]func(map[string]any){
		"harness output": func(o map[string]any) { o["output_source"] = "harness_stdout" },
		"missing base64": func(o map[string]any) { delete(o, "output_base64") },
		"bad base64":     func(o map[string]any) { o["output_base64"] = "%%%" },
		"wrong state":    func(o map[string]any) { o["target_state"] = "timeout" },
	} {
		t.Run(name, func(t *testing.T) {
			o := map[string]any{}
			for k, v := range base {
				o[k] = v
			}
			mutate(o)
			if nativeMatch(caseWith(plan(nil)), o) {
				t.Fatal("invalid target output observation matched")
			}
		})
	}
	harness := plan(&db.NativeTarget{Harness: &db.NativeArtifactBinding{ArtifactID: 8, SHA256: strings.Repeat("a", 64), Name: "harness.py"}})
	if nativeMatch(caseWith(harness), base) {
		t.Fatal("harness case accepted stdout as target impact evidence")
	}
}

func TestNativeMatchPreservesExitAndSignalAssertions(t *testing.T) {
	exit := 7
	if !nativeMatch(&db.NativeCase{ExpectedExit: &exit}, map[string]any{"target_state": "exit", "exit_code": float64(7)}) {
		t.Fatal("matching exit code rejected")
	}
	if nativeMatch(&db.NativeCase{ExpectedExit: &exit}, map[string]any{"target_state": "crashed", "exit_code": float64(7)}) {
		t.Fatal("exit code matched with wrong target state")
	}
	signal := 11
	if !nativeMatch(&db.NativeCase{ExpectedSignal: &signal}, map[string]any{"target_state": "crashed", "exit_code": float64(128 + signal)}) {
		t.Fatal("legacy Docker signal convention rejected")
	}
	if nativeMatch(&db.NativeCase{ExpectedSignal: &signal}, map[string]any{"target_state": "crashed", "exit_code": float64(128 + 6)}) {
		t.Fatal("wrong signal matched")
	}
}

func TestNativeExportSnapshotIntegrityAndPortableReplay(t *testing.T) {
	specimen := []byte("synthetic specimen")
	specimenHash := sha256.Sum256(specimen)
	caseHash := strings.Repeat("c", 64)
	snapshot := map[string]any{
		"specimen_base64": base64.StdEncoding.EncodeToString(specimen),
		"artifact":        map[string]any{"name": "specimen.elf", "sha256": hex.EncodeToString(specimenHash[:])},
		"case":            db.NativeCase{ID: 123456, TaskID: 654321, ArtifactID: 77, IntentID: 88, ProfileID: "lab", Title: "portable", Argv: []string{"--check"}, InputBase64: "AQ==", SHA256: caseHash},
		"replay":          db.NativeRun{RunID: 991122, TaskID: 654321, ArtifactID: 77, IntentID: 99, CaseID: 123456, Observation: json.RawMessage(`{"target_state":"exit","exit_code":0,"matches_expectation":true}`)},
		"attachments":     []any{}, "source_evidence": []any{},
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _ := json.Marshal(func() any { var v any; _ = json.Unmarshal(raw, &v); return v }())
	h := sha256.Sum256(canonical)
	digest := hex.EncodeToString(h[:])
	if _, err := nativeExport(raw, strings.Repeat("0", 64)); err == nil {
		t.Fatal("tampered snapshot hash accepted")
	}
	archive, err := nativeExport(raw, digest)
	if err != nil {
		t.Fatalf("valid snapshot export failed: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	var replayJSON []byte
	for _, f := range zr.File {
		if f.Name == "replay.json" {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			replayJSON, err = io.ReadAll(rc)
			_ = rc.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(replayJSON) == 0 {
		t.Fatal("portable replay.json missing")
	}
	for _, internal := range []string{"123456", "654321", "991122", "\"task_id\"", "\"intent_id\"", "\"artifact_id\"", "\"run_id\""} {
		if bytes.Contains(replayJSON, []byte(internal)) {
			t.Errorf("portable replay.json leaks internal identifier/field %q: %s", internal, replayJSON)
		}
	}
}
