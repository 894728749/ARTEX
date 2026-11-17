package db

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

func TestValidateNativeCase(t *testing.T) {
	exit := 0
	valid := NativeCase{ArtifactID: 7, ProfileID: "lab", Title: "empty input", InputBase64: "", ExpectedExit: &exit}
	if err := ValidateNativeCase(&valid); err != nil {
		t.Fatalf("valid case rejected: %v", err)
	}
	if valid.Argv == nil || valid.SHA256 == "" {
		t.Fatalf("case was not normalized and hashed: %+v", valid)
	}
	invalid := []NativeCase{
		{ArtifactID: 7, ProfileID: "lab", Title: "bad base64", InputBase64: "!", ExpectedExit: &exit},
		{ArtifactID: 7, ProfileID: "lab", Title: "missing expectation", InputBase64: ""},
		{ArtifactID: 7, ProfileID: "lab", Title: "two expectations", InputBase64: "", ExpectedExit: &exit, ExpectedSignal: new(int)},
		{ArtifactID: 7, ProfileID: "lab", Title: "bad argv", InputBase64: "", ExpectedExit: &exit, Argv: []string{"bad\x00arg"}},
	}
	for i, item := range invalid {
		if err := ValidateNativeCase(&item); err == nil {
			t.Errorf("invalid fixture %d was accepted", i)
		}
	}
}

func TestNativeArchiveScopeRejectsCrossTaskBindings(t *testing.T) {
	base := map[string]json.RawMessage{
		"reverse_native_configs": json.RawMessage(`[]`), "reverse_native_cases": json.RawMessage(`[]`),
		"reverse_native_runs": json.RawMessage(`[]`), "finding_native_evidence": json.RawMessage(`[]`),
		"reverse_artifacts": json.RawMessage(`[]`), "exploration_nodes": json.RawMessage(`[]`),
		"reverse_runtime_runs": json.RawMessage(`[]`), "reverse_conclusions": json.RawMessage(`[]`), "findings": json.RawMessage(`[]`),
	}
	for name, tables := range map[string]map[string]json.RawMessage{
		"foreign config owner": func() map[string]json.RawMessage {
			tables := cloneArchiveFixture(base)
			tables["reverse_native_configs"] = json.RawMessage(`[{"task_id":12,"mode":"pwn","revision":2}]`)
			return tables
		}(),
		"foreign artifact reference": func() map[string]json.RawMessage {
			tables := cloneArchiveFixture(base)
			tables["reverse_native_cases"] = json.RawMessage(`[{"id":1,"task_id":11,"artifact_id":99,"intent_id":4}]`)
			tables["exploration_nodes"] = json.RawMessage(`[{"id":4,"kind":"intent"}]`)
			return tables
		}(),
	} {
		if err := validateNativeArchiveScope(&TaskArchiveSnapshot{FormatVersion: 5, TaskID: 11, Tables: tables}); err == nil {
			t.Errorf("%s passed archive scope validation", name)
		}
	}
}

func cloneArchiveFixture(in map[string]json.RawMessage) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func TestNativeArchiveScopeValidatesReplayPlan(t *testing.T) {
	value := 0
	c := NativeCase{ID: 1, TaskID: 11, ArtifactID: 3, IntentID: 4, ProfileID: "lab", Title: "plan", ReplayPlan: &NativeReplayPlan{Version: 1, Assertion: &NativeReplayAssertion{Type: "exit_code", Value: &value}}}
	if err := ValidateNativeCase(&c); err != nil {
		t.Fatal(err)
	}
	base := map[string]json.RawMessage{
		"reverse_native_configs": json.RawMessage(`[]`), "reverse_native_runs": json.RawMessage(`[]`),
		"finding_native_evidence": json.RawMessage(`[]`), "reverse_runtime_runs": json.RawMessage(`[]`),
		"reverse_conclusions": json.RawMessage(`[]`), "findings": json.RawMessage(`[]`),
		"reverse_artifacts": json.RawMessage(`[{"id":3,"task_id":11}]`),
		"exploration_nodes": json.RawMessage(`[{"id":4,"kind":"intent"}]`),
	}
	for _, tc := range []struct {
		name      string
		mutate    func(map[string]any)
		wantError bool
	}{
		{"valid", func(map[string]any) {}, false},
		{"changed hash", func(row map[string]any) { row["sha256"] = "tampered" }, true},
		{"unknown field", func(row map[string]any) { row["replay_plan"].(map[string]any)["harness_id"] = 9 }, true},
		{"unsupported version", func(row map[string]any) { row["replay_plan"].(map[string]any)["version"] = 2 }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(c)
			var row map[string]any
			if err := json.Unmarshal(raw, &row); err != nil {
				t.Fatal(err)
			}
			tc.mutate(row)
			tables := cloneArchiveFixture(base)
			tables["reverse_native_cases"], _ = json.Marshal([]any{row})
			err := validateNativeArchiveScope(&TaskArchiveSnapshot{FormatVersion: 5, TaskID: 11, Tables: tables})
			if (err != nil) != tc.wantError {
				t.Fatalf("validation error=%v wantError=%v", err, tc.wantError)
			}
		})
	}
}

func TestNativeArchiveScopeAllowsLegacyPackagesWithoutNativeTables(t *testing.T) {
	snapshot := &TaskArchiveSnapshot{FormatVersion: 4, TaskID: 11, Tables: map[string]json.RawMessage{}}
	if err := validateNativeArchiveScope(snapshot); err != nil {
		t.Fatalf("legacy archive should not require native tables: %v", err)
	}
	for version := 1; version <= 5; version++ {
		if !IsTaskArchiveFormatSupported(version) {
			t.Errorf("archive version %d should be supported", version)
		}
	}
	if IsTaskArchiveFormatSupported(6) {
		t.Fatal("future archive version should not be supported")
	}
}

func TestNativeConfigRequiresPausedReverseTask(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTaskWithOptions("native mode pause", "test mode gating", TaskCreateOptions{Kind: "reverse"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	if err := d.SetPaused(task.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := d.SetNativeConfig(context.Background(), task.ID, "pwn"); err == nil {
		t.Fatal("native mode changed while task was running")
	}
	if err := d.SetPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := d.SetNativeConfig(context.Background(), task.ID, "pwn"); err != nil {
		t.Fatal(err)
	}
	config, err := d.NativeConfig(task.ID)
	if err != nil || config.Mode != "pwn" || config.Revision != 1 {
		t.Fatalf("native config=%+v err=%v", config, err)
	}
}

func TestNativeArchiveSnapshotRestore(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if err := d.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTaskWithOptions("native archive", "restore cases and evidence", TaskCreateOptions{Kind: "reverse"})
	if err != nil {
		t.Fatal(err)
	}
	var archiveID int64
	t.Cleanup(func() {
		if archiveID > 0 {
			_, _ = d.Exec(`DELETE FROM task_archives WHERE id=$1`, archiveID)
		}
		_, _ = d.Exec(`DELETE FROM findings WHERE task_id=$1 OR vulnclass=$2`, task.ID, fmt.Sprintf("native-archive-%d", task.ID))
		_ = d.DeleteTask(task.ID)
	})
	if err := d.SetNativeConfig(context.Background(), task.ID, "pwn"); err != nil {
		t.Fatal(err)
	}
	artifact, err := d.AddReverseArtifact(task.ID, ReverseArtifact{Name: "fixture.elf", Format: "elf", SizeBytes: 3, SHA256: "fixture", Path: fmt.Sprintf("tasks/%d/fixture.elf", task.ID)})
	if err != nil {
		t.Fatal(err)
	}
	var intentID int64
	if err := d.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin) VALUES($1,'intent','{}',0,'running','test') RETURNING id`, task.ExplorationID).Scan(&intentID); err != nil {
		t.Fatal(err)
	}
	expected := 0
	caseRecord, err := d.CreateNativeCase(context.Background(), NativeCase{TaskID: task.ID, ArtifactID: artifact.ID, IntentID: intentID, ProfileID: "lab-linux", Title: "replay fixture", Argv: []string{"--check"}, InputBase64: "AQID", ExpectedExit: &expected})
	if err != nil {
		t.Fatal(err)
	}
	planned, err := d.CreateNativeCase(t.Context(), NativeCase{TaskID: task.ID, ArtifactID: artifact.ID, IntentID: intentID, ProfileID: "lab-linux", Title: "planned replay", InputBase64: "AP8=", ReplayPlan: &NativeReplayPlan{Version: 1, Assertion: &NativeReplayAssertion{Type: "exit_code", Value: &expected}}})
	if err != nil {
		t.Fatal(err)
	}
	readBack, err := d.NativeCase(task.ID, planned.ID)
	if err != nil || readBack.ReplayPlan == nil || readBack.ReplayPlan.InputMode != "stdin" || readBack.SHA256 != planned.SHA256 {
		t.Fatalf("replay plan was not persisted: case=%+v err=%v", readBack, err)
	}
	// Opening again reapplies schema migrations over both old and new cases.
	reopened, err := Open(testDSN(t))
	if err != nil {
		t.Fatalf("reapplying schema with legacy and planned cases: %v", err)
	}
	_ = reopened.Close()
	var runtimeID int64
	if err := d.QueryRow(`INSERT INTO reverse_runtime_runs(task_id,artifact_id,intent_id,profile_id,status) VALUES($1,$2,$3,'lab-linux','running') RETURNING id`, task.ID, artifact.ID, intentID).Scan(&runtimeID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO reverse_runtime_policies(task_id,enabled,profile_ids,artifact_ids,max_duration_ms) VALUES($1,true,'["lab-linux"]',$2,10000)`, task.ID, fmt.Sprintf("[%d]", artifact.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO reverse_native_runs(run_id,task_id,artifact_id,intent_id,case_id,config_revision,mode,target_state,observation) VALUES($1,$2,$3,$4,$5,1,'replay','running','{}')`, runtimeID, task.ID, artifact.ID, intentID, caseRecord.ID); err != nil {
		t.Fatal(err)
	}
	var conclusionID int64
	if err := d.QueryRow(`INSERT INTO reverse_conclusions(task_id,intent_id,question,answer,state,evidence,reviewer_intent_id) VALUES($1,$2,'test question','candidate','accepted',jsonb_build_array(jsonb_build_object('artifact_id',$3::bigint)),NULL) RETURNING id`, task.ID, intentID, artifact.ID).Scan(&conclusionID); err != nil {
		t.Fatal(err)
	}
	var findingID int64
	if err := d.QueryRow(`INSERT INTO findings(task_id,node_id,vulnclass,name) VALUES($1,$2,$3,'Native finding') RETURNING id`, task.ID, intentID, fmt.Sprintf("native-archive-%d", task.ID)).Scan(&findingID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO finding_native_evidence(finding_id,source_task_id,conclusion_id,case_id,run_id,sha256,snapshot) VALUES($1,$2,$3,$4,$5,'snap-hash','{"specimen":"fixture"}')`, findingID, task.ID, conclusionID, caseRecord.ID, runtimeID); err != nil {
		t.Fatal(err)
	}
	archive, err := d.QueueTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	archiveID = archive.ID
	claimTaskArchiveFixture(t, d, archive.ID)
	snapshot, err := d.SnapshotTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.FormatVersion != 5 || snapshot.DataCounts["reverse_native_cases"] != 2 || snapshot.DataCounts["reverse_native_runs"] != 1 || snapshot.DataCounts["finding_native_evidence"] != 1 {
		t.Fatalf("native archive counts/version: version=%d counts=%v", snapshot.FormatVersion, snapshot.DataCounts)
	}
	if err := d.CompleteTaskArchive(archive.ID, snapshot, "fixture.tar.zst", "fixture", 1, 1); err != nil {
		t.Fatal(err)
	}
	var archivedRows int
	if err := d.QueryRow(`SELECT (SELECT count(*) FROM reverse_native_configs WHERE task_id=$1)+(SELECT count(*) FROM reverse_native_cases WHERE task_id=$1)+(SELECT count(*) FROM reverse_native_runs WHERE task_id=$1)+(SELECT count(*) FROM finding_native_evidence WHERE finding_id=$2)`, task.ID, findingID).Scan(&archivedRows); err != nil || archivedRows != 0 {
		t.Fatalf("archive did not clear live native rows: count=%d err=%v", archivedRows, err)
	}
	if _, err := d.QueueTaskArchiveRestore(archive.ID); err != nil {
		t.Fatal(err)
	}
	claimTaskArchiveFixture(t, d, archive.ID)
	if _, err := d.RestoreTaskArchive(archive.ID, snapshot, 0); err != nil {
		t.Fatal(err)
	}
	var mode string
	if err := d.QueryRow(`SELECT mode FROM reverse_native_configs WHERE task_id=$1`, task.ID).Scan(&mode); err != nil || mode != "pwn" {
		t.Fatalf("restored mode=%q err=%v", mode, err)
	}
	restoredCases, err := d.NativeCases(task.ID)
	if err != nil || len(restoredCases) != 2 {
		t.Fatalf("restored cases=%+v err=%v", restoredCases, err)
	}
	for _, c := range restoredCases {
		digest := c.SHA256
		if err := ValidateNativeCase(&c); err != nil || c.SHA256 != digest {
			t.Fatalf("restored case identity changed: case=%+v err=%v", c, err)
		}
		if c.ID == planned.ID && (c.ReplayPlan == nil || c.ReplayPlan.Assertion == nil || *c.ReplayPlan.Assertion.Value != expected || c.SHA256 != planned.SHA256) {
			t.Fatalf("restored plan changed: %+v", c)
		}
		if c.ID == caseRecord.ID && (c.ReplayPlan != nil || c.SHA256 != caseRecord.SHA256) {
			t.Fatalf("legacy case changed: %+v", c)
		}
	}
	var targetState, runtimeStatus string
	if err := d.QueryRow(`SELECT native.target_state,runtime.status FROM reverse_native_runs native JOIN reverse_runtime_runs runtime ON runtime.id=native.run_id WHERE native.task_id=$1`, task.ID).Scan(&targetState, &runtimeStatus); err != nil || targetState != "failed" || runtimeStatus != "failed" {
		t.Fatalf("restored run states native=%q runtime=%q err=%v", targetState, runtimeStatus, err)
	}
	var enabled bool
	if err := d.QueryRow(`SELECT enabled FROM reverse_runtime_policies WHERE task_id=$1`, task.ID).Scan(&enabled); err != nil || enabled {
		t.Fatalf("restored execution authorization enabled=%v err=%v", enabled, err)
	}
	var restoredSnapshot string
	if err := d.QueryRow(`SELECT snapshot::text FROM finding_native_evidence WHERE finding_id=$1`, findingID).Scan(&restoredSnapshot); err != nil || restoredSnapshot != `{"specimen": "fixture"}` {
		t.Fatalf("finding evidence snapshot=%s err=%v", restoredSnapshot, err)
	}
	if err := d.CompleteTaskArchiveRestore(archive.ID); err != nil {
		t.Fatal(err)
	}
	archiveID = 0
	if _, err := d.DeleteTaskCascade(task.ID, false, false); err != nil {
		t.Fatalf("preserve-finding cleanup: %v", err)
	}
	if err := d.QueryRow(`SELECT snapshot::text FROM finding_native_evidence WHERE finding_id=$1`, findingID).Scan(&restoredSnapshot); err != nil || restoredSnapshot != `{"specimen": "fixture"}` {
		t.Fatalf("preserving finding lost native evidence: snapshot=%s err=%v", restoredSnapshot, err)
	}
	if _, err := d.Exec(`DELETE FROM findings WHERE id=$1`, findingID); err != nil {
		t.Fatal(err)
	}
}
