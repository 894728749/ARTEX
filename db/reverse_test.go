package db

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestReverseArtifactAndConclusionOwnership(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer d.Close()
	suffix := fmt.Sprintf("reverse-contract-%d", testID())
	first, err := d.CreateTaskWithOptions(suffix, "inspect sample", TaskCreateOptions{Kind: "reverse"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.CreateTask(suffix+" other", "inspect other", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM task_archives WHERE task_id IN ($1,$2)`, first.ID, second.ID)
		_ = d.DeleteTask(first.ID)
		_ = d.DeleteTask(second.ID)
	})
	a, err := d.AddReverseArtifact(first.ID, ReverseArtifact{Name: "sample.bin", Format: "bin", SizeBytes: 3, SHA256: "abc", Path: "/private/sample"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.AddReverseArtifact(second.ID, ReverseArtifact{Name: "x", SizeBytes: 1, SHA256: "x", Path: "/x"}); !errors.Is(err, ErrReverseTaskRequired) {
		t.Fatalf("wrong task accepted: %v", err)
	}
	var source, reviewer int64
	if err = d.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin) VALUES($1,'intent','{}',0,'running','test') RETURNING id`, first.ExplorationID).Scan(&source); err != nil {
		t.Fatal(err)
	}
	if err = d.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin) VALUES($1,'intent','{}',0,'running','test') RETURNING id`, first.ExplorationID).Scan(&reviewer); err != nil {
		t.Fatal(err)
	}
	c, err := d.CreateReverseConclusion(first.ID, ReverseConclusionInput{IntentID: source, Question: "Does it contain header?", Answer: "Yes", Evidence: []ReverseEvidence{{ArtifactID: a.ID, Locator: "offset 0", Observation: "magic bytes"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.ReviewReverseConclusion(first.ID, c.ID, source, "accepted", "same intent"); !errors.Is(err, ErrReverseConclusionInvalid) {
		t.Fatalf("same intent reviewed own conclusion: %v", err)
	}
	accepted, err := d.ReviewReverseConclusion(first.ID, c.ID, reviewer, "accepted", "confirmed from bytes")
	if err != nil {
		t.Fatal(err)
	}
	if accepted.State != "accepted" || accepted.ReviewerIntentID == nil || *accepted.ReviewerIntentID != reviewer {
		t.Fatalf("review not persisted: %+v", accepted)
	}
}

func testID() int64 { return time.Now().UnixNano() }

func TestReverseArchivePreservesIdentityAndEvidence(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer d.Close()
	if err := d.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTaskWithOptions("reverse archive", "explain sample", TaskCreateOptions{Kind: "reverse"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM task_archives WHERE task_id=$1`, task.ID)
		_ = d.DeleteTask(task.ID)
	})
	if !task.Paused || task.CoverageEnabled || task.WorkflowVersion != 1 {
		t.Fatalf("draft identity: %+v", task)
	}
	if _, err := d.Exec(`UPDATE tasks SET kind='pentest' WHERE id=$1`, task.ID); err == nil {
		t.Fatal("workflow identity changed")
	}
	a, err := d.AddReverseArtifact(task.ID, ReverseArtifact{Name: "sample.js", Format: "js", SizeBytes: 3, SHA256: "fixture", Path: fmt.Sprintf("tasks/%d/reverse/artifacts/sample.js", task.ID)})
	if err != nil {
		t.Fatal(err)
	}
	store := d.Exploration(task.ExplorationID)
	iid, err := store.AddNode(KindIntent, map[string]any{"summary": "analyze"}, 0, "done", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.CreateReverseConclusion(task.ID, ReverseConclusionInput{IntentID: iid, Question: "question", Answer: "candidate", Evidence: []ReverseEvidence{{ArtifactID: a.ID, Locator: "line 1", Observation: "literal"}}})
	if err != nil {
		t.Fatal(err)
	}
	archive, err := d.QueueTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := d.SnapshotTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.CompleteTaskArchive(archive.ID, snapshot, "fixture.tar.zst", "fixture", 3, 3); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM reverse_artifacts WHERE task_id=$1`, task.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("archive left hot artifact: %d %v", count, err)
	}
	if _, err := d.QueueTaskArchiveRestore(archive.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.RestoreTaskArchive(archive.ID, snapshot, 0); err != nil {
		t.Fatal(err)
	}
	live, err := d.GetTask(task.ID)
	if err != nil || live == nil || live.Kind != "reverse" || live.WorkflowVersion != 1 {
		t.Fatalf("workflow lost: %+v %v", live, err)
	}
	restored, err := d.GetReverseArtifact(task.ID, a.ID)
	if err != nil || restored == nil || restored.Path != a.Path {
		t.Fatalf("artifact lost: %+v %v", restored, err)
	}
	conclusion, err := d.GetReverseConclusion(task.ID, c.ID)
	if err != nil || conclusion == nil || conclusion.Evidence[0].ArtifactID != a.ID {
		t.Fatalf("conclusion lost: %+v %v", conclusion, err)
	}
}
