package db

import "testing"

func TestExecutionTailReviewOnceAndPause(t *testing.T) {
	d, task, add := collaborationDB(t)
	// Initialize before adding new findings, just like a running upgraded task.
	if _, err := d.FindingReviewStatus(task.ID); err != nil {
		t.Fatal(err)
	}
	add("tail finding")
	if id, _, err := d.BeginFindingReview(t.Context(), task.ID, false); err != nil || id != 0 {
		t.Fatalf("early batch %d %v", id, err)
	}
	_ = d.SetStatus(task.ID, "done")
	_ = d.SetPaused(task.ID, true)
	if id, _, err := d.BeginFindingReview(t.Context(), task.ID, false); err != nil || id != 0 {
		t.Fatalf("paused tail %d %v", id, err)
	}
	_ = d.SetPaused(task.ID, false)
	_, _ = d.Exec(`UPDATE finding_review_state SET enabled=false WHERE task_id=$1`, task.ID)
	if id, _, err := d.BeginFindingReview(t.Context(), task.ID, false); err != nil || id != 0 {
		t.Fatalf("disabled tail %d %v", id, err)
	}
	_, _ = d.Exec(`UPDATE finding_review_state SET enabled=true WHERE task_id=$1`, task.ID)
	id, _, err := d.BeginFindingReview(t.Context(), task.ID, false)
	if err != nil || id == 0 {
		t.Fatalf("tail not admitted %d %v", id, err)
	}
	if err = d.FinishFindingReview(t.Context(), id, false, "synthetic failure"); err != nil {
		t.Fatal(err)
	}
	if again, _, err := d.BeginFindingReview(t.Context(), task.ID, false); err != nil || again != 0 {
		t.Fatalf("failed tail retried %d %v", again, err)
	}
	add("new evidence")
	id, _, err = d.BeginFindingReview(t.Context(), task.ID, false)
	if err != nil || id == 0 {
		t.Fatalf("new tail %d %v", id, err)
	}
	if err = d.FinishFindingReview(t.Context(), id, true, "checked new batch"); err != nil {
		t.Fatal(err)
	}
	if again, _, err := d.BeginFindingReview(t.Context(), task.ID, false); err != nil || again != 0 {
		t.Fatalf("finished tail repeated %d %v", again, err)
	}
}
