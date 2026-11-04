package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func collaborationDB(t *testing.T) (*DB, *Task, func(string) int64) {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTask("finding collaboration test", "offline", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM findings WHERE task_id=$1`, task.ID)
		_, _ = d.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID)
		d.Close()
	})
	add := func(name string) int64 {
		t.Helper()
		id, err := d.AddFinding(task.ID, 0, "auth", name, "high", "same root", name+" proof", "test", nil)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	return d, task, add
}

func TestFindingConsolidationAtomicEvidenceAndLists(t *testing.T) {
	d, task, add := collaborationDB(t)
	a, b, c := add("primary"), add("scope extension"), add("independent")
	_, err := d.Exec(`UPDATE findings SET report='original report',asset_ids='[11]' WHERE id=$1`, a)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = d.Exec(`UPDATE findings SET asset_ids='[12]' WHERE id=$1`, b)
	in := ConsolidateFindingsInput{CanonicalID: a, SourceIDs: []int64{b}, Name: "single root cause", Summary: "verified wider scope", Severity: "critical", Reason: "same component, condition and remediation", Versions: map[string]int64{fmt.Sprint(a): 0, fmt.Sprint(b): 0}}
	if err = d.ConsolidateFindings(t.Context(), task.ID, 0, in); err != nil {
		t.Fatal(err)
	}
	f, err := d.GetFinding(a)
	if err != nil {
		t.Fatal(err)
	}
	if f.Name != in.Name || len(f.AssetIDs) != 2 || f.EvidenceVersion != 1 || f.Report != "original report" || f.ReportEvidenceVersion == f.EvidenceVersion || !strings.Contains(f.Evidence, "scope extension proof") {
		t.Fatalf("canonical=%+v", f)
	}
	original, _ := d.GetFinding(b)
	if original == nil || original.Evidence != "scope extension proof" {
		t.Fatal("source evidence lost")
	}
	rows, total, err := d.ListFindingsPage(FindingFilter{TaskID: fmt.Sprint(task.ID)}, 1, 20)
	if err != nil || total != 2 || len(rows) != 2 {
		t.Fatalf("list total=%d len=%d err=%v", total, len(rows), err)
	}
	exported, err := d.ListFindingsForExport(FindingFilter{}, []int64{a, b, c})
	if err != nil || len(exported) != 2 {
		t.Fatalf("export=%d err=%v", len(exported), err)
	}
	var snapshot string
	err = d.QueryRow(`SELECT snapshot::text FROM finding_consolidations WHERE canonical_id=$1`, a).Scan(&snapshot)
	if err != nil || !strings.Contains(snapshot, "original report") || !strings.Contains(snapshot, "scope extension proof") {
		t.Fatalf("audit=%s err=%v", snapshot, err)
	}
	var count int
	if err = d.QueryRow(`SELECT count(*) FROM finding_report_rewrites WHERE finding_id=$1 AND evidence_version=1 AND status='pending'`, a).Scan(&count); err != nil || count != 1 {
		t.Fatal("rewrite not durably queued", err, count)
	}
	// Same request cannot duplicate evidence/audit or hide another finding.
	if err = d.ConsolidateFindings(t.Context(), task.ID, 0, in); err == nil {
		t.Fatal("accepted stale merge")
	}
}

func TestFindingReportRewriteClaimOnPausedTaskAndExplicitRetry(t *testing.T) {
	d, task, add := collaborationDB(t)
	findingID := add("paused report")
	if err := d.SetPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO finding_report_rewrites(finding_id,evidence_version) VALUES($1,0)`, findingID); err != nil {
		t.Fatal(err)
	}
	jobID, claimedFindingID, version, err := d.ClaimFindingReportRewrite()
	if err != nil || jobID == 0 || claimedFindingID != findingID || version != 0 {
		t.Fatalf("claim paused task: job=%d finding=%d version=%d err=%v", jobID, claimedFindingID, version, err)
	}
	if _, err = d.Exec(`UPDATE finding_report_rewrites SET status='failed',last_error='reporter unavailable' WHERE id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	count, err := d.RetryFindingReportRewrites(task.ID)
	if err != nil || count != 1 {
		t.Fatalf("explicit retry count=%d err=%v", count, err)
	}
	jobID, claimedFindingID, version, err = d.ClaimFindingReportRewrite()
	if err != nil || jobID == 0 || claimedFindingID != findingID || version != 0 {
		t.Fatalf("claim retried report: job=%d finding=%d version=%d err=%v", jobID, claimedFindingID, version, err)
	}
	if _, err = d.Exec(`UPDATE finding_report_rewrites SET status='completed' WHERE id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	secondFindingID := add("second paused report")
	thirdFindingID := add("third paused report")
	if _, err = d.Exec(`INSERT INTO finding_report_rewrites(finding_id,evidence_version) VALUES($1,0),($2,0)`, secondFindingID, thirdFindingID); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	var claimCount int
	var claimMu sync.Mutex
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			id, _, _, claimErr := d.ClaimFindingReportRewrite()
			if claimErr == nil && id != 0 {
				claimMu.Lock()
				claimCount++
				claimMu.Unlock()
			} else if claimErr != nil && claimErr != sql.ErrNoRows {
				t.Errorf("concurrent claim: %v", claimErr)
			}
		}()
	}
	close(start)
	wg.Wait()
	var running int
	if err = d.QueryRow(`SELECT count(*) FROM finding_report_rewrites WHERE status='running'`).Scan(&running); err != nil || claimCount != 1 || running != 1 {
		t.Fatalf("concurrent single-flight claims=%d running=%d err=%v", claimCount, running, err)
	}
}

func TestFindingConsolidationRejectsCrossTaskAndStaleEvidence(t *testing.T) {
	d, task, add := collaborationDB(t)
	a, b := add("a"), add("b")
	other, err := d.CreateTask("other task", "offline", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM tasks WHERE id=$1`, other.ID)
	in := ConsolidateFindingsInput{CanonicalID: a, SourceIDs: []int64{b}, Name: "unified", Summary: "summary", Severity: "high", Reason: "same root", Versions: map[string]int64{fmt.Sprint(a): 0, fmt.Sprint(b): 99}}
	if err = d.ConsolidateFindings(t.Context(), task.ID, 0, in); err == nil {
		t.Fatal("accepted stale version")
	}
	in.Versions[fmt.Sprint(b)] = 0
	_, _ = d.Exec(`UPDATE findings SET task_id=$2 WHERE id=$1`, b, other.ID)
	defer d.Exec(`DELETE FROM findings WHERE id=$1`, b)
	if err = d.ConsolidateFindings(t.Context(), task.ID, 0, in); err == nil {
		t.Fatal("accepted cross-task merge")
	}
	f, _ := d.GetFinding(a)
	if f.Name != "a" || f.EvidenceVersion != 0 {
		t.Fatalf("failed merge partially changed data: %+v", f)
	}
	var count int
	_ = d.QueryRow(`SELECT count(*) FROM finding_consolidations WHERE canonical_id=$1`, a).Scan(&count)
	if count != 0 {
		t.Fatal("audit committed on rollback")
	}
}

func TestFindingRelationsScopeCyclesAndMergeBoundary(t *testing.T) {
	d, task, add := collaborationDB(t)
	a, b, c := add("condition"), add("capability"), add("impact")
	edge := FindingRelation{Source: a, Target: b, Kind: "prerequisite", Rationale: "needs condition", Evidence: "stored trace", Status: "verified"}
	if _, err := d.SaveFindingRelation(t.Context(), task.ID, edge); err != nil {
		t.Fatal(err)
	}
	edge.Source, edge.Target = b, c
	if _, err := d.SaveFindingRelation(t.Context(), task.ID, edge); err != nil {
		t.Fatal(err)
	}
	edge.Source, edge.Target = c, a
	if _, err := d.SaveFindingRelation(t.Context(), task.ID, edge); err == nil {
		t.Fatal("accepted dependency cycle")
	}
	edge.Source, edge.Target = a, a
	if _, err := d.SaveFindingRelation(t.Context(), task.ID, edge); err == nil {
		t.Fatal("accepted self edge")
	}
	in := ConsolidateFindingsInput{CanonicalID: a, SourceIDs: []int64{b}, Name: "unified", Summary: "summary", Severity: "high", Reason: "same root", Versions: map[string]int64{fmt.Sprint(a): 0, fmt.Sprint(b): 0}}
	if err := d.ConsolidateFindings(t.Context(), task.ID, 0, in); err == nil {
		t.Fatal("collapsed dependency endpoints")
	}
	nodes, edges, err := d.FindingGraph(task.ID)
	if err != nil || len(nodes) != 3 || len(edges) != 2 {
		t.Fatalf("graph=%v %v %v", nodes, edges, err)
	}
	raw, _ := json.Marshal(edges)
	if !strings.Contains(string(raw), `"source"`) || strings.Contains(string(raw), `"Source"`) {
		t.Fatal("frontend contract", string(raw))
	}
}

func TestFindingReviewBatchWatermarksAndFailureRetry(t *testing.T) {
	d, task, add := collaborationDB(t)
	add("one")
	add("two")
	id, _, err := d.BeginFindingReview(t.Context(), task.ID, false)
	if err != nil || id != 0 {
		t.Fatal("premature review", id, err)
	}
	third := add("three")
	id, cutoff, err := d.BeginFindingReview(t.Context(), task.ID, false)
	if err != nil || id == 0 || cutoff != third {
		t.Fatal("batch not triggered", id, cutoff, err)
	}
	dupe, _, err := d.BeginFindingReview(t.Context(), task.ID, true)
	if err != nil || dupe != 0 {
		t.Fatal("duplicate active review", dupe, err)
	}
	add("while running")
	if err = d.FinishFindingReview(t.Context(), id, true, "all evidence checked, distinct causes"); err != nil {
		t.Fatal(err)
	}
	status, err := d.FindingReviewStatus(task.ID)
	if err != nil || status.PendingCount != 1 || status.Running {
		t.Fatal(status, err)
	}
	id, _, err = d.BeginFindingReview(t.Context(), task.ID, true)
	if err != nil || id == 0 {
		t.Fatal(id, err)
	}
	if err = d.FinishFindingReview(t.Context(), id, false, "interrupted"); err != nil {
		t.Fatal(err)
	}
	id, _, err = d.BeginFindingReview(t.Context(), task.ID, false)
	if err != nil || id != 0 {
		t.Fatal("failed batch auto retried", id, err)
	}
	id, _, err = d.BeginFindingReview(t.Context(), task.ID, true)
	if err != nil || id == 0 {
		t.Fatal("manual retry blocked", id, err)
	}
}

func TestFindingCollaborationArchiveRoundTrip(t *testing.T) {
	d, task, add := collaborationDB(t)
	if err := d.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	a, b, c := add("scope extension"), add("canonical later record"), add("independent cause")
	in := ConsolidateFindingsInput{CanonicalID: b, SourceIDs: []int64{a}, Name: "one root cause", Summary: "whole impact", Severity: "high", Reason: "same remediation", Versions: map[string]int64{fmt.Sprint(a): 0, fmt.Sprint(b): 0}}
	if err := d.ConsolidateFindings(t.Context(), task.ID, 0, in); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SaveFindingRelation(t.Context(), task.ID, FindingRelation{Source: b, Target: c, Kind: "enables", Rationale: "provides capability", Evidence: "stored evidence", Status: "proposed"}); err != nil {
		t.Fatal(err)
	}
	if err := d.SetPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	ar, err := d.QueueTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM task_archives WHERE id=$1`, ar.ID) })
	if _, err = d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := d.SnapshotTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.CompleteTaskArchive(ar.ID, snapshot, "/tmp/offline-test.tar.zst", "fixture", 1, 1); err != nil {
		t.Fatal(err)
	}
	if _, err = d.QueueTaskArchiveRestore(ar.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err = d.RestoreTaskArchive(ar.ID, snapshot, 0); err != nil {
		t.Fatal(err)
	}
	nodes, edges, err := d.FindingGraph(task.ID)
	if err != nil || len(nodes) != 2 || len(edges) != 1 {
		t.Fatal(nodes, edges, err)
	}
	var n int
	if err = d.QueryRow(`SELECT count(*) FROM finding_consolidations WHERE canonical_id=$1`, b).Scan(&n); err != nil || n != 1 {
		t.Fatal("audit lost", n, err)
	}
	if err = d.QueryRow(`SELECT count(*) FROM finding_report_rewrites WHERE finding_id=$1`, b).Scan(&n); err != nil || n != 1 {
		t.Fatal("rewrite lost", n, err)
	}
	// Deletion of the unified finding must also remove retained source nodes.
	if _, err = d.Exec(`DELETE FROM task_archives WHERE id=$1`, ar.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.DeleteFinding(b); err != nil {
		t.Fatal("logical finding deletion", err)
	}
	if f, _ := d.GetFinding(a); f != nil {
		t.Fatal("orphaned source record")
	}
}
