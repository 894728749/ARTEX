package db

import "testing"

func TestReverseDependencyFailureAndRecovery(t *testing.T) {
	d, task, s := executionFixtureKind(t, "reverse")
	d.Exec(`UPDATE tasks SET paused=false WHERE id=$1`, task.ID)
	parent := executionWork(t, s, "parent", WorkContract{})
	child := executionWork(t, s, "child", WorkContract{DependsOn: []int64{parent}})
	grand := executionWork(t, s, "grand", WorkContract{DependsOn: []int64{child}})
	d.Exec(`UPDATE exploration_nodes SET state='exhausted' WHERE id=$1`, parent)
	if _, err := s.ReconcileIntentDependencies(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{child, grand} {
		n, _ := s.GetNode(id)
		if n.State != "blocked" || n.BlockedReason != "dependency_failed" {
			t.Fatalf("unpropagated %+v", n)
		}
	}
	if err := s.RetryWorkIntent(t.Context(), parent, "continue saved checkpoint"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReconcileIntentDependencies(t.Context()); err != nil {
		t.Fatal(err)
	}
	n, _ := s.GetNode(child)
	if n.State != "waiting" {
		t.Fatalf("child %s", n.State)
	}
	d.Exec(`UPDATE exploration_nodes SET state='done' WHERE id=$1`, parent)
	if _, err := s.ReconcileIntentDependencies(t.Context()); err != nil {
		t.Fatal(err)
	}
	n, _ = s.GetNode(child)
	if n.State != "open" {
		t.Fatalf("child %s", n.State)
	}
	n, _ = s.GetNode(grand)
	if n.State != "waiting" {
		t.Fatalf("grand %s", n.State)
	}
	// Reconciliation is stable and does not keep waking the planner.
	if changed, err := s.ReconcileIntentDependencies(t.Context()); err != nil || changed != 0 {
		t.Fatalf("changed %d %v", changed, err)
	}
}
