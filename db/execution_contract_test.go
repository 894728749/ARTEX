package db

import (
	"fmt"
	"sync"
	"testing"
)

func executionFixture(t *testing.T) (*DB, *Task, *ExplorationStore) {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTask("execution contract", "offline synthetic test", nil, 0, 0)
	if err != nil {
		d.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID)
		_, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, task.ExplorationID)
		d.Close()
	})
	return d, task, d.Exploration(task.ExplorationID)
}
func executionEvidence(t *testing.T, s *ExplorationStore) EvidenceReference {
	t.Helper()
	id, err := s.AddNode(KindFact, map[string]any{"summary": "synthetic negative observation", "evidence": "fixture: response=denied", "confidence": "observed"}, 0, "confirmed", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.GetNode(id)
	if err != nil {
		t.Fatal(err)
	}
	return EvidenceReference{NodeID: id, Version: n.EvidenceVersion}
}
func executionWork(t *testing.T, s *ExplorationStore, name string, c WorkContract) int64 {
	t.Helper()
	id, err := s.AddWorkIntent(t.Context(), name, 5, nil, nil, c)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func executionAttempt(t *testing.T, s *ExplorationStore, id int64) int64 {
	t.Helper()
	ok, err := s.ClaimIntent(id, "test")
	if err != nil || !ok {
		t.Fatalf("claim %d=%v %v", id, ok, err)
	}
	n, err := s.BeginIntentAttempt(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	_, attempt := IntentContract(n)
	return attempt
}

func TestExecutionContractAdmissionAndDependencies(t *testing.T) {
	d, _, s := executionFixture(t)
	first := executionWork(t, s, "first", WorkContract{Acceptance: []string{"check denied"}, ResourceKey: "account"})
	downstream := executionWork(t, s, "dependent", WorkContract{DependsOn: []int64{first}, ResourceKey: "account"})
	n, _ := s.GetNode(downstream)
	if n.State != "waiting" {
		t.Fatal(n.State)
	}
	if ok, err := s.ClaimIntent(downstream, "early"); ok || err != nil {
		t.Fatalf("premature %v %v", ok, err)
	}
	attempt := executionAttempt(t, s, first)
	other := executionWork(t, s, "same resource", WorkContract{ResourceKey: "account"})
	if ok, err := s.ClaimIntent(other, "racy"); ok || err != nil {
		t.Fatalf("resource collision %v %v", ok, err)
	}
	// A blocked top window must not hide unrelated runnable work.
	for i := 0; i < 25; i++ {
		executionWork(t, s, fmt.Sprintf("blocked %d", i), WorkContract{DependsOn: []int64{first}})
	}
	independent := executionWork(t, s, "independent", WorkContract{})
	picked, err := s.ClaimNextIntent(t.Context(), "free")
	if err != nil || picked == nil || picked.ID != independent {
		t.Fatalf("ready selection %+v %v", picked, err)
	}
	ref := executionEvidence(t, s)
	result := IntentResult{Outcome: "negative", Summary: "hypothesis disproved", Evidence: []EvidenceReference{ref}, Satisfied: []string{"check denied"}}
	if err = s.SubmitIntentResult(t.Context(), first, attempt, result); err != nil {
		t.Fatal(err)
	}
	state, err := s.FinishIntentAttempt(t.Context(), first, attempt, "done")
	if err != nil || state != "done" {
		t.Fatalf("finish=%s %v", state, err)
	}
	if ok, err := s.ClaimIntent(downstream, "ready"); !ok || err != nil {
		t.Fatalf("dependency never ready %v %v", ok, err)
	}
	var before, after int
	_ = d.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1`, s.ID()).Scan(&before)
	if _, err = s.AddWorkIntent(t.Context(), "bad anchor", 5, []int64{999999999}, nil, WorkContract{}); err == nil {
		t.Fatal("invalid anchor accepted")
	}
	_ = d.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1`, s.ID()).Scan(&after)
	if before != after {
		t.Fatal("partial admission left an orphan")
	}
}

func TestExecutionContractDedupAndResourceRace(t *testing.T) {
	_, _, s := executionFixture(t)
	ref := executionEvidence(t, s)
	ids := make(chan int64, 8)
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := s.AddWorkIntent(t.Context(), "stable", 5, nil, []int64{ref.NodeID, ref.NodeID}, WorkContract{DirectionKey: "fixture"})
			ids <- id
			errs <- err
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)
	var expected int64
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for id := range ids {
		if expected == 0 {
			expected = id
		}
		if id != expected {
			t.Fatal("duplicate work", id, expected)
		}
	}
	_ = s.SetNodeState(ref.NodeID, "dismissed")
	fresh, err := s.AddWorkIntent(t.Context(), "stable", 5, nil, []int64{ref.NodeID}, WorkContract{DirectionKey: "fixture"})
	if err != nil || fresh == expected {
		t.Fatalf("changed input not distinct: %d %v", fresh, err)
	}
	a := executionWork(t, s, "resource A", WorkContract{ResourceKey: "mutex"})
	b := executionWork(t, s, "resource B", WorkContract{ResourceKey: "mutex"})
	wins := make(chan bool, 2)
	for _, id := range []int64{a, b} {
		wg.Add(1)
		go func(id int64) {
			defer wg.Done()
			ok, err := s.ClaimIntent(id, "concurrent")
			if err != nil {
				t.Errorf("resource claim: %v", err)
			}
			wins <- ok
		}(id)
	}
	wg.Wait()
	close(wins)
	count := 0
	for ok := range wins {
		if ok {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("resource claims won=%d", count)
	}
}

func TestExecutionContractResultsAndGoalProof(t *testing.T) {
	d, _, s := executionFixture(t)
	ref := executionEvidence(t, s)
	missing := executionWork(t, s, "missing result", WorkContract{})
	attempt := executionAttempt(t, s, missing)
	if state, err := s.FinishIntentAttempt(t.Context(), missing, attempt, "done"); err != nil || state != "blocked" {
		t.Fatalf("empty return=%s %v", state, err)
	}
	if err := s.RetryWorkIntent(t.Context(), missing, "fixture service recovered, resume missing result"); err != nil {
		t.Fatal(err)
	}
	attempt = executionAttempt(t, s, missing)
	if state, err := s.FinishIntentAttempt(t.Context(), missing, attempt, "done"); err != nil || state != "blocked" {
		t.Fatal(state, err)
	}
	if err := s.RetryWorkIntent(t.Context(), missing, "repeat"); err == nil {
		t.Fatal("unbounded automatic retry accepted")
	}
	id := executionWork(t, s, "verified", WorkContract{Acceptance: []string{"exact condition"}})
	attempt = executionAttempt(t, s, id)
	r := IntentResult{Outcome: "succeeded", Summary: "checked", Evidence: []EvidenceReference{ref}}
	if err := s.SubmitIntentResult(t.Context(), id, attempt, r); err == nil {
		t.Fatal("missing acceptance accepted")
	}
	r.Satisfied = []string{"exact condition"}
	if err := s.SubmitIntentResult(t.Context(), id, attempt+1, r); err == nil {
		t.Fatal("stale attempt accepted")
	}
	if err := s.SubmitIntentResult(t.Context(), id, attempt, r); err != nil {
		t.Fatal(err)
	}
	_, _ = d.Exec(`UPDATE exploration_nodes SET payload=payload||'{"evidence":"changed"}'::jsonb WHERE id=$1`, ref.NodeID)
	if state, err := s.FinishIntentAttempt(t.Context(), id, attempt, "done"); err != nil || state != "blocked" {
		t.Fatalf("stale evidence=%s %v", state, err)
	}
	goal, err := s.AddGoal(map[string]any{"text": "fixture goal"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ProveGoal(t.Context(), goal, ref, "stale proof", executionGoalVersion(t, s, goal)); err == nil {
		t.Fatal("stale goal proof accepted")
	}
	n, _ := s.GetNode(ref.NodeID)
	ref.Version = n.EvidenceVersion
	if all, err := s.ProveGoal(t.Context(), goal, ref, "exact condition proven by fixture", executionGoalVersion(t, s, goal)); err != nil || !all {
		t.Fatalf("proof %v %v", all, err)
	}
	if err = s.UpdateGoalPayload(goal, "changed condition", ""); err != nil {
		t.Fatal(err)
	}
	n, _ = s.GetNode(goal)
	if n.State != "open" {
		t.Fatal("edited proof remained met")
	}
	oldVersion := n.EvidenceVersion
	_ = s.UpdateGoalPayload(goal, "another condition", "")
	if _, err = s.ProveGoal(t.Context(), goal, ref, "old condition", oldVersion); err == nil {
		t.Fatal("stale goal definition accepted")
	}
	for _, state := range []string{"origin", "dismissed"} {
		bad, err := s.AddNode(KindFact, map[string]any{"evidence": "fixture"}, 0, state, "test", nil)
		if err != nil {
			t.Fatal(err)
		}
		bn, _ := s.GetNode(bad)
		if _, err = s.ProveGoal(t.Context(), goal, EvidenceReference{bad, bn.EvidenceVersion}, "bad", executionGoalVersion(t, s, goal)); err == nil {
			t.Fatal("invalid evidence accepted", state)
		}
	}
	inferred, _ := s.AddNode(KindFact, map[string]any{"evidence": "fixture", "confidence": "inferred"}, 0, "confirmed", "test", nil)
	n, _ = s.GetNode(inferred)
	if _, err = s.ProveGoal(t.Context(), goal, EvidenceReference{inferred, n.EvidenceVersion}, "guess", executionGoalVersion(t, s, goal)); err == nil {
		t.Fatal("inferred proof accepted")
	}
}

func TestExecutionPlanningWaitAndFinalization(t *testing.T) {
	d, task, s := executionFixture(t)
	if err := s.RecordPlanningDecision(t.Context(), PlanningDecision{Kind: "waiting", Reason: "need fixture", ResumeWhen: "new fact"}); err != nil {
		t.Fatal(err)
	}
	if wait, err := s.PlanningWaitUnchanged(t.Context()); err != nil || !wait {
		t.Fatalf("waiting=%v %v", wait, err)
	}
	ref := executionEvidence(t, s)
	if wait, err := s.PlanningWaitUnchanged(t.Context()); err != nil || wait {
		t.Fatalf("new fact ignored=%v %v", wait, err)
	}
	goal, _ := s.AddGoal(map[string]any{"text": "finish fixture"}, "test")
	_, err := s.ProveGoal(t.Context(), goal, ref, "fixture complete", executionGoalVersion(t, s, goal))
	if err != nil {
		t.Fatal(err)
	}
	running := executionWork(t, s, "running", WorkContract{})
	executionAttempt(t, s, running)
	queued := executionWork(t, s, "queued", WorkContract{})
	_ = d.SetStatus(task.ID, "running")
	status, err := d.AdvanceGoalFinalization(t.Context(), task.ID, true)
	if err != nil || status != "finalizing" {
		t.Fatalf("begin %s %v", status, err)
	}
	if status, err = d.AdvanceGoalFinalization(t.Context(), task.ID, false); err != nil || status != "finalizing" {
		t.Fatalf("completed over active tool %s %v", status, err)
	}
	_ = d.SetPaused(task.ID, true)
	_ = s.SetIntentState(running, "stopped")
	if status, err = d.AdvanceGoalFinalization(t.Context(), task.ID, false); err != nil || status != "finalizing" {
		t.Fatalf("pause lost %s %v", status, err)
	}
	_ = d.SetPaused(task.ID, false)
	_, _ = s.AddGoal(map[string]any{"text": "new goal"}, "test")
	if status, err = d.AdvanceGoalFinalization(t.Context(), task.ID, false); err != nil || status != "running" {
		t.Fatalf("new goal lost %s %v", status, err)
	}
	goals, _ := s.ListByKind(KindGoal, 100)
	for _, g := range goals {
		if g.State == "open" {
			if _, err = s.ProveGoal(t.Context(), g.ID, ref, "fixture complete", executionGoalVersion(t, s, g.ID)); err != nil {
				t.Fatal(err)
			}
		}
	}
	_, _ = d.AdvanceGoalFinalization(t.Context(), task.ID, true)
	if status, err = d.AdvanceGoalFinalization(t.Context(), task.ID, false); err != nil || status != "done" {
		t.Fatalf("drain %s %v", status, err)
	}
	n, _ := s.GetNode(queued)
	if n.State != "stopped" {
		t.Fatal("queued work left claimable", n.State)
	}
}

func executionGoalVersion(t *testing.T, s *ExplorationStore, id int64) string {
	t.Helper()
	n, err := s.GetNode(id)
	if err != nil || n == nil {
		t.Fatal(err)
	}
	return n.EvidenceVersion
}
