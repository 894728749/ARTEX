package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func workflowRequestFixture(t *testing.T) (*DB, *Task, *Task) {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	makeTask := func(kind string) *Task {
		task, e := d.CreateTaskWithOptions("workflow request test", "offline", TaskCreateOptions{Kind: kind})
		if e != nil {
			t.Fatal(e)
		}
		return task
	}
	source, target := makeTask("pentest"), makeTask("reverse")
	t.Cleanup(func() {
		_, _ = d.DeleteTaskCascade(source.ID, false, false)
		_, _ = d.DeleteTaskCascade(target.ID, false, false)
		_ = d.Close()
	})
	return d, source, target
}

func workflowRequestInput(source, target int64, key string) WorkflowRequestInput {
	return WorkflowRequestInput{RequestKey: key, SourceTaskID: source, TargetTaskID: target, Question: "Verify the selected parser behavior", Acceptance: []string{"state the behavior", "cite selected evidence"}, InputSnapshot: json.RawMessage(`{"artifact_id":42,"evidence":["sample.js:parse()"]}`), BudgetSeconds: 60}
}

func TestWorkflowRequestCreateIdempotencyAndDirection(t *testing.T) {
	d, source, target := workflowRequestFixture(t)
	ctx := context.Background()
	first, created, err := d.CreateWorkflowRequest(ctx, workflowRequestInput(source.ID, target.ID, " review-1 "))
	if err != nil || !created || first.Status != "pending" || first.Depth != 1 {
		t.Fatalf("first=%+v created=%v err=%v", first, created, err)
	}
	if first.RequestKey != "review-1" {
		t.Fatalf("request key was not canonicalized: %q", first.RequestKey)
	}
	second, created, err := d.CreateWorkflowRequest(ctx, workflowRequestInput(source.ID, target.ID, "review-1"))
	if err != nil || created || second.ID != first.ID {
		t.Fatalf("idempotent=%+v created=%v err=%v", second, created, err)
	}
	changed := workflowRequestInput(source.ID, target.ID, "review-1")
	changed.Question = "different question"
	if _, _, err = d.CreateWorkflowRequest(ctx, changed); !errors.Is(err, ErrWorkflowRequestConflict) {
		t.Fatalf("changed key content err=%v", err)
	}
	changed = workflowRequestInput(source.ID, target.ID, "review-1")
	changed.BudgetSeconds++
	if _, _, err = d.CreateWorkflowRequest(ctx, changed); !errors.Is(err, ErrWorkflowRequestConflict) {
		t.Fatalf("changed key budget err=%v", err)
	}
	rows, err := d.ListWorkflowRequests(ctx, source.ID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("source list=%d err=%v", len(rows), err)
	}
	rows, err = d.ListWorkflowRequests(ctx, target.ID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("target list=%d err=%v", len(rows), err)
	}
	if _, _, err = d.CreateWorkflowRequest(ctx, WorkflowRequestInput{RequestKey: "same-kind", SourceTaskID: source.ID, TargetTaskID: source.ID + 999999, Question: "q", Acceptance: []string{"a"}, InputSnapshot: json.RawMessage(`{}`), BudgetSeconds: 2}); err == nil {
		t.Fatal("missing target task accepted")
	}
}

func TestWorkflowRequestParentBudgetDepthAndTerminalOperations(t *testing.T) {
	d, source, target := workflowRequestFixture(t)
	ctx := context.Background()
	rootInput := workflowRequestInput(source.ID, target.ID, "root")
	rootInput.BudgetSeconds = 20
	root, _, err := d.CreateWorkflowRequest(ctx, rootInput)
	if err != nil {
		t.Fatal(err)
	}
	childInput := workflowRequestInput(target.ID, source.ID, "child")
	childInput.BudgetSeconds = 120
	childInput.ParentRequestID = &root.ID
	child, created, err := d.CreateWorkflowRequest(ctx, childInput)
	if err != nil || !created || child.Depth != 2 || child.BudgetSeconds > root.BudgetSeconds || child.ExpiresAt.After(root.ExpiresAt) {
		t.Fatalf("child=%+v created=%v err=%v", child, created, err)
	}
	thirdInput := workflowRequestInput(source.ID, target.ID, "third")
	thirdInput.ParentRequestID = &child.ID
	third, _, err := d.CreateWorkflowRequest(ctx, thirdInput)
	if err != nil || third.Depth != 3 {
		t.Fatalf("third=%+v err=%v", third, err)
	}
	fourthInput := workflowRequestInput(target.ID, source.ID, "fourth")
	fourthInput.ParentRequestID = &third.ID
	if _, _, err = d.CreateWorkflowRequest(ctx, fourthInput); !errors.Is(err, ErrWorkflowRequestInvalid) {
		t.Fatalf("depth 4 err=%v", err)
	}
	badResult := json.RawMessage(`{"summary":"done"}`)
	if err = d.CompleteWorkflowRequest(ctx, root.ID, target.ID, badResult); !errors.Is(err, ErrWorkflowRequestInvalid) {
		t.Fatalf("missing evidence err=%v", err)
	}
	result := json.RawMessage(`{"summary":"parser behavior verified","evidence":[{"artifact_id":42,"claim":"parse() accepts source"}]}`)
	if err = d.CompleteWorkflowRequest(ctx, root.ID, target.ID, result); err != nil {
		t.Fatal(err)
	}
	if err = d.CompleteWorkflowRequest(ctx, root.ID, target.ID, result); err != nil {
		t.Fatalf("same-result retry: %v", err)
	}
	if err = d.CancelWorkflowRequest(ctx, root.ID, source.ID); !errors.Is(err, ErrWorkflowRequestTerminal) {
		t.Fatalf("terminal cancel err=%v", err)
	}
	if err = d.CompleteWorkflowRequest(ctx, child.ID, target.ID, result); !errors.Is(err, ErrWorkflowRequestDenied) {
		t.Fatalf("wrong target err=%v", err)
	}
	if err = d.CancelWorkflowRequest(ctx, child.ID, target.ID); err != nil {
		t.Fatal(err)
	}
	if err = d.CancelWorkflowRequest(ctx, child.ID, target.ID); err != nil {
		t.Fatalf("cancel retry: %v", err)
	}
}

func TestWorkflowRequestParentBudgetIncludesCancelledAndCompletedChildren(t *testing.T) {
	d, source, target := workflowRequestFixture(t)
	ctx := context.Background()
	rootInput := workflowRequestInput(source.ID, target.ID, "budget-root")
	rootInput.BudgetSeconds = 30
	root, _, err := d.CreateWorkflowRequest(ctx, rootInput)
	if err != nil {
		t.Fatal(err)
	}
	firstInput := workflowRequestInput(target.ID, source.ID, "budget-child-1")
	firstInput.BudgetSeconds = 15
	firstInput.ParentRequestID = &root.ID
	first, _, err := d.CreateWorkflowRequest(ctx, firstInput)
	if err != nil {
		t.Fatal(err)
	}
	secondInput := workflowRequestInput(target.ID, source.ID, "budget-child-2")
	secondInput.BudgetSeconds = 20
	secondInput.ParentRequestID = &root.ID
	second, _, err := d.CreateWorkflowRequest(ctx, secondInput)
	if err != nil {
		t.Fatal(err)
	}
	if first.BudgetSeconds+second.BudgetSeconds != root.BudgetSeconds {
		t.Fatalf("allocated child budget=%d, parent budget=%d", first.BudgetSeconds+second.BudgetSeconds, root.BudgetSeconds)
	}
	if err = d.CancelWorkflowRequest(ctx, first.ID, target.ID); err != nil {
		t.Fatal(err)
	}
	result := json.RawMessage(`{"summary":"bounded response","evidence":["selected evidence"]}`)
	if err = d.CompleteWorkflowRequest(ctx, second.ID, source.ID, result); err != nil {
		t.Fatal(err)
	}
	thirdInput := workflowRequestInput(target.ID, source.ID, "budget-child-3")
	thirdInput.BudgetSeconds = 1
	thirdInput.ParentRequestID = &root.ID
	if _, _, err = d.CreateWorkflowRequest(ctx, thirdInput); !errors.Is(err, ErrWorkflowRequestInvalid) {
		t.Fatalf("spent budget was reused after terminal children: %v", err)
	}
	var allocated int
	if err = d.QueryRowContext(ctx, `SELECT sum(budget_seconds) FROM workflow_requests WHERE parent_request_id=$1`, root.ID).Scan(&allocated); err != nil {
		t.Fatal(err)
	}
	if allocated != root.BudgetSeconds {
		t.Fatalf("persisted allocation=%d, parent budget=%d", allocated, root.BudgetSeconds)
	}
}

func TestWorkflowRequestCannotCompleteAfterExpiry(t *testing.T) {
	d, source, target := workflowRequestFixture(t)
	ctx := context.Background()
	r, _, err := d.CreateWorkflowRequest(ctx, workflowRequestInput(source.ID, target.ID, "completion-after-expiry"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.ExecContext(ctx, `UPDATE workflow_requests SET expires_at=now()-interval '1 second' WHERE id=$1`, r.ID); err != nil {
		t.Fatal(err)
	}
	result := json.RawMessage(`{"summary":"late","evidence":["too late"]}`)
	if err = d.CompleteWorkflowRequest(ctx, r.ID, target.ID, result); !errors.Is(err, ErrWorkflowRequestTerminal) {
		t.Fatalf("late completion err=%v", err)
	}
	got, err := d.GetWorkflowRequest(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "pending" || len(got.Result) != 0 {
		t.Fatalf("late completion overwrote request: %+v", got)
	}
	rows, err := d.ExpireWorkflowRequests(ctx)
	if err != nil || len(rows) != 1 || rows[0].ID != r.ID || rows[0].Status != "expired" {
		t.Fatalf("scheduler should receive the expired request for wakeup: rows=%v err=%v", rows, err)
	}
}

func TestWorkflowRequestBindAndExpire(t *testing.T) {
	d, source, target := workflowRequestFixture(t)
	ctx := context.Background()
	r, _, err := d.CreateWorkflowRequest(ctx, workflowRequestInput(source.ID, target.ID, "bind-expire"))
	if err != nil {
		t.Fatal(err)
	}
	insertIntent := func(task *Task) int64 {
		t.Helper()
		var id int64
		err := d.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,payload,state) VALUES($1,'intent','{}','open') RETURNING id`, task.ExplorationID).Scan(&id)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	srcIntent, dstIntent := insertIntent(source), insertIntent(target)
	if err = d.BindWorkflowRequestIntents(ctx, r.ID, srcIntent, dstIntent); err != nil {
		t.Fatal(err)
	}
	if err = d.BindWorkflowRequestIntents(ctx, r.ID, srcIntent, dstIntent); err != nil {
		t.Fatalf("same intent binding retry: %v", err)
	}
	if err = d.BindWorkflowRequestIntents(ctx, r.ID, dstIntent, srcIntent); !errors.Is(err, ErrWorkflowRequestConflict) {
		t.Fatalf("different rebinding err=%v", err)
	}
	if _, err = d.ExecContext(ctx, `UPDATE workflow_requests SET expires_at=now()-interval '1 second' WHERE id=$1`, r.ID); err != nil {
		t.Fatal(err)
	}
	expired, err := d.ExpireWorkflowRequests(ctx)
	if err != nil || len(expired) != 1 || expired[0].ID != r.ID || expired[0].Status != "expired" {
		t.Fatalf("expired=%+v err=%v", expired, err)
	}
	if again, err := d.ExpireWorkflowRequests(ctx); err != nil || len(again) != 0 {
		t.Fatalf("repeat expiry=%v err=%v", again, err)
	}
}

func TestWorkflowRequestRejectsMalformedAndOversizedInput(t *testing.T) {
	d, source, target := workflowRequestFixture(t)
	ctx := context.Background()
	for name, in := range map[string]WorkflowRequestInput{
		"invalid-json": {RequestKey: "bad-json", SourceTaskID: source.ID, TargetTaskID: target.ID, Question: "q", Acceptance: []string{"a"}, InputSnapshot: json.RawMessage(`{} {}`), BudgetSeconds: 1},
		"oversized":    {RequestKey: "large", SourceTaskID: source.ID, TargetTaskID: target.ID, Question: "q", Acceptance: []string{"a"}, InputSnapshot: json.RawMessage(fmt.Sprintf(`{"x":%q}`, strings.Repeat("x", maxWorkflowSnapshotBytes))), BudgetSeconds: 1},
	} {
		if _, _, err := d.CreateWorkflowRequest(ctx, in); !errors.Is(err, ErrWorkflowRequestInvalid) {
			t.Errorf("%s err=%v", name, err)
		}
	}
	for name, acceptance := range map[string][]string{"nil": nil, "empty": {}, "blank": {"  "}} {
		in := workflowRequestInput(source.ID, target.ID, "acceptance-"+name)
		in.Acceptance = acceptance
		if _, _, err := d.CreateWorkflowRequest(ctx, in); !errors.Is(err, ErrWorkflowRequestInvalid) {
			t.Errorf("acceptance %s err=%v", name, err)
		}
	}
	terminal, err := d.CreateTaskWithOptions("terminal", "offline", TaskCreateOptions{Kind: "reverse"})
	if err != nil {
		t.Fatal(err)
	}
	if err = d.SetStatus(terminal.ID, "done"); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = d.DeleteTaskCascade(terminal.ID, false, false) }()
	if _, _, err = d.CreateWorkflowRequest(ctx, workflowRequestInput(source.ID, terminal.ID, "terminal-target")); !errors.Is(err, ErrWorkflowRequestInvalid) {
		t.Fatalf("terminal target err=%v", err)
	}
	if _, err := d.GetWorkflowRequest(ctx, 1<<60); !errors.Is(err, ErrWorkflowRequestNotFound) {
		t.Fatalf("missing get err=%v", err)
	}
}
