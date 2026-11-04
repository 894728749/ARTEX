package db

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"
)

var (
	ErrWorkflowRequestInvalid  = errors.New("invalid workflow request")
	ErrWorkflowRequestConflict = errors.New("workflow request key conflicts with existing request")
	ErrWorkflowRequestNotFound = errors.New("workflow request not found")
	ErrWorkflowRequestDenied   = errors.New("workflow request operation not permitted")
	ErrWorkflowRequestTerminal = errors.New("workflow request is already terminal")
)

const (
	maxWorkflowSnapshotBytes = 64 << 10
	maxWorkflowResultBytes   = 64 << 10
	maxWorkflowAcceptance    = 32
)

// WorkflowRequest is a bounded, task-to-task handoff. InputSnapshot is only the
// caller-selected material for this question; it is not task context sharing.
type WorkflowRequest struct {
	ID              int64           `json:"id"`
	RequestKey      string          `json:"request_key"`
	SourceTaskID    int64           `json:"source_task_id"`
	TargetTaskID    int64           `json:"target_task_id"`
	SourceIntentID  *int64          `json:"source_intent_id,omitempty"`
	TargetIntentID  *int64          `json:"target_intent_id,omitempty"`
	Question        string          `json:"question"`
	Acceptance      []string        `json:"acceptance"`
	InputSnapshot   json.RawMessage `json:"input_snapshot"`
	Status          string          `json:"status"`
	Result          json.RawMessage `json:"result,omitempty"`
	BudgetSeconds   int             `json:"budget_seconds"`
	Depth           int             `json:"depth"`
	ParentRequestID *int64          `json:"parent_request_id,omitempty"`
	ExpiresAt       time.Time       `json:"expires_at"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// WorkflowRequestInput is the caller-supplied portion of a handoff.
type WorkflowRequestInput struct {
	RequestKey      string          `json:"request_key"`
	SourceTaskID    int64           `json:"source_task_id"`
	TargetTaskID    int64           `json:"target_task_id"`
	Question        string          `json:"question"`
	Acceptance      []string        `json:"acceptance"`
	InputSnapshot   json.RawMessage `json:"input_snapshot"`
	BudgetSeconds   int             `json:"budget_seconds"`
	ParentRequestID *int64          `json:"parent_request_id,omitempty"`
	ExpiresAt       time.Time       `json:"expires_at,omitempty"`
}

const workflowRequestCols = `id,request_key,source_task_id,target_task_id,source_intent_id,target_intent_id,
 question,acceptance,input_snapshot,status,result,budget_seconds,depth,parent_request_id,expires_at,created_at,updated_at`

func scanWorkflowRequest(row interface{ Scan(...any) error }) (*WorkflowRequest, error) {
	r := new(WorkflowRequest)
	var srcIntent, dstIntent, parent sql.NullInt64
	var acceptance, snapshot, result []byte
	if err := row.Scan(&r.ID, &r.RequestKey, &r.SourceTaskID, &r.TargetTaskID, &srcIntent, &dstIntent,
		&r.Question, &acceptance, &snapshot, &r.Status, &result, &r.BudgetSeconds, &r.Depth, &parent,
		&r.ExpiresAt, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	if srcIntent.Valid {
		r.SourceIntentID = &srcIntent.Int64
	}
	if dstIntent.Valid {
		r.TargetIntentID = &dstIntent.Int64
	}
	if parent.Valid {
		r.ParentRequestID = &parent.Int64
	}
	r.Acceptance = []string{}
	if err := json.Unmarshal(acceptance, &r.Acceptance); err != nil {
		return nil, err
	}
	r.InputSnapshot = append(json.RawMessage(nil), snapshot...)
	if len(result) > 0 {
		r.Result = append(json.RawMessage(nil), result...)
	}
	return r, nil
}

func canonicalJSON(raw json.RawMessage, max int, objectOrArray bool) (json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > max {
		return nil, fmt.Errorf("%w: JSON size", ErrWorkflowRequestInvalid)
	}
	var value any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return nil, fmt.Errorf("%w: malformed JSON: %v", ErrWorkflowRequestInvalid, err)
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing JSON", ErrWorkflowRequestInvalid)
	}
	if objectOrArray {
		switch value.(type) {
		case map[string]any, []any:
		default:
			return nil, fmt.Errorf("%w: expected object or array JSON", ErrWorkflowRequestInvalid)
		}
	}
	b, err := json.Marshal(value)
	return b, err
}

func workflowPayloadEqual(a, b json.RawMessage) bool {
	ca, ea := canonicalJSON(a, maxWorkflowSnapshotBytes, false)
	cb, eb := canonicalJSON(b, maxWorkflowSnapshotBytes, false)
	return ea == nil && eb == nil && bytes.Equal(ca, cb)
}

func validateWorkflowInput(in WorkflowRequestInput) (WorkflowRequestInput, json.RawMessage, error) {
	in.RequestKey = strings.TrimSpace(in.RequestKey)
	in.Question = strings.TrimSpace(in.Question)
	if len(in.Acceptance) == 0 || in.RequestKey == "" || len(in.RequestKey) > 160 || in.SourceTaskID <= 0 || in.TargetTaskID <= 0 || in.SourceTaskID == in.TargetTaskID || in.Question == "" || len(in.Question) > 4000 || in.BudgetSeconds < 1 || in.BudgetSeconds > 3600 || len(in.Acceptance) > maxWorkflowAcceptance {
		return in, nil, fmt.Errorf("%w: field bounds", ErrWorkflowRequestInvalid)
	}
	for i := range in.Acceptance {
		in.Acceptance[i] = strings.TrimSpace(in.Acceptance[i])
		if in.Acceptance[i] == "" || len(in.Acceptance[i]) > 1000 {
			return in, nil, fmt.Errorf("%w: acceptance item", ErrWorkflowRequestInvalid)
		}
	}
	snapshot, err := canonicalJSON(in.InputSnapshot, maxWorkflowSnapshotBytes, true)
	if err != nil {
		return in, nil, err
	}
	return in, snapshot, nil
}

func (d *DB) GetWorkflowRequest(ctx context.Context, id int64) (*WorkflowRequest, error) {
	r, err := scanWorkflowRequest(d.QueryRowContext(ctx, `SELECT `+workflowRequestCols+` FROM workflow_requests WHERE id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrWorkflowRequestNotFound
	}
	return r, err
}

func (d *DB) CreateWorkflowRequest(ctx context.Context, in WorkflowRequestInput) (*WorkflowRequest, bool, error) {
	in, snapshot, err := validateWorkflowInput(in)
	if err != nil {
		return nil, false, err
	}
	acceptance, _ := json.Marshal(in.Acceptance)
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, fmt.Sprintf("workflow-request:%d:%s", in.SourceTaskID, strings.TrimSpace(in.RequestKey))); err != nil {
		return nil, false, err
	}
	// Look up the idempotency key before dynamic parent-budget calculations.
	existing, e := scanWorkflowRequest(tx.QueryRowContext(ctx, `SELECT `+workflowRequestCols+` FROM workflow_requests WHERE source_task_id=$1 AND request_key=$2`, in.SourceTaskID, strings.TrimSpace(in.RequestKey)))
	if e == nil {
		budgetMatches := existing.BudgetSeconds == in.BudgetSeconds
		if in.ParentRequestID != nil {
			budgetMatches = existing.BudgetSeconds <= in.BudgetSeconds
		}
		expiryMatches := in.ExpiresAt.IsZero() || existing.ExpiresAt.Equal(in.ExpiresAt) || (in.ParentRequestID != nil && existing.ExpiresAt.Before(in.ExpiresAt))
		if existing.TargetTaskID == in.TargetTaskID && existing.Question == strings.TrimSpace(in.Question) && reflect.DeepEqual(existing.Acceptance, in.Acceptance) && workflowPayloadEqual(existing.InputSnapshot, snapshot) && sameOptionalID(existing.ParentRequestID, in.ParentRequestID) && budgetMatches && expiryMatches {
			return existing, false, nil
		}
		return nil, false, ErrWorkflowRequestConflict
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return nil, false, e
	}
	// Lock tasks in a stable order so concurrent reciprocal requests cannot deadlock.
	ids := []int64{in.SourceTaskID, in.TargetTaskID}
	if ids[0] > ids[1] {
		ids[0], ids[1] = ids[1], ids[0]
	}
	tasks := map[int64]workflowTaskState{}
	for _, id := range ids {
		var state workflowTaskState
		if err = tx.QueryRowContext(ctx, `SELECT kind,status,deleted_at IS NOT NULL FROM tasks WHERE id=$1 FOR UPDATE`, id).Scan(&state.kind, &state.status, &state.deleted); err != nil {
			return nil, false, fmt.Errorf("workflow task %d: %w", id, err)
		}
		tasks[id] = state
	}
	src, dst := tasks[in.SourceTaskID], tasks[in.TargetTaskID]
	if src.deleted || dst.deleted || IsTerminal(src.status) || IsTerminal(dst.status) || src.kind == dst.kind || !validWorkflowKind(src.kind) || !validWorkflowKind(dst.kind) {
		return nil, false, fmt.Errorf("%w: tasks must be active and have opposite workflow kinds", ErrWorkflowRequestInvalid)
	}
	now := time.Now().UTC()
	budget := in.BudgetSeconds
	depth := 1
	expires := in.ExpiresAt
	if expires.IsZero() {
		expires = now.Add(time.Duration(budget) * time.Second)
	}
	if in.ParentRequestID != nil {
		parent, pe := scanWorkflowRequest(tx.QueryRowContext(ctx, `SELECT `+workflowRequestCols+` FROM workflow_requests WHERE id=$1 FOR UPDATE`, *in.ParentRequestID))
		if pe != nil {
			return nil, false, fmt.Errorf("parent workflow request: %w", pe)
		}
		if parent.TargetTaskID != in.SourceTaskID || parent.Status != "pending" {
			return nil, false, fmt.Errorf("%w: parent must be pending and target the source task", ErrWorkflowRequestInvalid)
		}
		depth = parent.Depth + 1
		var allocated int
		if err = tx.QueryRowContext(ctx, `SELECT COALESCE(sum(budget_seconds),0) FROM workflow_requests WHERE parent_request_id=$1`, parent.ID).Scan(&allocated); err != nil {
			return nil, false, err
		}
		remaining := parent.BudgetSeconds - allocated
		deadlineRemaining := int(parent.ExpiresAt.Sub(now).Seconds())
		if deadlineRemaining < remaining {
			remaining = deadlineRemaining
		}
		if remaining < 1 || depth > 3 {
			return nil, false, fmt.Errorf("%w: parent budget/depth exhausted", ErrWorkflowRequestInvalid)
		}
		if budget > remaining {
			budget = remaining
		}
		if expires.After(parent.ExpiresAt) {
			expires = parent.ExpiresAt
		}
	}
	if !expires.After(now) {
		return nil, false, fmt.Errorf("%w: expiry must be in the future", ErrWorkflowRequestInvalid)
	}
	if expires.After(now.Add(time.Duration(budget) * time.Second)) {
		expires = now.Add(time.Duration(budget) * time.Second)
	}
	var id int64
	err = tx.QueryRowContext(ctx, `INSERT INTO workflow_requests(request_key,source_task_id,target_task_id,question,acceptance,input_snapshot,budget_seconds,depth,parent_request_id,expires_at)
VALUES($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7,$8,$9,$10) RETURNING id`, strings.TrimSpace(in.RequestKey), in.SourceTaskID, in.TargetTaskID, strings.TrimSpace(in.Question), acceptance, snapshot, budget, depth, in.ParentRequestID, expires).Scan(&id)
	if err != nil {
		return nil, false, err
	}
	if err = tx.Commit(); err != nil {
		return nil, false, err
	}
	r, err := d.GetWorkflowRequest(ctx, id)
	return r, true, err
}

type workflowTaskState struct {
	kind, status string
	deleted      bool
}

func validWorkflowKind(k string) bool { return k == "pentest" || k == "reverse" }
func sameOptionalID(a, b *int64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func (d *DB) ListWorkflowRequests(ctx context.Context, taskID int64) ([]*WorkflowRequest, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+workflowRequestCols+` FROM workflow_requests WHERE source_task_id=$1 OR target_task_id=$1 ORDER BY created_at,id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*WorkflowRequest
	for rows.Next() {
		r, e := scanWorkflowRequest(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (d *DB) CompleteWorkflowRequest(ctx context.Context, id, targetTaskID int64, result json.RawMessage) error {
	bounded, err := canonicalJSON(result, maxWorkflowResultBytes, false)
	if err != nil {
		return err
	}
	var obj map[string]json.RawMessage
	if err = json.Unmarshal(bounded, &obj); err != nil || obj == nil {
		return fmt.Errorf("%w: result must be an object", ErrWorkflowRequestInvalid)
	}
	for _, key := range []string{"summary", "evidence"} {
		var v any
		if raw := obj[key]; len(raw) == 0 || json.Unmarshal(raw, &v) != nil || !nonEmptyWorkflowValue(v) {
			return fmt.Errorf("%w: result requires non-empty %s", ErrWorkflowRequestInvalid, key)
		}
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := scanWorkflowRequest(tx.QueryRowContext(ctx, `SELECT `+workflowRequestCols+` FROM workflow_requests WHERE id=$1 FOR UPDATE`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrWorkflowRequestNotFound
	}
	if err != nil {
		return err
	}
	if r.TargetTaskID != targetTaskID {
		return ErrWorkflowRequestDenied
	}
	if r.Status != "pending" {
		if r.Status == "completed" && workflowPayloadEqual(r.Result, bounded) {
			return nil
		}
		return ErrWorkflowRequestTerminal
	}
	var expired bool
	if err = tx.QueryRowContext(ctx, `SELECT now()>=$1`, r.ExpiresAt).Scan(&expired); err != nil {
		return err
	}
	if expired {
		return ErrWorkflowRequestTerminal
	}
	res, err := tx.ExecContext(ctx, `UPDATE workflow_requests SET status='completed',result=$2::jsonb,updated_at=now() WHERE id=$1 AND status='pending' AND expires_at>now()`, id, bounded)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return ErrWorkflowRequestTerminal
	}
	return tx.Commit()
}
func nonEmptyWorkflowValue(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(x) != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	default:
		return true
	}
}

func (d *DB) CancelWorkflowRequest(ctx context.Context, id, sourceTaskID int64) error {
	res, err := d.ExecContext(ctx, `UPDATE workflow_requests SET status='cancelled',updated_at=now() WHERE id=$1 AND source_task_id=$2 AND status='pending' AND expires_at>now()`, id, sourceTaskID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 1 {
		return nil
	}
	var source int64
	var status string
	var expired bool
	err = d.QueryRowContext(ctx, `SELECT source_task_id,status,expires_at<=now() FROM workflow_requests WHERE id=$1`, id).Scan(&source, &status, &expired)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrWorkflowRequestNotFound
	}
	if err != nil {
		return err
	}
	if source != sourceTaskID {
		return ErrWorkflowRequestDenied
	}
	if status == "cancelled" {
		return nil
	}
	if status == "pending" && expired {
		return ErrWorkflowRequestTerminal
	}
	return ErrWorkflowRequestTerminal
}

func (d *DB) ExpireWorkflowRequests(ctx context.Context) ([]*WorkflowRequest, error) {
	rows, err := d.QueryContext(ctx, `UPDATE workflow_requests SET status='expired',updated_at=now() WHERE status='pending' AND expires_at<=now() RETURNING `+workflowRequestCols)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*WorkflowRequest
	for rows.Next() {
		r, e := scanWorkflowRequest(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (d *DB) BindWorkflowRequestIntents(ctx context.Context, id, sourceIntentID, targetIntentID int64) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := scanWorkflowRequest(tx.QueryRowContext(ctx, `SELECT `+workflowRequestCols+` FROM workflow_requests WHERE id=$1 FOR UPDATE`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrWorkflowRequestNotFound
	}
	if err != nil {
		return err
	}
	if r.SourceIntentID != nil || r.TargetIntentID != nil {
		if r.SourceIntentID != nil && r.TargetIntentID != nil && *r.SourceIntentID == sourceIntentID && *r.TargetIntentID == targetIntentID {
			return nil
		}
		return ErrWorkflowRequestConflict
	}
	for _, pair := range []struct{ taskID, intentID int64 }{{r.SourceTaskID, sourceIntentID}, {r.TargetTaskID, targetIntentID}} {
		var ok bool
		err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM tasks t JOIN exploration_nodes n ON n.exploration_id=t.exploration_id WHERE t.id=$1 AND t.deleted_at IS NULL AND n.id=$2 AND n.kind='intent' AND n.state<>'deleted')`, pair.taskID, pair.intentID).Scan(&ok)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: intent %d is not live and owned by task %d", ErrWorkflowRequestInvalid, pair.intentID, pair.taskID)
		}
	}

	_, err = tx.ExecContext(ctx, `UPDATE workflow_requests SET source_intent_id=$2,target_intent_id=$3,updated_at=now() WHERE id=$1`, id, sourceIntentID, targetIntentID)
	if err != nil {
		return err
	}
	return tx.Commit()
}
