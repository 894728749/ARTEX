package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

func validateNativeReplayTx(tx *sql.Tx, taskID, caseID, runID, reviewerID int64) (*NativeCase, error) {
	var raw, observation []byte
	var runConfig, currentConfig, policyRevision int64
	var enabled bool
	err := tx.QueryRow(`SELECT row_to_json(k),n.observation,n.config_revision,COALESCE(cfg.revision,0),p.revision,p.enabled
 FROM reverse_native_cases k JOIN reverse_native_runs n ON n.case_id=k.id AND n.task_id=k.task_id
 JOIN reverse_runtime_runs r ON r.id=n.run_id LEFT JOIN reverse_native_configs cfg ON cfg.task_id=k.task_id
 JOIN reverse_runtime_policies p ON p.task_id=k.task_id
 WHERE k.task_id=$1 AND k.id=$2 AND n.run_id=$3 AND n.intent_id=$4 AND k.intent_id<>$4
 AND n.mode='replay' AND r.status='completed' AND n.target_state IN ('exit','crashed')
 FOR SHARE OF k,n,r,p`, taskID, caseID, runID, reviewerID).Scan(&raw, &observation, &runConfig, &currentConfig, &policyRevision, &enabled)
	if err != nil {
		return nil, errors.New("independent completed replay required")
	}
	var c NativeCase
	if err = json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	digest := c.SHA256
	if err = ValidateNativeCase(&c); err != nil || c.SHA256 != digest {
		return nil, errors.New("native case identity changed")
	}
	var o map[string]any
	if json.Unmarshal(observation, &o) != nil || o["matches_expectation"] != true || o["case_sha256"] != digest {
		return nil, errors.New("replay is not bound to current case")
	}
	if runConfig != currentConfig || !enabled {
		return nil, errors.New("native analysis configuration or authorization changed")
	}
	var superseded bool
	if err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM reverse_native_cases WHERE task_id=$1 AND replay_plan->>'parent_case_id'=$2)`, taskID, jsonNumber(caseID)).Scan(&superseded); err != nil {
		return nil, err
	}
	if superseded {
		return nil, errors.New("case has a newer version; independent review must be repeated")
	}
	if c.ReplayPlan != nil && c.ReplayPlan.Version == 2 {
		manifest, _ := o["manifest"].(map[string]any)
		if c.ReplayPlan.PolicyRevision != policyRevision || o["policy_revision"] != float64(policyRevision) || manifest["image"] != c.ReplayPlan.Image || manifest["artifact_sha256"] != c.ReplayPlan.ArtifactSHA256 {
			return nil, errors.New("replay environment or policy changed")
		}
	}
	return &c, nil
}

func jsonNumber(id int64) string { b, _ := json.Marshal(id); return string(b) }

func (d *DB) AcceptNativeReview(ctx context.Context, taskID, conclusionID, caseID, runID, reviewerID int64, review string) (json.RawMessage, error) {
	if review == "" || len(review) > 16000 {
		return nil, errors.New("bounded independent review rationale required")
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	c, err := validateNativeReplayTx(tx, taskID, caseID, runID, reviewerID)
	if err != nil {
		return nil, err
	}
	var bound sql.NullInt64
	var state string
	var previousReviewer sql.NullInt64
	var reviewed sql.NullTime
	if err = tx.QueryRow(`SELECT c.native_case_id,c.state,c.reviewer_intent_id,c.reviewed_at FROM reverse_conclusions c JOIN tasks t ON t.id=c.task_id
 WHERE c.id=$1 AND c.task_id=$2 AND c.intent_id=$3 AND EXISTS(SELECT 1 FROM exploration_nodes n WHERE n.id=$4 AND n.exploration_id=t.exploration_id AND n.kind='intent' AND n.state='running') FOR UPDATE OF c`, conclusionID, taskID, c.IntentID, reviewerID).Scan(&bound, &state, &previousReviewer, &reviewed); err != nil {
		return nil, errors.New("conclusion and case must have same author and a running independent reviewer")
	}
	if state != "proposed" && !(state == "accepted" && previousReviewer.Valid && previousReviewer.Int64 == reviewerID && (!bound.Valid || bound.Int64 == caseID) && reviewed.Valid && !c.CreatedAt.After(reviewed.Time)) {
		return nil, errors.New("old review cannot be reused for another case version")
	}
	revision := int64(0)
	if c.ReplayPlan != nil {
		revision = c.ReplayPlan.PolicyRevision
	}
	_, err = tx.Exec(`UPDATE reverse_conclusions SET state='accepted',reviewer_intent_id=$3,review=$4,reviewed_at=now(),native_case_id=$5,native_run_id=$6,native_case_sha256=$7,native_policy_revision=$8 WHERE id=$1 AND task_id=$2`, conclusionID, taskID, reviewerID, review, caseID, runID, c.SHA256, revision)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return d.NativeReview(taskID, conclusionID)
}

func (d *DB) NativeReview(taskID, conclusionID int64) (json.RawMessage, error) {
	var raw []byte
	err := d.QueryRow(`SELECT jsonb_build_object('case_id',native_case_id,'run_id',native_run_id,'case_sha256',native_case_sha256,'policy_revision',native_policy_revision,'reviewer_intent_id',reviewer_intent_id,'reviewed_at',reviewed_at,'review',review) FROM reverse_conclusions WHERE task_id=$1 AND id=$2`, taskID, conclusionID).Scan(&raw)
	return raw, err
}
