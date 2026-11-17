package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Native modes change the evidence workflow, never the execution authorization.
type NativeConfig struct {
	Mode     string `json:"mode"`
	Revision int64  `json:"revision"`
}
type NativeCase struct {
	ID             int64             `json:"id"`
	TaskID         int64             `json:"task_id"`
	ArtifactID     int64             `json:"artifact_id"`
	IntentID       int64             `json:"intent_id"`
	ProfileID      string            `json:"profile_id"`
	Title          string            `json:"title"`
	Argv           []string          `json:"argv"`
	InputBase64    string            `json:"input_base64"`
	ExpectedExit   *int              `json:"expected_exit,omitempty"`
	ExpectedSignal *int              `json:"expected_signal,omitempty"`
	ReplayPlan     *NativeReplayPlan `json:"replay_plan,omitempty"`
	SHA256         string            `json:"sha256"`
	CreatedAt      time.Time         `json:"created_at"`
}
type NativeRun struct {
	RunID          int64           `json:"run_id"`
	TaskID         int64           `json:"task_id"`
	ArtifactID     int64           `json:"artifact_id"`
	IntentID       int64           `json:"intent_id"`
	CaseID         int64           `json:"case_id,omitempty"`
	ConfigRevision int64           `json:"config_revision"`
	Mode           string          `json:"mode"`
	TargetState    string          `json:"target_state"`
	ResultPath     string          `json:"result_path"`
	Observation    json.RawMessage `json:"observation"`
}

func (d *DB) NativeConfig(taskID int64) (NativeConfig, error) {
	c := NativeConfig{Mode: "analysis"}
	if _, e := d.reverseTask(taskID); e != nil {
		return c, e
	}
	e := d.QueryRow(`SELECT mode,revision FROM reverse_native_configs WHERE task_id=$1`, taskID).Scan(&c.Mode, &c.Revision)
	if errors.Is(e, sql.ErrNoRows) {
		e = nil
	}
	return c, e
}
func (d *DB) SetNativeConfig(ctx context.Context, taskID int64, mode string) error {
	if mode != "analysis" && mode != "pwn" {
		return errors.New("mode must be analysis or pwn")
	}
	tx, e := d.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var kind, status string
	var paused bool
	if e = tx.QueryRowContext(ctx, `SELECT kind,status,paused FROM tasks WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, taskID).Scan(&kind, &status, &paused); e != nil {
		return e
	}
	if kind != "reverse" {
		return ErrReverseTaskRequired
	}
	if !paused && !IsTerminal(status) {
		return errors.New("请先暂停任务再调整分析模式")
	}
	var running bool
	if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM reverse_runtime_runs WHERE task_id=$1 AND status='running')`, taskID).Scan(&running); e != nil {
		return e
	}
	if running {
		return errors.New("请等待当前运行清理完成")
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO reverse_native_configs(task_id,mode,revision) VALUES($1,$2,1) ON CONFLICT(task_id) DO UPDATE SET mode=$2,revision=reverse_native_configs.revision+1`, taskID, mode)
	if e != nil {
		return e
	}
	return tx.Commit()
}
func ValidateNativeCase(c *NativeCase) error {
	input, e := base64.StdEncoding.Strict().DecodeString(c.InputBase64)
	if e != nil || len(input) > 65536 {
		return errors.New("input_base64 must encode at most 65536 bytes")
	}
	if strings.TrimSpace(c.Title) == "" || len(c.Title) > 500 || len(c.Argv) > 64 || c.ProfileID == "" {
		return errors.New("invalid case title, profile or argv")
	}
	for _, a := range c.Argv {
		if len(a) > 4096 || strings.ContainsRune(a, 0) {
			return errors.New("invalid argv")
		}
	}
	assertions := 0
	if c.ExpectedExit != nil {
		assertions++
	}
	if c.ExpectedSignal != nil {
		assertions++
	}
	if c.ReplayPlan != nil {
		if e = c.ReplayPlan.Validate(); e != nil {
			return e
		}
		if c.ReplayPlan.Assertion != nil {
			assertions++
		}
		if c.ReplayPlan.InputMode == "file" {
			found := false
			for _, arg := range c.Argv {
				if arg == "{input}" {
					found = true
				}
			}
			if !found {
				return errors.New("file input requires exact {input} argv placeholder")
			}
		}
	}
	if assertions != 1 {
		return errors.New("select exactly one exit, signal or replay_plan assertion")
	}
	if c.ExpectedExit != nil && (*c.ExpectedExit < 0 || *c.ExpectedExit > 125) {
		return errors.New("expected_exit outside 0..125")
	}
	if c.ExpectedSignal != nil && (*c.ExpectedSignal < 1 || *c.ExpectedSignal > 64) {
		return errors.New("expected_signal outside 1..64")
	}
	c.InputBase64 = base64.StdEncoding.EncodeToString(input)
	if c.Argv == nil {
		c.Argv = []string{}
	}
	identity := []any{c.ArtifactID, c.ProfileID, c.Argv, c.InputBase64, c.ExpectedExit, c.ExpectedSignal}
	if c.ReplayPlan != nil {
		identity = append(identity, c.ReplayPlan)
	}
	raw, _ := json.Marshal(identity)
	h := sha256.Sum256(raw)
	c.SHA256 = hex.EncodeToString(h[:])
	return nil
}
func (d *DB) CreateNativeCase(ctx context.Context, c NativeCase) (*NativeCase, error) {
	if e := ValidateNativeCase(&c); e != nil {
		return nil, e
	}
	if a, e := d.GetReverseArtifact(c.TaskID, c.ArtifactID); e != nil {
		return nil, e
	} else if a == nil {
		return nil, errors.New("材料不属于当前任务")
	} else if c.ReplayPlan != nil && c.ReplayPlan.Version == 2 && a.SHA256 != c.ReplayPlan.ArtifactSHA256 {
		return nil, errors.New("case specimen hash does not match task artifact")
	}
	if c.ReplayPlan != nil {
		for _, b := range c.ReplayPlan.Target.Bindings() {
			a, e := d.GetReverseArtifact(c.TaskID, b.ArtifactID)
			if e != nil {
				return nil, e
			}
			if a == nil || a.SHA256 != b.SHA256 || a.ID == c.ArtifactID {
				return nil, errors.New("attachment identity does not match task artifact")
			}
		}
		if c.ReplayPlan.ParentCaseID > 0 {
			parent, e := d.NativeCase(c.TaskID, c.ReplayPlan.ParentCaseID)
			if e != nil {
				return nil, e
			}
			if parent.ArtifactID != c.ArtifactID {
				return nil, errors.New("parent case belongs to another target")
			}
		}
	}
	argv, _ := json.Marshal(c.Argv)
	plan, _ := json.Marshal(c.ReplayPlan)
	e := d.QueryRowContext(ctx, `INSERT INTO reverse_native_cases(task_id,artifact_id,intent_id,profile_id,title,argv,input_base64,expected_exit,expected_signal,sha256,replay_plan) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULLIF($11::jsonb,'null'::jsonb) WHERE EXISTS(SELECT 1 FROM tasks t JOIN exploration_nodes n ON n.exploration_id=t.exploration_id WHERE t.id=$1 AND n.id=$3 AND n.kind='intent' AND n.state='running') RETURNING id,created_at`, c.TaskID, c.ArtifactID, c.IntentID, c.ProfileID, c.Title, argv, c.InputBase64, c.ExpectedExit, c.ExpectedSignal, c.SHA256, plan).Scan(&c.ID, &c.CreatedAt)
	return &c, e
}
func (d *DB) NativeCases(taskID int64) ([]NativeCase, error) {
	out := []NativeCase{}
	rows, e := d.Query(`SELECT row_to_json(c) FROM reverse_native_cases c WHERE task_id=$1 ORDER BY id DESC LIMIT 200`, taskID)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		var c NativeCase
		if e = rows.Scan(&raw); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(raw, &c); e != nil {
			return nil, e
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
func (d *DB) NativeCase(taskID, id int64) (*NativeCase, error) {
	var raw []byte
	var c NativeCase
	e := d.QueryRow(`SELECT row_to_json(c) FROM reverse_native_cases c WHERE task_id=$1 AND id=$2`, taskID, id).Scan(&raw)
	if e != nil {
		return nil, e
	}
	e = json.Unmarshal(raw, &c)
	return &c, e
}
func (d *DB) BeginNativeRun(ctx context.Context, run NativeRun) error {
	_, e := d.ExecContext(ctx, `INSERT INTO reverse_native_runs(run_id,task_id,artifact_id,intent_id,case_id,config_revision,mode,target_state,observation) VALUES($1,$2,$3,$4,NULLIF($5,0),$6,$7,'starting','{}')`, run.RunID, run.TaskID, run.ArtifactID, run.IntentID, run.CaseID, run.ConfigRevision, run.Mode)
	return e
}
func (d *DB) FinishNativeRun(runID int64, state, path string, raw []byte) error {
	_, e := d.Exec(`UPDATE reverse_native_runs SET target_state=$2,result_path=$3,observation=$4 WHERE run_id=$1`, runID, state, path, raw)
	return e
}
func (d *DB) NativeRuns(taskID int64) ([]NativeRun, error) {
	out := []NativeRun{}
	rows, e := d.Query(`SELECT row_to_json(n) FROM reverse_native_runs n WHERE task_id=$1 ORDER BY run_id DESC LIMIT 100`, taskID)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		var r NativeRun
		if e = rows.Scan(&raw); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(raw, &r); e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// The bounded immutable snapshot includes the specimen itself, input, environment
// and original observation. It survives deletion of the source task.
func (d *DB) PublishNativeFinding(ctx context.Context, taskID, conclusionID, caseID, runID, reviewerID int64, in RecordFindingInput, snapshot json.RawMessage) (out *RecordedFinding, err error) {
	if len(snapshot) == 0 || len(snapshot) > 24<<20 || !json.Valid(snapshot) {
		return nil, errors.New("invalid native snapshot")
	}
	var canonical any
	if err = json.Unmarshal(snapshot, &canonical); err != nil {
		return nil, err
	}
	snapshot, err = json.Marshal(canonical)
	if err != nil {
		return nil, err
	}
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if e := LockTaskEvidenceTx(tx, taskID); e != nil {
			return e
		}
		var existing int64
		e := tx.QueryRow(`SELECT finding_id FROM finding_native_evidence WHERE source_task_id=$1 AND conclusion_id=$2`, taskID, conclusionID).Scan(&existing)
		if e == nil {
			out = &RecordedFinding{FindingID: existing}
			return nil
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		var exp, sourceID, artifactID int64
		var answer string
		var evidence []byte
		e = tx.QueryRow(`SELECT t.exploration_id,c.intent_id,k.artifact_id,c.answer,c.evidence FROM tasks t JOIN reverse_conclusions c ON c.task_id=t.id JOIN reverse_native_cases k ON k.task_id=t.id JOIN reverse_native_runs n ON n.case_id=k.id JOIN reverse_runtime_runs r ON r.id=n.run_id WHERE t.id=$1 AND c.id=$2 AND k.id=$3 AND n.run_id=$4 AND c.state='accepted' AND c.reviewer_intent_id=$5 AND c.intent_id<>$5 AND k.intent_id=c.intent_id AND k.intent_id<>$5 AND n.intent_id=$5 AND r.status='completed' AND n.mode='replay' AND n.observation->>'matches_expectation'='true' AND EXISTS(SELECT 1 FROM exploration_nodes i WHERE i.id=$5 AND i.exploration_id=t.exploration_id AND i.state='running') FOR SHARE OF c,k,n,r`, taskID, conclusionID, caseID, runID, reviewerID).Scan(&exp, &sourceID, &artifactID, &answer, &evidence)
		if e != nil {
			return errors.New("需要独立审核者对同一案例成功重放并接受结论")
		}
		c, e := validateNativeReplayTx(tx, taskID, caseID, runID, reviewerID)
		if e != nil {
			return e
		}
		if c.ReplayPlan != nil && c.ReplayPlan.Version == 2 {
			var bound bool
			if e = tx.QueryRow(`SELECT native_case_id=$2 AND native_run_id=$3 AND native_case_sha256=$4 FROM reverse_conclusions WHERE id=$1`, conclusionID, caseID, runID, c.SHA256).Scan(&bound); e != nil || !bound {
				return errors.New("native_review must bind this case and replay before publication")
			}
		}
		var refs []ReverseEvidence
		if json.Unmarshal(evidence, &refs) != nil {
			return errors.New("invalid conclusion evidence")
		}
		matched := false
		for _, r := range refs {
			if r.ArtifactID == artifactID {
				matched = true
			}
		}
		if !matched {
			return errors.New("结论未引用案例材料")
		}
		in.TaskID = taskID
		in.ExplorationID = exp
		in.IntentID = reviewerID
		in.Worker = "reverse_reviewer"
		in.Evidence = answer + "\nNative evidence: immutable specimen/input/environment/replay snapshot."
		out, e = RecordFindingTx(ctx, tx, in, nil)
		if e != nil {
			return e
		}
		h := sha256.Sum256(snapshot)
		_, e = tx.Exec(`INSERT INTO finding_native_evidence(finding_id,source_task_id,conclusion_id,case_id,run_id,sha256,snapshot) VALUES($1,$2,$3,$4,$5,$6,$7)`, out.FindingID, taskID, conclusionID, caseID, runID, hex.EncodeToString(h[:]), []byte(snapshot))
		return e
	})
	return
}
