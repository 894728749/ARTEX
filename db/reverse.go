package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrReverseTaskRequired = errors.New("reverse task required")
var ErrReverseConclusionInvalid = errors.New("invalid reverse conclusion")

type ReverseArtifact struct {
	ID        int64     `json:"id"`
	TaskID    int64     `json:"task_id"`
	Name      string    `json:"name"`
	Format    string    `json:"format"`
	SizeBytes int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
	Source    string    `json:"source"`
	Version   string    `json:"version"`
	Path      string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

type ReverseEvidence struct {
	ArtifactID  int64  `json:"artifact_id"`
	Locator     string `json:"locator"`
	Observation string `json:"observation"`
	ResultPath  string `json:"result_path,omitempty"`
}

type ReverseConclusion struct {
	ID               int64             `json:"id"`
	TaskID           int64             `json:"task_id"`
	IntentID         int64             `json:"intent_id"`
	NodeID           *int64            `json:"node_id,omitempty"`
	Question         string            `json:"question"`
	Answer           string            `json:"answer"`
	State            string            `json:"state"`
	Evidence         []ReverseEvidence `json:"evidence"`
	Limitations      string            `json:"limitations"`
	ReviewerIntentID *int64            `json:"reviewer_intent_id,omitempty"`
	Review           string            `json:"review"`
	CreatedAt        time.Time         `json:"created_at"`
	ReviewedAt       *time.Time        `json:"reviewed_at,omitempty"`
}

type ReverseConclusionInput struct {
	IntentID    int64
	NodeID      *int64
	Question    string
	Answer      string
	Evidence    []ReverseEvidence
	Limitations string
}

func (d *DB) reverseTask(taskID int64) (int64, error) {
	var exp int64
	err := d.QueryRow(`SELECT exploration_id FROM tasks WHERE id=$1 AND kind='reverse' AND deleted_at IS NULL`, taskID).Scan(&exp)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrReverseTaskRequired
	}
	return exp, err
}

func (d *DB) AddReverseArtifact(taskID int64, a ReverseArtifact) (*ReverseArtifact, error) {
	if _, err := d.reverseTask(taskID); err != nil {
		return nil, err
	}
	if a.Name == "" || a.Path == "" || a.SizeBytes < 0 || a.SHA256 == "" {
		return nil, fmt.Errorf("invalid reverse artifact")
	}
	err := d.QueryRow(`INSERT INTO reverse_artifacts(task_id,name,format,size_bytes,sha256,source,version,path) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id,created_at`, taskID, a.Name, a.Format, a.SizeBytes, a.SHA256, a.Source, a.Version, a.Path).Scan(&a.ID, &a.CreatedAt)
	if err != nil {
		return nil, err
	}
	a.TaskID = taskID
	return &a, nil
}
func scanReverseArtifact(r interface{ Scan(...any) error }) (*ReverseArtifact, error) {
	var a ReverseArtifact
	err := r.Scan(&a.ID, &a.TaskID, &a.Name, &a.Format, &a.SizeBytes, &a.SHA256, &a.Source, &a.Version, &a.Path, &a.CreatedAt)
	return &a, err
}

const reverseArtifactCols = `id,task_id,name,format,size_bytes,sha256,source,version,path,created_at`

func (d *DB) ListReverseArtifacts(taskID int64) ([]ReverseArtifact, error) {
	if _, e := d.reverseTask(taskID); e != nil {
		return nil, e
	}
	rows, e := d.Query(`SELECT `+reverseArtifactCols+` FROM reverse_artifacts WHERE task_id=$1 ORDER BY id`, taskID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []ReverseArtifact{}
	for rows.Next() {
		a, e := scanReverseArtifact(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}
func (d *DB) GetReverseArtifact(taskID, artifactID int64) (*ReverseArtifact, error) {
	if _, e := d.reverseTask(taskID); e != nil {
		return nil, e
	}
	a, e := scanReverseArtifact(d.QueryRow(`SELECT `+reverseArtifactCols+` FROM reverse_artifacts WHERE task_id=$1 AND id=$2`, taskID, artifactID))
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	return a, e
}

const reverseConclusionCols = `id,task_id,intent_id,node_id,question,answer,state,evidence,limitations,reviewer_intent_id,review,created_at,reviewed_at`

func scanReverseConclusion(r interface{ Scan(...any) error }) (*ReverseConclusion, error) {
	var c ReverseConclusion
	var ev []byte
	err := r.Scan(&c.ID, &c.TaskID, &c.IntentID, &c.NodeID, &c.Question, &c.Answer, &c.State, &ev, &c.Limitations, &c.ReviewerIntentID, &c.Review, &c.CreatedAt, &c.ReviewedAt)
	if err == nil {
		_ = json.Unmarshal(ev, &c.Evidence)
		if c.Evidence == nil {
			c.Evidence = []ReverseEvidence{}
		}
	}
	return &c, err
}
func (d *DB) CreateReverseConclusion(taskID int64, in ReverseConclusionInput) (*ReverseConclusion, error) {
	exp, e := d.reverseTask(taskID)
	if e != nil {
		return nil, e
	}
	if in.IntentID <= 0 || in.Question == "" || in.Answer == "" {
		return nil, ErrReverseConclusionInvalid
	}
	var ok bool
	e = d.QueryRow(`SELECT EXISTS(SELECT 1 FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 AND kind='intent')`, in.IntentID, exp).Scan(&ok)
	if e != nil {
		return nil, e
	}
	if !ok {
		return nil, ErrReverseConclusionInvalid
	}
	if in.NodeID != nil {
		var nodeOK bool
		if e = d.QueryRow(`SELECT EXISTS(SELECT 1 FROM exploration_nodes WHERE id=$1 AND exploration_id=$2)`, *in.NodeID, exp).Scan(&nodeOK); e != nil {
			return nil, e
		}
		if !nodeOK {
			return nil, ErrReverseConclusionInvalid
		}
	}
	for _, ref := range in.Evidence {
		if ref.ArtifactID <= 0 || ref.Locator == "" || ref.Observation == "" {
			return nil, ErrReverseConclusionInvalid
		}
		var exists bool
		if e = d.QueryRow(`SELECT EXISTS(SELECT 1 FROM reverse_artifacts WHERE id=$1 AND task_id=$2)`, ref.ArtifactID, taskID).Scan(&exists); e != nil {
			return nil, e
		}
		if !exists {
			return nil, ErrReverseConclusionInvalid
		}
	}
	ev, _ := json.Marshal(in.Evidence)
	return scanReverseConclusion(d.QueryRow(`INSERT INTO reverse_conclusions(task_id,intent_id,node_id,question,answer,evidence,limitations) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING `+reverseConclusionCols, taskID, in.IntentID, in.NodeID, in.Question, in.Answer, string(ev), in.Limitations))
}
func (d *DB) ListReverseConclusions(taskID int64) ([]ReverseConclusion, error) {
	if _, e := d.reverseTask(taskID); e != nil {
		return nil, e
	}
	rows, e := d.Query(`SELECT `+reverseConclusionCols+` FROM reverse_conclusions WHERE task_id=$1 ORDER BY id`, taskID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []ReverseConclusion{}
	for rows.Next() {
		c, e := scanReverseConclusion(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}
func (d *DB) GetReverseConclusion(taskID, conclusionID int64) (*ReverseConclusion, error) {
	if _, e := d.reverseTask(taskID); e != nil {
		return nil, e
	}
	c, e := scanReverseConclusion(d.QueryRow(`SELECT `+reverseConclusionCols+` FROM reverse_conclusions WHERE task_id=$1 AND id=$2`, taskID, conclusionID))
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	return c, e
}
func (d *DB) ReviewReverseConclusion(taskID, conclusionID, reviewerIntentID int64, state, review string) (*ReverseConclusion, error) {
	exp, e := d.reverseTask(taskID)
	if e != nil {
		return nil, e
	}
	if reviewerIntentID <= 0 || strings.TrimSpace(review) == "" || (state != "accepted" && state != "rejected" && state != "unresolved") {
		return nil, ErrReverseConclusionInvalid
	}
	var sourceID int64
	var evRaw []byte
	if e = d.QueryRow(`SELECT intent_id,evidence FROM reverse_conclusions WHERE id=$1 AND task_id=$2`, conclusionID, taskID).Scan(&sourceID, &evRaw); errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	} else if e != nil {
		return nil, e
	}
	if reviewerIntentID == sourceID {
		return nil, ErrReverseConclusionInvalid
	}
	var reviewerOK bool
	if e = d.QueryRow(`SELECT EXISTS(SELECT 1 FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 AND kind='intent' AND state='running')`, reviewerIntentID, exp).Scan(&reviewerOK); e != nil {
		return nil, e
	}
	if !reviewerOK {
		return nil, ErrReverseConclusionInvalid
	}
	if state == "accepted" {
		var refs []ReverseEvidence
		_ = json.Unmarshal(evRaw, &refs)
		if len(refs) == 0 {
			return nil, ErrReverseConclusionInvalid
		}
		for _, r := range refs {
			if r.Locator == "" || r.Observation == "" {
				return nil, ErrReverseConclusionInvalid
			}
		}
	}
	c, err := scanReverseConclusion(d.QueryRow(`UPDATE reverse_conclusions SET state=$3,reviewer_intent_id=$4,review=$5,reviewed_at=now() WHERE id=$1 AND task_id=$2 AND state='proposed' RETURNING `+reverseConclusionCols, conclusionID, taskID, state, reviewerIntentID, review))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: 结论已核验；新的解释请提交新结论", ErrReverseConclusionInvalid)
	}
	return c, err
}

// SetReverseConclusionNode attaches a graph fact/finding created after a conclusion write.
func (d *DB) SetReverseConclusionNode(taskID, conclusionID, nodeID int64) error {
	exp, e := d.reverseTask(taskID)
	if e != nil {
		return e
	}
	var ok bool
	if e = d.QueryRow(`SELECT EXISTS(SELECT 1 FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 AND kind IN ('fact','finding'))`, nodeID, exp).Scan(&ok); e != nil {
		return e
	}
	if !ok {
		return ErrReverseConclusionInvalid
	}
	res, e := d.Exec(`UPDATE reverse_conclusions SET node_id=$3 WHERE task_id=$1 AND id=$2`, taskID, conclusionID, nodeID)
	if e != nil {
		return e
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return sql.ErrNoRows
	}
	return nil
}
