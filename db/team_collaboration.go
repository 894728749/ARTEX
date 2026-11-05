package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

var ErrTeamCollaborationDenied = errors.New("team collaboration authorization denied")
var ErrTeamCollaborationConflict = errors.New("team collaboration state conflict")

type Team struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}
type TeamMember struct {
	ID        int64     `json:"id"`
	TeamID    int64     `json:"team_id"`
	Login     string    `json:"login"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
}
type TeamDevice struct {
	ID            int64           `json:"id"`
	TeamID        int64           `json:"team_id"`
	OwnerMemberID int64           `json:"owner_member_id"`
	Name          string          `json:"name"`
	Capabilities  json.RawMessage `json:"capabilities"`
	Revoked       bool            `json:"revoked"`
	CreatedAt     time.Time       `json:"created_at"`
}
type TeamExecutionAssignment struct {
	ID             int64           `json:"id"`
	TeamID         int64           `json:"team_id"`
	TaskID         int64           `json:"task_id"`
	IntentID       int64           `json:"intent_id"`
	DeviceID       int64           `json:"device_id"`
	MemberID       int64           `json:"member_id"`
	Epoch          int64           `json:"epoch"`
	Attempt        int64           `json:"attempt"`
	LeaseUntil     time.Time       `json:"lease_until"`
	State          string          `json:"state"`
	Config         json.RawMessage `json:"config_snapshot"`
	Input          json.RawMessage `json:"input_snapshot"`
	Result         json.RawMessage `json:"result,omitempty"`
	ReviewMemberID *int64          `json:"review_member_id,omitempty"`
	ReviewDecision string          `json:"review_decision,omitempty"`
	ReviewNote     string          `json:"review_note,omitempty"`
	ReviewedAt     *time.Time      `json:"reviewed_at,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}

func teamHash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func validJSONSnapshot(b []byte) bool {
	var v any
	if len(b) == 0 || len(b) > 1<<20 || json.Unmarshal(b, &v) != nil {
		return false
	}
	switch v.(type) {
	case map[string]any, []any:
		return true
	default:
		return false
	}
}
func teamMemberTx(ctx context.Context, tx *sql.Tx, teamID, memberID int64) error {
	var ok bool
	e := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM team_members WHERE id=$1 AND team_id=$2 AND revoked_at IS NULL)`, memberID, teamID).Scan(&ok)
	if e != nil {
		return e
	}
	if !ok {
		return ErrTeamCollaborationDenied
	}
	return nil
}
func teamPermissionTx(ctx context.Context, tx *sql.Tx, teamID, taskID, memberID int64, permission string) error {
	if permission != "read" {
		if err := LockTaskEvidenceTx(tx, taskID); err != nil {
			return err
		}
	}
	var id int64
	if e := tx.QueryRowContext(ctx, `SELECT id FROM team_members WHERE id=$1 AND team_id=$2 AND revoked_at IS NULL FOR SHARE`, memberID, teamID).Scan(&id); e != nil {
		return ErrTeamCollaborationDenied
	}
	// Hold both member and permission rows until the business transaction commits.
	// Revocation cannot succeed between authorization and the protected write.
	e := tx.QueryRowContext(ctx, `SELECT p.member_id FROM team_tasks tt JOIN tasks t ON t.id=tt.task_id AND t.deleted_at IS NULL AND t.archived_at IS NULL JOIN team_task_permissions p ON p.team_id=tt.team_id AND p.task_id=tt.task_id WHERE tt.team_id=$1 AND tt.task_id=$2 AND p.member_id=$3 AND p.permission=$4 FOR SHARE OF p`, teamID, taskID, memberID, permission).Scan(&id)
	if e == sql.ErrNoRows {
		return ErrTeamCollaborationDenied
	}
	return e
}

func (d *DB) CreateTeam(ctx context.Context, name string) (*Team, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 200 {
		return nil, fmt.Errorf("invalid team name")
	}
	var t Team
	e := d.QueryRowContext(ctx, `INSERT INTO teams(name) VALUES($1) RETURNING id,name,created_at`, name).Scan(&t.ID, &t.Name, &t.CreatedAt)
	return &t, e
}
func (d *DB) CreateTeamMember(ctx context.Context, teamID int64, login, passwordHash string) (*TeamMember, error) {
	login = strings.TrimSpace(login)
	if teamID < 1 || login == "" || len(login) > 160 || strings.TrimSpace(passwordHash) == "" {
		return nil, fmt.Errorf("invalid member input")
	}
	var m TeamMember
	e := d.QueryRowContext(ctx, `INSERT INTO team_members(team_id,login,password_hash) VALUES($1,$2,$3) RETURNING id,team_id,login,false,created_at`, teamID, login, passwordHash).Scan(&m.ID, &m.TeamID, &m.Login, &m.Revoked, &m.CreatedAt)
	return &m, e
}
func (d *DB) ListTeamMembers(ctx context.Context, teamID int64) ([]TeamMember, error) {
	rows, e := d.QueryContext(ctx, `SELECT id,team_id,login,revoked_at IS NOT NULL,created_at FROM team_members WHERE team_id=$1 ORDER BY id`, teamID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []TeamMember{}
	for rows.Next() {
		var m TeamMember
		if e = rows.Scan(&m.ID, &m.TeamID, &m.Login, &m.Revoked, &m.CreatedAt); e != nil {
			return nil, e
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
func (d *DB) GetTeamMember(ctx context.Context, teamID, memberID int64) (*TeamMember, error) {
	var m TeamMember
	e := d.QueryRowContext(ctx, `SELECT id,team_id,login,revoked_at IS NOT NULL,created_at FROM team_members WHERE team_id=$1 AND id=$2`, teamID, memberID).Scan(&m.ID, &m.TeamID, &m.Login, &m.Revoked, &m.CreatedAt)
	if e != nil {
		return nil, e
	}
	return &m, nil
}
func (d *DB) RevokeTeamMember(ctx context.Context, teamID, memberID int64) error {
	tx, e := d.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = teamMemberTx(ctx, tx, teamID, memberID); e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `UPDATE team_members SET revoked_at=now() WHERE team_id=$1 AND id=$2 AND revoked_at IS NULL`, teamID, memberID)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `UPDATE team_devices SET revoked_at=now() WHERE team_id=$1 AND owner_member_id=$2 AND revoked_at IS NULL`, teamID, memberID)
	if e != nil {
		return e
	}
	return tx.Commit()
}

func (d *DB) AttachTeamTask(ctx context.Context, teamID, taskID, memberID int64, permission string) error {
	if permission != "read" && permission != "execute" && permission != "review" && permission != "manage" {
		return fmt.Errorf("invalid team task permission")
	}
	tx, e := d.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = LockTaskEvidenceTx(tx, taskID); e != nil {
		return e
	}
	if e = teamMemberTx(ctx, tx, teamID, memberID); e != nil {
		return e
	}
	var alive bool
	e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM tasks WHERE id=$1 AND deleted_at IS NULL AND archived_at IS NULL)`, taskID).Scan(&alive)
	if e != nil {
		return e
	}
	if !alive {
		return ErrTeamCollaborationDenied
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO team_tasks(team_id,task_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, teamID, taskID); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO team_task_permissions(team_id,task_id,member_id,permission) VALUES($1,$2,$3,$4) ON CONFLICT(team_id,task_id,member_id,permission) DO NOTHING`, teamID, taskID, memberID, permission); e != nil {
		return e
	}
	return tx.Commit()
}
func (d *DB) CheckTeamTaskPermission(ctx context.Context, teamID, taskID, memberID int64, permission string) error {
	// The permission guard takes shared row locks to serialize with revocation.
	// PostgreSQL disallows SELECT FOR SHARE in a read-only transaction.
	tx, e := d.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	return teamPermissionTx(ctx, tx, teamID, taskID, memberID, permission)
}

type TeamResource struct {
	ID            int64           `json:"id"`
	TeamID        int64           `json:"team_id"`
	TaskID        int64           `json:"task_id"`
	Key           string          `json:"key"`
	Value         json.RawMessage `json:"value"`
	OwnerMemberID *int64          `json:"owner_member_id,omitempty"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

func (d *DB) PutTeamResource(ctx context.Context, teamID, taskID, memberID int64, key string, value json.RawMessage) (*TeamResource, error) {
	key = strings.TrimSpace(key)
	if key == "" || len(key) > 200 || !validJSONSnapshot(value) {
		return nil, fmt.Errorf("invalid team resource")
	}
	tx, e := d.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if e = teamPermissionTx(ctx, tx, teamID, taskID, memberID, "manage"); e != nil {
		return nil, e
	}
	var r TeamResource
	e = tx.QueryRowContext(ctx, `INSERT INTO team_resources(team_id,task_id,resource_key,value,owner_member_id) VALUES($1,$2,$3,$4::jsonb,$5) ON CONFLICT(team_id,task_id,resource_key) DO UPDATE SET value=EXCLUDED.value,owner_member_id=EXCLUDED.owner_member_id,updated_at=now() RETURNING id,team_id,task_id,resource_key,value,owner_member_id,updated_at`, teamID, taskID, key, string(value), memberID).Scan(&r.ID, &r.TeamID, &r.TaskID, &r.Key, &r.Value, &r.OwnerMemberID, &r.UpdatedAt)
	if e != nil {
		return nil, e
	}
	return &r, tx.Commit()
}
func (d *DB) GetTeamResource(ctx context.Context, teamID, taskID, memberID int64, key string) (*TeamResource, error) {
	tx, e := d.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if e = teamPermissionTx(ctx, tx, teamID, taskID, memberID, "read"); e != nil {
		return nil, e
	}
	var r TeamResource
	e = tx.QueryRowContext(ctx, `SELECT id,team_id,task_id,resource_key,value,owner_member_id,updated_at FROM team_resources WHERE team_id=$1 AND task_id=$2 AND resource_key=$3`, teamID, taskID, key).Scan(&r.ID, &r.TeamID, &r.TaskID, &r.Key, &r.Value, &r.OwnerMemberID, &r.UpdatedAt)
	if e != nil {
		return nil, e
	}
	return &r, nil
}

func (d *DB) CreateTeamDevicePairing(ctx context.Context, teamID, memberID int64, ttl time.Duration) (string, error) {
	if ttl < time.Minute || ttl > 24*time.Hour {
		return "", fmt.Errorf("pairing ttl must be 1m..24h")
	}
	raw := make([]byte, 32)
	if _, e := rand.Read(raw); e != nil {
		return "", e
	}
	token := hex.EncodeToString(raw)
	tx, e := d.BeginTx(ctx, nil)
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	if e = teamMemberTx(ctx, tx, teamID, memberID); e != nil {
		return "", e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO team_device_pairings(team_id,member_id,token_hash,expires_at) VALUES($1,$2,$3,now()+$4::interval)`, teamID, memberID, teamHash(token), fmt.Sprintf("%f seconds", ttl.Seconds()))
	if e != nil {
		return "", e
	}
	return token, tx.Commit()
}
func (d *DB) PairTeamDevice(ctx context.Context, pairingToken, name string, capabilities json.RawMessage) (*TeamDevice, string, error) {
	if len(name) > 160 || strings.TrimSpace(name) == "" || !validJSONSnapshot(capabilities) {
		return nil, "", fmt.Errorf("invalid device input")
	}
	raw := make([]byte, 32)
	if _, e := rand.Read(raw); e != nil {
		return nil, "", e
	}
	deviceToken := hex.EncodeToString(raw)
	tx, e := d.BeginTx(ctx, nil)
	if e != nil {
		return nil, "", e
	}
	defer tx.Rollback()
	var teamID, memberID int64
	e = tx.QueryRowContext(ctx, `UPDATE team_device_pairings SET consumed_at=now() WHERE token_hash=$1 AND consumed_at IS NULL AND expires_at>now() AND EXISTS(SELECT 1 FROM team_members m WHERE m.id=team_device_pairings.member_id AND m.revoked_at IS NULL) RETURNING team_id,member_id`, teamHash(pairingToken)).Scan(&teamID, &memberID)
	if e != nil {
		return nil, "", ErrTeamCollaborationDenied
	}
	var device TeamDevice
	e = tx.QueryRowContext(ctx, `INSERT INTO team_devices(team_id,owner_member_id,name,token_hash,capabilities) VALUES($1,$2,$3,$4,$5::jsonb) RETURNING id,team_id,owner_member_id,name,capabilities,false,created_at`, teamID, memberID, name, teamHash(deviceToken), string(capabilities)).Scan(&device.ID, &device.TeamID, &device.OwnerMemberID, &device.Name, &device.Capabilities, &device.Revoked, &device.CreatedAt)
	if e != nil {
		return nil, "", e
	}
	return &device, deviceToken, tx.Commit()
}
func (d *DB) AuthenticateTeamDevice(ctx context.Context, token string) (*TeamDevice, error) {
	var v TeamDevice
	e := d.QueryRowContext(ctx, `SELECT id,team_id,owner_member_id,name,capabilities,false,created_at FROM team_devices WHERE token_hash=$1 AND revoked_at IS NULL AND EXISTS(SELECT 1 FROM team_members m WHERE m.id=owner_member_id AND m.revoked_at IS NULL)`, teamHash(token)).Scan(&v.ID, &v.TeamID, &v.OwnerMemberID, &v.Name, &v.Capabilities, &v.Revoked, &v.CreatedAt)
	if e != nil {
		return nil, ErrTeamCollaborationDenied
	}
	return &v, nil
}
func (d *DB) RevokeTeamDevice(ctx context.Context, teamID, deviceID, memberID int64) error {
	res, e := d.ExecContext(ctx, `UPDATE team_devices SET revoked_at=now() WHERE team_id=$1 AND id=$2 AND owner_member_id=$3 AND revoked_at IS NULL AND EXISTS(SELECT 1 FROM team_members m WHERE m.id=$3 AND m.team_id=$1 AND m.revoked_at IS NULL)`, teamID, deviceID, memberID)
	if e != nil {
		return e
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return ErrTeamCollaborationDenied
	}
	return nil
}

// CreateTeamExecutionAssignment holds the task's exploration lock while checking
// dependencies/resources and marking the intent remote, serializing against local claims.
func teamWorkflowDeadlineTx(ctx context.Context, tx *sql.Tx, workflowID, taskID int64) (time.Time, error) {
	if workflowID == 0 {
		return time.Time{}, nil
	}
	var deadline time.Time
	e := tx.QueryRowContext(ctx, `SELECT expires_at FROM workflow_requests WHERE id=$1 AND target_task_id=$2 AND status='pending' AND expires_at>now() FOR SHARE`, workflowID, taskID).Scan(&deadline)
	return deadline, e
}

func (d *DB) CreateTeamExecutionAssignment(ctx context.Context, teamID, taskID, intentID, memberID, deviceID int64, lease time.Duration, config, input json.RawMessage, actorMemberID ...int64) (*TeamExecutionAssignment, error) {
	actor := int64(-1)
	if len(actorMemberID) > 0 {
		actor = actorMemberID[0]
	}
	return d.createTeamExecutionAssignment(ctx, teamID, taskID, intentID, memberID, deviceID, lease, config, input, actor, nil)
}

func (d *DB) CreateTeamExecutionAssignmentAuthorized(ctx context.Context, teamID, taskID, intentID, memberID, deviceID int64, lease time.Duration, config, input, expectedPayload json.RawMessage, actorMemberID int64) (*TeamExecutionAssignment, error) {
	if !json.Valid(expectedPayload) {
		return nil, fmt.Errorf("invalid expected intent payload")
	}
	return d.createTeamExecutionAssignment(ctx, teamID, taskID, intentID, memberID, deviceID, lease, config, input, actorMemberID, expectedPayload)
}

func (d *DB) createTeamExecutionAssignment(ctx context.Context, teamID, taskID, intentID, memberID, deviceID int64, lease time.Duration, config, input json.RawMessage, actor int64, expectedPayload json.RawMessage) (*TeamExecutionAssignment, error) {
	if lease < time.Minute || lease > 24*time.Hour || !validJSONSnapshot(config) || !validJSONSnapshot(input) {
		return nil, fmt.Errorf("invalid assignment lease or snapshot")
	}
	tx, e := d.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	var expID int64
	var taskDeadline sql.NullTime
	e = tx.QueryRowContext(ctx, `SELECT exploration_id,deadline_at FROM tasks WHERE id=$1 AND deleted_at IS NULL AND archived_at IS NULL AND status NOT IN ('finalizing','done','failed','timeout') FOR UPDATE`, taskID).Scan(&expID, &taskDeadline)
	if e != nil {
		return nil, ErrTeamCollaborationDenied
	}
	if _, e = tx.ExecContext(ctx, `SELECT id FROM explorations WHERE id=$1 FOR UPDATE`, expID); e != nil {
		return nil, e
	}
	if e = teamPermissionTx(ctx, tx, teamID, taskID, memberID, "execute"); e != nil {
		return nil, e
	}
	if actor != -1 {
		if actor != 0 {
			if e = teamPermissionTx(ctx, tx, teamID, taskID, actor, "read"); e != nil {
				return nil, ErrTeamCollaborationDenied
			}
			if e = teamPermissionTx(ctx, tx, teamID, taskID, actor, "manage"); e != nil {
				return nil, ErrTeamCollaborationDenied
			}
		}
		if e = teamPermissionTx(ctx, tx, teamID, taskID, memberID, "read"); e != nil {
			return nil, ErrTeamCollaborationDenied
		}
	}
	var lockedMember int64
	if e = tx.QueryRowContext(ctx, `SELECT id FROM team_members WHERE id=$1 AND team_id=$2 AND revoked_at IS NULL FOR SHARE`, memberID, teamID).Scan(&lockedMember); e != nil {
		return nil, ErrTeamCollaborationDenied
	}
	var owner int64
	e = tx.QueryRowContext(ctx, `SELECT owner_member_id FROM team_devices WHERE id=$1 AND team_id=$2 AND revoked_at IS NULL AND EXISTS(SELECT 1 FROM team_members m WHERE m.id=team_devices.owner_member_id AND m.revoked_at IS NULL) FOR UPDATE`, deviceID, teamID).Scan(&owner)
	if e != nil || owner != memberID {
		return nil, ErrTeamCollaborationDenied
	}
	var deviceBusy bool
	if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM team_execution_assignments WHERE device_id=$1 AND state IN ('assigned','claimed','running'))`, deviceID).Scan(&deviceBusy); e != nil {
		return nil, e
	}
	if deviceBusy {
		return nil, ErrTeamCollaborationConflict
	}
	var payload []byte
	var state string
	e = tx.QueryRowContext(ctx, `SELECT payload,state FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 AND kind='intent' FOR UPDATE`, intentID, expID).Scan(&payload, &state)
	if e != nil || (state != "open" && state != "waiting") {
		return nil, ErrTeamCollaborationConflict
	}
	if len(expectedPayload) > 0 {
		var equal bool
		if e = tx.QueryRowContext(ctx, `SELECT $1::jsonb=$2::jsonb`, string(expectedPayload), string(payload)).Scan(&equal); e != nil {
			return nil, e
		}
		if !equal {
			return nil, ErrTeamCollaborationConflict
		}
	}
	var p map[string]any
	if json.Unmarshal(payload, &p) != nil {
		return nil, ErrTeamCollaborationConflict
	}
	contract, _ := p["contract"].(map[string]any)
	if contract == nil {
		contract = map[string]any{}
		p["contract"] = contract
	}
	var dispatchID int64
	if contract["remote_dispatch_pending"] == true {
		dispatchID, e = strconv.ParseInt(fmt.Sprint(contract["remote_dispatch_id"]), 10, 64)
		if e != nil {
			return nil, ErrTeamCollaborationConflict
		}
		var queued bool
		if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM team_dispatch_queue WHERE id=$1 AND team_id=$2 AND task_id=$3 AND intent_id=$4 AND requested_by=$5 AND state='queued' AND expires_at>now())`, dispatchID, teamID, taskID, intentID, actor).Scan(&queued); e != nil || !queued {
			return nil, ErrTeamCollaborationConflict
		}
	}
	workflowID := int64(0)
	if v := contract["workflow_request_id"]; v != nil && fmt.Sprint(v) != "0" {
		workflowID, e = strconv.ParseInt(fmt.Sprint(v), 10, 64)
		if e != nil || workflowID < 1 {
			return nil, ErrTeamCollaborationConflict
		}
	}
	if v := p["workflow_wait_id"]; v != nil {
		return nil, ErrTeamCollaborationConflict
	}
	workflowDeadline, e := teamWorkflowDeadlineTx(ctx, tx, workflowID, taskID)
	if e != nil {
		return nil, ErrTeamCollaborationConflict
	}
	if !workflowDeadline.IsZero() {
		if capped := time.Until(workflowDeadline); capped < lease {
			lease = capped
		}
	}
	if taskDeadline.Valid {
		if capped := time.Until(taskDeadline.Time); capped < lease {
			lease = capped
		}
	}
	if lease <= 0 {
		return nil, ErrTeamCollaborationConflict
	}
	if deps, ok := contract["depends_on"].([]any); ok {
		for _, dep := range deps {
			id := fmt.Sprint(dep)
			var ready bool
			if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 AND kind='intent' AND state='done')`, id, expID).Scan(&ready); e != nil {
				return nil, e
			}
			if !ready {
				return nil, ErrTeamCollaborationConflict
			}
		}
	}
	resource, _ := contract["resource_key"].(string)
	if resource != "" {
		var busy bool
		e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM exploration_nodes WHERE exploration_id=$1 AND kind='intent' AND state='running' AND payload->'contract'->>'resource_key'=$2)`, expID, resource).Scan(&busy)
		if e != nil {
			return nil, e
		}
		if busy {
			return nil, ErrTeamCollaborationConflict
		}
	}
	var epoch, attempt int64
	e = tx.QueryRowContext(ctx, `SELECT COALESCE(max(epoch),0)+1 FROM team_execution_assignments WHERE intent_id=$1`, intentID).Scan(&epoch)
	if e != nil {
		return nil, e
	}
	_ = attempt
	var old int64
	e = tx.QueryRowContext(ctx, `SELECT COALESCE((payload->>'execution_attempt')::bigint,0) FROM exploration_nodes WHERE id=$1`, intentID).Scan(&old)
	if e != nil {
		return nil, e
	}
	attempt = old + 1
	contract["remote_device_id"] = deviceID
	contract["remote_epoch"] = epoch
	contract["remote_assignment_pending"] = true
	delete(contract, "remote_dispatch_pending")
	delete(contract, "remote_dispatch_id")
	p["contract"] = contract
	encoded, e := json.Marshal(p)
	if e != nil {
		return nil, e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE exploration_nodes SET payload=$2::jsonb WHERE id=$1`, intentID, string(encoded)); e != nil {
		return nil, e
	}
	var a TeamExecutionAssignment
	var deadlineArg any
	if !workflowDeadline.IsZero() {
		deadlineArg = workflowDeadline
	}
	e = tx.QueryRowContext(ctx, `INSERT INTO team_execution_assignments(team_id,task_id,intent_id,member_id,device_id,epoch,attempt,resource_key,lease_until,state,config_snapshot,input_snapshot) VALUES($1,$2,$3,$4,$5,$6,$7,$8,LEAST(now()+$9::interval,COALESCE($12::timestamptz,'infinity'::timestamptz)),'assigned',$10::jsonb,$11::jsonb) RETURNING id,team_id,task_id,intent_id,device_id,member_id,epoch,attempt,lease_until,state,config_snapshot,input_snapshot,created_at`, teamID, taskID, intentID, memberID, deviceID, epoch, attempt, resource, fmt.Sprintf("%f seconds", lease.Seconds()), string(config), string(input), deadlineArg).Scan(&a.ID, &a.TeamID, &a.TaskID, &a.IntentID, &a.DeviceID, &a.MemberID, &a.Epoch, &a.Attempt, &a.LeaseUntil, &a.State, &a.Config, &a.Input, &a.CreatedAt)
	if e != nil {
		var pgErr *pgconn.PgError
		if errors.As(e, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrTeamCollaborationConflict
		}
		return nil, e
	}
	if dispatchID > 0 {
		if _, e = tx.ExecContext(ctx, `UPDATE team_dispatch_queue SET state='assigned',assignment_id=$2,last_error='' WHERE id=$1`, dispatchID, a.ID); e != nil {
			return nil, e
		}
	}
	return &a, tx.Commit()
}
func scanTeamAssignment(row *sql.Row) (*TeamExecutionAssignment, error) {
	var a TeamExecutionAssignment
	var result []byte
	var reviewer sql.NullInt64
	var decision, note sql.NullString
	var reviewed sql.NullTime
	e := row.Scan(&a.ID, &a.TeamID, &a.TaskID, &a.IntentID, &a.DeviceID, &a.MemberID, &a.Epoch, &a.Attempt, &a.LeaseUntil, &a.State, &a.Config, &a.Input, &result, &reviewer, &decision, &note, &reviewed, &a.CreatedAt)
	a.Result = result
	if e != nil {
		return nil, e
	}
	if reviewer.Valid {
		a.ReviewMemberID = &reviewer.Int64
	}
	if decision.Valid {
		a.ReviewDecision = decision.String
	}
	if note.Valid {
		a.ReviewNote = note.String
	}
	if reviewed.Valid {
		a.ReviewedAt = &reviewed.Time
	}
	return &a, nil
}

const teamAssignmentCols = `id,team_id,task_id,intent_id,device_id,member_id,epoch,attempt,lease_until,state,config_snapshot,input_snapshot,result,review_member_id,review_decision,review_note,reviewed_at,created_at`
const teamAssignmentBaseCols = `id,team_id,task_id,intent_id,device_id,member_id,epoch,attempt,lease_until,state,config_snapshot,input_snapshot,created_at`

func (d *DB) PollTeamExecutionAssignments(ctx context.Context, deviceID int64, token string, limit int) ([]TeamExecutionAssignment, error) {
	if limit < 1 || limit > 100 {
		limit = 20
	}
	rows, e := d.QueryContext(ctx, `SELECT a.`+strings.ReplaceAll(teamAssignmentBaseCols, ",", `,a.`)+` FROM team_execution_assignments a JOIN team_devices d ON d.id=a.device_id AND d.revoked_at IS NULL AND d.owner_member_id=a.member_id JOIN exploration_nodes n ON n.id=a.intent_id WHERE a.device_id=$1 AND d.token_hash=$2 AND a.state IN ('assigned','claimed','running') AND a.lease_until>now() AND n.payload->'contract'->>'remote_assignment_pending'='true' AND n.payload->'contract'->>'remote_device_id'=a.device_id::text AND n.payload->'contract'->>'remote_epoch'=a.epoch::text AND EXISTS(SELECT 1 FROM team_members m JOIN team_task_permissions p ON p.member_id=m.id AND p.team_id=m.team_id AND p.task_id=a.task_id AND p.permission='execute' WHERE m.id=a.member_id AND m.team_id=a.team_id AND m.revoked_at IS NULL) AND EXISTS(SELECT 1 FROM tasks t WHERE t.id=a.task_id AND t.deleted_at IS NULL AND NOT t.paused AND NOT t.queued AND t.status NOT IN ('paused','finalizing','done','failed','timeout')) AND (COALESCE(n.payload->'contract'->>'workflow_request_id','0')='0' OR EXISTS(SELECT 1 FROM workflow_requests wr WHERE wr.id=(n.payload->'contract'->>'workflow_request_id')::bigint AND wr.target_task_id=a.task_id AND wr.status='pending' AND wr.expires_at>now())) ORDER BY a.created_at LIMIT $3`, deviceID, teamHash(token), limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []TeamExecutionAssignment{}
	for rows.Next() {
		var a TeamExecutionAssignment
		if e = rows.Scan(&a.ID, &a.TeamID, &a.TaskID, &a.IntentID, &a.DeviceID, &a.MemberID, &a.Epoch, &a.Attempt, &a.LeaseUntil, &a.State, &a.Config, &a.Input, &a.CreatedAt); e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (d *DB) transitionTeamAssignment(ctx context.Context, id, deviceID int64, token string, epoch int64, next string, lease time.Duration, result json.RawMessage) (*TeamExecutionAssignment, error) {
	tx, e := d.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	// Every writer follows task -> exploration -> device -> assignment -> intent.
	// First read only the immutable task association to discover the lock roots.
	var taskID, intentID, teamID, memberID int64
	e = tx.QueryRowContext(ctx, `SELECT task_id,intent_id,team_id,member_id FROM team_execution_assignments WHERE id=$1 AND device_id=$2 AND epoch=$3`, id, deviceID, epoch).Scan(&taskID, &intentID, &teamID, &memberID)
	if e != nil {
		return nil, ErrTeamCollaborationDenied
	}
	if next == "completed" {
		var completed bool
		e = tx.QueryRowContext(ctx, `SELECT a.state='completed' AND a.result IS NOT DISTINCT FROM $4::jsonb FROM team_execution_assignments a JOIN team_devices d ON d.id=a.device_id AND d.revoked_at IS NULL JOIN team_members m ON m.id=a.member_id AND m.revoked_at IS NULL WHERE a.id=$1 AND a.device_id=$2 AND a.epoch=$3 AND d.token_hash=$5 AND EXISTS(SELECT 1 FROM team_task_permissions p WHERE p.team_id=a.team_id AND p.task_id=a.task_id AND p.member_id=a.member_id AND p.permission='execute')`, id, deviceID, epoch, nullJSON(result), teamHash(token)).Scan(&completed)
		if e == nil && completed {
			a, scanErr := scanTeamAssignment(tx.QueryRowContext(ctx, `SELECT `+teamAssignmentCols+` FROM team_execution_assignments WHERE id=$1`, id))
			if scanErr != nil {
				return nil, scanErr
			}
			return a, tx.Commit()
		}
		if e != nil && e != sql.ErrNoRows {
			return nil, e
		}
		if e == nil {
			var isCompleted bool
			if scanErr := tx.QueryRowContext(ctx, `SELECT state='completed' FROM team_execution_assignments WHERE id=$1`, id).Scan(&isCompleted); scanErr == nil && isCompleted {
				return nil, ErrTeamCollaborationConflict
			}
		}
	}
	var expID int64
	e = tx.QueryRowContext(ctx, `SELECT exploration_id FROM tasks WHERE id=$1 AND deleted_at IS NULL AND NOT queued AND status NOT IN ('finalizing','done','failed','timeout') AND ((NOT paused AND status<>'paused') OR $2='completed') FOR UPDATE`, taskID, next).Scan(&expID)
	if e != nil {
		return nil, ErrTeamCollaborationDenied
	}
	if _, e = tx.ExecContext(ctx, `SELECT id FROM explorations WHERE id=$1 FOR UPDATE`, expID); e != nil {
		return nil, e
	}
	var lockedMember int64
	e = tx.QueryRowContext(ctx, `SELECT id FROM team_members WHERE id=$1 AND team_id=$2 AND revoked_at IS NULL FOR SHARE`, memberID, teamID).Scan(&lockedMember)
	if e != nil {
		return nil, ErrTeamCollaborationDenied
	}
	var a TeamExecutionAssignment
	var ownerMemberID int64
	e = tx.QueryRowContext(ctx, `SELECT owner_member_id FROM team_devices WHERE id=$1 AND revoked_at IS NULL AND token_hash=$2 FOR UPDATE`, deviceID, teamHash(token)).Scan(&ownerMemberID)
	if e != nil {
		return nil, ErrTeamCollaborationDenied
	}
	loaded, loadErr := scanTeamAssignment(tx.QueryRowContext(ctx, `SELECT `+teamAssignmentCols+` FROM team_execution_assignments WHERE id=$1 AND task_id=$2 AND intent_id=$3 AND team_id=$4 AND device_id=$5 AND epoch=$6 AND member_id=$7 AND lease_until>now() FOR UPDATE`, id, taskID, intentID, teamID, deviceID, epoch, ownerMemberID))
	e = loadErr
	if e != nil {
		return nil, ErrTeamCollaborationDenied
	}
	a = *loaded
	if e = teamPermissionTx(ctx, tx, a.TeamID, a.TaskID, a.MemberID, "execute"); e != nil {
		return nil, ErrTeamCollaborationDenied
	}
	var portable struct {
		Version int `json:"version"`
	}
	_ = json.Unmarshal(a.Config, &portable)
	if portable.Version == 1 {
		if e = teamPermissionTx(ctx, tx, a.TeamID, a.TaskID, a.MemberID, "read"); e != nil {
			return nil, e
		}
	}
	var payload []byte
	var intentState string
	var intentOwner string
	e = tx.QueryRowContext(ctx, `SELECT payload,state,COALESCE(owner,'') FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 AND kind='intent' FOR UPDATE`, a.IntentID, expID).Scan(&payload, &intentState, &intentOwner)
	if e != nil {
		return nil, ErrTeamCollaborationDenied
	}
	var node map[string]any
	if json.Unmarshal(payload, &node) != nil {
		return nil, ErrTeamCollaborationConflict
	}
	contract, _ := node["contract"].(map[string]any)
	if contract == nil || fmt.Sprint(contract["remote_assignment_pending"]) != "true" || fmt.Sprint(contract["remote_device_id"]) != fmt.Sprint(deviceID) || fmt.Sprint(contract["remote_epoch"]) != fmt.Sprint(epoch) {
		return nil, ErrTeamCollaborationConflict
	}
	workflowID := int64(0)
	if v := contract["workflow_request_id"]; v != nil && fmt.Sprint(v) != "0" {
		workflowID, e = strconv.ParseInt(fmt.Sprint(v), 10, 64)
		if e != nil || workflowID < 1 {
			return nil, ErrTeamCollaborationDenied
		}
	}
	deadline, e := teamWorkflowDeadlineTx(ctx, tx, workflowID, a.TaskID)
	if e != nil {
		return nil, ErrTeamCollaborationDenied
	}
	var taskDeadline sql.NullTime
	if e = tx.QueryRowContext(ctx, `SELECT deadline_at FROM tasks WHERE id=$1`, a.TaskID).Scan(&taskDeadline); e != nil {
		return nil, e
	}
	if taskDeadline.Valid && (deadline.IsZero() || taskDeadline.Time.Before(deadline)) {
		deadline = taskDeadline.Time
	}
	var conf map[string]any
	if len(a.Config) > 0 {
		_ = json.Unmarshal(a.Config, &conf)
	}
	if conf != nil && conf["version"] == float64(1) {
		if seconds, ok := conf["budget_seconds"].(float64); ok && seconds > 0 {
			started := time.Now()
			if a.State != "assigned" {
				if e = tx.QueryRowContext(ctx, `SELECT COALESCE(started_at,created_at) FROM team_execution_assignments WHERE id=$1`, a.ID).Scan(&started); e != nil {
					return nil, e
				}
			}
			hard := started.Add(time.Duration(int64(seconds)) * time.Second)
			if deadline.IsZero() || hard.Before(deadline) {
				deadline = hard
			}
		}
	}
	if a.State != "assigned" && a.State != "claimed" && a.State != "running" {
		return nil, ErrTeamCollaborationConflict
	}
	if a.State == "assigned" && intentState != "open" && intentState != "waiting" {
		return nil, ErrTeamCollaborationConflict
	}
	if (a.State == "claimed" || a.State == "running") && (intentState != "running" || intentOwner != fmt.Sprint(deviceID)) {
		return nil, ErrTeamCollaborationConflict
	}
	if next == "claimed" && (a.State == "claimed" || a.State == "running") {
		return &a, tx.Commit()
	}
	if next == "heartbeat" && a.State == "assigned" {
		return nil, ErrTeamCollaborationConflict
	}
	if next == "completed" && a.State != "running" {
		var checkpoint struct {
			Outcome string `json:"outcome"`
		}
		_ = json.Unmarshal(result, &checkpoint)
		if a.State != "claimed" || (checkpoint.Outcome != "blocked" && checkpoint.Outcome != "failed") {
			return nil, ErrTeamCollaborationConflict
		}
	}
	if next == "claimed" {
		if intentState != "open" && intentState != "waiting" {
			return nil, ErrTeamCollaborationConflict
		}
		node["execution_attempt"] = a.Attempt
		encoded, mErr := json.Marshal(node)
		if mErr != nil {
			return nil, mErr
		}
		if _, e = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='running',owner=$2,payload=$3::jsonb WHERE id=$1`, a.IntentID, fmt.Sprint(deviceID), string(encoded)); e != nil {
			return nil, e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE team_execution_assignments SET state='claimed',started_at=COALESCE(started_at,now()) WHERE id=$1`, id); e != nil {
			return nil, e
		}
		a.State = "claimed"
		return &a, tx.Commit()
	}
	if next == "heartbeat" {
		if lease < time.Minute || lease > 24*time.Hour {
			return nil, fmt.Errorf("invalid lease")
		}
		if !deadline.IsZero() {
			if capped := time.Until(deadline); capped < lease {
				lease = capped
			}
		}
		if lease <= 0 {
			return nil, ErrTeamCollaborationDenied
		}
		var deadlineArg any
		if !deadline.IsZero() {
			deadlineArg = deadline
		}
		e = tx.QueryRowContext(ctx, `UPDATE team_execution_assignments SET state='running',lease_until=LEAST(now()+$2::interval,COALESCE($3::timestamptz,'infinity'::timestamptz)) WHERE id=$1 RETURNING lease_until`, id, fmt.Sprintf("%f seconds", lease.Seconds()), deadlineArg).Scan(&a.LeaseUntil)
		if e == nil {
			res, updateErr := tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='running',owner=$2 WHERE id=$1 AND state='running' AND owner=$2`, a.IntentID, fmt.Sprint(deviceID))
			e = updateErr
			if e == nil {
				changed, _ := res.RowsAffected()
				if changed != 1 {
					e = ErrTeamCollaborationConflict
				}
			}
		}
	} else {
		_, e = tx.ExecContext(ctx, `UPDATE team_execution_assignments SET state=$2,result=CASE WHEN $2='completed' THEN $3::jsonb ELSE result END,finished_at=now() WHERE id=$1`, id, next, nullJSON(result))
		if next == "completed" {
			a.Result = json.RawMessage(nullJSON(result))
		}
	}
	if e != nil {
		return nil, e
	}
	if next == "completed" || next == "cancelled" {
		_, e = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='paused',owner=NULL,payload=payload #- '{contract,remote_assignment_pending}' #- '{contract,remote_device_id}' #- '{contract,remote_epoch}' WHERE id=$1 AND payload->'contract'->>'remote_assignment_pending'='true' AND payload->'contract'->>'remote_epoch'=$2 AND state IN ('open','waiting','running')`, a.IntentID, fmt.Sprint(epoch))
		if e != nil {
			return nil, e
		}
	}
	if next == "heartbeat" {
		a.State = "running"
	} else {
		a.State = next
	}
	return &a, tx.Commit()
}
func nullJSON(b []byte) string {
	if len(b) == 0 {
		return "null"
	}
	if !json.Valid(b) {
		return "null"
	}
	return string(b)
}
func (d *DB) ClaimTeamExecutionAssignment(ctx context.Context, id, deviceID int64, token string, epoch int64) (*TeamExecutionAssignment, error) {
	return d.transitionTeamAssignment(ctx, id, deviceID, token, epoch, "claimed", 0, nil)
}
func (d *DB) HeartbeatTeamExecutionAssignment(ctx context.Context, id, deviceID int64, token string, epoch int64, lease time.Duration) (*TeamExecutionAssignment, error) {
	return d.transitionTeamAssignment(ctx, id, deviceID, token, epoch, "heartbeat", lease, nil)
}
func (d *DB) CompleteTeamExecutionAssignment(ctx context.Context, id, deviceID int64, token string, epoch int64, result json.RawMessage) (*TeamExecutionAssignment, error) {
	if len(result) > 0 && !validJSONSnapshot(result) {
		return nil, fmt.Errorf("invalid result json")
	}
	return d.transitionTeamAssignment(ctx, id, deviceID, token, epoch, "completed", 0, result)
}
func (d *DB) CancelTeamExecutionAssignment(ctx context.Context, id, deviceID int64, token string, epoch int64) (*TeamExecutionAssignment, error) {
	return d.transitionTeamAssignment(ctx, id, deviceID, token, epoch, "cancelled", 0, nil)
}
func (d *DB) ReconcileTeamExecutionAssignments(ctx context.Context, now time.Time) (int64, error) {
	rows, e := d.QueryContext(ctx, `SELECT id,task_id,intent_id,device_id,epoch FROM team_execution_assignments WHERE state IN ('assigned','claimed','running') AND lease_until<=$1 ORDER BY task_id,id`, now)
	if e != nil {
		return 0, e
	}
	type expired struct{ id, task, intent, device, epoch int64 }
	xs := []expired{}
	for rows.Next() {
		var x expired
		if e = rows.Scan(&x.id, &x.task, &x.intent, &x.device, &x.epoch); e != nil {
			rows.Close()
			return 0, e
		}
		xs = append(xs, x)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return 0, e
	}
	var count int64
	for _, x := range xs {
		tx, txErr := d.BeginTx(ctx, nil)
		if txErr != nil {
			return count, txErr
		}
		if txErr = LockTaskEvidenceTx(tx, x.task); txErr != nil {
			_ = tx.Rollback()
			if errors.Is(txErr, ErrTaskArchiveState) || errors.Is(txErr, sql.ErrNoRows) {
				continue
			}
			return count, txErr
		}
		var expID int64
		txErr = tx.QueryRowContext(ctx, `SELECT exploration_id FROM tasks WHERE id=$1 FOR UPDATE`, x.task).Scan(&expID)
		if txErr == sql.ErrNoRows {
			_ = tx.Rollback()
			continue
		}
		if txErr != nil {
			_ = tx.Rollback()
			return count, txErr
		}
		if _, txErr = tx.ExecContext(ctx, `SELECT id FROM explorations WHERE id=$1 FOR UPDATE`, expID); txErr != nil {
			_ = tx.Rollback()
			return count, txErr
		}
		if _, txErr = tx.ExecContext(ctx, `SELECT id FROM team_devices WHERE id=$1 FOR UPDATE`, x.device); txErr != nil {
			_ = tx.Rollback()
			return count, txErr
		}
		var currentID int64
		txErr = tx.QueryRowContext(ctx, `SELECT id FROM team_execution_assignments WHERE id=$1 AND task_id=$2 AND intent_id=$3 AND device_id=$4 AND epoch=$5 AND state IN ('assigned','claimed','running') AND lease_until<=$6 FOR UPDATE`, x.id, x.task, x.intent, x.device, x.epoch, now).Scan(&currentID)
		if txErr == sql.ErrNoRows {
			_ = tx.Rollback()
			continue
		}
		if txErr != nil {
			_ = tx.Rollback()
			return count, txErr
		}
		if _, txErr = tx.ExecContext(ctx, `SELECT id FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 FOR UPDATE`, x.intent, expID); txErr != nil {
			_ = tx.Rollback()
			return count, txErr
		}
		if _, txErr = tx.ExecContext(ctx, `UPDATE team_execution_assignments SET state='expired',finished_at=$2 WHERE id=$1`, x.id, now); txErr != nil {
			_ = tx.Rollback()
			return count, txErr
		}
		if _, txErr = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='paused',owner=NULL,payload=payload #- '{contract,remote_assignment_pending}' #- '{contract,remote_device_id}' #- '{contract,remote_epoch}' WHERE id=$1 AND state IN ('open','waiting','running') AND payload->'contract'->>'remote_assignment_pending'='true' AND payload->'contract'->>'remote_device_id'=$2 AND payload->'contract'->>'remote_epoch'=$3`, x.intent, fmt.Sprint(x.device), fmt.Sprint(x.epoch)); txErr != nil {
			_ = tx.Rollback()
			return count, txErr
		}
		if txErr = tx.Commit(); txErr != nil {
			return count, txErr
		}
		count++
	}
	return count, nil
}

// RecordTeamCommandReceipt only deduplicates receipt storage. It does not make
// a surrounding business operation atomic or exactly-once; callers must commit
// the business mutation and its receipt in one transaction when that guarantee is needed.
func (d *DB) RecordTeamCommandReceipt(ctx context.Context, teamID, memberID int64, commandID string, payload json.RawMessage, result json.RawMessage) (json.RawMessage, error) {
	if strings.TrimSpace(commandID) == "" || len(commandID) > 200 || !validJSONSnapshot(payload) || len(result) > 0 && !json.Valid(result) {
		return nil, fmt.Errorf("invalid command receipt")
	}
	hash := teamHash(string(payload))
	tx, e := d.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if e = teamMemberTx(ctx, tx, teamID, memberID); e != nil {
		return nil, e
	}
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, fmt.Sprintf("team-receipt:%d:%d:%s", teamID, memberID, commandID)); e != nil {
		return nil, e
	}
	var existingHash string
	var existing []byte
	e = tx.QueryRowContext(ctx, `SELECT payload_hash,result FROM team_command_receipts WHERE team_id=$1 AND member_id=$2 AND command_id=$3 FOR UPDATE`, teamID, memberID, commandID).Scan(&existingHash, &existing)
	if e == nil {
		if existingHash != hash {
			return nil, ErrTeamCollaborationConflict
		}
		return existing, tx.Commit()
	}
	if e != sql.ErrNoRows {
		return nil, e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO team_command_receipts(team_id,member_id,command_id,payload_hash,result) VALUES($1,$2,$3,$4,$5::jsonb)`, teamID, memberID, commandID, hash, nullJSON(result))
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return result, nil
}
