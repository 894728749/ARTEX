package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/collab"
)

type TeamMessage struct {
	ID             int64     `json:"id"`
	Kind           string    `json:"kind"`
	Text           string    `json:"text"`
	CreatedAt      time.Time `json:"created_at"`
	ExecutorID     int64     `json:"executor_id"`
	MemberID       int64     `json:"member_id"`
	GuidanceStatus string    `json:"guidance_status,omitempty"`
}

// MessagePage is an allowlist projection of THIS exploration. No inherited
// activity, metadata, reasoning, tool blobs or credentials are exposed here.
func (s *ExplorationStore) MessagePage(ctx context.Context, f ActivitySessionFilter, before int64, limit int) ([]TeamMessage, bool, error) {
	return s.messageWindow(ctx, f, before, limit, false)
}

func (s *ExplorationStore) MessageSince(ctx context.Context, f ActivitySessionFilter, after int64, limit int) ([]TeamMessage, bool, error) {
	return s.messageWindow(ctx, f, after, limit, true)
}

func (s *ExplorationStore) messageWindow(ctx context.Context, f ActivitySessionFilter, cursor int64, limit int, forward bool) ([]TeamMessage, bool, error) {
	if limit < 1 || limit > 200 {
		limit = 100
	}
	cond, args := f.cond(2)
	values := append([]any{s.expID}, args...)
	barg := len(values) + 1
	values = append(values, cursor, limit+1)
	order, compare := "DESC", "<"
	if forward {
		order, compare = "ASC", ">"
	}
	q := fmt.Sprintf(`SELECT a.id,CASE WHEN a.kind='result' THEN 'text' ELSE a.kind END,CASE WHEN a.kind='user' THEN COALESCE(a.summary,'') ELSE COALESCE(NULLIF(a.detail,''),a.summary,'') END,a.created_at,
	 COALESCE(x.device_id,0),COALESCE(m.member_id,0),
	 CASE WHEN m.direction='user' THEN CASE WHEN m.delivered_at IS NOT NULL THEN 'delivered'
	 WHEN x.state NOT IN ('assigned','claimed','running') OR x.lease_until<=now() OR x.messages_closed THEN 'closed' ELSE 'pending' END ELSE '' END
	 FROM (SELECT * FROM activity WHERE exploration_id=$1%s AND (kind IN ('text','user') OR (kind='result' AND COALESCE(tool,'')='')) AND ($%d<=0 OR id%s$%d) ORDER BY id %s LIMIT $%d) a
	 LEFT JOIN team_execution_messages m ON m.activity_id=a.id
	 LEFT JOIN team_execution_assignments x ON x.id=m.assignment_id ORDER BY a.id %s`, cond, barg, compare, barg, order, barg+1, order)
	rows, err := s.db.QueryContext(ctx, q, values...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	items := []TeamMessage{}
	for rows.Next() {
		var m TeamMessage
		if err = rows.Scan(&m.ID, &m.Kind, &m.Text, &m.CreatedAt, &m.ExecutorID, &m.MemberID, &m.GuidanceStatus); err != nil {
			return nil, false, err
		}
		items = append(items, m)
	}
	if err = rows.Err(); err != nil {
		return nil, false, err
	}
	more := len(items) > limit
	if more {
		items = items[:limit]
	}
	if !forward {
		for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
			items[i], items[j] = items[j], items[i]
		}
	}
	return items, more, nil
}

func validTeamText(s string, max int) bool {
	return strings.TrimSpace(s) != "" && len(s) <= max && !strings.ContainsRune(s, 0) && utf8.ValidString(s)
}

func addTeamMessageTx(ctx context.Context, tx *sql.Tx, a *TeamExecutionAssignment, exp int64, kind, key, text string, member int64) (int64, error) {
	var id int64
	var body string
	err := tx.QueryRowContext(ctx, `SELECT id,body FROM team_execution_messages WHERE assignment_id=$1 AND epoch=$2 AND direction=$3 AND dedup_key=$4`, a.ID, a.Epoch, kind, key).Scan(&id, &body)
	if err == nil {
		if body != text {
			return 0, ErrTeamCollaborationConflict
		}
		return id, nil
	}
	if err != sql.ErrNoRows {
		return 0, err
	}
	var activity int64
	err = tx.QueryRowContext(ctx, `INSERT INTO activity(exploration_id,node_id,worker,kind,summary,detail) VALUES($1,$2,$3,$4,$5,$5) RETURNING id`, exp, a.IntentID, fmt.Sprintf("device#%d", a.DeviceID), kind, text).Scan(&activity)
	if err != nil {
		return 0, err
	}
	err = tx.QueryRowContext(ctx, `INSERT INTO team_execution_messages(assignment_id,epoch,direction,dedup_key,body,member_id,activity_id) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`, a.ID, a.Epoch, kind, key, text, member, activity).Scan(&id)
	return id, err
}

// QueueTeamGuidance serializes with device exchange/seal and result submission.
// A request is bound to an exact assignment epoch, never a later replacement.
func (d *DB) QueueTeamGuidance(ctx context.Context, team, task, intent, assignment, epoch, member int64, key, text string) error {
	if !validTeamText(text, 16000) || utf8.RuneCountInString(text) > 4000 || !validTeamText(key, 128) {
		return ErrTeamCollaborationConflict
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exp int64
	err = tx.QueryRowContext(ctx, `SELECT exploration_id FROM tasks WHERE id=$1 AND NOT paused AND (NOT queued OR queue_mode='remote_resume') AND deleted_at IS NULL AND archived_at IS NULL AND status NOT IN ('paused','finalizing','done','failed','timeout') AND EXISTS(SELECT 1 FROM team_tasks WHERE team_id=$2 AND task_id=$1) FOR UPDATE`, task, team).Scan(&exp)
	if err != nil {
		return ErrTeamCollaborationDenied
	}
	if _, err = tx.ExecContext(ctx, `SELECT id FROM explorations WHERE id=$1 FOR UPDATE`, exp); err != nil {
		return err
	}
	if member != 0 {
		for _, p := range []string{"read", "execute"} {
			if err = teamPermissionTx(ctx, tx, team, task, member, p); err != nil {
				return err
			}
		}
	}
	a, err := scanTeamAssignment(tx.QueryRowContext(ctx, `SELECT `+teamAssignmentCols+` FROM team_execution_assignments WHERE id=$1 AND team_id=$2 AND task_id=$3 AND intent_id=$4 AND epoch=$5 FOR UPDATE`, assignment, team, task, intent, epoch))
	if err != nil {
		return ErrTeamCollaborationConflict
	}
	// A retry keeps its original acknowledgement even if the run just ended.
	dedup := fmt.Sprintf("%d:%s", member, key)
	var old string
	err = tx.QueryRowContext(ctx, `SELECT body FROM team_execution_messages WHERE assignment_id=$1 AND epoch=$2 AND direction='user' AND dedup_key=$3`, assignment, epoch, dedup).Scan(&old)
	if err == nil {
		if old != text {
			return ErrTeamCollaborationConflict
		}
		return tx.Commit()
	}
	if err != sql.ErrNoRows {
		return err
	}
	var ready, closed, ownerActive bool
	err = tx.QueryRowContext(ctx, `SELECT a.messages_ready,a.messages_closed,EXISTS(SELECT 1 FROM team_devices d JOIN team_members m ON m.id=d.owner_member_id WHERE d.id=a.device_id AND d.revoked_at IS NULL AND m.revoked_at IS NULL) FROM team_execution_assignments a WHERE id=$1`, assignment).Scan(&ready, &closed, &ownerActive)
	if err != nil {
		return err
	}
	if !ready || closed || !ownerActive || (a.State != "claimed" && a.State != "running") || !a.LeaseUntil.After(time.Now()) {
		return ErrTeamCollaborationConflict
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM team_execution_messages WHERE assignment_id=$1 AND direction='user' AND delivered_at IS NULL`, assignment).Scan(&count); err != nil {
		return err
	}
	if count >= 32 {
		return ErrTeamCollaborationConflict
	}
	if _, err = addTeamMessageTx(ctx, tx, a, exp, "user", dedup, text, member); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) ExchangeTeamMessages(ctx context.Context, id, device int64, token string, in collab.MessageExchange) (*collab.MessageExchangeReply, error) {
	if len(in.Messages) > 32 || len(in.Delivered) > 32 {
		return nil, ErrTeamCollaborationConflict
	}
	for _, m := range in.Messages {
		if m.Seq < 1 || !validTeamText(m.Text, 64<<10) {
			return nil, ErrTeamCollaborationConflict
		}
	}
	out := &collab.MessageExchangeReply{Guidance: []collab.Guidance{}}
	_, err := d.transitionTeamAssignmentMessages(ctx, id, device, token, in.Epoch, "heartbeat", 2*time.Minute, nil, &in, out)
	return out, err
}

func exchangeTeamMessagesTx(ctx context.Context, tx *sql.Tx, a *TeamExecutionAssignment, exp int64, in *collab.MessageExchange, out *collab.MessageExchangeReply) error {
	var closed bool
	if err := tx.QueryRowContext(ctx, `SELECT messages_closed FROM team_execution_assignments WHERE id=$1`, a.ID).Scan(&closed); err != nil {
		return err
	}
	if closed {
		out.Sealed = true
		return nil
	}
	for _, m := range in.Messages {
		if _, err := addTeamMessageTx(ctx, tx, a, exp, "text", fmt.Sprint(m.Seq), m.Text, 0); err != nil {
			return err
		}
	}
	for _, id := range in.Delivered {
		if _, err := tx.ExecContext(ctx, `UPDATE team_execution_messages SET delivered_at=COALESCE(delivered_at,now()) WHERE id=$1 AND assignment_id=$2 AND epoch=$3 AND direction='user'`, id, a.ID, a.Epoch); err != nil {
			return err
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,body FROM team_execution_messages WHERE assignment_id=$1 AND epoch=$2 AND direction='user' AND delivered_at IS NULL ORDER BY id LIMIT 32`, a.ID, a.Epoch)
	if err != nil {
		return err
	}
	for rows.Next() {
		var g collab.Guidance
		if err = rows.Scan(&g.ID, &g.Text); err != nil {
			rows.Close()
			return err
		}
		out.Guidance = append(out.Guidance, g)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	out.Sealed = in.Seal && len(out.Guidance) == 0
	_, err = tx.ExecContext(ctx, `UPDATE team_execution_assignments SET messages_ready=true,messages_closed=$2 WHERE id=$1`, a.ID, out.Sealed)
	return err
}
