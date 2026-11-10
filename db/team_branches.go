package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/collab"
)

// Branch commands always lock task -> project -> member/permission. Existing
// task archive/delete guards therefore serialize with every branch mutation.
func (d *DB) BranchMode(ctx context.Context, task int64) (bool, error) {
	var enabled bool
	err := d.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM team_branch_projects WHERE task_id=$1)`, task).Scan(&enabled)
	return enabled, err
}

func branchLoadTx(ctx context.Context, tx *sql.Tx, team, task int64, write bool) (*collab.BranchProject, error) {
	suffix := " FOR SHARE"
	if write {
		suffix = " FOR UPDATE"
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT state FROM team_branch_projects WHERE team_id=$1 AND task_id=$2`+suffix, team, task).Scan(&raw); err != nil {
		return nil, err
	}
	var p collab.BranchProject
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func branchActorTx(ctx context.Context, tx *sql.Tx, team, task int64, a collab.BranchActor) (collab.BranchActor, error) {
	var status string
	if err := tx.QueryRowContext(ctx, `SELECT paused,status FROM tasks WHERE id=$1 AND deleted_at IS NULL AND archived_at IS NULL`, task).Scan(&a.TaskPaused, &status); err != nil {
		return a, ErrTeamCollaborationDenied
	}
	a.TaskTerminal = slices.Contains([]string{"done", "failed", "timeout", "finalizing"}, status)
	if !a.Admin {
		if err := teamPermissionTx(ctx, tx, team, task, a.MemberID, "read"); err != nil {
			return a, err
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT d.id,d.owner_member_id,d.capabilities,d.revoked_at IS NULL AND m.revoked_at IS NULL,
 COALESCE(d.last_seen_at>now()-interval '30 seconds',false)
 FROM team_devices d JOIN team_members m ON m.id=d.owner_member_id WHERE d.team_id=$1`, team)
	if err != nil {
		return a, err
	}
	defer rows.Close()
	a.Devices = map[int64]collab.BranchDevice{}
	for rows.Next() {
		var v collab.BranchDevice
		var raw []byte
		if err = rows.Scan(&v.ID, &v.OwnerID, &raw, &v.Active, &v.Online); err != nil {
			return a, err
		}
		var caps struct {
			Protocol         int                     `json:"branch_protocol"`
			Roles            []string                `json:"roles"`
			RoleCapabilities map[string][]string     `json:"role_capabilities"`
			RuntimeProfiles  []collab.RuntimeProfile `json:"runtime_profiles"`
		}
		if json.Unmarshal(raw, &caps) == nil {
			v.Protocol = caps.Protocol
			v.Roles = caps.Roles
			v.RoleCapabilities = caps.RoleCapabilities
			v.RuntimeProfiles = caps.RuntimeProfiles
		}
		a.Devices[v.ID] = v
	}
	if err = rows.Err(); err != nil {
		return a, err
	}
	if a.DeviceID > 0 {
		dev, ok := a.Devices[a.DeviceID]
		if !ok || !dev.Active || dev.OwnerID != a.MemberID || dev.Protocol != collab.BranchProtocol {
			return a, ErrTeamCollaborationDenied
		}
		if err = teamPermissionTx(ctx, tx, team, task, a.MemberID, "execute"); err != nil {
			return a, err
		}
	}
	return a, nil
}

func (d *DB) CreateBranchProject(ctx context.Context, team, task int64, a collab.BranchActor, policy collab.BranchPolicy) (*collab.BranchProject, error) {
	if err := collab.ValidateBranchPolicy(policy); err != nil {
		return nil, err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = LockTaskEvidenceTx(tx, task); err != nil {
		return nil, err
	}
	if !a.Admin {
		if err = teamPermissionTx(ctx, tx, team, task, a.MemberID, "manage"); err != nil {
			return nil, err
		}
	}
	var shared, paused bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM team_tasks WHERE team_id=$1 AND task_id=$2),paused FROM tasks WHERE id=$2`, team, task).Scan(&shared, &paused); err != nil || !shared || !paused {
		return nil, fmt.Errorf("分支模式只能在已共享且暂停的任务上明确启用")
	}
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM team_execution_assignments WHERE task_id=$1 AND state IN ('assigned','claimed','running')) OR EXISTS(SELECT 1 FROM team_dispatch_queue WHERE task_id=$1 AND state='queued') OR EXISTS(SELECT 1 FROM exploration_nodes n JOIN tasks t ON t.exploration_id=n.exploration_id WHERE t.id=$1 AND n.kind='intent' AND n.state='running')`, task).Scan(&active); err != nil {
		return nil, err
	}
	if active {
		return nil, fmt.Errorf("请先结束现有工作单，再启用分支模式")
	}
	p := &collab.BranchProject{TeamID: team, TaskID: task, Revision: 1, Policy: policy, State: "paused", Pool: []collab.BranchPoolWork{}, Branches: []collab.ExecutionBranch{}, Permissions: map[string][]string{}, Receipts: map[string]collab.BranchReceipt{}}
	if a.MemberID > 0 {
		p.Permissions[strconv.FormatInt(a.MemberID, 10)] = append([]string{}, collab.BranchPermissions...)
	}
	raw, _ := json.Marshal(p)
	if _, err = tx.ExecContext(ctx, `INSERT INTO team_branch_projects(team_id,task_id,state) VALUES($1,$2,$3)`, team, task, raw); err != nil {
		return nil, err
	}
	return p, tx.Commit()
}

func (d *DB) ApplyBranchCommand(ctx context.Context, team, task int64, a collab.BranchActor, c collab.BranchCommand) (*collab.BranchReply, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = LockTaskEvidenceTx(tx, task); err != nil {
		return nil, err
	}
	p, err := branchLoadTx(ctx, tx, team, task, true)
	if err != nil {
		return nil, err
	}
	a, err = branchActorTx(ctx, tx, team, task, a)
	if err != nil {
		return nil, err
	}
	if a.DeviceID > 0 {
		if err = collab.CheckBranchAccess(p, a, c.BranchID, "execute"); err != nil {
			return nil, err
		}
	}
	// A grant/transfer cannot target identities outside this team, even when the
	// request is made by the system administrator.
	if c.MemberID > 0 {
		if err = teamMemberTx(ctx, tx, team, c.MemberID); err != nil {
			return nil, err
		}
	}
	if c.Type == "claim" || c.Type == "transfer" {
		member := a.MemberID
		if c.MemberID > 0 {
			member = c.MemberID
		}
		for _, permission := range []string{"read", "execute"} {
			if err = teamPermissionTx(ctx, tx, team, task, member, permission); err != nil {
				return nil, err
			}
		}
	}
	if c.Unit != nil {
		var contract WorkContract
		if json.Unmarshal(c.Unit.Contract, &contract) != nil || contract.ExecutionRole != c.Unit.Role || len(contract.Acceptance) == 0 || contract.BudgetSeconds < 1 || contract.BudgetSeconds > 7200 {
			return nil, fmt.Errorf("工作单合同必须绑定角色、验收条件和有限预算")
		}
		// Dependencies remain branch-local unit IDs; contracts must agree with the
		// explicit protocol field rather than introducing a hidden second graph.
		if !slices.Equal(contract.DependsOn, c.Unit.DependsOn) {
			return nil, fmt.Errorf("合同依赖与工作单依赖不一致")
		}
	}
	if err = lockBranchResources(ctx, tx, team); err != nil {
		return nil, err
	}
	if err = reserveBranchOperation(ctx, tx, p, c); err != nil {
		return nil, err
	}
	receipt, events, err := collab.ApplyBranchCommand(p, a, c, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if err = syncBranchAssistance(ctx, tx, p); err != nil {
		return nil, err
	}
	if c.Type == "project_pause" || c.Type == "project_resume" || c.Type == "close" || c.Type == "invalidate_evidence" {
		paused := p.State != "running"
		if _, err = tx.ExecContext(ctx, `UPDATE tasks SET paused=$2,queued=false,queue_mode='' WHERE id=$1`, task, paused); err != nil {
			return nil, err
		}
	}
	for _, ev := range events {
		p.Cursor++
		ev.ID = p.Cursor
		ev.CreatedAt = time.Now().UTC()
		raw, e := json.Marshal(ev)
		if e != nil {
			return nil, e
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO team_branch_events(task_id,seq,branch_id,event) VALUES($1,$2,$3,$4)`, task, ev.ID, ev.BranchID, raw); err != nil {
			return nil, err
		}
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if len(raw) > 32<<20 {
		return nil, fmt.Errorf("分支项目状态超过大小上限")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE team_branch_projects SET state=$2,updated_at=now() WHERE task_id=$1`, task, raw); err != nil {
		return nil, err
	}
	reply := &collab.BranchReply{Policy: p.Policy, Receipt: receipt, Cursor: p.Cursor}
	bid := c.BranchID
	if receipt.BranchID > 0 {
		bid = receipt.BranchID
	}
	for i := range p.Branches {
		if p.Branches[i].ID == bid {
			copy := p.Branches[i]
			reply.Branch = &copy
			break
		}
	}
	if a.DeviceID > 0 {
		restrictBranchReply(reply)
		branchReplyDependencies(p, a, reply)
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return reply, nil
}

func restrictBranchReply(r *collab.BranchReply) {
	if r.Branch == nil {
		return
	}
	b := r.Branch
	assets := []collab.BranchAsset{}
	for _, v := range r.Policy.Assets {
		if slices.Contains(b.Spec.AssetIDs, v.ID) {
			assets = append(assets, v)
		}
	}
	r.Policy.Assets = assets
	materials := []collab.Material{}
	for _, v := range r.Policy.Materials {
		if slices.Contains(b.Spec.MaterialHashes, v.SHA256) {
			materials = append(materials, v)
		}
	}
	r.Policy.Materials = materials
	roles := map[string]collab.ExecutionConfig{}
	for k, v := range r.Policy.Roles {
		if slices.Contains(b.Spec.Roles, k) {
			roles[k] = v
		}
	}
	r.Policy.Roles = roles
	r.Policy.PlannerPrompts = map[string]string{b.Spec.Kind: r.Policy.PlannerPrompts[b.Spec.Kind]}
}

func branchReplyDependencies(p *collab.BranchProject, a collab.BranchActor, r *collab.BranchReply) {
	if r.Branch == nil {
		return
	}
	if r.Branch.Spec.Coordinator {
		view := collab.BranchProject{TeamID: p.TeamID, TaskID: p.TaskID, Revision: p.Revision, State: p.State, Policy: p.Policy}
		view.Policy.PlannerPrompts = nil
		view.Policy.Materials = nil
		view.Policy.Roles = map[string]collab.ExecutionConfig{}
		for key, cfg := range p.Policy.Roles {
			cfg.SystemPrompt = ""
			view.Policy.Roles[key] = cfg
		}
		for _, w := range p.Pool {
			if w.Spec.Restricted && !slices.Contains(w.Spec.Members, a.MemberID) {
				continue
			}
			w.Spec.MaterialHashes = nil
			view.Pool = append(view.Pool, w)
		}
		for _, b := range p.Branches {
			if collab.CheckBranchAccess(p, a, b.ID, "process") != nil {
				continue
			}
			b.Units = nil
			b.Operations = nil
			b.Guidance = nil
			b.Checkpoint = ""
			b.Spec.MaterialHashes = nil
			view.Branches = append(view.Branches, b)
		}
		r.Coordination = &collab.BranchSnapshot{Project: view}
	}
	for _, source := range p.Branches {
		if !slices.Contains(r.Branch.Spec.DependsOn, source.ID) || collab.CheckBranchAccess(p, a, source.ID, "process") != nil {
			continue
		}
		source.Operations = nil
		source.Guidance = nil
		if collab.CheckBranchAccess(p, a, source.ID, "evidence") != nil {
			units := append([]collab.BranchUnit{}, source.Units...)
			for i := range units {
				if units[i].Result != nil {
					v := *units[i].Result
					v.Evidence = nil
					units[i].Result = &v
				}
			}
			source.Units = units
			source.Spec.MaterialHashes = nil
		}
		r.Dependencies = append(r.Dependencies, source)
	}
}

func (d *DB) BranchDevicePoll(ctx context.Context, device *TeamDevice) ([]collab.BranchReply, error) {
	rows, err := d.QueryContext(ctx, `SELECT p.task_id FROM team_branch_projects p JOIN tasks t ON t.id=p.task_id WHERE p.team_id=$1 AND t.deleted_at IS NULL AND t.archived_at IS NULL ORDER BY p.task_id`, device.TeamID)
	if err != nil {
		return nil, err
	}
	ids := []int64{}
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	out := []collab.BranchReply{}
	for _, task := range ids {
		tx, e := d.BeginTx(ctx, nil)
		if e != nil {
			return nil, e
		}
		e = LockTaskEvidenceTx(tx, task)
		var p *collab.BranchProject
		if e == nil {
			p, e = branchLoadTx(ctx, tx, device.TeamID, task, false)
		}
		a := collab.BranchActor{MemberID: device.OwnerMemberID, DeviceID: device.ID}
		if e == nil {
			a, e = branchActorTx(ctx, tx, device.TeamID, task, a)
		}
		if e == nil {
			for i := range p.Branches {
				b := p.Branches[i]
				if b.DeviceID != device.ID || b.OwnerID != device.OwnerMemberID || slices.Contains([]string{"accepted", "cancelled", "failed", "review_pending"}, b.State) {
					continue
				}
				if collab.CheckBranchAccess(p, a, b.ID, "execute") != nil {
					continue
				}
				r := collab.BranchReply{Branch: &b, Policy: p.Policy, Cursor: p.Cursor}
				restrictBranchReply(&r)
				branchReplyDependencies(p, a, &r)
				out = append(out, r)
			}
		}
		tx.Rollback()
		if e != nil && !errors.Is(e, ErrTeamCollaborationDenied) {
			return nil, e
		}
	}
	return out, nil
}

// All process surfaces (snapshot, replay, stream, search and export) use this
// single permission-aware projection. Raw state and events are never handlers.
func (d *DB) BranchSnapshot(ctx context.Context, team, task int64, a collab.BranchActor, branch, after int64, limit int, search string) (*collab.BranchSnapshot, error) {
	if limit < 1 || limit > 200 {
		limit = 100
	}
	if after < 0 {
		return nil, fmt.Errorf("invalid cursor")
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = LockTaskEvidenceTx(tx, task); err != nil {
		return nil, err
	}
	p, err := branchLoadTx(ctx, tx, team, task, false)
	if err != nil {
		return nil, err
	}
	a, err = branchActorTx(ctx, tx, team, task, a)
	if err != nil {
		return nil, err
	}
	if err = collab.CheckBranchAccess(p, a, branch, "read"); err != nil {
		return nil, err
	}
	permissions := []string{}
	for _, perm := range collab.BranchPermissions {
		if collab.CheckBranchAccess(p, a, branch, perm) == nil {
			permissions = append(permissions, perm)
		}
	}
	canProcess := slices.Contains(permissions, "process")
	if (after > 0 || search != "") && !canProcess {
		return nil, ErrTeamCollaborationDenied
	}
	events := []collab.BranchEvent{}
	cursor := after
	if canProcess {
		rows, e := tx.QueryContext(ctx, `SELECT seq,event FROM team_branch_events WHERE task_id=$1 AND seq>$2 ORDER BY seq LIMIT $3`, task, after, limit)
		if e != nil {
			return nil, e
		}
		for rows.Next() {
			var id int64
			var raw []byte
			if err = rows.Scan(&id, &raw); err != nil {
				rows.Close()
				return nil, err
			}
			cursor = id
			var ev collab.BranchEvent
			if json.Unmarshal(raw, &ev) != nil {
				rows.Close()
				return nil, fmt.Errorf("invalid stored event")
			}
			if branch > 0 && ev.BranchID != 0 && ev.BranchID != branch {
				continue
			}
			if collab.CheckBranchAccess(p, a, ev.BranchID, "process") != nil {
				continue
			}
			if collab.CheckBranchAccess(p, a, ev.BranchID, "evidence") != nil {
				ev.Evidence = nil
			}
			if search != "" && !strings.Contains(strings.ToLower(ev.Text), strings.ToLower(search)) {
				continue
			}
			events = append(events, ev)
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	more := canProcess && cursor < p.Cursor
	projected := *p
	projected.Receipts = nil
	projected.Permissions = nil
	if slices.Contains(permissions, "manage") {
		projected.Permissions = p.Permissions
	}
	projected.Policy.PlannerPrompts = nil
	projected.Policy.Roles = nil
	if !slices.Contains(permissions, "evidence") {
		projected.Policy.Materials = nil
	}
	projected.Branches = []collab.ExecutionBranch{}
	for _, b := range p.Branches {
		if branch > 0 && b.ID != branch {
			continue
		}
		if collab.CheckBranchAccess(p, a, b.ID, "read") != nil {
			continue
		}
		b.Operations = nil
		if collab.CheckBranchAccess(p, a, b.ID, "process") != nil {
			b.Units = nil
			b.Guidance = nil
			b.Checkpoint = ""
			b.Reason = ""
		}
		if collab.CheckBranchAccess(p, a, b.ID, "evidence") != nil {
			for i := range b.Units {
				if b.Units[i].Result != nil {
					r := *b.Units[i].Result
					r.Evidence = nil
					b.Units[i].Result = &r
				}
			}
			b.Spec.MaterialHashes = nil
		}
		projected.Branches = append(projected.Branches, b)
	}
	projected.Pool = []collab.BranchPoolWork{}
	for _, w := range p.Pool {
		if w.Spec.Restricted && !a.Admin && !slices.Contains(w.Spec.Members, a.MemberID) {
			continue
		}
		if !slices.Contains(permissions, "evidence") {
			w.Spec.MaterialHashes = nil
		}
		projected.Pool = append(projected.Pool, w)
	}
	return &collab.BranchSnapshot{Project: projected, Permissions: permissions, Events: events, Cursor: cursor, HasMore: more}, nil
}
