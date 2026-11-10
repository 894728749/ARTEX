package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/artex/collab"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// localBranchConfig is opt-in and entirely device-local. ScopeFields maps each
// command/MCP alias to JSON fields whose scalar values must match an authorized
// asset target. EnvSecretNames are never emitted and their values are redacted.
type localBranchConfig struct {
	Enabled        bool                `json:"enabled"`
	ScopeFields    map[string][]string `json:"scope_fields,omitempty"`
	MaterialMode   string              `json:"material_mode,omitempty"`
	RedactStrings  []string            `json:"redact_strings,omitempty"`
	EnvSecretNames []string            `json:"env_secret_names,omitempty"`
}

type branchList struct {
	Branches []collab.BranchReply `json:"branches"`
}

var branchProviderFactory = deviceProviderFactory

var branchJournalPaths sync.Map

func branchJournalKey(b *collab.ExecutionBranch) string { return fmt.Sprintf("%d/%d", b.TaskID, b.ID) }
func registerBranchJournal(b *collab.ExecutionBranch, path string) {
	if b != nil && path != "" {
		branchJournalPaths.Store(branchJournalKey(b), path)
	}
}
func branchJournalFor(b *collab.ExecutionBranch) string {
	if b == nil {
		return ""
	}
	v, _ := branchJournalPaths.Load(branchJournalKey(b))
	p, _ := v.(string)
	return p
}

func branchPath(taskID, branchID int64) string {
	return fmt.Sprintf("/api/collaboration/device/branches/%d/%d/command", taskID, branchID)
}

func (c localExecutionConfig) validateBranches() error {
	if !c.Branches.Enabled {
		return nil
	}
	if c.Branches.MaterialMode != "" && c.Branches.MaterialMode != "assigned" {
		return errors.New("branch material_mode must be assigned")
	}
	if len(c.Branches.RedactStrings) > 128 || len(c.Branches.EnvSecretNames) > 128 {
		return errors.New("branch redaction policy exceeds limits")
	}
	for alias, fields := range c.Branches.ScopeFields {
		if !nodeSafeName.MatchString(alias) || len(fields) == 0 || len(fields) > 16 {
			return fmt.Errorf("invalid branch scope mapping %q", alias)
		}
		for _, f := range fields {
			if strings.TrimSpace(f) == "" || len(f) > 128 {
				return fmt.Errorf("invalid scope field for %q", alias)
			}
		}
	}
	for _, name := range c.Branches.EnvSecretNames {
		if !nodeSafeName.MatchString(name) {
			return errors.New("invalid branch secret environment name")
		}
	}
	for role, r := range c.Roles {
		if role == "planner" || role == "reverse_planner" {
			if len(r.Capabilities) != 0 {
				return fmt.Errorf("branch role %s cannot have tool capabilities", role)
			}
		}
		if role == "reviewer" {
			for _, cap := range r.Capabilities {
				if x, ok := c.Commands[cap]; ok && !x.ReadOnly {
					return fmt.Errorf("reviewer capability %q must be read-only", cap)
				}
				if x, ok := c.MCPTools[cap]; ok && !x.ReadOnly {
					return fmt.Errorf("reviewer MCP capability %q must be read-only", cap)
				}
				if _, ok := c.Commands[cap]; !ok {
					if _, ok = c.MCPTools[cap]; !ok {
						return fmt.Errorf("reviewer capability %q is not configured", cap)
					}
				}
				if len(c.Branches.ScopeFields[cap]) == 0 {
					return fmt.Errorf("reviewer capability %q needs target scope fields", cap)
				}
			}
		}
	}
	return nil
}

// pollBranches advertises protocol 1 only after explicit local opt-in. The
// legacy assignment polling and message protocol remain independent.
func pollBranches(ctx context.Context, cfg localExecutionConfig, origin, token string, client *http.Client, once bool) error {
	if !cfg.Branches.Enabled {
		return nil
	}
	var list branchList
	if err := request(ctx, client, origin, "/api/collaboration/device/branches", token, nil, &list); err != nil {
		return err
	}
	for _, reply := range list.Branches {
		if reply.Branch != nil {
			if err := processBranch(ctx, cfg, origin, token, client, reply); err != nil {
				if !isTransientNodeError(err) {
					return err
				}
			}
		}
	}
	return nil
}

func processBranch(ctx context.Context, cfg localExecutionConfig, origin, token string, client *http.Client, reply collab.BranchReply) error {
	cfg = branchRedactedConfig(cfg, token)
	b := reply.Branch
	if b == nil || b.ID < 1 || b.TaskID < 1 || b.Epoch < 1 {
		return errors.New("invalid branch reply")
	}
	if b.State != "waiting_ready" && b.State != "ready" && b.State != "running" && b.State != "waiting_dependency" && b.State != "pausing" && b.State != "transfer_wait" {
		return nil
	}
	base := cfg.WorkDir
	if base == "" {
		base = "node-executions"
	}
	work := filepath.Join(base, "branches", fmt.Sprintf("%d-%d", b.TaskID, b.ID))
	if err := os.MkdirAll(work, 0700); err != nil {
		return err
	}
	journal := filepath.Join(work, "journal.ndjson")
	registerBranchJournal(b, journal)
	if err := repairBranchJournal(journal); err != nil {
		return err
	}
	if blocked, err := replayBranchOutbox(ctx, client, origin, token, b, journal); err != nil {
		return err
	} else if blocked {
		return nil
	}
	if err := appendBranchJournal(journal, map[string]any{"kind": "observed", "branch": b.ID, "epoch": b.Epoch, "state": b.State}); err != nil {
		return err
	}
	if unresolved, err := branchHasUnresolved(journal); err != nil {
		return err
	} else if unresolved && branchUnresolvedEpochChanged(journal, b.Epoch) {
		if branchOldOperationsConfirmed(journal, b) {
			if err = branchReconcileConfirmedJournal(journal, b.Epoch); err != nil {
				return err
			}
		} else {
			_ = appendBranchJournal(journal, map[string]any{"kind": "handoff_pending", "epoch": b.Epoch})
			return nil
		}
	}
	if b.State == "waiting_dependency" {
		if err := branchCommand(ctx, client, origin, token, b, collab.BranchCommand{Type: "heartbeat"}); err != nil {
			return err
		}
		if b.State == "waiting_dependency" {
			return nil
		}
	}
	if b.State == "pausing" || b.State == "transfer_wait" {
		return runBranchRound(ctx, cfg, origin, token, client, reply, work, journal)
	}
	if b.State == "waiting_ready" {
		if reason := branchNotReady(cfg, reply.Policy, b); reason != "" {
			return branchCommand(ctx, client, origin, token, b, collab.BranchCommand{Type: "not_ready", Text: reason})
		}
		if err := branchCommand(ctx, client, origin, token, b, collab.BranchCommand{Type: "ready"}); err != nil {
			return err
		}
		return nil
	}
	// Durable runner execution is deliberately fail-closed after any model/tool
	// operation marker. The server owns branch progression; this device only
	// executes bounded, acknowledged command transitions.
	return runBranchRound(ctx, cfg, origin, token, client, reply, work, journal)
}

func branchNotReady(cfg localExecutionConfig, p collab.BranchPolicy, b *collab.ExecutionBranch) string {
	spec := b.Spec
	if p.Version < 1 || len(p.Roles) == 0 {
		return "branch policy has no executable role configuration"
	}
	materialByHash := map[string]collab.Material{}
	var materialTotal int64
	for _, m := range p.Materials {
		raw, e := hex.DecodeString(m.SHA256)
		if e != nil || len(raw) != 32 || m.ID != m.SHA256 || m.Size < 0 || m.Size > 256<<20 {
			return "branch material manifest is invalid"
		}
		materialByHash[m.SHA256] = m
		materialTotal += m.Size
	}
	if materialTotal > 512<<20 {
		return "branch material budget exceeds local limit"
	}
	for _, h := range spec.MaterialHashes {
		if _, ok := materialByHash[h]; !ok {
			return "a required branch material is missing from policy"
		}
	}
	needed := map[string]bool{}
	for _, role := range spec.Roles {
		needed[role] = true
	}
	if spec.Kind == "reverse" {
		needed["reverse_reviewer"] = true
	} else {
		needed["reviewer"] = true
	}
	if spec.Kind == "reverse" {
		needed["reverse_planner"] = true
	} else {
		needed["planner"] = true
	}
	for role := range needed {
		portable, ok := p.Roles[role]
		if role == "planner" || role == "reverse_planner" {
			portable = collab.ExecutionConfig{Version: 1, Kind: spec.Kind, Role: role, SystemPrompt: p.PlannerPrompts[spec.Kind], MaxTurns: 1, BudgetSeconds: p.MaxToolSeconds}
			ok = strings.TrimSpace(portable.SystemPrompt) != ""
		}
		if !ok {
			return "missing coordinator role policy: " + role
		}
		local, ok := cfg.Roles[role]
		if !ok {
			return "this device has no local role configured for " + role
		}
		model, ok := cfg.Models[local.Model]
		if !ok {
			return "local model configuration is missing for " + role
		}
		if os.Getenv(model.APIKeyEnv) == "" {
			return "local model credential is unavailable for " + role
		}
		if portable.Role != role {
			return "coordinator role policy does not match " + role
		}
		if portable.Version != 1 || portable.BudgetSeconds < 1 || portable.BudgetSeconds > 7200 || portable.MaxTurns < 1 || portable.MaxTurns > 64 {
			return "coordinator role policy is invalid for " + role
		}
		if role == "planner" || role == "reverse_planner" {
			if len(portable.Capabilities) > 0 || len(local.Capabilities) > 0 {
				return "planner role must not have tool capabilities"
			}
			continue
		}
		localCaps := map[string]bool{"read_material": true}
		for _, c := range local.Capabilities {
			localCaps[c] = true
		}
		for _, c := range portable.Capabilities {
			if c == reverseRuntimeCapability && role == "reverse_dynamic" {
				continue
			}
			if !localCaps[c] {
				return "local device lacks configured tool capability for " + role
			}
			if _, ok := cfg.Commands[c]; !ok {
				if _, ok = cfg.MCPTools[c]; !ok && c != reverseRuntimeCapability && c != "read_material" {
					return "local tool configuration is unavailable for " + c
				}
			}
			if role != "worker" {
				if x, ok := cfg.Commands[c]; ok && !x.ReadOnly {
					return "review role requires read-only local commands"
				}
				if x, ok := cfg.MCPTools[c]; ok && !x.ReadOnly {
					return "review role requires read-only MCP tools"
				}
			}
			if c != reverseRuntimeCapability && c != "read_material" && len(cfg.Branches.ScopeFields[c]) == 0 {
				return "local target scope mapping is missing for " + c
			}
		}
	}
	for _, u := range spec.Roles {
		if u == "reverse_dynamic" && (len(spec.MaterialHashes) == 0) {
			return "dynamic role requires hash-bound runtime materials"
		}
	}
	for _, unit := range b.Units {
		for _, h := range unit.Spec.MaterialHashes {
			if _, ok := materialByHash[h]; !ok {
				return "a unit references material outside branch policy"
			}
		}
		if unit.Spec.Runtime != nil {
			if unit.Spec.Role != "reverse_dynamic" {
				return "runtime binding is only permitted on reverse_dynamic units"
			}
			ec, ok := p.Roles[unit.Spec.Role]
			if !ok {
				return "dynamic role policy is missing"
			}
			ec.Runtime = unit.Spec.Runtime
			ec.DynamicAllowed = true
			seen := []collab.Material{}
			for _, h := range unit.Spec.MaterialHashes {
				for _, m := range p.Materials {
					if m.SHA256 == h {
						seen = append(seen, m)
					}
				}
			}
			if _, err := cfg.matchRuntimeBinding(ec, seen); err != nil {
				return "local dynamic runtime binding does not match this unit"
			}
		}
		if unit.State != "superseded" && unit.State != "complete" && unit.State != "completed" && unit.State != "failed" && unit.State != "cancelled" && unit.Spec.Role == "reverse_dynamic" && unit.Spec.Runtime == nil {
			return "reverse_dynamic unit is missing its explicit runtime binding"
		}
	}
	return ""
}

func runBranchRound(ctx context.Context, cfg localExecutionConfig, origin, token string, client *http.Client, reply collab.BranchReply, work, journal string) error {
	b := reply.Branch
	// Every irreversible invocation gets a write-ahead marker. An unresolved
	// marker is intentionally never replayed after restart/epoch transfer.
	if unresolved, err := branchHasUnresolved(journal); err != nil {
		return err
	} else if unresolved {
		if branchUnresolvedEpochChanged(journal, b.Epoch) {
			_ = appendBranchJournal(journal, map[string]any{"kind": "handoff_pending", "epoch": b.Epoch})
			return nil
		}
		if err = uploadBranchRecoveryEvidence(ctx, cfg, origin, token, client, b, work); err != nil {
			return err
		}
		return branchCommand(ctx, client, origin, token, b, collab.BranchCommand{Type: "checkpoint", Text: "An operation has an unknown outcome after restart or ownership transfer. It was not replayed. Complete journaled evidence is preserved; request independent review or explicit recovery."})
	}
	if b.State == "pausing" || b.State == "transfer_wait" {
		return branchCommand(ctx, client, origin, token, b, collab.BranchCommand{Type: "checkpoint", Text: "Stopped at the branch boundary; no further model or tool operation was started."})
	}
	if b.State != "ready" && b.State != "running" {
		return nil
	}
	files, err := fetchBranchMaterials(ctx, client, origin, token, b, reply.Policy, work)
	if err != nil {
		return branchCommand(ctx, client, origin, token, b, collab.BranchCommand{Type: "checkpoint", State: "blocked", Text: "Assigned materials could not be verified; no model or tool operation started."})
	}
	for _, unit := range b.Units {
		if unit.State != "planned" && unit.State != "running" {
			continue
		}
		if !branchUnitDependenciesReady(b, unit) {
			continue
		}
		if unit.Spec.Role == "reverse_dynamic" && unit.Spec.Runtime == nil {
			return branchCommand(ctx, client, origin, token, b, collab.BranchCommand{Type: "checkpoint", Text: "Dynamic work awaits a device/profile/material-bound single-use authorization."})
		}
		if err = runBranchUnit(ctx, cfg, origin, token, client, reply, unit, files, work, journal); err != nil {
			if branchOperationDenied(err) {
				return branchCommand(ctx, client, origin, token, b, collab.BranchCommand{Type: "checkpoint", Text: "Server authorization denied the next operation; execution stopped before model/tool invocation."})
			}
			return err
		}
		if b.State != "running" {
			return branchCommand(ctx, client, origin, token, b, collab.BranchCommand{Type: "checkpoint", Text: "Stopped at the completed unit boundary."})
		}
	}
	return runBranchPlanner(ctx, cfg, origin, token, client, reply, files, work, journal)
}

func branchUnitDependenciesReady(b *collab.ExecutionBranch, u collab.BranchUnit) bool {
	byID := map[int64]collab.BranchUnit{}
	for _, x := range b.Units {
		byID[x.ID] = x
	}
	for _, id := range u.Spec.DependsOn {
		dep, ok := byID[id]
		if !ok || dep.State != "candidate" || dep.Result == nil || dep.Result.Outcome != "candidate" {
			return false
		}
	}
	return true
}

func uploadBranchRecoveryEvidence(ctx context.Context, cfg localExecutionConfig, origin, token string, client *http.Client, b *collab.ExecutionBranch, work string) error {
	paths, err := filepath.Glob(filepath.Join(work, "unit-*-evidence.ndjson"))
	if err != nil {
		return err
	}
	for _, path := range paths {
		var unitID int64
		_, _ = fmt.Sscanf(filepath.Base(path), "unit-%d-evidence.ndjson", &unitID)
		rows, e := loadNodeEvidence(path)
		if e != nil {
			return e
		}
		for i := range rows {
			rows[i].Content = redactBranchText(cfg, rows[i].Content)
			rows[i].SHA256 = collab.ContentHash([]byte(rows[i].Content))
			rows[i].Input = nil
			ev := rows[i]
			if e = branchCommand(ctx, client, origin, token, b, collab.BranchCommand{Type: "event", Event: &collab.BranchEvent{Kind: "evidence", UnitID: unitID, Text: "Preserved local evidence receipt.", Evidence: &ev}}); e != nil {
				return e
			}
		}
	}
	return nil
}

func fetchBranchMaterials(ctx context.Context, client *http.Client, origin, token string, b *collab.ExecutionBranch, p collab.BranchPolicy, work string) (map[string]string, error) {
	allowed := map[string]bool{}
	for _, m := range p.Materials {
		allowed[m.SHA256] = true
	}
	for _, u := range b.Units {
		for _, h := range u.Spec.MaterialHashes {
			if !allowed[h] {
				return nil, errors.New("unit material is outside branch policy")
			}
		}
	}
	dir := filepath.Join(work, "materials")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	files := map[string]string{}
	for _, m := range p.Materials {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if m.Size < 0 || m.Size > 256<<20 {
			return nil, errors.New("branch material size exceeds limit")
		}
		dst := filepath.Join(dir, m.SHA256)
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return nil, err
		}
		for offset := int64(0); offset < m.Size; {
			end := offset + (4 << 20) - 1
			if end >= m.Size {
				end = m.Size - 1
			}
			path := fmt.Sprintf("/api/collaboration/device/branches/%d/%d/materials/%s?epoch=%d", b.TaskID, b.ID, m.SHA256, b.Epoch)
			r, e := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(origin, "/")+path, nil)
			if e != nil {
				f.Close()
				return nil, e
			}
			r.Header.Set("Authorization", "Bearer "+token)
			r.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, end))
			resp, e := client.Do(r)
			if e != nil {
				f.Close()
				return nil, e
			}
			want := fmt.Sprintf("bytes %d-%d/%d", offset, end, m.Size)
			if resp.StatusCode != http.StatusPartialContent || resp.Header.Get("Content-Range") != want {
				resp.Body.Close()
				f.Close()
				return nil, errors.New("invalid branch material range")
			}
			limit := end - offset + 1
			chunk, e := io.ReadAll(io.LimitReader(resp.Body, limit+1))
			resp.Body.Close()
			if e != nil || int64(len(chunk)) != limit {
				f.Close()
				return nil, errors.New("invalid branch material chunk")
			}
			if _, e = f.WriteAt(chunk, offset); e != nil {
				f.Close()
				return nil, e
			}
			if e = f.Sync(); e != nil {
				f.Close()
				return nil, e
			}
			offset += int64(len(chunk))
		}
		data, e := io.ReadAll(io.LimitReader(f, m.Size+1))
		if e != nil {
			f.Close()
			return nil, e
		}
		if e = f.Close(); e != nil {
			return nil, e
		}
		if int64(len(data)) != m.Size || collab.ContentHash(data) != m.SHA256 {
			return nil, errors.New("branch material hash or size mismatch")
		}
		files[m.SHA256] = dst
	}
	for _, u := range b.Units {
		for _, h := range u.Spec.MaterialHashes {
			if _, ok := files[h]; !ok {
				return nil, errors.New("unit material is unavailable")
			}
		}
	}
	return files, nil
}

func runBranchPlanner(ctx context.Context, cfg localExecutionConfig, origin, token string, client *http.Client, reply collab.BranchReply, files map[string]string, work, journal string) error {
	b := reply.Branch
	registerBranchJournal(b, journal)
	snapshot := branchPlannerSnapshotKey(b, reply.Policy, reply.Dependencies)
	if done, err := branchPlannerSnapshotDone(journal, snapshot); err != nil {
		return err
	} else if done {
		return nil
	}
	role := "planner"
	if b.Spec.Kind == "reverse" {
		role = "reverse_planner"
	}
	rc := collab.ExecutionConfig{Version: 1, Kind: b.Spec.Kind, Role: role, SystemPrompt: reply.Policy.PlannerPrompts[b.Spec.Kind], MaxTurns: 1, BudgetSeconds: reply.Policy.MaxToolSeconds}
	if strings.TrimSpace(rc.SystemPrompt) == "" || rc.BudgetSeconds < 1 {
		return errors.New("branch planner policy is unavailable")
	}
	local := cfg.Roles[role]
	model := cfg.Models[local.Model]
	provider, err := branchProviderFactory(model, os.Getenv(model.APIKeyEnv))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(rc.BudgetSeconds)*time.Second)
	defer cancel()
	var waiting, submitted atomic.Bool
	tools := branchPlannerTools(ctx, cfg, origin, token, client, b, reply.Policy, reply.Dependencies, journal, cancel, &waiting, &submitted)
	provider = &branchMeteredProvider{inner: provider, ctx: ctx, cfg: cfg, origin: origin, token: token, client: client, branch: b, unitID: 0, role: role, journal: journal, plannerSnapshot: snapshot}
	opt := agentcore.Options{Provider: provider, SystemPrompt: []string{rc.SystemPrompt, "You are the persistent planner for this branch only. Review current units, results, accepted dependencies, coordination work pool, and remaining budget before proposing new work. Never replay an unknown or failed unit: propose a new unit with supersedes set to the old unit ID and explain an independent verification route. Use propose_work for one bounded unit, branch_wait when blocked, and submit_branch only with candidate or negative after reviewer coverage."}, Tools: tools, PermissionMode: permission.ModeBypass, WorkingDir: work, MaxTurns: rc.MaxTurns, MaxDuration: time.Duration(rc.BudgetSeconds) * time.Second, EnableWebFetch: false, EnableWebSearch: false}
	s := agentcore.NewSession(opt)
	defer s.Close()
	input, _ := json.Marshal(map[string]any{"goal": reply.Policy.Goal, "branch": b, "dependencies": reply.Dependencies, "coordination": reply.Coordination, "policy": reply.Policy, "verified_material_hashes": sortedMapKeys(files)})
	initialUnits, initialState := len(b.Units), b.State
	for _, g := range b.Guidance {
		if g.Status == "queued" || g.Status == "pending" {
			if err := branchCommand(ctx, client, origin, token, b, collab.BranchCommand{Type: "guidance_received", GuidanceIDs: []int64{g.ID}}); err != nil {
				return err
			}
		}
	}
	var out strings.Builder
	for ev, e := range s.Prompt(ctx, string(input)) {
		if e != nil {
			if waiting.Load() || submitted.Load() {
				return appendBranchJournal(journal, map[string]any{"kind": "planner_done", "snapshot": snapshot})
			}
			return e
		}
		if ev.Kind == "text" {
			out.WriteString(ev.Text)
		}
	}
	text := strings.TrimSpace(out.String())
	if text != "" {
		if err := branchCommand(ctx, client, origin, token, b, collab.BranchCommand{Type: "event", Event: &collab.BranchEvent{Kind: "plan", Text: redactBranchText(cfg, text)}}); err != nil {
			return err
		}
	}
	if len(b.Units) == initialUnits && b.State == initialState && !waiting.Load() && !submitted.Load() {
		if err := branchCommand(ctx, client, origin, token, b, collab.BranchCommand{Type: "checkpoint", State: "paused", Text: "Planner produced no new work, wait, or submission. Await member guidance or a branch policy/control change before planning again."}); err != nil {
			return err
		}
		return appendBranchJournal(journal, map[string]any{"kind": "planner_paused", "snapshot": snapshot})
	}
	for _, g := range b.Guidance {
		if g.Status == "queued" || g.Status == "pending" || g.Status == "received" {
			if err := branchCommand(ctx, client, origin, token, b, collab.BranchCommand{Type: "guidance_applied", GuidanceIDs: []int64{g.ID}}); err != nil {
				return err
			}
		}
	}
	return appendBranchJournal(journal, map[string]any{"kind": "planner_done", "snapshot": snapshot})
}

func branchPlannerSnapshotKey(b *collab.ExecutionBranch, p collab.BranchPolicy, deps []collab.ExecutionBranch) string {
	units := append([]collab.BranchUnit(nil), b.Units...)
	sort.Slice(units, func(i, j int) bool { return units[i].ID < units[j].ID })
	v := struct {
		Epoch         int64                    `json:"epoch"`
		Revision      int64                    `json:"revision"`
		State         string                   `json:"state"`
		PolicyVersion int64                    `json:"policy_version"`
		Spec          collab.BranchWorkSpec    `json:"spec"`
		Units         []collab.BranchUnit      `json:"units"`
		Guidance      []collab.BranchGuidance  `json:"guidance"`
		Dependencies  []collab.ExecutionBranch `json:"dependencies"`
	}{b.Epoch, b.Revision, b.State, p.Version, b.Spec, units, b.Guidance, deps}
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func branchPlannerSnapshotDone(path, key string) (bool, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	done := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		var r struct{ Kind, Snapshot string }
		if json.Unmarshal([]byte(line), &r) == nil && r.Snapshot != "" {
			if r.Kind == "planner_start" {
				done[r.Snapshot] = false
			}
			if r.Kind == "planner_done" {
				done[r.Snapshot] = true
			}
		}
	}
	return done[key], nil
}

func branchPlannerTools(ctx context.Context, cfg localExecutionConfig, origin, token string, client *http.Client, b *collab.ExecutionBranch, p collab.BranchPolicy, dependencies []collab.ExecutionBranch, journal string, cancel context.CancelFunc, waiting, submitted *atomic.Bool) []actool.CoreTool {
	make := func(name, description string, schema map[string]any, fn func(json.RawMessage) (string, error)) actool.CoreTool {
		return actool.Build(actool.Spec{Name: name, Description: description, Schema: schema, ReadOnly: func(json.RawMessage) bool { return false }, Concurrent: func(json.RawMessage) bool { return false }, Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		}, Run: func(_ context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			out, err := fn(input)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(out), nil
		}})
	}
	tools := []actool.CoreTool{
		make("propose_work", "Propose one bounded branch unit that respects branch assets, materials, roles, and remaining budget.", map[string]any{"type": "object", "properties": map[string]any{"unit": map[string]any{"type": "object"}}, "required": []string{"unit"}}, func(raw json.RawMessage) (string, error) {
			var w collab.BranchUnitSpec
			var x map[string]json.RawMessage
			if json.Unmarshal(raw, &x) != nil || json.Unmarshal(x["unit"], &w) != nil {
				return "", errors.New("invalid unit")
			}
			if err := validateBranchUnit(b, p, dependencies, w); err != nil {
				return "", err
			}
			rec, err := postBranch(ctx, client, origin, token, b, collab.BranchCommand{Type: "plan", Unit: &w})
			return fmt.Sprintf("unit_id=%d receipt=%s", rec.UnitID, rec.Hash), err
		}),
		make("branch_wait", "Checkpoint this branch while waiting for a dependency or guidance.", map[string]any{"type": "object", "properties": map[string]any{"reason": map[string]any{"type": "string"}}, "required": []string{"reason"}}, func(raw json.RawMessage) (string, error) {
			var q struct {
				Reason string `json:"reason"`
			}
			if json.Unmarshal(raw, &q) != nil {
				return "", errors.New("invalid wait")
			}
			err := branchCommand(ctx, client, origin, token, b, collab.BranchCommand{Type: "checkpoint", State: "waiting_dependency", Text: redactBranchText(cfg, q.Reason)})
			if err == nil {
				waiting.Store(true)
				cancel()
			}
			return "checkpoint saved", err
		}),
		make("request_assistance", "Request another bounded work item from the team pool, then wait for its dependency.", map[string]any{"type": "object", "properties": map[string]any{"work": map[string]any{"type": "object"}}, "required": []string{"work"}}, func(raw json.RawMessage) (string, error) {
			var w collab.BranchWorkSpec
			var x map[string]json.RawMessage
			if json.Unmarshal(raw, &x) != nil || json.Unmarshal(x["work"], &w) != nil {
				return "", errors.New("invalid assistance request")
			}
			if err := branchCommand(ctx, client, origin, token, b, collab.BranchCommand{Type: "assist", Work: &w}); err != nil {
				return "", err
			}
			if err := branchCommand(ctx, client, origin, token, b, collab.BranchCommand{Type: "checkpoint", State: "waiting_dependency", Text: "Assistance requested; pausing this branch until the new dependency is accepted and reviewed."}); err != nil {
				return "", err
			}
			waiting.Store(true)
			cancel()
			return "assistance requested; waiting for dependency", nil
		}),
		make("submit_branch", "Submit candidate or negative result for independent member review after reviewer work is complete.", map[string]any{"type": "object", "properties": map[string]any{"outcome": map[string]any{"enum": []string{"candidate", "negative"}}, "text": map[string]any{"type": "string"}}, "required": []string{"outcome", "text"}}, func(raw json.RawMessage) (string, error) {
			var q struct{ Outcome, Text string }
			if json.Unmarshal(raw, &q) != nil || (q.Outcome != "candidate" && q.Outcome != "negative") {
				return "", errors.New("invalid branch outcome")
			}
			if !branchHasReviewerResult(b) {
				return "", errors.New("independent reviewer result is still required")
			}
			err := branchCommand(ctx, client, origin, token, b, collab.BranchCommand{Type: "submit", Outcome: q.Outcome, Text: redactBranchText(cfg, q.Text)})
			if err == nil {
				submitted.Store(true)
				cancel()
			}
			return "submitted for independent review", err
		}),
	}
	if b.Spec.Coordinator {
		tools = append(tools,
			make("propose_branch", "Propose one bounded child branch for a coordination work item.", map[string]any{"type": "object", "properties": map[string]any{"work": map[string]any{"type": "object"}}, "required": []string{"work"}}, func(raw json.RawMessage) (string, error) {
				var x struct {
					Work collab.BranchWorkSpec `json:"work"`
				}
				if json.Unmarshal(raw, &x) != nil {
					return "", errors.New("invalid branch proposal")
				}
				rec, err := postBranch(ctx, client, origin, token, b, collab.BranchCommand{Type: "propose", Work: &x.Work})
				return fmt.Sprintf("branch proposal receipt=%s", rec.Hash), err
			}),
			make("publish_branch", "Publish the prepared coordination branch to the authorized work pool.", map[string]any{"type": "object", "properties": map[string]any{"work": map[string]any{"type": "object"}}, "required": []string{"work"}}, func(raw json.RawMessage) (string, error) {
				var x struct {
					Work collab.BranchWorkSpec `json:"work"`
				}
				if json.Unmarshal(raw, &x) != nil {
					return "", errors.New("invalid branch publication")
				}
				rec, err := postBranch(ctx, client, origin, token, b, collab.BranchCommand{Type: "publish", Work: &x.Work})
				return fmt.Sprintf("branch publication receipt=%s", rec.Hash), err
			}),
		)
	}
	return tools
}

func validateBranchUnit(b *collab.ExecutionBranch, p collab.BranchPolicy, dependencies []collab.ExecutionBranch, u collab.BranchUnitSpec) error {
	if strings.TrimSpace(u.Key) == "" || strings.TrimSpace(u.Question) == "" || u.Role == "" || len(u.Contract) == 0 {
		return errors.New("unit requires key, question, role, and WorkContract")
	}
	if u.Supersedes < 0 {
		return errors.New("invalid supersedes unit ID")
	}
	var c struct {
		BudgetSeconds int `json:"budget_seconds"`
	}
	if json.Unmarshal(u.Contract, &c) != nil || c.BudgetSeconds < 1 || c.BudgetSeconds > p.MaxToolSeconds {
		return errors.New("unit wall budget exceeds branch policy")
	}
	roles := map[string]bool{}
	for _, r := range b.Spec.Roles {
		roles[r] = true
	}
	if !roles[u.Role] || p.Roles[u.Role].Role != u.Role {
		return errors.New("unit role is not authorized by this branch")
	}
	assets := map[string]bool{}
	for _, a := range p.Assets {
		assets[a.ID] = true
	}
	for _, id := range u.AssetIDs {
		if !assets[id] {
			return errors.New("unit asset is outside branch policy")
		}
	}
	branchAssets := map[string]bool{}
	for _, id := range b.Spec.AssetIDs {
		branchAssets[id] = true
	}
	for _, id := range u.AssetIDs {
		if !branchAssets[id] {
			return errors.New("unit asset is outside the claimed work scope")
		}
	}
	mats := map[string]bool{}
	for _, m := range p.Materials {
		mats[m.SHA256] = true
	}
	for _, h := range u.MaterialHashes {
		if !mats[h] {
			return errors.New("unit material is outside branch policy")
		}
	}
	branchMats := map[string]bool{}
	for _, h := range b.Spec.MaterialHashes {
		branchMats[h] = true
	}
	for _, h := range u.MaterialHashes {
		if !branchMats[h] {
			return errors.New("unit material is outside the claimed work scope")
		}
	}
	roleCaps := map[string]bool{}
	for _, c := range p.Roles[u.Role].Capabilities {
		roleCaps[c] = true
	}
	for _, c := range u.Capabilities {
		if !roleCaps[c] && c != "read_material" && !(u.Role == "reverse_dynamic" && c == reverseRuntimeCapability) {
			return fmt.Errorf("unit capability %q is not authorized by its role", c)
		}
	}
	depEvidence := map[string]bool{}
	for _, d := range dependencies {
		for _, du := range d.Units {
			depEvidence[fmt.Sprintf("%d/%d/%s", d.ID, du.ID, du.EvidenceVersion)] = du.Result != nil
		}
	}
	for _, ref := range u.EvidenceRefs {
		if ref.BranchID < 1 || ref.UnitID < 1 || ref.Version == "" || !depEvidence[fmt.Sprintf("%d/%d/%s", ref.BranchID, ref.UnitID, ref.Version)] {
			return errors.New("evidence reference is unavailable or changed")
		}
	}
	return nil
}

var branchCommandLocks sync.Map

func branchCommandLock(b *collab.ExecutionBranch) *sync.Mutex {
	key := branchJournalKey(b)
	v, _ := branchCommandLocks.LoadOrStore(key, &sync.Mutex{})
	return v.(*sync.Mutex)
}

func postBranch(ctx context.Context, client *http.Client, origin, token string, b *collab.ExecutionBranch, c collab.BranchCommand) (collab.BranchReceipt, error) {
	lock := branchCommandLock(b)
	lock.Lock()
	defer lock.Unlock()
	return postBranchLocked(ctx, client, origin, token, b, c)
}
func postBranchLocked(ctx context.Context, client *http.Client, origin, token string, b *collab.ExecutionBranch, c collab.BranchCommand) (collab.BranchReceipt, error) {
	c.BranchID = b.ID
	c.Epoch = b.Epoch
	c.Revision = b.Revision
	if c.RequestID == "" {
		c.RequestID = branchRequestID(b.ID, b.Epoch, c)
	}
	journal := branchJournalFor(b)
	if journal == "" {
		return collab.BranchReceipt{}, errors.New("branch journal is not registered")
	}
	if err := appendBranchJournal(journal, map[string]any{"kind": "command_pending", "request_id": c.RequestID, "epoch": c.Epoch, "command": c}); err != nil {
		return collab.BranchReceipt{}, err
	}
	var r collab.BranchReply
	if err := sendBranchCommand(ctx, client, origin, token, b, c, &r); err != nil {
		var status *nodeHTTPError
		if errors.As(err, &status) && status.Code >= 400 && status.Code < 500 {
			if e := appendBranchJournal(journal, map[string]any{"kind": "command_rejected", "request_id": c.RequestID, "epoch": c.Epoch, "status": status.Code}); e != nil {
				return r.Receipt, e
			}
		}
		return r.Receipt, err
	}
	if err := appendBranchJournal(journal, map[string]any{"kind": "command_ack", "request_id": c.RequestID, "epoch": c.Epoch}); err != nil {
		return r.Receipt, err
	}
	if r.Branch != nil {
		*b = *r.Branch
	}
	return r.Receipt, nil
}

func sendBranchCommand(ctx context.Context, client *http.Client, origin, token string, b *collab.ExecutionBranch, c collab.BranchCommand, out *collab.BranchReply) error {
	var err error
	for i := 0; i < 3; i++ {
		err = request(ctx, client, origin, branchPath(b.TaskID, b.ID), token, c, out)
		if err == nil {
			return nil
		}
		if !isTransientNodeError(err) {
			return err
		}
		if i < 2 {
			if e := waitNodeRetry(ctx, time.Duration(i+1)*time.Second); e != nil {
				return e
			}
		}
	}
	return err
}

func replayBranchOutbox(ctx context.Context, client *http.Client, origin, token string, b *collab.ExecutionBranch, journal string) (bool, error) {
	if err := repairBranchJournal(journal); err != nil {
		return false, err
	}
	raw, err := os.ReadFile(journal)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	pending := map[string]collab.BranchCommand{}
	order := []string{}
	acked := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		var r struct {
			Kind      string               `json:"kind"`
			RequestID string               `json:"request_id"`
			Command   collab.BranchCommand `json:"command"`
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if json.Unmarshal([]byte(line), &r) != nil {
			return false, errors.New("branch journal contains invalid JSON")
		}
		switch r.Kind {
		case "command_pending":
			if r.RequestID != "" {
				if _, ok := pending[r.RequestID]; !ok {
					order = append(order, r.RequestID)
				}
				pending[r.RequestID] = r.Command
			}
		case "command_ack", "command_orphaned", "command_rejected":
			acked[r.RequestID] = true
		}
	}
	for _, id := range order {
		c := pending[id]
		// An ack can be durable while the following unit_finished record is not.
		// Reconcile that crash window even for already-acknowledged commands.
		if c.Epoch == b.Epoch && c.Type == "unit_result" && branchCommandObserved(b, c) {
			if err := branchFinishAcceptedUnitResult(journal, c.UnitID, c.Epoch); err != nil {
				return false, err
			}
		}
		if acked[id] {
			continue
		}
		if c.Epoch != b.Epoch {
			// Old commands remain in the audit journal, never get rewritten to the
			// new authority. The operation fence below still requires confirmation.
			if err := appendBranchJournal(journal, map[string]any{"kind": "command_orphaned", "request_id": id, "epoch": c.Epoch}); err != nil {
				return false, err
			}
			continue
		}
		if branchCommandObserved(b, c) {
			if err := appendBranchJournal(journal, map[string]any{"kind": "command_ack", "request_id": id, "epoch": c.Epoch, "observed": true}); err != nil {
				return false, err
			}
			if c.Type == "unit_result" {
				if err := branchFinishAcceptedUnitResult(journal, c.UnitID, c.Epoch); err != nil {
					return false, err
				}
			}
			continue
		}
		if c.Type == "unit_result" {
			if u := unitByIDNode(b, c.UnitID); u != nil && u.Result != nil {
				return false, errors.New("server unit result differs from durable local result; refusing replay")
			}
		}
		var reply collab.BranchReply
		if err := sendBranchCommand(ctx, client, origin, token, b, c, &reply); err != nil {
			var status *nodeHTTPError
			if errors.As(err, &status) && status.Code >= 400 && status.Code < 500 && status.Code != http.StatusRequestTimeout && status.Code != http.StatusTooManyRequests {
				if e := appendBranchJournal(journal, map[string]any{"kind": "command_rejected", "request_id": id, "epoch": c.Epoch, "status": status.Code}); e != nil {
					return false, e
				}
				continue
			}
			return false, err
		}
		if err := appendBranchJournal(journal, map[string]any{"kind": "command_ack", "request_id": id, "epoch": c.Epoch}); err != nil {
			return false, err
		}
		if reply.Branch != nil {
			*b = *reply.Branch
		}
		if c.Type == "unit_result" && branchCommandObserved(b, c) {
			if err := branchFinishAcceptedUnitResult(journal, c.UnitID, c.Epoch); err != nil {
				return false, err
			}
		}
	}
	return false, nil
}

func branchFinishAcceptedUnitResult(path string, unit, epoch int64) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	started, finished := false, false
	for _, line := range strings.Split(string(raw), "\n") {
		var r struct {
			Kind string `json:"kind"`
			Unit int64  `json:"unit"`
		}
		if json.Unmarshal([]byte(line), &r) != nil {
			continue
		}
		if r.Unit == unit {
			if r.Kind == "unit_start" {
				started = true
			}
			if r.Kind == "unit_finished" {
				finished = true
			}
		}
	}
	if started && !finished {
		return appendBranchJournal(path, map[string]any{"kind": "unit_finished", "unit": unit, "epoch": epoch, "reason": "server already accepted durable unit result"})
	}
	return nil
}

func branchCommandObserved(b *collab.ExecutionBranch, c collab.BranchCommand) bool {
	switch c.Type {
	case "start", "end":
		if c.Operation != nil {
			for _, op := range b.Operations {
				if op.ID == c.Operation.ID {
					return c.Type == "start" || op.State != "started"
				}
			}
		}
	case "plan":
		if c.Unit != nil {
			for _, u := range b.Units {
				if u.Spec.Key == c.Unit.Key {
					return true
				}
			}
		}
	case "event":
		return c.Event != nil && c.Event.Seq <= b.NodeSeq
	case "ready":
		return b.State != "waiting_ready"
	case "not_ready":
		return b.Reason == c.Text
	case "checkpoint":
		return b.Checkpoint == c.Text
	case "unit_result":
		if u := unitByIDNode(b, c.UnitID); u != nil {
			if c.Result == nil || u.Result == nil {
				return false
			}
			want, e1 := json.Marshal(c.Result)
			got, e2 := json.Marshal(u.Result)
			return e1 == nil && e2 == nil && bytes.Equal(want, got)
		}
	case "submit":
		return b.State == "review_pending" || b.State == "accepted" || b.State == "partial"
	case "guidance_received", "guidance_applied":
		for _, g := range b.Guidance {
			for _, id := range c.GuidanceIDs {
				if g.ID == id && (c.Type == "guidance_received" && g.Status != "queued" || c.Type == "guidance_applied" && g.Status == "applied") {
					return true
				}
			}
		}
	case "propose", "publish", "assist":
		return false
	}
	return false
}
func unitByIDNode(b *collab.ExecutionBranch, id int64) *collab.BranchUnit {
	for i := range b.Units {
		if b.Units[i].ID == id {
			return &b.Units[i]
		}
	}
	return nil
}

type branchMeteredProvider struct {
	inner           llm.Provider
	ctx             context.Context
	cfg             localExecutionConfig
	origin, token   string
	client          *http.Client
	branch          *collab.ExecutionBranch
	unitID          int64
	role, journal   string
	plannerSnapshot string
	plannerMarked   bool
}

func (p *branchMeteredProvider) operation(r llm.CompletionRequest) (string, error) {
	registerBranchJournal(p.branch, p.journal)
	if _, err := postBranch(p.ctx, p.client, p.origin, p.token, p.branch, collab.BranchCommand{Type: "heartbeat"}); err != nil {
		return "", err
	}
	if p.role != "planner" && p.role != "reverse_planner" && branchHasQueuedGuidance(p.branch) {
		return "", errors.New("new branch guidance requires planner review before another model call")
	}
	raw, _ := json.Marshal(r)
	id := branchRequestID(p.branch.ID, p.branch.Epoch, collab.BranchCommand{Type: "model"})
	op := collab.BranchOperation{ID: id, Epoch: p.branch.Epoch, UnitID: p.unitID, Kind: "model", Role: p.role, InputHash: collab.ContentHash(raw)}
	if err := appendBranchJournal(p.journal, map[string]any{"kind": "operation_start", "op": op}); err != nil {
		return "", err
	}
	if _, err := postBranch(p.ctx, p.client, p.origin, p.token, p.branch, collab.BranchCommand{Type: "start", Operation: &op}); err != nil {
		if branchOperationDenied(err) {
			_ = appendBranchJournal(p.journal, map[string]any{"kind": "operation_end", "op": id, "state": "denied"})
		}
		return "", err
	}
	if p.unitID == 0 && (p.role == "planner" || p.role == "reverse_planner") && !p.plannerMarked {
		if err := appendBranchJournal(p.journal, map[string]any{"kind": "planner_start", "snapshot": p.plannerSnapshot, "epoch": p.branch.Epoch}); err != nil {
			return "", err
		}
		p.plannerMarked = true
	}
	if p.unitID > 0 {
		if err := appendBranchJournal(p.journal, map[string]any{"kind": "unit_start", "unit": p.unitID, "epoch": p.branch.Epoch}); err != nil {
			return "", err
		}
	}
	return id, nil
}

func branchHasQueuedGuidance(b *collab.ExecutionBranch) bool {
	for _, g := range b.Guidance {
		if g.Status == "queued" || g.Status == "pending" || g.Status == "received" {
			return true
		}
	}
	return false
}
func (p *branchMeteredProvider) finish(id, state string) error {
	op := collab.BranchOperation{ID: id, Epoch: p.branch.Epoch, UnitID: p.unitID, Kind: "model", Role: p.role, State: state}
	if _, err := postBranch(p.ctx, p.client, p.origin, p.token, p.branch, collab.BranchCommand{Type: "end", Operation: &op}); err != nil {
		return err
	}
	return appendBranchJournal(p.journal, map[string]any{"kind": "operation_end", "op": id, "state": state})
}
func (p *branchMeteredProvider) Stream(ctx context.Context, r llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		id, err := p.operation(r)
		if err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		// Buffer the model response so the operation is durably ended before the
		// harness can launch any tool calls yielded by that response.
		events := []llm.StreamEvent{}
		failed := false
		for ev, e := range p.inner.Stream(ctx, r) {
			if e != nil {
				failed = true
				break
			}
			events = append(events, ev)
		}
		state := "complete"
		if failed {
			state = "uncertain"
		}
		if e := p.finish(id, state); e != nil && !failed {
			failed = true
		}
		if failed {
			_ = yield(llm.StreamEvent{}, errors.New("branch model operation ended uncertainly"))
			return
		}
		for _, ev := range events {
			if !yield(ev, nil) {
				return
			}
		}
	}
}
func (p *branchMeteredProvider) Complete(ctx context.Context, r llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	id, err := p.operation(r)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	m, s, u, e := p.inner.Complete(ctx, r)
	state := "complete"
	if e != nil {
		state = "uncertain"
	}
	if x := p.finish(id, state); e == nil && x != nil {
		e = x
	}
	return m, s, u, e
}

func runBranchUnit(ctx context.Context, cfg localExecutionConfig, origin, token string, client *http.Client, reply collab.BranchReply, unit collab.BranchUnit, files map[string]string, work, journal string) error {
	b := reply.Branch
	registerBranchJournal(b, journal)
	spec := unit.Spec
	local, ok := cfg.Roles[spec.Role]
	if !ok {
		return errors.New("branch unit role is not configured locally")
	}
	portable, ok := reply.Policy.Roles[spec.Role]
	if !ok {
		return errors.New("branch unit role is not authorized by policy")
	}
	var contract struct {
		BudgetSeconds int      `json:"budget_seconds"`
		Acceptance    []string `json:"acceptance"`
	}
	if json.Unmarshal(spec.Contract, &contract) != nil || contract.BudgetSeconds < 1 || contract.BudgetSeconds > reply.Policy.MaxToolSeconds {
		return errors.New("invalid or over-budget WorkContract")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(contract.BudgetSeconds)*time.Second)
	defer cancel()
	model, ok := cfg.Models[local.Model]
	if !ok || os.Getenv(model.APIKeyEnv) == "" {
		return errors.New("local role model or credential is unavailable")
	}
	provider, err := branchProviderFactory(model, os.Getenv(model.APIKeyEnv))
	if err != nil {
		return err
	}
	allowed := map[string]bool{}
	for _, name := range portable.Capabilities {
		allowed[name] = true
	}
	for _, name := range spec.Capabilities {
		if !allowed[name] {
			return fmt.Errorf("capability %q is outside role policy", name)
		}
	}
	ev := &nodeEvidence{journal: filepath.Join(work, fmt.Sprintf("unit-%d-evidence.ndjson", unit.ID))}
	assignment := collab.Assignment{ID: b.ID, TaskID: b.TaskID, IntentID: unit.ID, DeviceID: b.DeviceID, Epoch: b.Epoch, State: "running", Config: portable, Input: collab.ExecutionInput{Version: 1, Intent: spec.Question}}
	assignment.Config.Role = spec.Role
	assignment.Config.Capabilities = spec.Capabilities
	for _, h := range spec.MaterialHashes {
		for _, m := range reply.Policy.Materials {
			if h == m.SHA256 {
				assignment.Input.Materials = append(assignment.Input.Materials, m)
			}
		}
	}
	unitFiles := map[string]string{}
	for _, h := range spec.MaterialHashes {
		if p, ok := files[h]; ok {
			unitFiles[h] = p
		}
	}
	assetSet := map[string]bool{}
	for _, id := range spec.AssetIDs {
		assetSet[id] = true
	}
	unitAssets := []collab.BranchAsset{}
	for _, a := range reply.Policy.Assets {
		if assetSet[a.ID] {
			unitAssets = append(unitAssets, a)
		}
	}
	tools := []actool.CoreTool{readMaterialTool(unitFiles, ev, func(context.Context) error { return nil })}
	for _, name := range spec.Capabilities {
		if name == "read_material" {
			continue
		}
		if name == reverseRuntimeCapability {
			if spec.Role != "reverse_dynamic" || spec.Runtime == nil {
				return errors.New("dynamic runtime authorization is missing")
			}
			pc := portable
			pc.Runtime = spec.Runtime
			pc.DynamicAllowed = true
			rp, pe := cfg.matchRuntimeBinding(pc, assignment.Input.Materials)
			if pe != nil {
				return pe
			}
			tools = append(tools, reverseObserveRuntimeTool(rp, *spec.Runtime, unitFiles, ev, func(context.Context) error { return nil }))
			continue
		}
		cmd, exists := cfg.Commands[name]
		if exists {
			if spec.Role != "worker" && !cmd.ReadOnly {
				return errors.New("review and reverse roles require read-only commands")
			}
			fields := cfg.Branches.ScopeFields[name]
			if len(fields) == 0 {
				return fmt.Errorf("capability %q lacks local target scope fields", name)
			}
			tools = append(tools, scopedBranchTool(name, cmd, work, ev, fields, unitAssets))
			continue
		}
		if _, exists = cfg.MCPTools[name]; exists {
			if len(cfg.Branches.ScopeFields[name]) == 0 {
				return fmt.Errorf("MCP capability %q lacks local target scope fields", name)
			}
		} else {
			return fmt.Errorf("local capability %q is not configured", name)
		}
	}
	if len(spec.Capabilities) > 0 {
		mcp, merr := buildAssignmentMCP(ctx, cfg, assignment, work, ev, func(context.Context) error { return nil })
		if merr != nil {
			return merr
		}
		defer mcp.close()
		for _, t := range mcp.tools {
			tools = append(tools, scopedMCPBranchTool(t, spec.Capabilities, cfg.Branches.ScopeFields, unitAssets))
		}
	}
	provider = &branchMeteredProvider{inner: provider, ctx: ctx, cfg: cfg, origin: origin, token: token, client: client, branch: b, unitID: unit.ID, role: spec.Role, journal: journal}
	hooks := &branchToolHooks{ctx: ctx, client: client, origin: origin, token: token, branch: b, unitID: unit.ID, role: spec.Role, journal: journal, active: map[string][]string{}, activeHashes: map[string][]string{}, cancel: cancel}
	tools = bindBranchToolHooks(tools, hooks)
	sys := fmt.Sprintf("Perform this bounded unit only: %s\nAcceptance criteria: %s\nUse authorized tools/materials. Report evidence and uncertainty; do not claim the criterion was accepted.", spec.Question, strings.Join(contract.Acceptance, "; "))
	s := agentcore.NewSession(agentcore.Options{Provider: provider, SystemPrompt: []string{portable.SystemPrompt, sys}, Tools: tools, Hooks: hooks, PermissionMode: permission.ModeBypass, WorkingDir: work, MaxTurns: portable.MaxTurns, MaxDuration: time.Duration(contract.BudgetSeconds) * time.Second, EnableWebFetch: false, EnableWebSearch: false})
	defer s.Close()
	var summary strings.Builder
	var promptErr error
	for event, e := range s.Prompt(ctx, branchUnitInput(spec, b, reply.Policy, reply.Dependencies)) {
		if e != nil {
			promptErr = e
			break
		}
		if event.Kind == "text" {
			summary.WriteString(event.Text)
		}
	}
	outcome, summaryText, parseErr := parseBranchUnitFinal(summary.String())
	if branchHasQueuedGuidance(b) {
		outcome = "blocked"
		summaryText = "Paused because new branch guidance arrived; planner must apply it before continuation."
	}
	if promptErr != nil && outcome == "" {
		outcome = "blocked"
		summaryText = "Unit paused before a final result: " + promptErr.Error()
	}
	if parseErr != nil && outcome == "" {
		outcome = "blocked"
		summaryText = "Unit did not return a valid final JSON result: " + parseErr.Error()
	}
	if outcome == "" {
		outcome = "blocked"
		summaryText = "Unit ended without a valid final JSON result."
	}
	evidence := ev.list()
	for i := range evidence {
		evidence[i].Content = redactBranchText(cfg, evidence[i].Content)
		evidence[i].SHA256 = collab.ContentHash([]byte(evidence[i].Content))
		evidence[i].Input = nil
	}
	result := collab.ExecutionResult{Version: 1, Outcome: outcome, Summary: redactBranchText(cfg, summaryText), Role: spec.Role, Model: model.Model, Evidence: evidence}
	if err = result.Validate(portable); err != nil {
		return err
	}
	if err = appendBranchJournal(journal, map[string]any{"kind": "unit_result", "unit": unit.ID, "result": result}); err != nil {
		return err
	}
	if err = branchCommand(ctx, client, origin, token, b, collab.BranchCommand{Type: "unit_result", UnitID: unit.ID, Result: &result, Text: "complete"}); err != nil {
		return err
	}
	if err = appendBranchJournal(journal, map[string]any{"kind": "unit_finished", "unit": unit.ID, "epoch": b.Epoch}); err != nil {
		return err
	}
	if branchHasQueuedGuidance(b) {
		return nil
	}
	return promptErr
}

func branchUnitInput(s collab.BranchUnitSpec, branch *collab.ExecutionBranch, p collab.BranchPolicy, dependencies []collab.ExecutionBranch) string {
	byID := map[int64]collab.BranchUnit{}
	for _, u := range branch.Units {
		byID[u.ID] = u
	}
	required := []collab.BranchUnit{}
	for _, id := range s.DependsOn {
		if u, ok := byID[id]; ok {
			required = append(required, u)
		}
	}
	sources := []collab.BranchUnit{}
	sourceBranches := []int64{}
	for _, ref := range s.EvidenceRefs {
		for _, dep := range dependencies {
			if dep.ID == ref.BranchID {
				for _, u := range dep.Units {
					if u.ID == ref.UnitID && u.EvidenceVersion == ref.Version {
						sources = append(sources, u)
						sourceBranches = append(sourceBranches, dep.ID)
					}
				}
			}
		}
	}
	b, _ := json.Marshal(map[string]any{"question": s.Question, "work_contract": json.RawMessage(s.Contract), "asset_ids": s.AssetIDs, "material_hashes": s.MaterialHashes, "branch_goal": p.Goal, "dependency_unit_results": required, "source_evidence_refs": map[string]any{"branch_ids": sourceBranches, "units": sources}, "final_format": "Return final JSON only: {\"outcome\":\"candidate|blocked|failed\",\"summary\":\"...\"}."})
	return string(b)
}

func parseBranchUnitFinal(raw string) (string, string, error) {
	type final struct {
		Outcome string `json:"outcome"`
		Summary string `json:"summary"`
	}
	dec := json.NewDecoder(strings.NewReader(strings.TrimSpace(raw)))
	dec.DisallowUnknownFields()
	var f final
	if err := dec.Decode(&f); err != nil {
		return "", "", err
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return "", "", errors.New("trailing final content")
	}
	if (f.Outcome != "candidate" && f.Outcome != "blocked" && f.Outcome != "failed") || strings.TrimSpace(f.Summary) == "" {
		return "", "", errors.New("outcome and summary are required")
	}
	return f.Outcome, strings.TrimSpace(f.Summary), nil
}

func scopedBranchTool(name string, cfg localCommandConfig, work string, ev *nodeEvidence, fields []string, assets []collab.BranchAsset) actool.CoreTool {
	base := commandTool(name, cfg, work, func(context.Context) error { return nil }, ev)
	return actool.Build(actool.Spec{Name: name, Description: cfg.Description, Schema: cfg.Schema, ReadOnly: func(json.RawMessage) bool { return cfg.ReadOnly }, Concurrent: func(json.RawMessage) bool { return false }, Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
		return permission.Allowed()
	}, Run: func(ctx context.Context, input json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
		if err := validateScopeInput(input, fields, assets); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		return base.Call(ctx, input, tc)
	}})
}

type branchScopedTool struct {
	base   actool.CoreTool
	fields []string
	assets []collab.BranchAsset
}

func (t *branchScopedTool) Name() string                           { return t.base.Name() }
func (t *branchScopedTool) Description() string                    { return t.base.Description() }
func (t *branchScopedTool) Prompt() string                         { return t.base.Prompt() }
func (t *branchScopedTool) InputSchema() map[string]any            { return t.base.InputSchema() }
func (t *branchScopedTool) IsReadOnly(b json.RawMessage) bool      { return t.base.IsReadOnly(b) }
func (t *branchScopedTool) IsConcurrencySafe(json.RawMessage) bool { return false }
func (t *branchScopedTool) CheckPermissions(ctx context.Context, b json.RawMessage, pc permission.Context) permission.Decision {
	return t.base.CheckPermissions(ctx, b, pc)
}
func (t *branchScopedTool) Call(ctx context.Context, b json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	if err := validateScopeInput(b, t.fields, t.assets); err != nil {
		return actool.Errorf(err.Error()), nil
	}
	return t.base.Call(ctx, b, tc)
}
func scopedMCPBranchTool(base actool.CoreTool, caps []string, fields map[string][]string, assets []collab.BranchAsset) actool.CoreTool {
	for _, cap := range caps {
		if cap == base.Name() && len(fields[cap]) > 0 {
			return &branchScopedTool{base: base, fields: fields[cap], assets: assets}
		}
	}
	return base
}
func branchHasReviewerResult(b *collab.ExecutionBranch) bool {
	foundWork := false
	for _, unit := range b.Units {
		if unit.State == "superseded" {
			continue
		}
		if unit.Spec.Role == "planner" || unit.Spec.Role == "reverse_planner" || unit.Spec.Role == "reviewer" || unit.Spec.Role == "reverse_reviewer" {
			continue
		}
		foundWork = true
		reviewed := false
		for _, review := range b.Units {
			if review.Spec.Role != "reviewer" && review.Spec.Role != "reverse_reviewer" {
				continue
			}
			if review.State != "candidate" || review.Result == nil || review.Result.Outcome != "candidate" {
				continue
			}
			for _, dep := range review.Spec.DependsOn {
				if dep == unit.ID {
					reviewed = true
				}
			}
		}
		if !reviewed {
			return false
		}
	}
	return foundWork
}

func validateScopeInput(raw json.RawMessage, fields []string, assets []collab.BranchAsset) error {
	var obj map[string]any
	if json.Unmarshal(raw, &obj) != nil {
		return errors.New("invalid scoped tool input")
	}
	allowed := map[string]bool{}
	for _, a := range assets {
		allowed[strings.TrimSpace(a.Target)] = true
	}
	for _, f := range fields {
		v, ok := obj[f]
		if !ok {
			return fmt.Errorf("scope field %s is required", f)
		}
		s, ok := v.(string)
		if !ok || !allowed[strings.TrimSpace(s)] {
			return errors.New("tool target is outside authorized assets")
		}
	}
	return nil
}

type branchToolHooks struct {
	ctx           context.Context
	client        *http.Client
	origin, token string
	branch        *collab.ExecutionBranch
	unitID        int64
	role, journal string
	cancel        context.CancelFunc
	mu            sync.Mutex
	active        map[string][]string
	activeHashes  map[string][]string
}

func (h *branchToolHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	registerBranchJournal(h.branch, h.journal)
	if _, err := postBranch(h.ctx, h.client, h.origin, h.token, h.branch, collab.BranchCommand{Type: "heartbeat"}); err != nil {
		if h.cancel != nil {
			h.cancel()
		}
		return true, "branch state unavailable before tool permit", input
	}
	if branchHasQueuedGuidance(h.branch) {
		if h.cancel != nil {
			h.cancel()
		}
		return true, "new branch guidance requires planner review before another tool", input
	}
	opID := branchRequestID(h.branch.ID, h.branch.Epoch, collab.BranchCommand{Type: "tool", Text: name})
	op := collab.BranchOperation{ID: opID, Epoch: h.branch.Epoch, UnitID: h.unitID, Kind: "tool", Role: h.role, Tool: name, InputHash: collab.ContentHash(input)}
	if err := appendBranchJournal(h.journal, map[string]any{"kind": "operation_start", "op": op}); err != nil {
		return true, "could not persist tool authorization checkpoint", input
	}
	if _, err := postBranch(h.ctx, h.client, h.origin, h.token, h.branch, collab.BranchCommand{Type: "start", Operation: &op}); err != nil {
		if branchOperationDenied(err) {
			_ = appendBranchJournal(h.journal, map[string]any{"kind": "operation_end", "op": opID, "state": "denied"})
			if h.cancel != nil {
				h.cancel()
			}
		}
		return true, "tool authorization denied or unavailable", input
	}
	if h.unitID > 0 {
		if err := appendBranchJournal(h.journal, map[string]any{"kind": "unit_start", "unit": h.unitID, "epoch": h.branch.Epoch}); err != nil {
			if h.cancel != nil {
				h.cancel()
			}
			return true, "could not persist unit start marker", input
		}
	}
	h.mu.Lock()
	h.active[name] = append(h.active[name], opID)
	h.activeHashes[name] = append(h.activeHashes[name], collab.ContentHash(input))
	h.mu.Unlock()
	return false, "", input
}

func branchOperationDenied(err error) bool {
	var e *nodeHTTPError
	return errors.As(err, &e) && (e.Code == http.StatusConflict || e.Code == http.StatusForbidden)
}
func (h *branchToolHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	h.mu.Lock()
	ids := h.active[name]
	if len(ids) == 0 {
		h.mu.Unlock()
		return
	}
	id := ids[len(ids)-1]
	h.active[name] = ids[:len(ids)-1]
	if len(h.activeHashes[name]) > 0 {
		h.activeHashes[name] = h.activeHashes[name][:len(h.activeHashes[name])-1]
	}
	h.mu.Unlock()
	state := "complete"
	if isErr {
		state = "uncertain"
	}
	op := collab.BranchOperation{ID: id, Epoch: h.branch.Epoch, UnitID: h.unitID, Kind: "tool", Role: h.role, Tool: name, InputHash: collab.ContentHash(input), State: state}
	_ = appendBranchJournal(h.journal, map[string]any{"kind": "operation_end", "op": id, "state": state})
	endCtx, cancel := context.WithTimeout(context.WithoutCancel(h.ctx), 10*time.Second)
	defer cancel()
	if _, err := postBranch(endCtx, h.client, h.origin, h.token, h.branch, collab.BranchCommand{Type: "end", Operation: &op}); err != nil && h.cancel != nil {
		h.cancel()
	}
}

func (h *branchToolHooks) verify(name string, input []byte) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	hashes := h.activeHashes[name]
	return len(hashes) > 0 && hashes[len(hashes)-1] == collab.ContentHash(input)
}

type branchAuthorizedTool struct {
	base  actool.CoreTool
	hooks *branchToolHooks
}

func (t *branchAuthorizedTool) Name() string                           { return t.base.Name() }
func (t *branchAuthorizedTool) Description() string                    { return t.base.Description() }
func (t *branchAuthorizedTool) Prompt() string                         { return t.base.Prompt() }
func (t *branchAuthorizedTool) InputSchema() map[string]any            { return t.base.InputSchema() }
func (t *branchAuthorizedTool) IsReadOnly(b json.RawMessage) bool      { return t.base.IsReadOnly(b) }
func (t *branchAuthorizedTool) IsConcurrencySafe(json.RawMessage) bool { return false }
func (t *branchAuthorizedTool) CheckPermissions(ctx context.Context, b json.RawMessage, pc permission.Context) permission.Decision {
	return t.base.CheckPermissions(ctx, b, pc)
}
func (t *branchAuthorizedTool) Call(ctx context.Context, b json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	if !t.hooks.verify(t.base.Name(), b) {
		return actool.Errorf("tool call input changed after authorization"), nil
	}
	return t.base.Call(ctx, b, tc)
}
func bindBranchToolHooks(tools []actool.CoreTool, h *branchToolHooks) []actool.CoreTool {
	out := make([]actool.CoreTool, 0, len(tools))
	for _, t := range tools {
		out = append(out, &branchAuthorizedTool{base: t, hooks: h})
	}
	return out
}
func (h *branchToolHooks) Stop(context.Context, []llm.Message) (bool, []string, string) {
	return false, nil, ""
}

var _ harness.HookRunner = (*branchToolHooks)(nil)

func redactBranchText(cfg localExecutionConfig, s string) string {
	for _, env := range cfg.Branches.EnvSecretNames {
		if v := os.Getenv(env); v != "" {
			s = strings.ReplaceAll(s, v, "[redacted]")
		}
	}
	for _, v := range cfg.Branches.RedactStrings {
		if v != "" {
			s = strings.ReplaceAll(s, v, "[redacted]")
		}
	}
	return s
}

func branchRedactedConfig(cfg localExecutionConfig, token string) localExecutionConfig {
	cfg.Branches.RedactStrings = append([]string(nil), cfg.Branches.RedactStrings...)
	if token != "" {
		cfg.Branches.RedactStrings = append(cfg.Branches.RedactStrings, token)
	}
	for _, m := range cfg.Models {
		if v := os.Getenv(m.APIKeyEnv); v != "" {
			cfg.Branches.RedactStrings = append(cfg.Branches.RedactStrings, v)
		}
	}
	for _, name := range cfg.Branches.EnvSecretNames {
		if v := os.Getenv(name); v != "" {
			cfg.Branches.RedactStrings = append(cfg.Branches.RedactStrings, v)
		}
	}
	return cfg
}

func sortedMapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func branchCommand(ctx context.Context, client *http.Client, origin, token string, b *collab.ExecutionBranch, cmd collab.BranchCommand) error {
	if b == nil {
		return errors.New("missing branch")
	}
	lock := branchCommandLock(b)
	lock.Lock()
	defer lock.Unlock()
	cmd.BranchID = b.ID
	cmd.Epoch = b.Epoch
	cmd.Revision = b.Revision
	if cmd.Event != nil {
		cmd.Event.BranchID = b.ID
		cmd.Event.Epoch = b.Epoch
		cmd.Event.DeviceID = b.DeviceID
		cmd.Event.Seq = b.NodeSeq + 1
	}
	if cmd.RequestID == "" {
		cmd.RequestID = branchRequestID(b.ID, b.Epoch, cmd)
	}
	journal := branchJournalFor(b)
	if journal == "" {
		return errors.New("branch journal is not registered")
	}
	if err := appendBranchJournal(journal, map[string]any{"kind": "command_pending", "request_id": cmd.RequestID, "epoch": cmd.Epoch, "command": cmd}); err != nil {
		return err
	}
	var reply collab.BranchReply
	if err := sendBranchCommand(ctx, client, origin, token, b, cmd, &reply); err != nil {
		var status *nodeHTTPError
		if errors.As(err, &status) && status.Code >= 400 && status.Code < 500 {
			if e := appendBranchJournal(journal, map[string]any{"kind": "command_rejected", "request_id": cmd.RequestID, "epoch": cmd.Epoch, "status": status.Code}); e != nil {
				return e
			}
		}
		return err
	}
	if err := appendBranchJournal(journal, map[string]any{"kind": "command_ack", "request_id": cmd.RequestID, "epoch": cmd.Epoch}); err != nil {
		return err
	}
	if reply.Branch != nil {
		*b = *reply.Branch
	}
	return nil
}

func branchRequestID(branch, epoch int64, c collab.BranchCommand) string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return fmt.Sprintf("%d-%d-%s", branch, epoch, hex.EncodeToString(raw[:]))
	}
	b, _ := json.Marshal(c)
	sum := sha256.Sum256(append([]byte(fmt.Sprintf("%d/%d/", branch, epoch)), b...))
	return hex.EncodeToString(sum[:])
}

func appendBranchJournal(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(append(b, '\n')); err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	return err
}

// repairBranchJournal salvages only a torn final record. The original bytes are
// retained in a private audit copy before truncation; corruption before EOF is fatal.
func repairBranchJournal(path string) error {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(raw) == 0 {
		return nil
	}
	lastNL := strings.LastIndexByte(string(raw), '\n')
	completeEnd := lastNL + 1
	for start := 0; start < len(raw); {
		rel := strings.IndexByte(string(raw[start:]), '\n')
		end := len(raw)
		if rel >= 0 {
			end = start + rel
		}
		line := bytes.TrimSpace(raw[start:end])
		if len(line) > 0 && !json.Valid(line) {
			if rel >= 0 {
				return errors.New("branch journal has corruption before final record")
			}
			backup := path + ".torn-" + time.Now().UTC().Format("20060102T150405.000000000Z")
			bf, e := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if e != nil {
				return e
			}
			_, e = bf.Write(raw)
			if e == nil {
				e = bf.Sync()
			}
			ce := bf.Close()
			if e == nil {
				e = ce
			}
			if e != nil {
				return e
			}
			f, e := os.OpenFile(path, os.O_WRONLY, 0600)
			if e != nil {
				return e
			}
			e = f.Truncate(int64(start))
			if e == nil {
				e = f.Sync()
			}
			ce = f.Close()
			if e == nil {
				e = ce
			}
			return e
		}
		if rel < 0 {
			break
		}
		start = end + 1
	}
	if lastNL < 0 || completeEnd < len(raw) {
		f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		_, e = f.Write([]byte{'\n'})
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e == nil {
			e = ce
		}
		return e
	}
	return nil
}

func branchHasUnresolved(path string) (bool, error) {
	if err := repairBranchJournal(path); err != nil {
		return true, err
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	active := map[string]bool{}
	unitActive := map[int64]bool{}
	plannerActive := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var row map[string]any
		if json.Unmarshal([]byte(line), &row) != nil {
			return true, nil
		}
		if row["kind"] == "operation_start" {
			op, _ := row["op"].(map[string]any)
			if id, ok := op["id"].(string); ok && id != "" {
				active[id] = true
			}
		}
		if row["kind"] == "operation_end" {
			if id, ok := row["op"].(string); ok {
				delete(active, id)
			}
		}
		if row["kind"] == "unit_start" {
			if id, ok := row["unit"].(float64); ok {
				unitActive[int64(id)] = true
			}
		}
		if row["kind"] == "unit_finished" {
			if id, ok := row["unit"].(float64); ok {
				delete(unitActive, int64(id))
			}
		}
		if row["kind"] == "planner_start" {
			if id, ok := row["snapshot"].(string); ok {
				plannerActive[id] = true
			}
		}
		if row["kind"] == "planner_done" || row["kind"] == "planner_paused" {
			if id, ok := row["snapshot"].(string); ok {
				delete(plannerActive, id)
			}
		}
	}
	return len(active) > 0 || len(unitActive) > 0 || len(plannerActive) > 0, nil
}

func branchUnresolvedEpochChanged(path string, epoch int64) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	active := map[string]int64{}
	units := map[int64]int64{}
	planners := map[string]int64{}
	for _, line := range strings.Split(string(raw), "\n") {
		var r map[string]any
		if json.Unmarshal([]byte(line), &r) != nil {
			continue
		}
		switch r["kind"] {
		case "operation_start":
			if op, ok := r["op"].(map[string]any); ok {
				if id, ok := op["id"].(string); ok {
					ep, _ := op["epoch"].(float64)
					active[id] = int64(ep)
				}
			}
		case "operation_end":
			if id, ok := r["op"].(string); ok {
				delete(active, id)
			}
		case "unit_start":
			id, _ := r["unit"].(float64)
			ep, _ := r["epoch"].(float64)
			units[int64(id)] = int64(ep)
		case "unit_finished":
			id, _ := r["unit"].(float64)
			delete(units, int64(id))
		case "planner_start":
			id, _ := r["snapshot"].(string)
			ep, _ := r["epoch"].(float64)
			planners[id] = int64(ep)
		case "planner_done", "planner_paused":
			id, _ := r["snapshot"].(string)
			delete(planners, id)
		}
	}
	for _, e := range active {
		if e != 0 && e != epoch {
			return true
		}
	}
	for _, e := range units {
		if e != 0 && e != epoch {
			return true
		}
	}
	for _, e := range planners {
		if e != 0 && e != epoch {
			return true
		}
	}
	return false
}

func branchOldOperationsConfirmed(path string, b *collab.ExecutionBranch) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	local := map[string]bool{}
	units := map[int64]bool{}
	planners := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		var r map[string]any
		if json.Unmarshal([]byte(line), &r) != nil {
			continue
		}
		if r["kind"] == "operation_start" {
			if op, ok := r["op"].(map[string]any); ok {
				if id, ok := op["id"].(string); ok {
					if ep, _ := op["epoch"].(float64); int64(ep) != b.Epoch {
						local[id] = true
					}
				}
			}
		}
		if r["kind"] == "operation_end" {
			if id, ok := r["op"].(string); ok {
				delete(local, id)
			}
		}
		if r["kind"] == "unit_start" {
			id, _ := r["unit"].(float64)
			ep, _ := r["epoch"].(float64)
			if int64(ep) != b.Epoch {
				units[int64(id)] = true
			}
		}
		if r["kind"] == "unit_finished" {
			id, _ := r["unit"].(float64)
			delete(units, int64(id))
		}
		if r["kind"] == "planner_start" {
			id, _ := r["snapshot"].(string)
			ep, _ := r["epoch"].(float64)
			if id != "" && int64(ep) != b.Epoch {
				planners[id] = true
			}
		}
		if r["kind"] == "planner_done" || r["kind"] == "planner_paused" {
			id, _ := r["snapshot"].(string)
			delete(planners, id)
		}
	}
	server := map[string]string{}
	for _, op := range b.Operations {
		server[op.ID] = op.State
	}
	for id := range local {
		state, ok := server[id]
		if ok && !(state == "cancelled" || state == "failed" || state == "stale" || state == "complete") {
			return false
		}
	}
	unitsByID := map[int64]string{}
	for _, u := range b.Units {
		unitsByID[u.ID] = u.State
	}
	for id := range units {
		state, ok := unitsByID[id]
		if !ok || !(state == "uncertain" || state == "superseded" || state == "failed" || state == "cancelled" || state == "candidate") {
			return false
		}
	}
	if len(planners) > 0 {
		for _, op := range b.Operations {
			if op.State == "started" || op.State == "uncertain" {
				return false
			}
		}
	}
	return len(local) > 0 || len(units) > 0 || len(planners) > 0
}

func branchReconcileConfirmedJournal(path string, epoch int64) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	ops := map[string]bool{}
	units := map[int64]bool{}
	planners := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		var r map[string]any
		if json.Unmarshal([]byte(line), &r) != nil {
			continue
		}
		switch r["kind"] {
		case "operation_start":
			if op, ok := r["op"].(map[string]any); ok {
				if id, ok := op["id"].(string); ok {
					if ep, _ := op["epoch"].(float64); int64(ep) != epoch {
						ops[id] = true
					}
				}
			}
		case "operation_end":
			if id, ok := r["op"].(string); ok {
				delete(ops, id)
			}
		case "unit_start":
			id, _ := r["unit"].(float64)
			if ep, _ := r["epoch"].(float64); int64(ep) != epoch {
				units[int64(id)] = true
			}
		case "unit_finished":
			id, _ := r["unit"].(float64)
			delete(units, int64(id))
		case "planner_start":
			id, _ := r["snapshot"].(string)
			if ep, _ := r["epoch"].(float64); int64(ep) != epoch {
				planners[id] = true
			}
		case "planner_done":
			id, _ := r["snapshot"].(string)
			delete(planners, id)
		}
	}
	for id := range ops {
		if err = appendBranchJournal(path, map[string]any{"kind": "operation_end", "op": id, "state": "confirmed_stopped_by_server", "epoch": epoch}); err != nil {
			return err
		}
	}
	for id := range units {
		if err = appendBranchJournal(path, map[string]any{"kind": "unit_finished", "unit": id, "epoch": epoch, "reason": "confirmed stopped; replacement requires explicit supersedes"}); err != nil {
			return err
		}
	}
	for sig := range planners {
		if err = appendBranchJournal(path, map[string]any{"kind": "planner_done", "snapshot": sig, "epoch": epoch, "reason": "confirmed stopped by server"}); err != nil {
			return err
		}
	}
	return nil
}
