package collab

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	ErrBranchDenied   = errors.New("branch access denied")
	ErrBranchConflict = errors.New("branch command conflict")
	ErrBranchInvalid  = errors.New("invalid branch command")
)

var branchPermissions = map[string]bool{"read": true, "process": true, "evidence": true, "discuss": true, "execute": true, "guide": true, "control": true, "review": true, "manage": true}

// ValidateBranchPolicy checks the immutable task-level envelope used by every branch.
func ValidateBranchPolicy(p BranchPolicy) error {
	if p.Version < 1 || strings.TrimSpace(p.Goal) == "" || len(p.Goal) > 64<<10 || p.Budget < 1 || p.Budget > 100_000 || p.MaxToolSeconds < 1 || p.MaxToolSeconds > 60 || p.MinToolIntervalMS < 0 || p.MinToolIntervalMS > 60000 || len(p.Kinds) == 0 || len(p.Kinds) > 2 || len(p.Assets) > 256 || len(p.Materials) > 16 {
		return ErrBranchInvalid
	}
	seen := map[string]bool{}
	for _, k := range p.Kinds {
		if (k != "pentest" && k != "reverse") || seen[k] {
			return ErrBranchInvalid
		}
		seen[k] = true
	}
	seen = map[string]bool{}
	for _, a := range p.Assets {
		if a.ID == "" || a.Target == "" || a.Version == "" || len(a.ID) > 200 || len(a.Target) > 2048 || len(a.Version) > 256 || seen[a.ID] {
			return ErrBranchInvalid
		}
		seen[a.ID] = true
	}
	seen = map[string]bool{}
	for _, m := range p.Materials {
		if m.ID != m.SHA256 || m.SHA256 == "" || len(m.SHA256) != 64 || m.Size < 0 || m.Size > 256<<20 || seen[m.SHA256] {
			return ErrBranchInvalid
		}
		b, e := hex.DecodeString(m.SHA256)
		if e != nil || len(b) != 32 {
			return ErrBranchInvalid
		}
		seen[m.SHA256] = true
	}
	kinds := map[string]bool{}
	for _, k := range p.Kinds {
		kinds[k] = true
	}
	for kind, prompt := range p.PlannerPrompts {
		if !kinds[kind] || strings.TrimSpace(prompt) == "" || len(prompt) > 128<<10 {
			return ErrBranchInvalid
		}
	}
	for role, c := range p.Roles {
		if !validBranchName(role, 80) || c.Role != role || c.Version != 1 || strings.TrimSpace(c.SystemPrompt) == "" || len(c.SystemPrompt) > 128<<10 || c.BudgetSeconds < 1 || c.BudgetSeconds > 7200 || len(c.Capabilities) > 64 || !kinds[c.Kind] || !branchRoleAllowed(c.Kind, role) {
			return ErrBranchInvalid
		}
		uniq := map[string]bool{}
		for _, cap := range c.Capabilities {
			if !validBranchName(cap, 80) || uniq[cap] {
				return ErrBranchInvalid
			}
			uniq[cap] = true
		}
		if role == "reviewer" || role == "reverse_reviewer" {
			for _, cap := range c.Capabilities {
				if !readOnlyReviewCapability(cap) {
					return ErrBranchInvalid
				}
			}
		}
	}
	return nil
}

func validBranchName(s string, n int) bool {
	if len(s) == 0 || len(s) > n {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' || r == ':') {
			return false
		}
	}
	return true
}

// CheckBranchAccess applies explicit per-task permission and restricted branch membership.
func CheckBranchAccess(p *BranchProject, a BranchActor, branchID int64, permission string) error {
	if p == nil || branchID < 0 || !branchPermissions[permission] {
		return ErrBranchDenied
	}
	member := a.MemberID
	if a.DeviceID > 0 {
		d, ok := a.Devices[a.DeviceID]
		if !ok || !d.Active || d.OwnerID < 1 {
			return ErrBranchDenied
		}
		member = d.OwnerID
	}
	if branchID == 0 {
		if a.Admin && permission != "review" {
			return nil
		}
		if member > 0 && hasBranchPermission(p, member, permission) {
			return nil
		}
		return ErrBranchDenied
	}
	b := findBranch(p, branchID)
	if b == nil {
		return ErrBranchDenied
	}
	if b.Spec.Restricted && !a.Admin && member > 0 && !hasID(b.Spec.Members, member) && !hasID(b.Contributors, member) {
		return ErrBranchDenied
	}
	if a.Admin && permission != "review" {
		return nil
	}
	if member < 1 || !hasBranchPermission(p, member, permission) {
		return ErrBranchDenied
	}
	return nil
}

func hasBranchPermission(p *BranchProject, id int64, permission string) bool {
	for _, x := range p.Permissions[strconv.FormatInt(id, 10)] {
		if x == permission {
			return true
		}
	}
	return false
}
func hasID(xs []int64, id int64) bool {
	for _, x := range xs {
		if x == id {
			return true
		}
	}
	return false
}
func findBranch(p *BranchProject, id int64) *ExecutionBranch {
	for i := range p.Branches {
		if p.Branches[i].ID == id {
			return &p.Branches[i]
		}
	}
	return nil
}
func nextID[T any](xs []T, id func(T) int64) int64 {
	n := int64(0)
	for _, x := range xs {
		if v := id(x); v > n {
			n = v
		}
	}
	return n + 1
}
func addEvent(p *BranchProject, b *ExecutionBranch, a BranchActor, kind, text string, unit int64, now time.Time) (BranchEvent, error) {
	if len(text) > 8192 || strings.TrimSpace(kind) == "" || len(kind) > 64 {
		return BranchEvent{}, ErrBranchInvalid
	}
	e := BranchEvent{UnitID: unit, Kind: kind, Text: text, CreatedAt: now}
	if b != nil {
		e.BranchID = b.ID
		e.Epoch = b.Epoch
	}
	if a.DeviceID > 0 {
		e.DeviceID = a.DeviceID
	} else {
		e.MemberID = a.MemberID
	}
	return e, nil
}
func receiptKey(a BranchActor, id string) string {
	if a.DeviceID > 0 {
		return "d:" + strconv.FormatInt(a.DeviceID, 10) + ":" + id
	}
	return "m:" + strconv.FormatInt(a.MemberID, 10) + ":" + id
}
func commandHash(c BranchCommand) string {
	raw, _ := json.Marshal(c)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func appendUnique(xs []int64, id int64) []int64 {
	if !hasID(xs, id) {
		xs = append(xs, id)
	}
	return xs
}
func stringContains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
func subsetStrings(got, allowed []string) bool {
	for _, x := range got {
		if !stringContains(allowed, x) {
			return false
		}
	}
	return true
}
func branchActorMember(a BranchActor, b *ExecutionBranch) (int64, bool) {
	if a.MemberID > 0 && a.DeviceID == 0 {
		return a.MemberID, true
	}
	if a.DeviceID > 0 {
		d, ok := a.Devices[a.DeviceID]
		return d.OwnerID, ok && d.Active && d.OwnerID == b.OwnerID && b.DeviceID == a.DeviceID
	}
	return 0, false
}
func requireAccess(p *BranchProject, a BranchActor, b *ExecutionBranch, perm string) error {
	return CheckBranchAccess(p, a, b.ID, perm)
}
func branchWorkValid(policy BranchPolicy, w BranchWorkSpec) error {
	if strings.TrimSpace(w.Title) == "" || len(w.Title) > 300 || strings.TrimSpace(w.Question) == "" || len(w.Question) > 8192 || !stringContains(policy.Kinds, w.Kind) || w.Budget < 1 || w.Budget > policy.Budget || len(w.AssetIDs) > len(policy.Assets) || len(w.MaterialHashes) > len(policy.Materials) || len(w.Roles) == 0 || len(w.Roles) > 32 || len(w.Acceptance) > 32 || len(w.ResourceKeys) > 64 || len(w.DependsOn) > 128 || len(w.Members) > 256 {
		return ErrBranchInvalid
	}
	assets := []string{}
	for _, x := range policy.Assets {
		assets = append(assets, x.ID)
	}
	mats := []string{}
	for _, x := range policy.Materials {
		mats = append(mats, x.SHA256)
	}
	if !subsetStrings(w.AssetIDs, assets) || !subsetStrings(w.MaterialHashes, mats) {
		return ErrBranchInvalid
	}
	for _, r := range w.Roles {
		cfg, ok := policy.Roles[r]
		if !ok || cfg.Kind != w.Kind {
			return ErrBranchInvalid
		}
	}
	for _, x := range w.Acceptance {
		if strings.TrimSpace(x) == "" || len(x) > 2048 {
			return ErrBranchInvalid
		}
	}
	for _, x := range w.ResourceKeys {
		if !validBranchName(x, 128) {
			return ErrBranchInvalid
		}
	}
	for _, x := range w.Members {
		if x < 1 {
			return ErrBranchInvalid
		}
	}
	return nil
}
func totalBudget(p *BranchProject) int64 {
	n := int64(0)
	for _, w := range p.Pool {
		if w.BranchID == 0 && w.State != "rejected" && w.State != "cancelled" {
			n += w.Spec.Budget
		}
	}
	for _, b := range p.Branches {
		n += b.Spec.Budget
	}
	return n
}
func unitByID(b *ExecutionBranch, id int64) *BranchUnit {
	for i := range b.Units {
		if b.Units[i].ID == id {
			return &b.Units[i]
		}
	}
	return nil
}
func allUnitsCandidate(b *ExecutionBranch) bool {
	if len(b.Units) == 0 {
		return false
	}
	for _, u := range b.Units {
		if u.State == "superseded" {
			continue
		}
		if u.State != "candidate" || u.Result == nil || u.Result.Outcome != "candidate" || u.EvidenceVersion == "" {
			return false
		}
	}
	return true
}
func hasReviewerUnit(b *ExecutionBranch) bool {
	for _, u := range b.Units {
		if (u.Spec.Role == "reviewer" || u.Spec.Role == "reverse_reviewer") && u.State == "candidate" && u.Result != nil && u.Result.Outcome == "candidate" {
			covered := true
			for _, other := range b.Units {
				if other.State != "superseded" && other.ID != u.ID && other.Spec.Role != "reviewer" && other.Spec.Role != "reverse_reviewer" && !hasID(u.Spec.DependsOn, other.ID) {
					covered = false
				}
			}
			if covered {
				return true
			}
		}
	}
	return false
}

func validBranchEvidenceRefs(p *BranchProject, b *ExecutionBranch, refs []BranchEvidenceRef) bool {
	seen := map[string]bool{}
	for _, ref := range refs {
		key := strconv.FormatInt(ref.BranchID, 10) + ":" + strconv.FormatInt(ref.UnitID, 10)
		if ref.BranchID < 1 || ref.UnitID < 1 || ref.Version == "" || seen[key] || !hasID(b.Spec.DependsOn, ref.BranchID) {
			return false
		}
		seen[key] = true
		source := findBranch(p, ref.BranchID)
		if source == nil || source.State != "accepted" {
			return false
		}
		u := unitByID(source, ref.UnitID)
		if u == nil || u.EvidenceVersion != ref.Version || u.State != "candidate" {
			return false
		}
	}
	return true
}

func invalidateEvidenceRefs(p *BranchProject, sourceBranchID, sourceUnitID int64, newVersion, reason string) {
	type invalidation struct {
		branch, unit int64
		version      string
	}
	queue := []invalidation{{sourceBranchID, sourceUnitID, newVersion}}
	seen := map[string]bool{}
	for len(queue) > 0 {
		x := queue[0]
		queue = queue[1:]
		key := strconv.FormatInt(x.branch, 10) + ":" + strconv.FormatInt(x.unit, 10)
		if seen[key] {
			continue
		}
		seen[key] = true
		for bi := range p.Branches {
			b := &p.Branches[bi]
			stale := false
			for ui := range b.Units {
				u := &b.Units[ui]
				for _, ref := range u.Spec.EvidenceRefs {
					if ref.BranchID == x.branch && (x.unit == 0 || ref.UnitID == x.unit) && ref.Version != x.version {
						if u.State == "candidate" {
							u.State = "stale"
							u.EvidenceVersion = ""
							queue = append(queue, invalidation{b.ID, u.ID, ""})
						}
						stale = true
					}
				}
				if b.ID == x.branch && (x.unit == 0 || hasID(u.Spec.DependsOn, x.unit)) && u.State == "candidate" {
					u.State = "stale"
					u.EvidenceVersion = ""
					stale = true
					queue = append(queue, invalidation{b.ID, u.ID, ""})
				}
			}
			if stale {
				if b.State == "accepted" || b.State == "review_pending" {
					b.State = "needs_supplement"
				}
				b.Reason = reason
				b.Reviewers = nil
				b.Revision++
				for wi := range p.Pool {
					if p.Pool[wi].BranchID == b.ID {
						p.Pool[wi].State = "claimed"
					}
				}
			}
		}
	}
	if p.State == "complete" {
		p.State = "paused"
		p.ClosedNote = "证据失效，必须重新核验：" + reason
	}
}
func containsOperation(b *ExecutionBranch, id string) *BranchOperation {
	for i := range b.Operations {
		if b.Operations[i].ID == id {
			return &b.Operations[i]
		}
	}
	return nil
}

// ApplyBranchCommand is the deterministic in-memory protocol transition. Persistence, locking and
// globally unique IDs belong to the caller; IDs allocated here are monotonic within the supplied project.
func ApplyBranchCommand(p *BranchProject, a BranchActor, c BranchCommand, now time.Time) (BranchReceipt, []BranchEvent, error) {
	if p == nil {
		return BranchReceipt{}, nil, ErrBranchInvalid
	}
	if a.DeviceID > 0 {
		owned := findBranch(p, c.BranchID)
		if owned == nil || owned.DeviceID != a.DeviceID || owned.OwnerID != a.MemberID || owned.Epoch != c.Epoch || CheckBranchAccess(p, a, owned.ID, "execute") != nil {
			return BranchReceipt{}, nil, ErrBranchDenied
		}
	}
	if p == nil || c.Type == "" || c.RequestID == "" || len(c.RequestID) > 200 {
		return BranchReceipt{}, nil, ErrBranchInvalid
	}
	if err := ValidateBranchPolicy(p.Policy); err != nil {
		return BranchReceipt{}, nil, err
	}
	k := receiptKey(a, c.RequestID)
	h := commandHash(c)
	if p.Receipts != nil {
		if old, ok := p.Receipts[k]; ok {
			if old.Hash != h {
				return BranchReceipt{}, nil, ErrBranchConflict
			}
			return old, nil, nil
		}
	}
	var r BranchReceipt
	var events []BranchEvent
	var err error
	var b *ExecutionBranch
	if c.BranchID > 0 {
		b = findBranch(p, c.BranchID)
		if b == nil {
			return r, nil, ErrBranchDenied
		}
	}
	need := func(permission string) error {
		if b == nil {
			return ErrBranchDenied
		}
		return requireAccess(p, a, b, permission)
	}
	member := a.MemberID
	isNode := a.DeviceID > 0
	if isNode {
		d, ok := a.Devices[a.DeviceID]
		if !ok || !d.Active {
			return r, nil, ErrBranchDenied
		}
		member = d.OwnerID
		if b != nil && c.Type != "publish" && CheckBranchAccess(p, a, b.ID, "execute") != nil {
			return r, nil, ErrBranchDenied
		}
	}
	add := func(kind, text string, unit int64) error {
		e, x := addEvent(p, b, a, kind, text, unit, now)
		if x == nil {
			events = append(events, e)
		}
		return x
	}
	mutated := false
	chargePlanning := isNode && stringContains([]string{"plan", "assist", "propose", "publish", "submit"}, c.Type)
	if chargePlanning && (b == nil || b.Spent >= b.Spec.Budget || totalSpent(p) >= p.Policy.Budget) {
		return r, nil, ErrBranchConflict
	}
	switch c.Type {
	case "extend_policy":
		if isNode || (!a.Admin && !hasBranchManage(p, member)) || p.State != "paused" || c.Policy == nil || c.Revision != p.Revision {
			return r, nil, ErrBranchDenied
		}
		for _, branch := range p.Branches {
			if hasInflight(&branch) {
				return r, nil, ErrBranchConflict
			}
		}
		if c.Policy.Budget < p.Policy.Budget || len(c.Policy.Materials) > 0 || len(c.Policy.Roles) > 0 || len(c.Policy.PlannerPrompts) > 0 {
			return r, nil, ErrBranchInvalid
		}
		updated := p.Policy
		updated.Version++
		updated.Budget = c.Policy.Budget
		for _, asset := range c.Policy.Assets {
			found := false
			for _, old := range updated.Assets {
				if old.ID == asset.ID {
					if old != asset {
						return r, nil, ErrBranchConflict
					}
					found = true
				}
			}
			if !found {
				updated.Assets = append(updated.Assets, asset)
			}
		}
		if err = ValidateBranchPolicy(updated); err != nil {
			return r, nil, err
		}
		p.Policy = updated
		for i := range p.Branches {
			p.Branches[i].PolicyVersion = updated.Version
			p.Branches[i].Revision++
		}
		mutated = true
	case "cancel_work":
		if isNode || (!a.Admin && !hasBranchManage(p, member)) || c.Revision != p.Revision || strings.TrimSpace(c.Text) == "" {
			return r, nil, ErrBranchDenied
		}
		for i := range p.Pool {
			w := &p.Pool[i]
			if w.ID == c.WorkID && w.BranchID == 0 && (w.State == "proposed" || w.State == "published") {
				w.State = "cancelled"
				mutated = true
			}
		}
	case "grant", "revoke":
		if isNode || (!a.Admin && !hasBranchManage(p, member)) {
			return r, nil, ErrBranchDenied
		}
		if !branchPermissions[c.Permission] || c.MemberID < 1 {
			return r, nil, ErrBranchInvalid
		}
		key := strconv.FormatInt(c.MemberID, 10)
		list := p.Permissions[key]
		revoking := c.Type == "revoke" || c.Revoke
		found := false
		out := make([]string, 0, len(list)+1)
		for _, v := range list {
			if v == c.Permission {
				found = true
				if !revoking {
					out = append(out, v)
				}
			} else {
				out = append(out, v)
			}
		}
		if !revoking && !found {
			out = append(out, c.Permission)
		}
		sort.Strings(out)
		if len(out) == 0 {
			delete(p.Permissions, key)
		} else {
			if p.Permissions == nil {
				p.Permissions = map[string][]string{}
			}
			p.Permissions[key] = out
		}
		mutated = true
	case "publish", "propose":
		if c.Work == nil {
			return r, nil, ErrBranchInvalid
		}
		coordinator := isNode && b != nil && b.Spec.Coordinator
		if (isNode && (b == nil || b.State != "running" || a.TaskPaused || p.State != "running")) || p.State == "complete" || p.State == "partial" || c.Work.ParentBranchID != 0 || c.Work.WorkflowRequestID != 0 || (isNode && c.Work.Coordinator) {
			return r, nil, ErrBranchDenied
		}
		if isNode && !coordinator {
			return r, nil, ErrBranchDenied
		}
		if !isNode && !a.Admin && !hasBranchManage(p, member) {
			return r, nil, ErrBranchDenied
		}
		if err = branchWorkValid(p.Policy, *c.Work); err != nil {
			return r, nil, err
		}
		for _, existing := range p.Pool {
			if existing.State != "cancelled" && existing.State != "rejected" && reflect.DeepEqual(existing.Spec, *c.Work) {
				return BranchReceipt{WorkID: existing.ID, BranchID: existing.BranchID}, nil, nil
			}
		}
		if totalBudget(p)+c.Work.Budget > p.Policy.Budget {
			return r, nil, ErrBranchConflict
		}
		for _, dep := range c.Work.DependsOn {
			if dep < 1 || findBranch(p, dep) == nil {
				return r, nil, ErrBranchInvalid
			}
		}
		w := BranchPoolWork{ID: nextID(p.Pool, func(x BranchPoolWork) int64 { return x.ID }), Spec: *c.Work, CreatedBy: member, State: "published"}
		if isNode && (!p.Policy.AutoPublish || c.Type == "propose") {
			w.State = "proposed"
		}
		p.Pool = append(p.Pool, w)
		r.WorkID = w.ID
		mutated = true
	case "assist":
		if b == nil || c.Work == nil || (!isNode && need("manage") != nil) || (isNode && (b.State != "running" || a.TaskPaused || p.State != "running")) {
			return r, nil, ErrBranchDenied
		}
		if err = branchWorkValid(p.Policy, *c.Work); err != nil {
			return r, nil, err
		}
		if c.Work.Kind == b.Spec.Kind || !subsetStrings(c.Work.AssetIDs, b.Spec.AssetIDs) || !subsetStrings(c.Work.MaterialHashes, b.Spec.MaterialHashes) || c.Work.Budget < 1 || c.Work.Budget >= b.Spec.Budget-b.Spent {
			return r, nil, ErrBranchConflict
		}
		for _, dep := range c.Work.DependsOn {
			if dep == b.ID || findBranch(p, dep) == nil || dependencyCycle(p, b.ID, dep) {
				return r, nil, ErrBranchConflict
			}
		}
		parentBudget := b.Spec.Budget
		w := BranchPoolWork{ID: nextID(p.Pool, func(x BranchPoolWork) int64 { return x.ID }), Spec: *c.Work, CreatedBy: member, State: "published"}
		w.Spec.ParentBranchID = b.ID
		w.Spec.WorkflowRequestID = 0 // Persistence assigns a globally unique workflow request ID.
		w.Spec.Coordinator = false
		w.Spec.Restricted = b.Spec.Restricted
		w.Spec.Members = append([]int64{}, b.Spec.Members...)
		p.Pool = append(p.Pool, w)
		b.Spec.Budget = parentBudget - w.Spec.Budget
		// The source waits for its requested assistance; the assistant must NOT
		// depend on the source being accepted (that would be a circular wait).
		r.WorkID = w.ID
		mutated = true
	case "approve":
		if !a.Admin && !hasBranchManage(p, member) {
			return r, nil, ErrBranchDenied
		}
		var w *BranchPoolWork
		for i := range p.Pool {
			if p.Pool[i].ID == c.WorkID {
				w = &p.Pool[i]
				break
			}
		}
		if w == nil || w.State != "proposed" {
			return r, nil, ErrBranchConflict
		}
		w.State = "published"
		mutated = true
	case "claim":
		if p.State == "complete" || p.State == "partial" || a.TaskTerminal {
			return r, nil, ErrBranchConflict
		}
		if isNode || member < 1 || !hasBranchPermission(p, member, "execute") {
			return r, nil, ErrBranchDenied
		}
		if !hasBranchPermission(p, member, "read") {
			return r, nil, ErrBranchDenied
		}
		var w *BranchPoolWork
		for i := range p.Pool {
			if p.Pool[i].ID == c.WorkID {
				w = &p.Pool[i]
				break
			}
		}
		if w == nil {
			return r, nil, ErrBranchDenied
		}
		if w.Spec.Restricted && !hasID(w.Spec.Members, member) {
			return r, nil, ErrBranchDenied
		}
		if w.BranchID > 0 {
			bb := findBranch(p, w.BranchID)
			if bb != nil && bb.OwnerID == member {
				r.BranchID = bb.ID
				return r, nil, nil
			}
			return r, nil, ErrBranchConflict
		}
		if w.State != "published" {
			return r, nil, ErrBranchConflict
		}
		if totalBudget(p) > p.Policy.Budget {
			return r, nil, ErrBranchConflict
		}
		deviceID, compatible := selectBranchDevice(a, w.Spec, member, c.DeviceID)
		if !compatible {
			return r, nil, ErrBranchDenied
		}
		d, ok := a.Devices[deviceID]
		if !ok || !d.Active || d.OwnerID != member {
			return r, nil, ErrBranchDenied
		}
		bnew := ExecutionBranch{ID: nextID(p.Branches, func(x ExecutionBranch) int64 { return x.ID }), WorkID: w.ID, TeamID: p.TeamID, TaskID: p.TaskID, Spec: w.Spec, OwnerID: member, ControlID: member, DeviceID: deviceID, Epoch: 1, Revision: 1, PolicyVersion: p.Policy.Version, State: "waiting_ready", Units: []BranchUnit{}, Guidance: []BranchGuidance{}, Contributors: []int64{member}}
		if d.Protocol != BranchProtocol || !subsetStrings(w.Spec.Roles, d.Roles) {
			bnew.Reason = "设备离线或协议/角色能力不匹配"
		} else if !d.Online {
			bnew.Reason = "设备离线，等待就绪"
		}
		p.Branches = append(p.Branches, bnew)
		if w.Spec.ParentBranchID > 0 {
			parent := findBranch(p, w.Spec.ParentBranchID)
			if parent == nil || dependencyCycle(p, parent.ID, bnew.ID) {
				return r, nil, ErrBranchConflict
			}
			parent.Spec.DependsOn = appendUnique(parent.Spec.DependsOn, bnew.ID)
			parent.Revision++
		}
		w.BranchID = bnew.ID
		w.State = "claimed"
		r.BranchID = bnew.ID
		mutated = true
	case "ready", "not_ready":
		if !isNode || a.DeviceID != b.DeviceID || c.Epoch != b.Epoch || a.TaskTerminal || p.State == "complete" || p.State == "partial" {
			return r, nil, ErrBranchDenied
		}
		if c.Type == "not_ready" {
			if hasInflight(b) || !stringContains([]string{"waiting_ready", "running", "waiting_dependency"}, b.State) {
				return r, nil, ErrBranchConflict
			}
			b.State = "waiting_ready"
			b.Reason = c.Text
		} else {
			if b.State != "waiting_ready" || hasInflight(b) {
				return r, nil, ErrBranchConflict
			}
			if dependenciesAccepted(p, b) {
				b.State = "running"
			} else {
				b.State = "waiting_dependency"
				b.Reason = "waiting for dependency"
			}
			if p.State == "paused" || a.TaskPaused {
				b.State = "waiting_ready"
				b.Reason = "主任务已暂停"
			}
			if b.State == "running" {
				b.LeaseUntil = now.Add(2 * time.Minute)
				b.Reason = ""
			}
		}
		mutated = true
		err = add(c.Type, c.Text, 0)
	case "heartbeat":
		if !isNode || a.DeviceID != b.DeviceID || c.Epoch != b.Epoch {
			return r, nil, ErrBranchDenied
		}
		if (a.TaskPaused || p.State != "running" || a.TaskTerminal) && b.State == "running" {
			if hasInflight(b) {
				b.State = "pausing"
			} else {
				b.State = "paused"
			}
			b.Reason = "主任务已暂停"
		}
		if b.State == "waiting_dependency" && dependenciesAccepted(p, b) && !a.TaskPaused && p.State == "running" {
			b.State = "running"
			b.Reason = ""
			mutated = true
		}
		if !stringContains([]string{"running", "waiting_dependency", "pausing", "paused", "transfer_wait", "cancelled", "waiting_ready", "needs_supplement", "review_pending", "accepted"}, b.State) {
			return r, nil, ErrBranchDenied
		}
		if b.State == "running" {
			b.LeaseUntil = now.Add(2 * time.Minute)
		}
		mutated = true
	case "plan":
		if !isNode || a.DeviceID != b.DeviceID || c.Epoch != b.Epoch || b.State != "running" || a.TaskPaused || a.TaskTerminal || p.State != "running" || c.Unit == nil || !dependenciesAccepted(p, b) || !b.LeaseUntil.After(now) {
			return r, nil, ErrBranchDenied
		}
		if err = validateBranchUnit(p.Policy, b, *c.Unit); err != nil {
			return r, nil, err
		}
		if c.Unit.Runtime != nil {
			return r, nil, ErrBranchInvalid
		}
		if !validBranchEvidenceRefs(p, b, c.Unit.EvidenceRefs) {
			return r, nil, ErrBranchDenied
		}
		for _, ref := range c.Unit.EvidenceRefs {
			if CheckBranchAccess(p, a, ref.BranchID, "evidence") != nil {
				return r, nil, ErrBranchDenied
			}
		}
		for _, u := range b.Units {
			if u.Spec.Key == c.Unit.Key {
				if reflect.DeepEqual(u.Spec, *c.Unit) {
					return BranchReceipt{BranchID: b.ID, UnitID: u.ID}, nil, nil
				}
				return r, nil, ErrBranchConflict
			}
		}
		for _, dep := range c.Unit.DependsOn {
			if unitByID(b, dep) == nil {
				return r, nil, ErrBranchInvalid
			}
		}
		if c.Unit.Supersedes > 0 {
			old := unitByID(b, c.Unit.Supersedes)
			if old == nil || !stringContains([]string{"uncertain", "stale", "failed"}, old.State) || hasInflight(b) {
				return r, nil, ErrBranchConflict
			}
			old.State = "superseded"
		}
		u := BranchUnit{ID: nextID(b.Units, func(x BranchUnit) int64 { return x.ID }), Spec: *c.Unit, State: "planned"}
		b.Units = append(b.Units, u)
		r.UnitID = u.ID
		mutated = true
		err = add("plan", u.Spec.Question, u.ID)
	case "start":
		if !isNode || a.DeviceID != b.DeviceID || c.Epoch != b.Epoch || c.Operation == nil || b.State != "running" || p.State == "paused" || p.State == "complete" || p.State == "partial" || a.TaskPaused || a.TaskTerminal || !hasBranchPermission(p, member, "execute") {
			return r, nil, ErrBranchDenied
		}
		op := *c.Operation
		if !validBranchName(op.ID, 160) || op.Epoch != b.Epoch || op.UnitID < 0 || op.InputHash == "" || len(op.InputHash) != 64 || !b.LeaseUntil.After(now) || b.PolicyVersion != p.Policy.Version || !dependenciesAccepted(p, b) {
			return r, nil, ErrBranchInvalid
		}
		decodedHash, hashErr := hex.DecodeString(op.InputHash)
		if hashErr != nil || len(decodedHash) != 32 {
			return r, nil, ErrBranchInvalid
		}
		if old := containsOperation(b, op.ID); old != nil {
			copy := *old
			copy.State = op.State
			if reflect.DeepEqual(copy, op) {
				return BranchReceipt{BranchID: b.ID, UnitID: op.UnitID}, nil, nil
			}
			return r, nil, ErrBranchConflict
		}
		u := unitByID(b, op.UnitID)
		if op.Kind != "model" && op.Kind != "tool" {
			return r, nil, ErrBranchInvalid
		}
		plannerRole := "planner"
		if b.Spec.Kind == "reverse" {
			plannerRole = "reverse_planner"
		}
		planning := op.UnitID == 0 && op.Kind == "model" && op.Role == plannerRole
		if !planning {
			if u == nil || !stringContains([]string{"planned", "running"}, u.State) || op.Role != u.Spec.Role {
				return r, nil, ErrBranchConflict
			}
			for _, id := range u.Spec.DependsOn {
				dep := unitByID(b, id)
				if dep == nil || dep.State != "candidate" || dep.Result == nil || dep.Result.Outcome != "candidate" {
					return r, nil, ErrBranchConflict
				}
			}
			if !validBranchEvidenceRefs(p, b, u.Spec.EvidenceRefs) {
				return r, nil, ErrBranchConflict
			}
		}
		if hasInflight(b) {
			return r, nil, ErrBranchConflict
		}
		dev := a.Devices[a.DeviceID]
		if dev.Protocol != BranchProtocol || !stringContains(dev.Roles, op.Role) {
			return r, nil, ErrBranchDenied
		}
		if op.Kind == "tool" {
			if (u.Spec.Role == "reviewer" || u.Spec.Role == "reverse_reviewer") && op.Tool != "read_material" {
				return r, nil, ErrBranchDenied
			}
			for _, x := range b.Operations {
				if x.State == "started" && x.Kind == "tool" {
					return r, nil, ErrBranchConflict
				}
			}
			if op.Tool != "read_material" && op.Tool != "reverse_observe_runtime" && (!stringContains(p.Policy.Roles[u.Spec.Role].Capabilities, op.Tool) || !stringContains(u.Spec.Capabilities, op.Tool) || !stringContains(dev.RoleCapabilities[u.Spec.Role], op.Tool)) {
				return r, nil, ErrBranchDenied
			}
			if op.Tool == "read_material" && len(u.Spec.MaterialHashes) == 0 {
				return r, nil, ErrBranchDenied
			}
			if op.Tool == "reverse_observe_runtime" && u.Spec.Role != "reverse_dynamic" {
				return r, nil, ErrBranchDenied
			}
			if op.Tool == "reverse_observe_runtime" {
				for _, old := range b.Operations {
					if old.UnitID == u.ID && old.Tool == op.Tool {
						return r, nil, ErrBranchDenied
					}
				}
			}
		} else if op.Tool != "" {
			return r, nil, ErrBranchInvalid
		}
		if u != nil && (u.Spec.Role == "reverse_dynamic") != (u.Spec.Runtime != nil) {
			return r, nil, ErrBranchDenied
		}
		for i := range p.Branches {
			other := &p.Branches[i]
			if other.ID == b.ID {
				continue
			}
			for _, o := range other.Operations {
				if op.Kind == "tool" && (o.State == "started" || o.State == "uncertain") && o.Kind == "tool" && resourceConflict(b, u, other, o.UnitID) {
					return r, nil, ErrBranchConflict
				}
			}
		}
		if b.Spent >= b.Spec.Budget || totalSpent(p) >= p.Policy.Budget {
			return r, nil, ErrBranchConflict
		}
		op.State = "started"
		b.Operations = append(b.Operations, op)
		if u != nil {
			if u.State == "planned" {
				u.Attempt++
			}
			u.State = "running"
		}
		b.Spent++
		mutated = true
		err = add(op.Kind+"_start", op.ID, op.UnitID)
	case "end":
		if !isNode || a.DeviceID != b.DeviceID || c.Epoch != b.Epoch || c.Operation == nil {
			return r, nil, ErrBranchDenied
		}
		o := containsOperation(b, c.Operation.ID)
		if o == nil || o.State != "started" {
			return r, nil, ErrBranchConflict
		}
		if c.State == "uncertain" || c.Operation.State == "uncertain" {
			o.State = "uncertain"
		} else {
			o.State = "complete"
		}
		mutated = true
		err = add(o.Kind+"_end", o.ID, o.UnitID)
	case "unit_result":
		if !isNode || a.DeviceID != b.DeviceID || c.Epoch != b.Epoch || c.Result == nil || !stringContains([]string{"running", "pausing", "transfer_wait"}, b.State) || hasInflight(b) {
			return r, nil, ErrBranchDenied
		}
		u := unitByID(b, c.UnitID)
		if u == nil || (u.State != "running" && u.State != "candidate") {
			return r, nil, ErrBranchInvalid
		}
		cfg, ok := p.Policy.Roles[u.Spec.Role]
		if !ok || c.Result.Validate(cfg) != nil {
			return r, nil, ErrBranchInvalid
		}
		raw, _ := json.Marshal(c.Result)
		newVersion := ContentHash(raw)
		if u.State == "candidate" && u.EvidenceVersion != newVersion {
			return r, nil, ErrBranchConflict
		}
		if u.EvidenceVersion != "" && u.EvidenceVersion != newVersion {
			invalidateEvidenceRefs(p, b.ID, u.ID, newVersion, "source evidence version changed")
		}
		u.Result = c.Result
		u.State = "candidate"
		if c.Result.Outcome != "candidate" {
			u.State = "failed"
		}
		u.EvidenceVersion = newVersion
		b.Contributors = appendUnique(b.Contributors, member)
		r.UnitID = u.ID
		mutated = true
		err = add("evidence", c.Result.Summary, u.ID)
	case "event", "discuss":
		if !isNode {
			err = need("discuss")
		}
		if err != nil {
			return r, nil, err
		}
		if c.Type == "event" && c.Event == nil {
			return r, nil, ErrBranchInvalid
		}
		if c.Type == "event" {
			if !isNode || a.DeviceID != b.DeviceID || c.Event.Seq != b.NodeSeq+1 {
				return r, nil, ErrBranchConflict
			}
			if c.Event.BranchID != 0 && c.Event.BranchID != b.ID || c.Event.Epoch != 0 && c.Event.Epoch != b.Epoch || c.Event.UnitID > 0 && unitByID(b, c.Event.UnitID) == nil || c.Event.MemberID != 0 || c.Event.DeviceID != 0 && c.Event.DeviceID != a.DeviceID {
				return r, nil, ErrBranchInvalid
			}
			if !allowedBranchEvent(c.Event.Kind) || len(c.Event.Text) > 4096 {
				return r, nil, ErrBranchInvalid
			}
			b.NodeSeq = c.Event.Seq
			mutated = true
			err = add(c.Event.Kind, c.Event.Text, c.Event.UnitID)
			if err == nil {
				events[len(events)-1].Seq = c.Event.Seq
				if c.Event.Evidence != nil {
					ev := c.Event.Evidence
					if len(ev.Content) > 64<<10 || ev.SHA256 != ContentHash([]byte(ev.Content)) || len(ev.Input) > 0 {
						return r, nil, ErrBranchInvalid
					}
					copy := *ev
					events[len(events)-1].Evidence = &copy
				}
			}
		} else {
			if isNode || len(c.Text) > 4096 {
				return r, nil, ErrBranchInvalid
			}
			mutated = true
			err = add("message", c.Text, c.UnitID)
		}
	case "guide":
		if isNode || (member < 1 && !a.Admin) || need("guide") != nil || (!a.Admin && b.ControlID != member) || !stringContains([]string{"running", "waiting_ready", "waiting_dependency", "paused"}, b.State) {
			return r, nil, ErrBranchDenied
		}
		if strings.TrimSpace(c.Text) == "" || len(c.Text) > 4096 {
			return r, nil, ErrBranchInvalid
		}
		g := BranchGuidance{ID: nextID(b.Guidance, func(x BranchGuidance) int64 { return x.ID }), MemberID: member, Text: c.Text, Status: "queued", Epoch: b.Epoch}
		b.Guidance = append(b.Guidance, g)
		mutated = true
		r.BranchID = b.ID
		err = add("guidance", c.Text, 0)
	case "authorize_runtime":
		if err = need("manage"); err != nil {
			return r, nil, err
		}
		if isNode || c.Runtime == nil || c.Revision != b.Revision || c.DeviceID != b.DeviceID {
			return r, nil, ErrBranchDenied
		}
		u := unitByID(b, c.UnitID)
		if u == nil || u.State != "planned" || u.Spec.Runtime != nil || u.Spec.Role != "reverse_dynamic" || c.Runtime.Validate() != nil || len(c.Runtime.ArtifactHashes) == 0 {
			return r, nil, ErrBranchInvalid
		}
		if !subsetStrings(c.Runtime.ArtifactHashes, u.Spec.MaterialHashes) {
			return r, nil, ErrBranchDenied
		}
		profileOK := false
		for _, profile := range a.Devices[b.DeviceID].RuntimeProfiles {
			if profile == c.Runtime.RuntimeProfile {
				profileOK = true
			}
		}
		if !profileOK {
			return r, nil, ErrBranchDenied
		}
		u.Spec.Runtime = c.Runtime
		mutated = true
		r.UnitID = u.ID
		err = add("runtime_authorized", c.Runtime.ID, u.ID)
	case "guidance_received", "guidance_applied":
		if !isNode || a.DeviceID != b.DeviceID || c.Epoch != b.Epoch {
			return r, nil, ErrBranchDenied
		}
		status := "received"
		if c.Type == "guidance_applied" {
			status = "applied"
		}
		for i := range b.Guidance {
			if hasID(c.GuidanceIDs, b.Guidance[i].ID) && b.Guidance[i].Epoch == b.Epoch && b.Guidance[i].Status == map[bool]string{true: "received", false: "queued"}[status == "applied"] {
				b.Guidance[i].Status = status
				mutated = true
			}
		}
		if !mutated {
			return r, nil, ErrBranchConflict
		}
		err = add(c.Type, c.Text, 0)
	case "project_pause", "project_resume":
		if !a.Admin && !hasBranchManage(p, member) {
			return r, nil, ErrBranchDenied
		}
		if c.Revision != p.Revision {
			return r, nil, ErrBranchConflict
		}
		if c.Type == "project_pause" {
			if p.State == "complete" || p.State == "partial" {
				return r, nil, ErrBranchConflict
			}
			p.State = "paused"
			for i := range p.Branches {
				x := &p.Branches[i]
				if x.State == "running" {
					if hasInflight(x) {
						x.State = "pausing"
					} else {
						x.State = "paused"
					}
					x.Reason = "主任务已暂停"
					x.Revision++
				}
			}
		} else {
			if p.State != "paused" {
				return r, nil, ErrBranchConflict
			}
			p.State = "running"
			for i := range p.Branches {
				x := &p.Branches[i]
				if x.State == "paused" && x.Reason == "主任务已暂停" && !hasInflight(x) {
					x.State = "waiting_ready"
					x.Reason = ""
					x.Revision++
				}
			}
		}
		mutated = true
	case "pause", "resume", "stop", "control_takeover":
		if err = need("control"); err != nil {
			return r, nil, err
		}
		if isNode || (!a.Admin && b.ControlID != member && !(c.Type == "control_takeover" && hasBranchManage(p, member))) {
			return r, nil, ErrBranchDenied
		}
		if c.Revision != b.Revision {
			return r, nil, ErrBranchConflict
		}
		switch c.Type {
		case "pause":
			if b.State != "running" {
				return r, nil, ErrBranchConflict
			}
			if hasInflight(b) {
				b.State = "pausing"
			} else {
				b.State = "paused"
			}
		case "resume":
			if !stringContains([]string{"paused", "needs_supplement", "waiting_ready"}, b.State) || hasInflight(b) || p.State != "running" || a.TaskPaused {
				return r, nil, ErrBranchConflict
			}
			b.State = "waiting_ready"
			b.Reason = ""
		case "stop":
			if b.State == "accepted" || b.State == "cancelled" {
				return r, nil, ErrBranchConflict
			}
			b.State = "cancelled"
			cancelBranchAssistance(p, b.ID)
			for i := range p.Pool {
				if p.Pool[i].BranchID == b.ID {
					p.Pool[i].State = "cancelled"
				}
			}
			for i := range b.Operations {
				if b.Operations[i].State == "started" {
					b.Operations[i].State = "uncertain"
				}
			}
			for i := range b.Guidance {
				if b.Guidance[i].Status != "applied" {
					b.Guidance[i].Status = "failed"
				}
			}
		case "control_takeover":
			if c.MemberID < 1 || CheckBranchAccess(p, BranchActor{MemberID: c.MemberID}, b.ID, "control") != nil {
				return r, nil, ErrBranchInvalid
			}
			b.ControlID = c.MemberID
		}
		b.Revision++
		mutated = true
		err = add(c.Type, c.Text, 0)
	case "checkpoint":
		if c.State == "waiting_dependency" {
			if !isNode || a.DeviceID != b.DeviceID || c.Epoch != b.Epoch || hasInflight(b) || b.State != "running" || dependenciesAccepted(p, b) {
				return r, nil, ErrBranchDenied
			}
			b.State = "waiting_dependency"
			b.Checkpoint = c.Text
			mutated = true
			err = add("checkpoint", c.Text, 0)
			break
		}
		if !isNode || a.DeviceID != b.DeviceID || c.Epoch != b.Epoch || !stringContains([]string{"pausing", "running", "transfer_wait", "waiting_ready", "cancelled", "paused"}, b.State) {
			return r, nil, ErrBranchDenied
		}
		if hasInflight(b) {
			// A restart can report uncertainty, never silently clear the fence.
			for i := range b.Operations {
				if b.Operations[i].State == "started" {
					b.Operations[i].State = "uncertain"
				}
			}
			b.Checkpoint = c.Text
			b.Reason = "存在未确认操作；需确认执行端已停止后继续"
			if b.State != "transfer_wait" && b.State != "cancelled" {
				b.State = "paused"
			}
			mutated = true
			err = add("checkpoint", c.Text, 0)
			break
		}
		b.Checkpoint = c.Text
		if b.State == "transfer_wait" && b.PendingOwnerID > 0 {
			if !canTransferTo(p, a, b) {
				return r, nil, ErrBranchDenied
			}
			finishBranchTransfer(b)
		} else {
			if b.State != "cancelled" {
				b.State = "paused"
			}
		}
		mutated = true
		err = add("checkpoint", c.Text, 0)
	case "transfer":
		if err = need("control"); err != nil {
			return r, nil, err
		}
		if isNode || (!a.Admin && b.ControlID != member) || c.MemberID < 1 || c.Revision != b.Revision || stringContains([]string{"accepted", "cancelled", "failed", "review_pending"}, b.State) {
			return r, nil, ErrBranchDenied
		}
		deviceID, ok := selectBranchDevice(a, b.Spec, c.MemberID, c.DeviceID)
		if !ok || !hasBranchPermission(p, c.MemberID, "read") || !hasBranchPermission(p, c.MemberID, "execute") {
			return r, nil, ErrBranchDenied
		}
		if hasInflight(b) || !b.LeaseUntil.IsZero() && now.Before(b.LeaseUntil) {
			b.PendingOwnerID = c.MemberID
			b.PendingDeviceID = deviceID
			b.State = "transfer_wait"
		} else {
			b.PendingOwnerID = c.MemberID
			b.PendingDeviceID = deviceID
			finishBranchTransfer(b)
		}
		mutated = true
		err = add("transfer", c.Text, 0)
	case "confirm_stopped":
		if err = need("control"); err != nil {
			return r, nil, err
		}
		if isNode || (!a.Admin && b.ControlID != member) || !stringContains([]string{"transfer_wait", "paused", "cancelled"}, b.State) || strings.TrimSpace(c.Text) == "" || c.Revision != b.Revision {
			return r, nil, ErrBranchDenied
		}
		if hasInflight(b) {
			for i := range b.Operations {
				if b.Operations[i].State == "started" || b.Operations[i].State == "uncertain" {
					b.Operations[i].State = "cancelled"
				}
			}
		}
		if b.State == "transfer_wait" {
			if !canTransferTo(p, a, b) {
				return r, nil, ErrBranchDenied
			}
			finishBranchTransfer(b)
		} else {
			b.Epoch++
			b.NodeSeq = 0
			b.LeaseUntil = time.Time{}
			for i := range b.Units {
				if b.Units[i].State == "running" {
					b.Units[i].State = "uncertain"
				}
				if b.Units[i].State != "candidate" {
					b.Units[i].Spec.Runtime = nil
				}
			}
			b.Reason = "未确认工作单保留为未决，不会自动重放；可规划新的补充工作"
		}
		mutated = true
		err = add("transfer_confirmed", c.Text, 0)
	case "submit":
		if !isNode || a.DeviceID != b.DeviceID || c.Epoch != b.Epoch || b.State != "running" || !allUnitsCandidate(b) || !hasReviewerUnit(b) || hasInflight(b) || a.TaskPaused || p.State != "running" || !dependenciesAccepted(p, b) {
			return r, nil, ErrBranchConflict
		}
		if c.Outcome != "candidate" && c.Outcome != "negative" {
			return r, nil, ErrBranchInvalid
		}
		b.State = "review_pending"
		b.Outcome = c.Outcome
		b.Summary = c.Text
		mutated = true
		err = add("submitted", c.Text, 0)
	case "review":
		if err = need("review"); err != nil {
			return r, nil, err
		}
		if member < 1 || isNode || b.State != "review_pending" || hasID(b.Contributors, member) || c.Revision != b.Revision || !allUnitsCandidate(b) || !dependenciesAccepted(p, b) {
			return r, nil, ErrBranchDenied
		}
		b.Reviewers = appendUnique(b.Reviewers, member)
		if c.State == "accept" {
			b.State = "accepted"
			for i := range p.Pool {
				if p.Pool[i].BranchID == b.ID {
					p.Pool[i].State = "accepted"
				}
			}
		} else if c.State == "supplement" {
			b.State = "needs_supplement"
			b.Reason = c.Text
			for i := range b.Units {
				u := &b.Units[i]
				if u.Spec.Role == "reviewer" || u.Spec.Role == "reverse_reviewer" {
					u.State = "stale"
					u.EvidenceVersion = ""
				}
			}
		} else {
			return r, nil, ErrBranchInvalid
		}
		mutated = true
		err = add("review", c.Text, 0)
	case "dependency":
		if !isNode {
			err = need("manage")
		}
		if err != nil {
			return r, nil, err
		}
		if isNode && a.DeviceID != b.DeviceID {
			return r, nil, ErrBranchDenied
		}
		target := c.WorkID
		if target < 1 {
			target = c.MemberID
		}
		if target < 1 || target == b.ID {
			return r, nil, ErrBranchInvalid
		}
		dep := findBranch(p, target)
		if dep == nil || dependencyCycle(p, b.ID, dep.ID) {
			return r, nil, ErrBranchConflict
		}
		if !hasID(b.Spec.DependsOn, dep.ID) {
			b.Spec.DependsOn = append(b.Spec.DependsOn, dep.ID)
			mutated = true
		}
		err = add("dependency", strconv.FormatInt(dep.ID, 10), 0)
	case "invalidate_evidence":
		if err = need("manage"); err != nil {
			if requireAccess(p, a, b, "review") != nil {
				return r, nil, err
			}
		}
		if strings.TrimSpace(c.Text) == "" {
			return r, nil, ErrBranchInvalid
		}
		for i := range b.Units {
			if c.UnitID == 0 || c.UnitID == b.Units[i].ID {
				b.Units[i].EvidenceVersion = ""
				b.Units[i].State = "stale"
			}
		}
		if b.State == "accepted" || b.State == "review_pending" {
			b.State = "needs_supplement"
		}
		for i := range p.Pool {
			if p.Pool[i].BranchID == b.ID {
				p.Pool[i].State = "claimed"
			}
		}
		invalidateEvidenceRefs(p, b.ID, c.UnitID, "", c.Text)
		mutated = true
		err = add("evidence_invalidated", c.Text, 0)
	case "close":
		if isNode || (!a.Admin && !hasBranchManage(p, member)) || c.Revision != p.Revision {
			return r, nil, ErrBranchDenied
		}
		complete := len(p.Branches) > 0
		for _, x := range p.Pool {
			if x.State == "published" || x.State == "claimed" || x.State == "proposed" {
				complete = false
			}
		}
		for _, x := range p.Branches {
			if hasInflight(&x) {
				return r, nil, ErrBranchConflict
			}
			if x.State != "accepted" {
				complete = false
			}
		}
		if complete {
			p.State = "complete"
			p.ClosedNote = c.Text
		} else {
			if c.State != "partial" || strings.TrimSpace(c.Text) == "" {
				return r, nil, ErrBranchConflict
			}
			p.State = "partial"
			p.ClosedNote = c.Text
		}
		mutated = true
	default:
		return r, nil, ErrBranchInvalid
	}
	if err != nil {
		return BranchReceipt{}, nil, err
	}
	if !mutated {
		return BranchReceipt{}, nil, ErrBranchConflict
	}
	if chargePlanning {
		b.Spent++
	}
	if len(events) == 0 && c.Type != "heartbeat" {
		ev, _ := addEvent(p, b, a, c.Type, c.Text, c.UnitID, now)
		events = append(events, ev)
	}
	if b != nil {
		if b.Revision == 0 {
			b.Revision = 1
		}
		if !isNode && c.Type != "control_takeover" && c.Type != "pause" && c.Type != "resume" && c.Type != "stop" {
			b.Revision++
		}
		r.BranchID = b.ID
	}
	if !isNode || c.Type == "assist" || c.Type == "publish" || c.Type == "propose" {
		p.Revision++
	}
	if p.Receipts == nil {
		p.Receipts = map[string]BranchReceipt{}
	}
	r.Hash = h
	if c.Type != "heartbeat" {
		p.Receipts[k] = r
	}
	return r, events, nil
}

func hasBranchManage(p *BranchProject, member int64) bool {
	return member > 0 && hasBranchPermission(p, member, "manage")
}

func cancelBranchAssistance(p *BranchProject, parent int64) {
	for i := range p.Pool {
		w := &p.Pool[i]
		if w.Spec.ParentBranchID != parent || w.State == "accepted" || w.State == "cancelled" {
			continue
		}
		w.State = "cancelled"
		if b := findBranch(p, w.BranchID); b != nil {
			b.State = "cancelled"
			b.Reason = "来源分支取消了协助请求"
			b.Revision++
			for j := range b.Operations {
				if b.Operations[j].State == "started" {
					b.Operations[j].State = "uncertain"
				}
			}
			cancelBranchAssistance(p, b.ID)
		}
	}
}

func canTransferTo(p *BranchProject, a BranchActor, b *ExecutionBranch) bool {
	_, ok := selectBranchDevice(a, b.Spec, b.PendingOwnerID, b.PendingDeviceID)
	return ok && hasBranchPermission(p, b.PendingOwnerID, "read") && hasBranchPermission(p, b.PendingOwnerID, "execute")
}
func finishBranchTransfer(b *ExecutionBranch) {
	b.Epoch++
	b.Revision++
	b.NodeSeq = 0
	b.OwnerID = b.PendingOwnerID
	b.ControlID = b.PendingOwnerID
	b.DeviceID = b.PendingDeviceID
	b.Contributors = appendUnique(b.Contributors, b.OwnerID)
	b.PendingOwnerID = 0
	b.PendingDeviceID = 0
	b.LeaseUntil = time.Time{}
	b.State = "waiting_ready"
	b.Reason = ""
	for i := range b.Units {
		if b.Units[i].State == "running" {
			b.Units[i].State = "uncertain"
		}
		if b.Units[i].State != "candidate" {
			b.Units[i].Spec.Runtime = nil
		}
	}
	for i := range b.Guidance {
		if b.Guidance[i].Status != "applied" {
			b.Guidance[i].Status = "failed"
		}
	}
}
func validateBranchUnit(p BranchPolicy, b *ExecutionBranch, u BranchUnitSpec) error {
	if !validBranchName(u.Key, 128) || strings.TrimSpace(u.Question) == "" || len(u.Question) > 8192 || !stringContains(b.Spec.Roles, u.Role) || len(u.AssetIDs) > len(b.Spec.AssetIDs) || len(u.MaterialHashes) > len(b.Spec.MaterialHashes) || !subsetStrings(u.AssetIDs, b.Spec.AssetIDs) || !subsetStrings(u.MaterialHashes, b.Spec.MaterialHashes) || !subsetStrings(u.Capabilities, p.Roles[u.Role].Capabilities) || len(u.DependsOn) > 64 || len(u.Contract) > 64<<10 || len(u.Contract) > 0 && !json.Valid(u.Contract) {
		return ErrBranchInvalid
	}
	return nil
}
func branchRoleAllowed(kind, role string) bool {
	switch kind {
	case "pentest":
		return role == "worker" || role == "reviewer"
	case "reverse":
		return role == "reverse_static" || role == "reverse_dynamic" || role == "reverse_reviewer"
	}
	return false
}

func selectBranchDevice(a BranchActor, spec BranchWorkSpec, member, requested int64) (int64, bool) {
	ids := make([]int64, 0, len(a.Devices))
	for id := range a.Devices {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		if requested > 0 && id != requested {
			continue
		}
		d := a.Devices[id]
		if d.Active && d.OwnerID == member && d.Protocol == BranchProtocol && subsetStrings(spec.Roles, d.Roles) {
			return id, true
		}
	}
	return 0, false
}

func readOnlyReviewCapability(cap string) bool {
	return cap == "read_material"
}
func dependenciesAccepted(p *BranchProject, b *ExecutionBranch) bool {
	for _, w := range p.Pool {
		if w.Spec.ParentBranchID == b.ID && w.State != "accepted" && w.State != "cancelled" && w.State != "rejected" {
			return false
		}
	}
	for _, id := range b.Spec.DependsOn {
		x := findBranch(p, id)
		if x == nil || x.State != "accepted" {
			return false
		}
	}
	return true
}
func totalSpent(p *BranchProject) int64 {
	var n int64
	for _, b := range p.Branches {
		n += b.Spent
	}
	return n
}
func resourceConflict(a *ExecutionBranch, ua *BranchUnit, b *ExecutionBranch, unitID int64) bool {
	ub := unitByID(b, unitID)
	if ub == nil {
		return false
	}
	ak := append(append([]string{}, a.Spec.ResourceKeys...), contractResourceKey(ua.Spec.Contract))
	bk := append(append([]string{}, b.Spec.ResourceKeys...), contractResourceKey(ub.Spec.Contract))
	for _, x := range ak {
		if x == "" {
			continue
		}
		for _, y := range bk {
			if x == y {
				return true
			}
		}
	}
	return false
}
func contractResourceKey(raw json.RawMessage) string {
	var v struct {
		ResourceKey string `json:"resource_key"`
	}
	_ = json.Unmarshal(raw, &v)
	return v.ResourceKey
}
func (u *BranchUnit) SpecContractKeys() []string { // resource keys are declared by work and bound into each unit contract when needed.
	var v struct {
		ResourceKeys []string `json:"resource_keys"`
	}
	_ = json.Unmarshal(u.Spec.Contract, &v)
	return v.ResourceKeys
}
func hasInflight(b *ExecutionBranch) bool {
	for _, o := range b.Operations {
		if o.State == "started" || o.State == "uncertain" {
			return true
		}
	}
	return false
}
func allowedBranchEvent(k string) bool {
	switch k {
	case "message", "plan", "tool_start", "tool_end", "tool_error", "checkpoint", "evidence", "status", "guidance_received", "guidance_applied":
		return true
	}
	return false
}
func dependencyCycle(p *BranchProject, from, to int64) bool {
	seen := map[int64]bool{}
	var walk func(int64) bool
	walk = func(id int64) bool {
		if id == from {
			return true
		}
		if seen[id] {
			return false
		}
		seen[id] = true
		b := findBranch(p, id)
		if b == nil {
			return false
		}
		for _, x := range b.Spec.DependsOn {
			if walk(x) {
				return true
			}
		}
		return false
	}
	return walk(to)
}
func dependsOn(xs []int64, id int64) bool { return hasID(xs, id) }
