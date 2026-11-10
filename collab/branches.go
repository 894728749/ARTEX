package collab

import (
	"encoding/json"
	"time"
)

// BranchProtocol is opt-in. It does not change the legacy assignment protocol.
const BranchProtocol = 1

var BranchPermissions = []string{"read", "process", "evidence", "discuss", "execute", "guide", "control", "review", "manage"}

type BranchAsset struct {
	ID      string `json:"id"`
	Target  string `json:"target"`
	Version string `json:"version"`
}

// Budget counts authorized model requests and tool calls, not money. Every
// retry/assistance/epoch consumes the same project allocation. Runtime remains
// additionally bounded by MaxToolSeconds and each WorkContract's wall budget.
type BranchPolicy struct {
	Version           int64                      `json:"version"`
	Goal              string                     `json:"goal"`
	Assets            []BranchAsset              `json:"assets"`
	Materials         []Material                 `json:"materials"`
	Budget            int64                      `json:"budget"`
	MaxToolSeconds    int                        `json:"max_tool_seconds"`
	MinToolIntervalMS int                        `json:"min_tool_interval_ms"`
	AutoPublish       bool                       `json:"auto_publish"`
	Kinds             []string                   `json:"kinds"`
	PlannerPrompts    map[string]string          `json:"planner_prompts"`
	Roles             map[string]ExecutionConfig `json:"roles"`
}

type BranchWorkSpec struct {
	Title             string   `json:"title"`
	Question          string   `json:"question"`
	Kind              string   `json:"kind"`
	AssetIDs          []string `json:"asset_ids"`
	MaterialHashes    []string `json:"material_hashes"`
	Roles             []string `json:"roles"`
	Acceptance        []string `json:"acceptance"`
	Budget            int64    `json:"budget"`
	ResourceKeys      []string `json:"resource_keys"`
	DependsOn         []int64  `json:"depends_on"`
	Restricted        bool     `json:"restricted"`
	Members           []int64  `json:"members"`
	WorkflowRequestID int64    `json:"workflow_request_id,omitempty"`
	ParentBranchID    int64    `json:"parent_branch_id,omitempty"`
	Coordinator       bool     `json:"coordinator,omitempty"`
}

type BranchPoolWork struct {
	ID        int64          `json:"id"`
	Spec      BranchWorkSpec `json:"spec"`
	State     string         `json:"state"`
	BranchID  int64          `json:"branch_id,omitempty"`
	CreatedBy int64          `json:"created_by"`
}

type BranchUnitSpec struct {
	Key            string   `json:"key"`
	Question       string   `json:"question"`
	Role           string   `json:"role"`
	AssetIDs       []string `json:"asset_ids"`
	MaterialHashes []string `json:"material_hashes"`
	Capabilities   []string `json:"capabilities"`
	// Exact WorkContract JSON is retained rather than flattening its semantics.
	Contract     json.RawMessage     `json:"contract"`
	DependsOn    []int64             `json:"depends_on"`
	Runtime      *RuntimeBinding     `json:"runtime,omitempty"`
	EvidenceRefs []BranchEvidenceRef `json:"evidence_refs,omitempty"`
	Supersedes   int64               `json:"supersedes,omitempty"`
}

type BranchEvidenceRef struct {
	BranchID int64  `json:"branch_id"`
	UnitID   int64  `json:"unit_id"`
	Version  string `json:"version"`
}

type BranchUnit struct {
	ID              int64            `json:"id"`
	Spec            BranchUnitSpec   `json:"spec"`
	State           string           `json:"state"`
	Attempt         int64            `json:"attempt"`
	Result          *ExecutionResult `json:"result,omitempty"`
	EvidenceVersion string           `json:"evidence_version,omitempty"`
}

type BranchOperation struct {
	ID        string `json:"id"`
	Epoch     int64  `json:"epoch"`
	UnitID    int64  `json:"unit_id"`
	Kind      string `json:"kind"`
	Role      string `json:"role"`
	Tool      string `json:"tool,omitempty"`
	InputHash string `json:"input_hash"`
	State     string `json:"state"`
}

type BranchGuidance struct {
	ID       int64  `json:"id"`
	MemberID int64  `json:"member_id"`
	Text     string `json:"text"`
	Status   string `json:"status"`
	Epoch    int64  `json:"epoch"`
}

type ExecutionBranch struct {
	ID              int64             `json:"id"`
	WorkID          int64             `json:"work_id"`
	TeamID          int64             `json:"team_id"`
	TaskID          int64             `json:"task_id"`
	Spec            BranchWorkSpec    `json:"spec"`
	OwnerID         int64             `json:"owner_id"`
	ControlID       int64             `json:"control_id"`
	DeviceID        int64             `json:"device_id"`
	Epoch           int64             `json:"epoch"`
	Revision        int64             `json:"revision"`
	PolicyVersion   int64             `json:"policy_version"`
	State           string            `json:"state"`
	Reason          string            `json:"reason,omitempty"`
	LeaseUntil      time.Time         `json:"lease_until"`
	Spent           int64             `json:"spent"`
	PendingOwnerID  int64             `json:"pending_owner_id,omitempty"`
	PendingDeviceID int64             `json:"pending_device_id,omitempty"`
	Units           []BranchUnit      `json:"units"`
	Operations      []BranchOperation `json:"operations,omitempty"`
	Guidance        []BranchGuidance  `json:"guidance"`
	Checkpoint      string            `json:"checkpoint,omitempty"`
	Outcome         string            `json:"outcome,omitempty"`
	Summary         string            `json:"summary,omitempty"`
	Reviewers       []int64           `json:"reviewers,omitempty"`
	Contributors    []int64           `json:"contributors"`
	NodeSeq         int64             `json:"node_seq"`
}

type BranchEvent struct {
	ID        int64              `json:"id"`
	BranchID  int64              `json:"branch_id"`
	UnitID    int64              `json:"unit_id,omitempty"`
	Epoch     int64              `json:"epoch,omitempty"`
	Seq       int64              `json:"seq,omitempty"`
	Kind      string             `json:"kind"`
	Text      string             `json:"text"`
	MemberID  int64              `json:"member_id,omitempty"`
	DeviceID  int64              `json:"device_id,omitempty"`
	Evidence  *ExecutionEvidence `json:"evidence,omitempty"`
	CreatedAt time.Time          `json:"created_at"`
}

type BranchProject struct {
	TeamID      int64               `json:"team_id"`
	TaskID      int64               `json:"task_id"`
	Revision    int64               `json:"revision"`
	Cursor      int64               `json:"cursor"`
	Policy      BranchPolicy        `json:"policy"`
	State       string              `json:"state"`
	Pool        []BranchPoolWork    `json:"pool"`
	Branches    []ExecutionBranch   `json:"branches"`
	Permissions map[string][]string `json:"permissions,omitempty"`
	ClosedNote  string              `json:"closed_note,omitempty"`
	// Receipt hashes are server-private and must not appear in public snapshots.
	Receipts map[string]BranchReceipt `json:"receipts,omitempty"`
}

type BranchReceipt struct {
	Hash     string `json:"hash"`
	BranchID int64  `json:"branch_id,omitempty"`
	WorkID   int64  `json:"work_id,omitempty"`
	UnitID   int64  `json:"unit_id,omitempty"`
}

// One versioned command envelope is used by REST and the durable node outbox.
// The server has separate member/device allowlists; a device cannot send a
// management command by merely choosing its Type.
type BranchCommand struct {
	Type        string           `json:"type"`
	RequestID   string           `json:"request_id"`
	BranchID    int64            `json:"branch_id,omitempty"`
	WorkID      int64            `json:"work_id,omitempty"`
	UnitID      int64            `json:"unit_id,omitempty"`
	Epoch       int64            `json:"epoch,omitempty"`
	Revision    int64            `json:"revision,omitempty"`
	MemberID    int64            `json:"member_id,omitempty"`
	DeviceID    int64            `json:"device_id,omitempty"`
	Permission  string           `json:"permission,omitempty"`
	Revoke      bool             `json:"revoke,omitempty"`
	Text        string           `json:"text,omitempty"`
	State       string           `json:"state,omitempty"`
	Outcome     string           `json:"outcome,omitempty"`
	Work        *BranchWorkSpec  `json:"work,omitempty"`
	Unit        *BranchUnitSpec  `json:"unit,omitempty"`
	Operation   *BranchOperation `json:"operation,omitempty"`
	Result      *ExecutionResult `json:"result,omitempty"`
	Event       *BranchEvent     `json:"event,omitempty"`
	GuidanceIDs []int64          `json:"guidance_ids,omitempty"`
	Runtime     *RuntimeBinding  `json:"runtime,omitempty"`
	Policy      *BranchPolicy    `json:"policy,omitempty"`
}

type BranchReply struct {
	Branch       *ExecutionBranch  `json:"branch,omitempty"`
	Policy       BranchPolicy      `json:"policy"`
	Receipt      BranchReceipt     `json:"receipt"`
	Cursor       int64             `json:"cursor"`
	Dependencies []ExecutionBranch `json:"dependencies,omitempty"`
	Coordination *BranchSnapshot   `json:"coordination,omitempty"`
}

type BranchSnapshot struct {
	Project     BranchProject `json:"project"`
	Permissions []string      `json:"permissions"`
	Events      []BranchEvent `json:"events"`
	Cursor      int64         `json:"cursor"`
	HasMore     bool          `json:"has_more"`
}

// BranchActor is constructed by authenticated server code, never from request JSON.
type BranchActor struct {
	Admin        bool
	MemberID     int64
	DeviceID     int64
	TaskPaused   bool
	TaskTerminal bool
	Devices      map[int64]BranchDevice
}
type BranchDevice struct {
	ID               int64
	OwnerID          int64
	Active           bool
	Online           bool
	Protocol         int
	Roles            []string
	RoleCapabilities map[string][]string
	RuntimeProfiles  []RuntimeProfile
}
