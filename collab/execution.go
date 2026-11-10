package collab

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ExecutionConfig is a portable, immutable role snapshot. Credentials, executable
// paths and database handles are resolved only by the receiving device.
type ExecutionConfig struct {
	Version         int             `json:"version"`
	MessageProtocol int             `json:"message_protocol,omitempty"`
	Kind            string          `json:"kind"`
	Role            string          `json:"role"`
	SystemPrompt    string          `json:"system_prompt"`
	Capabilities    []string        `json:"capabilities"`
	MaxTurns        int             `json:"max_turns"`
	BudgetSeconds   int             `json:"budget_seconds"`
	DynamicAllowed  bool            `json:"dynamic_allowed"`
	Runtime         *RuntimeBinding `json:"runtime,omitempty"`
}

// RuntimeProfile describes a device-owned environment without exposing local
// commands, paths, connection details or secrets. Digest binds its exact policy.
type RuntimeProfile struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Platform      string `json:"platform"`
	Digest        string `json:"digest"`
	MaxDurationMS int    `json:"max_duration_ms"`
}

type RuntimeBinding struct {
	RuntimeProfile
	ArtifactHashes []string `json:"artifact_hashes"`
}

func (p RuntimeProfile) Validate() error {
	b, err := hex.DecodeString(p.Digest)
	if !validCapability(p.ID) || len(p.Name) > 160 || (p.Platform != "windows" && p.Platform != "linux" && p.Platform != "android") || err != nil || len(b) != 32 || p.MaxDurationMS < 100 || p.MaxDurationMS > 60000 {
		return errors.New("invalid device runtime profile")
	}
	return nil
}

type Material struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type ExecutionInput struct {
	Version     int             `json:"version"`
	TaskName    string          `json:"task_name"`
	TaskGoal    string          `json:"task_goal"`
	Intent      string          `json:"intent"`
	Contract    json.RawMessage `json:"contract"`
	Acceptance  json.RawMessage `json:"acceptance"`
	Constraints json.RawMessage `json:"constraints"`
	Context     string          `json:"context"`
	Materials   []Material      `json:"materials"`
}

type Assignment struct {
	ID         int64           `json:"id"`
	TaskID     int64           `json:"task_id"`
	IntentID   int64           `json:"intent_id"`
	DeviceID   int64           `json:"device_id"`
	MemberID   int64           `json:"member_id"`
	Epoch      int64           `json:"epoch"`
	Attempt    int64           `json:"attempt"`
	State      string          `json:"state"`
	LeaseUntil time.Time       `json:"lease_until"`
	Config     ExecutionConfig `json:"config_snapshot"`
	Input      ExecutionInput  `json:"input_snapshot"`
}

type ExecutionEvidence struct {
	ID        string          `json:"id"`
	Tool      string          `json:"tool"`
	SHA256    string          `json:"sha256"`
	Content   string          `json:"content"`
	IsError   bool            `json:"is_error"`
	Input     json.RawMessage `json:"input,omitempty"`
	Truncated bool            `json:"truncated,omitempty"`
}

type ExecutionResult struct {
	Version    int                 `json:"version"`
	Outcome    string              `json:"outcome"`
	Summary    string              `json:"summary"`
	Checkpoint string              `json:"checkpoint,omitempty"`
	Role       string              `json:"role"`
	Model      string              `json:"model"`
	Evidence   []ExecutionEvidence `json:"evidence"`
}

func ContentHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func (c ExecutionConfig) Validate() error {
	validRole := c.Kind == "pentest" && c.Role == "worker" || c.Kind == "reverse" && (c.Role == "reverse_static" || c.Role == "reverse_dynamic" || c.Role == "reverse_reviewer")
	if c.Version != 1 || (c.MessageProtocol != 0 && c.MessageProtocol != 1) || !validRole || len(c.SystemPrompt) > 128<<10 || c.MaxTurns < 1 || c.MaxTurns > 64 || c.BudgetSeconds < 10 || c.BudgetSeconds > 7200 || len(c.Capabilities) > 32 {
		return errors.New("invalid portable execution configuration")
	}
	if c.Role == "reverse_dynamic" && !c.DynamicAllowed {
		return errors.New("dynamic observation is not authorized for this task")
	}
	if c.Role == "reverse_dynamic" {
		if c.Runtime == nil || c.Runtime.Validate() != nil || len(c.Runtime.ArtifactHashes) == 0 || len(c.Runtime.ArtifactHashes) > 16 {
			return errors.New("dynamic runtime and materials must be explicitly bound")
		}
		seenHashes := map[string]bool{}
		for _, h := range c.Runtime.ArtifactHashes {
			b, e := hex.DecodeString(h)
			if e != nil || len(b) != 32 || seenHashes[h] {
				return errors.New("invalid runtime material binding")
			}
			seenHashes[h] = true
		}
	} else if c.Runtime != nil || c.DynamicAllowed {
		return errors.New("runtime authorization belongs only to the dynamic role")
	}
	seen := map[string]bool{}
	for _, name := range c.Capabilities {
		if !validCapability(name) || seen[name] {
			return errors.New("invalid or duplicate capability")
		}
		seen[name] = true
	}
	return nil
}

func validCapability(s string) bool {
	if len(s) < 1 || len(s) > 80 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func (r ExecutionResult) Validate(c ExecutionConfig) error {
	if r.Version != 1 || r.Role != c.Role || strings.TrimSpace(r.Summary) == "" || len(r.Summary) > 64<<10 || len(r.Checkpoint) > 64<<10 || len(r.Model) > 256 || len(r.Evidence) > 128 {
		return errors.New("invalid execution result")
	}
	if r.Outcome != "candidate" && r.Outcome != "blocked" && r.Outcome != "failed" {
		return errors.New("device results cannot directly accept conclusions")
	}
	seen := map[string]bool{}
	allowed := map[string]bool{"read_material": true}
	if c.Role == "reverse_dynamic" && c.DynamicAllowed {
		allowed["reverse_observe_runtime"] = true
	}
	for _, name := range c.Capabilities {
		allowed[name] = true
	}
	for _, e := range r.Evidence {
		if !validCapability(e.ID) || seen[e.ID] || !allowed[e.Tool] || len(e.Content) > 64<<10 || len(e.Input) > 64<<10 || (len(e.Input) > 0 && !json.Valid(e.Input)) || e.SHA256 != ContentHash([]byte(e.Content)) {
			return fmt.Errorf("invalid evidence receipt: %s", e.ID)
		}
		seen[e.ID] = true
	}
	b, err := json.Marshal(r)
	if err != nil || len(b) > 900<<10 {
		return errors.New("result exceeds durable receipt limit")
	}
	return nil
}

func (a Assignment) Validate() error {
	if a.ID < 1 || a.TaskID < 1 || a.IntentID < 1 || a.Epoch < 1 || a.Input.Version != 1 || strings.TrimSpace(a.Input.Intent) == "" || len(a.Input.Materials) > 16 {
		return errors.New("invalid assignment")
	}
	if err := a.Config.Validate(); err != nil {
		return err
	}
	seen := map[string]bool{}
	var total int64
	for _, m := range a.Input.Materials {
		b, e := hex.DecodeString(m.SHA256)
		if e != nil || len(b) != 32 || m.ID != m.SHA256 || seen[m.ID] || m.Size < 0 || m.Size > 256<<20 || len(m.Name) > 256 {
			return errors.New("invalid input material")
		}
		seen[m.ID] = true
		total += m.Size
	}
	if total > 512<<20 {
		return errors.New("input material budget exceeded")
	}
	if a.Config.Runtime != nil {
		for _, h := range a.Config.Runtime.ArtifactHashes {
			if !seen[h] {
				return errors.New("runtime material missing from assignment")
			}
		}
	}
	return nil
}
