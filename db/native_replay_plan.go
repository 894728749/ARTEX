package db

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// NativeReplayPlan v1 retains the bounded stdin replay contract. Version 2
// binds target/environment identity and adds attachments, file input and output assertions.
// Unknown fields are rejected rather than silently dropping replay conditions.
type NativeReplayPlan struct {
	Version        int                    `json:"version"`
	InputMode      string                 `json:"input_mode"`
	Assertion      *NativeReplayAssertion `json:"assertion,omitempty"`
	ArtifactSHA256 string                 `json:"artifact_sha256,omitempty"`
	Image          string                 `json:"image,omitempty"`
	PolicyRevision int64                  `json:"policy_revision,omitempty"`
	Target         *NativeTarget          `json:"target,omitempty"`
	ParentCaseID   int64                  `json:"parent_case_id,omitempty"`
}

type NativeArtifactBinding struct {
	ArtifactID int64  `json:"artifact_id"`
	SHA256     string `json:"sha256"`
	Name       string `json:"name,omitempty"`
}
type NativeTarget struct {
	Dependencies []NativeArtifactBinding `json:"dependencies,omitempty"`
	Loader       *NativeArtifactBinding  `json:"loader,omitempty"`
	Harness      *NativeArtifactBinding  `json:"harness,omitempty"`
}

type NativeReplayAssertion struct {
	Type       string `json:"type"`
	Value      *int   `json:"value"`
	DataBase64 string `json:"data_base64,omitempty"`
}

func (p *NativeReplayPlan) UnmarshalJSON(raw []byte) error {
	type plain NativeReplayPlan
	var decoded plain
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&decoded); err != nil {
		return fmt.Errorf("invalid replay_plan: %w", err)
	}
	*p = NativeReplayPlan(decoded)
	return nil
}

func (p *NativeReplayPlan) Validate() error {
	if p.Version != 1 && p.Version != 2 {
		return errors.New("replay_plan.version must be 1 or 2")
	}
	if p.Version == 1 && (p.ArtifactSHA256 != "" || p.Image != "" || p.PolicyRevision != 0 || p.Target != nil || p.ParentCaseID != 0) {
		return errors.New("v2 replay fields require version 2")
	}
	if p.Version == 2 {
		if !NativeSHA256(p.ArtifactSHA256) || !NativeImageDigest(p.Image) || p.PolicyRevision < 1 || p.ParentCaseID < 0 {
			return errors.New("v2 replay requires specimen hash, immutable image and current policy revision")
		}
		if p.Target != nil {
			if err := p.Target.Validate(); err != nil {
				return err
			}
		}
	}
	if p.InputMode == "" {
		p.InputMode = "stdin"
	}
	if p.InputMode != "stdin" && !(p.Version == 2 && p.InputMode == "file") {
		return errors.New("unsupported replay input mode")
	}
	if p.Target != nil && p.Target.Harness != nil && p.InputMode != "stdin" {
		return errors.New("harness supports only stdin input")
	}
	if p.Assertion == nil {
		return nil // An existing top-level exit or signal expectation is allowed.
	}
	a := p.Assertion
	if a.Type == "stdout_contains_base64" && p.Version == 2 {
		data, err := base64.StdEncoding.Strict().DecodeString(a.DataBase64)
		if err != nil || len(data) == 0 || len(data) > 65536 || a.Value != nil {
			return errors.New("output assertion requires 1..65536 bytes and no numeric value")
		}
		if p.Target != nil && p.Target.Harness != nil {
			return errors.New("harness stdout is not target impact evidence")
		}
		a.DataBase64 = base64.StdEncoding.EncodeToString(data)
		return nil
	}
	if a.DataBase64 != "" {
		return errors.New("byte assertion data requires stdout_contains_base64")
	}
	if a.Value == nil {
		return errors.New("replay_plan.assertion.value is required")
	}
	switch a.Type {
	case "exit_code":
		if *a.Value < 0 || *a.Value > 125 {
			return errors.New("replay_plan exit_code outside 0..125")
		}
	case "signal":
		if *a.Value < 1 || *a.Value > 64 {
			return errors.New("replay_plan signal outside 1..64")
		}
	default:
		return errors.New("replay_plan v1 supports only exit_code or signal assertions")
	}
	return nil
}

func NativeSHA256(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && strings.ToLower(s) == s
}
func NativeImageDigest(s string) bool {
	if strings.ContainsAny(s, " \r\n\t") {
		return false
	}
	if strings.HasPrefix(s, "sha256:") {
		return NativeSHA256(strings.TrimPrefix(s, "sha256:"))
	}
	parts := strings.Split(s, "@sha256:")
	return len(parts) == 2 && parts[0] != "" && NativeSHA256(parts[1])
}
func (t *NativeTarget) Bindings() []NativeArtifactBinding {
	if t == nil {
		return nil
	}
	out := append([]NativeArtifactBinding{}, t.Dependencies...)
	if t.Loader != nil {
		out = append(out, *t.Loader)
	}
	if t.Harness != nil {
		out = append(out, *t.Harness)
	}
	return out
}
func (t *NativeTarget) Validate() error {
	if len(t.Dependencies) > 32 {
		return errors.New("at most 32 dependencies")
	}
	seen := map[int64]bool{}
	names := map[string]bool{}
	for _, b := range t.Bindings() {
		if b.ArtifactID <= 0 || !NativeSHA256(b.SHA256) || seen[b.ArtifactID] {
			return errors.New("invalid or duplicate attachment identity")
		}
		seen[b.ArtifactID] = true
		if b.Name == "" || b.Name == "." || b.Name == ".." || len(b.Name) > 255 || strings.ContainsAny(b.Name, "/\\\x00\r\n\t") || names[b.Name] {
			return errors.New("attachment requires unique safe basename")
		}
		names[b.Name] = true
	}
	return nil
}

// ReplayExpectations translates a validated case to the existing runner
// protocol. Signal matching retains the Docker 128+signal convention; it does
// not claim a debugger-observed crash or prove exploitability.
func (c *NativeCase) ReplayExpectations() (exitCode, signal *int) {
	if c.ReplayPlan != nil && c.ReplayPlan.Assertion != nil {
		a := c.ReplayPlan.Assertion
		switch a.Type {
		case "exit_code":
			return a.Value, nil
		case "signal":
			return nil, a.Value
		}
		return nil, nil
	}
	return c.ExpectedExit, c.ExpectedSignal
}
