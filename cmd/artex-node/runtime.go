package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/Autumn-27/artex/collab"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

const reverseRuntimeCapability = "reverse_observe_runtime"
const maxRuntimeBridgeOutput = 3 << 20

// All fields are device-local. The digest covers this value together with its
// map key (ID), including the command, arguments, settings and env allowlist.
type localRuntimeProfile struct {
	Name          string         `json:"name"`
	Platform      string         `json:"platform"`
	Command       string         `json:"command"`
	Args          []string       `json:"args"`
	Settings      map[string]any `json:"settings"`
	EnvAllowlist  []string       `json:"env_allowlist"`
	MaxDurationMS int            `json:"max_duration_ms"`
}

func (c localExecutionConfig) runtimeProfile(id string) (collab.RuntimeProfile, error) {
	p, ok := c.RuntimeProfiles[id]
	if !ok {
		return collab.RuntimeProfile{}, fmt.Errorf("runtime profile %q is not configured", id)
	}
	canonical, err := json.Marshal(struct {
		ID      string              `json:"id"`
		Profile localRuntimeProfile `json:"profile"`
	}{id, p})
	if err != nil {
		return collab.RuntimeProfile{}, err
	}
	h := sha256.Sum256(canonical)
	out := collab.RuntimeProfile{ID: id, Name: p.Name, Platform: p.Platform, Digest: hex.EncodeToString(h[:]), MaxDurationMS: p.MaxDurationMS}
	if err := out.Validate(); err != nil {
		return collab.RuntimeProfile{}, err
	}
	return out, nil
}

func (c localExecutionConfig) matchRuntimeBinding(config collab.ExecutionConfig, materials []collab.Material) (localRuntimeProfile, error) {
	if config.Runtime == nil {
		return localRuntimeProfile{}, errors.New("dynamic runtime binding is missing")
	}
	binding := config.Runtime
	if err := binding.RuntimeProfile.Validate(); err != nil {
		return localRuntimeProfile{}, err
	}
	role, ok := c.Roles["reverse_dynamic"]
	if !ok || !containsString(role.RuntimeProfiles, binding.ID) {
		return localRuntimeProfile{}, errors.New("runtime profile is not authorized for this device role")
	}
	local, err := c.runtimeProfile(binding.ID)
	if err != nil {
		return localRuntimeProfile{}, err
	}
	if local != binding.RuntimeProfile {
		return localRuntimeProfile{}, errors.New("runtime profile binding does not match the configured device profile")
	}
	allowedMaterials := map[string]bool{}
	for _, m := range materials {
		allowedMaterials[m.SHA256] = true
	}
	for _, h := range binding.ArtifactHashes {
		if !allowedMaterials[h] {
			return localRuntimeProfile{}, errors.New("runtime binding references a material outside the assignment")
		}
	}
	if len(binding.ArtifactHashes) == 0 {
		return localRuntimeProfile{}, errors.New("runtime binding contains no authorized materials")
	}
	return c.RuntimeProfiles[binding.ID], nil
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func runtimeMaterialAllowed(binding collab.RuntimeBinding, files map[string]string, hash string) (string, error) {
	if !containsString(binding.ArtifactHashes, hash) {
		return "", errors.New("material hash is not authorized by this runtime binding")
	}
	path, ok := files[hash]
	if !ok {
		return "", errors.New("authorized material is not available")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("authorized material is unavailable")
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	closeErr := f.Close()
	if err != nil || closeErr != nil || hex.EncodeToString(h.Sum(nil)) != hash {
		return "", errors.New("material hash verification failed immediately before observation")
	}
	return path, nil
}

type runtimeObservationRequest struct {
	Operation    string         `json:"operation"`
	Profile      map[string]any `json:"profile"`
	ArtifactPath string         `json:"artifact_path"`
	SHA256       string         `json:"sha256"`
	Script       string         `json:"script"`
	Argv         []string       `json:"argv"`
	PackageName  string         `json:"package_name"`
	DurationMS   int            `json:"duration_ms"`
}

func invokeNodeRuntime(ctx context.Context, p localRuntimeProfile, req runtimeObservationRequest) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	command := exec.Command(p.Command, p.Args...)
	command.Env = []string{}
	for _, key := range p.EnvAllowlist {
		if value, ok := os.LookupEnv(key); ok {
			command.Env = append(command.Env, key+"="+value)
		}
	}
	command.Stderr = io.Discard
	in, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := command.StdoutPipe()
	if err != nil {
		in.Close()
		return nil, err
	}
	if err = command.Start(); err != nil {
		in.Close()
		return nil, errors.New("runtime bridge could not be started")
	}
	profileSettings := map[string]any{}
	for k, v := range p.Settings {
		profileSettings[k] = v
	}
	profileSettings["platform"] = p.Platform
	req.Operation = "observe"
	req.Profile = profileSettings
	if err = json.NewEncoder(in).Encode(req); err != nil {
		_ = command.Process.Kill()
		_ = in.Close()
		_ = command.Wait()
		return nil, errors.New("runtime bridge request could not be sent")
	}
	type answer struct {
		raw      []byte
		err      error
		tooLarge bool
	}
	done := make(chan answer, 1)
	go func() {
		raw, readErr := io.ReadAll(io.LimitReader(out, maxRuntimeBridgeOutput+1))
		large := len(raw) > maxRuntimeBridgeOutput
		if large {
			_, _ = io.WriteString(in, "{\"cancel\":true}\n")
			_ = in.Close()
			_ = command.Process.Kill()
		}
		waitErr := command.Wait()
		if readErr == nil {
			readErr = waitErr
		}
		done <- answer{raw: raw, err: readErr, tooLarge: large}
	}()
	select {
	case result := <-done:
		if result.tooLarge {
			return result.raw, errors.New("runtime bridge output exceeded the evidence limit")
		}
		if result.err != nil {
			return result.raw, errors.New("runtime bridge did not complete cleanly")
		}
		if !json.Valid(bytes.TrimSpace(result.raw)) {
			return result.raw, errors.New("runtime bridge returned invalid JSON")
		}
		return bytes.TrimSpace(result.raw), nil
	case <-ctx.Done():
		_, _ = io.WriteString(in, "{\"cancel\":true}\n")
		_ = in.Close()
		timer := time.NewTimer(8 * time.Second)
		defer timer.Stop()
		select {
		case result := <-done:
			return result.raw, ctx.Err()
		case <-timer.C:
			_ = command.Process.Kill()
			result := <-done
			return result.raw, fmt.Errorf("runtime bridge cancellation exceeded cleanup bound: %w", ctx.Err())
		}
	}
}

func validateRuntimeObservation(raw []byte, platform, artifactHash, script string) error {
	var observation map[string]any
	if err := json.Unmarshal(raw, &observation); err != nil {
		return errors.New("runtime bridge returned no structured observation")
	}
	if observation["error"] != nil || observation["platform"] != platform || observation["artifact_sha256"] != artifactHash {
		return errors.New("runtime observation identity or execution failed")
	}
	scriptHash := sha256.Sum256([]byte(script))
	if observation["script_sha256"] != hex.EncodeToString(scriptHash[:]) {
		return errors.New("runtime observation script digest mismatch")
	}
	cleanup, _ := observation["cleanup"].(map[string]any)
	for _, field := range []string{"script_unloaded", "session_detached", "owned_process_terminated", "staging_removed"} {
		if cleanup[field] != true {
			return fmt.Errorf("runtime cleanup was not confirmed: %s", field)
		}
	}
	if platform == "android" && cleanup["package_removed"] != true {
		return errors.New("runtime package cleanup was not confirmed")
	}
	if failures, ok := observation["errors"].([]any); ok && len(failures) > 0 {
		return errors.New("runtime bridge reported execution or cleanup errors")
	}
	return nil
}

func reverseObserveRuntimeTool(p localRuntimeProfile, binding collab.RuntimeBinding, files map[string]string, evidence *nodeEvidence, gate func(context.Context) error) actool.CoreTool {
	schema := map[string]any{"type": "object", "properties": map[string]any{
		"sha256": map[string]any{"type": "string"}, "script": map[string]any{"type": "string"},
		"argv":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"package_name": map[string]any{"type": "string"}, "duration_ms": map[string]any{"type": "integer", "minimum": 100, "maximum": p.MaxDurationMS},
	}, "required": []string{"sha256", "script", "duration_ms"}, "additionalProperties": false}
	return actool.Build(actool.Spec{Name: reverseRuntimeCapability, Description: "Observe only a hash-bound task material in the explicitly authorized local runtime profile; the node owns and cleans up only the process it starts.", Schema: schema, RawInput: true, ReadOnly: func(json.RawMessage) bool { return false }, Concurrent: func(json.RawMessage) bool { return false }, Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
		return permission.Allowed()
	}, Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
		if err := gate(ctx); err != nil {
			if json.Valid(input) && len(input) <= 64<<10 {
				evidence.add(reverseRuntimeCapability, input, "fresh assignment heartbeat failed before runtime validation", true, false)
			}
			return actool.Errorf("fresh assignment heartbeat failed before runtime observation"), nil
		}
		if err := evidence.canStart(input); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		if err := evidence.beginTool(); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		defer evidence.endTool()
		var request struct {
			SHA256      string   `json:"sha256"`
			Script      string   `json:"script"`
			Argv        []string `json:"argv"`
			PackageName string   `json:"package_name"`
			DurationMS  int      `json:"duration_ms"`
		}
		fail := func(err error) (actool.Result, error) {
			evidence.add(reverseRuntimeCapability, input, err.Error(), true, false)
			return actool.Errorf(err.Error()), nil
		}
		decoder := json.NewDecoder(bytes.NewReader(input))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			return fail(errors.New("invalid runtime observation request"))
		}
		if decoder.Decode(&struct{}{}) != io.EOF {
			return fail(errors.New("invalid runtime observation request"))
		}
		if len(request.Script) == 0 || len(request.Script) > 128<<10 || strings.TrimSpace(request.Script) == "" {
			return fail(errors.New("runtime script must be nonempty and at most 128 KiB"))
		}
		if len(request.Argv) > 64 {
			return fail(errors.New("runtime argv exceeds the item limit"))
		}
		for _, arg := range request.Argv {
			if strings.ContainsRune(arg, 0) || len(arg) > 4096 {
				return fail(errors.New("runtime argv contains an invalid value"))
			}
		}
		if request.DurationMS < 100 || request.DurationMS > p.MaxDurationMS {
			return fail(errors.New("runtime duration exceeds the bound device profile"))
		}
		if p.Platform == "android" && (len(request.PackageName) > 255 || !androidPackagePattern.MatchString(request.PackageName)) {
			return fail(errors.New("Android observation requires an exact package name"))
		}
		artifactPath, err := runtimeMaterialAllowed(binding, files, request.SHA256)
		if err != nil {
			return fail(err)
		}
		if err = gate(ctx); err != nil {
			return fail(errors.New("fresh assignment heartbeat failed before runtime launch"))
		}
		runCtx, cancel := context.WithTimeout(ctx, time.Duration(request.DurationMS)*time.Millisecond+10*time.Second)
		defer cancel()
		bridgeRequest := runtimeObservationRequest{ArtifactPath: artifactPath, SHA256: request.SHA256, Script: request.Script, Argv: request.Argv, PackageName: request.PackageName, DurationMS: request.DurationMS}
		raw, runErr := invokeNodeRuntime(runCtx, p, bridgeRequest)
		if runErr == nil {
			runErr = validateRuntimeObservation(raw, p.Platform, request.SHA256, request.Script)
		} else if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) { // keep returned cleanup evidence, but classify cancellation as an error
		}
		content := string(raw)
		if content == "" {
			content = `{"error":"runtime bridge failed before returning evidence"}`
		}
		if runErr != nil {
			content += "\nnode_error: " + runErr.Error()
		}
		evidence.add(reverseRuntimeCapability, input, content, runErr != nil, len(content) > 64<<10)
		if runErr != nil {
			return actool.Errorf("runtime observation failed; durable evidence includes bridge output and cleanup state"), nil
		}
		return actool.Text(content), nil
	}})
}

var androidPackagePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$`)
