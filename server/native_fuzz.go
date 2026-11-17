package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

const (
	maxFuzzRequest       = 256 << 10
	maxFuzzObservation   = 256 << 10
	maxFuzzEvidence      = 256 << 10
	maxFuzzEvidenceFile  = maxFuzzEvidence + (8 << 10) // observation + bounded envelope
	fuzzOutputDiskLimit  = 64 << 20
	fuzzCorpusTotalBytes = 65536
)

var errFuzzEvidenceLimit = errors.New("fuzz evidence exceeds size limit")

// Synchronous, bounded campaigns only. AFL statistics and crashes are candidates,
// never findings. No background recovery queue or per-mutation database writes.
type nativeFuzzInput struct {
	SHA256     string `json:"sha256"`
	DataBase64 string `json:"data_base64"`
}
type nativeFuzzRequest struct {
	Action          string            `json:"action"`
	ArtifactID      int64             `json:"artifact_id"`
	ProfileID       string            `json:"profile_id"`
	Argv            []string          `json:"argv"`
	InputMode       string            `json:"input_mode"`
	Duration        int               `json:"duration_ms"`
	Seeds           []nativeFuzzInput `json:"seeds"`
	MaxExecutions   int               `json:"max_executions"`
	MaxCrashes      int               `json:"max_crashes"`
	RunID           int64             `json:"run_id"`
	CandidateSHA256 string            `json:"candidate_sha256"`
	ExpectedSignal  *int              `json:"expected_signal"`
}

var fuzzRunFields = map[string]bool{"action": true, "artifact_id": true, "profile_id": true,
	"argv": true, "input_mode": true, "duration_ms": true, "seeds": true,
	"max_executions": true, "max_crashes": true}
var fuzzImportFields = map[string]bool{"action": true, "run_id": true,
	"candidate_sha256": true, "expected_signal": true}
var fuzzReplayFields = map[string]bool{"action": true, "run_id": true,
	"candidate_sha256": true, "expected_signal": true, "duration_ms": true}

func decodeFuzzInput(in nativeFuzzInput, allowEmpty bool) ([]byte, error) {
	if len(in.DataBase64) > 5464 {
		return nil, errors.New("fuzz input exceeds 4096 bytes")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(in.DataBase64)
	if err != nil || len(data) > 4096 || base64.StdEncoding.EncodeToString(data) != in.DataBase64 {
		return nil, errors.New("invalid fuzz input encoding/size")
	}
	if !allowEmpty && len(data) == 0 {
		return nil, errors.New("fuzz seed must not be empty")
	}
	sum := sha256.Sum256(data)
	if in.SHA256 != hex.EncodeToString(sum[:]) {
		return nil, errors.New("fuzz input SHA256 mismatch")
	}
	return data, nil
}

func validateFuzzInputs(inputs []nativeFuzzInput, count, totalLimit int, allowEmpty bool) error {
	if len(inputs) > count {
		return errors.New("too many fuzz inputs")
	}
	total := 0
	for _, in := range inputs {
		data, err := decodeFuzzInput(in, allowEmpty)
		if err != nil {
			return err
		}
		total += len(data)
	}
	if total > totalLimit {
		return errors.New("fuzz input total exceeds limit")
	}
	return nil
}

func validateFuzzRequest(r *nativeFuzzRequest) error {
	if r.Duration < 1000 || r.Duration > 60000 || r.MaxExecutions < 100 || r.MaxExecutions > 1000000 || r.MaxCrashes < 1 || r.MaxCrashes > 8 {
		return errors.New("invalid fuzz duration/execution/crash budget")
	}
	if r.InputMode != "stdin" && r.InputMode != "file" {
		return errors.New("input_mode must be stdin or file")
	}
	if r.Argv == nil {
		r.Argv = []string{}
	}
	if len(r.Argv) > 64 {
		return errors.New("too many argv")
	}
	placeholders := 0
	for _, s := range r.Argv {
		if len(s) > 4096 || strings.ContainsRune(s, 0) || strings.Contains(s, "@@") {
			return errors.New("invalid argv")
		}
		if strings.Contains(s, "{input}") && s != "{input}" {
			return errors.New("input placeholder must be a whole argument")
		}
		if s == "{input}" {
			placeholders++
		}
	}
	if r.InputMode == "file" && placeholders != 1 {
		return errors.New("file mode requires exactly one {input} argv")
	}
	if r.InputMode == "stdin" && placeholders != 0 {
		return errors.New("stdin mode cannot use {input}")
	}
	if len(r.Seeds) == 0 || len(r.Seeds) > 32 {
		return errors.New("1..32 seeds are required")
	}
	return validateFuzzInputs(r.Seeds, 32, fuzzCorpusTotalBytes, false)
}

func validateFuzzActionFields(raw []byte) (string, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return "", errors.New("fuzz request must be a JSON object")
	}
	var action string
	if err := json.Unmarshal(fields["action"], &action); err != nil {
		return "", errors.New("action is required")
	}
	var allowed map[string]bool
	switch action {
	case "run":
		allowed = fuzzRunFields
	case "list":
		allowed = map[string]bool{"action": true}
	case "import_candidate":
		allowed = fuzzImportFields
	case "replay_candidate":
		allowed = fuzzReplayFields
	default:
		return "", errors.New("unknown native_fuzz action")
	}
	for key := range fields {
		if !allowed[key] {
			return "", fmt.Errorf("field %q is not allowed for action %s", key, action)
		}
	}
	return action, nil
}

var fuzzProfileFields = map[string]bool{"image": true, "fuzz_enabled": true, "enabled": true,
	"max_duration_ms": true, "platform": true, "network": true, "read_only_root": true,
	"seccomp_profile": true, "max_stream_bytes": true, "max_io_bytes": true, "name": true}

func validateFuzzProfile(p reverseRuntimeProfile) (int, error) {
	if p.Platform != "linux" || p.Engine != "docker-native" {
		return 0, errors.New("fuzz requires a linux docker-native profile")
	}
	for key := range p.Settings {
		if !fuzzProfileFields[key] {
			return 0, fmt.Errorf("unsupported fuzz profile setting %q", key)
		}
	}
	if p.Settings["fuzz_enabled"] != true {
		return 0, errors.New("fuzz disabled: profile.settings.fuzz_enabled must be true")
	}
	if p.Settings["enabled"] == false {
		return 0, errors.New("native profile is disabled")
	}
	image, ok := p.Settings["image"].(string)
	if !ok || !db.NativeImageDigest(image) {
		return 0, errors.New("immutable fuzz image required")
	}
	if platform, ok := p.Settings["platform"].(string); ok && platform != "linux" {
		return 0, errors.New("fuzz requires linux")
	}
	if network, ok := p.Settings["network"].(string); ok && network != "none" {
		return 0, errors.New("fuzz profile cannot request a network")
	}
	if ror, ok := p.Settings["read_only_root"].(bool); ok && !ror {
		return 0, errors.New("fuzz root filesystem must be read-only")
	}
	maximum := 60000
	if raw, ok := p.Settings["max_duration_ms"]; ok {
		value, ok := fuzzInt64(raw)
		if !ok || value < 1000 || value > 900000 {
			return 0, errors.New("invalid profile max_duration_ms")
		}
		if value < int64(maximum) {
			maximum = int(value)
		}
	}
	return maximum, nil
}

func fuzzInt64(v any) (int64, bool) {
	switch value := v.(type) {
	case float64:
		if math.IsNaN(value) || math.IsInf(value, 0) || value != math.Trunc(value) || value < 0 || value > 1e15 {
			return 0, false
		}
		return int64(value), true
	case int:
		if value < 0 {
			return 0, false
		}
		return int64(value), true
	case int64:
		if value < 0 {
			return 0, false
		}
		return value, true
	}
	return 0, false
}

func fuzzInt(v any) (int64, bool) {
	return fuzzInt64(v)
}

func fuzzObservation(o map[string]any, hash, image string, maxCrashes int) error {
	allowed := map[string]bool{"engine": true, "target_state": true, "manifest": true,
		"stats": true, "corpus": true, "crashes": true, "cleanup": true, "errors": true,
		"stats_trusted": true, "coverage_claimed": true, "candidate_status": true,
		"truncated": true, "limited": true, "reason": true, "cleanup_verified": true,
		"fuzz_request": true, "profile_id": true, "artifact_sha256": true, "image": true,
		"policy_revision": true, "candidate_only": true, "validated_campaign": true,
		"authority": true}
	for key := range o {
		if !allowed[key] {
			return fmt.Errorf("unsupported fuzz observation field %q", key)
		}
	}
	if o["engine"] != "afl++" {
		return errors.New("fuzz engine identity mismatch")
	}
	m, ok := o["manifest"].(map[string]any)
	if !ok {
		return errors.New("fuzz manifest missing")
	}
	manifestFields := map[string]bool{"engine": true, "artifact_sha256": true,
		"image": true, "input_mode": true, "afl_version": true, "showmap_version": true,
		"options_verified": true, "probe_edges": true, "probe_executions": true,
		"output_disk_limit_bytes": true, "single_worker": true}
	for key := range m {
		if !manifestFields[key] {
			return fmt.Errorf("unsupported fuzz manifest field %q", key)
		}
	}
	if m["engine"] != "afl++" || m["artifact_sha256"] != hash || m["image"] != image {
		return errors.New("fuzz manifest identity mismatch")
	}
	switch o["target_state"] {
	case "completed", "failed", "cancelled", "timeout":
	default:
		return errors.New("invalid fuzz target state")
	}
	for _, key := range []string{"input_mode", "afl_version", "showmap_version"} {
		if s, ok := m[key].(string); !ok || s == "" {
			return fmt.Errorf("fuzz manifest %s missing", key)
		}
	}
	if m["options_verified"] != true || m["single_worker"] != true {
		return errors.New("fuzz manifest did not verify bounded AFL options")
	}
	edges, ok := fuzzInt(m["probe_edges"])
	if !ok || edges < 1 {
		return errors.New("fuzz manifest lacks independent instrumentation edges")
	}
	probeExecs, ok := fuzzInt(m["probe_executions"])
	if !ok || probeExecs != 1 {
		return errors.New("fuzz manifest probe budget mismatch")
	}
	disk, ok := fuzzInt(m["output_disk_limit_bytes"])
	if !ok || disk < 1 || disk > fuzzOutputDiskLimit {
		return errors.New("fuzz manifest output disk limit is invalid")
	}
	cleanup, ok := o["cleanup"].(map[string]any)
	if !ok || len(cleanup) != 3 {
		return errors.New("fuzz cleanup missing")
	}
	for _, key := range []string{"owned_process_terminated", "container_removed", "staging_removed"} {
		if cleanup[key] != true {
			return errors.New("fuzz cleanup unconfirmed")
		}
	}
	if o["cleanup_verified"] != true {
		return errors.New("fuzz cleanup was not verified")
	}
	if o["stats_trusted"] != false || o["coverage_claimed"] != false {
		return errors.New("fuzz statistics must not be treated as trusted coverage")
	}
	if o["candidate_status"] != "unverified_requires_replay" {
		return errors.New("invalid fuzz candidate status")
	}
	if _, ok := o["truncated"].(bool); !ok {
		return errors.New("invalid fuzz truncation flag")
	}
	if _, ok := o["limited"].(bool); !ok {
		return errors.New("invalid fuzz limited flag")
	}
	if reason, ok := o["reason"]; ok && reason != nil {
		if s, ok := reason.(string); !ok || len(s) > 512 {
			return errors.New("invalid fuzz reason")
		}
	}
	errs, ok := o["errors"].([]any)
	if !ok || len(errs) > 8 {
		return errors.New("invalid fuzz errors")
	}
	for _, item := range errs {
		if s, ok := item.(string); !ok || len(s) > 512 {
			return errors.New("invalid fuzz error entry")
		}
	}
	if len(errs) > 0 {
		return errors.New("fuzz runner reported errors")
	}
	stats, ok := o["stats"].(map[string]any)
	if !ok {
		return errors.New("invalid fuzz stats")
	}
	statFields := map[string]bool{"execs_done": true, "saved_crashes": true,
		"saved_hangs": true, "corpus_count": true, "edges_found": true, "total_edges": true}
	for key, raw := range stats {
		if !statFields[key] {
			return errors.New("unsupported fuzz statistic")
		}
		if _, ok := fuzzInt(raw); !ok {
			return errors.New("invalid fuzz statistic value")
		}
	}
	corpus, err := fuzzObservationInputs(o["corpus"], 32, fuzzCorpusTotalBytes, false)
	if err != nil {
		return err
	}
	if _, err = fuzzObservationInputs(o["crashes"], maxCrashes, maxCrashes*4096, true); err != nil {
		return err
	}
	if o["target_state"] == "completed" && len(corpus) == 0 {
		return errors.New("completed fuzz campaign has no corpus evidence")
	}
	if o["target_state"] == "failed" {
		return errors.New("fuzz campaign failed")
	}
	return nil
}

func fuzzObservationInputs(raw any, max, total int, allowEmpty bool) ([]nativeFuzzInput, error) {
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var inputs []nativeFuzzInput
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if bytes.Equal(data, []byte("null")) || dec.Decode(&inputs) != nil {
		return nil, errors.New("invalid fuzz input list")
	}
	if len(inputs) == 0 {
		return inputs, nil
	}
	if err := validateFuzzInputs(inputs, max, total, allowEmpty); err != nil {
		return nil, err
	}
	return inputs, nil
}

// encodeFuzzEvidence measures the complete request+observation document. The
// limit is checked before any evidence file or ledger row is written.
func encodeFuzzEvidence(o map[string]any) ([]byte, error) {
	raw, err := json.Marshal(o)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxFuzzEvidence {
		return nil, errFuzzEvidenceLimit
	}
	return raw, nil
}

// compactFuzzFailure drops untrusted large request/corpus payloads so a failed
// campaign still has one bounded, ledger-matching evidence document.
func compactFuzzFailure(o map[string]any, reason string) map[string]any {
	if len(reason) > 512 {
		reason = reason[:512]
	}
	manifest, _ := o["manifest"].(map[string]any)
	if manifest == nil {
		manifest = map[string]any{"engine": "afl++"}
	}
	cleanup, _ := o["cleanup"].(map[string]any)
	if cleanup == nil {
		cleanup = map[string]any{"owned_process_terminated": false,
			"container_removed": false, "staging_removed": false}
	}
	verified, _ := o["cleanup_verified"].(bool)
	return map[string]any{
		"engine": "afl++", "target_state": "failed", "manifest": manifest,
		"stats": map[string]any{}, "corpus": []nativeFuzzInput{},
		"crashes": []nativeFuzzInput{}, "cleanup": cleanup,
		"cleanup_verified": verified, "errors": []string{reason},
		"stats_trusted": false, "coverage_claimed": false,
		"candidate_status": "unverified_requires_replay",
		"truncated":        true, "limited": true, "reason": "evidence_limit",
		"validated_campaign": false, "profile_id": o["profile_id"],
		"artifact_sha256": o["artifact_sha256"], "image": o["image"],
		"policy_revision": o["policy_revision"], "candidate_only": true,
		"authority": "candidate-only",
	}
}

func hasString(items []string, wanted string) bool {
	for _, item := range items {
		if item == wanted {
			return true
		}
	}
	return false
}

func hasInt64(items []int64, wanted int64) bool {
	for _, item := range items {
		if item == wanted {
			return true
		}
	}
	return false
}

func nativeFuzzRun(ctx context.Context, pg *db.DB, task *db.Task, info agent.RunInfo, dir string, r nativeFuzzRequest) (map[string]any, error) {
	if err := validateFuzzRequest(&r); err != nil {
		return nil, err
	}
	p, err := nativeProfile(r.ProfileID)
	if err != nil {
		return nil, err
	}
	profileMax, err := validateFuzzProfile(p)
	if err != nil {
		return nil, err
	}
	if r.Duration > profileMax {
		return nil, errors.New("duration exceeds profile limit")
	}
	image, _ := p.Settings["image"].(string)
	a, err := nativeArtifact(pg, task.ID, r.ArtifactID, dir)
	if err != nil {
		return nil, err
	}
	if _, err = inspectNativeELF(a.Path); err != nil {
		return nil, err
	}
	policy, err := pg.ReverseRuntimePolicy(task.ID)
	if err != nil {
		return nil, err
	}
	if !policy.Enabled || !hasString(policy.ProfileIDs, p.ID) || !hasInt64(policy.ArtifactIDs, a.ID) {
		return nil, errors.New("fuzz profile or artifact is outside runtime authorization")
	}
	if r.Duration > policy.MaxDurationMS {
		return nil, errors.New("duration exceeds runtime policy")
	}
	cfg, err := pg.NativeConfig(task.ID)
	if err != nil {
		return nil, err
	}
	runID, err := pg.BeginNativeRuntimeRun(ctx, task.ID, a.ID, info.IntentID, p.ID, r.Duration, nil, policy.Revision)
	if err != nil {
		return nil, err
	}
	status, path, message := "failed", "", "fuzz incomplete"
	defer func() { _ = pg.FinishReverseRuntimeRun(runID, status, path, message) }()
	if err = pg.BeginNativeRun(ctx, db.NativeRun{RunID: runID, TaskID: task.ID, ArtifactID: a.ID, IntentID: info.IntentID, ConfigRevision: cfg.Revision, Mode: "fuzz"}); err != nil {
		return nil, err
	}
	nativeStarted, nativeFinished := true, false
	defer func() {
		if nativeStarted && !nativeFinished {
			record, _ := json.Marshal(map[string]any{"target_state": "failed", "error": "native fuzz did not finish"})
			_ = pg.FinishNativeRun(runID, "failed", path, record)
		}
	}()
	pc, stopPolicy := nativePolicyContext(ctx, pg, task.ID, policy.Revision)
	defer stopPolicy()
	rc, stop := context.WithTimeout(pc, time.Duration(r.Duration)*time.Millisecond+30*time.Second)
	defer stop()
	raw, runErr := invokeReverseRuntime(rc, p, map[string]any{
		"operation": "fuzz", "request_id": fmt.Sprintf("fuzz-%d", runID),
		"artifact_path": nativeMappedPath(a.Path, p), "sha256": a.SHA256,
		"argv": r.Argv, "input_mode": r.InputMode, "duration_ms": r.Duration,
		"seeds": r.Seeds, "max_executions": r.MaxExecutions, "max_crashes": r.MaxCrashes})
	var frame reverseSessionFrame
	if len(raw) > maxFuzzObservation || json.Unmarshal(raw, &frame) != nil || frame.Kind != "final" || frame.Observation == nil {
		runErr = errors.New("invalid or oversized fuzz final response")
		frame.Observation = map[string]any{"target_state": "failed", "errors": []string{"invalid or oversized fuzz final response"}}
	}
	o := frame.Observation
	state, _ := o["target_state"].(string)
	if validateErr := fuzzObservation(o, a.SHA256, image, r.MaxCrashes); validateErr != nil {
		runErr = validateErr
	} else if manifest, _ := o["manifest"].(map[string]any); manifest["input_mode"] != r.InputMode {
		runErr = errors.New("fuzz manifest input mode mismatch")
	} else if runErr != nil {
		// A cancellation can race the transport teardown. A complete, bounded
		// cancelled/timeout observation with verified cleanup is still evidence.
		if pc.Err() == nil || (state != "cancelled" && state != "timeout") {
			runErr = fmt.Errorf("fuzz transport: %w", runErr)
		}
	}
	if pc.Err() != nil && runErr == nil && state != "cancelled" && state != "timeout" {
		runErr = pc.Err()
	}
	o["fuzz_request"] = r
	o["profile_id"] = p.ID
	o["artifact_sha256"] = a.SHA256
	o["image"] = image
	o["policy_revision"] = policy.Revision
	o["candidate_only"] = true
	o["authority"] = "candidate-only"
	// Construct and verify the complete request+observation document before
	// writing either the evidence file or the ledger. A failure is stored once,
	// as a compact validated_campaign=false document shared by both.
	o["validated_campaign"] = false
	if runErr != nil {
		state = "failed"
		o["target_state"] = "failed"
	}
	encoded, encodeErr := encodeFuzzEvidence(o)
	if encodeErr != nil {
		if !errors.Is(encodeErr, errFuzzEvidenceLimit) {
			return nil, encodeErr
		}
		runErr = errFuzzEvidenceLimit
		state = "failed"
		o = compactFuzzFailure(o, errFuzzEvidenceLimit.Error())
		encoded, encodeErr = encodeFuzzEvidence(o)
		if encodeErr != nil {
			return nil, encodeErr
		}
	} else if runErr == nil {
		o["validated_campaign"] = true
		encoded, encodeErr = encodeFuzzEvidence(o)
		if encodeErr != nil {
			return nil, encodeErr
		}
	}
	path, err = nativeSaveEvidenceWithAuthority(dir, task.ID, a, "native_fuzz", "candidate-only", o, nil)
	if err != nil {
		runErr = fmt.Errorf("fuzz evidence could not be stored: %w", err)
		state = "failed"
		o = compactFuzzFailure(o, runErr.Error())
		encoded, encodeErr = encodeFuzzEvidence(o)
		if encodeErr != nil {
			return nil, encodeErr
		}
		if path, err = nativeSaveEvidenceWithAuthority(dir, task.ID, a, "native_fuzz", "candidate-only", o, nil); err != nil {
			path = ""
		}
	}
	if runErr != nil {
		message = runErr.Error()
		state = "failed"
	} else {
		status = "completed"
		message = ""
		if state == "cancelled" {
			status = "cancelled"
		}
	}
	if err = pg.FinishNativeRun(runID, state, path, encoded); err != nil {
		return nil, err
	}
	nativeFinished = true
	return map[string]any{"run_id": runID, "result_path": path, "observation": o,
		"limitations": []string{"bounded synchronous campaign; no restart recovery",
			"AFL statistics and crash inputs are candidates, not verified vulnerabilities",
			"replay_candidate requires explicit signal expectation; no automatic finding publication"}}, runErr
}

func nativeLoadFuzzEvidence(dir string, taskID int64, run *db.NativeRun) (map[string]any, error) {
	if run.ResultPath == "" {
		return nil, errors.New("fuzz campaign has no evidence path")
	}
	path, err := reverseLocalPath(dir, run.ResultPath, filepath.Join("tasks", fmt.Sprint(taskID), "reverse", "results"))
	if err != nil {
		return nil, err
	}
	limit := nativeEvidenceLimit("native_fuzz")
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > int64(limit) {
		return nil, errors.New("fuzz evidence is missing or oversized")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > limit {
		return nil, errors.New("fuzz evidence is unreadable")
	}
	var document map[string]any
	if err = json.Unmarshal(raw, &document); err != nil {
		return nil, errors.New("fuzz evidence is not JSON")
	}
	content, _ := document["structuredContent"].(map[string]any)
	if content["operation"] != "native_fuzz" || content["authority"] != "candidate-only" {
		return nil, errors.New("fuzz evidence authority mismatch")
	}
	normalized, _ := content["normalized_result"].(map[string]any)
	if normalized == nil {
		return nil, errors.New("fuzz evidence has no normalized result")
	}
	want, _ := json.Marshal(normalized)
	var stored map[string]any
	if json.Unmarshal(run.Observation, &stored) != nil {
		return nil, errors.New("fuzz ledger observation is invalid")
	}
	got, _ := json.Marshal(stored)
	if !bytes.Equal(want, got) {
		return nil, errors.New("fuzz ledger and evidence file differ")
	}
	return normalized, nil
}

func nativeFuzzCandidate(ctx context.Context, pg *db.DB, task *db.Task, info agent.RunInfo, dir string, r nativeFuzzRequest) (map[string]any, error) {
	if r.ExpectedSignal == nil || *r.ExpectedSignal < 1 || *r.ExpectedSignal > 64 {
		return nil, errors.New("candidate requires explicit expected_signal 1..64")
	}
	if r.Action == "replay_candidate" && (r.Duration < 1000 || r.Duration > 60000) {
		return nil, errors.New("candidate replay duration must be 1000..60000")
	}
	if len(r.CandidateSHA256) != 64 || !db.NativeSHA256(r.CandidateSHA256) {
		return nil, errors.New("candidate_sha256 must be lowercase SHA-256")
	}
	runs, err := pg.NativeRuns(task.ID)
	if err != nil {
		return nil, err
	}
	var source *db.NativeRun
	for i := range runs {
		if runs[i].RunID == r.RunID && runs[i].Mode == "fuzz" {
			source = &runs[i]
			break
		}
	}
	if source == nil {
		return nil, errors.New("fuzz run unavailable in latest 100 task runs")
	}
	if source.TargetState != "completed" {
		return nil, errors.New("candidate source campaign did not complete")
	}
	o, err := nativeLoadFuzzEvidence(dir, task.ID, source)
	if err != nil {
		return nil, err
	}
	if o["validated_campaign"] != true {
		return nil, errors.New("unvalidated fuzz campaign")
	}
	var original nativeFuzzRequest
	rawRequest, _ := json.Marshal(o["fuzz_request"])
	dec := json.NewDecoder(bytes.NewReader(rawRequest))
	dec.DisallowUnknownFields()
	if dec.Decode(&original) != nil {
		return nil, errors.New("invalid campaign request")
	}
	if err = validateFuzzRequest(&original); err != nil {
		return nil, err
	}
	if original.ArtifactID != source.ArtifactID || original.ProfileID == "" {
		return nil, errors.New("campaign target identity mismatch")
	}
	p, err := nativeProfile(original.ProfileID)
	if err != nil {
		return nil, err
	}
	if _, err = validateFuzzProfile(p); err != nil {
		return nil, err
	}
	a, err := nativeArtifact(pg, task.ID, source.ArtifactID, dir)
	if err != nil {
		return nil, err
	}
	policy, err := pg.ReverseRuntimePolicy(task.ID)
	if err != nil {
		return nil, err
	}
	if !policy.Enabled || policy.Revision != int64FromAny(o["policy_revision"]) ||
		o["artifact_sha256"] != a.SHA256 || o["image"] != p.Settings["image"] ||
		o["profile_id"] != p.ID {
		return nil, errors.New("campaign target/image/policy changed")
	}
	if err = fuzzObservation(o, a.SHA256, o["image"].(string), original.MaxCrashes); err != nil {
		return nil, err
	}
	if manifest, _ := o["manifest"].(map[string]any); manifest["input_mode"] != original.InputMode {
		return nil, errors.New("campaign input mode mismatch")
	}
	var crashes []nativeFuzzInput
	b, _ := json.Marshal(o["crashes"])
	_ = json.Unmarshal(b, &crashes)
	input := ""
	found := false
	for _, c := range crashes {
		if c.SHA256 == r.CandidateSHA256 {
			data, decodeErr := decodeFuzzInput(c, true)
			if decodeErr != nil {
				return nil, decodeErr
			}
			input = base64.StdEncoding.EncodeToString(data)
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("candidate hash not found")
	}
	c := db.NativeCase{TaskID: task.ID, ArtifactID: a.ID, IntentID: info.IntentID,
		ProfileID: p.ID, Title: fmt.Sprintf("fuzz candidate %d %s", source.RunID, r.CandidateSHA256),
		Argv: original.Argv, InputBase64: input, ExpectedSignal: r.ExpectedSignal,
		ReplayPlan: &db.NativeReplayPlan{Version: 2, InputMode: original.InputMode,
			ArtifactSHA256: a.SHA256, Image: o["image"].(string), PolicyRevision: policy.Revision}}
	if err = nativePrepareCase(pg, task.ID, dir, &c); err != nil {
		return nil, err
	}
	created, err := pg.CreateNativeCase(ctx, c)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"case": created, "source_run_id": source.RunID,
		"candidate_only": true, "authority": "candidate-only", "replayed": false}
	if r.Action == "replay_candidate" {
		result, e := nativeReplay(ctx, pg, task, info, dir, created, r.Duration)
		out["replay"] = result
		out["replayed"] = e == nil
		return out, e
	}
	return out, nil
}

func int64FromAny(v any) int64 {
	n, _ := fuzzInt64(v)
	return n
}

func nativeFuzzTool(pg *db.DB, task *db.Task, info agent.RunInfo, dir string) actool.CoreTool {
	schema := reverseObject(map[string]any{
		"action":      map[string]any{"type": "string", "enum": []string{"run", "list", "import_candidate", "replay_candidate"}},
		"artifact_id": reverseInt(), "profile_id": reverseString(),
		"argv":           map[string]any{"type": "array", "items": reverseString()},
		"input_mode":     map[string]any{"type": "string", "enum": []string{"stdin", "file"}},
		"duration_ms":    reverseInt(),
		"seeds":          map[string]any{"type": "array", "items": reverseObject(map[string]any{"sha256": reverseString(), "data_base64": reverseString()}, "sha256", "data_base64")},
		"max_executions": reverseInt(), "max_crashes": reverseInt(), "run_id": reverseInt(),
		"candidate_sha256": reverseString(), "expected_signal": reverseInt(),
	}, "action")
	schema["additionalProperties"] = false
	return reverseTool("native_fuzz", "Bounded synchronous AFL++ run/list/import_candidate/replay_candidate. Requires explicit fuzz_enabled profile and runtime authorization. Crashes remain candidates; replay requires expected_signal. No background recovery or automatic Findings.", schema, func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
		if len(raw) > maxFuzzRequest || !json.Valid(raw) {
			return actool.Errorf("invalid or oversized fuzz request"), nil
		}
		action, err := validateFuzzActionFields(raw)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		var r nativeFuzzRequest
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&r); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		if r.Action != action {
			return actool.Errorf("native_fuzz action mismatch"), nil
		}
		var result any
		switch action {
		case "run":
			result, err = nativeFuzzRun(ctx, pg, task, info, dir, r)
		case "import_candidate", "replay_candidate":
			result, err = nativeFuzzCandidate(ctx, pg, task, info, dir, r)
		case "list":
			var runs []db.NativeRun
			runs, err = pg.NativeRuns(task.ID)
			items := []map[string]any{}
			for _, n := range runs {
				if n.Mode == "fuzz" {
					items = append(items, map[string]any{"run_id": n.RunID, "artifact_id": n.ArtifactID, "state": n.TargetState, "result_path": n.ResultPath})
				}
			}
			result = map[string]any{"campaigns": items, "limit": "latest 100 native task runs", "candidate_only": true}
		}
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		return reverseJSON(result), nil
	})
}
