package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

func nativeArtifact(pg *db.DB, taskID, id int64, dir string) (*db.ReverseArtifact, error) {
	a, e := pg.GetReverseArtifact(taskID, id)
	if e != nil {
		return nil, e
	}
	if a == nil {
		return nil, errors.New("材料不存在")
	}
	a.Path, e = reverseLocalPath(dir, a.Path, filepath.Join("tasks", strconv.FormatInt(taskID, 10), "reverse", "artifacts"))
	if e != nil {
		return nil, e
	}
	if e = verifyArtifact(a); e != nil {
		return nil, e
	}
	return a, nil
}

// Parse ELF bytes only. Never use ldd or execute the uploaded file.
func inspectNativeELF(path string) (map[string]any, error) {
	f, e := elf.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Machine != elf.EM_X86_64 {
		return nil, errors.New("仅支持 little-endian ELF64 x86-64")
	}
	nx := "unknown"
	relro := "none"
	interp := ""
	bindNow := false
	for _, p := range f.Progs {
		switch p.Type {
		case elf.PT_GNU_STACK:
			if p.Flags&elf.PF_X == 0 {
				nx = "enabled"
			} else {
				nx = "disabled"
			}
		case elf.PT_GNU_RELRO:
			relro = "partial"
		case elf.PT_INTERP:
			if p.Filesz <= 4096 {
				b := make([]byte, p.Filesz)
				_, _ = p.ReadAt(b, 0)
				interp = strings.TrimRight(string(b), "\x00")
			}
		}
	}
	if v, _ := f.DynValue(elf.DT_BIND_NOW); len(v) > 0 {
		bindNow = true
	}
	for _, tag := range []elf.DynTag{elf.DT_FLAGS, elf.DT_FLAGS_1} {
		v, _ := f.DynValue(tag)
		for _, n := range v {
			if (tag == elf.DT_FLAGS && n&8 != 0) || (tag == elf.DT_FLAGS_1 && n&1 != 0) {
				bindNow = true
			}
		}
	}
	if relro == "partial" && bindNow {
		relro = "full"
	}
	symbols, _ := f.DynamicSymbols()
	canary := "not_observed"
	for _, s := range symbols {
		if s.Name == "__stack_chk_fail" {
			canary = "import_observed"
		}
	}
	libs, _ := f.ImportedLibraries()
	if libs == nil {
		libs = []string{}
	}
	return map[string]any{"architecture": "x86_64", "class": 64, "endianness": "little", "elf_type": f.Type.String(), "entry": fmt.Sprintf("0x%x", f.Entry), "nx": nx, "relro": relro, "pie_candidate": f.Type == elf.ET_DYN, "canary": canary, "interpreter": interp, "needed": libs, "stripped": f.Section(".symtab") == nil, "limitations": []string{"ET_DYN alone does not distinguish PIE from a shared library", "canary import does not prove every function is protected", "runtime ASLR, libc resolution and exploitability require separate evidence"}}, nil
}
func nativeProfile(id string) (reverseRuntimeProfile, error) {
	ps, e := reverseRuntimeProfiles()
	if e != nil {
		return reverseRuntimeProfile{}, e
	}
	for _, p := range ps {
		if p.ID == id && p.Engine == "docker-native" && p.Platform == "linux" {
			if p.Settings["enabled"] == false {
				return reverseRuntimeProfile{}, errors.New("native 环境已停用")
			}
			return p, nil
		}
	}
	return reverseRuntimeProfile{}, errors.New("未配置 Linux docker-native 环境")
}
func nativeMappedPath(path string, p reverseRuntimeProfile) string {
	path = filepath.ToSlash(path)
	for _, m := range p.PathMappings {
		from := strings.TrimRight(filepath.ToSlash(m.From), "/")
		if strings.HasPrefix(path, from+"/") {
			return strings.TrimRight(m.To, "/") + strings.TrimPrefix(path, from)
		}
	}
	return path
}
func nativeDoctor(ctx context.Context, p reverseRuntimeProfile) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	raw, e := invokeReverseRuntime(ctx, p, map[string]any{"operation": "doctor"})
	var frame reverseSessionFrame
	if json.Unmarshal(raw, &frame) != nil {
		return nil, errors.New("invalid native doctor response")
	}
	o := frame.Observation
	return map[string]any{"available": e == nil && p.Settings["enabled"] != false && o["engine"] == "docker-native" && o["platform"] == "linux/x86_64" && o["docker_available"] == true && o["image_available"] == true && o["gdb_available"] == true, "observation": o}, e
}
func nativeObservationError(o map[string]any, hash string) error {
	manifest, _ := o["manifest"].(map[string]any)
	if manifest["engine"] != "docker-native" || manifest["artifact_sha256"] != hash {
		return errors.New("native evidence identity mismatch")
	}
	cleanup, _ := o["cleanup"].(map[string]any)
	for _, key := range []string{"owned_process_terminated", "container_removed", "staging_removed"} {
		if cleanup[key] != true {
			return errors.New("native cleanup not confirmed")
		}
	}
	if errs, ok := o["errors"].([]any); !ok || len(errs) > 0 {
		return errors.New("native runner reported errors")
	}
	switch o["target_state"] {
	case "exit", "crashed", "cancelled", "timeout":
		return nil
	}
	return errors.New("native target outcome unavailable")
}

// Legacy native sessions accept a stream capped at 3 MiB, so their evidence
// envelope must stay larger than that while remaining explicitly bounded.
// Fuzz campaigns keep a separate, tighter cap (maxFuzzEvidenceFile).
const maxNativeEvidenceBytes = 4 << 20

func nativeEvidenceLimit(operation string) int {
	if operation == "native_fuzz" {
		return maxFuzzEvidenceFile
	}
	return maxNativeEvidenceBytes
}

// Authority is explicit: an AFL campaign is only a candidate source, while a
// controlled replay is the evidence accepted by the independent reviewer.
func nativeSaveEvidenceWithAuthority(dir string, taskID int64, a *db.ReverseArtifact, operation, authority string, o map[string]any, transcript any) (string, error) {
	expectedAuthority := map[string]string{"native_inspect": "static-inspection",
		"native_session": "controlled-replay", "native_fuzz": "candidate-only",
		"native_replay": "controlled-replay"}[operation]
	if expectedAuthority == "" || authority != expectedAuthority {
		return "", errors.New("unsupported native operation/authority pair")
	}
	record := map[string]any{"structuredContent": map[string]any{"operation": operation, "provider": map[string]any{"name": "docker-native", "version": 1}, "subject": map[string]any{"digest": map[string]any{"sha256": a.SHA256}, "name": a.Name}, "normalized_result": o, "transcript": transcript, "authority": authority}}
	raw, e := json.Marshal(record)
	if e != nil {
		return "", e
	}
	if len(raw) > nativeEvidenceLimit(operation) {
		return "", errors.New("native evidence exceeds size limit")
	}
	prefix := filepath.Join("tasks", strconv.FormatInt(taskID, 10), "reverse", "results")
	dest := filepath.Join(dir, prefix)
	if e = os.MkdirAll(dest, 0700); e != nil {
		return "", e
	}
	f, e := os.CreateTemp(dest, "native-*.json")
	if e != nil {
		return "", e
	}
	path := filepath.Join(prefix, filepath.Base(f.Name()))
	_, e = f.Write(raw)
	ce := f.Close()
	if e == nil {
		e = ce
	}
	return filepath.ToSlash(path), e
}

// Compatibility entry point for the existing native session caller. New code
// must state its authority explicitly so fuzz campaigns cannot be mislabeled.
func nativeSaveEvidence(dir string, taskID int64, a *db.ReverseArtifact, operation string, o map[string]any, transcript any) (string, error) {
	authority := "controlled-replay"
	switch operation {
	case "native_session":
	case "native_inspect":
		authority = "static-inspection"
	default:
		return "", errors.New("unsupported native evidence operation")
	}
	return nativeSaveEvidenceWithAuthority(dir, taskID, a, operation, authority, o, transcript)
}
func (s *Server) reverseNativeRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/findings/{id}/native-export", s.nativeExportRoute)
	mux.HandleFunc("GET /api/findings/{id}/native-evidence", func(w http.ResponseWriter, r *http.Request) {
		id, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if e != nil {
			writeErr(w, 400, "invalid finding id")
			return
		}
		var raw []byte
		var digest string
		if e = s.m.pg.QueryRow(`SELECT sha256,snapshot FROM finding_native_evidence WHERE finding_id=$1`, id).Scan(&digest, &raw); e != nil {
			writeErr(w, 404, "native evidence not found")
			return
		}
		var v any
		if e = json.Unmarshal(raw, &v); e != nil {
			writeErr(w, 500, "invalid native snapshot")
			return
		}
		canonical, _ := json.Marshal(v)
		hash := sha256.Sum256(canonical)
		if hex.EncodeToString(hash[:]) != digest {
			writeErr(w, 409, "native snapshot integrity mismatch")
			return
		}
		writeJSON(w, 200, map[string]any{"sha256": digest, "snapshot": v})
	})
	mux.HandleFunc("GET /api/tasks/{id}/reverse/native", s.nativeState)
	mux.HandleFunc("PUT /api/tasks/{id}/reverse/native", func(w http.ResponseWriter, r *http.Request) {
		id, _, ok := s.reverseIDs(r)
		if !ok {
			writeErr(w, 404, "逆向任务不存在")
			return
		}
		var c db.NativeConfig
		if !decodeConversationRequest(w, r, &c) {
			return
		}
		if e := s.m.pg.SetNativeConfig(r.Context(), id, c.Mode); e != nil {
			writeErr(w, 409, e.Error())
			return
		}
		cfg, _ := s.m.pg.NativeConfig(id)
		writeJSON(w, 200, cfg)
	})
	mux.HandleFunc("GET /api/tasks/{id}/reverse/native/inspect", func(w http.ResponseWriter, r *http.Request) {
		id, _, ok := s.reverseIDs(r)
		if !ok {
			writeErr(w, 404, "逆向任务不存在")
			return
		}
		aid, _ := strconv.ParseInt(r.URL.Query().Get("artifact_id"), 10, 64)
		a, e := nativeArtifact(s.m.pg, id, aid, s.m.dir)
		if e != nil {
			writeErr(w, 400, e.Error())
			return
		}
		o, e := inspectNativeELF(a.Path)
		if e != nil {
			writeErr(w, 400, e.Error())
			return
		}
		o["artifact_sha256"] = a.SHA256
		writeJSON(w, 200, o)
	})
	mux.HandleFunc("GET /api/tasks/{id}/reverse/native/doctor", func(w http.ResponseWriter, r *http.Request) {
		_, _, ok := s.reverseIDs(r)
		if !ok {
			writeErr(w, 404, "逆向任务不存在")
			return
		}
		p, e := nativeProfile(r.URL.Query().Get("profile_id"))
		if e != nil {
			writeErr(w, 400, e.Error())
			return
		}
		o, e := nativeDoctor(r.Context(), p)
		if e != nil {
			writeErr(w, 503, e.Error())
			return
		}
		writeJSON(w, 200, o)
	})
}
func nativeReplay(ctx context.Context, pg *db.DB, task *db.Task, info agent.RunInfo, dir string, c *db.NativeCase, duration int) (map[string]any, error) {
	verified := *c
	if err := db.ValidateNativeCase(&verified); err != nil {
		return nil, err
	}
	if verified.SHA256 != c.SHA256 {
		return nil, errors.New("native case hash mismatch")
	}
	p, e := nativeProfile(c.ProfileID)
	if e != nil {
		return nil, e
	}
	a, e := nativeArtifact(pg, task.ID, c.ArtifactID, dir)
	if e != nil {
		return nil, e
	}
	if _, e = inspectNativeELF(a.Path); e != nil {
		return nil, e
	}
	policy, e := pg.ReverseRuntimePolicy(task.ID)
	if e != nil {
		return nil, e
	}
	if c.ReplayPlan != nil && c.ReplayPlan.Version == 2 && (c.ReplayPlan.ArtifactSHA256 != a.SHA256 || c.ReplayPlan.Image != p.Settings["image"] || c.ReplayPlan.PolicyRevision != policy.Revision) {
		return nil, errors.New("case target, image or policy identity changed")
	}
	target, attachments, e := nativeTarget(pg, task.ID, dir, p, c.ReplayPlan)
	if e != nil {
		return nil, e
	}
	cfg, e := pg.NativeConfig(task.ID)
	if e != nil {
		return nil, e
	}
	runID, e := pg.BeginNativeRuntimeRun(ctx, task.ID, a.ID, info.IntentID, p.ID, duration, attachments, policy.Revision)
	if e != nil {
		return nil, e
	}
	status, path, msg := "failed", "", "native replay incomplete"
	defer func() { _ = pg.FinishReverseRuntimeRun(runID, status, path, msg) }()
	if e = pg.BeginNativeRun(ctx, db.NativeRun{RunID: runID, TaskID: task.ID, ArtifactID: a.ID, IntentID: info.IntentID, CaseID: c.ID, ConfigRevision: cfg.Revision, Mode: "replay"}); e != nil {
		return nil, e
	}
	policyCtx, policyCancel := nativePolicyContext(ctx, pg, task.ID, policy.Revision)
	defer policyCancel()
	runCtx, cancel := context.WithTimeout(policyCtx, time.Duration(duration)*time.Millisecond+30*time.Second)
	defer cancel()
	expectedExit, expectedSignal := verified.ReplayExpectations()
	inputMode := "stdin"
	if verified.ReplayPlan != nil {
		inputMode = verified.ReplayPlan.InputMode
	}
	raw, runErr := invokeReverseRuntime(runCtx, p, map[string]any{"operation": "replay", "artifact_path": nativeMappedPath(a.Path, p), "sha256": a.SHA256, "argv": verified.Argv, "input_base64": verified.InputBase64, "input_mode": inputMode, "target": target, "expected_exit": expectedExit, "expected_signal": expectedSignal, "duration_ms": duration})
	var f reverseSessionFrame
	_ = json.Unmarshal(raw, &f)
	o := f.Observation
	if o == nil {
		o = map[string]any{}
	}
	if runErr == nil {
		runErr = nativeObservationError(o, a.SHA256)
	}
	// Compute the assertion locally; do not trust a runner supplied boolean.
	state, _ := o["target_state"].(string)
	matched := runErr == nil && nativeMatch(c, o)
	o["matches_expectation"] = matched
	o["case_sha256"] = c.SHA256
	o["policy_revision"] = policy.Revision
	o["replay_case"] = c
	path, e = nativeSaveEvidenceWithAuthority(dir, task.ID, a, "native_replay", "controlled-replay", o, nil)
	if e != nil {
		return nil, e
	}
	encoded, _ := json.Marshal(o)
	if e = pg.FinishNativeRun(runID, state, path, encoded); e != nil {
		return nil, e
	}
	if runErr == nil {
		status = "completed"
		msg = ""
	} else {
		msg = runErr.Error()
		if ctx.Err() != nil && state == "cancelled" && nativeObservationError(o, a.SHA256) == nil {
			status = "cancelled"
		}
	}
	out := map[string]any{"run_id": runID, "case_id": c.ID, "result_path": path, "observation": o}
	return out, runErr
}
func nativeReplayPlanSchema() map[string]any {
	assertion := reverseObject(map[string]any{
		"type":        map[string]any{"type": "string", "enum": []string{"exit_code", "signal", "stdout_contains_base64"}},
		"value":       reverseInt(),
		"data_base64": reverseString(),
	}, "type")
	assertion["additionalProperties"] = false
	binding := reverseObject(map[string]any{"artifact_id": reverseInt(), "sha256": reverseString(), "name": reverseString()}, "artifact_id", "sha256", "name")
	binding["additionalProperties"] = false
	target := reverseObject(map[string]any{"dependencies": map[string]any{"type": "array", "items": binding}, "loader": binding, "harness": binding})
	target["additionalProperties"] = false
	plan := reverseObject(map[string]any{
		"version":         map[string]any{"type": "integer", "enum": []int{1, 2}},
		"input_mode":      map[string]any{"type": "string", "enum": []string{"stdin", "file"}},
		"assertion":       assertion,
		"artifact_sha256": reverseString(), "image": reverseString(), "policy_revision": reverseInt(), "target": target, "parent_case_id": reverseInt(),
	}, "version")
	plan["additionalProperties"] = false
	return plan
}

func nativeTools(pg *db.DB, task *db.Task, info agent.RunInfo, dir, role string, m *nativeSessionManager) []actool.CoreTool {
	tools := []actool.CoreTool{reverseTool("native_inspect", "静态读取已上传 Linux x86-64 ELF、防护迹象和依赖名称；不会执行样本。", reverseObject(map[string]any{"artifact_id": reverseInt()}, "artifact_id"), func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
		var a struct {
			ArtifactID int64 `json:"artifact_id"`
		}
		if e := json.Unmarshal(raw, &a); e != nil {
			return actool.Errorf(e.Error()), nil
		}
		artifact, e := nativeArtifact(pg, task.ID, a.ArtifactID, dir)
		if e != nil {
			return actool.Errorf(e.Error()), nil
		}
		o, e := inspectNativeELF(artifact.Path)
		if e != nil {
			return actool.Errorf(e.Error()), nil
		}
		path, e := nativeSaveEvidenceWithAuthority(dir, task.ID, artifact, "native_inspect", "static-inspection", o, nil)
		if e != nil {
			return actool.Errorf(e.Error()), nil
		}
		return reverseJSON(map[string]any{"result_path": path, "artifact_sha256": artifact.SHA256, "observation": o}), nil
	})}
	if role != "reverse_dynamic" && role != "reverse_reviewer" && role != "worker" {
		return tools
	}
	if role == "reverse_dynamic" {
		tools = append(tools, nativeFuzzTool(pg, task, info, dir))
	}
	tools = append(tools, m.tool(), reverseTool("native_case", "create 保存不可变案例；replay 独立重放；repeat 返回 n/N；minimize 有界缩减同一目标输出断言并保留原输入。v2 支持已登记依赖/loader/Python harness、stdin/file 和目标输出断言，自动绑定当前样本哈希、镜像和策略版本。harness 输出不能作为目标影响证明。reviewer 只能 replay/repeat。", reverseObject(map[string]any{"action": reverseString(), "case_id": reverseInt(), "artifact_id": reverseInt(), "profile_id": reverseString(), "title": reverseString(), "argv": map[string]any{"type": "array", "items": reverseString()}, "input_base64": reverseString(), "expected_exit": reverseInt(), "expected_signal": reverseInt(), "replay_plan": nativeReplayPlanSchema(), "duration_ms": reverseInt(), "repeats": reverseInt(), "max_runs": reverseInt()}, "action"), func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
		var req struct {
			db.NativeCase
			Action   string `json:"action"`
			CaseID   int64  `json:"case_id"`
			Duration int    `json:"duration_ms"`
			Repeats  int    `json:"repeats"`
			MaxRuns  int    `json:"max_runs"`
		}
		if !json.Valid(raw) {
			return actool.Errorf("invalid native_case JSON"), nil
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if e := decoder.Decode(&req); e != nil {
			return actool.Errorf(e.Error()), nil
		}
		if role == "reverse_reviewer" && req.Action != "replay" && req.Action != "repeat" {
			return actool.Errorf("reviewer may only replay immutable cases"), nil
		}
		switch req.Action {
		case "create":
			req.NativeCase.TaskID = task.ID
			req.NativeCase.IntentID = info.IntentID
			if e := nativePrepareCase(pg, task.ID, dir, &req.NativeCase); e != nil {
				return actool.Errorf(e.Error()), nil
			}
			c, e := pg.CreateNativeCase(ctx, req.NativeCase)
			if e != nil {
				return actool.Errorf(e.Error()), nil
			}
			return reverseJSON(c), nil
		case "replay", "repeat", "minimize":
			c, e := pg.NativeCase(task.ID, req.CaseID)
			if e != nil {
				return actool.Errorf(e.Error()), nil
			}
			if req.Duration == 0 {
				req.Duration = 10000
			}
			if req.Action == "repeat" {
				if req.Repeats == 0 {
					req.Repeats = 3
				}
				o, e := nativeRepeat(ctx, pg, task, info, dir, c, req.Duration, req.Repeats)
				if e != nil {
					return actool.Errorf(e.Error()), nil
				}
				return reverseJSON(o), nil
			}
			if req.Action == "minimize" {
				if req.MaxRuns == 0 {
					req.MaxRuns = 32
				}
				o, e := nativeMinimize(ctx, pg, task, info, dir, c, req.Duration, req.MaxRuns)
				if e != nil {
					return actool.Errorf(e.Error()), nil
				}
				return reverseJSON(o), nil
			}
			o, e := nativeReplay(ctx, pg, task, info, dir, c, req.Duration)
			if e != nil {
				return actool.Errorf(e.Error()), nil
			}
			return reverseJSON(o), nil
		default:
			return actool.Errorf("action must be create, replay, repeat or minimize"), nil
		}
	}))
	if role == "reverse_reviewer" || role == "worker" {
		tools = append(tools, nativeReviewTool(pg, task, info, dir))
		tools = append(tools, reverseTool("native_publish_finding", "仅将已接受结论和独立成功重放关联为 Finding。保留独立材料/输入/运行证据快照；必须说明根因和影响，崩溃不能直接声称代码执行。", reverseObject(map[string]any{"conclusion_id": reverseInt(), "case_id": reverseInt(), "run_id": reverseInt(), "name": reverseString(), "vulnclass": reverseString(), "severity": reverseString(), "summary": reverseString()}, "conclusion_id", "case_id", "run_id", "name", "vulnclass", "severity", "summary"), func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			var r struct {
				ConclusionID                       int64 `json:"conclusion_id"`
				CaseID                             int64 `json:"case_id"`
				RunID                              int64 `json:"run_id"`
				Name, VulnClass, Severity, Summary string
			}
			if e := json.Unmarshal(raw, &r); e != nil {
				return actool.Errorf(e.Error()), nil
			}
			if r.Name == "" || r.VulnClass == "" || r.Summary == "" || len(r.Summary) > 16000 {
				return actool.Errorf("需要有界根因、影响与证据说明"), nil
			}
			switch r.Severity {
			case "info", "low", "medium", "high", "critical":
			default:
				return actool.Errorf("invalid severity"), nil
			}
			c, e := pg.NativeCase(task.ID, r.CaseID)
			if e != nil {
				return actool.Errorf(e.Error()), nil
			}
			a, e := nativeArtifact(pg, task.ID, c.ArtifactID, dir)
			if e != nil {
				return actool.Errorf(e.Error()), nil
			}
			if a.SizeBytes > 8<<20 {
				return actool.Errorf("独立 Finding 快照当前支持最大 8 MiB 样本；较大材料保留候选结论"), nil
			}
			binary, e := os.ReadFile(a.Path)
			if e != nil {
				return actool.Errorf(e.Error()), nil
			}
			runs, e := pg.NativeRuns(task.ID)
			if e != nil {
				return actool.Errorf(e.Error()), nil
			}
			var selected *db.NativeRun
			for i := range runs {
				if runs[i].RunID == r.RunID {
					selected = &runs[i]
				}
			}
			if selected == nil {
				return actool.Errorf("重放记录不存在"), nil
			}
			hash := sha256.Sum256(binary)
			if hex.EncodeToString(hash[:]) != a.SHA256 {
				return actool.Errorf("样本哈希发生变化"), nil
			}
			conclusion, e := pg.GetReverseConclusion(task.ID, r.ConclusionID)
			if e != nil || conclusion == nil {
				return actool.Errorf("结论不存在"), nil
			}
			evidence := []map[string]any{}
			total := 0
			for _, ref := range conclusion.Evidence {
				if ref.ResultPath == "" {
					continue
				}
				path, e := reverseLocalPath(dir, ref.ResultPath, filepath.Join("tasks", strconv.FormatInt(task.ID, 10), "reverse", "results"))
				if e != nil {
					return actool.Errorf(e.Error()), nil
				}
				stat, e := os.Stat(path)
				if e != nil || stat.Size() > 2<<20 {
					return actool.Errorf("原始证据不存在或超过单项 2 MiB 快照上限"), nil
				}
				data, e := os.ReadFile(path)
				if e != nil {
					return actool.Errorf(e.Error()), nil
				}
				total += len(data)
				if total > 6<<20 {
					return actool.Errorf("原始证据超过 6 MiB 快照总上限"), nil
				}
				h := sha256.Sum256(data)
				digest := hex.EncodeToString(h[:])
				if ref.ResultSHA256 != "" && ref.ResultSHA256 != digest {
					return actool.Errorf("结论原始证据哈希不匹配"), nil
				}
				evidence = append(evidence, map[string]any{"sha256": digest, "content_base64": base64.StdEncoding.EncodeToString(data)})
			}
			attachments := []map[string]any{}
			if c.ReplayPlan != nil {
				for _, binding := range c.ReplayPlan.Target.Bindings() {
					attached, err := nativeArtifact(pg, task.ID, binding.ArtifactID, dir)
					if err != nil {
						return actool.Errorf(err.Error()), nil
					}
					if attached.SHA256 != binding.SHA256 || attached.SizeBytes > 8<<20 {
						return actool.Errorf("attachment changed or exceeds 8 MiB evidence snapshot limit"), nil
					}
					data, err := os.ReadFile(attached.Path)
					if err != nil {
						return actool.Errorf(err.Error()), nil
					}
					total += len(data)
					if total > 12<<20 {
						return actool.Errorf("attachment and source evidence snapshot exceeds 12 MiB"), nil
					}
					attachments = append(attachments, map[string]any{"name": binding.Name, "sha256": binding.SHA256, "content_base64": base64.StdEncoding.EncodeToString(data)})
				}
			}
			review, _ := pg.NativeReview(task.ID, r.ConclusionID)
			snapshot, _ := json.Marshal(map[string]any{"version": 2, "artifact": map[string]any{"name": a.Name, "sha256": a.SHA256, "format": a.Format, "size_bytes": a.SizeBytes}, "specimen_base64": base64.StdEncoding.EncodeToString(binary), "attachments": attachments, "case": c, "replay": selected, "conclusion": conclusion, "native_review": review, "source_evidence": evidence})
			out, e := pg.PublishNativeFinding(ctx, task.ID, r.ConclusionID, r.CaseID, r.RunID, info.IntentID, db.RecordFindingInput{Name: r.Name, VulnClass: r.VulnClass, Severity: r.Severity, Summary: r.Summary}, snapshot)
			if e != nil {
				return actool.Errorf(e.Error()), nil
			}
			return reverseJSON(out), nil
		}))
	}
	return tools
}

func (s *Server) nativeState(w http.ResponseWriter, r *http.Request) {
	id, _, ok := s.reverseIDs(r)
	if !ok {
		writeErr(w, 404, "逆向任务不存在")
		return
	}
	cfg, e := s.m.pg.NativeConfig(id)
	if e != nil {
		writeErr(w, 500, e.Error())
		return
	}
	cases, e := s.m.pg.NativeCases(id)
	if e != nil {
		writeErr(w, 500, e.Error())
		return
	}
	runs, e := s.m.pg.NativeRuns(id)
	if e != nil {
		writeErr(w, 500, e.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"config": cfg, "cases": cases, "runs": runs})

}
