package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

type reverseRuntimeProfile struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Platform     string         `json:"platform"`
	Command      string         `json:"command"`
	Args         []string       `json:"args"`
	Settings     map[string]any `json:"settings"`
	PathMappings []struct {
		From string `json:"from"`
		To   string `json:"to"`
	} `json:"path_mappings"`
}

func reverseRuntimeProfiles() ([]reverseRuntimeProfile, error) {
	path := strings.TrimSpace(os.Getenv("ARTEX_REVERSE_RUNTIME_PROFILES"))
	if path == "" {
		return []reverseRuntimeProfile{}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("运行环境配置文件不可读")
	}
	defer f.Close()
	var profiles []reverseRuntimeProfile
	decoder := json.NewDecoder(io.LimitReader(f, 1<<20))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&profiles); err != nil {
		return nil, errors.New("运行环境配置格式错误")
	}
	if len(profiles) > 16 {
		return nil, errors.New("最多配置 16 个运行环境")
	}
	seen := map[string]bool{}
	for i := range profiles {
		p := &profiles[i]
		if !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`).MatchString(p.ID) || seen[p.ID] || (p.Platform != "linux" && p.Platform != "windows" && p.Platform != "android") || p.Command == "" {
			return nil, errors.New("运行环境必须有唯一 ID、支持的平台及启动命令")
		}
		seen[p.ID] = true
		if p.Settings == nil {
			p.Settings = map[string]any{}
		}
		p.Settings["platform"] = p.Platform
	}
	return profiles, nil
}

// The runner's control pipe requests graceful cleanup before a forced process
// termination. EOF also tells a surviving bridge to terminate its owned sample.
func invokeReverseRuntime(ctx context.Context, p reverseRuntimeProfile, request map[string]any) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	request["profile"] = p.Settings
	command := exec.Command(p.Command, p.Args...)
	in, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := command.StdoutPipe()
	if err != nil {
		in.Close()
		return nil, err
	}
	command.Stderr = io.Discard
	if err = command.Start(); err != nil {
		in.Close()
		return nil, errors.New("调试运行器无法启动")
	}
	defer in.Close()
	if err = json.NewEncoder(in).Encode(request); err != nil {
		command.Process.Kill()
		command.Wait()
		return nil, err
	}
	type answer struct {
		raw []byte
		err error
	}
	done := make(chan answer, 1)
	go func() {
		raw, readErr := io.ReadAll(io.LimitReader(out, 3*1024*1024+1))
		if len(raw) > 3*1024*1024 {
			_, _ = io.WriteString(in, "{\"cancel\":true}\n")
			stop := time.AfterFunc(8*time.Second, func() { _ = command.Process.Kill() })
			_, _ = io.Copy(io.Discard, out)
			stop.Stop()
		}
		waitErr := command.Wait()
		if readErr == nil {
			readErr = waitErr
		}
		done <- answer{raw, readErr}
	}()
	select {
	case result := <-done:
		if len(result.raw) > 3*1024*1024 {
			return nil, errors.New("运行时证据超出保存上限")
		}
		if result.err != nil {
			return result.raw, errors.New("运行时观察未完成，请检查引擎、样本和环境")
		}
		if !json.Valid(result.raw) {
			return result.raw, errors.New("运行器未返回有效 JSON 证据")
		}
		return result.raw, nil
	case <-ctx.Done():
		_, _ = io.WriteString(in, "{\"cancel\":true}\n")
		select {
		case result := <-done:
			return result.raw, ctx.Err()
		case <-time.After(8 * time.Second):
			_ = in.Close()
			_ = command.Process.Kill()
			result := <-done
			return result.raw, fmt.Errorf("运行器取消超时，清理结果未确认: %w", ctx.Err())
		}
	}
}

func reverseRuntimeObservationError(observation map[string]any, platform, artifactHash, script string) error {
	scriptHash := sha256.Sum256([]byte(script))
	var validationErr error
	if observation["platform"] != platform || observation["artifact_sha256"] != artifactHash || observation["script_sha256"] != hex.EncodeToString(scriptHash[:]) {
		validationErr = errors.New("运行器证据的材料、平台或脚本标识不匹配")
	}
	cleanup, _ := observation["cleanup"].(map[string]any)
	for _, key := range []string{"script_unloaded", "session_detached", "owned_process_terminated", "staging_removed"} {
		if cleanup[key] != true {
			validationErr = errors.New("运行时清理未确认，详见原始证据")
		}
	}
	if platform == "android" && cleanup["package_removed"] != true {
		validationErr = errors.New("实验 APK 清理未确认，详见原始证据")
	}
	if failures, ok := observation["errors"].([]any); ok && len(failures) > 0 {
		validationErr = errors.New("运行时脚本或清理未完成，详见原始证据")
	}
	return validationErr
}

func (s *Server) reverseDebugRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/reverse/runtime-profiles", func(w http.ResponseWriter, r *http.Request) {
		profiles, err := reverseRuntimeProfiles()
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		out := make([]map[string]any, len(profiles))
		var wg sync.WaitGroup
		limit := make(chan struct{}, 4)
		for i, p := range profiles {
			wg.Add(1)
			go func(i int, p reverseRuntimeProfile) {
				defer wg.Done()
				select {
				case limit <- struct{}{}:
				case <-r.Context().Done():
					return
				}
				defer func() { <-limit }()
				ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
				raw, err := invokeReverseRuntime(ctx, p, map[string]any{"operation": "doctor"})
				cancel()
				var doctor map[string]any
				_ = json.Unmarshal(raw, &doctor)
				out[i] = map[string]any{"id": p.ID, "name": p.Name, "platform": p.Platform, "available": err == nil && doctor["available"] == true && doctor["platform"] == p.Platform, "engine_version": doctor["version"], "limits": "仅已授权材料；进程隔离不等于沙箱"}
			}(i, p)
		}
		wg.Wait()
		writeJSON(w, 200, out)
	})
	mux.HandleFunc("GET /api/tasks/{id}/reverse/runtime", func(w http.ResponseWriter, r *http.Request) {
		id, _, ok := s.reverseIDs(r)
		if !ok {
			writeErr(w, 404, "逆向任务不存在")
			return
		}
		p, err := s.m.pg.ReverseRuntimePolicy(id)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		runs, err := s.m.pg.ListReverseRuntimeRuns(id)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"policy": p, "runs": runs})
	})
	mux.HandleFunc("PUT /api/tasks/{id}/reverse/runtime", func(w http.ResponseWriter, r *http.Request) {
		id, _, ok := s.reverseIDs(r)
		if !ok {
			writeErr(w, 404, "逆向任务不存在")
			return
		}
		var p db.ReverseRuntimePolicy
		if !decodeConversationRequest(w, r, &p) {
			return
		}
		profiles, err := reverseRuntimeProfiles()
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		known := map[string]bool{}
		for _, profile := range profiles {
			known[profile.ID] = true
		}
		for _, profileID := range p.ProfileIDs {
			if !known[profileID] {
				writeErr(w, 400, "运行环境不存在")
				return
			}
		}
		if err = s.m.pg.SetReverseRuntimePolicy(r.Context(), id, p); err != nil {
			writeErr(w, 409, err.Error())
			return
		}
		writeJSON(w, 200, p)
	})
}

func reverseDebugTool(pg *db.DB, task *db.Task, info agent.RunInfo, workDir string) actool.CoreTool {
	return reverseTool("reverse_observe_runtime", "在用户为当前任务授权的 Linux、Windows 或 Android 实验环境中启动并附加当前材料，运行有界 Frida 观察脚本，保存运行时证据并清理自有进程。不会附加任意既有进程。", reverseObject(map[string]any{"artifact_id": reverseInt(), "profile_id": reverseString(), "script": reverseString(), "argv": map[string]any{"type": "array", "items": reverseString()}, "package_name": reverseString(), "duration_ms": reverseInt()}, "artifact_id", "profile_id", "script", "duration_ms"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			ArtifactID  int64    `json:"artifact_id"`
			ProfileID   string   `json:"profile_id"`
			Script      string   `json:"script"`
			Argv        []string `json:"argv"`
			PackageName string   `json:"package_name"`
			DurationMS  int      `json:"duration_ms"`
		}
		if err := json.Unmarshal(in, &a); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		if len(a.Script) > 128*1024 || strings.TrimSpace(a.Script) == "" {
			return actool.Errorf("观察脚本不能为空，且不超过 128 KiB"), nil
		}
		profiles, err := reverseRuntimeProfiles()
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		var selected *reverseRuntimeProfile
		for i := range profiles {
			if profiles[i].ID == a.ProfileID {
				selected = &profiles[i]
				break
			}
		}
		if selected == nil {
			return actool.Errorf("运行环境未配置"), nil
		}
		artifact, err := pg.GetReverseArtifact(task.ID, a.ArtifactID)
		if err != nil || artifact == nil {
			return actool.Errorf("材料不存在"), nil
		}
		prefix := filepath.Join("tasks", strconv.FormatInt(task.ID, 10), "reverse")
		artifact.Path, err = reverseLocalPath(workDir, artifact.Path, filepath.Join(prefix, "artifacts"))
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		if err = verifyArtifact(artifact); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		runID, err := pg.BeginReverseRuntimeRun(ctx, task.ID, a.ArtifactID, info.IntentID, a.ProfileID, a.DurationMS)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		status, resultPath, message := "failed", "", "运行时观察未完成"
		defer func() { _ = pg.FinishReverseRuntimeRun(runID, status, resultPath, message) }()
		mapped := artifact.Path
		for _, mapping := range selected.PathMappings {
			from := strings.TrimRight(mapping.From, "/\\")
			if strings.HasPrefix(filepath.ToSlash(mapped), from+"/") {
				mapped = mapping.To + strings.TrimPrefix(filepath.ToSlash(mapped), from)
				break
			}
		}
		runCtx, cancel := context.WithTimeout(ctx, time.Duration(a.DurationMS)*time.Millisecond+120*time.Second)
		defer cancel()
		raw, runErr := invokeReverseRuntime(runCtx, *selected, map[string]any{"operation": "observe", "artifact_path": mapped, "sha256": artifact.SHA256, "script": a.Script, "argv": a.Argv, "package_name": a.PackageName, "duration_ms": a.DurationMS})
		var observation map[string]any
		decodeErr := json.Unmarshal(raw, &observation)
		if decodeErr != nil && len(raw) > 0 {
			observation = map[string]any{"runner_output": string(raw)}
		}
		if runErr == nil && (decodeErr != nil || observation["error"] != nil) {
			runErr = errors.New("运行器返回错误，未取得有效运行时证据")
		}
		if runErr == nil {
			runErr = reverseRuntimeObservationError(observation, selected.Platform, artifact.SHA256, a.Script)
		}
		record := map[string]any{"isError": runErr != nil, "structuredContent": map[string]any{"operation": "reverse_observe_runtime", "provider": map[string]any{"name": "Frida", "version": observation["version"]}, "subject": map[string]any{"digest": map[string]any{"sha256": artifact.SHA256}, "name": artifact.Name}, "normalized_result": observation, "confidence": "observed", "authority": "controlled-replay"}}
		encoded, _ := json.Marshal(record)
		dir := filepath.Join(workDir, prefix, "results")
		if err = os.MkdirAll(dir, 0700); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		file, err := os.CreateTemp(dir, "runtime-*.json")
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		_ = file.Chmod(0600)
		_, err = file.Write(encoded)
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			return actool.Errorf("运行时证据保存失败"), nil
		}
		rel, _ := filepath.Rel(workDir, file.Name())
		resultPath = filepath.ToSlash(rel)
		if runErr == nil {
			status, message = "completed", ""
		} else {
			message = runErr.Error()
			if ctx.Err() != nil {
				status = "cancelled"
			}
		}
		response := reverseJSON(map[string]any{"run_id": runID, "status": status, "result_path": resultPath, "bytes": len(encoded), "preview": reaPreview(json.RawMessage(encoded)), "message": message})
		response.IsError = runErr != nil
		return response, nil
	})
}
