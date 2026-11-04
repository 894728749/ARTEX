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
	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/reamcp"
	actool "github.com/Autumn-27/norma/tool"
)

func reaCommand() (string, []string, error) {
	command := strings.TrimSpace(os.Getenv("ARTEX_REA_COMMAND"))
	if command == "" {
		command = "rea"
		local := filepath.Join(config.BaseDir(), "tools", "node_modules", ".bin", "rea")
		if info, err := os.Stat(local); err == nil && !info.IsDir() {
			command = local
		}
	}
	path, err := exec.LookPath(command)
	if err != nil {
		return "", nil, errors.New("未找到 REA，请安装 rea-agents 并配置 ARTEX_REA_COMMAND")
	}
	args := []string{"mcp"}
	if raw := os.Getenv("ARTEX_REA_ARGS"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &args); err != nil || len(args) == 0 {
			return "", nil, errors.New("ARTEX_REA_ARGS 必须为非空 JSON 字符串数组")
		}
	}
	return path, args, nil
}

func newREASession(ctx context.Context, dir string, progress func(string)) (*reamcp.Client, error) {
	command, args, err := reaCommand()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return reamcp.New(ctx, command, args, dir, []string{"PATH=" + filepath.Dir(command) + string(os.PathListSeparator) + os.Getenv("PATH"), "REA_MCP_TOOL_FAMILIES=application,session,android,managed,native,direct,artifact", "REA_MCP_INPUT_SCHEMA_PROFILE=full", "REA_MCP_MAX_RESPONSE_BYTES=16777216"}, progress)
}

type reverseReadiness struct {
	Available   bool                     `json:"available"`
	Command     string                   `json:"command"`
	Version     string                   `json:"version"`
	ToolCount   int                      `json:"tool_count"`
	Formats     []string                 `json:"formats"`
	Limitations []string                 `json:"limitations"`
	Error       string                   `json:"error,omitempty"`
	Engines     []reverseEngineReadiness `json:"engines"`
}

type reverseEngineReadiness struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

func reverseEngineStatus(raw json.RawMessage) []reverseEngineReadiness {
	var result struct {
		Structured struct {
			Result struct {
				Availability struct {
					Groups []struct {
						Names     []string `json:"names"`
						Available bool     `json:"available"`
						Reason    string   `json:"reason"`
					} `json:"groups"`
				} `json:"tool_availability"`
				Candidates []struct {
					Provider struct {
						ID string `json:"id"`
					} `json:"provider"`
					Availability struct {
						Status string `json:"status"`
						Reason string `json:"reason"`
					} `json:"availability"`
				} `json:"analysis_provider_candidates"`
			} `json:"result"`
		} `json:"structuredContent"`
	}
	_ = json.Unmarshal(raw, &result)
	engines := []reverseEngineReadiness{{ID: "javascript", Name: "JavaScript / REA"}, {ID: "android", Name: "APK / JADX"}, {ID: "managed", Name: ".NET / 元数据与 IL"}, {ID: "native", Name: "原生 / Ghidra"}}
	for i, tool := range []string{"analyze_javascript_application", "inspect_android_method", "inspect_managed_members"} {
		for _, group := range result.Structured.Result.Availability.Groups {
			for _, name := range group.Names {
				if name == tool {
					engines[i].Available = group.Available
					engines[i].Reason = group.Reason
				}
			}
		}
	}
	for _, candidate := range result.Structured.Result.Candidates {
		if candidate.Provider.ID == "ghidra" {
			engines[3].Available = candidate.Availability.Status == "available"
			engines[3].Reason = candidate.Availability.Reason
		}
	}
	return engines
}

func (s *Server) reverseRuntimeRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/reverse/readiness", func(w http.ResponseWriter, r *http.Request) {
		ready := reverseReadiness{Formats: []string{}, Engines: []reverseEngineReadiness{}, Limitations: []string{"就绪检查表示引擎可调用；具体样本仍需分析并独立复核。", "静态分析不会执行上传材料；运行时观察需单独选择材料并授权实验环境。"}}
		command, _, err := reaCommand()
		ready.Command = filepath.Base(command)
		if err == nil {
			ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
			defer cancel()
			var client *reamcp.Client
			client, err = newREASession(ctx, filepath.Join(s.m.dir, "reverse-readiness"), nil)
			if err == nil {
				defer client.Close()
				ready.Version = client.Version
				var tools []reamcp.Tool
				tools, err = client.Tools(ctx)
				for _, tool := range tools {
					if reverseStaticToolAllowed(tool.Name) {
						ready.ToolCount++
					}
				}
				if err == nil {
					var state json.RawMessage
					state, err = client.Call(ctx, "binary_session", map[string]any{})
					if err == nil {
						ready.Engines = reverseEngineStatus(state)
						formats := map[string][]string{"javascript": {"js", "mjs", "cjs"}, "android": {"apk"}, "managed": {".NET exe/dll"}, "native": {"PE", "ELF", "Mach-O"}}
						for _, engine := range ready.Engines {
							if engine.Available {
								ready.Available = true
								ready.Formats = append(ready.Formats, formats[engine.ID]...)
							}
						}
					}
				}
			}
		}
		if err != nil {
			ready.Error = err.Error()
		}
		writeJSON(w, 200, ready)
	})
	mux.HandleFunc("GET /api/tasks/{id}/reverse/report", s.reverseReport)
}

func (s *Server) reverseReport(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok || t.Kind != "reverse" {
		writeErr(w, 404, "reverse task not found")
		return
	}
	id, _ := strconv.ParseInt(t.ID, 10, 64)
	artifacts, err := s.m.pg.ListReverseArtifacts(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	conclusions, err := s.m.pg.ListReverseConclusions(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# 逆向分析档案\n\n任务：%s\n\n分析问题：%s\n\n导出状态：%s\n\n## 材料\n\n", t.Name, t.Goal, s.resolvedTaskStatus(t))
	for _, a := range artifacts {
		fmt.Fprintf(&b, "- %s；格式 %s；版本 %s；大小 %d 字节；SHA256 `%s`\n", a.Name, a.Format, a.Version, a.SizeBytes, a.SHA256)
	}
	if len(artifacts) == 0 {
		b.WriteString("尚未上传材料。\n")
	}
	b.WriteString("\n## 分析结论\n\n")
	labels := map[string]string{"proposed": "待核验", "accepted": "已核验接受", "rejected": "已驳回", "unresolved": "未解决"}
	for _, c := range conclusions {
		clean := func(text string) string {
			return strings.ReplaceAll(reversePortableText(text, s.m.dir, t.ID, artifacts), fmt.Sprintf("结论 #%d", c.ID), "本结论")
		}
		fmt.Fprintf(&b, "### %s\n\n状态：%s\n\n%s\n\n", clean(c.Question), labels[c.State], clean(c.Answer))
		for _, ev := range c.Evidence {
			for _, a := range artifacts {
				if a.ID == ev.ArtifactID {
					fmt.Fprintf(&b, "- 材料：%s（SHA256 %s）；定位：%s；观察：%s\n", a.Name, a.SHA256, clean(ev.Locator), clean(ev.Observation))
				}
			}
		}
		fmt.Fprintf(&b, "\n局限：%s\n\n核验说明：%s\n\n", clean(c.Limitations), clean(c.Review))
	}
	if len(conclusions) == 0 {
		b.WriteString("尚未提交结论。\n")
	}
	b.WriteString("\n未核验与未解决项不作为已证实结论；报告状态不代表整个程序已被完整理解。\n")
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="reverse-analysis.md"`)
	_, _ = io.WriteString(w, b.String())
}

func reversePortableText(text, workDir, taskID string, artifacts []db.ReverseArtifact) string {
	for _, a := range artifacts {
		for _, path := range []string{filepath.Join(workDir, a.Path), filepath.ToSlash(filepath.Join(workDir, a.Path)), a.Path, filepath.ToSlash(a.Path)} {
			if path != "" {
				text = strings.ReplaceAll(text, path, a.Name)
			}
		}
		label := regexp.MustCompile(`\b(?:artifact id|artifact_id)\s*[:=]\s*` + strconv.FormatInt(a.ID, 10) + `\b`)
		text = label.ReplaceAllStringFunc(text, func(string) string { return "工件 " + a.Name })
	}
	for _, prefix := range []string{filepath.ToSlash(filepath.Join(workDir, "tasks", taskID, "reverse", "results")) + "/", filepath.ToSlash(filepath.Join("tasks", taskID, "reverse", "results")) + "/"} {
		text = strings.ReplaceAll(text, prefix, "evidence/")
	}
	text = strings.ReplaceAll(text, filepath.ToSlash(filepath.Join(workDir, "tasks", taskID))+"/", "")
	return text
}

func reverseObject(properties map[string]any, required ...string) map[string]any {
	schema := map[string]any{"type": "object", "properties": properties}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}
func reverseString() map[string]any { return map[string]any{"type": "string"} }
func reverseInt() map[string]any    { return map[string]any{"type": "integer"} }
func reverseJSON(v any) actool.Result {
	b, err := json.Marshal(v)
	if err != nil {
		return actool.Errorf(err.Error())
	}
	return actool.Text(string(b))
}
func reverseTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{Name: name, Description: desc, Schema: schema, Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
		return run(ctx, in)
	}})
}

func verifyArtifact(a *db.ReverseArtifact) error {
	if a == nil {
		return errors.New("材料不存在")
	}
	f, err := os.Open(a.Path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return err
	}
	if n != a.SizeBytes || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		return errors.New("材料已变化，与建档 SHA256 不符；请重新上传新版本")
	}
	return nil
}

// reverseAgentTools replaces the pentest skill/MCP augmentation for reverse
// tasks. The REA process is lazy, private to this run and killed on cleanup.
func reverseAgentTools(ctx context.Context, pg *db.DB, task *db.Task, workDir, role string) ([]actool.CoreTool, agent.DeferredInfo, func()) {
	info := agent.RunInfoFrom(ctx)
	taskDir := filepath.Join(workDir, "tasks", strconv.FormatInt(task.ID, 10), "reverse")
	resultDir := filepath.Join(taskDir, "results")
	var mu sync.Mutex
	var client *reamcp.Client
	var catalog []reamcp.Tool
	connect := func(callCtx context.Context) (*reamcp.Client, []reamcp.Tool, error) {
		mu.Lock()
		defer mu.Unlock()
		if client != nil {
			return client, catalog, nil
		}
		cl, err := newREASession(ctx, taskDir, nil)
		if err != nil {
			return nil, nil, err
		}
		ts, err := cl.Tools(callCtx)
		if err != nil {
			_ = cl.Close()
			return nil, nil, err
		}
		client, catalog = cl, ts
		return cl, ts, nil
	}
	cleanup := func() {
		mu.Lock()
		defer mu.Unlock()
		if client != nil {
			_ = client.Close()
		}
	}
	call := func(callCtx context.Context, name string, args map[string]any) (actool.Result, error) {
		if !reverseStaticToolAllowed(name) {
			return actool.Errorf("此工具不属于静态分析能力；运行时观察必须使用独立、已授权的调试环境"), nil
		}
		if err := validateReverseStaticPaths(args, taskDir); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		cl, tools, err := connect(callCtx)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		found := false
		for _, t := range tools {
			if t.Name == name {
				found = true
				break
			}
		}
		if !found {
			return actool.Errorf("工具不在当前 REA 目录中，请先 rea_catalog"), nil
		}
		if err := os.MkdirAll(resultDir, 0700); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		f, err := os.CreateTemp(resultDir, "rea-*.json")
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		_ = f.Chmod(0600)
		raw, err := cl.Call(callCtx, name, args)
		if err != nil {
			_ = f.Close()
			_ = os.Remove(f.Name())
			return actool.Errorf(err.Error()), nil
		}
		_, writeErr := f.Write(raw)
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil {
			return actool.Errorf("无法保存完整 REA 证据"), nil
		}
		var result struct {
			IsError bool                          `json:"isError"`
			Content []struct{ Type, Text string } `json:"content"`
		}
		_ = json.Unmarshal(raw, &result)
		text := reaPreview(raw)
		rel, _ := filepath.Rel(workDir, f.Name())
		response := reverseJSON(map[string]any{"is_error": result.IsError, "tool": name, "result_path": filepath.ToSlash(rel), "bytes": len(raw), "preview": text, "note": "完整 MCP result 已保存，包含 structuredContent；会话 evidence_id 不可代替这个持久引用。"})
		response.IsError = result.IsError
		return response, nil
	}
	tools := []actool.CoreTool{reverseTool("reverse_workspace", "读取本逆向任务的材料、结论和对应本地分析路径。工件必须核对哈希；结果路径相对 ARTEX 工作空间。", reverseObject(map[string]any{}), func(_ context.Context, _ json.RawMessage) (actool.Result, error) {
		as, err := pg.ListReverseArtifacts(task.ID)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		cs, err := pg.ListReverseConclusions(task.ID)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		items := []map[string]any{}
		for _, a := range as {
			items = append(items, map[string]any{"artifact": a, "local_path": filepath.Join(workDir, a.Path)})
		}
		policy, _ := pg.ReverseRuntimePolicy(task.ID)
		environments := []map[string]any{}
		profiles, profileErr := reverseRuntimeProfiles()
		for _, profile := range profiles {
			for _, allowed := range policy.ProfileIDs {
				if profile.ID == allowed {
					environments = append(environments, map[string]any{"id": profile.ID, "name": profile.Name, "platform": profile.Platform, "java_api": profile.Settings["java_bridge_module"] != nil})
					break
				}
			}
		}
		out := map[string]any{"artifacts": items, "conclusions": cs, "task_goal": task.Goal, "runtime_policy": policy, "runtime_environments": environments, "result_directory": resultDir, "material_state": map[bool]string{true: "available", false: "missing"}[len(as) > 0]}
		if profileErr != nil {
			out["runtime_profile_error"] = profileErr.Error()
		}
		return reverseJSON(out), nil
	})}
	if role == "worker" {
		tools = append(tools, reverseEvidenceViewTool(task.ID, workDir))
		tools = append(tools, reverseTool("rea_catalog", "查询此工作单独立 REA 会话的真实工具名称和输入 schema；query 用工具名/关键词，limit 最大 10。目录存在不代表外部引擎可用。", reverseObject(map[string]any{"query": reverseString(), "offset": reverseInt(), "limit": reverseInt()}), func(callCtx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Query         string
				Offset, Limit int
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			_, all, err := connect(callCtx)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			matches := []reamcp.Tool{}
			q := strings.ToLower(a.Query)
			for _, t := range all {
				if reverseStaticToolAllowed(t.Name) && (q == "" || strings.Contains(strings.ToLower(t.Name+" "+t.Description), q)) {
					matches = append(matches, t)
				}
			}
			if a.Offset < 0 {
				a.Offset = 0
			}
			if a.Offset > len(matches) {
				a.Offset = len(matches)
			}
			if a.Limit < 1 || a.Limit > 10 {
				a.Limit = 5
			}
			end := min(len(matches), a.Offset+a.Limit)
			return reverseJSON(map[string]any{"tools": matches[a.Offset:end], "total": len(matches), "next_offset": end, "session_scope": "本工作单专属，会在结束时关闭"}), nil
		}), reverseTool("rea_call", "调用 rea_catalog 已列出的工具，arguments 使用真实 schema。完整结果先保存到任务证据目录，再返回摘要。默认静态分析；禁止执行样本或自动访问材料中的网络地址。", reverseObject(map[string]any{"name": reverseString(), "arguments": map[string]any{"type": "object"}}, "name", "arguments"), func(callCtx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Name      string
				Arguments map[string]any
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return call(callCtx, a.Name, a.Arguments)
		}), reverseTool("rea_analyze_artifact", "核对工件 SHA256 并自动选择 JS、APK/JADX、.NET 元数据或原生 Ghidra 静态分析路线；不执行样本。原生打开后用 binary_overview/analyze_function 深入。", reverseObject(map[string]any{"artifact_id": reverseInt()}, "artifact_id"), func(callCtx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ID int64 `json:"artifact_id"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			artifact, err := pg.GetReverseArtifact(task.ID, a.ID)
			if err == nil && artifact != nil {
				artifact.Path, err = reverseLocalPath(workDir, artifact.Path, filepath.Join("tasks", strconv.FormatInt(task.ID, 10), "reverse", "artifacts"))
			}
			if err == nil {
				err = verifyArtifact(artifact)
			}
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			family, err := reverseArtifactFamily(artifact.Path, artifact.Format)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			dir := filepath.Join(taskDir, "workspaces", fmt.Sprintf("i%d", info.IntentID), fmt.Sprintf("a%d", a.ID))
			if err := os.MkdirAll(dir, 0700); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			data, err := os.ReadFile(artifact.Path)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			staged := filepath.Join(dir, "sample."+artifact.Format)
			if err := os.WriteFile(staged, data, 0600); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			name, args := reverseStaticArguments(family, staged)
			return call(callCtx, name, args)
		}))
		tools = append(tools, reverseConclusionTools(pg, task, info, workDir)...)
		tools = append(tools, reverseDebugTool(pg, task, info, workDir))
	}
	return tools, agent.DeferredInfo{}, cleanup
}
