package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/artex/teamsetup"
	"github.com/Autumn-27/norma/llm"
)

// ConfigureTeamOnboarding is called before the main HTTP listener starts.
func (s *Server) ConfigureTeamOnboarding(ctx context.Context, dataDir, binaryDir string, external bool) func() {
	s.teamAccess = teamsetup.New(ctx, filepath.Join(dataDir, "team-access"), binaryDir, BuildVersion, teamsetup.Detect(ctx), external, s.TeamHandler())
	return s.teamAccess.Close
}
func (s *Server) teamOnboardingRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/teams/{team}/onboarding", s.onboardingStatus)
	m.HandleFunc("POST /api/teams/{team}/onboarding/plan", s.onboardingPlan)
	m.HandleFunc("POST /api/teams/{team}/onboarding/apply", s.onboardingApply)
	m.HandleFunc("POST /api/teams/{team}/onboarding/disable", s.onboardingDisable)
	m.HandleFunc("POST /api/teams/{team}/onboarding/assist", s.onboardingAssist)
	m.HandleFunc("GET /api/teams/{team}/onboarding/bundle", s.onboardingBundle)
	m.HandleFunc("GET /api/teams/{team}/onboarding/host-script", s.onboardingHostScript)
}
func (s *Server) onboardingScope(w http.ResponseWriter, r *http.Request, admin bool) (teamIdentity, int64, bool) {
	w.Header().Set("Cache-Control", "no-store")
	p, id, ok := s.teamScope(w, r, admin)
	if !ok {
		return p, id, false
	}
	if s.m.pg == nil {
		writeErr(w, 503, "数据库不可用")
		return p, id, false
	}
	var exists bool
	if err := s.m.pg.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT 1 FROM teams WHERE id=$1)`, id).Scan(&exists); err != nil {
		writeErr(w, 503, "无法读取团队")
		return p, id, false
	}
	if !exists {
		writeErr(w, 404, "团队不存在")
		return p, id, false
	}
	if s.teamAccess == nil {
		writeErr(w, 503, "接入向导尚未初始化，请使用完整主程序启动")
		return p, id, false
	}
	return p, id, true
}
func onboardingDecode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		writeErr(w, 400, "请求字段无效")
		return false
	}
	return true
}

type onboardingCheck struct {
	Code   string `json:"code"`
	Status string `json:"status"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}
type onboardingDevice struct {
	ID               int64  `json:"id"`
	Name             string `json:"name"`
	Online           bool   `json:"online"`
	ExecutionEnabled bool   `json:"execution_enabled"`
	BranchProtocol   int    `json:"branch_protocol"`
	RoleCount        int    `json:"role_count"`
}

func onboardingChecks(state teamsetup.State, platforms []string) []onboardingCheck {
	out := []onboardingCheck{}
	switch {
	case state.External:
		out = append(out, onboardingCheck{"external", "manual", "入口由启动参数管理", "保留现有 TLS/Relay；使用高级手动配置，向导不会覆盖。"})
	case state.Error != "":
		out = append(out, onboardingCheck{"listener_error", "error", "成员入口未就绪", state.Error})
	case !state.Enabled:
		out = append(out, onboardingCheck{"prepare", "pending", "准备成员入口", "选择本机局域网地址，预览方案后开启。入口由所有团队共用。"})
	default:
		out = append(out, onboardingCheck{"local_tls", "ok", "本机 TLS 已通过", "这只证明本机入口可用，成员实际连接后才能确认跨设备可达。"})
	}
	if state.NeedsHostBridge && state.Enabled {
		out = append(out, onboardingCheck{"host_bridge", "manual", "Windows 主机需要桥接", "下载固定脚本，由主机管理员以 -Apply 运行；默认只预览。向导不会更改主机防火墙。"})
	}
	if len(platforms) == 0 {
		out = append(out, onboardingCheck{"node_assets", "error", "缺少匹配版本的接入资源", "安装同版本完整发行包中的 node-binaries，或使用高级手动接入。"})
	}
	out = append(out, onboardingCheck{"permissions", "manual", "配对与任务执行分别授权", "配对不分配任务。成员模型密钥和外部工具只在成员本机配置，主端另行授权任务/分支。"})
	return out
}
func (s *Server) onboardingStatus(w http.ResponseWriter, r *http.Request) {
	p, team, ok := s.onboardingScope(w, r, false)
	if !ok {
		return
	}
	devices := []onboardingDevice{}
	rows, err := s.m.pg.QueryContext(r.Context(), `SELECT d.id,d.name,COALESCE(d.last_seen_at>now()-interval '30 seconds',false),d.capabilities FROM team_devices d JOIN team_members m ON m.id=d.owner_member_id WHERE d.team_id=$1 AND ($2::bigint=0 OR d.owner_member_id=$2) AND d.revoked_at IS NULL AND m.revoked_at IS NULL ORDER BY d.id`, team, p.MemberID)
	if err != nil {
		writeErr(w, 503, "读取接入设备失败")
		return
	}
	defer rows.Close()
	for rows.Next() {
		var d onboardingDevice
		var raw []byte
		if rows.Scan(&d.ID, &d.Name, &d.Online, &raw) != nil {
			writeErr(w, 503, "读取接入设备失败")
			return
		}
		var caps struct {
			ExecutionEnabled bool     `json:"execution_enabled"`
			BranchProtocol   int      `json:"branch_protocol"`
			Roles            []string `json:"roles"`
		}
		_ = json.Unmarshal(raw, &caps)
		d.ExecutionEnabled = caps.ExecutionEnabled
		d.BranchProtocol = caps.BranchProtocol
		d.RoleCount = len(caps.Roles)
		devices = append(devices, d)
	}
	if rows.Err() != nil {
		writeErr(w, 503, "读取接入设备失败")
		return
	}
	state := s.teamAccess.State()
	env := s.teamAccess.Environment()
	platforms := s.teamAccess.Platforms()
	if !p.Admin {
		env = teamsetup.Environment{Addresses: []teamsetup.Address{}}
		state.ListenAddress = ""
		state.AllowedCIDR = ""
		state.Error = ""
	}
	s.cfgMu.Lock()
	ai := s.llmProv != nil
	s.cfgMu.Unlock()
	writeJSON(w, 200, map[string]any{"admin": p.Admin, "environment": env, "state": state, "platforms": platforms, "ai_available": ai && p.Admin, "devices": devices, "checks": onboardingChecks(state, platforms)})
}
func (s *Server) onboardingPlan(w http.ResponseWriter, r *http.Request) {
	_, team, ok := s.onboardingScope(w, r, true)
	if !ok {
		return
	}
	var in teamsetup.Input
	if !onboardingDecode(w, r, &in) {
		return
	}
	plan, err := s.teamAccess.Prepare(team, in)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, plan)
}
func (s *Server) onboardingApply(w http.ResponseWriter, r *http.Request) {
	_, team, ok := s.onboardingScope(w, r, true)
	if !ok {
		return
	}
	var in struct {
		PlanID  string `json:"plan_id"`
		Confirm bool   `json:"confirm"`
	}
	if !onboardingDecode(w, r, &in) {
		return
	}
	if !in.Confirm {
		writeErr(w, 400, "请先确认接入方案")
		return
	}
	state, err := s.teamAccess.Apply(r.Context(), team, in.PlanID)
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, state)
}
func (s *Server) onboardingDisable(w http.ResponseWriter, r *http.Request) {
	_, _, ok := s.onboardingScope(w, r, true)
	if !ok {
		return
	}
	var in struct {
		Confirm bool `json:"confirm"`
	}
	if !onboardingDecode(w, r, &in) {
		return
	}
	if !in.Confirm {
		writeErr(w, 400, "停用会断开所有团队的受管连接，请确认")
		return
	}
	state, err := s.teamAccess.Disable()
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, state)
}
func (s *Server) onboardingBundle(w http.ResponseWriter, r *http.Request) {
	_, team, ok := s.onboardingScope(w, r, false)
	if !ok {
		return
	}
	b, err := s.teamAccess.Bundle(team, r.URL.Query().Get("platform"))
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="artex-member.zip"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(b)
}
func (s *Server) onboardingHostScript(w http.ResponseWriter, r *http.Request) {
	_, _, ok := s.onboardingScope(w, r, true)
	if !ok {
		return
	}
	b, err := s.teamAccess.HostScript()
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="artex-host-bridge.ps1"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(b)
}

type onboardingAdvice struct {
	Source            string   `json:"source"`
	Summary           string   `json:"summary"`
	Steps             []string `json:"steps"`
	RecommendedAction string   `json:"recommended_action"`
}

var onboardingIssues = map[string]bool{"explain": true, "tls": true, "unreachable": true, "model": true, "tools": true, "pairing": true}
var onboardingActions = map[string]bool{"prepare": true, "host_bridge": true, "download": true, "pair": true, "configure_models": true, "configure_tools": true, "refresh": true}

func adviceFallback(issue string, state teamsetup.State, assets bool) onboardingAdvice {
	a := onboardingAdvice{Source: "checks", Summary: "按当前检测结果继续接入；AI 不会执行系统命令。", Steps: []string{}, RecommendedAction: "refresh"}
	switch {
	case issue == "model":
		a.RecommendedAction = "configure_models"
		a.Steps = []string{"在成员本机 setup 输入模型配置，密钥只进入当前进程环境。", "配置验证不代表模型已实际调用；接入不会使用主端密钥。"}
	case issue == "tools":
		a.RecommendedAction = "configure_tools"
		a.Steps = []string{"在成员本机配置允许的 MCP 或命令，并显式绑定角色。", "角色生成不会自动授权外部工具；渗透与逆向角色保持独立。"}
	case state.External:
		a.Steps = []string{"当前入口由启动参数管理，请使用高级手动接入。", "保留已有 LAN/Relay 地址与证书，不使用向导覆盖。"}
	case !state.Enabled:
		a.RecommendedAction = "prepare"
		a.Steps = []string{"选择检测到的局域网地址和允许网段。", "生成方案，确认后启动受限成员入口。"}
	case issue == "tls":
		a.RecommendedAction = "download"
		a.Steps = []string{"重新获取当前接入包，通过独立渠道核对证书 SHA256。", "Node 使用包内公开证书；浏览器证书信任需单独处理，不要关闭 TLS 校验。"}
	case issue == "pairing":
		a.RecommendedAction = "pair"
		a.Steps = []string{"为正确成员生成一次性配对码，在成员本机 setup 输入。", "成功配对后复用已有身份；未启动 Node 时设备可能不在线。"}
	case state.NeedsHostBridge:
		a.RecommendedAction = "host_bridge"
		a.Steps = []string{"主机管理员先预览固定脚本，再通过 -Apply 创建指定网段和端口的转发。", "本机 TLS 通过不等于成员可达；运行成员接入包后刷新设备状态。"}
	case !assets:
		a.Steps = []string{"当前缺少同版本 Node 资源，安装完整发行包或按高级说明手动接入。"}
	default:
		a.RecommendedAction = "download"
		a.Steps = []string{"选择成员操作系统，下载并解压接入包。", "成员运行启动脚本，核对证书并输入单独提供的配对码。", "跨网需要已配置的 Relay 或 VPN；LAN 成功不表示跨网已就绪。"}
	}
	return a
}
func boundedOnboardingAdvice(ctx context.Context, prov llm.Provider, facts any) (onboardingAdvice, error) {
	raw, _ := json.Marshal(facts)
	temp := 0.0
	req := llm.CompletionRequest{System: []string{"你是 ARTEX 接入向导。只解释提供的结构化检测事实，不声称已完成远端测试，不编写系统命令或请求密钥。LAN 向导不自动搭建 Relay。配对不等于任务权限，角色存在不等于工具已可用。仅返回 JSON: {\"summary\":\"简短说明\",\"steps\":[\"最多5条具体步骤\"],\"recommended_action\":\"prepare|host_bridge|download|pair|configure_models|configure_tools|refresh\"}。不要 Markdown。"}, Messages: []llm.Message{llm.UserText(string(raw))}, MaxTokens: 800, Temperature: &temp, Thinking: "disabled"}
	var text strings.Builder
	for ev, err := range prov.Stream(ctx, req) {
		if err != nil {
			return onboardingAdvice{}, err
		}
		if ctx.Err() != nil {
			return onboardingAdvice{}, ctx.Err()
		}
		if ev.Type == llm.SETextDelta {
			if text.Len()+len(ev.Text) > 8192 {
				return onboardingAdvice{}, errors.New("response too large")
			}
			text.WriteString(ev.Text)
		}
	}
	var a onboardingAdvice
	d := json.NewDecoder(strings.NewReader(text.String()))
	d.DisallowUnknownFields()
	if d.Decode(&a) != nil || d.Decode(new(any)) != io.EOF || len(a.Summary) == 0 || len(a.Summary) > 1200 || len(a.Steps) == 0 || len(a.Steps) > 5 || !onboardingActions[a.RecommendedAction] {
		return a, errors.New("invalid advice")
	}
	for _, step := range a.Steps {
		if len(step) == 0 || len(step) > 1200 {
			return a, errors.New("invalid step")
		}
	}
	a.Source = "ai"
	return a, nil
}
func (s *Server) onboardingAssist(w http.ResponseWriter, r *http.Request) {
	_, _, ok := s.onboardingScope(w, r, true)
	if !ok {
		return
	}
	var in struct {
		Issue string `json:"issue"`
	}
	if !onboardingDecode(w, r, &in) {
		return
	}
	if !onboardingIssues[in.Issue] {
		writeErr(w, 400, "请选择预设诊断项")
		return
	}
	state := s.teamAccess.State()
	env := s.teamAccess.Environment()
	platforms := s.teamAccess.Platforms()
	answer := adviceFallback(in.Issue, state, len(platforms) > 0)
	s.cfgMu.Lock()
	prov := s.llmProv
	s.cfgMu.Unlock()
	if prov != nil {
		if !s.onboardingAI.TryLock() {
			writeErr(w, 429, "接入建议正在生成，请稍后重试")
			return
		}
		defer s.onboardingAI.Unlock()
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		// No addresses, names, paths, logs, credentials, task context or tool handles.
		facts := map[string]any{"issue": in.Issue, "os": env.OS, "arch": env.Arch, "wsl": env.WSL, "managed_enabled": state.Enabled, "external_entry": state.External, "needs_host_bridge": state.NeedsHostBridge, "local_tls_verified": state.LocalTLSVerified, "matching_node_assets": len(platforms) > 0, "remote_reachability": "not_verified", "deterministic_recommendation": answer}
		if generated, err := boundedOnboardingAdvice(llmrec.WithWorker(ctx, "team-onboarding"), prov, facts); err == nil {
			answer = generated
		} else {
			answer.Summary = "AI 建议暂不可用，以下为当前检测结果对应的固定步骤。"
		}
	}
	writeJSON(w, 200, answer)
}
