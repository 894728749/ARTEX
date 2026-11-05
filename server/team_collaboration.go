package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type teamIdentity struct {
	Admin            bool
	TeamID, MemberID int64
}
type teamIdentityKey struct{}

func (s *Server) teamPrincipal(r *http.Request) (teamIdentity, bool) {
	parsed, err := jwt.Parse(extractToken(r), func(t *jwt.Token) (any, error) { return s.jwtKey, nil }, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !parsed.Valid {
		return teamIdentity{}, false
	}
	sub, err := parsed.Claims.GetSubject()
	if err != nil {
		return teamIdentity{}, false
	}
	if sub == "ARTEX" {
		return teamIdentity{Admin: true}, true
	}
	parts := strings.Split(sub, ":")
	if len(parts) != 3 || parts[0] != "team" || s.m.pg == nil {
		return teamIdentity{}, false
	}
	team, e1 := strconv.ParseInt(parts[1], 10, 64)
	member, e2 := strconv.ParseInt(parts[2], 10, 64)
	if e1 != nil || e2 != nil || team < 1 || member < 1 {
		return teamIdentity{}, false
	}
	m, err := s.m.pg.GetTeamMember(r.Context(), team, member)
	return teamIdentity{TeamID: team, MemberID: member}, err == nil && !m.Revoked
}

// Team credentials never grant access to legacy system-wide administration.
// The team workspace exposes only explicitly shared tasks and owned devices.
func (s *Server) authorizeTeamPrincipal(w http.ResponseWriter, r *http.Request) bool {
	p, ok := s.teamPrincipal(r)
	if !ok {
		writeErr(w, 401, "身份已失效")
		return false
	}
	if p.Admin {
		return true
	}
	if r.URL.Path == "/api/teams" && r.Method == http.MethodGet {
		return true
	}
	if strings.HasPrefix(r.URL.Path, "/api/teams/") {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 && parts[2] == strconv.FormatInt(p.TeamID, 10) {
			return true
		}
	}
	writeErr(w, 403, "此身份只能访问获授权的团队工作区")
	return false
}

func (s *Server) teamScope(w http.ResponseWriter, r *http.Request, adminOnly bool) (teamIdentity, int64, bool) {
	p, ok := s.teamPrincipal(r)
	if !ok {
		writeErr(w, 401, "身份已失效")
		return p, 0, false
	}
	team, err := strconv.ParseInt(r.PathValue("team"), 10, 64)
	if err != nil || team < 1 {
		writeErr(w, 400, "团队编号无效")
		return p, 0, false
	}
	if (!p.Admin && p.TeamID != team) || (adminOnly && !p.Admin) {
		writeErr(w, 403, "没有此操作权限")
		return p, 0, false
	}
	return p, team, true
}

func (s *Server) teamLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		TeamID   int64  `json:"team_id"`
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if decode(r, &in) != nil || s.m.pg == nil {
		writeErr(w, 400, "登录信息无效")
		return
	}
	id, hash, err := s.m.pg.TeamMemberCredentials(r.Context(), in.TeamID, in.Login)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Password)) != nil {
		writeErr(w, 401, "团队、账号或密码错误")
		return
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{Subject: "team:" + strconv.FormatInt(in.TeamID, 10) + ":" + strconv.FormatInt(id, 10), IssuedAt: jwt.NewNumericDate(time.Now()), ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtTTL))}).SignedString(s.jwtKey)
	if err != nil {
		writeErr(w, 500, "生成登录凭据失败")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"token": token})
}

func (s *Server) teamList(w http.ResponseWriter, r *http.Request) {
	p, ok := s.teamPrincipal(r)
	if !ok {
		writeErr(w, 401, "身份已失效")
		return
	}
	items, err := s.m.pg.ListTeams(r.Context(), p.MemberID)
	if err != nil {
		writeErr(w, 500, "读取团队失败")
		return
	}
	writeJSON(w, 200, map[string]any{"teams": items, "is_admin": p.Admin})
}
func (s *Server) teamCreate(w http.ResponseWriter, r *http.Request) {
	p, ok := s.teamPrincipal(r)
	if !ok || !p.Admin {
		writeErr(w, 403, "需要管理员身份")
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if decode(r, &in) != nil {
		writeErr(w, 400, "团队名称无效")
		return
	}
	v, err := s.m.pg.CreateTeam(r.Context(), in.Name)
	if err != nil {
		writeErr(w, 400, "创建团队失败，请检查名称")
		return
	}
	writeJSON(w, 201, v)
}
func (s *Server) teamMembers(w http.ResponseWriter, r *http.Request) {
	_, team, ok := s.teamScope(w, r, false)
	if !ok {
		return
	}
	items, err := s.m.pg.ListTeamMembers(r.Context(), team)
	if err != nil {
		writeErr(w, 500, "读取成员失败")
		return
	}
	writeJSON(w, 200, items)
}
func (s *Server) teamMemberCreate(w http.ResponseWriter, r *http.Request) {
	_, team, ok := s.teamScope(w, r, true)
	if !ok {
		return
	}
	var in struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if decode(r, &in) != nil || strings.TrimSpace(in.Login) == "" {
		writeErr(w, 400, "账号无效")
		return
	}
	if msg := validatePassword(in.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "生成密码摘要失败")
		return
	}
	v, err := s.m.pg.CreateTeamMember(r.Context(), team, in.Login, string(hash))
	if err != nil {
		writeErr(w, 409, "成员创建失败，账号可能已存在")
		return
	}
	writeJSON(w, 201, v)
}
func (s *Server) teamMemberRevoke(w http.ResponseWriter, r *http.Request) {
	_, team, ok := s.teamScope(w, r, true)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("member"), 10, 64)
	if err != nil || s.m.pg.RevokeTeamMember(r.Context(), team, id) != nil {
		writeErr(w, 400, "成员撤销失败")
		return
	}
	writeJSON(w, 200, map[string]any{"revoked": true})
}
func (s *Server) teamPermissionGrant(w http.ResponseWriter, r *http.Request) {
	_, team, ok := s.teamScope(w, r, true)
	if !ok {
		return
	}
	task, err := strconv.ParseInt(r.PathValue("task"), 10, 64)
	if err != nil {
		writeErr(w, 400, "任务编号无效")
		return
	}
	var in struct {
		MemberID   int64  `json:"member_id"`
		Permission string `json:"permission"`
	}
	if decode(r, &in) != nil {
		writeErr(w, 400, "授权信息无效")
		return
	}
	if err = s.m.pg.AttachTeamTask(r.Context(), team, task, in.MemberID, in.Permission); err != nil {
		writeErr(w, 400, "授权失败，请检查任务及成员")
		return
	}
	writeJSON(w, 200, map[string]any{"granted": true})
}

func (s *Server) teamPermissionRevoke(w http.ResponseWriter, r *http.Request) {
	_, team, ok := s.teamScope(w, r, true)
	if !ok {
		return
	}
	task, e1 := strconv.ParseInt(r.PathValue("task"), 10, 64)
	member, e2 := strconv.ParseInt(r.PathValue("member"), 10, 64)
	permission := r.PathValue("permission")
	if e1 != nil || e2 != nil || (permission != "read" && permission != "execute" && permission != "review" && permission != "manage") {
		writeErr(w, 400, "授权信息无效")
		return
	}
	if _, err := s.m.pg.ExecContext(r.Context(), `DELETE FROM team_task_permissions WHERE team_id=$1 AND task_id=$2 AND member_id=$3 AND permission=$4`, team, task, member, permission); err != nil {
		writeErr(w, 500, "撤销权限失败")
		return
	}
	writeJSON(w, 200, map[string]any{"revoked": true})
}
func (s *Server) teamWorkspace(w http.ResponseWriter, r *http.Request) {
	p, team, ok := s.teamScope(w, r, false)
	if !ok {
		return
	}
	tasks, err := s.m.pg.TeamWorkspaceTasks(r.Context(), team, p.MemberID)
	if err != nil {
		writeErr(w, 500, "读取任务失败")
		return
	}
	devices, err := s.m.pg.TeamWorkspaceDevices(r.Context(), team, p.MemberID)
	if err != nil {
		writeErr(w, 500, "读取设备失败")
		return
	}
	writeJSON(w, 200, map[string]any{"tasks": tasks, "devices": devices, "is_admin": p.Admin, "member_id": p.MemberID, "remote_execution_available": true, "execution_mode": "candidate_review", "remote_roles": []string{"worker", "reverse_static", "reverse_reviewer"}})
}
func (s *Server) teamPairingCreate(w http.ResponseWriter, r *http.Request) {
	p, team, ok := s.teamScope(w, r, false)
	if !ok {
		return
	}
	var in struct {
		MemberID int64 `json:"member_id"`
	}
	if decode(r, &in) != nil {
		writeErr(w, 400, "配对信息无效")
		return
	}
	if !p.Admin {
		in.MemberID = p.MemberID
	}
	token, err := s.m.pg.CreateTeamDevicePairing(r.Context(), team, in.MemberID, 10*time.Minute)
	if err != nil {
		writeErr(w, 400, "创建配对码失败")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 201, map[string]any{"pairing_token": token, "expires_in": 600})
}
func (s *Server) teamDevicePair(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token        string          `json:"pairing_token"`
		Name         string          `json:"name"`
		Capabilities json.RawMessage `json:"capabilities"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if decode(r, &in) != nil || s.m.pg == nil {
		writeErr(w, 400, "配对信息无效")
		return
	}
	device, token, err := s.m.pg.PairTeamDevice(r.Context(), in.Token, in.Name, in.Capabilities)
	if err != nil {
		writeErr(w, 403, "配对码无效、已使用或已过期")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 201, map[string]any{"device": device, "device_token": token})
}
func (s *Server) teamDeviceRevoke(w http.ResponseWriter, r *http.Request) {
	p, team, ok := s.teamScope(w, r, false)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("device"), 10, 64)
	if err != nil {
		writeErr(w, 400, "设备编号无效")
		return
	}
	v, err := s.m.pg.GetTeamDevice(r.Context(), team, id)
	if err != nil || (!p.Admin && v.OwnerMemberID != p.MemberID) {
		writeErr(w, 403, "不能撤销此设备")
		return
	}
	if s.m.pg.RevokeTeamDevice(r.Context(), team, id, v.OwnerMemberID) != nil {
		writeErr(w, 409, "设备撤销失败")
		return
	}
	writeJSON(w, 200, map[string]any{"revoked": true})
}
func (s *Server) teamDeviceStatus(w http.ResponseWriter, r *http.Request) {
	device, ok := r.Context().Value(teamIdentityKey{}).(*db.TeamDevice)
	if !ok {
		writeErr(w, 401, "设备身份无效")
		return
	}
	writeJSON(w, 200, map[string]any{"device": device, "protocol_version": 1, "remote_execution_available": true, "execution_mode": "candidate_review"})
}

func (s *Server) authenticateTeamDeviceRequest(w http.ResponseWriter, r *http.Request) (*http.Request, bool) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" || s.m.pg == nil {
		writeErr(w, 401, "需要设备凭据")
		return r, false
	}
	v, err := s.m.pg.AuthenticateTeamDevice(r.Context(), token)
	if err != nil {
		writeErr(w, 401, "设备凭据无效或已撤销")
		return r, false
	}
	return r.WithContext(context.WithValue(r.Context(), teamIdentityKey{}, v)), true
}
