package server

import (
	"net/http"
	"strconv"
)

func (s *Server) teamPermissionRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/teams/{team}/permissions", s.teamPermissionList)
	mux.HandleFunc("PUT /api/teams/{team}/tasks/{task}/permissions", s.teamPermissionSet)
}
func (s *Server) teamPermissionList(w http.ResponseWriter, r *http.Request) {
	_, team, ok := s.teamScope(w, r, true)
	if !ok {
		return
	}
	items, err := s.m.pg.ListTeamTaskPermissions(r.Context(), team)
	if err != nil {
		writeErr(w, 500, "读取任务授权失败")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, items)
}
func (s *Server) teamPermissionSet(w http.ResponseWriter, r *http.Request) {
	_, team, ok := s.teamScope(w, r, true)
	if !ok {
		return
	}
	task, err := strconv.ParseInt(r.PathValue("task"), 10, 64)
	var in struct {
		MemberID    int64    `json:"member_id"`
		Permissions []string `json:"permissions"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err != nil || task < 1 || decode(r, &in) != nil || in.MemberID < 1 || in.Permissions == nil || len(in.Permissions) > 4 {
		writeErr(w, 400, "请明确选择成员、任务和权限；空数组代表撤销全部任务权限")
		return
	}
	if err = s.m.pg.SetTeamTaskPermissions(r.Context(), team, task, in.MemberID, in.Permissions); err != nil {
		writeErr(w, 400, "保存失败，请检查任务、有效成员及权限选择")
		return
	}
	writeJSON(w, 200, map[string]any{"saved": true, "permissions": in.Permissions})
}
