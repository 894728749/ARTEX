package server

import (
	"database/sql"
	"errors"
	"github.com/Autumn-27/artex/db"
	"net/http"
)

func (s *Server) teamDeletionEligibility(w http.ResponseWriter, r *http.Request) {
	_, team, ok := s.teamScope(w, r, true)
	if !ok {
		return
	}
	v, err := s.m.pg.TeamDeletionEligibility(r.Context(), team)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "团队不存在")
		return
	}
	if err != nil {
		writeErr(w, 500, "检查团队删除条件失败")
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) teamDelete(w http.ResponseWriter, r *http.Request) {
	_, team, ok := s.teamScope(w, r, true)
	if !ok {
		return
	}
	err := s.m.pg.DeleteEmptyTeam(r.Context(), team)
	switch {
	case err == nil:
		writeJSON(w, 200, map[string]any{"deleted": true})
	case errors.Is(err, db.ErrTeamLifecycleConflict):
		writeErr(w, 409, "团队存在活动或历史记录，拒绝删除；请保留团队以供审计")
	case errors.Is(err, sql.ErrNoRows):
		writeErr(w, 404, "团队不存在")
	default:
		writeErr(w, 500, "删除团队失败")
	}
}
