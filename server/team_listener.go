package server

import (
	"net/http"
	"strings"
)

// TeamHandler is the deliberately smaller surface exposed to LAN/Relay peers.
// The ordinary loopback Handler remains the administration endpoint.
func (s *Server) TeamHandler() http.Handler { return s.teamOnly(s.Handler()) }

func (s *Server) teamOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-ARTEX-Entry", "team")
		p := r.URL.Path
		if p == "/" || p == "/login" || p == "/login/" {
			http.Redirect(w, r, "/team-login/", http.StatusTemporaryRedirect)
			return
		}
		if strings.HasPrefix(p, "/api/") {
			public := (p == "/api/health" && r.Method == "GET") || (p == "/api/auth/team-login" && r.Method == "POST") || (p == "/api/collaboration/pair" && r.Method == "POST")
			device := p == "/api/collaboration/device" || strings.HasPrefix(p, "/api/collaboration/device/")
			team := p == "/api/teams" || strings.HasPrefix(p, "/api/teams/")
			if !public && !device && !team {
				writeErr(w, 403, "此入口仅提供成员协作；管理员请使用本机管理地址")
				return
			}
			if team {
				if identity, ok := s.teamPrincipal(r); ok && identity.Admin {
					writeErr(w, 403, "管理员身份不能用于成员接入地址，请使用本机管理地址")
					return
				}
			}
		} else {
			allowed := r.Method == "GET" || r.Method == "HEAD"
			allowed = allowed && (p == "/team-login" || p == "/team-login/" || p == "/function/team" || p == "/function/team/" || strings.HasPrefix(p, "/_next/") || p == "/favicon.ico" || p == "/logo.png" || p == "/logo.svg")
			if !allowed {
				http.NotFound(w, r)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
