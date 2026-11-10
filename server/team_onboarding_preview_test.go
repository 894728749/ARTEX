package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Manual browser acceptance with real APIs, synthetic identities and no model.
func TestTeamOnboardingBrowserPreview(t *testing.T) {
	output := os.Getenv("ARTEX_BRANCH_PREVIEW_DIR")
	if output == "" {
		t.Skip("manual browser fixture is opt-in")
	}
	if !strings.Contains(os.Getenv("ARTEX_PG_DSN"), "dbname=usability_preview") {
		t.Skip("requires dedicated usability_preview database")
	}
	s, task, _ := workflowFixture(t)
	ctx := context.Background()
	pg := s.m.pg
	tid := mustTaskID(t, task.ID)
	if err := pg.SetPaused(tid, true); err != nil {
		t.Fatal(err)
	}
	task.updateLifecycle(func(v *taskLifecycleState) { v.Paused = true })
	team, err := pg.CreateTeam(ctx, "协作闭环验收")
	if err != nil {
		t.Fatal(err)
	}
	teamIDs := []int64{team.ID}
	defer func() {
		for _, id := range teamIDs {
			_, _ = pg.Exec(`DELETE FROM teams WHERE id=$1`, id)
		}
	}()
	for i := 0; i < 2; i++ {
		empty, e := pg.CreateTeam(ctx, "同名空团队验收")
		if e != nil {
			t.Fatal(e)
		}
		teamIDs = append(teamIDs, empty.ID)
	}
	// A shared paused task, deliberately no member grants or branch mode yet.
	if _, err = pg.Exec(`INSERT INTO team_tasks(team_id,task_id) VALUES($1,$2)`, team.ID, tid); err != nil {
		t.Fatal(err)
	}
	tokens := map[string]string{}
	members := map[string]int64{}
	tokens["admin"], err = signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("TeamFixture-Only-2026!"), bcrypt.MinCost)
	for _, role := range []string{"operator", "reader", "reviewer"} {
		m, e := pg.CreateTeamMember(ctx, team.ID, role, string(hash))
		if e != nil {
			t.Fatal(e)
		}
		members[role] = m.ID
		tokens[role], e = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{Subject: fmt.Sprintf("team:%d:%d", team.ID, m.ID), ExpiresAt: jwt.NewNumericDate(time.Now().Add(2 * time.Hour))}).SignedString(s.jwtKey)
		if e != nil {
			t.Fatal(e)
		}
	}
	// Ready capabilities are synthetic; the real node/TLS suite verifies execution.
	pair, err := pg.CreateTeamDevicePairing(ctx, team.ID, members["operator"], time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	d, _, err := pg.PairTeamDevice(ctx, pair, "隔离执行端 A", json.RawMessage(`{"version":1,"branch_protocol":1,"execution_enabled":true,"roles":["planner","worker","reviewer","reverse_planner","reverse_static","reverse_reviewer"],"capabilities":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	webRoot, _ := filepath.Abs("../web/out")
	if _, err = os.Stat(filepath.Join(webRoot, "function/team/index.html")); err != nil {
		t.Fatal(err)
	}
	handler := http.NewServeMux()
	handler.Handle("/api/", s.Handler())
	handler.Handle("/", http.FileServer(http.Dir(webRoot)))
	handler.HandleFunc("GET /fixture/{role}", func(w http.ResponseWriter, r *http.Request) {
		token, ok := tokens[r.PathValue("role")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		encoded, _ := json.Marshal(token)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, `<html><title>ARTEX 隔离验收</title><script>localStorage.setItem("artex_token",%s);location.href="/function/team/";</script></html>`, encoded)
	})
	l, err := net.Listen("tcp", "127.0.0.1:8895")
	if err != nil {
		t.Fatal(err)
	}
	host := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	defer host.Close()
	go host.Serve(l)
	// Separate member-only surface, same route filter as the actual TLS listener.
	memberMux := http.NewServeMux()
	memberMux.Handle("/api/", s.Handler())
	memberMux.Handle("/", http.FileServer(http.Dir(webRoot)))
	ml, err := net.Listen("tcp", "127.0.0.1:8896")
	if err != nil {
		t.Fatal(err)
	}
	mhost := &http.Server{Handler: s.teamOnly(memberMux), ReadHeaderTimeout: 5 * time.Second}
	defer mhost.Close()
	go mhost.Serve(ml)
	info := map[string]any{"admin_url": "http://127.0.0.1:8895/fixture/admin", "operator_url": "http://127.0.0.1:8895/fixture/operator", "reader_url": "http://127.0.0.1:8895/fixture/reader", "member_login": "http://127.0.0.1:8896/team-login/", "team": team.ID, "empty_teams": teamIDs[1:], "task": tid, "members": members, "device": d.ID}
	raw, _ := json.MarshalIndent(info, "", "  ")
	if err = os.WriteFile(filepath.Join(output, "preview.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("browser preview ready: localhost 8895 (admin), 8896 (member surface); no models or target operations")
	deadline := time.Now().Add(70 * time.Minute)
	for time.Now().Before(deadline) {
		if _, e := os.Stat(filepath.Join(output, "preview.stop")); e == nil {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
}
