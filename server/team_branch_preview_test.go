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

	"github.com/Autumn-27/artex/collab"
	"github.com/golang-jwt/jwt/v5"
)

// Optional, real-API browser fixture. It cannot start with the production DSN.
// Only loopback and an explicit synthetic database are allowed. No model runs.
func TestBranchBrowserPreview(t *testing.T) {
	output := os.Getenv("ARTEX_BRANCH_PREVIEW_DIR")
	if output == "" {
		t.Skip("manual browser fixture is opt-in")
	}
	if !strings.Contains(os.Getenv("ARTEX_PG_DSN"), "dbname=preview_regression") {
		t.Fatal("preview requires the isolated preview_regression database")
	}
	root, err := filepath.Abs("../web/out")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(root, "function/team/index.html")); err != nil {
		t.Fatal(err)
	}
	s, task, _ := workflowFixture(t)
	ctx := context.Background()
	pg := s.m.pg
	tid := mustTaskID(t, task.ID)
	if err = pg.SetPaused(tid, true); err != nil {
		t.Fatal(err)
	}
	task.updateLifecycle(func(v *taskLifecycleState) { v.Paused = true })
	team, err := pg.CreateTeam(ctx, "执行分支隔离验收")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM teams WHERE id=$1`, team.ID) })
	tokens := map[string]string{}
	var owner int64
	if _,err=pg.Exec(`INSERT INTO team_tasks(team_id,task_id) VALUES($1,$2)`,team.ID,tid);err!=nil{t.Fatal(err)}
	policy := collab.BranchPolicy{Version: 1, Goal: "仅验证本机隔离协作流程，不执行任何真实目标", Budget: 200, MaxToolSeconds: 30, Kinds: []string{"pentest", "reverse"}, Assets: []collab.BranchAsset{{ID: "fixture", Target: "https://owned.invalid", Version: "v1"}}, PlannerPrompts: map[string]string{"pentest": "fixture planner", "reverse": "fixture reverse planner"}, Roles: map[string]collab.ExecutionConfig{}}
	for _, role := range []string{"worker", "reviewer", "reverse_static", "reverse_reviewer", "reverse_dynamic"} {
		kind := "pentest"
		if strings.HasPrefix(role, "reverse_") {
			kind = "reverse"
		}
		policy.Roles[role] = collab.ExecutionConfig{Version: 1, Kind: kind, Role: role, SystemPrompt: "isolated fixture role", BudgetSeconds: 30, MaxTurns: 4}
	}
	if _, err = pg.CreateBranchProject(ctx, team.ID, tid, collab.BranchActor{Admin: true}, policy); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"operator", "reader", "reviewer"} {
		m, e := pg.CreateTeamMember(ctx, team.ID, "隔离"+role, "unused")
		if e != nil {
			t.Fatal(e)
		}
		for _, perm := range []string{"read", "execute", "review", "manage"} {
			if e = pg.AttachTeamTask(ctx, team.ID, tid, m.ID, perm); e != nil {
				t.Fatal(e)
			}
		}
		grants := collab.BranchPermissions
		if role == "reader" {
			grants = []string{"read"}
		}
		for _, perm := range grants {
			if _, e = pg.ApplyBranchCommand(ctx, team.ID, tid, collab.BranchActor{Admin: true}, collab.BranchCommand{Type: "grant", RequestID: fmt.Sprintf("grant-%d-%s", m.ID, perm), MemberID: m.ID, Permission: perm}); e != nil {
				t.Fatal(e)
			}
		}
		tokens[role], e = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{Subject: fmt.Sprintf("team:%d:%d", team.ID, m.ID), ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}).SignedString(s.jwtKey)
		if e != nil {
			t.Fatal(e)
		}
		if role == "operator" {
			owner = m.ID
		}
	}
	pair, err := pg.CreateTeamDevicePairing(ctx, team.ID, owner, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	device, _, err := pg.PairTeamDevice(ctx, pair, "本机隔离节点 A", json.RawMessage(`{"version":1,"branch_protocol":1,"execution_enabled":true,"roles":["planner","worker","reviewer","reverse_planner","reverse_static","reverse_dynamic","reverse_reviewer"],"capabilities":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	work := collab.BranchWorkSpec{Title: "共享消息与执行端编号验收", Question: "只查看合成计划、讨论和指导状态", Kind: "pentest", AssetIDs: []string{"fixture"}, Roles: []string{"worker", "reviewer"}, Acceptance: []string{"记录可见且权限明确"}, Budget: 60}
	publish, err := pg.ApplyBranchCommand(ctx, team.ID, tid, collab.BranchActor{Admin: true}, collab.BranchCommand{Type: "publish", RequestID: "publish", Work: &work})
	if err != nil {
		t.Fatal(err)
	}
	claim, err := pg.ApplyBranchCommand(ctx, team.ID, tid, collab.BranchActor{MemberID: owner}, collab.BranchCommand{Type: "claim", RequestID: "claim", WorkID: publish.Receipt.WorkID, DeviceID: device.ID})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 115; i++ {
		if _, err = pg.ApplyBranchCommand(ctx, team.ID, tid, collab.BranchActor{MemberID: owner}, collab.BranchCommand{Type: "discuss", RequestID: fmt.Sprintf("seed-%d", i), BranchID: claim.Branch.ID, Text: fmt.Sprintf("隔离历史消息 %d：授权查看、按序回放。", i)}); err != nil {
			t.Fatal(err)
		}
	}
	handler := http.NewServeMux()
	handler.Handle("/api/", s.Handler())
	handler.Handle("/", http.FileServer(http.Dir(root)))
	handler.HandleFunc("GET /fixture/{role}", func(w http.ResponseWriter, r *http.Request) {
		token, ok := tokens[r.PathValue("role")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		encoded, _ := json.Marshal(token)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, `<html><title>隔离协作验收</title><script>localStorage.setItem("artex_token",%s);location.href="/function/team/";</script></html>`, encoded)
	})
	listener, err := net.Listen("tcp", "127.0.0.1:8895")
	if err != nil {
		t.Fatal(err)
	}
	host := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	defer host.Close()
	go host.Serve(listener)
	if err = os.MkdirAll(output, 0700); err != nil {
		t.Fatal(err)
	}
	info, _ := json.Marshal(map[string]any{"url": "http://127.0.0.1:8895/fixture/operator", "reader_url": "http://127.0.0.1:8895/fixture/reader", "team": team.ID, "task": tid, "branch": claim.Branch.ID, "device": device.ID})
	if err = os.WriteFile(filepath.Join(output, "preview.json"), info, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("isolated preview ready on 127.0.0.1:8895; create preview.stop to shut down")
	deadline := time.Now().Add(30 * time.Minute)
	for time.Now().Before(deadline) {
		if _, e := os.Stat(filepath.Join(output, "preview.stop")); e == nil {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
}
