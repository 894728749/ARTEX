package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
)

func TestBranchEnableFromHTTPBothWorkflowsAndForeignMaterial(t *testing.T) {
	s, pentest, reverse := workflowFixture(t)
	pg := s.m.pg
	ctx := context.Background()
	team, err := pg.CreateTeam(ctx, "enable UI regression")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM teams WHERE id=$1`, team.ID) })
	admin, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range []*Task{pentest, reverse} {
		tid := mustTaskID(t, task.ID)
		if err = pg.SetPaused(tid, true); err != nil {
			t.Fatal(err)
		}
		task.updateLifecycle(func(v *taskLifecycleState) { v.Paused = true })
		if _, err = pg.Exec(`INSERT INTO team_tasks(team_id,task_id) VALUES($1,$2)`, team.ID, tid); err != nil {
			t.Fatal(err)
		}
		kind := "pentest"
		if task == reverse {
			kind = "reverse"
		}
		body := map[string]any{"policy": map[string]any{"goal": "isolated enable from UI", "budget": 30, "max_tool_seconds": 10, "kinds": []string{kind}, "assets": []any{}}, "artifact_ids": []int64{987654321}}
		call := func(want int) {
			t.Helper()
			raw, _ := json.Marshal(body)
			r := httptest.NewRequest("POST", fmt.Sprintf("/api/teams/%d/tasks/%d/branches/enable", team.ID, tid), bytes.NewReader(raw))
			r.Header.Set("Authorization", "Bearer "+admin)
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != want {
				t.Fatalf("%s enable got %d want %d: %s", kind, w.Code, want, w.Body.String())
			}
		}
		call(403)
		body["artifact_ids"] = []int64{}
		call(201)
		on, e := pg.BranchMode(ctx, tid)
		if e != nil || !on {
			t.Fatalf("%s mode=%t err=%v", kind, on, e)
		}
	}
}
