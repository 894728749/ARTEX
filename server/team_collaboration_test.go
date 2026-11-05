package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestTeamHTTPIdentityTaskVisibilityAndDeviceRevocation(t *testing.T) {
	s, task, _ := workflowFixture(t)
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	admin, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, token string, body any, status int) []byte {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		r, _ := http.NewRequest(method, server.URL+path, bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != status {
			t.Fatalf("%s %s got %d: %s", method, path, resp.StatusCode, data)
		}
		return data
	}
	var team db.Team
	if json.Unmarshal(request("POST", "/api/teams", admin, map[string]any{"name": "owned team fixture"}, 201), &team) != nil {
		t.Fatal("team response")
	}
	t.Cleanup(func() { _, _ = s.m.pg.Exec(`DELETE FROM teams WHERE id=$1`, team.ID) })
	prefix := fmt.Sprintf("/api/teams/%d", team.ID)
	var member db.TeamMember
	raw := request("POST", prefix+"/members", admin, map[string]any{"login": "alice", "password": "fixture-pass-123"}, 201)
	if bytes.Contains(raw, []byte("password")) {
		t.Fatal("password leaked")
	}
	_ = json.Unmarshal(raw, &member)
	request("POST", prefix+"/tasks/"+task.ID+"/permissions", admin, map[string]any{"member_id": member.ID, "permission": "read"}, 200)
	var login struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(request("POST", "/api/auth/team-login", "", map[string]any{"team_id": team.ID, "login": "alice", "password": "fixture-pass-123"}, 200), &login)
	if login.Token == "" {
		t.Fatal("missing team token")
	}
	request("GET", "/api/tasks", login.Token, nil, 403)
	request("GET", "/api/agents", login.Token, nil, 403)
	request("POST", prefix+"/members", login.Token, map[string]any{"login": "mallory", "password": "fixture-pass"}, 403)
	request("GET", fmt.Sprintf("/api/teams/%d/workspace", team.ID+1), login.Token, nil, 403)
	var workspace struct {
		Tasks   []db.TeamWorkspaceTask `json:"tasks"`
		Devices []db.TeamDevice        `json:"devices"`
	}
	_ = json.Unmarshal(request("GET", prefix+"/workspace", login.Token, nil, 200), &workspace)
	if len(workspace.Tasks) != 1 || fmt.Sprint(workspace.Tasks[0].ID) != task.ID {
		t.Fatalf("task visibility %v", workspace.Tasks)
	}
	var work struct {
		Permissions map[string]bool `json:"permissions"`
	}
	if err := json.Unmarshal(request("GET", prefix+"/tasks/"+task.ID+"/work", login.Token, nil, 200), &work); err != nil {
		t.Fatal(err)
	}
	if work.Permissions["execute"] || work.Permissions["review"] || work.Permissions["manage"] {
		t.Fatalf("read-only member received extra permissions: %v", work.Permissions)
	}
	request("DELETE", prefix+"/tasks/"+task.ID+fmt.Sprintf("/permissions/%d/read", member.ID), admin, nil, 200)
	request("GET", prefix+"/tasks/"+task.ID+"/work", login.Token, nil, 403)
	_ = json.Unmarshal(request("GET", prefix+"/workspace", login.Token, nil, 200), &workspace)
	if len(workspace.Tasks) != 0 {
		t.Fatal("revoked task is still visible")
	}
	var pairing struct {
		Token string `json:"pairing_token"`
	}
	_ = json.Unmarshal(request("POST", prefix+"/pairings", login.Token, map[string]any{"member_id": member.ID + 999}, 201), &pairing)
	var device struct {
		Device db.TeamDevice `json:"device"`
		Token  string        `json:"device_token"`
	}
	_ = json.Unmarshal(request("POST", "/api/collaboration/pair", "", map[string]any{"pairing_token": pairing.Token, "name": "owned device", "capabilities": map[string]any{"os": "synthetic"}}, 201), &device)
	if device.Device.OwnerMemberID != member.ID || device.Token == "" {
		t.Fatal("pairing owner or token invalid")
	}
	request("POST", "/api/collaboration/pair", "", map[string]any{"pairing_token": pairing.Token, "name": "replay", "capabilities": map[string]any{}}, 403)
	request("GET", "/api/collaboration/device", device.Token, nil, 200)
	request("GET", "/api/teams", device.Token, nil, 401)
	request("DELETE", prefix+fmt.Sprintf("/members/%d", member.ID), admin, nil, 200)
	request("GET", prefix+"/workspace", login.Token, nil, 401)
	request("GET", "/api/collaboration/device", device.Token, nil, 401)
	request("POST", "/api/auth/team-login", "", map[string]any{"team_id": team.ID, "login": "alice", "password": "fixture-pass-123"}, 401)
}

func TestCoordinatorLockRejectsSecondOwner(t *testing.T) {
	s, _, _ := workflowFixture(t)
	_ = s
	dsn, _, err := db.DSN()
	if err != nil {
		t.Fatal(err)
	}
	one, err := AcquireCoordinatorLock(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer one.Close()
	if two, err := AcquireCoordinatorLock(t.Context(), dsn); err == nil {
		two.Close()
		t.Fatal("second coordinator accepted")
	}
	one.Close()
	three, err := AcquireCoordinatorLock(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	three.Close()
}

func TestLocalExecutionBackendCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := (LocalExecutionBackend{}).Execute(ctx, LocalExecution{})
	if err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("cancelled execution admitted: %v", err)
	}
}
