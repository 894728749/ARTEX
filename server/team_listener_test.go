package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Autumn-27/artex/db"
	"golang.org/x/crypto/bcrypt"
)

func TestTeamListenerTLSScopesMemberAccess(t *testing.T) {
	s, _, _ := workflowFixture(t)
	ctx := context.Background()
	team, err := s.m.pg.CreateTeam(ctx, "team listener fixture")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.pg.Exec(`DELETE FROM teams WHERE id=$1`, team.ID) })
	password := "listener-fixture-password"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.m.pg.CreateTeamMember(ctx, team.ID, "listener", string(hash))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(s.TeamHandler())
	defer server.Close()
	client := server.Client()
	request := func(method, path, token, body string, want int) (int, []byte) {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, bytes.NewBufferString(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.Header.Get("X-ARTEX-Entry") != "team" {
			t.Fatal("member entry identification header missing")
		}
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != want {
			t.Fatalf("%s %s got %d want %d: %s", method, path, resp.StatusCode, want, data)
		}
		return resp.StatusCode, data
	}
	var login struct {
		Token string `json:"token"`
	}
	_, raw := request(http.MethodPost, "/api/auth/team-login", "", fmt.Sprintf(`{"team_id":%d,"login":"listener","password":%q}`, team.ID, password), 200)
	if err = json.Unmarshal(raw, &login); err != nil || login.Token == "" {
		t.Fatalf("login token=%q err=%v", login.Token, err)
	}
	_, raw = request(http.MethodGet, "/api/teams", login.Token, "", 200)
	var listing struct {
		Teams   []db.Team `json:"teams"`
		IsAdmin bool      `json:"is_admin"`
	}
	if err = json.Unmarshal(raw, &listing); err != nil || listing.IsAdmin || len(listing.Teams) != 1 || listing.Teams[0].ID != team.ID {
		t.Fatalf("team list=%+v err=%v", listing, err)
	}
	prefix := fmt.Sprintf("/api/teams/%d", team.ID)
	_, raw = request(http.MethodPost, prefix+"/pairings", login.Token, `{}`, 201)
	var pairing struct {
		Token string `json:"pairing_token"`
	}
	if err = json.Unmarshal(raw, &pairing); err != nil || pairing.Token == "" {
		t.Fatalf("pairing=%+v err=%v", pairing, err)
	}
	_, raw = request(http.MethodPost, "/api/collaboration/pair", "", fmt.Sprintf(`{"pairing_token":%q,"name":"TLS fixture device","capabilities":{"os":"synthetic"}}`, pairing.Token), 201)
	var paired struct {
		DeviceToken string `json:"device_token"`
	}
	if err = json.Unmarshal(raw, &paired); err != nil || paired.DeviceToken == "" {
		t.Fatalf("paired=%+v err=%v", paired, err)
	}
	request(http.MethodGet, "/api/collaboration/device", paired.DeviceToken, "", 200)
	admin, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ method, path, body string }{{http.MethodPost, "/api/auth/login", `{}`}, {http.MethodPost, "/api/auth/init", `{}`}, {http.MethodGet, "/api/settings", ""}, {http.MethodGet, "/api/tasks", ""}} {
		request(tc.method, tc.path, "", tc.body, 403)
	}
	request(http.MethodGet, "/api/teams", admin, "", 403)
	// The ordinary in-process handler retains its administrator surface.
	adminRequest := func(path string) int {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer "+admin)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w.Code
	}
	if code := adminRequest("/api/settings"); code != 200 {
		t.Fatalf("normal admin settings status=%d", code)
	}
	if code := adminRequest("/api/tasks"); code != 200 {
		t.Fatalf("normal admin tasks status=%d", code)
	}
}
