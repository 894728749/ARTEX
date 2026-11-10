package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/golang-jwt/jwt/v5"
)

func TestTeamPermissionsHTTPAtomicSetAndAuthorization(t *testing.T) {
	s, task, _ := workflowFixture(t)
	ctx := context.Background()
	team, err := s.m.pg.CreateTeam(ctx, "permissions owner")
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.m.pg.CreateTeam(ctx, "permissions other")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.pg.Exec(`DELETE FROM teams WHERE id IN ($1,$2)`, team.ID, other.ID) })
	member, err := s.m.pg.CreateTeamMember(ctx, team.ID, "member", "unused")
	if err != nil {
		t.Fatal(err)
	}
	crossTeamMember, err := s.m.pg.CreateTeamMember(ctx, other.ID, "foreign", "unused")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, token, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	prefix := fmt.Sprintf("/api/teams/%d", team.ID)
	path := fmt.Sprintf("%s/tasks/%s/permissions", prefix, task.ID)
	if w := request(http.MethodPut, path, admin, fmt.Sprintf(`{"member_id":%d,"permissions":["read","execute","review"]}`, member.ID)); w.Code != 200 {
		t.Fatalf("multi-permission PUT status=%d body=%s", w.Code, w.Body.String())
	}
	check := func(w *httptest.ResponseRecorder, want []string) {
		t.Helper()
		if w.Code != 200 {
			t.Fatalf("GET permissions status=%d body=%s", w.Code, w.Body.String())
		}
		var rows []db.TeamTaskPermission
		if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, row := range rows {
			if row.MemberID == member.ID && fmt.Sprint(row.TaskID) == task.ID {
				got[row.Permission] = true
			}
		}
		if len(got) != len(want) {
			t.Fatalf("permissions=%v want=%v", got, want)
		}
		for _, p := range want {
			if !got[p] {
				t.Fatalf("permissions=%v missing %s", got, p)
			}
		}
	}
	check(request(http.MethodGet, prefix+"/permissions", admin, ""), []string{"read", "execute", "review"})
	// Invalid permissions and a member from another team must leave the previous set untouched.
	if w := request(http.MethodPut, path, admin, fmt.Sprintf(`{"member_id":%d,"permissions":["read","root"]}`, member.ID)); w.Code != 400 {
		t.Fatalf("invalid permission status=%d body=%s", w.Code, w.Body.String())
	}
	check(request(http.MethodGet, prefix+"/permissions", admin, ""), []string{"read", "execute", "review"})
	if w := request(http.MethodPut, path, admin, fmt.Sprintf(`{"member_id":%d,"permissions":["manage"]}`, crossTeamMember.ID)); w.Code != 400 {
		t.Fatalf("cross-team member status=%d body=%s", w.Code, w.Body.String())
	}
	check(request(http.MethodGet, prefix+"/permissions", admin, ""), []string{"read", "execute", "review"})
	if w := request(http.MethodPut, path, admin, fmt.Sprintf(`{"member_id":%d,"permissions":[]}`, member.ID)); w.Code != 200 {
		t.Fatalf("clear permissions status=%d body=%s", w.Code, w.Body.String())
	}
	check(request(http.MethodGet, prefix+"/permissions", admin, ""), []string{})
	memberToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{Subject: fmt.Sprintf("team:%d:%d", team.ID, member.ID), ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}).SignedString(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	if w := request(http.MethodGet, prefix+"/permissions", memberToken, ""); w.Code != 403 {
		t.Fatalf("non-admin GET status=%d body=%s", w.Code, w.Body.String())
	}
	if w := request(http.MethodPut, path, memberToken, fmt.Sprintf(`{"member_id":%d,"permissions":["read"]}`, member.ID)); w.Code != 403 {
		t.Fatalf("non-admin PUT status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestTeamLifecycleProtectsActiveSharedTask(t *testing.T) {
	s, task, _ := workflowFixture(t)
	ctx := context.Background()
	team, err := s.m.pg.CreateTeam(ctx, "active shared task")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.pg.Exec(`DELETE FROM teams WHERE id=$1`, team.ID) })
	member, err := s.m.pg.CreateTeamMember(ctx, team.ID, "active-member", "unused")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.m.pg.SetTeamTaskPermissions(ctx, team.ID, mustTaskID(t, task.ID), member.ID, []string{"read"}); err != nil {
		t.Fatal(err)
	}
	admin, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/teams/%d", team.ID)
	request := func(method, url string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, url, nil)
		r.Header.Set("Authorization", "Bearer "+admin)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	if w := request(http.MethodGet, path+"/deletion-eligibility"); w.Code != 200 {
		t.Fatalf("eligibility status=%d body=%s", w.Code, w.Body.String())
	}
	if w := request(http.MethodDelete, path); w.Code != http.StatusConflict {
		t.Fatalf("active shared task DELETE status=%d body=%s", w.Code, w.Body.String())
	}
}
