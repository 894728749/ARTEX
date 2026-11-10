package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestTeamLifecycleHTTPAuthorizationAndConflict(t *testing.T) {
	s, _, _ := workflowFixture(t)
	team, err := s.m.pg.CreateTeam(context.Background(), "lifecycle http")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.pg.Exec(`DELETE FROM teams WHERE id=$1`, team.ID) })
	admin, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	member, err := s.m.pg.CreateTeamMember(context.Background(), team.ID, "member", "unused")
	if err != nil {
		t.Fatal(err)
	}
	memberToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{Subject: fmt.Sprintf("team:%d:%d", team.ID, member.ID), ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}).SignedString(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	// A retained member record is historical activity, even if its credential is revoked.
	w := request(http.MethodGet, fmt.Sprintf("/api/teams/%d/deletion-eligibility", team.ID), admin)
	if w.Code != http.StatusOK {
		t.Fatalf("eligibility status=%d body=%s", w.Code, w.Body.String())
	}
	var eligibility struct {
		Deletable bool     `json:"deletable"`
		Reasons   []string `json:"reasons"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &eligibility); err != nil || eligibility.Deletable || len(eligibility.Reasons) == 0 {
		t.Fatalf("eligibility=%+v err=%v", eligibility, err)
	}
	w = request(http.MethodDelete, fmt.Sprintf("/api/teams/%d", team.ID), memberToken)
	if w.Code != http.StatusForbidden {
		t.Fatalf("member DELETE status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(http.MethodDelete, fmt.Sprintf("/api/teams/%d", team.ID), admin)
	if w.Code != http.StatusConflict {
		t.Fatalf("historical DELETE status=%d body=%s", w.Code, w.Body.String())
	}
}
