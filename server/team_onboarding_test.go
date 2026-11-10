package server

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/teamsetup"
	"github.com/Autumn-27/norma/llm"
	"github.com/golang-jwt/jwt/v5"
)

type onboardingCapture struct {
	request llm.CompletionRequest
	text    string
	err     error
}

func (p *onboardingCapture) Stream(_ context.Context, r llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	p.request = r
	return func(y func(llm.StreamEvent, error) bool) {
		y(llm.StreamEvent{Type: llm.SETextDelta, Text: p.text}, p.err)
	}
}
func (p *onboardingCapture) Complete(ctx context.Context, r llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return accumulateStreamForTest(ctx, p.Stream, r)
}

func TestOnboardingAdviceOutputBoundary(t *testing.T) {
	for _, test := range []struct {
		name, text string
		ok         bool
	}{{"valid", `{"summary":"准备成员入口","steps":["确认地址并生成方案"],"recommended_action":"prepare"}`, true}, {"command", `{"summary":"x","steps":["x"],"recommended_action":"execute_shell"}`, false}, {"oversized", strings.Repeat("x", 8193), false}, {"unknown", `{"summary":"x","steps":["x"],"recommended_action":"prepare","shell":"anything"}`, false}, {"trailing", `{"summary":"x","steps":["x"],"recommended_action":"prepare"}{}`, false}} {
		t.Run(test.name, func(t *testing.T) {
			p := &onboardingCapture{text: test.text}
			a, err := boundedOnboardingAdvice(t.Context(), p, map[string]any{"issue": "explain"})
			if (err == nil) != test.ok {
				t.Fatalf("%+v %v", a, err)
			}
			if len(p.request.Tools) != 0 || len(p.request.Messages) != 1 || p.request.MaxTokens != 800 {
				t.Fatal("adviser received tools or task history")
			}
		})
	}
}
func TestOnboardingAPIIsolationAndAdvice(t *testing.T) {
	s, _, _ := workflowFixture(t)
	ctx := t.Context()
	team, err := s.m.pg.CreateTeam(ctx, "onboarding fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer s.m.pg.Exec(`DELETE FROM teams WHERE id=$1`, team.ID)
	one, err := s.m.pg.CreateTeamMember(ctx, team.ID, "member-one", "not-a-login-fixture")
	if err != nil {
		t.Fatal(err)
	}
	two, err := s.m.pg.CreateTeamMember(ctx, team.ID, "member-two", "not-a-login-fixture")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{one.ID, two.ID} {
		code, _ := s.m.pg.CreateTeamDevicePairing(ctx, team.ID, id, time.Minute)
		if _, _, err = s.m.pg.PairTeamDevice(ctx, code, fmt.Sprintf("device-secret-name-%d", id), json.RawMessage(`{"execution_enabled":false}`)); err != nil {
			t.Fatal(err)
		}
	}
	env := teamsetup.Environment{OS: "linux", Arch: "amd64", WSL: true, Distro: "PRIVATE-DISTRO", Addresses: []teamsetup.Address{{IP: "192.168.50.4", Interface: "PRIVATE-IFACE", CIDR: "192.168.50.0/24"}}}
	s.teamAccess = teamsetup.New(ctx, filepath.Join(t.TempDir(), "access"), t.TempDir(), BuildVersion, env, false, s.TeamHandler())
	defer s.teamAccess.Close()
	admin, _ := signJWT(s.jwtKey)
	member, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{Subject: fmt.Sprintf("team:%d:%d", team.ID, one.ID), ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}).SignedString(s.jwtKey)
	handler := s.Handler()
	base := fmt.Sprintf("/api/teams/%d/onboarding", team.ID)
	call := func(method, path, token, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	got := call("GET", base, member, "")
	if got.Code != 200 {
		t.Fatalf("%d %s", got.Code, got.Body)
	}
	var status struct {
		Environment teamsetup.Environment `json:"environment"`
		Devices     []onboardingDevice    `json:"devices"`
	}
	if json.Unmarshal(got.Body.Bytes(), &status) != nil || len(status.Devices) != 1 || len(status.Environment.Addresses) != 0 {
		t.Fatalf("member scope: %s", got.Body)
	}
	for _, route := range []string{"plan", "apply", "disable", "assist", "host-script"} {
		method := "POST"
		if route == "host-script" {
			method = "GET"
		}
		got = call(method, base+"/"+route, member, `{}`)
		if got.Code != 403 {
			t.Fatalf("member %s: %d", route, got.Code)
		}
	}
	got = call("POST", base+"/apply", admin, `{"confirm":false}`)
	if got.Code != 400 {
		t.Fatal("apply allowed without confirmation")
	}
	got = call("POST", base+"/plan", admin, `{"bind_ip":"192.168.50.4","public_ip":"192.168.50.4","port":18789,"allowed_cidr":"192.168.50.0/24"}`)
	if got.Code != 200 {
		t.Fatalf("plan: %s", got.Body)
	}
	if s.teamAccess.State().Enabled {
		t.Fatal("plan started listener")
	}
	p := &onboardingCapture{text: `{"summary":"已检查固定事实","steps":["确认接入地址"],"recommended_action":"prepare"}`}
	s.cfgMu.Lock()
	s.llmProv = p
	s.cfgMu.Unlock()
	got = call("POST", base+"/assist", admin, `{"issue":"explain"}`)
	if got.Code != 200 || !strings.Contains(got.Body.String(), `"source":"ai"`) {
		t.Fatalf("advice: %s", got.Body)
	}
	encoded, _ := json.Marshal(p.request)
	for _, secret := range []string{"192.168.50.4", "PRIVATE-DISTRO", "PRIVATE-IFACE", "device-secret-name", "not-a-login-fixture", admin, member} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("private fact in model request: %s", secret)
		}
	}
	got = call("POST", base+"/assist", admin, `{"issue":"explain","raw_log":"PRIVATE"}`)
	if got.Code != 400 {
		t.Fatal("freeform model input accepted")
	}
	p.text = "invalid"
	got = call("POST", base+"/assist", admin, `{"issue":"tls"}`)
	if got.Code != 200 || !strings.Contains(got.Body.String(), `"source":"checks"`) {
		t.Fatal("failed model did not fall back")
	}
	s.cfgMu.Lock()
	s.llmProv = nil
	s.cfgMu.Unlock()
	got = call("POST", base+"/assist", admin, `{"issue":"tools"}`)
	if got.Code != 200 || !strings.Contains(got.Body.String(), "configure_tools") {
		t.Fatal("no-model fallback unavailable")
	}
	r := httptest.NewRequest("POST", base+"/plan", strings.NewReader(`{}`))
	r.Header.Set("Authorization", "Bearer "+admin)
	w := httptest.NewRecorder()
	s.TeamHandler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("member listener accepted admin")
	}
	if _, err = os.Stat(filepath.Join(s.m.dir, "team-access", "access.json")); !os.IsNotExist(err) {
		t.Fatal("read-only tests modified production settings")
	}
}
