package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/teamsetup"
)

// Opt-in real Node process against real member routes and an isolated database.
// It pairs and resumes identity only; it never starts a model or claims work.
func TestOnboardingRealNodePairAndResume(t *testing.T) {
	binary := os.Getenv("ARTEX_NODE_ACCEPTANCE_BINARY")
	if binary == "" {
		t.Skip("set ARTEX_NODE_ACCEPTANCE_BINARY to a freshly built same-version Node")
	}
	if _, err := os.Stat(binary); err != nil {
		t.Fatal(err)
	}
	s, _, _ := workflowFixture(t)
	ctx := t.Context()
	team, err := s.m.pg.CreateTeam(ctx, "onboarding process fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer s.m.pg.Exec(`DELETE FROM teams WHERE id=$1`, team.ID)
	member, err := s.m.pg.CreateTeamMember(ctx, team.ID, "fixture-member", "not-a-login-hash")
	if err != nil {
		t.Fatal(err)
	}
	code, err := s.m.pg.CreateTeamDevicePairing(ctx, team.ID, member.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	host := httptest.NewTLSServer(s.TeamHandler())
	defer host.Close()
	u, _ := url.Parse(host.URL)
	sum := sha256.Sum256(host.Certificate().Raw)
	dir := t.TempDir()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: host.Certificate().Raw})
	if err = os.WriteFile(filepath.Join(dir, "coordinator-ca.pem"), ca, 0600); err != nil {
		t.Fatal(err)
	}
	j := teamsetup.JoinConfig{Schema: 1, TeamID: team.ID, Version: BuildVersion, CoordinatorURL: host.URL, ServerName: u.Hostname(), CAFile: "coordinator-ca.pem", CertificateSHA256: hex.EncodeToString(sum[:]), LANAddresses: []string{u.Host}}
	b, _ := json.Marshal(j)
	if err = os.WriteFile(filepath.Join(dir, "join.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	before := 0
	if err = s.m.pg.QueryRow(`SELECT count(*) FROM team_execution_assignments WHERE team_id=$1`, team.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	run := func(input string) string {
		t.Helper()
		runCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(runCtx, binary, "-join", "join.json", "-name", "isolated-node", "setup")
		cmd.Dir = dir
		cmd.Stdin = strings.NewReader(input)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("node setup failed: %v; %s", err, output)
		}
		if strings.Contains(string(output), code) {
			t.Fatal("pairing code printed")
		}
		return string(output)
	}
	output := run("yes\n1\n" + code + "\n")
	if !strings.Contains(output, "no execution roles") {
		t.Fatalf("unexpected setup output: %s", output)
	}
	identityPath := filepath.Join(dir, "node-state", "identity.json")
	identity, err := os.ReadFile(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	output = run("yes\n")
	if !strings.Contains(output, "pairing skipped") {
		t.Fatal("resume tried to pair again")
	}
	afterIdentity, _ := os.ReadFile(identityPath)
	if string(identity) != string(afterIdentity) {
		t.Fatal("identity changed on resume")
	}
	devices, err := s.m.pg.TeamWorkspaceDevices(ctx, team.ID, member.ID)
	if err != nil || len(devices) != 1 {
		t.Fatalf("devices: %d %v", len(devices), err)
	}
	var caps struct {
		Execution bool `json:"execution_enabled"`
	}
	json.Unmarshal(devices[0].Capabilities, &caps)
	if caps.Execution {
		t.Fatal("connection-only node enabled execution")
	}
	after := 0
	s.m.pg.QueryRow(`SELECT count(*) FROM team_execution_assignments WHERE team_id=$1`, team.ID).Scan(&after)
	if before != after {
		t.Fatal("setup assigned work")
	}
	t.Log("actual Node: trusted TLS -> config -> one-time pair -> same identity resume; no work claimed")
}
