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
	"time"

	"github.com/Autumn-27/artex/collab"
	"github.com/golang-jwt/jwt/v5"
)

type branchHTTPFixture struct {
	s                *Server
	teamID           int64
	taskID           int64
	otherTaskID      int64
	base             string
	adminToken       string
	tokens           map[string]string
	members          map[string]int64
	deviceID         int64
	deviceToken      string
	otherDeviceID    int64
	otherDeviceToken string
	host             *httptest.Server
}

func newBranchHTTPFixture(t *testing.T) *branchHTTPFixture {
	t.Helper()
	s, task, otherTask := workflowFixture(t)
	ctx := context.Background()
	pg := s.m.pg
	taskID := mustTaskID(t, task.ID)
	otherTaskID := mustTaskID(t, otherTask.ID)
	team, err := pg.CreateTeam(ctx, "branch http fixture")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM team_execution_assignments WHERE team_id=$1`, team.ID)
		_, _ = pg.Exec(`DELETE FROM teams WHERE id=$1`, team.ID)
	})
	f := &branchHTTPFixture{s: s, teamID: team.ID, taskID: taskID, base: fmt.Sprintf("/api/teams/%d/tasks/%d", team.ID, taskID), tokens: map[string]string{}, members: map[string]int64{}}
	adminToken, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	f.adminToken = adminToken
	for _, name := range []string{"owner", "process", "evidence", "guide", "control", "outsider", "reader"} {
		m, e := pg.CreateTeamMember(ctx, team.ID, name, "unused")
		if e != nil {
			t.Fatal(e)
		}
		f.members[name] = m.ID
		if e = pg.AttachTeamTask(ctx, team.ID, taskID, m.ID, "read"); e != nil {
			t.Fatal(e)
		}
		claims := jwt.RegisteredClaims{Subject: fmt.Sprintf("team:%d:%d", team.ID, m.ID), ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}
		tok, e := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.jwtKey)
		if e != nil {
			t.Fatal(e)
		}
		f.tokens[name] = tok
	}
	if err = pg.AttachTeamTask(ctx, team.ID, taskID, f.members["owner"], "execute"); err != nil {
		t.Fatal(err)
	}
	if err = pg.AttachTeamTask(ctx, team.ID, otherTaskID, f.members["reader"], "read"); err != nil {
		t.Fatal(err)
	}
	f.otherTaskID = otherTaskID
	if err = pg.AttachTeamTask(ctx, team.ID, taskID, f.members["owner"], "manage"); err != nil {
		t.Fatal(err)
	}
	if err = pg.SetPaused(taskID, true); err != nil {
		t.Fatal(err)
	}
	policy := collab.BranchPolicy{Version: 1, Goal: "HTTP fixture", Budget: 100, MaxToolSeconds: 30, MinToolIntervalMS: 0, Kinds: []string{"pentest"}, Assets: []collab.BranchAsset{{ID: "fixture", Target: "https://fixture.invalid", Version: "v1"}}, PlannerPrompts: map[string]string{"pentest": "fixture plan"}, Roles: map[string]collab.ExecutionConfig{}}
	for _, role := range []string{"worker", "reviewer"} {
		policy.Roles[role] = collab.ExecutionConfig{Version: 1, Kind: "pentest", Role: role, SystemPrompt: "fixture role", MaxTurns: 8, BudgetSeconds: 30, Capabilities: []string{}}
	}
	if _, err = pg.CreateBranchProject(ctx, team.ID, taskID, collab.BranchActor{Admin: true}, policy); err != nil {
		t.Fatal(err)
	}
	grants := map[string][]string{
		"owner":   {"read", "process", "evidence", "discuss", "execute", "guide", "control", "manage"},
		"process": {"read", "process"}, "evidence": {"read", "evidence"},
		"guide": {"read", "guide"}, "control": {"read", "control"},
		"outsider": {"read", "process", "evidence"}, "reader": {"read"},
	}
	for name, perms := range grants {
		for _, perm := range perms {
			cmd := collab.BranchCommand{Type: "grant", RequestID: "grant-" + name + "-" + perm, MemberID: f.members[name], Permission: perm}
			if _, err = pg.ApplyBranchCommand(ctx, team.ID, taskID, collab.BranchActor{Admin: true}, cmd); err != nil {
				t.Fatalf("grant %s/%s: %v", name, perm, err)
			}
		}
	}
	pair, err := pg.CreateTeamDevicePairing(ctx, team.ID, f.members["owner"], time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	caps := json.RawMessage(`{"version":1,"branch_protocol":1,"execution_enabled":true,"roles":["planner","worker","reviewer"],"role_capabilities":{}}`)
	device, token, err := pg.PairTeamDevice(ctx, pair, "branch owner node", caps)
	if err != nil {
		t.Fatal(err)
	}
	f.deviceID, f.deviceToken = device.ID, token
	pair, err = pg.CreateTeamDevicePairing(ctx, team.ID, f.members["outsider"], time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	other, otherToken, err := pg.PairTeamDevice(ctx, pair, "unauthorized node", caps)
	if err != nil {
		t.Fatal(err)
	}
	f.otherDeviceID, f.otherDeviceToken = other.ID, otherToken
	f.host = httptest.NewTLSServer(s.Handler())
	t.Cleanup(f.host.Close)
	return f
}

func (f *branchHTTPFixture) request(t *testing.T, method, path, token string, body any, want int) []byte {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req, err := http.NewRequest(method, f.host.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.host.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	result, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != want {
		t.Fatalf("%s %s: status %d want %d: %s", method, path, resp.StatusCode, want, result)
	}
	return result
}

func (f *branchHTTPFixture) createBranch(t *testing.T, title string, restricted bool, members []int64) int64 {
	t.Helper()
	work := collab.BranchWorkSpec{Title: title, Question: "inspect only the fixture", Kind: "pentest", AssetIDs: []string{"fixture"}, Roles: []string{"worker", "reviewer"}, Acceptance: []string{"evidence recorded"}, Budget: 40, Restricted: restricted, Members: members}
	f.request(t, "POST", f.base+"/branches/command", f.adminToken, collab.BranchCommand{Type: "publish", RequestID: "publish-" + title, Work: &work}, http.StatusOK)
	var pool struct {
		Project collab.BranchProject `json:"project"`
	}
	if err := json.Unmarshal(f.request(t, "GET", f.base+"/branches", f.tokens["owner"], nil, http.StatusOK), &pool); err != nil {
		t.Fatal(err)
	}
	var workID int64
	for _, p := range pool.Project.Pool {
		if p.Spec.Title == title {
			workID = p.ID
		}
	}
	if workID == 0 {
		t.Fatalf("work %q missing from owner projection", title)
	}
	var claimed struct {
		Receipt collab.BranchReceipt `json:"receipt"`
	}
	raw := f.request(t, "POST", f.base+"/branches/command", f.tokens["owner"], collab.BranchCommand{Type: "claim", RequestID: "claim-" + title, WorkID: workID, DeviceID: f.deviceID}, http.StatusOK)
	if err := json.Unmarshal(raw, &claimed); err != nil {
		t.Fatal(err)
	}
	if claimed.Receipt.BranchID == 0 {
		t.Fatalf("claim %q returned no branch ID", title)
	}
	return claimed.Receipt.BranchID
}

func (f *branchHTTPFixture) createSensitiveBranch(t *testing.T) int64 {
	return f.createBranch(t, "private branch", true, []int64{f.members["owner"]})
}

func TestBranchHTTPAccessMatrixScopedRoutesAndLegacyWrites(t *testing.T) {
	f := newBranchHTTPFixture(t)
	bid := f.createSensitiveBranch(t)
	publicID := f.createBranch(t, "public process branch", false, nil)
	var ownerView struct {
		Project collab.BranchProject `json:"project"`
	}
	if err := json.Unmarshal(f.request(t, "GET", f.base+"/branches", f.tokens["owner"], nil, http.StatusOK), &ownerView); err != nil {
		t.Fatal(err)
	}
	var public collab.ExecutionBranch
	for _, branch := range ownerView.Project.Branches {
		if branch.ID == publicID {
			public = branch
		}
	}
	if public.ID == 0 {
		t.Fatal("owner projection omitted public branch")
	}
	devicePath := fmt.Sprintf("/api/collaboration/device/branches/%d/%d/command", f.taskID, publicID)
	f.request(t, "POST", devicePath, f.deviceToken, collab.BranchCommand{Type: "ready", RequestID: "ready-public", BranchID: publicID, Epoch: public.Epoch}, http.StatusOK)
	evidenceContent := "authorized evidence body"
	evidence := &collab.ExecutionEvidence{ID: "ev-http", Tool: "fixture-tool", SHA256: collab.ContentHash([]byte(evidenceContent)), Content: evidenceContent}
	f.request(t, "POST", devicePath, f.deviceToken, collab.BranchCommand{Type: "event", RequestID: "event-public", BranchID: publicID, Epoch: public.Epoch, Event: &collab.BranchEvent{Seq: 1, Kind: "evidence", Text: "public event marker", Evidence: evidence}}, http.StatusOK)
	// Restricted visibility applies to snapshots and direct branch selection.
	raw := f.request(t, "GET", f.base+"/branches?branch="+fmt.Sprint(bid), f.tokens["outsider"], nil, http.StatusForbidden)
	if len(raw) == 0 {
		t.Fatal("expected denied sensitive snapshot")
	}
	// Branch process and evidence are independent; the process reader sees no evidence payload.
	adminCmd := func(cmd collab.BranchCommand) {
		t.Helper()
		f.request(t, "POST", f.base+"/branches/command", f.adminToken, cmd, http.StatusOK)
	}
	adminCmd(collab.BranchCommand{Type: "grant", RequestID: "grant-extra", MemberID: f.members["process"], Permission: "process"})
	// Process grants event text while stripping evidence; evidence alone grants neither events nor process.
	var processView struct {
		Events []collab.BranchEvent `json:"events"`
	}
	if err := json.Unmarshal(f.request(t, "GET", f.base+"/branches?branch="+fmt.Sprint(publicID), f.tokens["process"], nil, http.StatusOK), &processView); err != nil {
		t.Fatal(err)
	}
	foundProcessEvent := false
	for _, event := range processView.Events {
		if event.BranchID == publicID && event.Text == "public event marker" {
			foundProcessEvent = true
			if event.Evidence != nil {
				t.Fatalf("process-only projection leaked evidence: %+v", event.Evidence)
			}
		}
	}
	if !foundProcessEvent {
		t.Fatalf("process event was not visible: %+v", processView.Events)
	}
	var searchView struct {
		Events []collab.BranchEvent `json:"events"`
	}
	if err := json.Unmarshal(f.request(t, "GET", f.base+"/branches?branch="+fmt.Sprint(publicID)+"&q=public%20event", f.tokens["process"], nil, http.StatusOK), &searchView); err != nil {
		t.Fatal(err)
	}
	if len(searchView.Events) != 1 || searchView.Events[0].Text != "public event marker" {
		t.Fatalf("authorized search did not match event: %+v", searchView.Events)
	}
	var exportView struct {
		Events []collab.BranchEvent `json:"events"`
	}
	if err := json.Unmarshal(f.request(t, "GET", f.base+"/branches/export?branch="+fmt.Sprint(publicID), f.tokens["process"], nil, http.StatusOK), &exportView); err != nil {
		t.Fatal(err)
	}
	if len(exportView.Events) == 0 {
		t.Fatal("authorized process export omitted events")
	}
	var evidenceView struct {
		Events      []collab.BranchEvent `json:"events"`
		Permissions []string             `json:"permissions"`
	}
	if err := json.Unmarshal(f.request(t, "GET", f.base+"/branches?branch="+fmt.Sprint(publicID), f.tokens["evidence"], nil, http.StatusOK), &evidenceView); err != nil {
		t.Fatal(err)
	}
	if len(evidenceView.Events) != 0 || contains(evidenceView.Permissions, "process") {
		t.Fatalf("evidence implied process access: %+v", evidenceView)
	}
	// Basic read is insufficient for search, cursor replay, or event export.
	f.request(t, "GET", f.base+"/branches", f.tokens["reader"], nil, http.StatusOK)
	f.request(t, "GET", f.base+"/branches?after=1", f.tokens["reader"], nil, http.StatusForbidden)
	f.request(t, "GET", f.base+"/branches/export?q=private", f.tokens["reader"], nil, http.StatusForbidden)
	// The guide permission alone is insufficient while another member controls the branch.
	f.request(t, "POST", f.base+"/branches/command", f.tokens["guide"], collab.BranchCommand{Type: "guide", RequestID: "guide-without-control", BranchID: bid, Text: "not authorized yet"}, http.StatusForbidden)
	f.request(t, "POST", f.base+"/branches/command", f.tokens["owner"], collab.BranchCommand{Type: "guide", RequestID: "owner-guide", BranchID: bid, Text: "authorized guidance"}, http.StatusOK)
	var ownerSnapshot struct {
		Project collab.BranchProject `json:"project"`
	}
	if err := json.Unmarshal(f.request(t, "GET", f.base+"/branches?branch="+fmt.Sprint(publicID), f.tokens["owner"], nil, http.StatusOK), &ownerSnapshot); err != nil {
		t.Fatal(err)
	}
	var publicRevision int64
	for _, branch := range ownerSnapshot.Project.Branches {
		if branch.ID == publicID {
			publicRevision = branch.Revision
		}
	}
	var takeover struct {
		Snapshot struct {
			Project collab.BranchProject `json:"project"`
		} `json:"snapshot"`
	}
	takeoverRaw := f.request(t, "POST", f.base+"/branches/command", f.adminToken, collab.BranchCommand{Type: "control_takeover", RequestID: "admin-set-controller", BranchID: publicID, MemberID: f.members["control"], Revision: publicRevision}, http.StatusOK)
	if err := json.Unmarshal(takeoverRaw, &takeover); err != nil {
		t.Fatal(err)
	}
	publicRevision = 0
	for _, branch := range takeover.Snapshot.Project.Branches {
		if branch.ID == publicID {
			publicRevision = branch.Revision
		}
	}
	if publicRevision == 0 {
		t.Fatal("control takeover snapshot omitted branch")
	}
	f.request(t, "POST", f.base+"/branches/command", f.tokens["control"], collab.BranchCommand{Type: "stop", RequestID: "control-stop", BranchID: publicID, Revision: publicRevision, Text: "HTTP control permission test"}, http.StatusOK)
	// No branch HTTP route may fall through to legacy task/chat mutation endpoints.
	f.request(t, "POST", fmt.Sprintf("/api/tasks/%d/chat/stop", f.taskID), f.adminToken, map[string]any{"reason": "branch mode fixture"}, http.StatusConflict)
	f.request(t, "POST", fmt.Sprintf("/api/tasks/%d/intents/1/messages", f.taskID), f.adminToken, map[string]any{"message": "legacy write"}, http.StatusConflict)
	// The team branch endpoint must return 404 for an unshared task rather than crossing team scope.
	f.request(t, "GET", fmt.Sprintf("/api/teams/%d/tasks/%d/branches", f.teamID, f.otherTaskID), f.tokens["reader"], nil, http.StatusNotFound)
}

func TestBranchHTTPDeviceOwnershipAndSSERevocation(t *testing.T) {
	f := newBranchHTTPFixture(t)
	bid := f.createSensitiveBranch(t)
	var snap struct {
		Project collab.BranchProject `json:"project"`
	}
	_ = json.Unmarshal(f.request(t, "GET", f.base+"/branches", f.tokens["owner"], nil, http.StatusOK), &snap)
	var branch collab.ExecutionBranch
	for _, item := range snap.Project.Branches {
		if item.ID == bid {
			branch = item
		}
	}
	if branch.ID == 0 {
		t.Fatal("owner projection omitted branch")
	}
	devicePath := fmt.Sprintf("/api/collaboration/device/branches/%d/%d/command", f.taskID, bid)
	f.request(t, "POST", devicePath, f.otherDeviceToken, collab.BranchCommand{Type: "ready", RequestID: "wrong-device-ready", BranchID: bid, Epoch: branch.Epoch}, http.StatusForbidden)
	f.request(t, "POST", devicePath, f.deviceToken, collab.BranchCommand{Type: "ready", RequestID: "owner-ready", BranchID: bid, Epoch: branch.Epoch}, http.StatusOK)
	// SSE must terminate after process access is revoked; it cannot retain its initial authorization.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", f.host.URL+f.base+"/branches/stream?branch="+fmt.Sprint(bid), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+f.tokens["owner"])
	resp, err := f.host.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("SSE status %d: %s", resp.StatusCode, b)
	}
	buf := make([]byte, 256)
	_, _ = resp.Body.Read(buf) // initial sync event proves the subscription is live
	admin := collab.BranchCommand{Type: "grant", RequestID: "revoke-owner-process", MemberID: f.members["owner"], Permission: "process", Revoke: true}
	f.request(t, "POST", f.base+"/branches/command", f.adminToken, admin, http.StatusOK)
	done := make(chan error, 1)
	go func() { _, readErr := io.Copy(io.Discard, resp.Body); done <- readErr }()
	select {
	case readErr := <-done:
		if readErr != nil {
			t.Fatalf("SSE close after revocation: %v", readErr)
		}
	case <-time.After(3 * time.Second):
		_ = resp.Body.Close()
		t.Fatal("SSE remained open after process permission was revoked")
	}
	_ = resp.Body.Close()
	// A new request after revocation is denied even if this client held an SSE connection.
	f.request(t, "GET", f.base+"/branches/stream?branch="+fmt.Sprint(bid), f.tokens["owner"], nil, http.StatusForbidden)
}
