package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Autumn-27/artex/collab"
	"github.com/Autumn-27/artex/db"
)

func TestTeamExecutionHTTPHandoffEvidenceAndIndependentReview(t *testing.T) {
	s, _, task := workflowFixture(t)
	ctx := context.Background()
	pg := s.m.pg
	tid := mustTaskID(t, task.ID)
	// This fixture creates two tasks under a one-slot manager. Remote admission
	// is tested independently of that local queue, in the isolated test DB only.
	if _, err := pg.Exec(`UPDATE tasks SET paused=true,queued=false,status='created' WHERE id=$1`, tid); err != nil {
		t.Fatal(err)
	}
	team, err := pg.CreateTeam(ctx, "portable execution fixture")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM team_execution_assignments WHERE team_id=$1`, team.ID)
		_, _ = pg.Exec(`DELETE FROM teams WHERE id=$1`, team.ID)
	})
	member, err := pg.CreateTeamMember(ctx, team.ID, "executor", "unused")
	if err != nil {
		t.Fatal(err)
	}
	reviewer, err := pg.CreateTeamMember(ctx, team.ID, "reviewer", "unused")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct {
		member int64
		perm   string
	}{{member.ID, "execute"}, {member.ID, "read"}, {reviewer.ID, "read"}, {reviewer.ID, "review"}} {
		if err = pg.AttachTeamTask(ctx, team.ID, tid, p.member, p.perm); err != nil {
			t.Fatal(err)
		}
	}
	pair, err := pg.CreateTeamDevicePairing(ctx, team.ID, member.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	device, token, err := pg.PairTeamDevice(ctx, pair, "analysis device", json.RawMessage(`{"version":1,"execution_enabled":true,"roles":["reverse_static"],"capabilities":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	admin, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the real authenticated routing and TLS server.
	host := httptest.NewTLSServer(s.Handler())
	defer host.Close()
	request := func(method, path, credential string, body any, status int) []byte {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		r, _ := http.NewRequest(method, host.URL+path, bytes.NewReader(raw))
		r.Header.Set("Authorization", "Bearer "+credential)
		r.Header.Set("Content-Type", "application/json")
		res, e := host.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		if res.StatusCode != status {
			t.Fatalf("%s %s: %d %s", method, path, res.StatusCode, b)
		}
		return b
	}
	intent, err := task.Store.AddWorkIntent(ctx, "explain owned text fixture", 1, nil, nil, db.WorkContract{ExecutionRole: "reverse_static", Acceptance: []string{"cite the fixture"}, BudgetSeconds: 120})
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("owned fixture: same bytes across devices\n")
	relative := filepath.Join("tasks", task.ID, "reverse", "artifacts", "fixture.txt")
	if err = os.MkdirAll(filepath.Dir(filepath.Join(s.m.dir, relative)), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(s.m.dir, relative), content, 0600); err != nil {
		t.Fatal(err)
	}
	artifact, err := pg.AddReverseArtifact(tid, db.ReverseArtifact{Name: "fixture.txt", Path: relative, SizeBytes: int64(len(content)), SHA256: collab.ContentHash(content), Format: "text"})
	if err != nil {
		t.Fatal(err)
	}
	prefix := fmt.Sprintf("/api/teams/%d/tasks/%d", team.ID, tid)
	request("GET", prefix+"/work", token, nil, 401)
	var assignment collab.Assignment
	if err = json.Unmarshal(request("POST", prefix+"/assignments", admin, teamAssignInput{IntentID: intent, DeviceID: device.ID, ArtifactIDs: []int64{artifact.ID}}, 201), &assignment); err != nil {
		t.Fatal(err)
	}
	if err = assignment.Validate(); err != nil {
		t.Fatal(err)
	}
	request("POST", prefix+"/assignments", admin, teamAssignInput{IntentID: intent, DeviceID: device.ID}, 409)
	endpoint := fmt.Sprintf("/api/collaboration/device/assignments/%d", assignment.ID)
	if got := request("GET", "/api/collaboration/device/assignments", token, nil, 200); string(bytes.TrimSpace(got)) != "[]" {
		t.Fatalf("paused task leaked runnable work: %s", got)
	}
	request("POST", endpoint+"/claim", token, map[string]any{"epoch": assignment.Epoch}, 403)
	if _, err = pg.Exec(`UPDATE tasks SET paused=false WHERE id=$1`, tid); err != nil {
		t.Fatal(err)
	}
	request("GET", "/api/collaboration/device/assignments", token, nil, 200)
	request("POST", endpoint+"/claim", token, map[string]any{"epoch": assignment.Epoch + 1}, 409)
	request("POST", endpoint+"/claim", token, map[string]any{"epoch": assignment.Epoch}, 200)
	request("POST", endpoint+"/heartbeat", token, map[string]any{"epoch": assignment.Epoch}, 200)
	materialPath := endpoint + "/materials/" + artifact.SHA256 + fmt.Sprintf("?epoch=%d", assignment.Epoch)
	if got := request("GET", materialPath, token, nil, 200); !bytes.Equal(got, content) {
		t.Fatal("material changed in transit")
	}
	request("GET", endpoint+"/materials/unknown?epoch=1", token, nil, 404)
	result := collab.ExecutionResult{Version: 1, Role: "reverse_static", Model: "synthetic-provider", Outcome: "candidate", Summary: "Fixture observed; independent validation pending", Evidence: []collab.ExecutionEvidence{{ID: "ev1", Tool: "read_material", Content: string(content), SHA256: collab.ContentHash(content)}}}
	result.Evidence[0].SHA256 = "wrong"
	request("POST", endpoint+"/result", token, map[string]any{"epoch": assignment.Epoch, "result": result}, 400)
	result.Evidence[0].SHA256 = collab.ContentHash(content)
	request("POST", endpoint+"/result", token, map[string]any{"epoch": assignment.Epoch, "result": result}, 200)
	request("POST", endpoint+"/result", token, map[string]any{"epoch": assignment.Epoch, "result": result}, 200)
	result.Summary = "mutated retry"
	request("POST", endpoint+"/result", token, map[string]any{"epoch": assignment.Epoch, "result": result}, 409)
	n, err := task.Store.GetNode(intent)
	if err != nil || n.State != "paused" {
		t.Fatalf("device prematurely completed work: %+v %v", n, err)
	}
	request("POST", fmt.Sprintf("/api/teams/%d/assignments/%d/review", team.ID, assignment.ID), admin, map[string]any{"reviewer_id": reviewer.ID, "decision": "accept", "note": "admin cannot impersonate reviewer"}, 403)
	if err = pg.ReviewTeamExecutionAssignment(ctx, team.ID, assignment.ID, reviewer.ID, "accept", "checked exact fixture evidence"); err != nil {
		t.Fatal(err)
	}
	n, err = task.Store.GetNode(intent)
	if err != nil || n.State == "done" {
		t.Fatalf("review bypassed normal intent acceptance: %+v %v", n, err)
	}
	facts, err := task.Store.ListByKind("fact", 50)
	if err != nil || len(facts) == 0 {
		t.Fatalf("review lost evidence: %v", err)
	}
	if !bytes.Contains(facts[0].Payload, []byte(artifact.SHA256)) {
		t.Fatal("fact lost evidence hash")
	}
}

func TestTeamMaterialSnapshotDetectsCorruptionAndForeignPath(t *testing.T) {
	s, _, task := workflowFixture(t)
	tid := mustTaskID(t, task.ID)
	content := []byte("fixture")
	a := &db.ReverseArtifact{Name: "sample", Path: "outside", SHA256: collab.ContentHash(content), SizeBytes: int64(len(content))}
	if _, err := s.snapshotTeamMaterial(99, tid, a); err == nil {
		t.Fatal("accepted foreign path")
	}
	a.Path = filepath.Join("tasks", task.ID, "reverse", "artifacts", "owned.txt")
	path := filepath.Join(s.m.dir, a.Path)
	_ = os.MkdirAll(filepath.Dir(path), 0700)
	_ = os.WriteFile(path, []byte("changed"), 0600)
	if _, err := s.snapshotTeamMaterial(99, tid, a); err == nil {
		t.Fatal("accepted mismatched source hash")
	}
}
