package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Autumn-27/artex/collab"
	"github.com/Autumn-27/artex/db"
)

func TestTeamDispatchQueuesUntilRunnableAndPreservesScope(t *testing.T) {
	s, _, task := workflowFixture(t)
	ctx := context.Background()
	pg := s.m.pg
	tid := mustTaskID(t, task.ID)
	_, e := pg.Exec(`UPDATE tasks SET paused=true,queued=false,status='created' WHERE id=$1`, tid)
	if e != nil {
		t.Fatal(e)
	}
	team, e := pg.CreateTeam(ctx, "dispatch fixture")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM team_execution_assignments WHERE team_id=$1`, team.ID)
		_, _ = pg.Exec(`DELETE FROM teams WHERE id=$1`, team.ID)
	})
	member, e := pg.CreateTeamMember(ctx, team.ID, "dispatcher", "unused")
	if e != nil {
		t.Fatal(e)
	}
	for _, perm := range []string{"read", "execute", "manage"} {
		if e = pg.AttachTeamTask(ctx, team.ID, tid, member.ID, perm); e != nil {
			t.Fatal(e)
		}
	}
	pair, _ := pg.CreateTeamDevicePairing(ctx, team.ID, member.ID, time.Minute)
	caps := json.RawMessage(`{"version":1,"execution_enabled":true,"roles":["reverse_static"],"capabilities":[]}`)
	device, token, e := pg.PairTeamDevice(ctx, pair, "eligible", caps)
	if e != nil {
		t.Fatal(e)
	}
	if e = pg.UpdateTeamDeviceCapabilities(ctx, device.ID, token, caps); e != nil {
		t.Fatal(e)
	}
	intent, e := task.Store.AddWorkIntent(ctx, "queued fixture", 1, nil, nil, db.WorkContract{ExecutionRole: "reverse_static"})
	if e != nil {
		t.Fatal(e)
	}
	current, _ := pg.GetTask(tid)
	in := teamAssignInput{IntentID: intent}
	scope, payload, e := s.teamDispatchScope(current, in)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(teamQueuedInput{in, scope})
	id, e := pg.QueueTeamDispatch(ctx, team.ID, tid, intent, member.ID, raw, payload)
	if e != nil {
		t.Fatal(e)
	}
	if ok, e := task.Store.ClaimIntent(intent, "local"); e != nil || ok {
		t.Fatalf("local worker stole queue: %t %v", ok, e)
	}
	s.dispatchTeamOnce(ctx)
	rows, _ := pg.ListTeamDispatch(ctx, team.ID, tid, false)
	if len(rows) != 1 || rows[0].State != "queued" {
		t.Fatalf("paused dispatch %+v", rows)
	}
	_, _ = pg.Exec(`UPDATE tasks SET paused=false WHERE id=$1`, tid)
	s.dispatchTeamOnce(ctx)
	rows, _ = pg.ListTeamDispatch(ctx, team.ID, tid, false)
	if rows[0].State != "assigned" || rows[0].AssignmentID == nil {
		t.Fatalf("dispatch did not assign: %+v", rows)
	}
	assignments, _ := pg.ListTeamExecutionAssignments(ctx, team.ID, member.ID, tid)
	if len(assignments) != 1 || assignments[0].DeviceID != device.ID {
		t.Fatalf("wrong assignment %+v", assignments)
	}
	s.dispatchTeamOnce(ctx)
	assignments, _ = pg.ListTeamExecutionAssignments(ctx, team.ID, member.ID, tid)
	if len(assignments) != 1 {
		t.Fatal("duplicate assignment")
	}
	if e = pg.CancelTeamDispatch(ctx, team.ID, tid, id, member.ID, false, "stale cancel"); e == nil {
		t.Fatal("queued cancel revoked assigned work")
	}

	intent2, e := task.Store.AddWorkIntent(ctx, "second queue", 1, nil, nil, db.WorkContract{ExecutionRole: "reverse_static"})
	if e != nil {
		t.Fatal(e)
	}
	in.IntentID = intent2
	scope, payload, _ = s.teamDispatchScope(current, in)
	raw, _ = json.Marshal(teamQueuedInput{in, scope})
	_, e = pg.QueueTeamDispatch(ctx, team.ID, tid, intent2, member.ID, raw, payload)
	if e != nil {
		t.Fatal(e)
	}
	s.dispatchTeamOnce(ctx)
	rows, _ = pg.ListTeamDispatch(ctx, team.ID, tid, true)
	if len(rows) != 1 {
		t.Fatal("busy device did not leave queued work")
	}
	_, _ = pg.Exec(`UPDATE exploration_nodes SET payload=payload||'{"summary":"changed by owner"}'::jsonb WHERE id=$1`, intent2)
	s.dispatchTeamOnce(ctx)
	rows, _ = pg.ListTeamDispatch(ctx, team.ID, tid, true)
	if len(rows) != 0 {
		t.Fatal("changed scope remained runnable")
	}
	node, _ := task.Store.GetNode(intent2)
	if node.State != "paused" {
		t.Fatalf("invalidated queue should await owner: %s", node.State)
	}
}

func TestTeamDispatchRotatesBeyondFirstHundredQueuedRows(t *testing.T) {
	s, _, task := workflowFixture(t)
	ctx := context.Background()
	pg := s.m.pg
	tid := mustTaskID(t, task.ID)
	_, e := pg.Exec(`UPDATE tasks SET paused=true,queued=false,status='created' WHERE id=$1`, tid)
	if e != nil {
		t.Fatal(e)
	}
	team, e := pg.CreateTeam(ctx, "dispatch fairness fixture")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM team_execution_assignments WHERE team_id=$1`, team.ID)
		_, _ = pg.Exec(`DELETE FROM teams WHERE id=$1`, team.ID)
	})
	member, e := pg.CreateTeamMember(ctx, team.ID, "fair dispatcher", "unused")
	if e != nil {
		t.Fatal(e)
	}
	for _, perm := range []string{"read", "execute", "manage"} {
		if e = pg.AttachTeamTask(ctx, team.ID, tid, member.ID, perm); e != nil {
			t.Fatal(e)
		}
	}
	pair, _ := pg.CreateTeamDevicePairing(ctx, team.ID, member.ID, time.Minute)
	caps := json.RawMessage(`{"version":1,"execution_enabled":true,"roles":["reverse_static"],"capabilities":[]}`)
	device, token, e := pg.PairTeamDevice(ctx, pair, "fairness fixture", caps)
	if e != nil {
		t.Fatal(e)
	}
	if e = pg.UpdateTeamDeviceCapabilities(ctx, device.ID, token, caps); e != nil {
		t.Fatal(e)
	}
	var lastIntent int64
	for i := 0; i < 101; i++ {
		intent, e := task.Store.AddWorkIntent(ctx, fmt.Sprintf("fairness item %03d", i), 1, nil, nil, db.WorkContract{ExecutionRole: "reverse_static"})
		if e != nil {
			t.Fatalf("create intent %d: %v", i, e)
		}
		lastIntent = intent
		current, e := pg.GetTask(tid)
		if e != nil {
			t.Fatal(e)
		}
		in := teamAssignInput{IntentID: intent}
		scope, payload, e := s.teamDispatchScope(current, in)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := json.Marshal(teamQueuedInput{in, scope})
		if _, e = pg.QueueTeamDispatch(ctx, team.ID, tid, intent, member.ID, raw, payload); e != nil {
			t.Fatalf("queue item %d: %v", i, e)
		}
	}
	s.dispatchTeamOnce(ctx) // all 101 wait on the paused task; first 100 are marked attempted
	if _, e = pg.Exec(`UPDATE tasks SET paused=false WHERE id=$1`, tid); e != nil {
		t.Fatal(e)
	}
	s.dispatchTeamOnce(ctx)
	rows, e := pg.ListTeamDispatch(ctx, team.ID, tid, false)
	if e != nil {
		t.Fatal(e)
	}
	assigned := 0
	for _, row := range rows {
		if row.State == "assigned" {
			assigned++
			if row.IntentID != lastIntent {
				t.Fatalf("tail intent starved: got %d want %d", row.IntentID, lastIntent)
			}
		}
	}
	if assigned != 1 {
		t.Fatalf("expected the previously unvisited tail item to be assigned, assigned=%d", assigned)
	}
}

func TestTeamDynamicRuntimeRequiresExplicitMaterialAndProfileBinding(t *testing.T) {
	s, _, task := workflowFixture(t)
	ctx := context.Background()
	pg := s.m.pg
	tid := mustTaskID(t, task.ID)
	_, _ = pg.Exec(`UPDATE tasks SET paused=true,queued=false,status='created' WHERE id=$1`, tid)
	team, e := pg.CreateTeam(ctx, "runtime binding fixture")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM team_execution_assignments WHERE team_id=$1`, team.ID)
		_, _ = pg.Exec(`DELETE FROM teams WHERE id=$1`, team.ID)
	})
	member, _ := pg.CreateTeamMember(ctx, team.ID, "runtime owner", "unused")
	for _, perm := range []string{"read", "execute", "manage"} {
		if e = pg.AttachTeamTask(ctx, team.ID, tid, member.ID, perm); e != nil {
			t.Fatal(e)
		}
	}
	profile := collab.RuntimeProfile{ID: "linux-lab", Name: "owned fixture", Platform: "linux", Digest: collab.ContentHash([]byte("local settings")), MaxDurationMS: 1000}
	caps, _ := json.Marshal(map[string]any{"version": 1, "execution_enabled": true, "roles": []string{"reverse_dynamic"}, "capabilities": []string{"reverse_observe_runtime", "other_role_only"}, "role_capabilities": map[string][]string{"reverse_dynamic": {"reverse_observe_runtime"}}, "runtime_profiles": []collab.RuntimeProfile{profile}})
	pair, _ := pg.CreateTeamDevicePairing(ctx, team.ID, member.ID, time.Minute)
	device, _, e := pg.PairTeamDevice(ctx, pair, "runtime fixture", caps)
	if e != nil {
		t.Fatal(e)
	}
	intent, e := task.Store.AddWorkIntent(ctx, "observe owned sample", 1, nil, nil, db.WorkContract{ExecutionRole: "reverse_dynamic"})
	if e != nil {
		t.Fatal(e)
	}
	current, _ := pg.GetTask(tid)
	in := teamAssignInput{IntentID: intent, DeviceID: device.ID, RuntimeProfileID: profile.ID}
	if _, e = s.prepareTeamAssignment(ctx, team.ID, current, in, 0); e == nil {
		t.Fatal("dynamic observation without consent/materials was accepted")
	}
	in.AuthorizeRuntime = true
	if _, e = s.prepareTeamAssignment(ctx, team.ID, current, in, 0); e == nil {
		t.Fatal("empty materials accepted")
	}
	// The portable binding also refuses unknown material hashes independently of HTTP.
	a := collab.Assignment{ID: 1, TaskID: tid, IntentID: intent, Epoch: 1, Config: collab.ExecutionConfig{Version: 1, Kind: "reverse", Role: "reverse_dynamic", DynamicAllowed: true, Runtime: &collab.RuntimeBinding{RuntimeProfile: profile, ArtifactHashes: []string{profile.Digest}}, MaxTurns: 1, BudgetSeconds: 10}, Input: collab.ExecutionInput{Version: 1, Intent: fmt.Sprint(intent)}}
	if e = a.Validate(); e == nil {
		t.Fatal("runtime hash missing from input accepted")
	}
	content := []byte("owned inert fixture")
	relative := filepath.Join("tasks", task.ID, "reverse", "artifacts", "runtime-fixture.txt")
	path := filepath.Join(s.m.dir, relative)
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, content, 0600); e != nil {
		t.Fatal(e)
	}
	artifact, e := pg.AddReverseArtifact(tid, db.ReverseArtifact{Name: "runtime fixture", Path: relative, SizeBytes: int64(len(content)), SHA256: collab.ContentHash(content), Format: "text"})
	if e != nil {
		t.Fatal(e)
	}
	in.ArtifactIDs = []int64{artifact.ID}
	in.RuntimeDigest = collab.ContentHash([]byte("old advertised profile"))
	requestJSON, _ := json.Marshal(in)
	request := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/teams/%d/tasks/%d/dispatch", team.ID, tid), bytes.NewReader(requestJSON))
	adminToken, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+adminToken)
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("queued stale profile was silently rebound: %d %s", recorder.Code, recorder.Body.String())
	}
	in.RuntimeDigest = profile.Digest
	in.Capabilities = []string{"other_role_only"}
	if _, e = s.prepareTeamAssignment(ctx, team.ID, current, in, 0); e == nil {
		t.Fatal("capability from another role was accepted")
	}
	in.Capabilities = nil
	assigned, e := s.prepareTeamAssignment(ctx, team.ID, current, in, 0)
	if e != nil {
		t.Fatal(e)
	}
	var config collab.ExecutionConfig
	_ = json.Unmarshal(assigned.Config, &config)
	if len(config.Capabilities) != 1 || config.Capabilities[0] != "reverse_observe_runtime" {
		t.Fatal("explicit runtime consent failed to assemble the runtime tool")
	}
	if config.Runtime == nil || config.Runtime.Digest != profile.Digest || len(config.Runtime.ArtifactHashes) != 1 || config.Runtime.ArtifactHashes[0] != artifact.SHA256 {
		t.Fatalf("lost authorization binding %+v", config)
	}
	if e = s.teamSnapshotCurrent(ctx, assigned); e != nil {
		t.Fatal(e)
	}
	queuedIntent, e := task.Store.AddWorkIntent(ctx, "queued runtime fixture", 1, nil, nil, db.WorkContract{ExecutionRole: "reverse_dynamic"})
	if e != nil {
		t.Fatal(e)
	}
	queuedInput := teamAssignInput{IntentID: queuedIntent, DeviceID: device.ID, RuntimeProfileID: profile.ID, RuntimeDigest: profile.Digest, AuthorizeRuntime: true, ArtifactIDs: []int64{artifact.ID}}
	queuedTask, _ := pg.GetTask(tid)
	queuedScope, queuedPayload, e := s.teamDispatchScope(queuedTask, queuedInput)
	if e != nil {
		t.Fatal(e)
	}
	queuedRaw, _ := json.Marshal(teamQueuedInput{queuedInput, queuedScope})
	if _, e = pg.QueueTeamDispatch(ctx, team.ID, tid, queuedIntent, member.ID, queuedRaw, queuedPayload); e != nil {
		t.Fatal(e)
	}
	profile.Digest = collab.ContentHash([]byte("changed settings"))
	caps, _ = json.Marshal(map[string]any{"version": 1, "execution_enabled": true, "roles": []string{"reverse_dynamic"}, "capabilities": []string{"reverse_observe_runtime"}, "runtime_profiles": []collab.RuntimeProfile{profile}})
	_, _ = pg.Exec(`UPDATE team_devices SET capabilities=$2::jsonb WHERE id=$1`, device.ID, string(caps))
	s.dispatchTeamOnce(ctx)
	queue, e := pg.ListTeamDispatch(ctx, team.ID, tid, true)
	if e != nil {
		t.Fatal(e)
	}
	if len(queue) != 0 {
		t.Fatalf("profile-changed dispatch still queued: %+v", queue)
	}
	queuedNode, e := task.Store.GetNode(queuedIntent)
	if e != nil {
		t.Fatal(e)
	}
	var queuedContract map[string]any
	_ = json.Unmarshal(queuedNode.Payload, &queuedContract)
	if contract, _ := queuedContract["contract"].(map[string]any); contract["remote_dispatch_pending"] == true {
		t.Fatal("profile-changed dispatch retained remote pending marker")
	}
	if e = s.teamSnapshotCurrent(ctx, assigned); e == nil {
		t.Fatal("changed runtime settings did not invalidate assignment")
	}
}
