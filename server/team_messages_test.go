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
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/collab"
	"github.com/Autumn-27/artex/db"
	"github.com/golang-jwt/jwt/v5"
)

func TestTeamMessageHTTPPermissionsAndScope(t *testing.T) {
	s, task, other := workflowFixture(t)
	ctx := context.Background()
	pg := s.m.pg
	tid := mustTaskID(t, task.ID)
	team, err := pg.CreateTeam(ctx, "message fixture")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM team_execution_assignments WHERE team_id=$1`, team.ID)
		_, _ = pg.Exec(`DELETE FROM teams WHERE id=$1`, team.ID)
	})
	member, err := pg.CreateTeamMember(ctx, team.ID, "reader", "unused")
	if err != nil {
		t.Fatal(err)
	}
	if err = pg.AttachTeamTask(ctx, team.ID, tid, member.ID, "read"); err != nil {
		t.Fatal(err)
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{Subject: fmt.Sprintf("team:%d:%d", team.ID, member.ID), ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}).SignedString(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	iid, err := task.Store.AddWorkIntent(ctx, "message-only work", 1, nil, nil, db.WorkContract{})
	if err != nil {
		t.Fatal(err)
	}
	otherID, err := other.Store.AddWorkIntent(ctx, "private work", 1, nil, nil, db.WorkContract{})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []db.Activity{{Kind: "user", Summary: "hello", Detail: "hello"}, {Kind: "text", Summary: "reply", Detail: "full reply"}, {Kind: "result", Summary: "final", Detail: "complete final answer"}, {Kind: "result", Tool: "legacy-tool", Detail: "hidden legacy tool"}, {Kind: "tool_result", Summary: "hidden tool", Detail: "hidden secret"}, {Kind: "thinking", Summary: "hidden reasoning"}} {
		a.NodeID = &iid
		if _, err = task.Store.AppendActivity(a); err != nil {
			t.Fatal(err)
		}
	}
	host := httptest.NewTLSServer(s.Handler())
	defer host.Close()
	request := func(method, path, credential string, body any, code int) []byte {
		t.Helper()
		raw, _ := json.Marshal(body)
		r, e := http.NewRequest(method, host.URL+path, bytes.NewReader(raw))
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("Authorization", "Bearer "+credential)
		r.Header.Set("Content-Type", "application/json")
		response, e := host.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		result, e := io.ReadAll(response.Body)
		if e != nil {
			t.Fatal(e)
		}
		if response.StatusCode != code {
			t.Fatalf("%s %s: %d %s", method, path, response.StatusCode, result)
		}
		return result
	}
	base := fmt.Sprintf("/api/teams/%d/tasks/%d", team.ID, tid)
	raw := request("GET", base+fmt.Sprintf("/messages?session=intent:%d", iid), token, nil, 200)
	if bytes.Contains(raw, []byte("hidden")) || !bytes.Contains(raw, []byte("full reply")) || !bytes.Contains(raw, []byte("complete final answer")) {
		t.Fatalf("message projection %s", raw)
	}
	request("GET", base+fmt.Sprintf("/messages?session=intent:%d", otherID), token, nil, 404)
	request("GET", fmt.Sprintf("/api/teams/%d/tasks/%s/messages", team.ID, other.ID), admin, nil, 403)
	request("GET", fmt.Sprintf("/api/tasks/%d/collaboration/sessions", tid), token, nil, 403)
	request("GET", base+"/sessions", token, nil, 200)
	in := map[string]any{"intent_id": iid, "request_id": "request-1", "message": "direction"}
	request("POST", base+"/messages", token, in, 403)
	if err = pg.AttachTeamTask(ctx, team.ID, tid, member.ID, "execute"); err != nil {
		t.Fatal(err)
	}
	request("POST", base+"/messages", token, in, 409) // no running local session
	pair, e := pg.CreateTeamDevicePairing(ctx, team.ID, member.ID, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	device, deviceToken, e := pg.PairTeamDevice(ctx, pair, "message node", json.RawMessage(`{"version":1,"message_protocol":1,"execution_enabled":true,"roles":["worker"],"capabilities":[]}`))
	if e != nil {
		t.Fatal(e)
	}
	stored, e := pg.GetTask(tid)
	if e != nil {
		t.Fatal(e)
	}
	a, e := s.prepareTeamAssignment(ctx, team.ID, stored, teamAssignInput{IntentID: iid, DeviceID: device.ID}, 0)
	if e != nil {
		t.Fatal(e)
	}
	devicePath := fmt.Sprintf("/api/collaboration/device/assignments/%d", a.ID)
	request("POST", devicePath+"/claim", deviceToken, map[string]any{"epoch": a.Epoch}, 200)
	request("POST", devicePath+"/messages", deviceToken, collab.MessageExchange{Epoch: a.Epoch}, 200)
	in["assignment_id"] = a.ID
	in["epoch"] = a.Epoch
	request("POST", base+"/messages", token, in, 202)
	raw = request("POST", devicePath+"/messages", deviceToken, collab.MessageExchange{Epoch: a.Epoch, Messages: []collab.DeviceMessage{{Seq: 1, Text: "real HTTP remote reply"}}}, 200)
	var exchange collab.MessageExchangeReply
	if json.Unmarshal(raw, &exchange) != nil || len(exchange.Guidance) != 1 || exchange.Guidance[0].Text != "direction" {
		t.Fatalf("guidance response %s", raw)
	}
	request("POST", devicePath+"/messages", deviceToken, collab.MessageExchange{Epoch: a.Epoch, Delivered: []int64{exchange.Guidance[0].ID}, Seal: true}, 200)
	raw = request("GET", base+fmt.Sprintf("/messages?session=intent:%d", iid), token, nil, 200)
	if !bytes.Contains(raw, []byte("real HTTP remote reply")) || !bytes.Contains(raw, []byte(`"guidance_status":"delivered"`)) {
		t.Fatalf("remote projection %s", raw)
	}
	if _, err = pg.Exec(`DELETE FROM team_task_permissions WHERE team_id=$1 AND member_id=$2 AND permission='read'`, team.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	request("GET", base+"/messages", token, nil, 403)
}

func TestRemoteLocalAdmissionReentersFIFOWithoutRevokingLease(t *testing.T) {
	s, task, other := workflowFixture(t)
	ctx := context.Background()
	pg := s.m.pg
	tid := mustTaskID(t, task.ID)
	s.engine = newAdmissionTestServer(s.m, nil).engine
	s.m.mu.Lock()
	delete(s.m.tasks, other.ID)
	s.m.mu.Unlock()
	defer restoreConcurrencySetting(t, s.m)()
	if err := s.m.SetConcurrency(true, 1); err != nil {
		t.Fatal(err)
	}
	team, err := pg.CreateTeam(ctx, "remote queue fixture")
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
		id   int64
		perm string
	}{{member.ID, "execute"}, {member.ID, "read"}, {reviewer.ID, "review"}, {reviewer.ID, "read"}} {
		if err = pg.AttachTeamTask(ctx, team.ID, tid, p.id, p.perm); err != nil {
			t.Fatal(err)
		}
	}
	pair, err := pg.CreateTeamDevicePairing(ctx, team.ID, member.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	device, token, err := pg.PairTeamDevice(ctx, pair, "node", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	iid, err := task.Store.AddWorkIntent(ctx, "remote owned work", 1, nil, nil, db.WorkContract{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := pg.CreateTeamExecutionAssignment(ctx, team.ID, tid, iid, member.ID, device.ID, time.Hour, json.RawMessage(`{}`), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pg.ClaimTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch); err != nil {
		t.Fatal(err)
	}
	waiter, err := s.m.CreateTask("local waiter", "queue", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(mustTaskID(t, waiter.ID)) })
	if err = s.m.EnqueueTask(waiter.ID, "resume"); err != nil {
		t.Fatal(err)
	}
	s.engine.Pause(waiter.ID, agent.AbortPausedOnReload)
	// Neither an active local operation nor a live manual conversation is parked.
	s.engine.beginTaskOperation(task.ID)
	s.reconcileConcurrency()
	if task.lifecycleSnapshot().Queued {
		t.Fatal("active local operation parked")
	}
	s.engine.decInflight(task.ID)
	liveCtx, liveCancel := context.WithCancelCause(ctx)
	_, _, release := s.engine.liveRun(liveCtx, task.ID, liveCancel, true)
	s.reconcileConcurrency()
	if task.lifecycleSnapshot().Queued {
		t.Fatal("live main conversation parked")
	}
	release()
	liveCancel(nil)
	s.reconcileConcurrency()
	if !task.lifecycleSnapshot().Queued || task.lifecycleSnapshot().QueueMode != db.RemoteWaitQueueMode || waiter.lifecycleSnapshot().Queued {
		t.Fatal("remote did not release slot to FIFO")
	}
	if _, err = pg.HeartbeatTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch, time.Minute); err != nil {
		t.Fatalf("parking revoked remote lease: %v", err)
	}
	if _, err = pg.ExchangeTeamMessages(ctx, a.ID, device.ID, token, collab.MessageExchange{Epoch: a.Epoch}); err != nil {
		t.Fatal(err)
	}
	if err = pg.QueueTeamGuidance(ctx, team.ID, tid, iid, a.ID, a.Epoch, member.ID, "queued-guidance", "continue remotely"); err != nil {
		t.Fatalf("local queue blocked remote guidance: %v", err)
	}
	if _, err = pg.CompleteTeamExecutionAssignment(ctx, a.ID, device.ID, token, a.Epoch, json.RawMessage(`{"outcome":"candidate","summary":"fixture result","evidence":[]}`)); err != nil {
		t.Fatal(err)
	}
	s.reconcileConcurrency()
	if !task.lifecycleSnapshot().Queued {
		t.Fatal("pending review consumed slot")
	}
	if err = pg.ReviewTeamExecutionAssignment(ctx, team.ID, a.ID, reviewer.ID, "accept", "independently checked"); err != nil {
		t.Fatal(err)
	}
	s.reconcileConcurrency()
	if !task.lifecycleSnapshot().Queued || s.runningTaskCount("") > 1 {
		t.Fatal("returned local work bypassed capacity")
	}
	if err = s.m.SetTaskPaused(waiter.ID, true); err != nil {
		t.Fatal(err)
	}
	s.engine.Pause(waiter.ID, agent.AbortPausedByUser)
	s.reconcileConcurrency()
	if task.lifecycleSnapshot().Queued || s.runningTaskCount("") > 1 {
		t.Fatal("returned work did not reenter FIFO")
	}
	n, err := task.Store.GetNode(iid)
	if err != nil || n == nil || !strings.Contains(string(n.Payload), "remote_review_receipt") {
		t.Fatal("remote result lost", err)
	}
}
