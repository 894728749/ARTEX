package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

func TestFindingCollaborationAPIsAndReviewerScope(t *testing.T) {
	s, first, request := trafficEvidenceServer(t)
	f, _ := s.m.pg.GetFinding(first.FindingID)
	tid := *f.TaskID
	second, err := s.m.pg.AddFinding(tid, 0, "auth", "independent cause", "medium", "needs first", "stored proof", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf("/api/tasks/%d", tid)
	res := request("GET", base+"/finding-relations", "")
	if res.Code != 200 || !strings.Contains(res.Body.String(), `"nodes"`) {
		t.Fatal(res.Code, res.Body)
	}
	res = request("POST", base+"/finding-relations", fmt.Sprintf(`{"source":%d,"target":%d,"kind":"enables","rationale":"provides a prerequisite","evidence":"stored verification","status":"proposed"}`, first.FindingID, second))
	if res.Code != 201 {
		t.Fatal(res.Code, res.Body)
	}
	var edge struct{ ID int64 }
	_ = json.Unmarshal(res.Body.Bytes(), &edge)
	res = request("GET", base+"/finding-relations", "")
	if !strings.Contains(res.Body.String(), `"enables"`) {
		t.Fatal(res.Body)
	}
	res = request("DELETE", fmt.Sprintf("%s/finding-relations/%d", base, edge.ID), "")
	if res.Code != 200 {
		t.Fatal(res.Code, res.Body)
	}
	res = request("PATCH", base+"/finding-review-status", `{"enabled":false,"batch_size":4}`)
	if res.Code != 200 || !strings.Contains(res.Body.String(), `"batch_size":4`) {
		t.Fatal(res.Code, res.Body)
	}
	res = request("PATCH", base+"/finding-review-status", `{"batch_size":1}`)
	if res.Code != 400 {
		t.Fatal(res.Code, res.Body)
	}
	reviewer, err := s.m.pg.GetAgentByKey(findingReviewerKey)
	if err != nil || reviewer == nil {
		t.Fatal("reviewer seed failed", err)
	}
	tools := s.findingReviewTools()
	read := workflowTool(t, tools, "get_finding_review_context")
	workflowCall(t, context.Background(), read, map[string]any{}, true)
	rid, _, err := s.m.pg.BeginFindingReview(t.Context(), tid, true)
	if err != nil || rid == 0 {
		t.Fatal(rid, err)
	}
	conv, err := s.m.pg.CreateConversation(findingReviewerKey, "scope test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.pg.DeleteConversation(conv.ID) })
	if _, err = s.m.pg.Exec(`UPDATE finding_reviews SET conversation_id=$2 WHERE id=$1`, rid, conv.ID); err != nil {
		t.Fatal(err)
	}
	ctx := intercept.WithConvID(t.Context(), conv.ID)
	out := workflowCall(t, ctx, read, map[string]any{"limit": 1}, false)
	if !strings.Contains(out, `"has_more":true`) {
		t.Fatal(out)
	}
	workflowCall(t, ctx, read, map[string]any{"finding_id": first.FindingID}, false)
	workflowCall(t, ctx, read, map[string]any{"finding_id": int64(9223372036854775806)}, true)
	workflowCall(t, ctx, workflowTool(t, tools, "finish_finding_review"), map[string]any{"summary": "Distinct root causes; retained separately."}, false)
	workflowCall(t, ctx, read, map[string]any{}, true)
}

func TestGentleTaskPauseBlocksQueueAndWaitsForTool(t *testing.T) {
	s, f, _ := trafficEvidenceServer(t)
	row, _ := s.m.pg.GetFinding(f.FindingID)
	task, _ := s.m.Task(fmt.Sprint(*row.TaskID))
	if err := s.m.SetTaskStatus(task.ID, "running"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	ctx, control, release := s.engine.liveRun(ctx, task.ID, cancel, false)
	defer release()
	hooks := control.Hooks(nil)
	if blocked, _, _ := hooks.PreToolUse(ctx, "Probe", nil); blocked {
		t.Fatal("tool blocked before pause")
	}
	iid, err := task.Store.AddIntent(map[string]any{"summary": "queued work"}, 5, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.applyTaskControl(task, "pause_after_tool")
	if err != nil || !result.Paused {
		t.Fatal(result, err)
	}
	if ctx.Err() != nil {
		t.Fatal("cancelled active tool")
	}
	if claimed := s.engine.claimNext(task, "test"); claimed != nil {
		t.Fatalf("queued worker started: %+v", claimed)
	}
	if _, err = s.applyTaskControl(task, "resume"); err == nil {
		t.Fatal("resumed before active tool finished")
	}
	fresh, _ := s.m.pg.GetTask(*row.TaskID)
	if !fresh.Paused {
		t.Fatal("pause not persisted", fresh)
	}
	hooks.PostToolUse(ctx, "Probe", nil, []byte("saved result"), false)
	if context.Cause(ctx) != agent.AbortPausedAfterTool {
		t.Fatal(context.Cause(ctx))
	}
	intent, _ := task.Store.GetNode(iid)
	if intent.State != "open" {
		t.Fatal("queue was mutated", intent.State)
	}
}

func TestRunningWorkerMessageAcceptedAndDeduplicated(t *testing.T) {
	s, f, request := trafficEvidenceServer(t)
	row, _ := s.m.pg.GetFinding(f.FindingID)
	task, _ := s.m.Task(fmt.Sprint(*row.TaskID))
	iid, err := task.Store.AddIntent(map[string]any{"summary": "active work"}, 5, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := task.Store.ClaimIntent(iid, "worker"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	_, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	control := agent.NewLiveControl(cancel)
	s.engine.workMu.Lock()
	s.engine.work[iid] = &workExecution{control: control}
	s.engine.workMu.Unlock()
	defer func() { s.engine.workMu.Lock(); delete(s.engine.work, iid); s.engine.workMu.Unlock() }()
	path := fmt.Sprintf("/api/tasks/%s/intents/%d/messages", task.ID, iid)
	for range 2 {
		res := request("POST", path, `{"message":"adjust the next step","request_id":"same-request"}`)
		if res.Code != 202 {
			t.Fatal(res.Code, res.Body)
		}
	}
	text := control.NextOrSeal()
	if strings.Count(text, "adjust the next step") != 1 {
		t.Fatal(text)
	}
	node, _ := task.Store.GetNode(iid)
	if node.State != "running" {
		t.Fatal("guidance paused worker", node.State)
	}
}

func TestRunningMainAndStandaloneMessagesAccepted(t *testing.T) {
	s, f, request := trafficEvidenceServer(t)
	row, _ := s.m.pg.GetFinding(f.FindingID)
	task, _ := s.m.Task(fmt.Sprint(*row.TaskID))
	_, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	main := agent.NewLiveControl(cancel)
	seg, _ := task.Store.CurrentMainSeg()
	s.chatBusy[task.ID] = true
	s.chatLive.Store(task.ID, chatLiveRun{control: main, seg: seg})
	res := request("POST", "/api/chat?task="+task.ID, `{"message":"keep working with this correction"}`)
	if res.Code != 202 || !strings.Contains(main.NextOrSeal(), "this correction") {
		t.Fatal(res.Code, res.Body)
	}
	// A different main segment must never steer this running session.
	res = request("POST", "/api/chat?task="+task.ID, fmt.Sprintf(`{"message":"wrong segment","seg":%d}`, seg+1))
	if res.Code != 409 {
		t.Fatal(res.Code, res.Body)
	}
	delete(s.chatBusy, task.ID)
	s.chatLive.Delete(task.ID)
	conv, err := s.m.pg.CreateConversation("mainagent", "standalone guidance test", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.m.pg.DeleteConversation(conv.ID)
	s.chatAgent = agent.NewChatAgent(nil, "unused", t.TempDir(), nil, 0)
	control := agent.NewLiveControl(cancel)
	key := s.convBusyKey(conv.ID)
	s.chatBusy[key] = true
	s.chatLive.Store(key, chatLiveRun{control: control})
	res = request("POST", fmt.Sprintf("/api/conversations/%d/messages", conv.ID), `{"message":"standalone correction"}`)
	if res.Code != 202 || !strings.Contains(control.NextOrSeal(), "standalone correction") {
		t.Fatal(res.Code, res.Body)
	}
	delete(s.chatBusy, key)
	s.chatLive.Delete(key)
}

func TestFindingConsolidationCopiesBoundEvidenceAndRejectsOldReports(t *testing.T) {
	s, first, _ := trafficEvidenceServer(t)
	ctx := t.Context()
	f, _ := s.m.pg.GetFinding(first.FindingID)
	task, _ := s.m.Task(fmt.Sprint(*f.TaskID))
	second, err := s.evidenceStore().Record(ctx, db.RecordFindingInput{TaskID: *f.TaskID, ExplorationID: task.ExpID, Name: "same root extension", Summary: "scope", Severity: "high", Evidence: "additional verified scope"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	seedServerEvidenceFlow(t, s, "merge-proof", []byte("stored merged evidence"))
	list, err := s.evidenceStore().Bind(ctx, second.FindingID, []db.TrafficRef{{TrafficID: "merge-proof", Role: "proof", Note: "scope proof"}})
	if err != nil {
		t.Fatal(err)
	}
	in := db.ConsolidateFindingsInput{CanonicalID: first.FindingID, SourceIDs: []int64{second.FindingID}, Name: "one cause", Summary: "whole scope", Severity: "high", Reason: "same root", Versions: map[string]int64{fmt.Sprint(first.FindingID): f.EvidenceVersion, fmt.Sprint(second.FindingID): list.Version}}
	if err = s.m.pg.ConsolidateFindings(ctx, *f.TaskID, 0, in); err != nil {
		t.Fatal(err)
	}
	canonical, err := s.m.pg.GetFindingTraffic(ctx, first.FindingID)
	if err != nil || len(canonical.Bindings) != 1 {
		t.Fatal(canonical, err)
	}
	if canonical.Bindings[0].Snapshot.ID != list.Bindings[0].Snapshot.ID {
		t.Fatal("copied snapshot changed")
	}
	if _, err = s.m.pg.SetFindingReportVersionByNodeID(ctx, first.NodeID, "old report", &f.EvidenceVersion); err == nil {
		t.Fatal("accepted old evidence version")
	}
	if _, err = s.m.pg.SetFindingReportVersionByNodeID(ctx, first.NodeID, "unversioned report", nil); err == nil {
		t.Fatal("accepted unversioned consolidated report")
	}
	if _, err = s.m.pg.SetFindingReportVersionByNodeID(ctx, first.NodeID, "current report", &canonical.Version); err != nil {
		t.Fatal(err)
	}
	nodes, err := task.Store.ListByKind(db.KindFinding, 10)
	if err != nil || len(nodes) != 1 {
		t.Fatal("duplicate task finding", len(nodes), err)
	}
	stats, err := task.Store.Stats()
	if err != nil || stats[db.KindFinding] != 1 {
		t.Fatal(stats, err)
	}
	metrics, err := s.m.pg.TaskListMetricsAll()
	if err != nil {
		t.Fatal(err)
	}
	if metrics[task.ExpID].Findings.High != 1 {
		t.Fatal("task summary counted source", metrics[task.ExpID])
	}
}
