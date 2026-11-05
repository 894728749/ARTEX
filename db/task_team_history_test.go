package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestTaskArchiveSnapshotsTeamSourcesWithoutCredentials(t *testing.T) {
	d, team, member, task := teamCollabFixture(t)
	ctx := context.Background()
	if err := d.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	if err := d.AttachTeamTask(ctx, team.ID, task.ID, member.ID, "manage"); err != nil {
		t.Fatal(err)
	}
	if err := d.AttachTeamTask(ctx, team.ID, task.ID, member.ID, "execute"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PutTeamResource(ctx, team.ID, task.ID, member.ID, "handoff", json.RawMessage(`{"candidate":"keep"}`)); err != nil {
		t.Fatal(err)
	}
	intentID, err := d.Exploration(task.ExplorationID).AddWorkIntent(ctx, "archive candidate", 1, nil, nil, WorkContract{ResourceKey: "archive-resource"})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := d.CreateTeamDevicePairing(ctx, team.ID, member.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	device, token, err := d.PairTeamDevice(ctx, pair, "archive node", json.RawMessage(`{"os":"test"}`))
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := d.CreateTeamExecutionAssignment(ctx, team.ID, task.ID, intentID, member.ID, device.ID, time.Hour, json.RawMessage(`{"role":"reviewed candidate"}`), json.RawMessage(`{"target":"archive target"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err = d.SetPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`UPDATE team_execution_assignments SET state='running' WHERE id=$1`, assignment.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.QueueTaskArchive(task.ID); err == nil || !strings.Contains(err.Error(), "协作设备仍在收尾") {
		t.Fatalf("archive allowed an in-flight device: %v", err)
	}
	if _, err := d.Exec(`UPDATE team_execution_assignments SET state='completed',result=$2::jsonb,review_member_id=$3,review_decision='accept',review_note='review retained',reviewed_at=now() WHERE id=$1`, assignment.ID, `{"evidence":[{"kind":"http","url":"https://example.invalid/"}]}`, member.ID); err != nil {
		t.Fatal(err)
	}
	// A restored historical copy must not overwrite a newer live resource when
	// the task is archived for a second time.
	if _, err := d.Exec(`INSERT INTO task_team_history(task_id,kind,source_key,snapshot) VALUES($1,'team_resource',$2,'{"candidate":"obsolete"}')`, task.ID, fmt.Sprintf("%d:handoff", team.ID)); err != nil {
		t.Fatal(err)
	}
	snapshot, err := d.SnapshotTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := decodeArchiveRows(snapshot.Tables["team_history_sources"])
	if err != nil || len(rows) != 5 {
		t.Fatalf("team source rows=%d err=%v", len(rows), err)
	}
	encoded, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if strings.Contains(text, "obsolete") {
		t.Fatal("old history overrode live resource")
	}
	for _, want := range []string{"team_task", "team_permission", "team_assignment", "team_resource", "synthetic team", "handoff", "manage", "archive target", "review retained", "review_decision", "https://example.invalid/"} {
		if !strings.Contains(text, want) {
			t.Fatalf("team archive snapshot missing %q: %s", want, text)
		}
	}
	for _, forbidden := range []string{"token_hash", "password_hash", token} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("credential field %q leaked into snapshot: %s", forbidden, text)
		}
	}
	if err = d.SetPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	archive, err := d.QueueTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.PutTeamResource(ctx, team.ID, task.ID, member.ID, "handoff", json.RawMessage(`{"candidate":"too late"}`)); err == nil {
		t.Fatal("resource changed after archive queueing")
	}
	if err = d.AttachTeamTask(ctx, team.ID, task.ID, member.ID, "review"); err == nil {
		t.Fatal("permission changed after archive queueing")
	}
	// Claim only this fixture's job: other tests in the shared disposable DB
	// may deliberately leave queued jobs while testing archive eligibility.
	if _, err = d.Exec(`UPDATE task_archives SET state='archiving' WHERE id=$1 AND state='archive_queued'`, archive.ID); err != nil {
		t.Fatal(err)
	}
	if err = d.CompleteTaskArchive(archive.ID, snapshot, "/tmp/owned-team-fixture.tar.zst", "fixture", 100, 50); err != nil {
		t.Fatal(err)
	}
	if history, err := d.ListTaskTeamHistory(ctx, task.ID); err != nil || len(history) != 0 {
		t.Fatalf("cold archive retained heavyweight hot history: %v %v", history, err)
	}
	// Source identities can disappear while a task is cold; restore must retain
	// provenance without recreating members, device credentials or grants.
	if _, err = d.Exec(`DELETE FROM teams WHERE id=$1`, team.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.QueueTaskArchiveRestore(archive.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`UPDATE task_archives SET state='restoring' WHERE id=$1 AND state='restore_queued'`, archive.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.RestoreTaskArchive(archive.ID, snapshot, 600); err != nil {
		t.Fatal(err)
	}
	if err = d.CompleteTaskArchiveRestore(archive.ID); err != nil {
		t.Fatal(err)
	}
	history, err := d.ListTaskTeamHistory(ctx, task.ID)
	if err != nil || len(history) != 5 {
		t.Fatalf("restore lost provenance: %+v %v", history, err)
	}
	var active, identities int
	if err = d.QueryRow(`SELECT count(*) FROM team_execution_assignments WHERE task_id=$1`, task.ID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if err = d.QueryRow(`SELECT count(*) FROM teams WHERE id=$1`, team.ID).Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if active != 0 || identities != 0 {
		t.Fatal("restore resurrected live assignment or identity")
	}
	node, err := d.Exploration(task.ExplorationID).GetNode(intentID)
	if err != nil || node == nil || node.State != "paused" || strings.Contains(string(node.Payload), "remote_assignment_pending") {
		t.Fatalf("old execution reservation restored: %+v %v", node, err)
	}
}

func TestListTaskTeamHistoryReturnsStableReadOnlyRecords(t *testing.T) {
	d, _, _, task := teamCollabFixture(t)
	if _, err := d.Exec(`INSERT INTO task_team_history(task_id,kind,source_key,snapshot) VALUES($1,'team_assignment','assignment:17','{"assignment_id":17,"review_decision":"accept"}')`, task.ID); err != nil {
		t.Fatal(err)
	}
	items, err := d.ListTaskTeamHistory(context.Background(), task.ID)
	if err != nil || len(items) != 1 {
		t.Fatalf("history=%+v err=%v", items, err)
	}
	if items[0].Kind != "team_assignment" || items[0].SourceKey != "assignment:17" || !strings.Contains(string(items[0].Snapshot), `"review_decision": "accept"`) {
		t.Fatalf("unexpected history item: %+v", items[0])
	}
}

func TestRestoreTaskTeamHistoryIsIdempotent(t *testing.T) {
	d, _, _, task := teamCollabFixture(t)
	rows := json.RawMessage(`[{"kind":"team_assignment","source_key":"17","snapshot":{"assignment_id":17,"result":{"evidence":["kept"]}}}]`)
	for i := 0; i < 2; i++ {
		tx, err := d.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if err = restoreTaskTeamHistory(tx, task.ID, rows); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	items, err := d.ListTaskTeamHistory(context.Background(), task.ID)
	if err != nil || len(items) != 1 || !strings.Contains(string(items[0].Snapshot), "kept") {
		t.Fatalf("history=%+v err=%v", items, err)
	}
}
