package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func TestReverseDraftUploadAndIndependentVerification(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := New(ctx, m, t.TempDir(), m.dir, t.TempDir())
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	handler := s.Handler()
	request := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	bad := request("POST", "/api/tasks", `{"kind":"invented"}`)
	if bad.Code != 400 {
		t.Fatalf("unknown task type: %d", bad.Code)
	}
	created := request("POST", "/api/tasks", `{"kind":"reverse","name":"synthetic reverse fixture","description":"Local synthetic JS only","goal":"Explain frame transform"}`)
	if created.Code != 201 {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	var dto TaskDTO
	if err := json.Unmarshal(created.Body.Bytes(), &dto); err != nil {
		t.Fatal(err)
	}
	task, _ := m.Task(dto.ID)
	id, _ := strconv.ParseInt(dto.ID, 10, 64)
	t.Cleanup(func() { _ = m.pg.DeleteTask(id) })
	if dto.Kind != "reverse" || dto.WorkflowVersion != 1 || !dto.Paused || dto.CoverageEnabled || s.engine.Started(dto.ID) {
		t.Fatalf("invalid draft: %+v", dto)
	}
	if _, err := s.applyTaskControl(task, "resume"); err == nil || !strings.Contains(err.Error(), "材料") {
		t.Fatalf("empty draft started: %v", err)
	}
	code := []byte("export function frame(input) { return 'demo:' + input.trim().toUpperCase(); }\n")
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, _ := writer.CreateFormFile("file", "../../sample.js")
	_, _ = part.Write(code)
	_ = writer.WriteField("version", "fixture-v1")
	_ = writer.Close()
	req := httptest.NewRequest("POST", "/api/tasks/"+dto.ID+"/reverse/artifacts", &body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	up := httptest.NewRecorder()
	handler.ServeHTTP(up, req)
	if up.Code != 201 {
		t.Fatalf("upload: %d %s", up.Code, up.Body.String())
	}
	var a db.ReverseArtifact
	if err := json.Unmarshal(up.Body.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	if a.Name != "sample.js" || a.Format != "js" || strings.Contains(up.Body.String(), "\"path\"") {
		t.Fatalf("bad artifact response: %s", up.Body.String())
	}
	hash := sha256.Sum256(code)
	if a.SHA256 != hex.EncodeToString(hash[:]) {
		t.Fatal("wrong hash")
	}
	list := request("GET", "/api/tasks/"+dto.ID+"/reverse/artifacts", "")
	var as []db.ReverseArtifact
	if err := json.Unmarshal(list.Body.Bytes(), &as); err != nil || len(as) != 1 {
		t.Fatalf("artifact list is not array: %s %v", list.Body.String(), err)
	}
	download := request("GET", fmt.Sprintf("/api/tasks/%s/reverse/artifacts/%d/download", dto.ID, a.ID), "")
	if download.Code != 200 || !bytes.Equal(download.Body.Bytes(), code) {
		t.Fatalf("download mismatch: %d", download.Code)
	}
	pt, _ := m.pg.GetTask(id)
	store := m.pg.Exploration(pt.ExplorationID)
	source, _ := store.AddNode(db.KindIntent, map[string]any{"summary": "analyze"}, 0, "running", "test", nil)
	reviewer, _ := store.AddNode(db.KindIntent, map[string]any{"summary": "verify independently"}, 0, "running", "test", nil)
	analysisTools := reverseConclusionTools(m.pg, pt, agent.RunInfo{TaskID: id, IntentID: source}, m.dir)
	answer := workflowCall(t, context.Background(), workflowTool(t, analysisTools, "reverse_submit_conclusion"), map[string]any{"question": "How is frame built?", "answer": "Trim, uppercase, prefix demo:", "evidence": []db.ReverseEvidence{{ArtifactID: a.ID, Locator: "sample.js:1 frame", Observation: "return 'demo:' + input.trim().toUpperCase()"}}, "limitations": "Static behavior for string inputs; no server claim"}, false)
	var receipt struct {
		Conclusion db.ReverseConclusion
		Receipt    *db.Node `json:"receipt_node"`
	}
	_ = json.Unmarshal([]byte(answer), &receipt)
	if receipt.Conclusion.State != "proposed" || receipt.Receipt == nil {
		t.Fatalf("invalid submission: %s", answer)
	}
	goal, _ := store.AddNode(db.KindGoal, map[string]any{"text": "Explain frame"}, 0, "open", "test", nil)
	goalNode, _ := store.GetNode(goal)
	if _, err := store.ProveGoal(context.Background(), goal, db.EvidenceReference{NodeID: receipt.Receipt.ID, Version: receipt.Receipt.EvidenceVersion}, "receipt proves answer", db.NodeEvidenceVersion(goalNode)); err == nil {
		t.Fatal("unreviewed receipt proved goal")
	}
	workflowCall(t, context.Background(), workflowTool(t, analysisTools, "reverse_review_conclusion"), map[string]any{"conclusion_id": receipt.Conclusion.ID, "state": "accepted", "review": "self review"}, true)
	reviewTools := reverseConclusionTools(m.pg, pt, agent.RunInfo{TaskID: id, IntentID: reviewer}, m.dir)
	accepted := workflowCall(t, context.Background(), workflowTool(t, reviewTools, "reverse_review_conclusion"), map[string]any{"conclusion_id": receipt.Conclusion.ID, "state": "accepted", "review": "Re-read sample.js:1; the return expression applies trim then uppercase before the literal prefix."}, false)
	var review struct {
		Evidence *db.Node `json:"evidence_node"`
	}
	_ = json.Unmarshal([]byte(accepted), &review)
	if review.Evidence == nil {
		t.Fatalf("review missing evidence: %s", accepted)
	}
	if _, err := store.ProveGoal(context.Background(), goal, db.EvidenceReference{NodeID: review.Evidence.ID, Version: review.Evidence.EvidenceVersion}, "accepted explanation matches source expression", db.NodeEvidenceVersion(goalNode)); err != nil {
		t.Fatal(err)
	}
	report := request("GET", "/api/tasks/"+dto.ID+"/reverse/report", "")
	if report.Code != 200 || !strings.Contains(report.Body.String(), a.SHA256) || !strings.Contains(report.Body.String(), "已核验接受") {
		t.Fatalf("report incomplete: %s", report.Body.String())
	}
	// Source tampering must prevent a later analysis/review from accepting stale evidence.
	stored, _ := m.pg.GetReverseArtifact(id, a.ID)
	_ = os.WriteFile(filepath.Join(m.dir, stored.Path), []byte("changed"), 0600)
	if err := reverseEvidenceCheck(m.pg, id, m.dir, receipt.Conclusion.Evidence); err == nil {
		t.Fatal("changed input hash was accepted")
	}
}

func TestReverseLocalPathContainment(t *testing.T) {
	schema, _ := json.Marshal(reverseObject(map[string]any{}))
	if bytes.Contains(schema, []byte(`"required":null`)) {
		t.Fatal("provider-rejected null required array")
	}
	dir := t.TempDir()
	inside := filepath.Join(dir, "tasks", "1", "reverse", "results")
	if err := os.MkdirAll(inside, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inside, "evidence.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := reverseLocalPath(dir, "tasks/1/reverse/results/evidence.json", "tasks/1/reverse/results"); err != nil {
		t.Fatal(err)
	}
	if _, err := reverseLocalPath(dir, "../outside", "tasks/1/reverse/results"); err == nil {
		t.Fatal("traversal accepted")
	}
}

func TestReverseEvidenceSummaryAndPointer(t *testing.T) {
	code, _ := json.Marshal(map[string]any{"structuredContent": map[string]any{"normalized_result": "return value * 3 + 7;"}})
	if !strings.Contains(reaPreview(code), "return value * 3 + 7;") {
		t.Fatal("native scalar evidence missing from preview")
	}
	dir := t.TempDir()
	rel := "tasks/3/reverse/results/rea-fixture.json"
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"structuredContent": map[string]any{"evidence_id": "fixture-evidence", "normalized_result": map[string]any{"summary": "one module", "graph": []string{"one", "two", strings.Repeat("large-graph", 10000)}}}})
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	brief := reaPreview(raw)
	if !strings.Contains(brief, "fixture-evidence") || !strings.Contains(brief, "one module") || strings.Contains(brief, "large-graph") {
		t.Fatalf("unbounded or missing summary: %.300s", brief)
	}
	result := workflowCall(t, context.Background(), reverseEvidenceViewTool(3, dir), map[string]any{"path": rel, "pointer": "/structuredContent/normalized_result/graph", "offset": 1, "limit": 1}, false)
	if !strings.Contains(result, `"two"`) || !strings.Contains(result, `"next_offset":2`) {
		t.Fatalf("pagination lost boundary: %s", result)
	}
	workflowCall(t, context.Background(), reverseEvidenceViewTool(4, dir), map[string]any{"path": rel}, true)
	// REA's managed provider returns its normalized object as encoded JSON.
	// A reviewer must reach the last IL row without relying on a truncated preview.
	encoded, _ := json.Marshal(map[string]any{"methods": []any{map[string]any{"name": "Frame", "anchors": []string{"IL_000A brtrue.s", "IL_0017 ret"}}}})
	raw, _ = json.Marshal(map[string]any{"structuredContent": map[string]any{"normalized_result": string(encoded)}})
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	result = workflowCall(t, context.Background(), reverseEvidenceViewTool(3, dir), map[string]any{"path": rel, "pointer": "/structuredContent/normalized_result/methods/0/anchors", "offset": 1, "limit": 1}, false)
	if !strings.Contains(result, "IL_0017 ret") {
		t.Fatalf("encoded JSON could not be traversed: %s", result)
	}
	raw, _ = json.Marshal(map[string]any{"code": strings.Repeat("甲", 5000) + "end"})
	_ = os.WriteFile(path, raw, 0600)
	result = workflowCall(t, context.Background(), reverseEvidenceViewTool(3, dir), map[string]any{"path": rel, "pointer": "/code", "offset": 5000, "limit": 3}, false)
	if !strings.Contains(result, `"value":"end"`) || !strings.Contains(result, `"next_offset":5003`) {
		t.Fatalf("long Unicode text cannot be paged: %s", result)
	}
}

func TestReversePortableReportReferences(t *testing.T) {
	text := "artifact id=3 /executor/data/tasks/4/reverse/artifacts/random.js tasks/4/reverse/results/rea.json https://target.example/api /vendor/component.js"
	got := reversePortableText(text, "/executor/data", "4", []db.ReverseArtifact{{ID: 3, Name: "sample.js", Path: "tasks/4/reverse/artifacts/random.js"}})
	if strings.Contains(got, "/executor/") || strings.Contains(got, "tasks/4/") || strings.Contains(got, "artifact id=3") || !strings.Contains(got, "evidence/rea.json") || !strings.Contains(got, "https://target.example/api /vendor/component.js") {
		t.Fatalf("incorrect report reference mapping: %s", got)
	}
}
