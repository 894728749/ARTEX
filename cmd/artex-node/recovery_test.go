package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/collab"
)

func TestNodeGentlePauseFinishesToolAndPersistsEvidence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := nodeEvidence{stop: cancel, journal: filepath.Join(t.TempDir(), "evidence.ndjson")}
	if err := e.beginTool(); err != nil {
		t.Fatal(err)
	}
	e.requestPause()
	if ctx.Err() != nil {
		t.Fatal("gentle pause killed current tool")
	}
	e.add("read_material", json.RawMessage(`{"sha256":"fixture"}`), "current tool completed", false, false)
	e.endTool()
	if ctx.Err() == nil {
		t.Fatal("pause did not stop at tool boundary")
	}
	if e.beginTool() == nil {
		t.Fatal("another tool admitted after pause")
	}
	rows, err := loadNodeEvidence(e.journal)
	if err != nil || len(rows) != 1 || rows[0].Content != "current tool completed" {
		t.Fatalf("journal recovery: %v %v", rows, err)
	}
	f, err := os.OpenFile(e.journal, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"partial":`)
	f.Close()
	rows, err = loadNodeEvidence(e.journal)
	if err != nil || len(rows) != 1 {
		t.Fatal("incomplete final crash record lost previous durable evidence")
	}
}

func TestFetchMaterialsResumesDurablePartialAcrossRestart(t *testing.T) {
	payload := []byte("durable-material-content")
	hash := collab.ContentHash(payload)
	work := t.TempDir()
	materialDir := filepath.Join(work, "materials")
	if err := os.MkdirAll(materialDir, 0700); err != nil {
		t.Fatal(err)
	}
	cut := 8
	if err := os.WriteFile(filepath.Join(materialDir, hash+".partial"), payload[:cut], 0600); err != nil {
		t.Fatal(err)
	}
	var gotRange string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRange = r.Header.Get("Range")
		if gotRange != fmt.Sprintf("bytes=%d-%d", cut, len(payload)-1) {
			t.Errorf("unexpected range %q", gotRange)
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", cut, len(payload)-1, len(payload)))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(payload[cut:])
	}))
	defer srv.Close()
	a := collab.Assignment{ID: 7, Epoch: 3, Input: collab.ExecutionInput{Materials: []collab.Material{{SHA256: hash, Size: int64(len(payload))}}}}
	files, err := fetchMaterials(t.Context(), srv.Client(), srv.URL, "token", a, work)
	if err != nil {
		t.Fatal(err)
	}
	if gotRange == "" {
		t.Fatal("server did not receive a resume range")
	}
	if files[hash] != filepath.Join(materialDir, hash) {
		t.Fatalf("unexpected cache path: %v", files)
	}
	got, err := os.ReadFile(files[hash])
	if err != nil || string(got) != string(payload) {
		t.Fatalf("resumed object mismatch: %q %v", got, err)
	}
	if _, err = os.Stat(files[hash] + ".partial"); !os.IsNotExist(err) {
		t.Fatalf("partial remained after verified promotion: %v", err)
	}
}

func TestFetchMaterialsRejectsBadContentRangeWithoutPublishingCache(t *testing.T) {
	payload := []byte("verified-after-transfer")
	hash := collab.ContentHash(payload)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes 1-%d/%d", len(payload)-1, len(payload)))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(payload)
	}))
	defer srv.Close()
	work := t.TempDir()
	a := collab.Assignment{ID: 7, Epoch: 3, Input: collab.ExecutionInput{Materials: []collab.Material{{SHA256: hash, Size: int64(len(payload))}}}}
	if _, err := fetchMaterials(t.Context(), srv.Client(), srv.URL, "token", a, work); err == nil {
		t.Fatal("accepted mismatched Content-Range")
	}
	if _, err := os.Stat(filepath.Join(work, "materials", hash)); !os.IsNotExist(err) {
		t.Fatalf("bad response published as cache: %v", err)
	}
}

func TestNodeRetryClassification(t *testing.T) {
	for _, code := range []int{408, 429, 500, 503} {
		if !isTransientNodeError(&nodeHTTPError{Code: code}) {
			t.Errorf("HTTP %d should retry", code)
		}
	}
	for _, code := range []int{400, 401, 403, 404} {
		if isTransientNodeError(&nodeHTTPError{Code: code}) {
			t.Errorf("HTTP %d should be permanent", code)
		}
	}
}

func TestExecutionMarkerIsWriteOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "execution.started")
	if err := createExecutionMarker(path); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = createExecutionMarker(path); err == nil {
		t.Fatal("second execution marker creation replaced the no-replay fence")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatalf("no-replay fence changed: %q %q %v", before, after, err)
	}
}

func TestTransientHeartbeatCancellationDuringMaterialStagingIsRetryable(t *testing.T) {
	payload := []byte("material fixture")
	hash := collab.ContentHash(payload)
	assignment := collab.Assignment{ID: 55, TaskID: 4, IntentID: 8, DeviceID: 2, Epoch: 3, State: "assigned", Config: collab.ExecutionConfig{Version: 1, Kind: "pentest", Role: "worker", SystemPrompt: "fixture", MaxTurns: 1, BudgetSeconds: 20}, Input: collab.ExecutionInput{Version: 1, Intent: "stage fixture", Materials: []collab.Material{{ID: hash, SHA256: hash, Name: "fixture.bin", Size: int64(len(payload))}}}}
	var heartbeats, results int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/collaboration/device/assignments/55/claim":
			assignment.State = "claimed"
			_ = json.NewEncoder(w).Encode(assignment)
		case r.URL.Path == "/api/collaboration/device/assignments/55/heartbeat":
			heartbeats++
			if heartbeats == 2 {
				http.Error(w, "temporary coordinator failure", http.StatusServiceUnavailable)
				return
			}
			assignment.State = "running"
			_ = json.NewEncoder(w).Encode(assignment)
		case strings.Contains(r.URL.Path, "/materials/"):
			<-r.Context().Done()
		case strings.HasSuffix(r.URL.Path, "/result"):
			results++
			_ = json.NewEncoder(w).Encode(map[string]bool{"accepted": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	work := t.TempDir()
	cfg := localExecutionConfig{WorkDir: work, Roles: map[string]localRoleConfig{"worker": {Model: "m"}}, Models: map[string]localModelConfig{"m": {Endpoint: "http://unused", APIKeyEnv: "TEST_KEY", Model: "m", Format: "openai"}}}
	err := executeAssignment(context.Background(), cfg, assignment, srv.URL, "token", srv.Client())
	if err == nil || !isTransientNodeError(err) {
		t.Fatalf("staging cancellation lost the transient heartbeat error: %v", err)
	}
	if results != 0 {
		t.Fatalf("temporary staging outage was settled as a blocked receipt: %d", results)
	}
	marker := filepath.Join(work, "exec-55-3", "execution.started")
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("staging failure set the no-replay execution marker: %v", err)
	}
}

func TestPersistentNodeRunRetriesTemporaryCoordinatorFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/collaboration/device/capabilities":
			w.WriteHeader(http.StatusNoContent)
		case "/api/collaboration/device/assignments":
			attempts++
			if attempts == 1 {
				http.Error(w, "temporary", http.StatusServiceUnavailable)
				return
			}
			cancel()
			_, _ = w.Write([]byte(`[]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	statePath := filepath.Join(t.TempDir(), "identity.json")
	raw, _ := json.Marshal(deviceState{CoordinatorURL: srv.URL, Token: "device-token"})
	if err := os.WriteFile(statePath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := localExecutionConfig{WorkDir: filepath.Join(t.TempDir(), "work"), Roles: map[string]localRoleConfig{"worker": {Model: "m"}}, Models: map[string]localModelConfig{"m": {Endpoint: "http://localhost", APIKeyEnv: "TEST_KEY", Model: "m", Format: "openai"}}}
	err := runAssignments(ctx, cfg, statePath, srv.URL, srv.Client(), io.Discard, false)
	if err == nil || attempts != 2 {
		t.Fatalf("expected retry then cancellation, err=%v attempts=%d", err, attempts)
	}
}

func TestNodeEscapedEvidenceStaysWithinWireBudget(t *testing.T) {
	e := nodeEvidence{}
	for i := 0; i < 9; i++ {
		if e.canStart(json.RawMessage(`{}`)) != nil {
			break
		}
		e.add("read_material", json.RawMessage(`{}`), strings.Repeat("\x01", 64<<10), false, false)
	}
	r := collab.ExecutionResult{Version: 1, Role: "worker", Outcome: "candidate", Summary: "receipt", Evidence: e.list()}
	if err := r.Validate(collab.ExecutionConfig{Role: "worker"}); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r)
	if len(raw) > 600<<10 {
		t.Fatalf("unbounded encoded evidence: %d", len(raw))
	}
	text := strings.Repeat("中", 25000)
	e = nodeEvidence{}
	e.add("read_material", json.RawMessage(`{}`), text, false, false)
	r.Evidence = e.list()
	raw, _ = json.Marshal(r)
	var decoded collab.ExecutionResult
	_ = json.Unmarshal(raw, &decoded)
	if err := decoded.Validate(collab.ExecutionConfig{Role: "worker"}); err != nil {
		t.Fatalf("UTF8 truncation changed receipt hash: %v", err)
	}
}

func TestNodeQuarantinePreservesIdentityAndAcknowledgesOnce(t *testing.T) {
	dir := t.TempDir()
	box, err := collab.OpenOutbox(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	e := collab.Envelope{Version: 1, CommandID: "../untrusted-id", ExecutionID: "1", Epoch: 1, Payload: json.RawMessage(`{"summary":"kept"}`)}
	if err = box.Put(e); err != nil {
		t.Fatal(err)
	}
	if err = quarantineEnvelope(dir, box, e); err != nil {
		t.Fatal(err)
	}
	queued, _ := box.Pending()
	if len(queued) != 0 {
		t.Fatal("quarantined receipt still queued")
	}
	dead, err := collab.OpenOutbox(filepath.Join(dir, "quarantine"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := dead.Pending()
	if err != nil || len(rows) != 1 || rows[0].CommandID != e.CommandID {
		t.Fatalf("deadletter lost identity: %v %v", rows, err)
	}
}
