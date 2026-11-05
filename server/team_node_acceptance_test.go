package server

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/collab"
	"github.com/Autumn-27/artex/db"
)

// This opt-in integration test exercises the real artex-node process, the team
// coordinator over TLS, a local fake OpenAI-compatible SSE endpoint, and the
// isolated workflow database. It never calls a hosted model or a production API.
func TestTeamRealNodeProcessAcceptance(t *testing.T) {
	nodeBinary := strings.TrimSpace(os.Getenv("ARTEX_NODE_ACCEPTANCE_BINARY"))
	if nodeBinary == "" {
		t.Skip("ARTEX_NODE_ACCEPTANCE_BINARY is unset; full verification runner supplies the built node binary")
	}
	if _, err := os.Stat(nodeBinary); err != nil {
		t.Fatalf("configured node binary unavailable: %v", err)
	}

	s, _, task := workflowFixture(t)
	ctx := context.Background()
	pg := s.m.pg
	taskID := mustTaskID(t, task.ID)
	if _, err := pg.Exec(`UPDATE tasks SET paused=true,queued=false,status='created' WHERE id=$1`, taskID); err != nil {
		t.Fatal(err)
	}

	team, err := pg.CreateTeam(ctx, "real node acceptance fixture")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM team_execution_assignments WHERE team_id=$1`, team.ID)
		_, _ = pg.Exec(`DELETE FROM teams WHERE id=$1`, team.ID)
	})
	operator, err := pg.CreateTeamMember(ctx, team.ID, "node operator", "unused")
	if err != nil {
		t.Fatal(err)
	}
	reviewer, err := pg.CreateTeamMember(ctx, team.ID, "independent reviewer", "unused")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct {
		member int64
		perm   string
	}{{operator.ID, "read"}, {operator.ID, "execute"}, {reviewer.ID, "read"}, {reviewer.ID, "review"}} {
		if err = pg.AttachTeamTask(ctx, team.ID, taskID, p.member, p.perm); err != nil {
			t.Fatal(err)
		}
	}
	pair, err := pg.CreateTeamDevicePairing(ctx, team.ID, operator.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	deviceCaps, _ := json.Marshal(map[string]any{"version": 1, "execution_enabled": true, "roles": []string{"reverse_static"}, "capabilities": []string{}})
	device, deviceToken, err := pg.PairTeamDevice(ctx, pair, "node acceptance device", deviceCaps)
	if err != nil {
		t.Fatal(err)
	}

	intentID, err := task.Store.AddWorkIntent(ctx, "cite the supplied fixture exactly", 1, nil, nil, db.WorkContract{
		ExecutionRole: "reverse_static",
		Acceptance:    []string{"cite the fixture"},
		BudgetSeconds: 45,
	})
	if err != nil {
		t.Fatal(err)
	}
	material := []byte("owned fixture text: exact bytes must reach the local model\n")
	relative := filepath.Join("tasks", task.ID, "reverse", "artifacts", "node-acceptance.txt")
	materialPath := filepath.Join(s.m.dir, relative)
	if err = os.MkdirAll(filepath.Dir(materialPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(materialPath, material, 0600); err != nil {
		t.Fatal(err)
	}
	artifact, err := pg.AddReverseArtifact(taskID, db.ReverseArtifact{Name: "node-acceptance.txt", Path: relative, SizeBytes: int64(len(material)), SHA256: collab.ContentHash(material), Format: "text"})
	if err != nil {
		t.Fatal(err)
	}

	var modelMu sync.Mutex
	modelCalls := 0
	secondRequestHadMaterial := false
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			http.Error(w, "unexpected fake model path", http.StatusNotFound)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer local-node-only-key" {
			t.Errorf("node did not use its local model credential: %q", got)
		}
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("read fake model request: %v", readErr)
		}
		modelMu.Lock()
		modelCalls++
		call := modelCalls
		if call == 2 {
			secondRequestHadMaterial = bytes.Contains(body, bytes.TrimSpace(material))
		}
		modelMu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		if call == 1 {
			args, _ := json.Marshal(map[string]string{"sha256": artifact.SHA256})
			fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"read-fixture\",\"type\":\"function\",\"function\":{\"name\":\"read_material\",\"arguments\":%q}}]}}]}\n\n", string(args))
			fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n")
		} else {
			fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"Candidate: supplied fixture was read; independent review required.\"},\"finish_reason\":\"stop\"}]}\n\n")
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	defer model.Close()

	admin, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	host := httptest.NewTLSServer(s.Handler())
	defer host.Close()
	cert, err := x509.ParseCertificate(host.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	temp := t.TempDir()
	caPath := filepath.Join(temp, "coordinator-ca.pem")
	if err = os.WriteFile(caPath, rootPEM, 0600); err != nil {
		t.Fatal(err)
	}
	request := func(method, path, credential string, body any, status int) []byte {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		req, reqErr := http.NewRequest(method, host.URL+path, bytes.NewReader(raw))
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		req.Header.Set("Authorization", "Bearer "+credential)
		req.Header.Set("Content-Type", "application/json")
		res, doErr := host.Client().Do(req)
		if doErr != nil {
			t.Fatal(doErr)
		}
		defer res.Body.Close()
		response, _ := io.ReadAll(res.Body)
		if res.StatusCode != status {
			t.Fatalf("%s %s: HTTP %d: %s", method, path, res.StatusCode, response)
		}
		return response
	}

	// Queue through the real API with two logical devices. The dispatcher must
	// skip the online device with the wrong role and wait until the task resumes.
	prefix := fmt.Sprintf("/api/teams/%d/tasks/%d", team.ID, taskID)
	request(http.MethodPost, "/api/collaboration/device/capabilities", deviceToken, map[string]any{"capabilities": json.RawMessage(deviceCaps)}, http.StatusOK)
	decoyPair, err := pg.CreateTeamDevicePairing(ctx, team.ID, operator.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	decoy, decoyToken, err := pg.PairTeamDevice(ctx, decoyPair, "online wrong-role fixture", json.RawMessage(`{"version":1,"execution_enabled":true,"roles":["worker"],"capabilities":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	request(http.MethodPost, "/api/collaboration/device/capabilities", decoyToken, map[string]any{"capabilities": json.RawMessage(decoy.Capabilities)}, http.StatusOK)
	request(http.MethodPost, prefix+"/dispatch", admin, teamAssignInput{IntentID: intentID, ArtifactIDs: []int64{artifact.ID}}, http.StatusCreated)
	s.dispatchTeamOnce(ctx)
	queued, err := pg.ListTeamDispatch(ctx, team.ID, taskID, true)
	if err != nil || len(queued) != 1 || queued[0].AssignmentID != nil {
		t.Fatalf("paused queue dispatched: %+v %v", queued, err)
	}
	if _, err = pg.Exec(`UPDATE tasks SET paused=false,queued=false WHERE id=$1`, taskID); err != nil {
		t.Fatal(err)
	}
	s.dispatchTeamOnce(ctx)
	queued, err = pg.ListTeamDispatch(ctx, team.ID, taskID, false)
	if err != nil || len(queued) != 1 || queued[0].AssignmentID == nil {
		t.Fatalf("queue did not assign: %+v %v", queued, err)
	}
	var assignment collab.Assignment
	savedAssignment, err := pg.GetTeamExecutionForMember(ctx, team.ID, *queued[0].AssignmentID, operator.ID)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(savedAssignment)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(wire, &assignment); err != nil {
		t.Fatal(err)
	}
	if assignment.DeviceID != device.ID {
		t.Fatalf("wrong-role device selected: %d", assignment.DeviceID)
	}
	if err = assignment.Validate(); err != nil {
		t.Fatal(err)
	}

	nodeConfig := map[string]any{
		"coordinator_url": host.URL,
		"ca_file":         caPath,
		"server_name":     "127.0.0.1",
		"execution": map[string]any{
			"work_dir":   filepath.Join(temp, "node-work"),
			"outbox_dir": filepath.Join(temp, "node-outbox"),
			"roles":      map[string]any{"reverse_static": map[string]any{"model": "fixture-model", "capabilities": []string{}}},
			"models":     map[string]any{"fixture-model": map[string]any{"endpoint": model.URL, "api_key_env": "ARTEX_NODE_ACCEPTANCE_KEY", "model": "offline-fixture", "format": "openai"}},
			"commands":   map[string]any{},
		},
	}
	configPath := filepath.Join(temp, "node.json")
	configJSON, _ := json.Marshal(nodeConfig)
	if err = os.WriteFile(configPath, configJSON, 0600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(temp, "identity.json")
	stateJSON, _ := json.Marshal(map[string]any{"coordinator_url": host.URL, "device_token": deviceToken, "device": map[string]any{"id": device.ID, "name": device.Name}})
	if err = os.WriteFile(statePath, stateJSON, 0600); err != nil {
		t.Fatal(err)
	}

	procCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(procCtx, nodeBinary, "-config", configPath, "-state", statePath, "run-once")
	cmd.Env = append(os.Environ(), "ARTEX_NODE_ACCEPTANCE_KEY=local-node-only-key")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err = cmd.Run(); err != nil {
		t.Fatalf("real node process failed: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}

	modelMu.Lock()
	gotCalls, sawMaterial := modelCalls, secondRequestHadMaterial
	modelMu.Unlock()
	if gotCalls != 2 || !sawMaterial {
		t.Fatalf("fake model did not observe the tool round trip: calls=%d second_request_contains_material=%t", gotCalls, sawMaterial)
	}

	saved, err := pg.GetTeamExecutionForMember(ctx, team.ID, assignment.ID, operator.ID)
	if err != nil {
		t.Fatal(err)
	}
	if saved.State != "completed" {
		t.Fatalf("node result state=%q, want completed", saved.State)
	}
	var result collab.ExecutionResult
	if err = json.Unmarshal(saved.Result, &result); err != nil {
		t.Fatal(err)
	}
	if result.Role != "reverse_static" || result.Outcome != "candidate" || len(result.Evidence) != 1 {
		t.Fatalf("unexpected node candidate: %+v", result)
	}
	evidence := result.Evidence[0]
	if evidence.Tool != "read_material" || evidence.SHA256 != collab.ContentHash([]byte(evidence.Content)) || evidence.Content != string(material) {
		t.Fatalf("evidence does not preserve the exact fixture bytes: %+v", evidence)
	}
	intent, err := task.Store.GetNode(intentID)
	if err != nil || intent.State != "paused" {
		t.Fatalf("device candidate prematurely changed intent state: %+v %v", intent, err)
	}
	if err = pg.ReviewTeamExecutionAssignment(ctx, team.ID, assignment.ID, reviewer.ID, "accept", "independently confirmed the exact material evidence"); err != nil {
		t.Fatal(err)
	}
	intent, err = task.Store.GetNode(intentID)
	if err != nil || intent.State != "open" || intent.State == "done" {
		t.Fatalf("independent review must reopen intent without completing business acceptance: %+v %v", intent, err)
	}
}
