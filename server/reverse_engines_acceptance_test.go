package server

import (
	"bytes"
	"context"
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
	actool "github.com/Autumn-27/norma/tool"
)

// Opt-in real-engine acceptance. Supply synthetic artifacts and private runner
// profiles through the spec; ordinary unit tests never execute uploaded files.
func TestReverseRealEngineAcceptance(t *testing.T) {
	path := os.Getenv("ARTEX_REVERSE_ACCEPTANCE_SPEC")
	if path == "" {
		t.Skip("real engine acceptance requires explicit fixture spec")
	}
	var spec struct {
		Workspace string `json:"workspace"`
		Cases     []struct {
			Name       string         `json:"name"`
			Artifact   string         `json:"artifact"`
			Profile    string         `json:"profile"`
			Script     string         `json:"script"`
			Package    string         `json:"package"`
			Duration   int            `json:"duration"`
			StaticTool string         `json:"static_tool"`
			StaticArgs map[string]any `json:"static_args"`
			Expected   string         `json:"expected"`
		} `json:"cases"`
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Workspace == "" || len(spec.Cases) == 0 {
		t.Fatal("workspace and cases required")
	}
	if err = os.MkdirAll(spec.Workspace, 0700); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(spec.Workspace, "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	stopped, cancel := context.WithCancel(context.Background())
	cancel()
	s := New(stopped, m, t.TempDir(), m.dir, t.TempDir())
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	handler := s.Handler()
	request := func(method, path string, body []byte, contentType string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", contentType)
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	summaries := []map[string]any{}
	for _, c := range spec.Cases {
		t.Run(c.Name, func(t *testing.T) {
			created := request("POST", "/api/tasks", []byte(`{"kind":"reverse","name":"owned engine fixture","goal":"Explain the synthetic transform"}`), "application/json")
			if created.Code != 201 {
				t.Fatalf("create: %d %s", created.Code, created.Body)
			}
			var dto TaskDTO
			if err := json.Unmarshal(created.Body.Bytes(), &dto); err != nil {
				t.Fatal(err)
			}
			id, _ := strconv.ParseInt(dto.ID, 10, 64)
			defer m.pg.DeleteTask(id)
			var upload bytes.Buffer
			writer := multipart.NewWriter(&upload)
			part, err := writer.CreateFormFile("file", filepath.Base(c.Artifact))
			if err != nil {
				t.Fatal(err)
			}
			source, err := os.ReadFile(c.Artifact)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = part.Write(source); err != nil {
				t.Fatal(err)
			}
			writer.Close()
			uploaded := request("POST", "/api/tasks/"+dto.ID+"/reverse/artifacts", upload.Bytes(), writer.FormDataContentType())
			if uploaded.Code != 201 {
				t.Fatalf("upload: %d %s", uploaded.Code, uploaded.Body)
			}
			var artifact db.ReverseArtifact
			if err = json.Unmarshal(uploaded.Body.Bytes(), &artifact); err != nil {
				t.Fatal(err)
			}
			task, err := m.pg.GetTask(id)
			if err != nil {
				t.Fatal(err)
			}
			store := m.pg.Exploration(task.ExplorationID)
			analyst, err := store.AddNode(db.KindIntent, map[string]any{"summary": "owned sample observation"}, 0, "running", "acceptance", nil)
			if err != nil {
				t.Fatal(err)
			}
			reviewer, err := store.AddNode(db.KindIntent, map[string]any{"summary": "independent evidence review"}, 0, "running", "acceptance", nil)
			if err != nil {
				t.Fatal(err)
			}
			info := agent.RunInfo{TaskID: id, IntentID: analyst}
			runCtx := agent.WithWorkflow(agent.WithRunInfo(context.Background(), info), "reverse")
			role := "reverse_static"
			if c.Profile != "" {
				role = "reverse_dynamic"
			}
			base := agent.NewToolSet(store, "acceptance").WorkerTools()
			base = append(base, actool.DefaultTools()...)
			roleTools, _, cleanup := agent.AugmentTools(runCtx, role, base)
			defer cleanup()
			if names(roleTools)["reverse_review_conclusion"] != nil {
				t.Fatal("analyst received reviewer write tool")
			}
			resultPath := ""
			if c.Profile != "" {
				tool := workflowTool(t, roleTools, "reverse_observe_runtime")
				args := map[string]any{"artifact_id": artifact.ID, "profile_id": c.Profile, "script": c.Script, "package_name": c.Package, "duration_ms": c.Duration}
				workflowCall(t, runCtx, tool, args, true) // Explicit default-deny proof.
				policy, _ := json.Marshal(db.ReverseRuntimePolicy{Enabled: true, ProfileIDs: []string{c.Profile}, ArtifactIDs: []int64{artifact.ID}, MaxDurationMS: c.Duration})
				saved := request("PUT", "/api/tasks/"+dto.ID+"/reverse/runtime", policy, "application/json")
				if saved.Code != 200 {
					t.Fatalf("policy: %d %s", saved.Code, saved.Body)
				}
				answer := workflowCall(t, runCtx, tool, args, false)
				var result struct {
					Status string `json:"status"`
					Path   string `json:"result_path"`
				}
				if err = json.Unmarshal([]byte(answer), &result); err != nil {
					t.Fatal(err)
				}
				if result.Status != "completed" {
					t.Fatalf("run: %s", answer)
				}
				resultPath = result.Path
				runs, err := m.pg.ListReverseRuntimeRuns(id)
				if err != nil || len(runs) != 1 || runs[0].Status != "completed" || runs[0].ResultPath != resultPath {
					t.Fatalf("run history: %+v %v", runs, err)
				}
			} else {
				tools := roleTools
				answer := workflowCall(t, runCtx, workflowTool(t, tools, "rea_analyze_artifact"), map[string]any{"artifact_id": artifact.ID}, false)
				var result struct {
					Path string `json:"result_path"`
				}
				if err = json.Unmarshal([]byte(answer), &result); err != nil {
					t.Fatal(err)
				}
				resultPath = result.Path
				if c.StaticTool != "" {
					args := c.StaticArgs
					if args == nil {
						args = map[string]any{}
					}
					stored, _ := m.pg.GetReverseArtifact(id, artifact.ID)
					if args["path"] == "$artifact" {
						args["path"] = filepath.Join(m.dir, stored.Path)
					}
					answer = workflowCall(t, runCtx, workflowTool(t, tools, "rea_call"), map[string]any{"name": c.StaticTool, "arguments": args}, false)
					if err = json.Unmarshal([]byte(answer), &result); err != nil {
						t.Fatal(err)
					}
					resultPath = result.Path
				}
			}
			evidence, err := os.ReadFile(filepath.Join(m.dir, resultPath))
			if err != nil {
				t.Fatal(err)
			}
			if c.Expected == "" || !strings.Contains(string(evidence), c.Expected) {
				t.Fatalf("actual evidence lacks %q", c.Expected)
			}
			analysisTools := roleTools
			answer := workflowCall(t, runCtx, workflowTool(t, analysisTools, "reverse_submit_conclusion"), map[string]any{"question": "What did the controlled fixture demonstrate?", "answer": c.Expected, "evidence": []db.ReverseEvidence{{ArtifactID: artifact.ID, Locator: c.Name, Observation: "Verified in the saved raw engine result: " + c.Expected, ResultPath: resultPath}}, "limitations": "Only this synthetic sample, engine configuration and observation window; no general program-completeness claim."}, false)
			var submitted struct{ Conclusion db.ReverseConclusion }
			if err = json.Unmarshal([]byte(answer), &submitted); err != nil {
				t.Fatal(err)
			}
			reviewCtx := agent.WithWorkflow(agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: id, IntentID: reviewer}), "reverse")
			reviewTools, _, closeReview := agent.AugmentTools(reviewCtx, "reverse_reviewer", base)
			defer closeReview()
			if names(reviewTools)["reverse_submit_conclusion"] != nil {
				t.Fatal("reviewer received analyst write tool")
			}
			workflowCall(t, reviewCtx, workflowTool(t, reviewTools, "reverse_review_conclusion"), map[string]any{"conclusion_id": submitted.Conclusion.ID, "state": "accepted", "review": "Independent test intent re-read the persisted raw result, matched the expected synthetic behavior and checked the artifact digest."}, false)
			report := request("GET", fmt.Sprintf("/api/tasks/%d/reverse/report", id), nil, "")
			if report.Code != 200 || !strings.Contains(report.Body.String(), artifact.SHA256) || !strings.Contains(report.Body.String(), "已核验接受") {
				t.Fatal("report lacks reviewed evidence")
			}
			summaries = append(summaries, map[string]any{"case": c.Name, "artifact_sha256": artifact.SHA256, "result_path": resultPath, "bytes": len(evidence), "analysis_role": role, "review_role": "reverse_reviewer", "independent_review": "accepted", "report": true})
		})
	}
	summary, _ := json.MarshalIndent(summaries, "", "  ")
	if err = os.WriteFile(filepath.Join(spec.Workspace, "acceptance-summary.json"), summary, 0600); err != nil {
		t.Fatal(err)
	}
}
