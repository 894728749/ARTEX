package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestReverseConclusionIndexOmitsConclusionBody(t *testing.T) {
	c := db.ReverseConclusion{ID: 3, Question: "q", Answer: "must stay private to detail", State: "accepted", IntentID: 4, Evidence: []db.ReverseEvidence{{Observation: "full evidence"}}, Limitations: "full limitations", Review: "full review", CreatedAt: time.Now()}
	index, err := json.Marshal(reverseConclusionIndex(c))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(index), "must stay private") || strings.Contains(string(index), "full evidence") || strings.Contains(string(index), "full limitations") || strings.Contains(string(index), "full review") {
		t.Fatalf("index contains conclusion body: %s", index)
	}
	var fields map[string]any
	if err := json.Unmarshal(index, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"id", "question", "state", "intent_id", "reviewer_intent_id", "node_id", "created_at", "reviewed_at"} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("missing index field %q", key)
		}
	}
}

func TestReverseReadEvidenceFacetsAndTaskBoundary(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "tasks", "41", "reverse", "results")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "evidence.json")
	cases := []string{
		`{"structuredContent":{"normalized_result":"{\"summary\":\"nested\",\"source\":\"abcdef\",\"methods\":[\"m1\",\"m2\"],\"root_artifact_sha256\":\"hash\"}"}}`,
		`{"structured_content":{"normalized_result":{"summary":"snake","source":"uvwxyz","fields":{"x":1,"y":2},"references":["r1"]}}}`,
		`{"content":[{"type":"text","text":"{\"summary\":\"content-json\",\"source\":\"012345\",\"matches\":[1,2,3]}"}]}`,
	}
	for i, raw := range cases {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		got := workflowCall(t, context.Background(), reverseReadEvidenceTool(41, root), map[string]any{"result_path": "tasks/41/reverse/results/evidence.json", "facet": "source", "offset": 1, "limit": 3}, false)
		var response map[string]any
		if err := json.Unmarshal([]byte(got), &response); err != nil {
			t.Fatal(err)
		}
		if response["value"] != []string{"bcd", "vwx", "123"}[i] || response["total"] != float64(6) {
			t.Fatalf("case %d source page: %s", i, got)
		}
	}
	if err := os.WriteFile(path, []byte(cases[1]), 0600); err != nil {
		t.Fatal(err)
	}
	got := workflowCall(t, context.Background(), reverseReadEvidenceTool(41, root), map[string]any{"result_path": "tasks/41/reverse/results/evidence.json", "facet": "fields", "offset": 1, "limit": 1}, false)
	if !strings.Contains(got, `"value":{"y":2}`) {
		t.Fatalf("fields page: %s", got)
	}
	if err := os.WriteFile(path, []byte(cases[2]), 0600); err != nil {
		t.Fatal(err)
	}
	got = workflowCall(t, context.Background(), reverseReadEvidenceTool(41, root), map[string]any{"result_path": "tasks/41/reverse/results/evidence.json", "facet": "matches", "offset": 1, "limit": 1}, false)
	if !strings.Contains(got, `"value":[2]`) {
		t.Fatalf("array page: %s", got)
	}
	if err := os.WriteFile(path, []byte(`{"structuredContent":{"operation":"reverse_inspect_hermes","provider":"fixture","normalized_result":{"derived":{"sha256":"abc"},"analysis":{"summary":"Hermes index","methods":[{"id":1}],"items":[{"string_id":7}]}}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ facet, want string }{{"summary", "Hermes index"}, {"methods", `"id":1`}, {"matches", `"string_id":7`}} {
		got = workflowCall(t, context.Background(), reverseReadEvidenceTool(41, root), map[string]any{"result_path": "tasks/41/reverse/results/evidence.json", "facet": tc.facet}, false)
		if !strings.Contains(got, tc.want) {
			t.Fatalf("Hermes %s facet: %s", tc.facet, got)
		}
	}
	if err := os.WriteFile(path, []byte(`{"content":[{"type":"text","text":"{\"structuredContent\":{\"operation\":\"read\",\"normalized_result\":{\"source\":{\"language\":\"js\",\"text\":\"code-body\"}}}}"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	got = workflowCall(t, context.Background(), reverseReadEvidenceTool(41, root), map[string]any{"result_path": "tasks/41/reverse/results/evidence.json", "facet": "source"}, false)
	if !strings.Contains(got, "code-body") || strings.Contains(got, `"language"`) {
		t.Fatalf("source wrapper extraction: %s", got)
	}
	got = workflowCall(t, context.Background(), reverseReadEvidenceTool(41, root), map[string]any{"result_path": "tasks/41/reverse/results/evidence.json", "facet": "root"}, false)
	if !strings.Contains(got, `"operation":"read"`) || !strings.Contains(got, `"available_fields"`) {
		t.Fatalf("root summary: %s", got)
	}
	if _, err := reverseLocalPath(root, "tasks/42/reverse/results/evidence.json", filepath.Join("tasks", "41", "reverse", "results")); err == nil {
		t.Fatal("cross-task result path accepted")
	}
}
