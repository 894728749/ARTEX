package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestReverseWorkspaceExposesGrantedRuntimeCapabilitiesOnly(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer m.Close()
	task, err := m.pg.CreateTaskWithOptions("owned capability fixture", "select the right runtime", db.TaskCreateOptions{Kind: "reverse"})
	if err != nil {
		t.Fatal(err)
	}
	defer m.pg.DeleteTask(task.ID)
	if err = m.pg.SetPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	artifact, err := m.pg.AddReverseArtifact(task.ID, db.ReverseArtifact{Name: "fixture", Path: "fixture", Format: "elf", SizeBytes: 1, SHA256: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if err = m.pg.SetReverseRuntimePolicy(t.Context(), task.ID, db.ReverseRuntimePolicy{Enabled: true, ProfileIDs: []string{"allowed"}, ArtifactIDs: []int64{artifact.ID}, MaxDurationMS: 1000}); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(t.TempDir(), "profiles.json")
	content := `[{"id":"allowed","name":"owned Android","platform":"android","command":"private-runner-path","settings":{"java_bridge_module":"private-bridge-path","token":"private-token"}},{"id":"ungranted","platform":"linux","command":"not-exposed"}]`
	if err = os.WriteFile(config, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_REVERSE_RUNTIME_PROFILES", config)
	tools, _, close := reverseAgentTools(context.Background(), m.pg, task, m.dir, "planner")
	defer close()
	answer := workflowCall(t, context.Background(), workflowTool(t, tools, "reverse_workspace"), map[string]any{}, false)
	for _, secret := range []string{"private-runner-path", "private-bridge-path", "private-token", "ungranted"} {
		if strings.Contains(answer, secret) {
			t.Fatalf("private/ungranted runtime details exposed: %s", secret)
		}
	}
	var response struct {
		Environments []struct {
			ID, Name, Platform string
			Java               bool `json:"java_api"`
		} `json:"runtime_environments"`
	}
	if err = json.Unmarshal([]byte(answer), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Environments) != 1 || response.Environments[0].ID != "allowed" || response.Environments[0].Platform != "android" || !response.Environments[0].Java {
		t.Fatalf("missing runtime capabilities: %+v", response)
	}
}
