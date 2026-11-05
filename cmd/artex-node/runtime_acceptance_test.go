package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/collab"
)

// Opt-in acceptance uses explicitly supplied, owned executable fixtures. Normal
// test runs never install packages, launch a debugger, or execute a sample.
func TestNodeOwnedRuntimeAcceptance(t *testing.T) {
	path := os.Getenv("ARTEX_NODE_RUNTIME_ACCEPTANCE")
	if path == "" {
		t.Skip("owned runtime fixture specification not supplied")
	}
	var cases []struct {
		Name         string              `json:"name"`
		Profile      localRuntimeProfile `json:"profile"`
		Artifact     string              `json:"artifact"`
		Script       string              `json:"script"`
		PackageName  string              `json:"package_name"`
		DurationMS   int                 `json:"duration_ms"`
		Expected     string              `json:"expected"`
		EvidencePath string              `json:"evidence_path"`
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &cases); err != nil || len(cases) == 0 {
		t.Fatalf("invalid owned runtime cases: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			artifact, err := os.ReadFile(tc.Artifact)
			if err != nil {
				t.Fatal(err)
			}
			hash := collab.ContentHash(artifact)
			cfg := localExecutionConfig{RuntimeProfiles: map[string]localRuntimeProfile{"owned-lab": tc.Profile}, Roles: map[string]localRoleConfig{"reverse_dynamic": {RuntimeProfiles: []string{"owned-lab"}}}}
			profile, err := cfg.runtimeProfile("owned-lab")
			if err != nil {
				t.Fatal(err)
			}
			binding := collab.RuntimeBinding{RuntimeProfile: profile, ArtifactHashes: []string{hash}}
			selected, err := cfg.matchRuntimeBinding(collab.ExecutionConfig{Role: "reverse_dynamic", DynamicAllowed: true, Runtime: &binding}, []collab.Material{{SHA256: hash}})
			if err != nil {
				t.Fatal(err)
			}
			journal := filepath.Join(t.TempDir(), "evidence.ndjson")
			evidence := &nodeEvidence{journal: journal}
			gates := 0
			tool := reverseObserveRuntimeTool(selected, binding, map[string]string{hash: tc.Artifact}, evidence, func(context.Context) error { gates++; return nil })
			input, _ := json.Marshal(map[string]any{"sha256": hash, "script": tc.Script, "package_name": tc.PackageName, "duration_ms": tc.DurationMS})
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			result, err := tool.Call(ctx, input, nil)
			rows, loadErr := loadNodeEvidence(journal)
			if tc.EvidencePath != "" {
				saved, _ := json.MarshalIndent(rows, "", "  ")
				if e := os.WriteFile(tc.EvidencePath, saved, 0600); e != nil {
					t.Fatal(e)
				}
			}
			if err != nil || result.IsError || loadErr != nil || len(rows) != 1 {
				t.Fatalf("runtime failed: err=%v result=%s journal=%+v load=%v", err, result.Flatten(), rows, loadErr)
			}
			if gates != 2 || rows[0].IsError || rows[0].Tool != reverseRuntimeCapability || rows[0].Truncated {
				t.Fatalf("invalid runtime evidence: gates=%d rows=%+v", gates, rows)
			}
			if err := validateRuntimeObservation([]byte(rows[0].Content), tc.Profile.Platform, hash, tc.Script); err != nil {
				t.Fatal(err)
			}
			if tc.Expected == "" || !strings.Contains(rows[0].Content, tc.Expected) {
				t.Fatalf("missing actual fixture observation %q: %s", tc.Expected, rows[0].Content)
			}
		})
	}
}
