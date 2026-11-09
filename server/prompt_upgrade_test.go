package server

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func TestSeedPromptsUpgradesLegacyDefaultAndPreservesUserEdits(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no test database: %v", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	planner, err := pg.GetAgentByKey("planner")
	if err != nil || planner == nil {
		t.Fatalf("planner: %v", err)
	}
	worker, err := pg.GetAgentByKey("worker")
	if err != nil || worker == nil {
		t.Fatalf("worker: %v", err)
	}
	data, err := os.ReadFile("testdata/planner-default-5c0dbd4.txt")
	if err != nil {
		t.Fatal(err)
	}
	// Text fixture checkouts may use CRLF; Go raw string constants discard CR.
	legacy := strings.ReplaceAll(string(data), "\r\n", "\n")
	digest := sha256.Sum256([]byte(legacy))
	found := false
	for _, h := range agent.LegacyBuiltinPromptHashes("planner") {
		found = found || h == hex.EncodeToString(digest[:])
	}
	if !found {
		t.Fatal("historical fixture must match a recognized shipped default")
	}
	if _, err = pg.SavePrompt(planner.ID, legacy, "内置默认", "system"); err != nil {
		t.Fatal(err)
	}
	const custom = "保留用户自定义规则 {{.WorkerName}}"
	if _, err = pg.SavePrompt(worker.ID, custom, "custom", "user"); err != nil {
		t.Fatal(err)
	}
	// Historical completion flags must not suppress a later default update.
	if err = pg.SetSetting("planner_prompt_compact_realistic_v2", "true"); err != nil {
		t.Fatal(err)
	}
	seedPrompts(pg)
	got, err := pg.CurrentPrompt(planner.ID)
	if err != nil || got != agent.BuiltinPromptSeeds()["planner"] || !strings.Contains(got, "no_progress") {
		t.Fatalf("planner default was not upgraded: %v", err)
	}
	if got, err = pg.CurrentPrompt(worker.ID); err != nil || got != custom {
		t.Fatalf("user worker prompt was overwritten: %v", err)
	}
	versions, err := pg.ListPromptVersions(planner.ID)
	if err != nil {
		t.Fatal(err)
	}
	retained := false
	for _, v := range versions {
		retained = retained || v.Template == legacy
	}
	if !retained {
		t.Fatal("historical default was lost")
	}
	seedPrompts(pg)
	again, err := pg.ListPromptVersions(planner.ID)
	if err != nil || len(again) != len(versions) {
		t.Fatalf("repeated initialization appended versions: %v", err)
	}
}
