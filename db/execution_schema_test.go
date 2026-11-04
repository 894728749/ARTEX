package db

import (
	"encoding/json"
	"testing"
)

func TestExecutionToolSchemaUpgradePreservesSettings(t *testing.T) {
	d, _, _ := executionFixture(t)
	key := "execution-schema-fixture"
	_, _ = d.Exec(`DELETE FROM tools WHERE key=$1`, key)
	defer d.Exec(`DELETE FROM tools WHERE key=$1`, key)
	if err := d.SeedTool(key, "operator text", json.RawMessage(`{"type":"object","properties":{"reason":{"type":"string","description":"operator note","default":"keep"}},"required":["reason"]}`), json.RawMessage(`["planner"]`)); err != nil {
		t.Fatal(err)
	}
	_, _ = d.Exec(`UPDATE tools SET enabled=false WHERE key=$1`, key)
	for i := 0; i < 2; i++ {
		if err := d.EnsureToolSchemaFields(key, map[string]any{"goal_version": map[string]any{"type": "string"}}, []string{"reason", "goal_version"}); err != nil {
			t.Fatal(err)
		}
	}
	row, err := d.GetTool(key)
	if err != nil {
		t.Fatal(err)
	}
	if row.Enabled || row.Description != "operator text" || len(row.Agents) != 1 || row.Agents[0] != "planner" {
		t.Fatalf("settings overwritten %+v", row)
	}
	var schema struct {
		Properties map[string]map[string]any `json:"properties"`
		Required   []string                  `json:"required"`
	}
	if err = json.Unmarshal(row.Schema, &schema); err != nil {
		t.Fatal(err)
	}
	if schema.Properties["reason"]["default"] != "keep" || schema.Properties["reason"]["description"] != "operator note" || schema.Properties["goal_version"]["type"] != "string" || len(schema.Required) != 2 {
		t.Fatal(string(row.Schema))
	}
}
