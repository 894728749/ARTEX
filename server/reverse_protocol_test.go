package server

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func TestReverseReceiptSchemaMigrationPreservesConfiguration(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err = seedReverseRoles(m.pg, m.dir); err != nil {
		t.Fatal(err)
	}
	key := reverseToolPrefix + "complete_intent"
	old, err := m.pg.GetTool(key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		binds, _ := json.Marshal(old.Agents)
		m.pg.UpdateTool(key, old.Description, old.Schema, binds, old.Enabled)
	}()
	schema := json.RawMessage(`{"type":"object","properties":{"summary":{"type":"string","description":"operator note"}},"required":["summary"]}`)
	if err = m.pg.UpdateTool(key, "operator description", schema, json.RawMessage(`["reverse_static"]`), false); err != nil {
		t.Fatal(err)
	}
	if err = seedReverseRoles(m.pg, m.dir); err != nil {
		t.Fatal(err)
	}
	got, err := m.pg.GetTool(key)
	if err != nil {
		t.Fatal(err)
	}
	if got.Enabled || got.Description != "operator description" || len(got.Agents) != 1 || got.Agents[0] != "reverse_static" || !strings.Contains(string(got.Schema), "satisfied_ids") || !strings.Contains(string(got.Schema), "operator note") {
		t.Fatalf("migration lost configuration %+v", got)
	}
}

func TestReverseUnlimitedTaskStampsFirstRunWithoutDeadline(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	task, err := m.CreateTask("first run fixture", "no deadline", nil, 0, 600)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := strconv.ParseInt(task.ID, 10, 64)
	defer m.pg.DeleteTask(id)
	e := NewEngine(m)
	e.stampFirstRun(task)
	stored, err := m.pg.GetTask(id)
	if err != nil {
		t.Fatal(err)
	}
	if stored.FirstRunAt == nil || stored.DeadlineAt != nil {
		t.Fatalf("wrong unlimited clock %+v", stored)
	}
}
