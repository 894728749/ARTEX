package db

import (
	"fmt"
	"testing"
)

func TestExecutionReadQueries(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("execution reads", "execution reads")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) })
	store := d.Exploration(expID)
	intentID, err := store.AddIntent(map[string]any{"summary": "long output"}, 1, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1001; i++ {
		kind := "text"
		if i == 1000 {
			kind = "result"
		}
		_, err = store.AppendActivity(Activity{NodeID: &intentID, Kind: kind, Summary: fmt.Sprintf("row %d", i), Detail: fmt.Sprintf("detail %d", i)})
		if err != nil {
			t.Fatal(err)
		}
	}
	out, err := store.LatestIntentOutput(intentID)
	if err != nil || out == nil || out.Kind != "result" || out.Detail != "detail 1000" {
		t.Fatalf("latest preferred output = %+v, err=%v", out, err)
	}

	textIntent, err := store.AddIntent(map[string]any{"summary": "text only"}, 1, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_, err = store.AppendActivity(Activity{NodeID: &textIntent, Kind: "text", Summary: fmt.Sprintf("text %d", i), Detail: fmt.Sprintf("text detail %d", i)})
		if err != nil {
			t.Fatal(err)
		}
	}
	out, err = store.LatestIntentOutput(textIntent)
	if err != nil || out == nil || out.Detail != "text detail 2" {
		t.Fatalf("latest text output = %+v, err=%v", out, err)
	}

	oldRunning, err := store.AddIntent(map[string]any{"summary": "old running"}, 1, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err = store.SetIntentState(oldRunning, "running"); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin) SELECT $1,'fact','{}'::jsonb,0,'confirmed','test' FROM generate_series(1,350)`, expID); err != nil {
		t.Fatal(err)
	}
	running, err := store.ListRunningIntents()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range running {
		if n.ID == oldRunning {
			found = true
		}
	}
	if !found {
		t.Fatalf("old running intent %d absent from full list (%d rows)", oldRunning, len(running))
	}

	if _, err = d.Exec(`INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin) SELECT $1,'fact','{}'::jsonb,0,'confirmed','test' FROM generate_series(1,1100)`, expID); err != nil {
		t.Fatal(err)
	}
	count, err := store.CountKind("fact")
	if err != nil || count != 1450 {
		t.Fatalf("fact count=%d err=%v, want 1450", count, err)
	}

	if _, err = store.AddNode(KindFinding, map[string]any{"summary": "canonical"}, 0, "confirmed", "test", nil); err != nil {
		t.Fatal(err)
	}
	mergedFinding, err := store.AddNode(KindFinding, map[string]any{"summary": "merged", "merged_into": int64(1)}, 0, "confirmed", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	findings, err := store.CountKind(KindFinding)
	if err != nil || findings != 1 {
		t.Fatalf("finding count=%d err=%v, want 1 excluding merged node %d", findings, err, mergedFinding)
	}
	// A source task's running intent is not readable until terminal, and an
	// unrelated task's intent is never readable through the source-aware method.
	source, err := d.CreateTask("source", "source", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	current, err := d.CreateTaskWithOptions("current", "current", TaskCreateOptions{SourceTaskIDs: []int64{source.ID}})
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := d.CreateTask("unrelated", "unrelated", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(current.ID); _ = d.DeleteTask(source.ID); _ = d.DeleteTask(unrelated.ID) })
	currentStore, sourceStore, unrelatedStore := d.Exploration(current.ExplorationID), d.Exploration(source.ExplorationID), d.Exploration(unrelated.ExplorationID)
	sourceIntent, err := sourceStore.AddIntent(map[string]any{"summary": "source"}, 1, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = sourceStore.AppendActivity(Activity{NodeID: &sourceIntent, Kind: "result", Detail: "source secret"})
	if err != nil {
		t.Fatal(err)
	}
	unrelatedIntent, err := unrelatedStore.AddIntent(map[string]any{"summary": "unrelated"}, 1, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = unrelatedStore.AppendActivity(Activity{NodeID: &unrelatedIntent, Kind: "result", Detail: "unrelated secret"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := currentStore.LatestIntentOutputWithSources(sourceIntent)
	if err != nil || got != nil {
		t.Fatalf("nonterminal inherited output leaked: %+v err=%v", got, err)
	}
	if err = sourceStore.SetIntentState(sourceIntent, "done"); err != nil {
		t.Fatal(err)
	}
	got, err = currentStore.LatestIntentOutputWithSources(sourceIntent)
	if err != nil || got == nil || !got.Inherited || got.Detail != "source secret" {
		t.Fatalf("terminal source output=%+v err=%v", got, err)
	}
	got, err = currentStore.LatestIntentOutputWithSources(unrelatedIntent)
	if err != nil || got != nil {
		t.Fatalf("unrelated output leaked: %+v err=%v", got, err)
	}
}
