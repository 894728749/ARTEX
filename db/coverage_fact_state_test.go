package db

import (
	"fmt"
	"testing"
)

func TestCoverageCountsOnlyConfirmedFactAnchors(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	source, err := d.CreateTask("coverage state source", "test", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	current, err := d.CreateTaskWithOptions("coverage state current", "test", TaskCreateOptions{SourceTaskIDs: []int64{source.ID}})
	if err != nil {
		t.Fatal(err)
	}

	type assetFact struct {
		id    int64
		state string
	}
	makeAssets := func(taskID int64, prefix string) []assetFact {
		t.Helper()
		out := make([]assetFact, 0, 3)
		for _, state := range []string{"origin", "dismissed", "confirmed"} {
			domain := fmt.Sprintf("%s-%d-%s.invalid", prefix, taskID, state)
			if _, scopeErr := d.Assets().AddAgentScope(taskID, "root_domain", domain, "test", "agent"); scopeErr != nil {
				t.Fatal(scopeErr)
			}
			id, upsertErr := d.Assets().UpsertRootDomain(UpsertRootDomainReq{Domain: domain, TaskID: taskID})
			if upsertErr != nil {
				t.Fatal(upsertErr)
			}
			out = append(out, assetFact{id: id, state: state})
		}
		return out
	}
	currentAssets := makeAssets(current.ID, "coverage-current")
	sourceAssets := makeAssets(source.ID, "coverage-source")
	t.Cleanup(func() {
		_ = d.DeleteTask(current.ID)
		_ = d.DeleteTask(source.ID)
		ids := make([]int64, 0, len(currentAssets)+len(sourceAssets))
		for _, item := range append(currentAssets, sourceAssets...) {
			ids = append(ids, item.id)
		}
		_, _ = d.Assets().DeleteByIDs(ids)
	})

	addAnchors := func(explorationID int64, facts []assetFact) {
		t.Helper()
		store := d.Exploration(explorationID)
		for _, fact := range facts {
			if _, addErr := store.AddNode(KindFact, map[string]any{"summary": "coverage state fixture"}, 0, fact.state, "test", []int64{fact.id}); addErr != nil {
				t.Fatal(addErr)
			}
		}
		// Multiple confirmed anchors for the same asset must count once.
		for i := 0; i < 2; i++ {
			if _, addErr := store.AddNode(KindFact, map[string]any{"summary": "duplicate confirmed anchor"}, 0, "confirmed", "test", []int64{facts[2].id}); addErr != nil {
				t.Fatal(addErr)
			}
		}
	}
	addAnchors(current.ExplorationID, currentAssets)
	addAnchors(source.ExplorationID, sourceAssets)

	assets := d.Assets()
	coverage, err := assets.TaskCoverage(current.ID, current.ExplorationID)
	if err != nil {
		t.Fatal(err)
	}
	if coverage.Denominator != 3 || coverage.Tested != 1 {
		t.Fatalf("current coverage counts only confirmed facts: %+v", coverage)
	}
	untested, total, err := assets.ListUntestedAssets(current.ID, current.ExplorationID, "", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(untested) != 2 {
		t.Fatalf("current untested list: total=%d assets=%+v", total, untested)
	}
	graph, err := assets.BuildCoverageGraph(current.ID, current.ExplorationID)
	if err != nil {
		t.Fatal(err)
	}
	for _, fact := range append(currentAssets, sourceAssets...) {
		got, found := false, false
		for _, node := range graph.Nodes {
			if node.AssetID == fact.id {
				got = node.Tested
				found = true
				break
			}
		}
		if !found {
			t.Errorf("coverage graph omitted asset %d from current/direct-source scope", fact.id)
			continue
		}
		if want := fact.state == "confirmed"; got != want {
			t.Errorf("coverage graph asset %d state %s tested=%v want %v", fact.id, fact.state, got, want)
		}
	}

	combined, err := assets.TaskCoverageWithSources(current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if combined.Denominator != 6 || combined.Tested != 2 {
		t.Fatalf("source-aware coverage counts current and source confirmed facts once: %+v", combined)
	}
	combinedUntested, combinedTotal, err := assets.ListUntestedAssetsWithSources(current.ID, "", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if combinedTotal != 4 || len(combinedUntested) != 4 {
		t.Fatalf("source-aware untested list: total=%d assets=%+v", combinedTotal, combinedUntested)
	}
}
