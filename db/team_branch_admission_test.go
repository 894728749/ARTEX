package db

import (
	"context"
	"testing"

	"github.com/Autumn-27/artex/collab"
)

func TestBranchAdmissionSkipsBusyPriorityAndRejectsDirectClaim(t *testing.T) {
	d, team, member, branchTask, device := branchDBFixture(t)
	enableFixtureTool(t, d, branchTask.ID, device.ID)
	branch := branchDBRunning(t, d, team, member, branchTask, device, "admission-reservation")
	node := collab.BranchActor{MemberID: member.ID, DeviceID: device.ID}
	op := collab.BranchOperation{ID: "hold-shared-resource", Epoch: 1, UnitID: 1, Kind: "tool", Role: "worker", Tool: "inspect", InputHash: collab.ContentHash([]byte("admission fixture"))}
	branchDBCommand(t, d, team.ID, branchTask.ID, node, collab.BranchCommand{Type: "start", RequestID: "start-shared-resource", BranchID: branch.Branch.ID, Epoch: 1, Operation: &op})

	// Local scheduling happens in another exploration attached to the same
	// team. Its top priority intent conflicts with the live branch; the next
	// intent uses an independent resource and should remain admissible.
	localTask, err := d.CreateTaskWithOptions("branch admission scheduler fixture", "local scheduling", TaskCreateOptions{Kind: "pentest"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM tasks WHERE id=$1`, localTask.ID)
		_, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, localTask.ExplorationID)
	})
	if err = d.AttachTeamTask(context.Background(), team.ID, localTask.ID, member.ID, "read"); err != nil {
		t.Fatal(err)
	}
	store := d.Exploration(localTask.ExplorationID)
	highID, err := store.AddWorkIntent(context.Background(), "highest priority blocked resource", 10, nil, nil, WorkContract{ExecutionRole: "worker", Acceptance: []string{"verified"}, BudgetSeconds: 30, ResourceKey: "shared-fixture"})
	if err != nil {
		t.Fatal(err)
	}
	lowID, err := store.AddWorkIntent(context.Background(), "independent resource work", 2, nil, nil, WorkContract{ExecutionRole: "worker", Acceptance: []string{"verified"}, BudgetSeconds: 30, ResourceKey: "independent-fixture"})
	if err != nil {
		t.Fatal(err)
	}

	picked, err := store.ClaimNextIntent(context.Background(), "admission-test")
	if err != nil {
		t.Fatal(err)
	}
	if picked == nil || picked.ID != lowID || picked.State != "running" {
		t.Fatalf("frontier did not skip busy resource: picked=%+v high=%d low=%d", picked, highID, lowID)
	}
	highClaimed, err := store.ClaimIntent(highID, "direct-admission-test")
	if err != nil {
		t.Fatal(err)
	}
	if highClaimed {
		t.Fatal("direct claim admitted a resource held by the branch tool operation")
	}
	high, err := store.GetNode(highID)
	if err != nil {
		t.Fatal(err)
	}
	if high == nil || high.State != "open" {
		t.Fatalf("busy high priority intent was mutated: %+v", high)
	}
}
