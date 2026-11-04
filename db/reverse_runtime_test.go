package db

import "testing"

func TestReverseRuntimeExplicitArtifactAndProfilePermission(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	task, err := d.CreateTaskWithOptions("runtime permission", "owned fixture", TaskCreateOptions{Kind: "reverse"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	artifact, err := d.AddReverseArtifact(task.ID, ReverseArtifact{Name: "fixture", Path: "test-fixture", Format: "elf", SizeBytes: 1, SHA256: "fixture-sha"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.BeginReverseRuntimeRun(t.Context(), task.ID, artifact.ID, 0, "lab-linux", 1000); err == nil {
		t.Fatal("execution without permission")
	}
	policy := ReverseRuntimePolicy{Enabled: true, ProfileIDs: []string{"lab-linux"}, ArtifactIDs: []int64{artifact.ID}, MaxDurationMS: 2000}
	if err = d.SetReverseRuntimePolicy(t.Context(), task.ID, policy); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"other-lab", "../../host"} {
		if _, err = d.BeginReverseRuntimeRun(t.Context(), task.ID, artifact.ID, 0, p, 1000); err == nil {
			t.Fatal("unapproved environment", p)
		}
	}
	if _, err = d.BeginReverseRuntimeRun(t.Context(), task.ID, artifact.ID, 0, "lab-linux", 3000); err == nil {
		t.Fatal("unapproved duration")
	}
	if _, err = d.BeginReverseRuntimeRun(t.Context(), task.ID, artifact.ID, 999999999, "lab-linux", 1000); err == nil {
		t.Fatal("nonrunning work admitted")
	}
	id, err := d.BeginReverseRuntimeRun(t.Context(), task.ID, artifact.ID, 0, "lab-linux", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.FinishReverseRuntimeRun(id, "cancelled", "results/runtime.json", "cancelled by user"); err != nil {
		t.Fatal(err)
	}
	runs, err := d.ListReverseRuntimeRuns(task.ID)
	if err != nil || len(runs) != 1 || runs[0].Status != "cancelled" {
		t.Fatal(runs, err)
	}
	policy.ArtifactIDs = []int64{999999999}
	if err = d.SetReverseRuntimePolicy(t.Context(), task.ID, policy); err == nil {
		t.Fatal("foreign artifact authorized")
	}
}
