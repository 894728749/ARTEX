package db

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestDeleteEmptyTeamAndRejectAuditRows(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := context.Background()
	team, err := d.CreateTeam(ctx, "lifecycle empty")
	if err != nil {
		t.Fatal(err)
	}
	eligibility, err := d.TeamDeletionEligibility(ctx, team.ID)
	if err != nil || !eligibility.Deletable {
		t.Fatalf("eligibility=%+v err=%v", eligibility, err)
	}
	if err = d.DeleteEmptyTeam(ctx, team.ID); err != nil {
		t.Fatal(err)
	}
	team, err = d.CreateTeam(ctx, "lifecycle member")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM teams WHERE id=$1`, team.ID) })
	member, err := d.CreateTeamMember(ctx, team.ID, "revoked", "unused")
	if err != nil {
		t.Fatal(err)
	}
	if err = d.RevokeTeamMember(ctx, team.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	eligibility, err = d.TeamDeletionEligibility(ctx, team.ID)
	if err != nil {
		t.Fatal(err)
	}
	if eligibility.Deletable || len(eligibility.Reasons) == 0 {
		t.Fatalf("revoked member must preserve audit: %+v", eligibility)
	}
	if err = d.DeleteEmptyTeam(ctx, team.ID); !errors.Is(err, ErrTeamLifecycleConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestDeleteTeamSerializesConcurrentMemberInsert(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := context.Background()
	team, err := d.CreateTeam(ctx, "lifecycle race")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM teams WHERE id=$1`, team.ID) })
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	var deleteErr, insertErr error
	go func() { defer wg.Done(); <-start; deleteErr = d.DeleteEmptyTeam(ctx, team.ID) }()
	go func() { defer wg.Done(); <-start; _, insertErr = d.CreateTeamMember(ctx, team.ID, "racer", "unused") }()
	close(start)
	wg.Wait()
	if deleteErr == nil {
		if insertErr == nil {
			t.Fatal("member insert succeeded after team deletion")
		}
	} else {
		if !errors.Is(deleteErr, ErrTeamLifecycleConflict) {
			t.Fatalf("delete error: %v", deleteErr)
		}
		if insertErr != nil {
			t.Fatalf("insert should succeed when it wins serialization: %v", insertErr)
		}
		var count int
		if err = d.QueryRow(`SELECT count(*) FROM team_members WHERE team_id=$1`, team.ID).Scan(&count); err != nil || count != 1 {
			t.Fatalf("team/member retained count=%d err=%v", count, err)
		}
	}
}
