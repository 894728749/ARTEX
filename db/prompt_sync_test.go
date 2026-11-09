package db

import (
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func promptAgent(t *testing.T, d *DB) int64 {
	t.Helper()
	var id int64
	key := fmt.Sprintf("prompt_sync_%d", promptTestCounter.Add(1))
	if err := d.QueryRow(`INSERT INTO agents(key,name,role) VALUES($1,$1,'assistant') RETURNING id`, key).Scan(&id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM agents WHERE id=$1`, id) })
	return id
}

var promptTestCounter atomic.Int64

func openPromptDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func TestPromptBuiltinSyncRegressions(t *testing.T) {
	d := openPromptDB(t)
	t.Run("upgrade known default, preserve custom and unknown, future upgrade, idempotent", func(t *testing.T) {
		legacy, next, future := "legacy template", "next template", "future template"
		id := promptAgent(t, d)
		if err := d.SeedPromptIfEmpty(id, legacy); err != nil {
			t.Fatal(err)
		}
		if _, err := d.SyncBuiltinPrompt(id, legacy, nil); err != nil {
			t.Fatal(err)
		}
		changed, err := d.SyncBuiltinPrompt(id, next, nil)
		if err != nil || !changed {
			t.Fatalf("upgrade changed=%v err=%v", changed, err)
		}
		changed, err = d.SyncBuiltinPrompt(id, next, nil)
		if err != nil || changed {
			t.Fatalf("repeat changed=%v err=%v", changed, err)
		}
		if _, err = d.SyncBuiltinPrompt(id, "third", nil); err != nil {
			t.Fatal(err)
		}
		if got, _ := d.CurrentPrompt(id); got != "third" {
			t.Fatalf("future default/current=%q", got)
		}
		if _, err = d.SavePrompt(id, legacy, "user edit", "user"); err != nil {
			t.Fatal(err)
		}
		changed, err = d.SyncBuiltinPrompt(id, future, nil)
		if err != nil || changed {
			t.Fatalf("same-old-text custom changed=%v err=%v", changed, err)
		}
		if got, _ := d.CurrentPrompt(id); got != legacy {
			t.Fatalf("custom overwritten: %q", got)
		}
		unknown := promptAgent(t, d)
		if _, err = d.SavePrompt(unknown, "unknown system text", "", "system"); err != nil {
			t.Fatal(err)
		}
		if _, err = d.SyncBuiltinPrompt(unknown, future, nil); err != nil {
			t.Fatal(err)
		}
		if got, _ := d.CurrentPrompt(unknown); got != "unknown system text" {
			t.Fatalf("unknown system prompt overwritten: %q", got)
		}
		// Explicit legacy hash allows upgrading deployments predating the recorded marker.
		legacyHash := promptHash(legacy)
		old := promptAgent(t, d)
		if _, err = d.SavePrompt(old, legacy, "", "system"); err != nil {
			t.Fatal(err)
		}
		changed, err = d.SyncBuiltinPrompt(old, future, []string{legacyHash})
		if err != nil || !changed {
			t.Fatalf("legacy hash upgrade changed=%v err=%v", changed, err)
		}
		if got, _ := d.CurrentPrompt(old); got != future {
			t.Fatalf("future prompt=%q", got)
		}
	})
	t.Run("empty and missing agent rejected", func(t *testing.T) {
		if _, err := d.SyncBuiltinPrompt(999999999, "x", nil); err == nil {
			t.Fatal("missing agent accepted")
		}
		if _, err := d.SyncBuiltinPrompt(promptAgent(t, d), "", nil); err == nil {
			t.Fatal("empty template accepted")
		}
	})
	t.Run("failed marker write rolls back seed", func(t *testing.T) {
		id := promptAgent(t, d)
		_, err := d.Exec(`CREATE OR REPLACE FUNCTION prompt_sync_fail_marker() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced marker failure'; END $$`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = d.Exec(`CREATE TRIGGER prompt_sync_fail BEFORE INSERT OR UPDATE ON agent_prompt_defaults FOR EACH ROW EXECUTE FUNCTION prompt_sync_fail_marker()`); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = d.Exec(`DROP TRIGGER IF EXISTS prompt_sync_fail ON agent_prompt_defaults`)
			_, _ = d.Exec(`DROP FUNCTION IF EXISTS prompt_sync_fail_marker()`)
		})
		_, err = d.SyncBuiltinPrompt(id, "seed", nil)
		if err == nil {
			t.Fatal("expected injected failure")
		}
		_, _ = d.Exec(`DROP TRIGGER IF EXISTS prompt_sync_fail ON agent_prompt_defaults`)
		_, _ = d.Exec(`DROP FUNCTION IF EXISTS prompt_sync_fail_marker()`)
		var cur sql.NullInt64
		if err = d.QueryRow(`SELECT current_prompt_id FROM agents WHERE id=$1`, id).Scan(&cur); err != nil {
			t.Fatal(err)
		}
		var n int
		if err = d.QueryRow(`SELECT count(*) FROM agent_prompt_defaults WHERE agent_id=$1`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if cur.Valid || n != 0 {
			t.Fatalf("rollback incomplete: current=%v marker rows=%d", cur, n)
		}
		var versions int
		if err = d.QueryRow(`SELECT count(*) FROM agent_prompts WHERE agent_id=$1`, id).Scan(&versions); err != nil || versions != 0 {
			t.Fatalf("failed transaction retained prompt versions: %d, %v", versions, err)
		}
		if changed, err := d.SyncBuiltinPrompt(id, "seed", nil); err != nil || !changed {
			t.Fatalf("retry after failed synchronization: changed=%v err=%v", changed, err)
		}
	})
}

func TestPromptConcurrentWritesSerializeVersions(t *testing.T) {
	d := openPromptDB(t)
	id := promptAgent(t, d)
	const workers = 24
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := d.SavePrompt(id, fmt.Sprintf("saved-%d", i), "", "test"); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	var n, min, max int
	if err := d.QueryRow(`SELECT count(*),min(version),max(version) FROM agent_prompts WHERE agent_id=$1`, id).Scan(&n, &min, &max); err != nil {
		t.Fatal(err)
	}
	if n != workers || min != 1 || max != workers {
		t.Fatalf("versions count=%d min=%d max=%d", n, min, max)
	}
}

func TestPromptConcurrentSeedAndSync(t *testing.T) {
	d := openPromptDB(t)
	id := promptAgent(t, d)
	const workers = 20
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := d.SeedPromptIfEmpty(id, "initial"); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	var n int
	if err := d.QueryRow(`SELECT count(*) FROM agent_prompts WHERE agent_id=$1`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("prompt versions=%d, want exactly one concurrent seed", n)
	}
	if _, err := d.SyncBuiltinPrompt(id, "initial", nil); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := d.SavePrompt(id, fmt.Sprintf("parallel-save-%d", i), "", "test"); err != nil {
				t.Errorf("concurrent save: %v", err)
			}
		}(i)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := d.SyncBuiltinPrompt(id, "updated", nil); err != nil {
				t.Errorf("concurrent sync: %v", err)
			}
		}()
	}
	wg.Wait()
	if err := d.QueryRow(`SELECT count(*) FROM agent_prompts WHERE agent_id=$1`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < workers+1 || n > workers+2 {
		t.Fatalf("prompt versions=%d, want serialized saves and at most one sync", n)
	}
}
