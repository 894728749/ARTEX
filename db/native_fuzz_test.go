package db

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func fuzzTestDSN(t *testing.T) string {
	t.Helper()
	if os.Getenv("ARTEX_FUZZ_TEST_DB") != "1" {
		t.Skip("explicit disposable fuzz test DB required")
	}
	dsn := os.Getenv("ARTEX_PG_DSN")
	if strings.TrimSpace(dsn) == "" {
		t.Fatal("ARTEX_PG_DSN is required when ARTEX_FUZZ_TEST_DB=1")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || !regexp.MustCompile(`^artex_[a-z0-9_]+_(test|review)$`).MatchString(cfg.Database) {
		t.Fatal("unsafe test database name")
	}
	return dsn
}

func TestNativeFuzzDSNGuard(t *testing.T) {
	if os.Getenv("ARTEX_FUZZ_TEST_DB") != "1" {
		t.Skip("explicit disposable fuzz test DB required")
	}
	for _, tc := range []struct {
		dsn string
		ok  bool
	}{
		{"dbname=artex_fuzz_review", true},
		{"dbname=artex_fuzz_test", true},
		{"dbname=artex", false},
		{"dbname=artex_fuzz_review_prod", false},
		{"dbname=postgres", false},
		{"dbname=business_review", false},
	} {
		cfg, err := pgx.ParseConfig(tc.dsn)
		ok := err == nil && regexp.MustCompile(`^artex_[a-z0-9_]+_(test|review)$`).MatchString(cfg.Database)
		if ok != tc.ok {
			t.Fatalf("%q guard=%v want %v", tc.dsn, ok, tc.ok)
		}
	}
}

func TestNativeFuzzRunModeConstraintMigration(t *testing.T) {
	dsn := fuzzTestDSN(t)
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTaskWithOptions("synthetic fuzz ledger migration", "owned fixture", TaskCreateOptions{Kind: "reverse"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	artifact, err := d.AddReverseArtifact(task.ID, ReverseArtifact{
		Name: "fixture.elf", Format: "elf",
		Path:      fmt.Sprintf("tasks/%d/reverse/artifacts/fixture.elf", task.ID),
		SizeBytes: 64, SHA256: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	runtimeID := func() int64 {
		var id int64
		if err := d.QueryRow(`INSERT INTO reverse_runtime_runs(task_id,artifact_id,intent_id,profile_id,status) VALUES($1,$2,NULL,'fuzz-test','running') RETURNING id`, task.ID, artifact.ID).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	first := runtimeID()
	if _, err := d.Exec(`INSERT INTO reverse_native_runs(run_id,task_id,artifact_id,intent_id,config_revision,mode,target_state,observation) VALUES($1,$2,$3,0,1,'fuzz','completed','{}')`, first, task.ID, artifact.ID); err != nil {
		t.Fatalf("mode=fuzz rejected by ledger constraint: %v", err)
	}
	var mode string
	if err := d.QueryRow(`SELECT mode FROM reverse_native_runs WHERE run_id=$1`, first).Scan(&mode); err != nil || mode != "fuzz" {
		t.Fatalf("ledger mode=%q err=%v", mode, err)
	}
	second := runtimeID()
	if _, err := d.Exec(`INSERT INTO reverse_native_runs(run_id,task_id,artifact_id,intent_id,config_revision,mode,target_state,observation) VALUES($1,$2,$3,0,1,'bogus','completed','{}')`, second, task.ID, artifact.ID); err == nil {
		t.Fatal("unknown native ledger mode accepted")
	}
	var definition string
	if err := d.QueryRow(`SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname='reverse_native_runs_mode_check' AND conrelid='reverse_native_runs'::regclass`).Scan(&definition); err != nil || !strings.Contains(definition, "'fuzz'") {
		t.Fatalf("mode constraint definition=%q err=%v", definition, err)
	}
	// Reapplying the whole schema over an existing fuzz row must stay idempotent.
	reopened, err := Open(dsn)
	if err != nil {
		t.Fatalf("reapply schema with fuzz ledger row: %v", err)
	}
	_ = reopened.Close()
}
