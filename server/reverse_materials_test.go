package server

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func apkMaterialFixture(t *testing.T, entries map[string][]byte) (string, *db.ReverseArtifact) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "sample.apk")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for name, data := range entries {
		out, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		out.Write(data)
	}
	w.Close()
	f.Close()
	data, _ := os.ReadFile(p)
	h := sha256.Sum256(data)
	return dir, &db.ReverseArtifact{ID: 1, TaskID: 12, Path: p, Format: "apk", SHA256: hex.EncodeToString(h[:]), SizeBytes: int64(len(data))}
}

func TestReverseAPKMaterialSelection(t *testing.T) {
	hbc := make([]byte, 16)
	binary.LittleEndian.PutUint64(hbc, 0x1F1903C103BC1FC6)
	binary.LittleEndian.PutUint32(hbc[8:], 94)
	dir, a := apkMaterialFixture(t, map[string][]byte{"assets/index.android.bundle": hbc, "assets/plain.js": []byte("export const n=3;"), "../escape.js": []byte("bad")})
	result, err := prepareReverseAPK(t.Context(), a, dir, "assets/index.android.bundle", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	d := result["derived"].(reverseDerived)
	if d.Format != "hermes" || d.BytecodeVersion != 94 || d.ParentSHA256 != a.SHA256 {
		t.Fatalf("bad lineage %+v", d)
	}
	bytes, err := os.ReadFile(filepath.Join(dir, d.Path))
	if err != nil || len(bytes) != len(hbc) {
		t.Fatalf("read %v", err)
	}
	js, err := prepareReverseAPK(t.Context(), a, dir, "assets/plain.js", 0, 10)
	if err != nil || js["derived"].(reverseDerived).Format != "javascript" {
		t.Fatalf("JS: %v %v", js, err)
	}
	if _, err := prepareReverseAPK(t.Context(), a, dir, "../escape.js", 0, 10); err == nil {
		t.Fatal("accepted traversal")
	}
	cancelCtx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := prepareReverseAPK(cancelCtx, a, dir, "assets/plain.js", 0, 10); err == nil {
		t.Fatal("ignored cancellation")
	}
	a.SHA256 = "wrong"
	if _, err := prepareReverseAPK(t.Context(), a, dir, "", 0, 10); err == nil {
		t.Fatal("accepted changed parent")
	}
}

func TestReverseAPKMaterialRejectsDuplicateAndSymlink(t *testing.T) {
	dir, a := apkMaterialFixture(t, nil)
	f, _ := os.Create(a.Path)
	w := zip.NewWriter(f)
	for range 2 {
		x, _ := w.Create("assets/a.js")
		x.Write([]byte("x"))
	}
	w.Close()
	f.Close()
	data, _ := os.ReadFile(a.Path)
	h := sha256.Sum256(data)
	a.SizeBytes = int64(len(data))
	a.SHA256 = hex.EncodeToString(h[:])
	if _, err := prepareReverseAPK(t.Context(), a, dir, "assets/a.js", 0, 10); err == nil {
		t.Fatal("accepted ambiguous entry")
	}
}

func TestReverseDerivedToolsPreserveScopeAndHashes(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	task, err := m.pg.CreateTaskWithOptions("material fixture", "offline synthetic", db.TaskCreateOptions{Kind: "reverse"})
	if err != nil {
		t.Fatal(err)
	}
	defer m.pg.DeleteTask(task.ID)
	source, a := apkMaterialFixture(t, map[string][]byte{"assets/plain.js": []byte("export const value=3;")})
	_ = source
	dir := filepath.Join(m.dir, "tasks", fmt.Sprint(task.ID), "reverse", "artifacts")
	os.MkdirAll(dir, 0700)
	bytes, _ := os.ReadFile(a.Path)
	p := filepath.Join(dir, "fixture.apk")
	os.WriteFile(p, bytes, 0600)
	rel, _ := filepath.Rel(m.dir, p)
	a.Path = rel
	a.Name = "fixture.apk"
	a, err = m.pg.AddReverseArtifact(task.ID, *a)
	if err != nil {
		t.Fatal(err)
	}
	tools := reverseMaterialTools(m.pg, task, agent.RunInfo{}, m.dir)
	got := workflowCall(t, t.Context(), workflowTool(t, tools, "reverse_prepare_apk"), map[string]any{"artifact_id": a.ID, "entry": "assets/plain.js"}, false)
	var prepared struct {
		Ref    string `json:"result_path"`
		Result struct {
			Derived reverseDerived `json:"derived"`
		} `json:"result"`
	}
	if err = json.Unmarshal([]byte(got), &prepared); err != nil {
		t.Fatal(err)
	}
	if prepared.Ref == "" {
		t.Fatal(got)
	}
	text := workflowCall(t, t.Context(), workflowTool(t, tools, "reverse_read_derived"), map[string]any{"result_path": prepared.Ref, "offset": 7, "limit": 5}, false)
	if !strings.Contains(text, "const") {
		t.Fatalf("text %s", text)
	}
	evidence := []db.ReverseEvidence{{ArtifactID: a.ID, Locator: "assets/plain.js", Observation: "contains constant", ResultPath: prepared.Ref}}
	if err = reverseEvidenceCheck(m.pg, task.ID, m.dir, evidence); err != nil {
		t.Fatal(err)
	}
	if evidence[0].ResultSHA256 == "" {
		t.Fatal("result hash not captured")
	}
	// A derived receipt from another task is rejected before any analysis.
	workflowCall(t, t.Context(), workflowTool(t, tools, "reverse_read_derived"), map[string]any{"result_path": "tasks/99999/reverse/results/other.json"}, true)
	os.WriteFile(filepath.Join(m.dir, prepared.Result.Derived.Path), []byte("changed"), 0600)
	workflowCall(t, t.Context(), workflowTool(t, tools, "reverse_read_derived"), map[string]any{"result_path": prepared.Ref}, true)
	resultFile := filepath.Join(m.dir, prepared.Ref)
	stored, _ := os.ReadFile(resultFile)
	os.WriteFile(resultFile, append(stored, byte(' ')), 0600)
	if err = reverseEvidenceCheck(m.pg, task.ID, m.dir, evidence); err == nil {
		t.Fatal("accepted changed raw evidence")
	}
}

func TestReverseMaterialRejectsRedirectedRoot(t *testing.T) {
	dir, a := apkMaterialFixture(t, map[string][]byte{"assets/plain.js": []byte("const x=1;")})
	root := filepath.Join(dir, "tasks", "12", "reverse")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "derived")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := prepareReverseAPK(t.Context(), a, dir, "assets/plain.js", 0, 10); err == nil {
		t.Fatal("wrote through redirected derived root")
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Fatal("escaped writes")
	}
}

// Opt-in material acceptance reads the user's APK as static bytes into this
// synthetic fixture. It never runs the APK or connects to its hosts.
func TestReverseHermesV94MaterialAcceptance(t *testing.T) {
	p := os.Getenv("ARTEX_HERMES_ACCEPTANCE_APK")
	if p == "" {
		t.Skip("set explicit read-only APK fixture path")
	}
	z, err := zip.OpenReader(p)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	var bundle []byte
	for _, e := range z.File {
		if e.Name == "assets/index.android.bundle" {
			r, _ := e.Open()
			bundle = make([]byte, e.UncompressedSize64)
			n := 0
			for n < len(bundle) {
				x, err := r.Read(bundle[n:])
				n += x
				if err != nil {
					break
				}
			}
			r.Close()
		}
	}
	if len(bundle) == 0 {
		t.Fatal("missing bundle")
	}
	dir, a := apkMaterialFixture(t, map[string][]byte{"assets/index.android.bundle": bundle})
	prepared, err := prepareReverseAPK(t.Context(), a, dir, "assets/index.android.bundle", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	d := prepared["derived"].(reverseDerived)
	if d.Format != "hermes" || d.BytecodeVersion != 94 {
		t.Fatalf("format %+v", d)
	}
	for _, facet := range []string{"summary", "strings", "functions", "instructions"} {
		raw, err := inspectReverseHermes(t.Context(), map[string]any{"path": filepath.Join(dir, d.Path), "facet": facet, "function_id": 0, "limit": 3})
		if err != nil {
			t.Fatalf("%s: %v", facet, err)
		}
		var value map[string]any
		if json.Unmarshal(raw, &value) != nil || value["bytecode_version"] != float64(94) {
			t.Fatalf("bad result %s", raw)
		}
		if facet == "summary" {
			t.Logf("Hermes v94: functions=%v strings=%v", value["function_count"], value["string_count"])
		}
	}
}
