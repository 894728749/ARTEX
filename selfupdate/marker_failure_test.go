package selfupdate

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// stagedReleaseFixture serves a synthetic ZIP entirely in memory; no network or
// installed ARTEX executable is used by these tests.
func stagedReleaseFixture(t *testing.T) (*http.Client, *Release) {
	t.Helper()
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	w, err := zw.Create("fixture/artex")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(w, "#!/bin/sh\nexit 0\n"); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	name := AssetName("v0.4.2", runtime.GOOS, runtime.GOARCH)
	const base = "https://github.com/cyy081021/ARTEX/releases/download/v0.4.2/"
	rel := &Release{TagName: "v0.4.2", Assets: []Asset{
		{Name: name, URL: base + name, Size: int64(archive.Len())},
		{Name: sumsAsset, URL: base + sumsAsset},
	}}
	sums := fmt.Sprintf("%x  %s\n", sha256.Sum256(archive.Bytes()), name)
	client := &http.Client{Transport: releaseRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		var body io.Reader
		switch r.URL.String() {
		case base + sumsAsset:
			body = strings.NewReader(sums)
		case base + name:
			body = bytes.NewReader(archive.Bytes())
		default:
			t.Fatalf("unexpected request: %s", r.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(body), Header: make(http.Header), Request: r}, nil
	})}
	return client, rel
}

func assertNoStagedFiles(t *testing.T, p Paths) {
	t.Helper()
	for _, path := range []string{p.New, p.Sum, p.New + ".part", p.New + ".zip.part"} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("staged file must be absent: %s (stat error: %v)", path, err)
		}
	}
}

func assertOriginals(t *testing.T, p Paths, current, backup string) {
	t.Helper()
	if got := readAll(t, p.Current); got != current {
		t.Errorf("current executable changed: %q", got)
	}
	if got := readAll(t, p.Old); got != backup {
		t.Errorf("previous backup changed: %q", got)
	}
}

func TestStageRejectsMarkerWriteFailure(t *testing.T) {
	requireUnix(t)
	p := testPaths(t)
	fakeBin(t, p.Current, "current", 0)
	fakeBin(t, p.Old, "previous-backup", 0)
	current, backup := readAll(t, p.Current), readAll(t, p.Old)
	// A nonempty directory forces a real write error, independent of UID/mode.
	if err := os.Mkdir(p.Marker, 0o755); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(p.Marker, "keep")
	if err := os.WriteFile(blocker, []byte("do not remove recursively"), 0o644); err != nil {
		t.Fatal(err)
	}
	client, rel := stagedReleaseFixture(t)
	var phases []Phase
	err := stageRelease(context.Background(), client, rel, "0.4.1", func(ph Phase, _ int, _ string) {
		phases = append(phases, ph)
	}, p)
	if err == nil || !strings.Contains(err.Error(), "写入升级标记") {
		t.Errorf("marker write failure must be returned, got %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "清理升级文件") {
		t.Errorf("blocked marker cleanup must also be reported, got %v", err)
	}
	for _, ph := range phases {
		if ph == PhaseStaged {
			t.Error("failed staging must never announce readiness/restart")
		}
	}
	assertNoStagedFiles(t, p)
	assertOriginals(t, p, current, backup)
	if got := readAll(t, blocker); got != "do not remove recursively" {
		t.Errorf("cleanup modified unrelated directory contents: %q", got)
	}
}

func TestApplyStagedRejectsMissingOrUnreadableMarker(t *testing.T) {
	requireUnix(t)
	for _, kind := range []string{"missing", "invalid-json", "directory"} {
		t.Run(kind, func(t *testing.T) {
			p := testPaths(t)
			fakeBin(t, p.Current, "current", 0)
			fakeBin(t, p.Old, "previous-backup", 0)
			current, backup := readAll(t, p.Current), readAll(t, p.Old)
			stage(t, p, "new", 0)
			switch kind {
			case "invalid-json":
				if err := os.WriteFile(p.Marker, []byte("{partial"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(p.Marker, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			action, state := applyStaged(p)
			if action != Continue || !state.FailedStage || state.Pending || !strings.Contains(state.Detail, "升级标记") {
				t.Errorf("unsafe staged update must be rejected, got action=%v state=%+v", action, state)
			}
			assertOriginals(t, p, current, backup)
			assertNoStagedFiles(t, p)
			if _, err := os.Stat(p.Marker); !os.IsNotExist(err) {
				t.Errorf("rejected marker not cleaned: %v", err)
			}
		})
	}
}

func TestApplyStagedRejectsMarkerRewriteFailureBeforeSwap(t *testing.T) {
	requireUnix(t)
	p := testPaths(t)
	fakeBin(t, p.Current, "current", 0)
	fakeBin(t, p.Old, "previous-backup", 0)
	current, backup := readAll(t, p.Current), readAll(t, p.Old)
	if err := writeMarker(p.Marker, marker{From: "0.4.1", To: "0.4.2"}); err != nil {
		t.Fatal(err)
	}
	// The marker is readable initially; the smoke fixture replaces it with a
	// nonempty directory to inject failure specifically at the next marker write.
	quoted := "'" + strings.ReplaceAll(p.Marker, "'", "'\"'\"'") + "'"
	script := "#!/bin/sh\nset -e\nrm -- " + quoted + "\nmkdir -- " + quoted + "\nprintf keep > " + quoted + "/keep\n"
	if err := os.WriteFile(p.New, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	sum, err := fileSHA256(p.New)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.Sum, []byte(sum), 0o644); err != nil {
		t.Fatal(err)
	}
	action, state := applyStaged(p)
	if action != Continue || !state.FailedStage || state.Pending || !strings.Contains(state.Detail, "写入升级标记") {
		t.Errorf("marker write failure must precede any swap, got action=%v state=%+v", action, state)
	}
	if !strings.Contains(state.Detail, "清理升级文件") {
		t.Errorf("cleanup failure not reported: %+v", state)
	}
	assertOriginals(t, p, current, backup)
	assertNoStagedFiles(t, p)
	if got := readAll(t, filepath.Join(p.Marker, "keep")); got != "keep" {
		t.Errorf("cleanup modified blocker: %q", got)
	}
}

func TestStageAndApplyWithMarker(t *testing.T) {
	requireUnix(t)
	p := testPaths(t)
	fakeBin(t, p.Current, "current", 0)
	current := readAll(t, p.Current)
	client, rel := stagedReleaseFixture(t)
	var lastPhase Phase
	if err := stageRelease(context.Background(), client, rel, "0.4.1", func(ph Phase, _ int, _ string) {
		lastPhase = ph
	}, p); err != nil {
		t.Fatal(err)
	}
	if lastPhase != PhaseStaged || readAll(t, p.Current) != current {
		t.Fatal("successful staging must report ready without replacing current")
	}
	m, ok := readMarker(p.Marker)
	if !ok || m.From != "0.4.1" || m.To != "0.4.2" || m.Attempts != 0 || m.StagedAt == 0 {
		t.Fatalf("missing staging metadata: %+v, readable=%v", m, ok)
	}
	newBinary := readAll(t, p.New)
	action, state := applyStaged(p)
	if action != Restart || !state.Pending || state.FailedStage {
		t.Fatalf("normal upgrade rejected: action=%v state=%+v", action, state)
	}
	if readAll(t, p.Current) != newBinary || readAll(t, p.Old) != current {
		t.Fatal("normal swap must install new binary and preserve previous current")
	}
	if got, ok := readMarker(p.Marker); !ok || got != m {
		t.Errorf("rollback metadata must survive swap: %+v (readable=%v)", got, ok)
	}
	assertNoStagedFiles(t, p)
}
