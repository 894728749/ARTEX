package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReverseStaticRouteAndExecutionBoundary(t *testing.T) {
	root := t.TempDir()
	sample := filepath.Join(root, "test.elf")
	if err := os.WriteFile(sample, []byte("\x7fELFfixture"), 0600); err != nil {
		t.Fatal(err)
	}
	family, err := reverseArtifactFamily(sample, "elf")
	if err != nil || family != "native" {
		t.Fatal(family, err)
	}
	for format, want := range map[string]string{"js": "javascript", "mjs": "javascript", "apk": "android"} {
		got, err := reverseArtifactFamily(sample, format)
		if err != nil || got != want {
			t.Fatal(format, got, err)
		}
	}
	for _, name := range []string{"execute_rizin_command", "gdb_console", "start_frida_session", "install_adb_package", "set_address_name", "capture_process_scenario"} {
		if reverseStaticToolAllowed(name) {
			t.Fatal("static workflow admitted execution/mutation", name)
		}
	}
	for _, name := range []string{"analyze_javascript_application", "inspect_android_method", "inspect_managed_members", "procedure_pseudo_code"} {
		if !reverseStaticToolAllowed(name) {
			t.Fatal("missing analysis tool", name)
		}
	}
	if err := validateReverseStaticPaths(map[string]any{"path": sample}, root); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "private")
	_ = os.WriteFile(outside, []byte("outside"), 0600)
	if err := validateReverseStaticPaths(map[string]any{"source": map[string]any{"kind": "evidence-file", "path": outside}}, root); err == nil {
		t.Fatal("accepted another task's evidence")
	}
	for _, key := range []string{"manifest_path", "left_module_path", "right_bundle_path"} {
		if err := validateReverseStaticPaths(map[string]any{key: outside}, root); err == nil {
			t.Fatal("accepted outside path", key)
		}
	}
	if err := validateReverseStaticPaths(map[string]any{"source_paths": []any{"../outside.js"}}, root); err == nil {
		t.Fatal("accepted relative source escape")
	}
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err == nil {
		if err = validateReverseStaticPaths(map[string]any{"path": link}, root); err == nil {
			t.Fatal("accepted symlink escape")
		}
	}
}
