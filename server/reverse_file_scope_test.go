package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

func TestReverseFileToolsCannotReadOtherTasksOrPlatformFiles(t *testing.T) {
	root := t.TempDir()
	own := filepath.Join(root, "tasks", "1")
	other := filepath.Join(root, "tasks", "2")
	_ = os.MkdirAll(own, 0700)
	_ = os.MkdirAll(other, 0700)
	allowed := filepath.Join(own, "client.js")
	outside := filepath.Join(other, "private.txt")
	_ = os.WriteFile(allowed, []byte("export const answer=42;"), 0600)
	_ = os.WriteFile(outside, []byte("other task private value"), 0600)
	ctx := context.Background()
	tc := &actool.ToolContext{WorkingDir: own}
	for _, base := range actool.DefaultTools() {
		if !contains([]string{"Read", "LS", "Grep", "Glob"}, base.Name()) {
			continue
		}
		tool := &reverseFileTool{CoreTool: base, workDir: root, taskID: 1}
		field := "path"
		if base.Name() == "Read" {
			field = "file_path"
		}
		for _, path := range []string{outside, filepath.Join("..", "2", "private.txt"), filepath.Join(root, "config.json")} {
			raw, _ := json.Marshal(map[string]any{field: path, "pattern": "*"})
			r, err := tool.Call(ctx, raw, tc)
			if err != nil || !r.IsError {
				t.Fatalf("%s escaped via %s: %+v %v", base.Name(), path, r, err)
			}
		}
		if base.Name() == "Read" {
			raw, _ := json.Marshal(map[string]any{"file_path": "client.js"})
			r, err := tool.Call(ctx, raw, tc)
			if err != nil || r.IsError || !strings.Contains(r.Flatten(), "answer=42") {
				t.Fatalf("own material rejected: %+v %v", r, err)
			}
		}
	}
	link := filepath.Join(own, "outside.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink subcase unavailable: %v", err)
	}
	for _, base := range actool.DefaultTools() {
		if base.Name() != "Read" && base.Name() != "Grep" {
			continue
		}
		tool := &reverseFileTool{CoreTool: base, workDir: root, taskID: 1}
		args := map[string]any{"file_path": link}
		if base.Name() == "Grep" {
			args = map[string]any{"path": own, "pattern": "private", "output_mode": "content"}
		}
		raw, _ := json.Marshal(args)
		r, err := tool.Call(ctx, raw, tc)
		if err != nil || !r.IsError || strings.Contains(r.Flatten(), "other task private value") {
			t.Fatalf("%s followed foreign symlink: %+v %v", base.Name(), r, err)
		}
	}
}
