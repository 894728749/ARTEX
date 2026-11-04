package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// WorkingDir is a convenience, not a read boundary. Bound the built-in readers
// to this task even when a model supplies an absolute path or a symlink.
type reverseFileTool struct {
	actool.CoreTool
	workDir string
	taskID  int64
}

func (t *reverseFileTool) Description() string {
	return t.CoreTool.Description() + "\n仅可读取当前逆向任务目录及其已复制材料；不能读取其他任务或平台配置。"
}

func (t *reverseFileTool) Call(ctx context.Context, raw json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	if t.taskID <= 0 || t.workDir == "" {
		return actool.Errorf("读取工具缺少任务目录绑定"), nil
	}
	var args map[string]json.RawMessage
	if err := json.Unmarshal(raw, &args); err != nil || args == nil {
		return actool.Errorf("参数必须为对象"), nil
	}
	field := "path"
	if t.Name() == "Read" {
		field = "file_path"
	}
	var path string
	if value, ok := args[field]; ok {
		if err := json.Unmarshal(value, &path); err != nil {
			return actool.Errorf("路径必须为字符串"), nil
		}
	}
	prefix := filepath.Join("tasks", strconv.FormatInt(t.taskID, 10))
	root := filepath.Join(t.workDir, prefix)
	cwd := root
	if tc != nil && tc.WorkingDir != "" {
		cwd = tc.WorkingDir
	}
	if path == "" {
		path = cwd
	} else if !filepath.IsAbs(path) {
		if path == prefix || strings.HasPrefix(path, prefix+string(filepath.Separator)) {
			path = filepath.Join(t.workDir, path)
		} else {
			path = filepath.Join(cwd, path)
		}
	}
	relative, err := filepath.Rel(t.workDir, path)
	if err != nil {
		return actool.Errorf("路径不属于当前任务"), nil
	}
	path, err = reverseLocalPath(t.workDir, relative, prefix)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	if t.Name() == "Grep" {
		// The SDK's Go fallback follows individual file symlinks. Validate them before
		// handing it a recursive directory; don't let fallback choice change scope.
		count := 0
		err = filepath.WalkDir(path, func(p string, d fs.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				return walkErr
			}
			count++
			if count > 100000 {
				return fmt.Errorf("检索目录过大，请缩小到具体子目录")
			}
			if d.Type()&fs.ModeSymlink != 0 {
				rel, err := filepath.Rel(t.workDir, p)
				if err != nil {
					return err
				}
				if _, err = reverseLocalPath(t.workDir, rel, prefix); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
	}
	args[field], _ = json.Marshal(path)
	raw, _ = json.Marshal(args)
	if tc == nil {
		tc = &actool.ToolContext{WorkingDir: root}
	}
	return t.CoreTool.Call(ctx, raw, tc)
}
