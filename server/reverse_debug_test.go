package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func reverseRuntimeShellFixture(t *testing.T, body string) reverseRuntimeProfile {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("shell runner fixture is available in the Linux acceptance environment")
	}
	path := filepath.Join(t.TempDir(), "runner.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nset -eu\n"+body), 0700); err != nil {
		t.Fatal(err)
	}
	return reverseRuntimeProfile{ID: "fixture", Platform: "linux", Command: path, Settings: map[string]any{"platform": "linux"}}
}

func TestInvokeReverseRuntimeRunnerJSONProtocol(t *testing.T) {
	profile := reverseRuntimeShellFixture(t, `read request
case "$request" in *'"sha256":"abc"'*) ;; *) exit 2 ;; esac
case "$request" in *'"profile":{"platform":"linux"}'*) ;; *) exit 3 ;; esac
printf '{"available":true}'
`)
	raw, err := invokeReverseRuntime(context.Background(), profile, map[string]any{"operation": "doctor", "sha256": "abc"})
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil || result["available"] != true {
		t.Fatalf("runner JSON result=%s err=%v", raw, err)
	}
}

func TestInvokeReverseRuntimeRejectsMalformedAndOversizeOutput(t *testing.T) {
	t.Run("malformed", func(t *testing.T) {
		profile := reverseRuntimeShellFixture(t, "read request\nprintf 'not json'\n")
		if _, err := invokeReverseRuntime(context.Background(), profile, map[string]any{"operation": "doctor"}); err == nil {
			t.Fatal("malformed runner output was accepted")
		}
	})
	t.Run("oversize", func(t *testing.T) {
		profile := reverseRuntimeShellFixture(t, `read request
head -c 3145729 /dev/zero | tr '\000' x
`)
		if _, err := invokeReverseRuntime(context.Background(), profile, map[string]any{"operation": "doctor"}); err == nil {
			t.Fatal("oversize runner output was accepted")
		}
	})
}

func TestInvokeReverseRuntimeCancellationRequestsCleanup(t *testing.T) {
	profile := reverseRuntimeShellFixture(t, `read request
sleep 1
read cancellation
case "$cancellation" in *'"cancel":true'*) ;; *) exit 4 ;; esac
printf '{"cleaned":true}'
`)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	raw, err := invokeReverseRuntime(ctx, profile, map[string]any{"operation": "observe"})
	if err != context.DeadlineExceeded {
		t.Fatalf("cancellation error=%v, want deadline exceeded", err)
	}
	if strings.TrimSpace(string(raw)) != `{"cleaned":true}` {
		t.Fatalf("runner cleanup response=%q", raw)
	}
}

func TestReverseRuntimeObservationValidation(t *testing.T) {
	script := "send('fixture')"
	digest := sha256.Sum256([]byte(script))
	valid := func(platform string) map[string]any {
		cleanup := map[string]any{
			"script_unloaded": true, "session_detached": true,
			"owned_process_terminated": true, "staging_removed": true,
		}
		if platform == "android" {
			cleanup["package_removed"] = true
		}
		return map[string]any{
			"platform": platform, "artifact_sha256": "artifact-digest",
			"script_sha256": hex.EncodeToString(digest[:]), "cleanup": cleanup,
		}
	}
	tests := []struct {
		name     string
		platform string
		mutate   func(map[string]any)
		wantErr  string
	}{
		{name: "valid linux", platform: "linux"},
		{name: "valid android", platform: "android"},
		{name: "platform mismatch", platform: "linux", mutate: func(v map[string]any) { v["platform"] = "windows" }, wantErr: "材料、平台或脚本标识不匹配"},
		{name: "artifact hash mismatch", platform: "linux", mutate: func(v map[string]any) { v["artifact_sha256"] = "other" }, wantErr: "材料、平台或脚本标识不匹配"},
		{name: "script hash mismatch", platform: "linux", mutate: func(v map[string]any) { v["script_sha256"] = "other" }, wantErr: "材料、平台或脚本标识不匹配"},
		{name: "missing cleanup structure", platform: "linux", mutate: func(v map[string]any) { delete(v, "cleanup") }, wantErr: "清理未确认"},
		{name: "cleanup incomplete", platform: "linux", mutate: func(v map[string]any) { v["cleanup"].(map[string]any)["session_detached"] = false }, wantErr: "清理未确认"},
		{name: "android package retained", platform: "android", mutate: func(v map[string]any) { delete(v["cleanup"].(map[string]any), "package_removed") }, wantErr: "APK 清理未确认"},
		{name: "runner reports errors", platform: "linux", mutate: func(v map[string]any) { v["errors"] = []any{"script failed"} }, wantErr: "脚本或清理未完成"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			observation := valid(tt.platform)
			if tt.mutate != nil {
				tt.mutate(observation)
			}
			err := reverseRuntimeObservationError(observation, tt.platform, "artifact-digest", script)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("valid observation rejected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validation error=%v, want containing %q", err, tt.wantErr)
			}
		})
	}
}
