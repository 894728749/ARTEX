package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// Some REA providers wrap normalized JSON in a string. Decode only for the
// read view; the retained MCP result stays byte-for-byte intact.
func reverseEvidenceValue(value any) any {
	for range 4 {
		text, ok := value.(string)
		if !ok || !strings.HasPrefix(strings.TrimSpace(text), "{") && !strings.HasPrefix(strings.TrimSpace(text), "[") {
			break
		}
		var decoded any
		if json.Unmarshal([]byte(text), &decoded) != nil {
			break
		}
		value = decoded
	}
	return value
}

func reaPreview(raw json.RawMessage) string {
	var result struct {
		Structured map[string]any `json:"structuredContent"`
		Content    []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	_ = json.Unmarshal(raw, &result)
	if len(result.Structured) > 0 {
		result.Structured["normalized_result"] = reverseEvidenceValue(result.Structured["normalized_result"])
		brief := map[string]any{}
		for _, key := range []string{"evidence_id", "subject", "provider", "operation", "confidence", "authority", "limitations"} {
			if v, ok := result.Structured[key]; ok {
				brief[key] = v
			}
		}
		if normalized, ok := result.Structured["normalized_result"].(map[string]any); ok {
			fields := make([]string, 0, len(normalized))
			for key := range normalized {
				fields = append(fields, key)
			}
			sort.Strings(fields)
			brief["result_field_count"] = len(fields)
			brief["result_fields"] = fields[:min(30, len(fields))]
			for _, key := range []string{"summary", "statistics", "limitations", "root_artifact_sha256", "integrity_contradictions", "cleanup", "errors", "platform", "cancelled", "truncated", "duration_ms"} {
				if v, ok := normalized[key]; ok {
					brief[key] = v
				}
			}
			if messages, ok := normalized["messages"].([]any); ok {
				brief["message_count"] = len(messages)
				brief["message_preview"] = messages[:min(5, len(messages))]
			}
		}
		// Native decompilation is a scalar normalized result. Preserve useful
		// code in the bounded preview instead of returning only its identity.
		switch normalized := result.Structured["normalized_result"].(type) {
		case string:
			brief["result"] = normalized
		case []any:
			brief["result_count"] = len(normalized)
			brief["result_preview"] = normalized[:min(5, len(normalized))]
		}
		b, _ := json.Marshal(brief)
		text := string(b)
		if len(text) > 7000 {
			text = string([]rune(text)[:min(2500, len([]rune(text)))]) + " [摘要过长，使用 reverse_evidence_view 分页]"
		}
		return text
	}
	var text strings.Builder
	for _, item := range result.Content {
		text.WriteString(item.Text)
	}
	runes := []rune(text.String())
	if len(runes) > 2500 {
		return string(runes[:2500]) + " [预览截断，原始结果已保存]"
	}
	return text.String()
}

func reverseEvidenceViewTool(taskID int64, workDir string) actool.CoreTool {
	return reverseTool("reverse_evidence_view", "按 JSON Pointer 读取已保存的完整 MCP 证据。path 为 result_path；pointer 如 /structuredContent/normalized_result/summary。自动展开字符串内的 JSON，对象返回 fields 供逐层选择。数组按 offset/limit 分页（最多30项）；普通长文本按字符 offset/limit 分页（最多4000字符）。", reverseObject(map[string]any{"path": reverseString(), "pointer": reverseString(), "offset": reverseInt(), "limit": reverseInt()}, "path"), func(_ context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			Path, Pointer string
			Offset, Limit int
		}
		if err := json.Unmarshal(in, &a); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		path, err := reverseLocalPath(workDir, a.Path, filepath.Join("tasks", strconv.FormatInt(taskID, 10), "reverse", "results"))
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		f, err := os.Open(path)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		defer f.Close()
		var value any
		if err := json.NewDecoder(f).Decode(&value); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		if a.Pointer != "" {
			if !strings.HasPrefix(a.Pointer, "/") {
				return actool.Errorf("pointer 必须为空或以 / 开头"), nil
			}
			for _, token := range strings.Split(a.Pointer[1:], "/") {
				value = reverseEvidenceValue(value)
				token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
				switch v := value.(type) {
				case map[string]any:
					var ok bool
					value, ok = v[token]
					if !ok {
						return actool.Errorf("JSON Pointer 不存在"), nil
					}
				case []any:
					i, err := strconv.Atoi(token)
					if err != nil || i < 0 || i >= len(v) {
						return actool.Errorf("数组下标不存在"), nil
					}
					value = v[i]
				default:
					return actool.Errorf("JSON Pointer 无法继续展开"), nil
				}
			}
		}
		value = reverseEvidenceValue(value)
		out := map[string]any{"path": a.Path, "pointer": a.Pointer}
		if object, ok := value.(map[string]any); ok {
			fields := make([]string, 0, len(object))
			for key := range object {
				fields = append(fields, key)
			}
			sort.Strings(fields)
			out["field_count"] = len(fields)
			out["fields"] = fields[:min(60, len(fields))]
		}
		if text, ok := value.(string); ok {
			runes := []rune(text)
			a.Offset = min(max(0, a.Offset), len(runes))
			if a.Limit < 1 || a.Limit > 4000 {
				a.Limit = 4000
			}
			end := min(len(runes), a.Offset+a.Limit)
			value = string(runes[a.Offset:end])
			out["total"] = len(runes)
			out["next_offset"] = end
			out["truncated"] = end < len(runes)
		}
		if rows, ok := value.([]any); ok {
			if a.Offset < 0 {
				a.Offset = 0
			}
			a.Offset = min(a.Offset, len(rows))
			if a.Limit < 1 || a.Limit > 30 {
				a.Limit = 10
			}
			end := min(len(rows), a.Offset+a.Limit)
			value = rows[a.Offset:end]
			out["total"] = len(rows)
			out["next_offset"] = end
		}
		b, _ := json.Marshal(value)
		if len(b) > 12000 {
			out["preview"] = string([]rune(string(b))[:min(4000, len([]rune(string(b))))])
			out["truncated"] = true
			out["next"] = "缩小 pointer 或数组页大小；原始证据保留完整"
		} else {
			out["value"] = value
		}
		return reverseJSON(out), nil
	})
}
