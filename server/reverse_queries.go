package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

func reverseConclusionIndex(c db.ReverseConclusion) map[string]any {
	return map[string]any{"id": c.ID, "question": c.Question, "state": c.State, "intent_id": c.IntentID, "reviewer_intent_id": c.ReviewerIntentID, "node_id": c.NodeID, "created_at": c.CreatedAt, "reviewed_at": c.ReviewedAt}
}

func reverseConclusionReadTools(pg *db.DB, task *db.Task) []actool.CoreTool {
	return []actool.CoreTool{reverseTool("reverse_get_conclusion", "按编号读取本逆向任务已保存结论全文（答案、证据、局限和核验记录）。", reverseObject(map[string]any{"conclusion_id": reverseInt()}, "conclusion_id"), func(_ context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			ID int64 `json:"conclusion_id"`
		}
		if err := json.Unmarshal(in, &a); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		c, err := pg.GetReverseConclusion(task.ID, a.ID)
		if err != nil || c == nil {
			return actool.Errorf("结论不存在"), nil
		}
		return reverseJSON(c), nil
	})}
}

var reverseFacetNames = []string{"summary", "source", "fields", "methods", "references", "matches", "root"}

func reverseEvidenceObject(value any) map[string]any {
	m, _ := reverseEvidenceValue(value).(map[string]any)
	return m
}

func reverseEvidencePick(value any, names ...string) any {
	m := reverseEvidenceObject(value)
	for _, name := range names {
		if v, ok := m[name]; ok && v != nil {
			return reverseEvidenceValue(v)
		}
	}
	return nil
}

func reverseEvidenceSummary(structured, normalized any) any {
	if v := reverseEvidencePick(structured, "summary", "message"); v != nil {
		return v
	}
	if v := reverseEvidencePick(normalized, "summary", "message"); v != nil {
		return v
	}
	analysis := reverseEvidencePick(normalized, "analysis")
	return reverseEvidencePick(analysis, "summary", "message")
}

func reverseReadEvidenceTool(taskID int64, workDir string) actool.CoreTool {
	return reverseTool("reverse_read_evidence", "按规范 facet 读取已保存的 REA 结果。result_path 必须来自本任务的 rea_call；facet 为 summary/source/fields/methods/references/matches/root。数组、文本和对象支持 offset/limit 分页；超大值可回退 reverse_evidence_view 的 JSON Pointer。", reverseObject(map[string]any{"result_path": reverseString(), "facet": map[string]any{"type": "string", "enum": reverseFacetNames}, "offset": reverseInt(), "limit": reverseInt()}, "result_path", "facet"), func(_ context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			Path          string `json:"result_path"`
			Facet         string `json:"facet"`
			Offset, Limit int
		}
		if err := json.Unmarshal(in, &a); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		path, err := reverseLocalPath(workDir, a.Path, filepath.Join("tasks", strconv.FormatInt(taskID, 10), "reverse", "results"))
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		var raw any
		if err = json.Unmarshal(b, &raw); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		root := reverseEvidenceObject(raw)
		structured := map[string]any{}
		mergeStructured := func(v any) {
			m := reverseEvidenceObject(v)
			for _, key := range []string{"structuredContent", "structured_content"} {
				if wrapped := reverseEvidenceObject(m[key]); wrapped != nil {
					for k, x := range wrapped {
						structured[k] = reverseEvidenceValue(x)
					}
				}
			}
			if len(structured) == 0 {
				for k, x := range m {
					structured[k] = reverseEvidenceValue(x)
				}
			}
		}
		mergeStructured(root)
		content := []any{}
		if arr, ok := root["content"].([]any); ok {
			for _, item := range arr {
				if m, ok := item.(map[string]any); ok {
					if s, ok := m["text"].(string); ok {
						var parsed any
						if json.Unmarshal([]byte(s), &parsed) == nil {
							pm := reverseEvidenceObject(parsed)
							if pm != nil && (pm["structuredContent"] != nil || pm["structured_content"] != nil) {
								mergeStructured(pm)
							}
							content = append(content, reverseEvidenceValue(parsed))
						} else {
							content = append(content, s)
						}
					}
				}
			}
		}
		normalized := reverseEvidencePick(structured, "normalized_result", "normalizedResult")
		if normalized == nil && len(content) > 0 {
			normalized = content[0]
		}
		// Normalize text-wrapper providers and Hermes' {derived, analysis:{...}} result.
		if sm := reverseEvidenceObject(normalized); sm != nil && (sm["structuredContent"] != nil || sm["structured_content"] != nil) {
			for _, k := range []string{"structuredContent", "structured_content"} {
				if wrapped := reverseEvidenceObject(sm[k]); wrapped != nil {
					if n := reverseEvidencePick(wrapped, "normalized_result", "normalizedResult"); n != nil {
						normalized = n
					}
				}
			}
		}
		analysis := reverseEvidencePick(normalized, "analysis")
		if analysis == nil {
			analysis = normalized
		}
		rootHash := reverseEvidencePick(structured, "root_artifact_sha256", "root")
		if rootHash == nil {
			rootHash = reverseEvidencePick(normalized, "root_artifact_sha256", "root")
		}
		availableFields := []string{}
		if nm := reverseEvidenceObject(normalized); nm != nil {
			for k := range nm {
				availableFields = append(availableFields, k)
			}
			sort.Strings(availableFields)
		}
		rootSummary := map[string]any{}
		for _, key := range []string{"subject", "provider", "operation", "confidence", "authority", "limitations", "evidence_id"} {
			if v := reverseEvidencePick(structured, key); v != nil {
				rootSummary[key] = v
			}
		}
		if rootHash != nil {
			rootSummary["root_artifact_sha256"] = rootHash
		}
		rootSummary["available_fields"] = availableFields
		facets := map[string]any{}
		facets["summary"] = reverseEvidenceSummary(structured, normalized)
		source := reverseEvidencePick(analysis, "source", "code", "decompiled", "text")
		if sourceMap := reverseEvidenceObject(source); sourceMap != nil {
			if text, ok := sourceMap["text"]; ok {
				source = text
			}
		}
		facets["source"] = source
		facets["fields"] = reverseEvidencePick(analysis, "fields")
		facets["methods"] = reverseEvidencePick(analysis, "methods", "functions")
		facets["references"] = reverseEvidencePick(analysis, "references", "refs", "xrefs")
		facets["matches"] = reverseEvidencePick(analysis, "matches", "results", "items")
		facets["root"] = rootSummary
		available := []string{}
		for _, name := range reverseFacetNames {
			if facets[name] != nil {
				available = append(available, name)
			}
		}
		value, ok := facets[a.Facet]
		if !ok || value == nil {
			return reverseJSON(map[string]any{"error": "facet 不可用", "available_facets": available, "available_fields": availableFields}), nil
		}
		out := map[string]any{"result_path": a.Path, "facet": a.Facet, "available_facets": available, "available_fields": availableFields, "value": value}
		if text, ok := value.(string); ok {
			r := []rune(text)
			a.Offset = max(0, min(a.Offset, len(r)))
			if a.Limit < 1 || a.Limit > 3000 {
				a.Limit = 1000
			}
			end := min(len(r), a.Offset+a.Limit)
			out["value"] = string(r[a.Offset:end])
			out["total"] = len(r)
			out["next_offset"] = end
			out["truncated"] = end < len(r)
		}
		if rows, ok := value.([]any); ok {
			a.Offset = max(0, min(a.Offset, len(rows)))
			if a.Limit < 1 || a.Limit > 30 {
				a.Limit = 10
			}
			end := min(len(rows), a.Offset+a.Limit)
			out["value"] = rows[a.Offset:end]
			out["total"] = len(rows)
			out["next_offset"] = end
			out["truncated"] = end < len(rows)
		}
		if object, ok := value.(map[string]any); ok {
			keys := make([]string, 0, len(object))
			for k := range object {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			a.Offset = max(0, min(a.Offset, len(keys)))
			if a.Limit < 1 || a.Limit > 30 {
				a.Limit = 10
			}
			end := min(len(keys), a.Offset+a.Limit)
			page := map[string]any{}
			for _, k := range keys[a.Offset:end] {
				page[k] = object[k]
			}
			out["value"] = page
			out["total"] = len(keys)
			out["next_offset"] = end
			out["truncated"] = end < len(keys)
		}
		encoded, _ := json.Marshal(out)
		if len(encoded) > 12000 {
			out["value"] = "结果仍超过12KB；使用 reverse_evidence_view 按 JSON Pointer 读取并分页"
			out["truncated"] = true
			out["fallback_tool"] = "reverse_evidence_view"
			out["fallback_pointer"] = "/structuredContent/normalized_result"
		}
		return reverseJSON(out), nil
	})
}
