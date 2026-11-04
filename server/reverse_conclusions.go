package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// reverseLocalPath rejects relocated/unrelated and symlink-escaped references.
// The stored relative path remains portable with the task's workspace archive.
func reverseLocalPath(workDir, relative, requiredPrefix string) (string, error) {
	if filepath.IsAbs(relative) {
		return "", errors.New("证据路径必须相对任务工作空间")
	}
	root, err := filepath.Abs(filepath.Join(workDir, requiredPrefix))
	if err != nil {
		return "", err
	}
	path, err := filepath.Abs(filepath.Join(workDir, relative))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("证据不属于本逆向任务")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	rel, err = filepath.Rel(resolvedRoot, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("证据符号链接超出任务目录")
	}
	return resolved, nil
}

func reverseEvidenceCheck(pg *db.DB, taskID int64, workDir string, refs []db.ReverseEvidence) error {
	if len(refs) == 0 {
		return errors.New("结论至少需要一条工件定位证据")
	}
	prefix := filepath.Join("tasks", strconv.FormatInt(taskID, 10), "reverse")
	for _, ref := range refs {
		if strings.TrimSpace(ref.Locator) == "" || strings.TrimSpace(ref.Observation) == "" {
			return errors.New("证据必须写明定位和直接观察")
		}
		a, err := pg.GetReverseArtifact(taskID, ref.ArtifactID)
		if err != nil {
			return err
		}
		if a == nil {
			return errors.New("证据工件不存在")
		}
		path, err := reverseLocalPath(workDir, a.Path, filepath.Join(prefix, "artifacts"))
		if err != nil {
			return err
		}
		a.Path = path
		if err := verifyArtifact(a); err != nil {
			return err
		}
		if ref.ResultPath != "" {
			path, err := reverseLocalPath(workDir, ref.ResultPath, filepath.Join(prefix, "results"))
			if err != nil {
				return err
			}
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			var result struct {
				IsError bool `json:"isError"`
			}
			err = json.NewDecoder(f).Decode(&result)
			_ = f.Close()
			if err != nil || result.IsError {
				return errors.New("引用的 REA 结果不是有效成功证据；错误应作为局限/未决项保存")
			}
		}
	}
	return nil
}

func reverseConclusionTools(pg *db.DB, task *db.Task, info agent.RunInfo, workDir string) []actool.CoreTool {
	evidenceSchema := map[string]any{"type": "array", "items": reverseObject(map[string]any{"artifact_id": reverseInt(), "locator": reverseString(), "observation": reverseString(), "result_path": reverseString()}, "artifact_id", "locator", "observation")}
	return []actool.CoreTool{
		reverseTool("reverse_submit_conclusion", "提交候选解释（proposed），保留问题、答案、工件定位证据和局限。此操作不是核验完成；返回提交事实可用于本工作单完成，不能证明任务目标。", reverseObject(map[string]any{"question": reverseString(), "answer": reverseString(), "evidence": evidenceSchema, "limitations": reverseString()}, "question", "answer", "evidence", "limitations"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Question, Answer, Limitations string
				Evidence                      []db.ReverseEvidence
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if err := reverseEvidenceCheck(pg, task.ID, workDir, a.Evidence); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			c, err := pg.CreateReverseConclusion(task.ID, db.ReverseConclusionInput{IntentID: info.IntentID, Question: a.Question, Answer: a.Answer, Evidence: a.Evidence, Limitations: a.Limitations})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			store := pg.Exploration(task.ExplorationID)
			node, err := store.AddNode(db.KindFact, map[string]any{"summary": fmt.Sprintf("逆向候选结论 #%d 已提交，等待独立核验：%s", c.ID, c.Question), "evidence": fmt.Sprintf("reverse_conclusions #%d state=proposed；这只证明提交动作，未证明答案成立。", c.ID), "confidence": "observed", "reverse_receipt_id": c.ID}, 5, "confirmed", "reverse-analysis", nil)
			if err != nil {
				return actool.Errorf("结论已保存，但提交事实写入失败：" + err.Error()), nil
			}
			_ = store.Link(node, db.RelDerivedFrom, info.IntentID)
			n, _ := store.GetNode(node)
			return reverseJSON(map[string]any{"conclusion": c, "receipt_node": n, "next": "由另一条工作单读取材料与原始证据，然后 reverse_review_conclusion；本工作单用 receipt_node 完成，不作为用户目标证据。"}), nil
		}),
		reverseTool("reverse_review_conclusion", "另一条核验工作单重读材料与证据后作出接受/驳回/未解决判定。必须不同于分析意图。accepted 会创建有持久定位的结论事实，供 Planner 逐项目标验收。", reverseObject(map[string]any{"conclusion_id": reverseInt(), "state": map[string]any{"type": "string", "enum": []string{"accepted", "rejected", "unresolved"}}, "review": reverseString()}, "conclusion_id", "state", "review"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ID            int64 `json:"conclusion_id"`
				State, Review string
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			c, err := pg.GetReverseConclusion(task.ID, a.ID)
			if err != nil || c == nil {
				return actool.Errorf("结论不存在"), nil
			}
			if a.State == "accepted" {
				if err := reverseEvidenceCheck(pg, task.ID, workDir, c.Evidence); err != nil {
					return actool.Errorf(err.Error()), nil
				}
			}
			// Recover a review whose process stopped after persisting the verdict
			// but before creating the graph evidence. Completed reviews are immutable.
			if c.State != "proposed" {
				if c.NodeID != nil || c.ReviewerIntentID == nil || *c.ReviewerIntentID != info.IntentID || c.State != a.State {
					return actool.Errorf("结论已完成核验；请引用既有结论或提交新的解释"), nil
				}
			} else {
				c, err = pg.ReviewReverseConclusion(task.ID, a.ID, info.IntentID, a.State, a.Review)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
			}
			if c == nil {
				return actool.Errorf("结论不存在"), nil
			}
			ev, _ := json.Marshal(map[string]any{"question": c.Question, "answer": c.Answer, "state": c.State, "evidence": c.Evidence, "limitations": c.Limitations, "review": c.Review})
			payload := map[string]any{"summary": fmt.Sprintf("逆向结论 #%d [%s]：%s", c.ID, c.State, c.Answer), "evidence": string(ev), "confidence": "observed", "reverse_conclusion_id": c.ID, "reverse_state": c.State}
			store := pg.Exploration(task.ExplorationID)
			node, err := store.AddNode(db.KindFact, payload, 5, "confirmed", "reverse-review", nil)
			if err != nil {
				return actool.Errorf("核验已保存，但结论事实写入失败：" + err.Error()), nil
			}
			if err := pg.SetReverseConclusionNode(task.ID, c.ID, node); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			_ = store.Link(node, db.RelDerivedFrom, info.IntentID)
			n, _ := store.GetNode(node)
			return reverseJSON(map[string]any{"conclusion": c, "evidence_node": n}), nil
		}),
	}
}
