package server

import (
	"context"
	"encoding/json"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

func nativeReviewTool(pg *db.DB, task *db.Task, info agent.RunInfo, dir string) actool.CoreTool {
	return reverseTool("native_review", "独立审核者将结论绑定到精确案例哈希和新鲜重放。必须先 replay/repeat；旧版本或策略变化后需要新案例与新审核。", reverseObject(map[string]any{"conclusion_id": reverseInt(), "case_id": reverseInt(), "run_id": reverseInt(), "review": reverseString()}, "conclusion_id", "case_id", "run_id", "review"), func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
		var r struct {
			ConclusionID int64  `json:"conclusion_id"`
			CaseID       int64  `json:"case_id"`
			RunID        int64  `json:"run_id"`
			Review       string `json:"review"`
		}
		if e := json.Unmarshal(raw, &r); e != nil {
			return actool.Errorf(e.Error()), nil
		}
		c, e := pg.NativeCase(task.ID, r.CaseID)
		if e != nil {
			return actool.Errorf(e.Error()), nil
		}
		if e = nativePrepareCase(pg, task.ID, dir, c); e != nil {
			return actool.Errorf(e.Error()), nil
		}
		o, e := pg.AcceptNativeReview(ctx, task.ID, r.ConclusionID, r.CaseID, r.RunID, info.IntentID, r.Review)
		if e != nil {
			return actool.Errorf(e.Error()), nil
		}
		return actool.Text(string(o)), nil
	})
}
