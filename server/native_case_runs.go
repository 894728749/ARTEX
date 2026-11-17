package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func nativeRepeat(ctx context.Context, pg *db.DB, task *db.Task, info agent.RunInfo, dir string, c *db.NativeCase, duration, count int) (map[string]any, error) {
	if count < 1 || count > 10 {
		return nil, errors.New("repeats must be 1..10")
	}
	matched := 0
	runs := []map[string]any{}
	for i := 0; i < count; i++ {
		r, e := nativeReplay(ctx, pg, task, info, dir, c, duration)
		if e != nil {
			return map[string]any{"matches": matched, "attempted": len(runs), "requested": count, "runs": runs}, e
		}
		runs = append(runs, r)
		if r["observation"].(map[string]any)["matches_expectation"] == true {
			matched++
		}
	}
	return map[string]any{"matches": matched, "attempted": count, "requested": count, "runs": runs, "case_sha256": c.SHA256}, nil
}

func nativeMinimize(ctx context.Context, pg *db.DB, task *db.Task, info agent.RunInfo, dir string, c *db.NativeCase, duration, maxRuns int) (map[string]any, error) {
	if maxRuns < 3 || maxRuns > 64 {
		return nil, errors.New("max_runs must be 3..64")
	}
	if c.ReplayPlan == nil || c.ReplayPlan.Version != 2 || c.ReplayPlan.Assertion == nil || c.ReplayPlan.Assertion.Type != "stdout_contains_base64" {
		return nil, errors.New("minimize requires a v2 target-output assertion; signal alone is not a stable crash signature")
	}
	if c.IntentID != info.IntentID {
		return nil, errors.New("only the case author may create a minimized version")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	original, e := base64.StdEncoding.Strict().DecodeString(c.InputBase64)
	if e != nil {
		return nil, e
	}
	current := append([]byte(nil), original...)
	attempts := 0
	runs := []map[string]any{}
	limited := false
	trial := func(data []byte) (bool, error) {
		if attempts >= maxRuns || ctx.Err() != nil {
			limited = true
			return false, errors.New("minimization budget exhausted")
		}
		var candidate db.NativeCase
		raw, _ := json.Marshal(c)
		if e := json.Unmarshal(raw, &candidate); e != nil {
			return false, e
		}
		candidate.ID = 0
		candidate.ReplayPlan.ParentCaseID = c.ID
		candidate.InputBase64 = base64.StdEncoding.EncodeToString(data)
		if e := db.ValidateNativeCase(&candidate); e != nil {
			return false, e
		}
		attempts++
		r, e := nativeReplay(ctx, pg, task, info, dir, &candidate, duration)
		if r != nil {
			runs = append(runs, r)
		}
		if e != nil {
			return false, e
		}
		return r["observation"].(map[string]any)["matches_expectation"] == true, nil
	}
	for i := 0; i < 3; i++ {
		ok, e := trial(original)
		if e != nil {
			return nil, e
		}
		if !ok {
			return map[string]any{"reproduced": false, "attempts": attempts, "runs": runs, "reason": "baseline did not match 3/3"}, nil
		}
	}
	granularity := 2
	for len(current) > 0 && !limited {
		chunk := (len(current) + granularity - 1) / granularity
		reduced := false
		for start := 0; start < len(current); start += chunk {
			end := min(start+chunk, len(current))
			candidate := append(append([]byte{}, current[:start]...), current[end:]...)
			ok, e := trial(candidate)
			if e != nil {
				if limited {
					break
				}
				return nil, e
			}
			if ok {
				current = candidate
				granularity = max(2, granularity-1)
				reduced = true
				break
			}
		}
		if !reduced {
			if granularity >= len(current) {
				break
			}
			granularity = min(len(current), granularity*2)
		}
	}
	result := map[string]any{"reproduced": true, "original_case_id": c.ID, "original_bytes": len(original), "minimized_bytes": len(current), "attempts": attempts, "limited": limited, "runs": runs}
	if len(current) < len(original) {
		var candidate db.NativeCase
		raw, _ := json.Marshal(c)
		_ = json.Unmarshal(raw, &candidate)
		candidate.ID = 0
		candidate.ReplayPlan.ParentCaseID = c.ID
		candidate.Title = "Minimized: " + c.Title
		if len(candidate.Title) > 500 {
			candidate.Title = "Minimized native case"
		}
		candidate.InputBase64 = base64.StdEncoding.EncodeToString(current)
		created, e := pg.CreateNativeCase(ctx, candidate)
		if e != nil {
			return nil, e
		}
		result["case"] = created
	}
	return result, nil
}
