package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"time"

	"github.com/Autumn-27/artex/db"
)

// Resolve only registered task artifacts. No model-supplied host paths or
// addresses reach the native runner; every executable attachment is granted.
func nativeTarget(pg *db.DB, taskID int64, dir string, p reverseRuntimeProfile, plan *db.NativeReplayPlan) (map[string]any, []int64, error) {
	target := map[string]any{}
	ids := []int64{}
	if plan == nil || plan.Target == nil {
		return target, ids, nil
	}
	if err := plan.Target.Validate(); err != nil {
		return nil, nil, err
	}
	total := int64(0)
	resolve := func(b db.NativeArtifactBinding, kind string) (map[string]any, error) {
		a, e := nativeArtifact(pg, taskID, b.ArtifactID, dir)
		if e != nil {
			return nil, e
		}
		if a.SHA256 != b.SHA256 || a.SizeBytes > 64<<20 {
			return nil, errors.New("native attachment hash or size mismatch")
		}
		total += a.SizeBytes
		if total > 192<<20 {
			return nil, errors.New("native attachment bundle exceeds 192 MiB")
		}
		if kind != "harness" {
			if _, e = inspectNativeELF(a.Path); e != nil {
				return nil, e
			}
		}
		ids = append(ids, a.ID)
		out := map[string]any{"artifact_path": nativeMappedPath(a.Path, p), "sha256": b.SHA256, "name": b.Name}
		if kind == "harness" {
			out["language"] = "python"
		}
		return out, nil
	}
	deps := []map[string]any{}
	for _, b := range plan.Target.Dependencies {
		v, e := resolve(b, "dependency")
		if e != nil {
			return nil, nil, e
		}
		deps = append(deps, v)
	}
	if len(deps) > 0 {
		target["dependencies"] = deps
	}
	for kind, b := range map[string]*db.NativeArtifactBinding{"loader": plan.Target.Loader, "harness": plan.Target.Harness} {
		if b != nil {
			v, e := resolve(*b, kind)
			if e != nil {
				return nil, nil, e
			}
			target[kind] = v
		}
	}
	return target, ids, nil
}

func nativePrepareCase(pg *db.DB, taskID int64, dir string, c *db.NativeCase) error {
	if c.ReplayPlan == nil || c.ReplayPlan.Version != 2 {
		return db.ValidateNativeCase(c)
	}
	p, e := nativeProfile(c.ProfileID)
	if e != nil {
		return e
	}
	a, e := nativeArtifact(pg, taskID, c.ArtifactID, dir)
	if e != nil {
		return e
	}
	policy, e := pg.ReverseRuntimePolicy(taskID)
	if e != nil {
		return e
	}
	plan := c.ReplayPlan
	if plan.ArtifactSHA256 == "" {
		plan.ArtifactSHA256 = a.SHA256
	}
	if plan.Image == "" {
		plan.Image, _ = p.Settings["image"].(string)
	}
	if plan.PolicyRevision == 0 {
		plan.PolicyRevision = policy.Revision
	}
	if plan.ArtifactSHA256 != a.SHA256 || plan.Image != p.Settings["image"] || plan.PolicyRevision != policy.Revision {
		return errors.New("case target, image or policy identity changed")
	}
	if e = db.ValidateNativeCase(c); e != nil {
		return e
	}
	_, _, e = nativeTarget(pg, taskID, dir, p, plan)
	return e
}

func nativeMatch(c *db.NativeCase, o map[string]any) bool {
	exit, sig := c.ReplayExpectations()
	state, _ := o["target_state"].(string)
	code, known := o["exit_code"].(float64)
	if exit != nil {
		return known && state == "exit" && code == float64(*exit)
	}
	if sig != nil {
		return known && state == "crashed" && code == float64(128+*sig)
	}
	if c.ReplayPlan == nil || c.ReplayPlan.Assertion == nil {
		return false
	}
	a := c.ReplayPlan.Assertion
	if a.Type != "stdout_contains_base64" || o["output_source"] != "target_stdout" || (state != "exit" && state != "crashed") {
		return false
	}
	if c.ReplayPlan.Target != nil && c.ReplayPlan.Target.Harness != nil {
		return false
	}
	encoded, _ := o["output_base64"].(string)
	data, e := base64.StdEncoding.Strict().DecodeString(encoded)
	if e != nil {
		return false
	}
	needle, e := base64.StdEncoding.Strict().DecodeString(a.DataBase64)
	return e == nil && len(needle) > 0 && bytes.Contains(data, needle)
}

// Both replay and interactive sessions stop on policy replacement/revocation.
func nativePolicyContext(ctx context.Context, pg *db.DB, taskID, revision int64) (context.Context, context.CancelFunc) {
	child, cancel := context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-child.Done():
				return
			case <-ticker.C:
				policy, e := pg.ReverseRuntimePolicy(taskID)
				if e != nil || !policy.Enabled || policy.Revision != revision {
					cancel()
					return
				}
			}
		}
	}()
	return child, cancel
}
