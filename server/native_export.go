package server

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/Autumn-27/artex/db"
)

func nativeExport(raw []byte, digest string) ([]byte, error) {
	var canonical any
	if json.Unmarshal(raw, &canonical) != nil {
		return nil, errors.New("invalid native evidence")
	}
	b, _ := json.Marshal(canonical)
	h := sha256.Sum256(b)
	if hex.EncodeToString(h[:]) != digest {
		return nil, errors.New("native snapshot integrity mismatch")
	}
	var snapshot struct {
		Specimen    string                        `json:"specimen_base64"`
		Artifact    struct{ Name, SHA256 string } `json:"artifact"`
		Case        db.NativeCase                 `json:"case"`
		Replay      db.NativeRun                  `json:"replay"`
		Attachments []struct {
			Name, SHA256 string
			Content      string `json:"content_base64"`
		} `json:"attachments"`
		Source []struct {
			SHA256  string
			Content string `json:"content_base64"`
		} `json:"source_evidence"`
	}
	if e := json.Unmarshal(raw, &snapshot); e != nil {
		return nil, e
	}
	var buffer bytes.Buffer
	z := zip.NewWriter(&buffer)
	manifest := map[string]string{}
	add := func(name string, data []byte) error {
		w, e := z.Create(name)
		if e != nil {
			return e
		}
		if _, e = w.Write(data); e != nil {
			return e
		}
		h := sha256.Sum256(data)
		manifest[name] = hex.EncodeToString(h[:])
		return nil
	}
	decode := func(encoded, hash string) ([]byte, error) {
		data, e := base64.StdEncoding.Strict().DecodeString(encoded)
		if e != nil {
			return nil, e
		}
		h := sha256.Sum256(data)
		if hex.EncodeToString(h[:]) != hash {
			return nil, errors.New("evidence member hash mismatch")
		}
		return data, nil
	}
	sample, e := decode(snapshot.Specimen, snapshot.Artifact.SHA256)
	if e != nil {
		return nil, e
	}
	if e = add("specimen.elf", sample); e != nil {
		return nil, e
	}
	input, e := base64.StdEncoding.Strict().DecodeString(snapshot.Case.InputBase64)
	if e != nil {
		return nil, e
	}
	if e = add("input.bin", input); e != nil {
		return nil, e
	}
	for _, a := range snapshot.Attachments {
		data, e := decode(a.Content, a.SHA256)
		if e != nil {
			return nil, e
		}
		if e = add("attachments/"+a.SHA256, data); e != nil {
			return nil, e
		}
	}
	for _, a := range snapshot.Source {
		data, e := decode(a.Content, a.SHA256)
		if e != nil {
			return nil, e
		}
		if e = add("evidence/"+a.SHA256, data); e != nil {
			return nil, e
		}
	}
	plan := snapshot.Case.ReplayPlan
	portable := map[string]any{"argv": snapshot.Case.Argv, "input": "input.bin", "expected_exit": snapshot.Case.ExpectedExit, "expected_signal": snapshot.Case.ExpectedSignal, "case_sha256": snapshot.Case.SHA256, "specimen_sha256": snapshot.Artifact.SHA256}
	if plan != nil {
		portable["input_mode"] = plan.InputMode
		portable["assertion"] = plan.Assertion
		portable["image"] = plan.Image
		if plan.Target != nil {
			target := map[string]any{}
			deps := []map[string]any{}
			for _, v := range plan.Target.Dependencies {
				deps = append(deps, map[string]any{"name": v.Name, "sha256": v.SHA256, "file": "attachments/" + v.SHA256})
			}
			target["dependencies"] = deps
			for kind, v := range map[string]*db.NativeArtifactBinding{"loader": plan.Target.Loader, "harness": plan.Target.Harness} {
				if v != nil {
					target[kind] = map[string]any{"name": v.Name, "sha256": v.SHA256, "file": "attachments/" + v.SHA256}
				}
			}
			portable["target"] = target
		}
	}
	data, _ := json.MarshalIndent(portable, "", "  ")
	if e = add("replay.json", data); e != nil {
		return nil, e
	}
	var obs map[string]any
	_ = json.Unmarshal(snapshot.Replay.Observation, &obs)
	conditions := map[string]any{"target_state": obs["target_state"], "exit_code": obs["exit_code"], "signal": obs["signal"], "signal_source": obs["signal_source"], "matches_expectation": obs["matches_expectation"], "manifest": obs["manifest"], "cleanup": obs["cleanup"], "stderr": obs["stderr"], "target_observation": obs["target_observation"], "output_base64": obs["output_base64"], "output_source": obs["output_source"]}
	data, _ = json.MarshalIndent(conditions, "", "  ")
	if e = add("observation.json", data); e != nil {
		return nil, e
	}
	report := fmt.Sprintf("# Native replay evidence\n\nSpecimen SHA-256: `%s`\n\nCase SHA-256: `%s`\n\nObserved state: `%v`; assertion matched: `%v`.\n\nSee replay.json for exact input, arguments, attachments and assertion; observation.json contains recorded conditions and cleanup.\n\nSignal/exit or an output marker establishes only the stated observation. It does not by itself prove arbitrary code execution.\n", snapshot.Artifact.SHA256, snapshot.Case.SHA256, obs["target_state"], obs["matches_expectation"])
	if e = add("report.md", []byte(report)); e != nil {
		return nil, e
	}
	data, _ = json.MarshalIndent(map[string]any{"snapshot_sha256": digest, "files": manifest}, "", "  ")
	if e = add("manifest.json", data); e != nil {
		return nil, e
	}
	if e = z.Close(); e != nil {
		return nil, e
	}
	return buffer.Bytes(), nil
}

func (s *Server) nativeExportRoute(w http.ResponseWriter, r *http.Request) {
	id, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if e != nil {
		writeErr(w, 400, "invalid finding id")
		return
	}
	var raw []byte
	var digest string
	if e = s.m.pg.QueryRow(`SELECT sha256,snapshot FROM finding_native_evidence WHERE finding_id=$1`, id).Scan(&digest, &raw); e != nil {
		writeErr(w, 404, "native evidence not found")
		return
	}
	data, e := nativeExport(raw, digest)
	if e != nil {
		writeErr(w, 409, e.Error())
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="native-evidence.zip"`)
	w.WriteHeader(200)
	_, _ = w.Write(data)
}
