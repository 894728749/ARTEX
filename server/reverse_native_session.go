package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// Ownership is bound to one worker invocation, not a user supplied session ID.
type nativeSessionManager struct {
	ctx      context.Context
	pg       *db.DB
	task     *db.Task
	info     agent.RunInfo
	dir      string
	mu       sync.Mutex
	sessions map[string]*nativeSession
	closed   bool
}
type nativeSession struct {
	mu       sync.Mutex
	writeMu  sync.Mutex
	id       string
	runID    int64
	artifact *db.ReverseArtifact
	cmd      *exec.Cmd
	in       io.WriteCloser
	done     chan struct{}
	frames   []reverseSessionFrame
	bytes    int
	pending  map[string]chan reverseSessionFrame
	last     map[string]any
	fail     string
}

func (n *nativeSession) write(frame any) error {
	n.writeMu.Lock()
	defer n.writeMu.Unlock()
	return json.NewEncoder(n.in).Encode(frame)
}
func (n *nativeSession) request(ctx context.Context, id string, frame map[string]any) (map[string]any, error) {
	ch := make(chan reverseSessionFrame, 1)
	n.mu.Lock()
	if _, ok := n.pending[id]; ok {
		n.mu.Unlock()
		return nil, errors.New("request_id 已在处理中")
	}
	n.pending[id] = ch
	n.mu.Unlock()
	defer func() { n.mu.Lock(); delete(n.pending, id); n.mu.Unlock() }()
	frame["request_id"] = id
	if e := n.write(frame); e != nil {
		return nil, e
	}
	select {
	case f := <-ch:
		if msg, ok := f.Observation["error"].(string); ok {
			return f.Observation, errors.New(msg)
		}
		return f.Observation, nil
	case <-n.done:
		n.mu.Lock()
		defer n.mu.Unlock()
		if n.fail != "" {
			return n.last, errors.New(n.fail)
		}
		return n.last, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (n *nativeSession) stop() {
	select {
	case <-n.done:
		return
	default:
	}
	_ = n.write(map[string]any{"request_id": "owner-stop", "action": "stop"})
	_ = n.in.Close()
	select {
	case <-n.done:
	case <-time.After(10 * time.Second):
		_ = n.cmd.Process.Kill()
		<-n.done
	}
}
func (m *nativeSessionManager) close() {
	m.mu.Lock()
	m.closed = true
	all := make([]*nativeSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		all = append(all, s)
	}
	m.mu.Unlock()
	for _, s := range all {
		s.stop()
	}
}
func (m *nativeSessionManager) start(ctx context.Context, artifactID int64, profileID, mode string, argv []string, duration int) (map[string]any, error) {
	return m.startPlan(ctx, artifactID, profileID, mode, argv, duration, nil, "")
}
func (m *nativeSessionManager) startPlan(ctx context.Context, artifactID int64, profileID, mode string, argv []string, duration int, plan *db.NativeReplayPlan, input string) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || len(m.sessions) >= 4 {
		return nil, errors.New("当前工作单会话已关闭或达到 4 个上限")
	}
	if mode != "exec" && mode != "debug" {
		return nil, errors.New("mode must be exec or debug")
	}
	// An omitted argv is an empty argument list, never JSON null. The native
	// runner deliberately requires an array even when no arguments are passed.
	if argv == nil {
		argv = []string{}
	}
	if len(argv) > 64 {
		return nil, errors.New("argv exceeds limit")
	}
	for _, s := range argv {
		if len(s) > 4096 {
			return nil, errors.New("argv exceeds limit")
		}
	}
	a, e := nativeArtifact(m.pg, m.task.ID, artifactID, m.dir)
	if e != nil {
		return nil, e
	}
	if _, e = inspectNativeELF(a.Path); e != nil {
		return nil, e
	}
	p, e := nativeProfile(profileID)
	if e != nil {
		return nil, e
	}
	policy, e := m.pg.ReverseRuntimePolicy(m.task.ID)
	if e != nil {
		return nil, e
	}
	if plan != nil {
		if plan.Assertion != nil {
			return nil, errors.New("session plan must not include a replay assertion")
		}
		zero := 0
		c := db.NativeCase{ArtifactID: artifactID, ProfileID: profileID, Title: "session", Argv: argv, InputBase64: input, ExpectedExit: &zero, ReplayPlan: plan}
		if e = nativePrepareCase(m.pg, m.task.ID, m.dir, &c); e != nil {
			return nil, e
		}
	}
	if mode == "debug" && plan != nil && plan.Target != nil && plan.Target.Harness != nil {
		return nil, errors.New("harness is exec-only")
	}
	target, attachments, e := nativeTarget(m.pg, m.task.ID, m.dir, p, plan)
	if e != nil {
		return nil, e
	}
	cfg, e := m.pg.NativeConfig(m.task.ID)
	if e != nil {
		return nil, e
	}
	runID, e := m.pg.BeginNativeRuntimeRun(ctx, m.task.ID, a.ID, m.info.IntentID, p.ID, duration, attachments, policy.Revision)
	if e != nil {
		return nil, e
	}
	failRun := func(e error) (map[string]any, error) {
		_ = m.pg.FinishReverseRuntimeRun(runID, "failed", "", e.Error())
		raw, _ := json.Marshal(map[string]any{"error": e.Error()})
		_ = m.pg.FinishNativeRun(runID, "failed", "", raw)
		return nil, e
	}
	if e = m.pg.BeginNativeRun(ctx, db.NativeRun{RunID: runID, TaskID: m.task.ID, ArtifactID: a.ID, IntentID: m.info.IntentID, ConfigRevision: cfg.Revision, Mode: mode}); e != nil {
		return failRun(e)
	}
	cmd := exec.Command(p.Command, p.Args...)
	cmd.Stderr = io.Discard
	in, e := cmd.StdinPipe()
	if e != nil {
		return failRun(e)
	}
	out, e := cmd.StdoutPipe()
	if e != nil {
		in.Close()
		return failRun(e)
	}
	if e = cmd.Start(); e != nil {
		in.Close()
		return failRun(errors.New("native runner failed to start"))
	}
	s := &nativeSession{id: fmt.Sprintf("native-%d", runID), runID: runID, artifact: a, cmd: cmd, in: in, done: make(chan struct{}), pending: map[string]chan reverseSessionFrame{}}
	m.sessions[s.id] = s
	go m.read(s, out)
	go func() {
		policyCtx, cancel := nativePolicyContext(m.ctx, m.pg, m.task.ID, policy.Revision)
		defer cancel()
		timer := time.NewTimer(time.Duration(duration)*time.Millisecond + 30*time.Second)
		defer timer.Stop()
		heartbeat := time.NewTicker(5 * time.Second)
		defer heartbeat.Stop()
		seq := 0
		for {
			select {
			case <-s.done:
				return
			case <-policyCtx.Done():
				s.stop()
				return
			case <-timer.C:
				s.stop()
				return
			case <-heartbeat.C:
				seq++
				if e := s.write(map[string]any{"request_id": fmt.Sprintf("owner-heartbeat-%d", seq), "action": "heartbeat"}); e != nil {
					return
				}
			}
		}
	}()
	readyCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	inputMode := "stdin"
	if plan != nil {
		inputMode = plan.InputMode
	}
	o, e := s.request(readyCtx, "start", map[string]any{"operation": "session", "artifact_path": nativeMappedPath(a.Path, p), "sha256": a.SHA256, "argv": argv, "mode": mode, "duration_ms": duration, "profile": p.Settings, "target": target, "input_mode": inputMode, "input_base64": input, "lease_ms": 30000})
	if e != nil {
		s.stop()
		return nil, e
	}
	if o["engine"] != "docker-native" || o["platform"] != "linux/x86_64" || o["artifact_sha256"] != a.SHA256 || o["protocol_version"] != float64(1) {
		s.stop()
		return nil, errors.New("native ready identity mismatch")
	}
	return map[string]any{"session_id": s.id, "run_id": runID, "observation": o}, nil
}
func (m *nativeSessionManager) read(s *nativeSession, out io.Reader) {
	defer close(s.done)
	scan := bufio.NewScanner(out)
	scan.Buffer(make([]byte, 4096), 2<<20)
	var final map[string]any
	failure := ""
	for scan.Scan() {
		raw := scan.Bytes()
		var f reverseSessionFrame
		if json.Unmarshal(raw, &f) != nil || f.Observation == nil || (f.Kind != "ready" && f.Kind != "result" && f.Kind != "final" && f.Kind != "event") {
			failure = "invalid native protocol frame"
			break
		}
		s.mu.Lock()
		s.bytes += len(raw)
		if s.bytes > 3<<20 {
			s.mu.Unlock()
			failure = "native evidence limit exceeded"
			break
		}
		s.frames = append(s.frames, f)
		ch := s.pending[f.RequestID]
		s.mu.Unlock()
		if ch != nil {
			select {
			case ch <- f:
			default:
			}
		}
		if f.Kind == "final" {
			final = f.Observation
			break
		}
	}
	if failure == "" && scan.Err() != nil {
		failure = "native protocol stream interrupted"
	}
	if final == nil && failure == "" {
		failure = "native final cleanup evidence missing"
	}
	_ = s.in.Close()
	kill := time.AfterFunc(10*time.Second, func() { _ = s.cmd.Process.Kill() })
	waitErr := s.cmd.Wait()
	kill.Stop()
	if final == nil {
		final = map[string]any{"target_state": "failed", "errors": []string{failure}}
	}
	if e := nativeObservationError(final, s.artifact.SHA256); e != nil && failure == "" {
		failure = e.Error()
	}
	if waitErr != nil && failure == "" && final["target_state"] != "timeout" {
		failure = "native runner exited with an error"
	}
	path, e := nativeSaveEvidence(m.dir, m.task.ID, s.artifact, "native_session", final, s.frames)
	if e != nil {
		failure = "native evidence could not be saved"
	}
	state, _ := final["target_state"].(string)
	raw, _ := json.Marshal(final)
	if e = m.pg.FinishNativeRun(s.runID, state, path, raw); e != nil {
		failure = "native run evidence could not be recorded"
	}
	status := "completed"
	if state == "cancelled" {
		status = "cancelled"
	}
	if failure != "" || (state != "exit" && state != "crashed" && state != "cancelled") {
		status = "failed"
	}
	if e = m.pg.FinishReverseRuntimeRun(s.runID, status, path, failure); e != nil {
		failure = "runtime outcome could not be recorded"
	}
	s.mu.Lock()
	s.last = map[string]any{"run_id": s.runID, "result_path": path, "observation": final}
	s.fail = failure
	s.mu.Unlock()
}
func (m *nativeSessionManager) tool() actool.CoreTool {
	return reverseTool("native_session", "建立当前工作单私有 Linux 容器会话。start(mode=exec/debug)，可选 replay_plan v2 绑定已登记材料；会话计划不含 assertion。exec 支持 base64 send/recv/close_stdin；debug 使用类型化 GDB/MI。core/core_read 导出有界快照；status/stop 管理会话。", reverseObject(map[string]any{"action": reverseString(), "session_id": reverseString(), "request_id": reverseString(), "artifact_id": reverseInt(), "profile_id": reverseString(), "mode": reverseString(), "argv": map[string]any{"type": "array", "items": reverseString()}, "duration_ms": reverseInt(), "data_base64": reverseString(), "max_bytes": reverseInt(), "timeout_ms": reverseInt(), "command": map[string]any{"type": "object"}, "replay_plan": nativeReplayPlanSchema(), "input_base64": reverseString(), "stream": reverseString(), "offset": reverseInt(), "length": reverseInt()}, "action"), func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
		var r struct {
			Action      string               `json:"action"`
			SessionID   string               `json:"session_id"`
			RequestID   string               `json:"request_id"`
			ArtifactID  int64                `json:"artifact_id"`
			ProfileID   string               `json:"profile_id"`
			Mode        string               `json:"mode"`
			Argv        []string             `json:"argv"`
			Duration    int                  `json:"duration_ms"`
			ReplayPlan  *db.NativeReplayPlan `json:"replay_plan"`
			InputBase64 string               `json:"input_base64"`
			DataBase64  string               `json:"data_base64"`
			MaxBytes    int                  `json:"max_bytes"`
			TimeoutMS   int                  `json:"timeout_ms"`
			Command     json.RawMessage      `json:"command"`
			Stream      string               `json:"stream"`
			Offset      int64                `json:"offset"`
			Length      int                  `json:"length"`
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if e := dec.Decode(&r); e != nil {
			return actool.Errorf(e.Error()), nil
		}
		if r.Action == "start" {
			if r.Mode == "" {
				r.Mode = "exec"
			}
			if r.Duration == 0 {
				r.Duration = 30000
			}
			o, e := m.startPlan(ctx, r.ArtifactID, r.ProfileID, r.Mode, r.Argv, r.Duration, r.ReplayPlan, r.InputBase64)
			if e != nil {
				return actool.Errorf(e.Error()), nil
			}
			return reverseJSON(o), nil
		}
		m.mu.Lock()
		s := m.sessions[r.SessionID]
		m.mu.Unlock()
		if s == nil {
			return actool.Errorf("会话不属于当前工作单"), nil
		}
		if r.Action == "stop" {
			s.stop()
			s.mu.Lock()
			defer s.mu.Unlock()
			return reverseJSON(s.last), nil
		}
		if r.Action == "status" {
			select {
			case <-s.done:
				s.mu.Lock()
				defer s.mu.Unlock()
				return reverseJSON(s.last), nil
			default:
			}
		}
		if r.RequestID == "" || len(r.RequestID) > 128 || r.RequestID == "start" || r.RequestID == "owner-stop" {
			return actool.Errorf("需要唯一的 1–128 字符 request_id"), nil
		}
		var frame map[string]any
		_ = json.Unmarshal(raw, &frame)
		callCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
		defer cancel()
		o, e := s.request(callCtx, r.RequestID, frame)
		if e != nil {
			return actool.Errorf(e.Error()), nil
		}
		return reverseJSON(o), nil
	})
}
