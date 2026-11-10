package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBranchModeLookupErrorFailsClosed(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()
	if err := m.pg.Close(); err != nil {
		t.Fatalf("close test database: %v", err)
	}

	task := &Task{ID: "42", Status: "running"}
	m.mu.Lock()
	m.tasks[task.ID] = task
	m.mu.Unlock()
	s := &Server{ctx: context.Background(), m: m, engine: NewEngine(m), chatBusy: map[string]bool{}, chatCancel: map[string]context.CancelCauseFunc{}}

	if !s.isBranchTask(task.ID) {
		t.Fatal("legacy write guard must fail closed when branch lookup fails")
	}
	if s.isBranchTaskForConcurrencySlot(task.ID) {
		t.Fatal("database error must not be treated as confirmed branch mode")
	}
	if !s.engine.BeginDelete(task.ID) {
		t.Fatal("install deletion barrier")
	}
	if !s.occupiesConcurrencySlot(task) {
		t.Fatal("branch lookup error released the local task concurrency slot")
	}
	s.engine.AbortDelete(task.ID, false)

	if _, err := s.admitTask(task, "resume"); err == nil || !strings.Contains(err.Error(), "无法确认任务执行模式") {
		t.Fatalf("task admission should reject branch lookup errors, got %v", err)
	}
	if _, err := s.applyTaskControl(task, "pause"); err == nil || !strings.Contains(err.Error(), "无法确认任务执行模式") {
		t.Fatalf("task control should reject branch lookup errors, got %v", err)
	}

	chatReq := httptest.NewRequest(http.MethodPost, "/api/chat?task=42", strings.NewReader(`{"message":"hello"}`))
	chatRec := httptest.NewRecorder()
	s.chat(chatRec, chatReq)
	if chatRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("chat should reject branch lookup errors, status=%d body=%s", chatRec.Code, chatRec.Body.String())
	}

	guardReq := httptest.NewRequest(http.MethodPost, "/api/tasks/42/intents/1/control", nil)
	guardRec := httptest.NewRecorder()
	if s.guardBranchLegacyMutation(guardRec, guardReq) || guardRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("legacy writer guard should reject branch lookup errors, allowed=%v status=%d body=%s", guardRec.Code == 0, guardRec.Code, guardRec.Body.String())
	}

	// A nil Manager is used by legacy in-memory lifecycle tests and has no
	// persisted branch-mode state to consult.
	if (&Server{}).isBranchTask("42") {
		t.Fatal("nil Manager should retain non-branch in-memory behavior")
	}
}
