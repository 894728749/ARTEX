package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateTaskAutoRouteAPI(t *testing.T) {
	t.Run("native reverse draft", func(t *testing.T) {
		m, s := newAutoRouteAPITestServer(t)
		provider := &routeFixtureProvider{text: `{"primary_kind":"reverse","capabilities":["reverse","native"],"reason":"路由测试依据: ELF 样本需要静态行为分析","needs_materials":["ELF 样本"]}`}
		s.llmProv = provider
		description := "auto-route-native-api-test"
		body := map[string]any{"kind": "auto", "description": description, "goal": "分析提供的 ELF 文件", "material_hints": []map[string]any{{"name": "sample.elf", "size": 4096}}}
		encoded, _ := json.Marshal(body)
		req := httptest.NewRequest("POST", "/api/tasks", bytes.NewReader(encoded))
		rec := httptest.NewRecorder()
		s.createTask(rec, req)
		if rec.Code != 201 {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		var response struct {
			Task struct {
				ID     string `json:"id"`
				Kind   string `json:"kind"`
				Paused bool   `json:"paused"`
			} `json:"task"`
			Route taskRouteResult `json:"route"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Task.ID == "" || response.Task.Kind != "reverse" || !response.Task.Paused {
			t.Fatalf("unexpected task response: %#v", response.Task)
		}
		if response.Route.PrimaryKind != "reverse" || response.Route.Reason == "" {
			t.Fatalf("missing route result: %#v", response.Route)
		}
		if provider.calls != 1 {
			t.Fatalf("provider calls=%d, want 1", provider.calls)
		}
		var id int64
		if err := m.pg.QueryRow(`SELECT id FROM tasks WHERE description=$1`, description).Scan(&id); err != nil {
			t.Fatal(err)
		}
		created, err := m.pg.GetTask(id)
		if err != nil {
			t.Fatal(err)
		}
		if created.Kind != "reverse" || !created.Paused {
			t.Fatalf("stored kind=%q paused=%v", created.Kind, created.Paused)
		}
		cfg, err := m.pg.NativeConfig(id)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Mode != "analysis" || cfg.Revision <= 0 {
			t.Fatalf("native config=%#v", cfg)
		}
		policy, err := m.pg.ReverseRuntimePolicy(id)
		if err != nil {
			t.Fatal(err)
		}
		if policy.Enabled {
			t.Fatalf("runtime policy unexpectedly enabled: %#v", policy)
		}
		var hasReason bool
		if err := m.pg.QueryRow(`SELECT EXISTS(SELECT 1 FROM activity WHERE exploration_id=$1 AND detail LIKE $2)`, created.ExplorationID, "%路由测试依据: ELF 样本需要静态行为分析%").Scan(&hasReason); err != nil {
			t.Fatal(err)
		}
		if !hasReason {
			t.Fatal("route reason was not persisted in task activity")
		}
		// Remove only the task created by this test from the isolated test DB.
		if _, err := m.DeleteTask(response.Task.ID, DeleteTaskOptions{}); err != nil {
			t.Errorf("cleanup task: %v", err)
		}
	})

	t.Run("provider failure is retryable and creates no task", func(t *testing.T) {
		m, s := newAutoRouteAPITestServer(t)
		provider := &routeFixtureProvider{err: context.DeadlineExceeded}
		s.llmProv = provider
		description := "auto-route-provider-failure-api-test"
		body, _ := json.Marshal(map[string]any{"kind": "auto", "description": description, "goal": "分析材料"})
		req := httptest.NewRequest("POST", "/api/tasks", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		s.createTask(rec, req)
		if rec.Code != 503 {
			t.Fatalf("status=%d body=%s, want 503", rec.Code, rec.Body.String())
		}
		if provider.calls != 1 {
			t.Fatalf("provider calls=%d, want 1", provider.calls)
		}
		var count int
		if err := m.pg.QueryRow(`SELECT count(*) FROM tasks WHERE description=$1`, description).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("failed routing created %d task(s)", count)
		}
		if strings.TrimSpace(rec.Body.String()) == "" {
			t.Fatal("expected retryable error response")
		}
	})
}

func newAutoRouteAPITestServer(t *testing.T) (*Manager, *Server) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := New(ctx, m, "", t.TempDir(), t.TempDir())
	return m, s
}
