package server

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// teamTaskNative adapts the existing read-only task API handlers to a shared
// task. The path is data, never dispatched through a client-controlled URL.
func (s *Server) teamTaskNative(w http.ResponseWriter, r *http.Request) {
	_, _, task, ok := s.teamTaskScope(w, r, "read")
	if !ok {
		return
	}
	outerQ := r.URL.Query()
	paths := outerQ["path"]
	path := ""
	if len(paths) == 1 {
		path = paths[0]
	}
	if path == "" || strings.HasPrefix(path, "//") || strings.Contains(path, "://") || strings.Contains(path, "#") || strings.Contains(path, "\\") {
		writeErr(w, 400, "invalid native path")
		return
	}
	if strings.HasPrefix(path, "/") {
		path = strings.TrimPrefix(path, "/")
	}
	u, err := url.ParseRequestURI("/" + path)
	if err != nil || u.IsAbs() || u.Host != "" || u.Fragment != "" || u.Opaque != "" {
		writeErr(w, 400, "invalid native path")
		return
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	for _, part := range parts {
		if part == "." || part == ".." {
			writeErr(w, 400, "invalid native path")
			return
		}
	}
	tid := strconv.FormatInt(task.ID, 10)
	query := u.Query()
	for _, key := range []string{"task", "task_id", "context_task"} {
		for _, value := range query[key] {
			if value != "" && value != tid {
				writeErr(w, 403, "native query task does not match shared task")
				return
			}
		}
		if query.Has(key) {
			query.Set(key, tid)
		}
	}
	query.Set("task", tid)
	if len(parts) > 0 && parts[0] == "assets" {
		query.Set("task_id", tid)
	}
	var handler http.HandlerFunc
	values := map[string]string{}
	deny := func() { writeErr(w, 404, "native endpoint is not available for shared tasks") }
	if len(parts) == 2 && parts[0] == "exploration" {
		switch parts[1] {
		case "graph":
			handler = s.explorationGraph
		case "nodes":
			handler = s.explorationNodes
		case "intents":
			handler = s.intents
		case "frontier":
			handler = s.frontier
		case "findings":
			handler = s.findings
		case "tokens":
			handler = s.tokenStats
		default:
			deny()
			return
		}
	} else if len(parts) == 2 && parts[0] == "tokens" && parts[1] == "conversations" {
		handler = s.conversationTokens
	} else if len(parts) == 3 && parts[0] == "llm" && parts[1] == "records" && parts[2] == "by-model" {
		handler = s.pgTokenByModel
	} else if len(parts) == 1 && parts[0] == "stats" {
		// stats() includes process-wide traffic and asset totals. Keep its native
		// response shape, but produce only task-scoped fields here.
		s.teamTaskNativeStats(w, r, task)
		return
	} else if len(parts) == 1 && parts[0] == "report" {
		handler = s.getReport
	} else if len(parts) == 2 && parts[0] == "assets" && parts[1] == "counts" {
		handler = s.assetCounts
	} else if len(parts) == 1 && parts[0] == "assets" {
		handler = s.listAssets
	} else if len(parts) >= 2 && parts[0] == "tasks" {
		if parts[1] != tid {
			writeErr(w, 403, "native path task does not match shared task")
			return
		}
		if len(parts) == 2 {
			handler = s.getTask
		} else if len(parts) == 6 && parts[2] == "reverse" && parts[3] == "artifacts" && parts[5] == "download" {
			if task.Kind != "reverse" {
				deny()
				return
			}
			values["id"], values["aid"] = tid, parts[4]
			handler = s.reverseArtifactDownload
		} else {
			switch strings.Join(parts[2:], "/") {
			case "llm/resolution":
				handler = s.taskLLMResolutionHandler
			case "coverage":
				handler = s.taskCoverage
			case "coverage-graph":
				handler = s.taskCoverageGraph
			case "asset-refs":
				handler = s.taskAssetRefs
			case "intent-assets":
				handler = s.taskIntentAssets
			case "scope":
				handler = s.taskScopeList
			case "goals":
				handler = s.listGoals
			case "constraints":
				handler = s.listConstraints
			case "finding-relations":
				handler = s.teamNativeFindingRelations
			case "finding-review-status":
				handler = s.teamNativeFindingReviewStatus
			case "intercept-rules":
				handler = s.taskInterceptListRules
			case "reverse/artifacts":
				if task.Kind != "reverse" {
					deny()
					return
				}
				handler = s.reverseArtifactList
			case "reverse/conclusions":
				if task.Kind != "reverse" {
					deny()
					return
				}
				handler = s.reverseConclusionList
			case "reverse/native":
				if task.Kind != "reverse" {
					deny()
					return
				}
				handler = s.nativeState
			case "reverse/runtime":
				if task.Kind != "reverse" {
					deny()
					return
				}
				handler = s.teamNativeReverseRuntime
			case "reverse/report":
				if task.Kind != "reverse" {
					deny()
					return
				}
				handler = s.reverseReport
			case "workflow-requests":
				handler = s.teamNativeWorkflowRequests
			default:
				deny()
				return
			}
		}
		values["id"] = tid
	} else if len(parts) == 3 && parts[0] == "intercept" && parts[1] == "task" {
		if parts[2] != tid {
			writeErr(w, 403, "native path task does not match shared task")
			return
		}
		values["taskID"] = tid
		handler = func(w http.ResponseWriter, r *http.Request) { s.interceptTaskItems(w, r, true) }
	} else if len(parts) == 3 && parts[0] == "intercept" && parts[1] == "history" {
		// Detail is allowed only after proving that the approval belongs to this task.
		values["id"] = parts[2]
		if !s.teamNativeInterceptBelongs(w, r, task.ID, parts[2]) {
			return
		}
		handler = s.teamNativeInterceptDetail
	} else if len(parts) >= 3 && parts[0] == "exploration" && parts[1] == "findings" {
		fid := parts[2]
		if !s.teamNativeFindingBelongs(w, r, task.ID, fid) {
			return
		}
		values["id"] = fid
		switch {
		case len(parts) == 3:
			handler = s.teamNativeGetFinding
			query.Set("context_task", tid)
		case len(parts) == 4 && parts[3] == "retests":
			handler = s.listFindingRetests
		case len(parts) == 4 && parts[3] == "lineage":
			handler = s.findingLineage
		case len(parts) == 4 && parts[3] == "traffic":
			handler = s.getFindingTraffic
		case len(parts) == 5 && parts[3] == "traffic":
			values["binding_id"] = parts[4]
			handler = s.getFindingTrafficDetail
		case len(parts) == 6 && parts[3] == "traffic" && parts[5] == "body":
			values["binding_id"] = parts[4]
			handler = s.getFindingTrafficBody
		default:
			deny()
			return
		}
		if len(parts) > 3 {
			query.Del("context_task")
		}
	} else {
		deny()
		return
	}
	if len(parts) == 2 && parts[0] == "exploration" && parts[1] == "findings" && (query.Has("page") || query.Has("limit")) {
		// The native paginated task view uses the independent findings table; the
		// legacy task= branch intentionally returns a bare exploration-node array.
		query.Del("task")
		query.Set("task_id", tid)
	}
	if handler == nil {
		deny()
		return
	}
	clone := r.Clone(r.Context())
	clone.URL = &url.URL{Path: "/api/" + strings.Join(parts, "/"), RawQuery: query.Encode()}
	clone = clone.WithContext(clone.Context())
	for key, value := range values {
		clone.SetPathValue(key, value)
	}
	handler(w, clone)
}

func (s *Server) teamNativeGetFinding(w http.ResponseWriter, r *http.Request) {
	id, ok := positivePathID(w, r, "id")
	if !ok {
		return
	}
	taskID, err := strconv.ParseInt(r.URL.Query().Get("context_task"), 10, 64)
	if err != nil || taskID <= 0 {
		writeErr(w, 400, "context task required")
		return
	}
	f, err := s.m.pg.TeamTaskFinding(r.Context(), taskID, id)
	if err != nil {
		writeErr(w, 404, "finding not available in shared task")
		return
	}
	assets := s.resolveAssetIDs(f.AssetIDs)
	dto := findingFromDB(f, assets)
	if f.TaskID != nil && *f.TaskID != taskID {
		dto.SourceTaskID = i64s(*f.TaskID)
		dto.Inherited = true
	}
	writeJSON(w, 200, dto)
}

func positivePathID(w http.ResponseWriter, r *http.Request, key string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue(key), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "bad id")
		return 0, false
	}
	return id, true
}

func (s *Server) teamNativeFindingBelongs(w http.ResponseWriter, r *http.Request, taskID int64, raw string) bool {
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "bad finding id")
		return false
	}
	_, err = s.m.pg.TeamTaskFinding(r.Context(), taskID, id)
	if err != nil {
		writeErr(w, 404, "finding not available in shared task")
		return false
	}
	return true
}

func (s *Server) teamNativeInterceptBelongs(w http.ResponseWriter, r *http.Request, taskID int64, raw string) bool {
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "bad approval id")
		return false
	}
	items, err := s.m.pg.ListTaskIntercepts(strconv.FormatInt(taskID, 10))
	if err != nil {
		writeErr(w, 500, err.Error())
		return false
	}
	for _, item := range items {
		if strconv.FormatInt(item.ID, 10) == raw {
			return true
		}
	}
	writeErr(w, 404, "approval not found for shared task")
	return false
}

func (s *Server) teamNativeInterceptDetail(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad approval id")
		return
	}
	detail, err := s.m.pg.GetInterceptDetail(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if detail == nil {
		writeErr(w, 404, "not found")
		return
	}
	detail.ToolInput = nil
	if detail.Audit != nil {
		detail.Audit.ModelInput = nil
		detail.Audit.Output = ""
	}
	writeJSON(w, 200, detail)
}

// These small adapters keep the original response DTOs while avoiding handlers
// that require a loaded in-memory task or resolve an implicit active task.
func (s *Server) teamNativeFindingRelations(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	nodes, edges, err := s.m.pg.FindingGraph(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"nodes": nodes, "edges": edges})
}

func (s *Server) teamNativeFindingReviewStatus(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	out, err := s.m.pg.FindingReviewStatus(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) teamNativeReverseRuntime(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	policy, err := s.m.pg.ReverseRuntimePolicy(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	runs, err := s.m.pg.ListReverseRuntimeRuns(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"policy": policy, "runs": runs})
}

func (s *Server) teamNativeWorkflowRequests(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	items, err := s.m.pg.ListWorkflowRequests(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, items)
}

func (s *Server) teamTaskNativeStats(w http.ResponseWriter, r *http.Request, task *db.Task) {
	id := strconv.FormatInt(task.ID, 10)
	live, loaded := s.m.Task(id)
	if !loaded {
		writeErr(w, 404, "task not found")
		return
	}
	stats, err := live.Store.Stats()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	intents, err := live.Store.ListByKind(db.KindIntent, 100000)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	inFlight := 0
	for _, item := range intents {
		if item.State == "running" {
			inFlight++
		}
	}
	goals, err := live.Store.ListByKind(db.KindGoal, 10000)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	goalsMet := 0
	for _, goal := range goals {
		if goal.State == "met" {
			goalsMet++
		}
	}
	last, paused, calls := s.engine.LastActivity(id), s.engine.IsPaused(id), s.engine.ActiveLLMCalls(id)
	running := s.engine.ReadyFor(live) && s.engine.Started(id) && !paused
	stalled := running && calls == 0 && inFlight > 0 && last > 0 && time.Now().Unix()-last > 120
	mode := "idle"
	switch {
	case paused:
		mode = "paused"
	case stalled:
		mode = "stalled"
	case running && calls > 0:
		mode = "exploring"
	}
	writeJSON(w, 200, map[string]any{
		"engine_mode": mode, "llm_configured": s.engine.ReadyFor(live), "exploration": stats,
		"active_task": map[string]any{"id": live.ID, "description": live.Description, "goal": live.Goal,
			"running": running, "paused": paused, "engine_mode": mode, "in_flight": inFlight,
			"llm_in_flight": calls, "last_activity": last, "stalled": stalled,
			"goals_total": len(goals), "goals_met": goalsMet},
	})
}
