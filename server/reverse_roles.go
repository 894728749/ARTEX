package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
	"strings"
)

const reverseToolPrefix = "reverse__"

// Namespace configuration, not handler names. Both workflows can reuse a tool
// implementation without sharing enable flags, descriptions or defaults.
func reverseToolDefaults(pg *db.DB, dir string) []agent.ToolSeed {
	seeds := []agent.ToolSeed{}
	for _, sd := range agent.BuiltinToolSeeds() {
		if !agent.ReverseToolAllowed(sd.Key) {
			continue
		}
		roles := []string{}
		for _, legacy := range sd.Agents {
			switch legacy {
			case "mainagent":
				roles = append(roles, "reverse_main")
			case "planner":
				roles = append(roles, "reverse_planner")
			case "goals":
				roles = append(roles, "reverse_goals")
			case "worker":
				roles = append(roles, "reverse_static", "reverse_dynamic", "reverse_reviewer")
			}
		}
		sd.Key = reverseToolPrefix + sd.Key
		sd.Agents = roles
		seeds = append(seeds, sd)
	}
	for _, t := range actool.DefaultTools() {
		if !agent.ReverseToolAllowed(t.Name()) {
			continue
		}
		seeds = append(seeds, agent.ToolSeed{Key: reverseToolPrefix + t.Name(), Desc: t.Description(), Schema: t.InputSchema(), Agents: []string{"reverse_main", "reverse_planner", "reverse_static", "reverse_dynamic", "reverse_reviewer"}})
	}
	tools, _, close := reverseAgentTools(context.Background(), pg, &db.Task{}, dir, "worker")
	defer close()
	for _, t := range tools {
		roles := []string{"reverse_static", "reverse_dynamic", "reverse_reviewer"}
		switch t.Name() {
		case "reverse_workspace":
			roles = []string{"reverse_main", "reverse_goals", "reverse_planner", "reverse_static", "reverse_dynamic", "reverse_reviewer"}
		case "reverse_submit_conclusion":
			roles = []string{"reverse_static", "reverse_dynamic"}
		case "reverse_review_conclusion":
			roles = []string{"reverse_reviewer"}
		case "reverse_observe_runtime":
			roles = []string{"reverse_dynamic", "reverse_reviewer"}
		}
		seeds = append(seeds, agent.ToolSeed{Key: reverseToolPrefix + t.Name(), Desc: t.Description(), Schema: t.InputSchema(), Agents: roles})
	}
	return seeds
}

func seedReverseRoles(pg *db.DB, dir string) error {
	for _, sd := range reverseToolDefaults(pg, dir) {
		schema, _ := json.Marshal(sd.Schema)
		binds, _ := json.Marshal(sd.Agents)
		if err := pg.SeedTool(sd.Key, sd.Desc, schema, binds); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) workflowRoleAvailable(t *Task, key string) bool {
	if t == nil {
		return false
	}
	if t.Kind == "reverse" {
		a, err := s.m.pg.GetAgentByKey(key)
		if err != nil || a == nil || !a.Enabled {
			return false
		}
	}
	return true
}

func (s *Server) workerForIntent(t *Task, intent *db.Node) (*agent.Worker, error) {
	if t.Kind != "reverse" {
		return s.agentsForTask(t).wk, nil
	}
	contract, _ := db.IntentContract(intent)
	key, err := agent.ReverseWorkerKey(contract.ExecutionRole)
	if err != nil {
		return nil, err
	}
	if !s.taskRuntimeAvailable(t, key) {
		return nil, fmt.Errorf("逆向角色 %s 已停用或模型不可用", key)
	}
	return s.agentsForTask(t).workers[key], nil
}

func permittedReverseRoleTool(key, name string) bool {
	if !strings.HasPrefix(key, "reverse_") {
		return true
	}
	switch name {
	case "reverse_submit_conclusion":
		return key == "reverse_static" || key == "reverse_dynamic"
	case "reverse_review_conclusion":
		return key == "reverse_reviewer"
	case "reverse_observe_runtime":
		return key == "reverse_dynamic" || key == "reverse_reviewer"
	}
	return true
}

func (s *Server) recordAgentConfiguration(t *Task, key string, intentID int64) {
	if t == nil || s.m.pg == nil {
		return
	}
	a, err := s.m.pg.GetAgentByKey(key)
	if err != nil || a == nil {
		return
	}
	prompt, _ := s.m.pg.CurrentPrompt(a.ID)
	promptHash := sha256.Sum256([]byte(prompt))
	tools, _ := s.m.pg.ListTools()
	bound := []*db.Tool{}
	for _, tool := range tools {
		if contains(tool.Agents, key) {
			bound = append(bound, tool)
		}
	}
	mcps, _ := s.m.pg.AgentVisible(a.ID, "mcp")
	skills, _ := s.m.pg.AgentSkillNames(a.ID)
	snapshot := map[string]any{"agent": a, "prompt_sha256": fmt.Sprintf("%x", promptHash), "tools": bound, "mcp_bindings": mcps, "skill_bindings": skills}
	raw, _ := json.Marshal(snapshot)
	hash := sha256.Sum256(raw)
	metadata, _ := json.Marshal(map[string]any{"agent_config": map[string]any{"key": key, "revision": fmt.Sprintf("%x", hash), "prompt_sha256": fmt.Sprintf("%x", promptHash), "max_turns": a.MaxTurns, "run_seconds": a.RunSecs, "llm_profile_id": a.LLMProfileID}})
	worker := "planner"
	if key == "mainagent" || key == "reverse_main" {
		worker = "mainagent"
	}
	activity := db.Activity{Worker: worker, Kind: "agent_config", Summary: "执行角色：" + key, Metadata: metadata}
	if intentID > 0 {
		activity.NodeID = &intentID
		if n, err := t.Store.GetNode(intentID); err == nil && n != nil {
			activity.Worker = n.Owner
		}
	}
	s.engine.emitActivity(t, activity)
}
