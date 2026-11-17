package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Autumn-27/norma/llm"
)

type taskMaterialHint struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type taskRouteResult struct {
	PrimaryKind    string   `json:"primary_kind"`
	Capabilities   []string `json:"capabilities"`
	Reason         string   `json:"reason"`
	NeedsMaterials []string `json:"needs_materials"`
}

var errTaskRouteInvalid = errors.New("自动分类结果无效")

// classifyTask uses the configured project provider and treats malformed or
// failed model output as retryable; no keyword fallback is performed.
func classifyTask(ctx context.Context, prov llm.Provider, description, goal string, materials []taskMaterialHint) (taskRouteResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if prov == nil {
		return taskRouteResult{}, errors.New("自动分类模型不可用，请配置或选择 LLM 配置后重试")
	}
	input, _ := json.Marshal(struct {
		Description string             `json:"description"`
		Goal        string             `json:"goal"`
		Materials   []taskMaterialHint `json:"materials"`
	}{description, goal, materials})
	system := `Classify an ARTEX task before creation. Return only JSON with primary_kind (pentest or reverse), capabilities (unique values from web, reverse, native), reason (short evidence-based explanation), needs_materials (array of concrete missing inputs, empty if none). Consider only supplied description, goal and filenames/sizes. Do not infer source contents. Mixed tasks may include multiple capabilities; choose the best primary kind. When the requested work centers on a native executable, library, firmware, or native source artifact, choose reverse as the primary kind and include native capability; this keeps initial handling in the static-analysis workflow. Never claim authorization to execute native code.`
	temp := 0.0
	req := llm.CompletionRequest{System: []string{system}, Messages: []llm.Message{llm.UserText(string(input))}, MaxTokens: 320, Temperature: &temp, Thinking: "disabled"}
	var sb strings.Builder
	for ev, err := range prov.Stream(ctx, req) {
		if err != nil {
			return taskRouteResult{}, errors.New("自动分类暂时失败，请重试")
		}
		if ev.Type == llm.SETextDelta {
			if sb.Len()+len(ev.Text) > 8192 {
				return taskRouteResult{}, errTaskRouteInvalid
			}
			sb.WriteString(ev.Text)
		}
	}
	var result taskRouteResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(sb.String())), &result); err != nil {
		return taskRouteResult{}, errTaskRouteInvalid
	}
	if result.PrimaryKind != "pentest" && result.PrimaryKind != "reverse" {
		return taskRouteResult{}, errTaskRouteInvalid
	}
	if strings.TrimSpace(result.Reason) == "" || len(result.Reason) > 600 {
		return taskRouteResult{}, errTaskRouteInvalid
	}
	allowed := map[string]bool{"web": true, "reverse": true, "native": true}
	seen := map[string]bool{}
	for _, cap := range result.Capabilities {
		if !allowed[cap] || seen[cap] {
			return taskRouteResult{}, errTaskRouteInvalid
		}
		seen[cap] = true
	}
	if len(seen) == 0 || len(result.NeedsMaterials) > 12 {
		return taskRouteResult{}, errTaskRouteInvalid
	}
	// Native capability requires the paused reverse workflow and its runtime
	// authorization boundary. Do not let contradictory model output launch a
	// general pentest worker with an unreviewed native specimen.
	if seen["native"] && result.PrimaryKind != "reverse" {
		return taskRouteResult{}, errTaskRouteInvalid
	}
	for i, item := range result.NeedsMaterials {
		result.NeedsMaterials[i] = strings.TrimSpace(item)
		if result.NeedsMaterials[i] == "" || len(result.NeedsMaterials[i]) > 240 {
			return taskRouteResult{}, errTaskRouteInvalid
		}
	}
	return result, nil
}
