package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

type executionProvider struct {
	run func(context.Context, llm.CompletionRequest, func(llm.StreamEvent, error) bool)
}

func (p executionProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(y func(llm.StreamEvent, error) bool) { p.run(ctx, req, y) }
}
func (p executionProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	acc := llm.NewAccumulator()
	for ev, e := range p.Stream(ctx, req) {
		if e != nil {
			return llm.Message{}, "", llm.Usage{}, e
		}
		acc.Add(ev)
	}
	return acc.Message(), acc.StopReason, acc.Usage, nil
}
func TestExecutionWorkerSavesEvidenceAndAcceptanceThroughSDK(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("synthetic execution", "offline fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	s := d.Exploration(task.ExplorationID)
	id, err := s.AddWorkIntent(t.Context(), "check fixture", 5, nil, nil, db.WorkContract{Acceptance: []string{"fixture observed"}, BudgetSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ClaimIntent(id, "fixture"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	n, err := s.BeginIntentAttempt(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.AddConstraint("rule", "synthetic constraint", "test"); err != nil {
		t.Fatal(err)
	}
	turn := 0
	var providerErr error
	provider := executionProvider{run: func(ctx context.Context, req llm.CompletionRequest, y func(llm.StreamEvent, error) bool) {
		turn++
		if !strings.Contains(strings.Join(req.System, "\n"), "synthetic constraint") {
			providerErr = fmt.Errorf("latest constraints absent from model request")
		}
		if turn == 1 && !strings.Contains(strings.Join(req.System, "\n"), "fixture observed") {
			providerErr = fmt.Errorf("work contract absent")
		}
		var name string
		var input any
		switch turn {
		case 1:
			name = "record_fact"
			input = map[string]any{"summary": "fixture verified", "intent_id": id, "evidence": "synthetic output=ok", "confidence": "observed", "planning_impact": "acceptance now supported"}
		case 2, 3:
			facts, e := s.ListByKind(db.KindFact, 100)
			if e != nil {
				providerErr = e
				return
			}
			var evidence *db.Node
			for _, f := range facts {
				if f.State != "origin" {
					evidence = f
					break
				}
			}
			if evidence == nil {
				providerErr = fmt.Errorf("record_fact was not executed")
				return
			}
			if turn == 2 {
				name = "node_detail"
				input = map[string]any{"id": evidence.ID}
			} else {
				name = "complete_intent"
				input = map[string]any{"outcome": "succeeded", "summary": "synthetic checked", "satisfied": []string{"fixture observed"}, "evidence_refs": []db.EvidenceReference{{NodeID: evidence.ID, Version: evidence.EvidenceVersion}}}
			}
		default:
			if !y(llm.StreamEvent{Type: llm.SETextDelta, Text: "fixture complete"}, nil) {
				return
			}
			y(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil)
			return
		}
		raw, _ := json.Marshal(input)
		for _, ev := range []llm.StreamEvent{{Type: llm.SEToolUseStart, ToolID: fmt.Sprint(turn), ToolName: name}, {Type: llm.SEToolInputJSON, Text: string(raw)}, {Type: llm.SEMessageDelta, StopReason: "tool_use"}} {
			if !y(ev, nil) {
				return
			}
		}
	}}
	worker := NewWorker(provider, "fixture", t.TempDir(), nil, 0, 8)
	notifications := 0
	ctx := WithFactNotifier(t.Context(), func(intent int64, summary string) {
		if intent == id && strings.Contains(summary, "fixture verified") {
			notifications++
		}
	})
	_, _, err = worker.Execute(ctx, "fixture", task.ID, nil, s, n, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if providerErr != nil {
		t.Fatal(providerErr)
	}
	if turn != 4 {
		t.Fatalf("turns=%d", turn)
	}
	_, attempt := db.IntentContract(n)
	state, err := s.FinishIntentAttempt(t.Context(), id, attempt, "done")
	if err != nil || state != "done" {
		t.Fatalf("sdk result %s %v", state, err)
	}
	if notifications != 1 {
		t.Fatalf("fact notifications=%d", notifications)
	}
}
