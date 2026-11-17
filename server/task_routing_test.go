package server

import (
	"context"
	"iter"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

type routeFixtureProvider struct {
	text  string
	err   error
	calls int
}

func (p *routeFixtureProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return llm.Message{}, "", llm.Usage{}, nil
}
func (p *routeFixtureProvider) Stream(_ context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	p.calls++
	return func(yield func(llm.StreamEvent, error) bool) {
		if p.err != nil {
			yield(llm.StreamEvent{}, p.err)
			return
		}
		yield(llm.StreamEvent{Type: llm.SETextDelta, Text: p.text}, nil)
	}
}

func TestClassifyTaskParsesBoundedMixedRoute(t *testing.T) {
	p := &routeFixtureProvider{text: `{"primary_kind":"reverse","capabilities":["reverse","native"],"reason":"描述要求分析本机二进制行为","needs_materials":["样本文件"]}`}
	r, err := classifyTask(context.Background(), p, "分析这个程序", "还原启动行为", []taskMaterialHint{{Name: "sample.bin", Size: 12}})
	if err != nil {
		t.Fatal(err)
	}
	if r.PrimaryKind != "reverse" || len(r.Capabilities) != 2 || r.NeedsMaterials[0] != "样本文件" {
		t.Fatalf("unexpected route: %#v", r)
	}
	if p.calls != 1 {
		t.Fatalf("provider calls=%d, want 1", p.calls)
	}
}

func TestClassifyTaskRejectsInvalidOutputWithoutFallback(t *testing.T) {
	for _, output := range []string{"not json", `{"primary_kind":"reverse","capabilities":["magic"],"reason":"x"}`, `{"primary_kind":"pentest","capabilities":["web"],"reason":""}`, `{"primary_kind":"pentest","capabilities":["web","native"],"reason":"mixed task"}`} {
		p := &routeFixtureProvider{text: output}
		if _, err := classifyTask(context.Background(), p, "web target", "test", nil); err == nil {
			t.Fatalf("output %q unexpectedly accepted", output)
		}
		if p.calls != 1 {
			t.Fatalf("provider calls=%d, want 1", p.calls)
		}
	}
}

func TestClassifyTaskReturnsProviderFailure(t *testing.T) {
	p := &routeFixtureProvider{err: context.DeadlineExceeded}
	if _, err := classifyTask(context.Background(), p, "", "", nil); err == nil {
		t.Fatal("expected provider error")
	}
}
