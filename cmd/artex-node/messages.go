package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/collab"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

const maxMessageGuidanceContinuations = 8
const maxMessageExchangeBytes = 240 << 10

type nodeMessageRecord struct {
	Direction string `json:"direction"`
	Seq       int64  `json:"seq,omitempty"`
	ID        int64  `json:"id,omitempty"`
	Text      string `json:"text"`
}

// nodeMessageBridge carries only complete user-facing text events. Tool data
// and reasoning never enter this journal or coordinator endpoint.
type nodeMessageBridge struct {
	mu           sync.Mutex
	client       *http.Client
	origin       string
	token        string
	path         string
	epoch        int64
	journal      string
	cancel       context.CancelFunc
	seq          int64
	outbox       []collab.DeviceMessage
	ack          []int64
	ackReady     bool
	err          error
	sealed       bool
	stops        int
	textBoundary uint64
}

func newNodeMessageBridge(a collab.Assignment, client *http.Client, origin, token, journal string, cancel context.CancelFunc) *nodeMessageBridge {
	return &nodeMessageBridge{
		client: client, origin: origin, token: token,
		path:  fmt.Sprintf("/api/collaboration/device/assignments/%d/messages", a.ID),
		epoch: a.Epoch, journal: journal, cancel: cancel,
	}
}

func (b *nodeMessageBridge) failLocked(err error) error {
	if err == nil {
		return b.err
	}
	if b.err == nil {
		b.err = err
		if b.cancel != nil {
			b.cancel()
		}
	}
	return b.err
}

func (b *nodeMessageBridge) appendRecordLocked(record nodeMessageRecord) error {
	if b.journal == "" {
		return errors.New("message journal path is empty")
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(b.journal, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(append(raw, '\n')); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	return err
}

func (b *nodeMessageBridge) addText(text string) {
	if strings.TrimSpace(text) == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.addTextLocked(text)
}

func (b *nodeMessageBridge) addTextLocked(text string) {
	if strings.TrimSpace(text) == "" || b.err != nil || b.sealed {
		return
	}
	if len(b.outbox) >= 32 || len(text) > 64<<10 {
		b.failLocked(errors.New("team message budget exceeded"))
		return
	}
	seq := b.seq + 1
	if err := b.appendRecordLocked(nodeMessageRecord{Direction: "outbound", Seq: seq, Text: text}); err != nil {
		b.failLocked(fmt.Errorf("persist team message: %w", err))
		return
	}
	b.seq = seq
	b.outbox = append(b.outbox, collab.DeviceMessage{Seq: seq, Text: text})
}

func (b *nodeMessageBridge) exchangeLocked(ctx context.Context, seal bool) (collab.MessageExchangeReply, error) {
	if b.err != nil {
		return collab.MessageExchangeReply{}, b.err
	}
	req := collab.MessageExchange{Epoch: b.epoch, Messages: append([]collab.DeviceMessage(nil), b.outbox...), Delivered: append([]int64(nil), b.ack...), Seal: seal}
	encoded, err := json.Marshal(req)
	if err != nil || len(encoded) > maxMessageExchangeBytes {
		return collab.MessageExchangeReply{}, b.failLocked(errors.New("team message exchange exceeds local request limit"))
	}
	var reply collab.MessageExchangeReply
	backoff := time.Second
	for {
		err = request(ctx, b.client, b.origin, b.path, b.token, req, &reply)
		if err == nil {
			break
		}
		if ctx.Err() != nil || !isTransientNodeError(err) {
			return collab.MessageExchangeReply{}, b.failLocked(fmt.Errorf("team message exchange failed: %w", err))
		}
		if waitErr := waitNodeRetry(ctx, backoff); waitErr != nil {
			return collab.MessageExchangeReply{}, b.failLocked(fmt.Errorf("team message exchange failed: %w", err))
		}
		backoff = nextNodeBackoff(backoff)
	}
	for _, guide := range reply.Guidance {
		if guide.ID <= 0 || strings.TrimSpace(guide.Text) == "" {
			return collab.MessageExchangeReply{}, b.failLocked(errors.New("coordinator returned invalid team guidance"))
		}
		if err := b.appendRecordLocked(nodeMessageRecord{Direction: "guidance", ID: guide.ID, Text: guide.Text}); err != nil {
			return collab.MessageExchangeReply{}, b.failLocked(fmt.Errorf("persist team guidance: %w", err))
		}
	}
	// The server accepted these sequence-numbered events and delivered receipts.
	// A lost HTTP response leaves the old values in place and retries idempotently.
	b.outbox = nil
	b.ack = nil
	b.ackReady = false
	b.sealed = reply.Sealed
	for _, guide := range reply.Guidance {
		b.ack = append(b.ack, guide.ID)
	}
	return reply, nil
}

func renderNodeGuidance(guidance []collab.Guidance) string {
	var out strings.Builder
	out.WriteString("Coordinator guidance (user-provided; apply it before the next action):")
	for _, item := range guidance {
		out.WriteString("\n- ")
		out.WriteString(item.Text)
	}
	return out.String()
}

func (b *nodeMessageBridge) PreToolUse(ctx context.Context, _ string, _ []byte) (bool, string, []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return true, "team message exchange failed; execution stopped", nil
	}
	// Same-response tool calls share one model batch. Only acknowledge guidance
	// after the next provider call, when this batch's blocked result is in history.
	if len(b.ack) > 0 && !b.ackReady {
		return true, "coordinator guidance was delivered at this tool boundary; wait for the next model turn before using tools", nil
	}
	reply, err := b.exchangeLocked(ctx, false)
	if err != nil {
		return true, "team message exchange failed; execution stopped", nil
	}
	if reply.Sealed {
		return true, b.failLocked(errors.New("coordinator sealed the team message channel before tool execution")).Error(), nil
	}
	if len(reply.Guidance) > 0 {
		return true, renderNodeGuidance(reply.Guidance), nil
	}
	return false, "", nil
}

func (b *nodeMessageBridge) PostToolUse(context.Context, string, []byte, []byte, bool) {}

// BeginModelCall runs just before a provider request. By this point any pending
// guidance result from the previous turn has been appended to the Session input.
func (b *nodeMessageBridge) BeginModelCall() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.ack) > 0 {
		b.ackReady = true
	}
}

func (b *nodeMessageBridge) Error() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	if !b.sealed {
		return errors.New("team message channel did not seal before execution ended")
	}
	return nil
}

func (b *nodeMessageBridge) TextBoundary() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.textBoundary
}

func (b *nodeMessageBridge) FinishPrompt(ctx context.Context, finalText string) (collab.MessageExchangeReply, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return collab.MessageExchangeReply{}, b.err
	}
	if b.sealed {
		return collab.MessageExchangeReply{Sealed: true}, nil
	}
	b.stops++
	if b.stops > maxMessageGuidanceContinuations {
		return collab.MessageExchangeReply{}, b.failLocked(errors.New("team guidance continuation limit reached before message channel sealed"))
	}
	b.addTextLocked(finalText)
	return b.exchangeLocked(ctx, true)
}

func (b *nodeMessageBridge) Start(ctx context.Context) (collab.MessageExchangeReply, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	reply, err := b.exchangeLocked(ctx, false)
	if err == nil && len(reply.Guidance) > 0 {
		// The caller places this in the initial Prompt before the first model call.
		b.ackReady = true
	}
	return reply, err
}

func (b *nodeMessageBridge) StopWithMessages(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	return b.stop(ctx, messages)
}

func (b *nodeMessageBridge) stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return true, nil, "team message exchange failed; execution stopped"
	}
	if b.sealed {
		return false, nil, ""
	}
	b.stops++
	if b.stops > maxMessageGuidanceContinuations {
		b.failLocked(errors.New("team guidance continuation limit reached before message channel sealed"))
		return true, nil, "team guidance continuation limit reached; execution stopped"
	}
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == llm.RoleAssistant {
			b.addTextLocked(messages[i].Text())
			// Stop has journaled the authoritative complete assistant response.
			// The outer stream consumer must discard its duplicate KindText deltas
			// before processing any events from a continued Prompt.
			b.textBoundary++
			break
		}
	}
	reply, err := b.exchangeLocked(ctx, true)
	if err != nil {
		return true, nil, "team message exchange failed; execution stopped"
	}
	if len(reply.Guidance) > 0 {
		return false, []string{renderNodeGuidance(reply.Guidance)}, ""
	}
	if !reply.Sealed {
		return false, []string{"Coordinator has not sealed the message channel yet; wait for any pending guidance before ending."}, ""
	}
	return false, nil, ""
}

// Forward the SDK's full conversation to the bridge so Stop can journal the
// authoritative final assistant text before it seals the channel.
type nodeMessageHooks struct{ bridge *nodeMessageBridge }

func (h *nodeMessageHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	return h.bridge.PreToolUse(ctx, name, input)
}
func (h *nodeMessageHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	h.bridge.PostToolUse(ctx, name, input, result, isErr)
}
func (h *nodeMessageHooks) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	return h.bridge.StopWithMessages(ctx, messages)
}

var _ harness.HookRunner = (*nodeMessageHooks)(nil)

type nodeMessageProvider struct {
	inner      llm.Provider
	beforeCall func()
}

func (p *nodeMessageProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		p.beforeCall()
		for event, err := range p.inner.Stream(ctx, req) {
			if !yield(event, err) {
				return
			}
		}
	}
}

func (p *nodeMessageProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.beforeCall()
	return p.inner.Complete(ctx, req)
}
