// Package reamcp runs a private REA stdio session for one analysis worker.
// It retains the complete MCP result (including structuredContent), rather than
// reducing evidence to the text intended for a model's context window.
package reamcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
)

type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type Client struct {
	cmd      *exec.Cmd
	in       io.WriteCloser
	writeMu  sync.Mutex
	mu       sync.Mutex
	pending  map[int64]chan envelope
	next     atomic.Int64
	closed   chan struct{}
	once     sync.Once
	err      error
	Version  string
	progress func(string)
}

type envelope struct {
	ID     int64           `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func New(ctx context.Context, command string, args []string, dir string, env []string, progress func(string)) (*Client, error) {
	if command == "" {
		return nil, errors.New("REA command is not configured")
	}
	cmd := exec.Command(command, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	configureProcess(cmd)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		_ = in.Close()
		return nil, err
	}
	// REA diagnostics can include artifact contents. Keep stdout evidence only;
	// do not mix arbitrary stderr text into logs or JSON-RPC framing.
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		_ = in.Close()
		return nil, err
	}
	c := &Client{cmd: cmd, in: in, pending: map[int64]chan envelope{}, closed: make(chan struct{}), progress: progress}
	go func() { c.read(out); err := cmd.Wait(); c.finish(err) }()
	go func() {
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-c.closed:
		}
	}()
	raw, err := c.request(ctx, "initialize", map[string]any{
		"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "artex-reverse", "version": "1"},
	})
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	var init struct {
		ServerInfo struct {
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(raw, &init); err != nil {
		_ = c.Close()
		return nil, err
	}
	c.Version = init.ServerInfo.Version
	if err := c.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

func (c *Client) send(v any) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return json.NewEncoder(c.in).Encode(v)
}

func (c *Client) read(r io.Reader) {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64<<10), 256<<20)
	for s.Scan() {
		var e envelope
		if json.Unmarshal(s.Bytes(), &e) != nil {
			c.finish(errors.New("REA emitted invalid JSON-RPC"))
			_ = c.Close()
			return
		}
		if e.ID != 0 {
			c.mu.Lock()
			ch := c.pending[e.ID]
			c.mu.Unlock()
			if ch != nil {
				select {
				case ch <- e:
				default:
				}
			}
		} else if e.Method == "notifications/progress" && c.progress != nil {
			// Report activity counts rather than inventing a percentage.
			c.progress("REA 正在处理分析请求")
		}
	}
	if err := s.Err(); err != nil {
		c.finish(fmt.Errorf("REA response stream: %w", err))
		_ = c.Close()
	}
}

func (c *Client) finish(err error) {
	c.once.Do(func() {
		if err == nil {
			err = io.EOF
		}
		c.mu.Lock()
		c.err = err
		c.mu.Unlock()
		close(c.closed)
	})
}

func (c *Client) request(ctx context.Context, method string, params any) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id := c.next.Add(1)
	ch := make(chan envelope, 1)
	c.mu.Lock()
	c.pending[id] = ch
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pending, id); c.mu.Unlock() }()
	if err := c.send(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
		return nil, err
	}
	select {
	case e := <-ch:
		if e.Error != nil {
			return nil, fmt.Errorf("REA RPC %d: %s", e.Error.Code, e.Error.Message)
		}
		return e.Result, nil
	case <-ctx.Done():
		_ = c.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": id, "reason": "ARTEX run cancelled"}})
		// A cancelled request's provider may continue. Terminate this run-owned
		// process tree; no other worker shares its session.
		_ = c.Close()
		return nil, ctx.Err()
	case <-c.closed:
		c.mu.Lock()
		err := c.err
		c.mu.Unlock()
		return nil, fmt.Errorf("REA session closed: %w", err)
	}
}

func (c *Client) Tools(ctx context.Context) ([]Tool, error) {
	var tools []Tool
	cursor := ""
	for {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		raw, err := c.request(ctx, "tools/list", params)
		if err != nil {
			return nil, err
		}
		var page struct {
			Tools []Tool `json:"tools"`
			Next  string `json:"nextCursor"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, err
		}
		tools = append(tools, page.Tools...)
		if page.Next == "" {
			return tools, nil
		}
		if page.Next == cursor {
			return nil, errors.New("REA returned a repeated tools cursor")
		}
		cursor = page.Next
	}
}

func (c *Client) Call(ctx context.Context, name string, arguments map[string]any) (json.RawMessage, error) {
	return c.request(ctx, "tools/call", map[string]any{"name": name, "arguments": arguments, "_meta": map[string]any{"progressToken": c.next.Load() + 1}})
}

func (c *Client) Close() error {
	_ = c.in.Close()
	if c.cmd.Process != nil {
		_ = killProcess(c.cmd)
	}
	return nil
}
