package server

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestActivityStreamIdleHeartbeat(t *testing.T) {
	s, task, _ := workflowFixture(t)
	h := httptest.NewServer(http.HandlerFunc(s.streamActivity))
	defer h.Close()
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(h.URL + "?task=" + task.ID + "&since=9223372036854775806")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("stream response: %s %v", resp.Status, resp.Header)
	}
	scan := bufio.NewScanner(resp.Body)
	var frame []string
	for scan.Scan() {
		if scan.Text() == "" {
			break
		}
		frame = append(frame, scan.Text())
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(frame, "\n"); got != "event: heartbeat\ndata: {}" {
		t.Fatalf("idle stream must send an observable heartbeat without an activity id: %q", got)
	}
}
