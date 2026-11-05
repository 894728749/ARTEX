package collab

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type gatedTLSPath struct {
	listener net.Listener
	origin   string
	enabled  atomic.Bool
}

func newGatedTLSPath(t *testing.T, origin string) *gatedTLSPath {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := &gatedTLSPath{listener: listener, origin: origin}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			if !g.enabled.Load() {
				_ = client.Close()
				continue
			}
			upstream, err := net.Dial("tcp", g.origin)
			if err != nil {
				_ = client.Close()
				continue
			}
			go func() {
				defer client.Close()
				defer upstream.Close()
				finished := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(upstream, client); finished <- struct{}{} }()
				go func() { _, _ = io.Copy(client, upstream); finished <- struct{}{} }()
				<-finished
			}()
		}
	}()
	return g
}

func TestHybridLANFailureRecoveryAndFallback(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "LAN") }))
	defer origin.Close()
	u, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	path := newGatedTLSPath(t, net.JoinHostPort("127.0.0.1", u.Port()))
	relay := httptest.NewServer(NewRelayServer(RelayOptions{Secrets: map[string]string{"room": "secret"}, IdleTimeout: 3 * time.Second}))
	defer relay.Close()
	wsURL := "ws" + strings.TrimPrefix(relay.URL, "http") + "/v1/tunnel"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	holdStarted := make(chan struct{})
	releaseHold := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(releaseHold) })
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- ServeRelayHTTP(ctx, RelayConfig{URL: wsURL, Room: "room", Secret: "secret", Peer: "coordinator"}, origin.TLS,
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/hold" {
					close(holdStarted)
					<-releaseHold
					_, _ = io.WriteString(w, "held")
					return
				}
				_, _ = io.WriteString(w, "RELAY")
			}))
	}()
	d := NewHybridDialer(HybridConfig{
		Candidates: []Candidate{{Address: path.listener.Addr().String(), ServerName: "example.com", RootCAs: testRoots(t, origin.TLS.Certificates[0])}},
		Relay:      RelayConfig{URL: wsURL, Room: "room", Secret: "secret", Peer: "coordinator"},
		TLS:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: testRoots(t, origin.TLS.Certificates[0])}, Timeout: time.Second,
		LANProbeInterval: 25 * time.Millisecond, LANProbeSuccesses: 2,
	})
	defer d.CloseIdleConnections()
	requestPath := func(path string) string {
		t.Helper()
		resp, err := d.RoundTripper().RoundTrip(mustRequest(t, "https://example.com:"+u.Port()+path))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	request := func() string { return requestPath("/") }
	if got := request(); got != "RELAY" {
		t.Fatalf("initial unreachable LAN route returned %q", got)
	}
	if status := d.TransportStatus(); status.Route != "relay" || status.LastError == "" {
		t.Fatalf("fallback status = %+v", status)
	}
	held := make(chan struct {
		body string
		err  error
	}, 1)
	go func() {
		response, err := d.RoundTripper().RoundTrip(mustRequest(t, "https://example.com:"+u.Port()+"/hold"))
		if err != nil {
			held <- struct {
				body string
				err  error
			}{err: err}
			return
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		held <- struct {
			body string
			err  error
		}{body: string(body), err: err}
	}()
	select {
	case <-holdStarted:
	case <-time.After(time.Second):
		t.Fatal("relay request did not reach the blocking handler")
	}

	path.enabled.Store(true)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if got := request(); got == "LAN" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("LAN did not become preferred after successful probes; status=%+v", d.TransportStatus())
		}
		time.Sleep(30 * time.Millisecond)
	}
	if status := d.TransportStatus(); status.Route != "lan" || status.LastChange.IsZero() || status.LastError != "" {
		t.Fatalf("recovered LAN status = %+v", status)
	}
	releaseOnce.Do(func() { close(releaseHold) })
	select {
	case result := <-held:
		if result.err != nil || result.body != "held" {
			t.Fatalf("in-progress relay request was interrupted: body=%q err=%v", result.body, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("in-progress relay request did not finish after LAN recovery")
	}

	path.enabled.Store(false)
	d.CloseIdleConnections()
	if got := request(); got != "RELAY" {
		t.Fatalf("LAN failure did not fall back to relay, got %q", got)
	}
	if status := d.TransportStatus(); status.Route != "relay" || status.LastError == "" {
		t.Fatalf("post-recovery fallback status = %+v", status)
	}
	cancel()
	select {
	case <-serveDone:
	case <-time.After(time.Second):
		t.Fatal("relay HTTP workers did not stop")
	}
}

func TestHybridLANWorksWhenRelayIsDown(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "LAN survives relay outage") }))
	defer origin.Close()
	u, _ := url.Parse(origin.URL)
	closedRelay := httptest.NewServer(http.NotFoundHandler())
	relayURL := "ws" + strings.TrimPrefix(closedRelay.URL, "http") + "/v1/tunnel"
	closedRelay.Close()
	d := NewHybridDialer(HybridConfig{
		Candidates: []Candidate{{Address: net.JoinHostPort("127.0.0.1", u.Port()), ServerName: "example.com", RootCAs: testRoots(t, origin.TLS.Certificates[0])}},
		Relay:      RelayConfig{URL: relayURL, Room: "room", Secret: "secret", Peer: "agent"},
		TLS:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: testRoots(t, origin.TLS.Certificates[0])},
	})
	defer d.CloseIdleConnections()
	resp, err := d.RoundTripper().RoundTrip(mustRequest(t, "https://example.com:"+u.Port()+"/"))
	if err != nil {
		t.Fatalf("healthy LAN was made dependent on relay: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "LAN survives relay outage" {
		t.Fatalf("LAN response=%q err=%v", body, err)
	}
	if status := d.TransportStatus(); status.Route != "lan" {
		t.Fatalf("route status = %+v", status)
	}
}

func TestHybridTLSAuthenticationFailureDoesNotFallback(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer origin.Close()
	u, _ := url.Parse(origin.URL)
	relayAttempts := atomic.Int32{}
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		relayAttempts.Add(1)
		http.Error(w, "observed fallback", http.StatusBadGateway)
	}))
	defer relay.Close()
	leaf := origin.TLS.Certificates[0]
	wrongPin := strings.Repeat("A", 44)
	d := NewHybridDialer(HybridConfig{
		Candidates: []Candidate{{Address: net.JoinHostPort("127.0.0.1", u.Port()), ServerName: "example.com", RootCAs: testRoots(t, leaf), SPKIPin: wrongPin}},
		Relay:      RelayConfig{URL: "ws" + strings.TrimPrefix(relay.URL, "http") + "/v1/tunnel", Room: "room", Secret: "secret", Peer: "agent"},
		TLS:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: testRoots(t, leaf)}, Timeout: time.Second,
	})
	_, err := d.DialTLSContext(context.Background(), "tcp", "example.com:"+u.Port())
	if err == nil || !strings.Contains(err.Error(), "pin mismatch") {
		t.Fatalf("wrong certificate pin result = %v", err)
	}
	if relayAttempts.Load() != 0 {
		t.Fatalf("TLS authentication failure was bypassed through relay (%d attempts)", relayAttempts.Load())
	}
}
