package collab

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDirectTLSRoundTripper(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("direct")) }))
	defer s.Close()
	roots := testRoots(t, s.TLS.Certificates[0])
	u, _ := url.Parse(s.URL)
	port := u.Port()
	d := NewHybridDialer(HybridConfig{Candidates: []Candidate{{Address: net.JoinHostPort("127.0.0.1", port), ServerName: "example.test", RootCAs: roots}}, TLS: &tls.Config{MinVersion: tls.VersionTLS12}})
	// The candidate name intentionally differs from the test certificate; use the cert SAN instead.
	d.cfg.Candidates[0].ServerName = "invalid-name.example"
	resp, err := d.RoundTripper().RoundTrip(mustRequest(t, "https://example.com/"))
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected hostname verification to reject mismatched certificate")
	}
	d.cfg.Candidates[0].ServerName = "example.com"
	resp, err = d.RoundTripper().RoundTrip(mustRequest(t, "https://example.com/"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if _, err := d.RoundTripper().RoundTrip(mustRequest(t, "http://example.com/")); err == nil {
		t.Fatal("expected plaintext HTTP URL rejection")
	}
	leaf, _ := x509.ParseCertificate(s.TLS.Certificates[0].Certificate[0])
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	pinned := NewHybridDialer(HybridConfig{Candidates: []Candidate{{Address: net.JoinHostPort("127.0.0.1", port), ServerName: "example.com", SPKIPin: base64.StdEncoding.EncodeToString(pin[:])}}})
	conn, err := pinned.DialTLSContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("valid pin rejected: %v", err)
	}
	_ = conn.Close()
	bad := pinned.cfg.Candidates[0]
	bad.SPKIPin = base64.StdEncoding.EncodeToString(make([]byte, 32))
	badDialer := NewHybridDialer(HybridConfig{Candidates: []Candidate{bad}})
	if _, err := badDialer.DialTLSContext(context.Background(), "tcp", "example.com:443"); err == nil {
		t.Fatal("wrong pin must fail authentication")
	}
}

func TestRelayFallbackEndToEndTLS(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("secret-response")) }))
	defer origin.Close()
	cert := origin.TLS.Certificates[0]
	roots := testRoots(t, cert)
	// A relay sees only WebSocket binary frames; TLS is terminated by the test server after the paired tunnel.
	relay := httptest.NewServer(NewRelayServer(RelayOptions{Secrets: map[string]string{"team": "shared-secret"}, IdleTimeout: 5 * time.Second}))
	defer relay.Close()
	wsURL := "ws" + relay.URL[len("http"):] + "/v1/tunnel"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	coordCfg := RelayConfig{URL: wsURL, Room: "team", Secret: "shared-secret", Peer: "coordinator"}
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- ServeRelayHTTP(ctx, coordCfg, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("secret-response")) }))
	}()
	time.Sleep(50 * time.Millisecond)
	u, _ := url.Parse(origin.URL)
	d := NewHybridDialer(HybridConfig{Candidates: []Candidate{{Address: "127.0.0.1:1", ServerName: "example.com", RootCAs: roots}}, Relay: RelayConfig{URL: wsURL, Room: "team", Secret: "shared-secret", Peer: "coordinator"}, TLS: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}})
	req := mustRequest(t, "https://example.com:"+u.Port()+"/")
	resp, err := d.RoundTripper().RoundTrip(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 32)
	n, err := resp.Body.Read(buf)
	if err != nil && n == 0 {
		t.Fatal(err)
	}
	if string(buf[:n]) != "secret-response" {
		t.Fatalf("unexpected response %q", buf[:n])
	}
	cancel()
	select {
	case <-serveDone:
	case <-time.After(time.Second):
		t.Fatal("coordinator did not stop after cancellation")
	}
}

func TestWrongPinCannotFallbackToCA(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer origin.Close()
	cert := origin.TLS.Certificates[0]
	roots := testRoots(t, cert)
	relay := httptest.NewServer(NewRelayServer(RelayOptions{Secrets: map[string]string{"room": "secret"}, IdleTimeout: 2 * time.Second}))
	defer relay.Close()
	wsURL := "ws" + relay.URL[len("http"):] + "/v1/tunnel"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cfg := RelayConfig{URL: wsURL, Room: "room", Secret: "secret", Peer: "coordinator"}
	serverResult := make(chan error, 1)
	go func() {
		raw, err := AcceptRelay(ctx, cfg)
		if err != nil {
			serverResult <- err
			return
		}
		defer raw.Close()
		serverResult <- tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}).Handshake()
	}()
	wrong := base64.StdEncoding.EncodeToString(make([]byte, 32))
	d := NewHybridDialer(HybridConfig{Candidates: []Candidate{{Address: "127.0.0.1:1", ServerName: "example.com", SPKIPin: wrong}}, TLS: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, Relay: cfg})
	if _, err := d.DialTLSContext(ctx, "tcp", "example.com:443"); err == nil {
		t.Fatal("wrong SPKI pin must fail relay fallback even when the CA trusts the certificate")
	}
	select {
	case err := <-serverResult:
		if err == nil {
			t.Fatal("server observed successful TLS despite wrong pin")
		}
	case <-time.After(time.Second):
		t.Fatal("server TLS handshake did not end after pin rejection")
	}
}

func TestRelayIdleClientDoesNotBlockAnotherDevice(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer origin.Close()
	relay := httptest.NewServer(NewRelayServer(RelayOptions{Secrets: map[string]string{"room": "secret"}}))
	defer relay.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := RelayConfig{URL: "ws" + relay.URL[len("http"):] + "/v1/tunnel", Room: "room", Secret: "secret", Peer: "coordinator"}
	go ServeRelayHTTP(ctx, cfg, origin.TLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("second-device")) }))
	client := func() *HybridDialer {
		return NewHybridDialer(HybridConfig{Candidates: []Candidate{{Address: "127.0.0.1:1", ServerName: "example.com", RootCAs: testRoots(t, origin.TLS.Certificates[0])}}, Relay: cfg, TLS: &tls.Config{RootCAs: testRoots(t, origin.TLS.Certificates[0])}})
	}
	one, two := client(), client()
	defer one.CloseIdleConnections()
	defer two.CloseIdleConnections()
	conn, err := one.DialTLSContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deadline, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	r, _ := http.NewRequestWithContext(deadline, "GET", "https://example.com/", nil)
	response, err := two.RoundTripper().RoundTrip(r)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
}

func TestOutboxReplayConflictAndCorruption(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "outbox")
	o, err := OpenOutbox(dir, 4096)
	if err != nil {
		t.Fatal(err)
	}
	e := Envelope{Version: 1, CommandID: "stable-1", ExecutionID: "exec-1", Epoch: 4, Payload: json.RawMessage(`{"x":1}`)}
	if err := o.Put(e); err != nil {
		t.Fatal(err)
	}
	if err := o.Put(e); err != nil {
		t.Fatal(err)
	}
	p, err := o.Pending()
	if err != nil || len(p) != 1 {
		t.Fatalf("pending=%v err=%v", p, err)
	}
	changed := e
	changed.Payload = json.RawMessage(`{"x":2}`)
	if err := o.Put(changed); err == nil {
		t.Fatal("expected payload conflict")
	}
	changed = e
	changed.Epoch++
	if err := o.Put(changed); err == nil {
		t.Fatal("expected epoch identity conflict")
	}
	changed = e
	changed.ExecutionID = "other-execution"
	if err := o.Put(changed); err == nil {
		t.Fatal("expected execution identity conflict")
	}
	longID := e
	longID.CommandID = strings.Repeat("long-id-", 80)
	if err := o.Put(longID); err != nil {
		t.Fatalf("long command ID should use bounded filename: %v", err)
	}
	longPending, err := o.Pending()
	if err != nil || len(longPending) != 2 {
		t.Fatalf("long ID pending=%d err=%v", len(longPending), err)
	}
	if err := o.Ack(e.CommandID); err != nil {
		t.Fatal(err)
	}
	if err := o.Ack(longID.CommandID); err != nil {
		t.Fatal(err)
	}
	p, err = o.Pending()
	if err != nil || len(p) != 0 {
		t.Fatalf("ack did not remove pending command: %v %v", p, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Pending(); err == nil {
		t.Fatal("expected corrupted outbox to fail closed")
	}
}

func TestInboxDedupAndCancellation(t *testing.T) {
	i, err := OpenInbox(filepath.Join(t.TempDir(), "inbox"), 4096)
	if err != nil {
		t.Fatal(err)
	}
	e := Envelope{Version: 1, CommandID: "cmd", ExecutionID: "exec", Payload: json.RawMessage(`null`)}
	first, err := i.Accept(e)
	if err != nil || !first {
		t.Fatalf("first=%v err=%v", first, err)
	}
	first, err = i.Accept(e)
	if err != nil || first {
		t.Fatalf("duplicate=%v err=%v", first, err)
	}
	e.Payload = json.RawMessage(`false`)
	if _, err := i.Accept(e); err == nil {
		t.Fatal("expected duplicate payload conflict")
	}
	e.Payload = json.RawMessage(`null`)
	e.Epoch++
	if _, err := i.Accept(e); err == nil {
		t.Fatal("expected duplicate epoch identity conflict")
	}
	i2, err := OpenInbox(i.dir, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if first, err := i2.Accept(Envelope{Version: 1, CommandID: "cmd", ExecutionID: "exec", Payload: json.RawMessage(`null`)}); err != nil || first {
		t.Fatalf("durable inbox replay first=%v err=%v", first, err)
	}
	longInbox := Envelope{Version: 1, CommandID: strings.Repeat("long-inbox-", 60), ExecutionID: "exec", Payload: json.RawMessage(`true`)}
	if first, err := i2.Accept(longInbox); err != nil || !first {
		t.Fatalf("long inbox ID first=%v err=%v", first, err)
	}
	i3, err := OpenInbox(i.dir, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if first, err := i3.Accept(longInbox); err != nil || first {
		t.Fatalf("long inbox ID replay first=%v err=%v", first, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DialRelay(ctx, RelayConfig{URL: "ws://127.0.0.1:1/v1/tunnel", Room: "r", Secret: "s", Peer: "p"}, "agent"); err == nil {
		t.Fatal("expected canceled dial")
	}
	if _, err := DialRelay(context.Background(), RelayConfig{URL: "ws://relay.invalid/v1/tunnel", Room: "r", Secret: "s", Peer: "p"}, "agent"); err == nil {
		t.Fatal("unencrypted ws to a non-loopback host must be rejected by default")
	}
	if _, err := DialRelay(context.Background(), RelayConfig{URL: "wss://relay.invalid/v1/tunnel?secret=leak", Room: "r", Secret: "s", Peer: "p"}, "agent"); err == nil {
		t.Fatal("URL credentials must be rejected")
	}
}

func TestRelayPendingAndIdleLimits(t *testing.T) {
	srv := NewRelayServer(RelayOptions{Secrets: map[string]string{"r": "s"}, PendingPerRoom: 1, MaxConnections: 4, IdleTimeout: 100 * time.Millisecond})
	h := httptest.NewServer(srv)
	defer h.Close()
	url := "ws" + h.URL[len("http"):] + "/v1/tunnel"
	cfg := RelayConfig{URL: url, Room: "r", Secret: "s", Peer: "p"}
	first, err := DialRelay(context.Background(), cfg, "coordinator")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := DialRelay(context.Background(), cfg, "coordinator")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	deadline := time.Now().Add(time.Second)
	for len(srv.sem) < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	srv.mu.Lock()
	queued := len(srv.waiting["r\x00p"]["coordinator"])
	srv.mu.Unlock()
	if queued != 1 {
		t.Fatalf("pending limit not enforced: queued=%d", queued)
	}
	deadline = time.Now().Add(time.Second)
	for len(srv.sem) > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(srv.sem) != 0 {
		t.Fatal("idle timeout did not release pending connection slots")
	}
}

func TestRelayCancellationClosesActiveStream(t *testing.T) {
	relay := httptest.NewServer(NewRelayServer(RelayOptions{Secrets: map[string]string{"room": "secret"}, IdleTimeout: 3 * time.Second}))
	defer relay.Close()
	wsURL := "ws" + relay.URL[len("http"):] + "/v1/tunnel"
	cfg := RelayConfig{URL: wsURL, Room: "room", Secret: "secret", Peer: "device-a"}
	coordCtx, stopCoord := context.WithCancel(context.Background())
	defer stopCoord()
	coord := make(chan net.Conn, 1)
	coordErr := make(chan error, 1)
	go func() {
		c, e := AcceptRelay(coordCtx, cfg)
		if e != nil {
			coordErr <- e
			return
		}
		coord <- c
	}()
	agentCtx, cancelAgent := context.WithCancel(context.Background())
	agent, e := DialRelay(agentCtx, cfg, "agent")
	if e != nil {
		t.Fatal(e)
	}
	defer agent.Close()
	var peer net.Conn
	select {
	case peer = <-coord:
	case e := <-coordErr:
		t.Fatal(e)
	case <-time.After(time.Second):
		t.Fatal("relay pair did not form")
	}
	defer peer.Close()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	cancelAgent()
	_, e = peer.Read(make([]byte, 1))
	if e == nil {
		t.Fatal("expected canceled agent to close peer stream")
	}
}

func mustRequest(t *testing.T, u string) *http.Request {
	t.Helper()
	r, e := http.NewRequest("GET", u, nil)
	if e != nil {
		t.Fatal(e)
	}
	return r
}

func testRoots(t *testing.T, cert tls.Certificate) *x509.CertPool {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return roots
}
