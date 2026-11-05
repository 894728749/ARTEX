package collab

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type Candidate struct {
	Address, ServerName string
	RootCAs             *x509.CertPool
	SPKIPin             string // Base64 SHA-256 of leaf RawSubjectPublicKeyInfo; pin mode still checks hostname and certificate dates.
}
type RelayConfig struct {
	URL, Room, Secret, Peer string
	AllowInsecureWS         bool // Explicit opt-in for non-loopback ws; wss is recommended for remote relay access.
}
type HybridConfig struct {
	Candidates        []Candidate
	Relay             RelayConfig
	TLS               *tls.Config
	Timeout           time.Duration
	LANProbeInterval  time.Duration
	LANProbeSuccesses int
}
type HybridDialer struct {
	cfg        HybridConfig
	transport  *http.Transport
	once       sync.Once
	probeMu    sync.Mutex
	statusMu   sync.RWMutex
	status     TransportStatus
	lastProbe  time.Time
	lanSuccess int
}

// TransportStatus describes the most recent stable route decision. Route is
// "unknown", "lan", or "relay"; LastError records the latest failed attempt.
type TransportStatus struct {
	Route      string    `json:"route"`
	LastChange time.Time `json:"last_change"`
	LastError  string    `json:"last_error,omitempty"`
}

type tlsAuthenticationError struct{ cause error }

func (e tlsAuthenticationError) Error() string { return e.cause.Error() }
func (e tlsAuthenticationError) Unwrap() error { return e.cause }

func isTLSAuthenticationError(err error) bool {
	var verificationError *tls.CertificateVerificationError
	return errors.As(err, &verificationError)
}

// NewHybridDialer returns a TLS-dialing HTTP transport adapter: TLS is verified locally
// on either the LAN socket or the byte-only relay stream, so the relay never sees HTTP plaintext.
func NewHybridDialer(cfg HybridConfig) *HybridDialer {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.LANProbeInterval <= 0 {
		cfg.LANProbeInterval = 250 * time.Millisecond
	}
	if cfg.LANProbeSuccesses <= 0 {
		cfg.LANProbeSuccesses = 2
	}
	return &HybridDialer{cfg: cfg}
}
func (d *HybridDialer) RoundTripper() http.RoundTripper {
	d.once.Do(func() {
		tc := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, DialTLSContext: d.DialTLSContext}
		d.transport = tc
	})
	return httpsOnlyRoundTripper{dialer: d, next: d.transport}
}

type httpsOnlyRoundTripper struct {
	dialer *HybridDialer
	next   http.RoundTripper
}

func (r httpsOnlyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil || !strings.EqualFold(req.URL.Scheme, "https") {
		return nil, errors.New("hybrid transport only permits https URLs")
	}
	if r.dialer != nil {
		r.dialer.maybeRecoverLAN(req.Context(), requestAddress(req.URL))
	}
	return r.next.RoundTrip(req)
}

func requestAddress(u *url.URL) string {
	if u == nil {
		return ""
	}
	if _, _, err := net.SplitHostPort(u.Host); err == nil {
		return u.Host
	}
	return net.JoinHostPort(u.Hostname(), "443")
}

// TransportStatus returns a race-safe copy of the latest route state.
func (d *HybridDialer) TransportStatus() TransportStatus {
	d.statusMu.RLock()
	defer d.statusMu.RUnlock()
	return d.status
}

func (d *HybridDialer) setStatus(route, lastError string) {
	d.statusMu.Lock()
	defer d.statusMu.Unlock()
	if d.status.Route != route {
		d.status.Route = route
		d.status.LastChange = time.Now().UTC()
	}
	d.status.LastError = lastError
}

func (d *HybridDialer) recordProbe(err error) bool {
	d.statusMu.Lock()
	defer d.statusMu.Unlock()
	if err != nil {
		d.lanSuccess = 0
		d.status.LastError = err.Error()
		return false
	}
	d.lanSuccess++
	d.status.LastError = ""
	if d.lanSuccess < d.cfg.LANProbeSuccesses {
		return false
	}
	if d.status.Route != "lan" {
		d.status.Route = "lan"
		d.status.LastChange = time.Now().UTC()
	}
	return true
}

func (d *HybridDialer) maybeRecoverLAN(ctx context.Context, address string) {
	if len(d.cfg.Candidates) == 0 || d.cfg.Relay.URL == "" || ctx.Err() != nil || !d.probeMu.TryLock() {
		return
	}
	defer d.probeMu.Unlock()
	d.statusMu.Lock()
	if d.status.Route != "relay" || time.Since(d.lastProbe) < d.cfg.LANProbeInterval {
		d.statusMu.Unlock()
		return
	}
	d.lastProbe = time.Now()
	d.statusMu.Unlock()

	var lastErr error
	for _, candidate := range d.cfg.Candidates {
		if candidate.Address == "" {
			continue
		}
		conn, err := d.dialCandidate(ctx, "tcp", address, candidate)
		if err == nil {
			_ = conn.Close()
			if d.recordProbe(nil) {
				d.CloseIdleConnections()
			}
			return
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no LAN candidates configured")
	}
	d.recordProbe(lastErr)
}
func (d *HybridDialer) CloseIdleConnections() {
	if d.transport != nil {
		d.transport.CloseIdleConnections()
	}
}
func (d *HybridDialer) DialTLSContext(ctx context.Context, network, address string) (net.Conn, error) {
	var errs []string
	for _, c := range d.cfg.Candidates {
		if c.Address == "" {
			continue
		}
		tc, e := d.dialCandidate(ctx, network, address, c)
		if e == nil {
			d.setStatus("lan", "")
			return tc, nil
		}
		var authErr tlsAuthenticationError
		if errors.As(e, &authErr) {
			d.setStatus("unknown", e.Error())
			return nil, e
		}
		errs = append(errs, e.Error())
	}
	if d.cfg.Relay.URL == "" {
		err := fmt.Errorf("LAN dial failed and relay is not configured: %s", strings.Join(errs, "; "))
		d.setStatus("unknown", err.Error())
		return nil, err
	}
	raw, e := DialRelay(ctx, d.cfg.Relay, "agent")
	if e != nil {
		err := fmt.Errorf("LAN dial failed (%s); relay: %w", strings.Join(errs, "; "), e)
		d.setStatus("unknown", err.Error())
		return nil, err
	}
	serverName := address
	if h, _, e := net.SplitHostPort(address); e == nil {
		serverName = h
	}
	security := Candidate{ServerName: serverName}
	if len(d.cfg.Candidates) > 0 {
		security = d.cfg.Candidates[0]
	}
	for _, candidate := range d.cfg.Candidates {
		if candidate.ServerName == "" || candidate.ServerName == serverName {
			security = candidate
			if security.ServerName == "" {
				security.ServerName = serverName
			}
			break
		}
	}
	tc := tls.Client(raw, d.tlsFor(security, address))
	if e = tc.HandshakeContext(ctx); e != nil {
		raw.Close()
		err := fmt.Errorf("relay end-to-end TLS: %w", e)
		d.setStatus("unknown", err.Error())
		return nil, err
	}
	d.setStatus("relay", strings.Join(errs, "; "))
	d.statusMu.Lock()
	d.lanSuccess = 0
	d.statusMu.Unlock()
	return tc, nil
}

func (d *HybridDialer) dialCandidate(ctx context.Context, network, address string, candidate Candidate) (net.Conn, error) {
	cctx, cancel := context.WithTimeout(ctx, d.cfg.Timeout)
	raw, err := (&net.Dialer{}).DialContext(cctx, network, candidate.Address)
	cancel()
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, d.tlsFor(candidate, address))
	hctx, hcancel := context.WithTimeout(ctx, d.cfg.Timeout)
	err = tc.HandshakeContext(hctx)
	hcancel()
	if err != nil {
		_ = raw.Close()
		if isTLSAuthenticationError(err) {
			return nil, tlsAuthenticationError{cause: err}
		}
		return nil, err
	}
	return tc, nil
}
func (d *HybridDialer) tlsFor(c Candidate, address string) *tls.Config {
	base := d.cfg.TLS
	if base == nil {
		base = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	out := base.Clone()
	out.InsecureSkipVerify = false
	if c.RootCAs != nil {
		out.RootCAs = c.RootCAs
	}
	if c.ServerName != "" {
		out.ServerName = c.ServerName
	} else if h, _, e := net.SplitHostPort(address); e == nil {
		out.ServerName = h
	}
	if c.SPKIPin != "" {
		// Pin mode still verifies the certificate hostname, validity window, and key usage below.
		// InsecureSkipVerify is enabled only to replace CA chain validation with the explicit pin check.
		out.InsecureSkipVerify = true
		want, e := base64.StdEncoding.DecodeString(c.SPKIPin)
		if e != nil {
			want, _ = base64.RawStdEncoding.DecodeString(c.SPKIPin)
		}
		prior := out.VerifyConnection
		out.VerifyConnection = func(cs tls.ConnectionState) error {
			if prior != nil {
				if e := prior(cs); e != nil {
					return tlsAuthenticationError{cause: e}
				}
			}
			if len(cs.PeerCertificates) == 0 {
				return tlsAuthenticationError{cause: errors.New("peer sent no certificate")}
			}
			leaf := cs.PeerCertificates[0]
			if e := leaf.VerifyHostname(out.ServerName); e != nil {
				return tlsAuthenticationError{cause: fmt.Errorf("pinned certificate hostname: %w", e)}
			}
			now := time.Now()
			if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
				return tlsAuthenticationError{cause: errors.New("pinned certificate is outside its validity period")}
			}
			if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 && leaf.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
				return tlsAuthenticationError{cause: errors.New("pinned certificate cannot authenticate a TLS server")}
			}
			if len(leaf.ExtKeyUsage) > 0 {
				ok := false
				for _, usage := range leaf.ExtKeyUsage {
					if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
						ok = true
					}
				}
				if !ok {
					return tlsAuthenticationError{cause: errors.New("pinned certificate is not valid for TLS server use")}
				}
			}
			got := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
			if len(want) != len(got) || subtle.ConstantTimeCompare(want, got[:]) != 1 {
				return tlsAuthenticationError{cause: errors.New("SPKI pin mismatch")}
			}
			return nil
		}
	}
	return out
}

// DialRelay opens one authenticated byte stream to a named room peer. Role is agent or coordinator.
func DialRelay(ctx context.Context, cfg RelayConfig, role string) (net.Conn, error) {
	if role != "agent" && role != "coordinator" {
		return nil, errors.New("role must be agent or coordinator")
	}
	u, e := url.Parse(cfg.URL)
	if e != nil {
		return nil, e
	}
	switch u.Scheme {
	case "wss", "ws":
	default:
		return nil, errors.New("relay URL must use ws or wss")
	}
	if u.User != nil {
		return nil, errors.New("relay URL userinfo is forbidden")
	}
	if len(u.Query()) > 0 {
		return nil, errors.New("relay URL query parameters are forbidden; use RelayConfig fields and Authorization for credentials")
	}
	if u.Scheme == "ws" && !cfg.AllowInsecureWS && !isLoopbackHost(u.Hostname()) {
		return nil, errors.New("unencrypted ws is allowed only for loopback tests or explicit opt-in")
	}
	if cfg.Room == "" || cfg.Secret == "" || cfg.Peer == "" || len(cfg.Peer) > 128 {
		return nil, errors.New("relay room, secret and bounded peer identity are required")
	}
	q := u.Query()
	q.Set("room", cfg.Room)
	q.Set("role", role)
	q.Set("peer", cfg.Peer)
	u.RawQuery = q.Encode()
	d := websocket.Dialer{HandshakeTimeout: 10 * time.Second, EnableCompression: false}
	conn, _, e := d.DialContext(ctx, u.String(), http.Header{"Authorization": []string{"Bearer " + cfg.Secret}})
	if e != nil {
		return nil, e
	}
	wc := &wsConn{c: conn, local: dummyAddr("local"), remote: dummyAddr("relay")}
	if ctx.Done() != nil {
		go func() { <-ctx.Done(); _ = wc.Close() }()
	}
	return wc, nil
}
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type wsConn struct {
	c             *websocket.Conn
	rmu, wmu      sync.Mutex
	buf           []byte
	closed        sync.Once
	local, remote net.Addr
}

func (w *wsConn) Read(p []byte) (int, error) {
	w.rmu.Lock()
	defer w.rmu.Unlock()
	for len(w.buf) == 0 {
		t, b, e := w.c.ReadMessage()
		if e != nil {
			return 0, e
		}
		if t != websocket.BinaryMessage {
			return 0, errors.New("unexpected relay frame")
		}
		w.buf = b
	}
	n := copy(p, w.buf)
	w.buf = w.buf[n:]
	return n, nil
}
func (w *wsConn) Write(p []byte) (int, error) {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	if e := w.c.WriteMessage(websocket.BinaryMessage, p); e != nil {
		return 0, e
	}
	return len(p), nil
}
func (w *wsConn) Close() error {
	var e error
	w.closed.Do(func() {
		e = w.c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
		_ = w.c.Close()
	})
	return e
}
func (w *wsConn) LocalAddr() net.Addr  { return w.local }
func (w *wsConn) RemoteAddr() net.Addr { return w.remote }
func (w *wsConn) SetDeadline(t time.Time) error {
	if e := w.c.SetReadDeadline(t); e != nil {
		return e
	}
	return w.c.SetWriteDeadline(t)
}
func (w *wsConn) SetReadDeadline(t time.Time) error  { return w.c.SetReadDeadline(t) }
func (w *wsConn) SetWriteDeadline(t time.Time) error { return w.c.SetWriteDeadline(t) }

type dummyAddr string

func (a dummyAddr) Network() string { return "websocket" }
func (a dummyAddr) String() string  { return string(a) }

// AcceptRelay waits for the next agent stream at the coordinator side. Reconnect in the caller after errors.
func AcceptRelay(ctx context.Context, cfg RelayConfig) (net.Conn, error) {
	return DialRelay(ctx, cfg, "coordinator")
}

// ServeRelayHTTP keeps a bounded pool of outbound coordinator streams so an
// idle keep-alive or long-running SSE cannot monopolize every other device.
func ServeRelayHTTP(ctx context.Context, cfg RelayConfig, tlsConfig *tls.Config, handler http.Handler) error {
	if tlsConfig == nil {
		return errors.New("TLS config required")
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for ctx.Err() == nil {
				raw, err := AcceptRelay(ctx, cfg)
				if err != nil {
					select {
					case <-ctx.Done():
						return
					case <-time.After(250 * time.Millisecond):
					}
					continue
				}
				srv := &http.Server{Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second}
				finished := make(chan struct{})
				go func() {
					select {
					case <-ctx.Done():
						_ = srv.Close()
						_ = raw.Close()
					case <-finished:
					}
				}()
				_ = srv.Serve(&tlsListener{Conn: raw, cfg: tlsConfig, done: ctx.Done(), closed: make(chan struct{})})
				close(finished)
			}
		}()
	}
	workers.Wait()
	return ctx.Err()
}

type tlsListener struct {
	net.Conn
	cfg    *tls.Config
	mu     sync.Mutex
	used   bool
	done   <-chan struct{}
	closed chan struct{}
}

func (l *tlsListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.used {
		l.mu.Unlock()
		select {
		case <-l.done:
		case <-l.closed:
		}
		return nil, net.ErrClosed
	}
	l.used = true
	l.mu.Unlock()
	return &trackedTLSConn{Conn: tls.Server(l.Conn, l.cfg), closed: l.closed}, nil
}
func (l *tlsListener) Close() error   { return l.Conn.Close() }
func (l *tlsListener) Addr() net.Addr { return l.Conn.LocalAddr() }

type trackedTLSConn struct {
	*tls.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *trackedTLSConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}
