package collab

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type RelayOptions struct {
	Secrets        map[string]string
	MaxConnections int
	MaxPayload     int64
	IdleTimeout    time.Duration
	PendingPerRoom int
}
type relayPair struct {
	ws               *websocket.Conn
	room, role, peer string
	ready            chan *relayPair
}
type RelayServer struct {
	opts    RelayOptions
	up      websocket.Upgrader
	mu      sync.Mutex
	waiting map[string]map[string][]*relayPair
	sem     chan struct{}
}

// NewRelayServer accepts only configured room credentials and pairs coordinator/agent streams.
// It has no TCP dial API and therefore cannot be used as an arbitrary destination proxy.
func NewRelayServer(o RelayOptions) *RelayServer {
	if o.MaxConnections <= 0 {
		o.MaxConnections = 128
	}
	if o.MaxPayload <= 0 {
		o.MaxPayload = 1 << 20
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = 2 * time.Minute
	}
	if o.PendingPerRoom <= 0 {
		o.PendingPerRoom = 16
	}
	return &RelayServer{opts: o, up: websocket.Upgrader{ReadBufferSize: 4096, WriteBufferSize: 4096, CheckOrigin: func(*http.Request) bool { return true }}, waiting: map[string]map[string][]*relayPair{}, sem: make(chan struct{}, o.MaxConnections)}
}
func (s *RelayServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/tunnel" {
		http.NotFound(w, r)
		return
	}
	room, role, peerID := r.URL.Query().Get("room"), r.URL.Query().Get("role"), r.URL.Query().Get("peer")
	for key := range r.URL.Query() {
		switch strings.ToLower(key) {
		case "room", "role", "peer":
		default:
			http.Error(w, "unexpected URL query parameter", 400)
			return
		}
	}
	auth, _, hasBearer := strings.Cut(r.Header.Get("Authorization"), " ")
	if !hasBearer || !strings.EqualFold(auth, "Bearer") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	secret := strings.TrimSpace(r.Header.Get("Authorization")[len(auth)+1:])
	expected, ok := s.opts.Secrets[room]
	if !ok || secret == "" || len(secret) > 4096 || !constantSecretEqual(expected, secret) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if role != "agent" && role != "coordinator" {
		http.Error(w, "invalid role", 400)
		return
	}
	if peerID == "" || len(peerID) > 128 {
		http.Error(w, "invalid peer identity", 400)
		return
	}
	select {
	case s.sem <- struct{}{}:
	default:
		http.Error(w, "relay capacity reached", http.StatusServiceUnavailable)
		return
	}
	defer func() { <-s.sem }()
	ws, e := s.up.Upgrade(w, r, nil)
	if e != nil {
		return
	}
	ws.SetReadLimit(s.opts.MaxPayload)
	p := &relayPair{ws: ws, room: room, role: role, peer: peerID, ready: make(chan *relayPair, 1)}
	peer := s.pairOrQueue(p)
	if peer == nil {
		defer s.removeWaiting(p)
		timer := time.NewTimer(s.opts.IdleTimeout)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			_ = ws.Close()
			return
		case <-timer.C:
			_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(1013, "pair timeout"), time.Now().Add(time.Second))
			_ = ws.Close()
			return
		case <-p.ready:
			// The arriving peer owns the single bridge; leave this upgraded socket open for it.
			return
		}
	}
	if peer == nil {
		return
	}
	defer ws.Close()
	defer peer.ws.Close()
	s.bridge(ws, peer.ws)
}

func (s *RelayServer) pairOrQueue(p *relayPair) *relayPair {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := p.room + "\x00" + p.peer
	if s.waiting[key] == nil {
		s.waiting[key] = map[string][]*relayPair{}
	}
	other := "agent"
	if p.role == "agent" {
		other = "coordinator"
	}
	q := s.waiting[key][other]
	if len(q) > 0 {
		peer := q[0]
		s.waiting[key][other] = q[1:]
		peer.ready <- p
		if len(s.waiting[key][other]) == 0 && len(s.waiting[key][p.role]) == 0 {
			delete(s.waiting, key)
		}
		return peer
	}
	own := s.waiting[key][p.role]
	if len(own) >= s.opts.PendingPerRoom {
		return nil
	}
	s.waiting[key][p.role] = append(own, p)
	return nil
}
func (s *RelayServer) removeWaiting(p *relayPair) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.waiting[p.room+"\x00"+p.peer][p.role]
	for i, x := range q {
		if x == p {
			s.waiting[p.room+"\x00"+p.peer][p.role] = append(q[:i], q[i+1:]...)
			break
		}
	}
	for role, queue := range s.waiting[p.room+"\x00"+p.peer] {
		if len(queue) == 0 {
			delete(s.waiting[p.room+"\x00"+p.peer], role)
		}
	}
	if len(s.waiting[p.room+"\x00"+p.peer]) == 0 {
		delete(s.waiting, p.room+"\x00"+p.peer)
	}
}
func (s *RelayServer) bridge(a, b *websocket.Conn) {
	done := make(chan struct{}, 2)
	pump := func(dst, src *websocket.Conn) {
		defer func() { done <- struct{}{} }()
		for {
			_ = src.SetReadDeadline(time.Now().Add(s.opts.IdleTimeout))
			typ, p, e := src.ReadMessage()
			if e != nil {
				return
			}
			if typ != websocket.BinaryMessage {
				return
			}
			_ = dst.SetWriteDeadline(time.Now().Add(s.opts.IdleTimeout))
			if e = dst.WriteMessage(websocket.BinaryMessage, p); e != nil {
				return
			}
		}
	}
	go pump(a, b)
	go pump(b, a)
	<-done
	closeFrame := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
	_ = a.WriteControl(websocket.CloseMessage, closeFrame, time.Now().Add(time.Second))
	_ = b.WriteControl(websocket.CloseMessage, closeFrame, time.Now().Add(time.Second))
}
func constantSecretEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var d byte
	for i := range a {
		d |= a[i] ^ b[i]
	}
	return d == 0
}
