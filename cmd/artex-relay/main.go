package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Autumn-27/artex/collab"
)

type roomsFlag map[string]string

func (r *roomsFlag) String() string { return "room=secret[,room=secret]" }
func (r *roomsFlag) Set(v string) error {
	for _, pair := range strings.Split(v, ",") {
		p := strings.SplitN(pair, "=", 2)
		if len(p) != 2 || p[0] == "" || p[1] == "" {
			return flag.ErrHelp
		}
		(*r)[p[0]] = p[1]
	}
	return nil
}
func main() {
	addr := flag.String("listen", "127.0.0.1:8769", "HTTP listen address (default loopback only)")
	roomsFile := flag.String("rooms-file", "", "private JSON file mapping room names to secrets")
	var rooms roomsFlag = map[string]string{}
	flag.Var(&rooms, "room", "configured room=secret (repeatable)")
	max := flag.Int("max-connections", 128, "maximum active and pending websocket connections")
	payload := flag.Int64("max-payload", 1<<20, "maximum websocket frame size in bytes")
	idle := flag.Duration("idle-timeout", 2*time.Minute, "stream idle timeout and pending pairing timeout")
	flag.Parse()
	if *roomsFile != "" {
		raw, err := os.ReadFile(*roomsFile)
		if err != nil || len(raw) > 64<<10 || json.Unmarshal(raw, &rooms) != nil {
			log.Fatal("invalid room credentials file")
		}
	}
	if len(rooms) == 0 {
		log.Fatal("at least one -room room=secret is required")
	}
	srv := collab.NewRelayServer(collab.RelayOptions{Secrets: rooms, MaxConnections: *max, MaxPayload: *payload, IdleTimeout: *idle})
	log.Printf("ARTEX relay listening on %s; expose only behind a TLS reverse proxy when remote clients need access", *addr)
	httpSrv := &http.Server{Addr: *addr, Handler: srv, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	log.Fatal(httpSrv.ListenAndServe())
}
