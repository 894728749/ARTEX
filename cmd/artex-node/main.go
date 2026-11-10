// artex-node pairs a device with one team coordinator. It does not start a
// second coordinator or access PostgreSQL on the member's machine.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/collab"
)

var version = "dev"

type nodeConfig struct {
	CoordinatorURL string                `json:"coordinator_url"`
	ServerName     string                `json:"server_name"`
	CAFile         string                `json:"ca_file"`
	SPKIPin        string                `json:"spki_pin"`
	LANAddresses   []string              `json:"lan_addresses"`
	RelayURL       string                `json:"relay_url"`
	RelayRoom      string                `json:"relay_room"`
	RelayPeer      string                `json:"relay_peer"`
	RelaySecretEnv string                `json:"relay_secret_env"`
	Execution      *localExecutionConfig `json:"execution,omitempty"`
}
type deviceState struct {
	CoordinatorURL string          `json:"coordinator_url"`
	TeamID         int64           `json:"team_id"`
	Token          string          `json:"device_token"`
	Device         json.RawMessage `json:"device"`
}

func clientFor(c nodeConfig) (*http.Client, *collab.HybridDialer, error) {
	u, err := url.Parse(c.CoordinatorURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, nil, errors.New("coordinator_url must be an HTTPS origin")
	}
	var roots *x509.CertPool
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, nil, errors.New("could not read CA file")
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, nil, errors.New("invalid CA file")
		}
	}
	name := c.ServerName
	if name == "" {
		name = u.Hostname()
	}
	addresses := c.LANAddresses
	if len(addresses) == 0 {
		address := u.Host
		if u.Port() == "" {
			address = net.JoinHostPort(u.Hostname(), "443")
		}
		addresses = []string{address}
	}
	candidates := []collab.Candidate{}
	for _, address := range addresses {
		candidates = append(candidates, collab.Candidate{Address: address, ServerName: name, RootCAs: roots, SPKIPin: c.SPKIPin})
	}
	relay := collab.RelayConfig{URL: c.RelayURL, Room: c.RelayRoom, Peer: c.RelayPeer}
	if c.RelayURL != "" {
		if c.RelaySecretEnv == "" {
			return nil, nil, errors.New("relay_secret_env is required")
		}
		relay.Secret = os.Getenv(c.RelaySecretEnv)
		if relay.Secret == "" {
			return nil, nil, errors.New("relay secret environment variable is missing")
		}
	}
	d := collab.NewHybridDialer(collab.HybridConfig{Candidates: candidates, Relay: relay, TLS: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name, RootCAs: roots}, Timeout: 5 * time.Second})
	return &http.Client{Transport: d.RoundTripper(), Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("coordinator redirects are not allowed") }}, d, nil
}

func request(ctx context.Context, client *http.Client, origin, path, token string, input, output any) error {
	var body []byte
	var err error
	method := "GET"
	if input != nil {
		method = "POST"
		body, err = json.Marshal(input)
		if err != nil {
			return err
		}
	}
	r, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(origin, "/")+path, bytes.NewReader(body))
	if err != nil {
		return errors.New("invalid coordinator request")
	}
	if input != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(r)
	if err != nil {
		return &nodeConnectionError{cause: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &nodeHTTPError{Code: resp.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return errors.New("invalid coordinator response size")
	}
	if len(data) == 0 || output == nil {
		return nil
	}
	return json.Unmarshal(data, output)
}

type nodeConnectionError struct{ cause error }

func (e *nodeConnectionError) Error() string {
	return "coordinator connection failed; check TLS, LAN and relay configuration"
}
func (e *nodeConnectionError) Unwrap() error { return e.cause }

func saveState(path string, state deviceState) error {
	if _, err := os.Lstat(path); err == nil {
		return errors.New("device state already exists; refusing to replace identity")
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".artex-node-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	// Link refuses an existing target atomically, including concurrent pairing.
	if err = os.Link(tmp, path); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		directory, err := os.Open(filepath.Dir(path))
		if err != nil {
			return err
		}
		defer directory.Close()
		if err = directory.Sync(); err != nil {
			return err
		}
	}
	return nil
}

func run(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	flags := flag.NewFlagSet("artex-node", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "node.json", "coordinator connection configuration")
	statePath := flags.String("state", "node-state/identity.json", "private device identity file")
	name := flags.String("name", "", "device display name")
	showVersion := flags.Bool("version", false, "print node build and protocol versions")
	joinPath := flags.String("join", "join.json", "team onboarding join configuration")
	if err := flags.Parse(args); err != nil {
		return errors.New("usage: artex-node [-version] -config node.json -state node-state/identity.json [-name device] check|pair|status|run|run-once")
	}
	if *showVersion {
		fmt.Fprintf(out, "artex-node %s (device protocol 1, branch protocol 1)\n", version)
		return nil
	}
	if flags.NArg() != 1 {
		return errors.New("choose setup, check, pair, status, run, or run-once")
	}
	if flags.Arg(0) == "setup" {
		return runSetup(ctx, *joinPath, *configPath, *statePath, *name, in, out)
	}
	data, err := os.ReadFile(*configPath)
	if err != nil {
		return errors.New("could not read node config")
	}
	var config nodeConfig
	if len(data) > 64<<10 || json.Unmarshal(data, &config) != nil {
		return errors.New("invalid node config")
	}
	client, dialer, err := clientFor(config)
	if err != nil {
		return err
	}
	defer dialer.CloseIdleConnections()
	switch flags.Arg(0) {
	case "check":
		// Inspection only: never pair, claim work, start tools or call a model.
		if config.Execution != nil {
			if err = config.Execution.validate(); err != nil {
				return err
			}
			if (config.Execution.WorkDir != "" && !filepath.IsAbs(config.Execution.WorkDir)) || (config.Execution.OutboxDir != "" && !filepath.IsAbs(config.Execution.OutboxDir)) {
				return errors.New("execution work_dir and outbox_dir must be absolute")
			}
			roles := []string{}
			for role, binding := range config.Execution.Roles {
				model := config.Execution.Models[binding.Model]
				if os.Getenv(model.APIKeyEnv) == "" {
					return fmt.Errorf("role %s: model credential environment variable is missing", role)
				}
				if config.Execution.Branches.Enabled && role != "planner" && role != "reverse_planner" {
					planner := "planner"
					if strings.HasPrefix(role, "reverse_") {
						planner = "reverse_planner"
					}
					if _, ok := config.Execution.Roles[planner]; !ok {
						return fmt.Errorf("role %s needs a local %s binding", role, planner)
					}
					for _, capability := range binding.Capabilities {
						if capability != "read_material" && capability != "reverse_observe_runtime" && len(config.Execution.Branches.ScopeFields[capability]) == 0 {
							return fmt.Errorf("capability %s needs branches.scope_fields", capability)
						}
					}
				}
				roles = append(roles, role)
			}
			sort.Strings(roles)
			fmt.Fprintf(out, "Local roles validated: %s; branch protocol enabled: %t. Models and tools were not invoked.\n", strings.Join(roles, ", "), config.Execution.Branches.Enabled)
		} else {
			fmt.Fprintln(out, "Connection-only configuration; execution is not enabled.")
		}
		var health struct {
			OK      bool   `json:"ok"`
			Service string `json:"service"`
			Version string `json:"version"`
		}
		if err = request(ctx, client, config.CoordinatorURL, "/api/health", "", nil, &health); err != nil {
			return err
		}
		if !health.OK || health.Service != "artex" || health.Version == "" {
			return errors.New("endpoint did not return a valid ARTEX health response")
		}
		fmt.Fprintf(out, "TLS verified; route: %s; coordinator: %s; node: %s. No identity or work was changed.\n", dialer.TransportStatus().Route, health.Version, version)
		if version != "dev" && version != health.Version {
			fmt.Fprintln(out, "Version mismatch: use a node built from the same release as the coordinator before enabling execution.")
		}
	case "pair":
		if _, err := os.Lstat(*statePath); !os.IsNotExist(err) {
			return errors.New("device state already exists or is unreadable")
		}
		token := strings.TrimSpace(os.Getenv("ARTEX_PAIRING_TOKEN"))
		if token == "" {
			fmt.Fprintln(out, "Enter the one-time pairing code:")
			scan := bufio.NewScanner(io.LimitReader(in, 4096))
			if scan.Scan() {
				token = strings.TrimSpace(scan.Text())
			}
		}
		if token == "" || len(token) > 1000 {
			return errors.New("missing or invalid pairing code")
		}
		deviceName := *name
		if deviceName == "" {
			deviceName, _ = os.Hostname()
		}
		var response struct {
			Device json.RawMessage `json:"device"`
			Token  string          `json:"device_token"`
		}
		input := map[string]any{"pairing_token": token, "name": deviceName, "capabilities": map[string]any{"os": runtime.GOOS, "arch": runtime.GOARCH, "execution_enabled": false}}
		if err = request(ctx, client, config.CoordinatorURL, "/api/collaboration/pair", "", input, &response); err != nil {
			return err
		}
		if response.Token == "" || !json.Valid(response.Device) {
			return errors.New("coordinator returned invalid device identity")
		}
		if err = saveState(*statePath, deviceState{CoordinatorURL: config.CoordinatorURL, Token: response.Token, Device: response.Device}); err != nil {
			return err
		}
		fmt.Fprintln(out, "Device paired. Private identity saved; remote execution is not enabled.")
	case "status":
		info, err := os.Lstat(*statePath)
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("device identity file unavailable")
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
			return errors.New("device identity must be private (chmod 600)")
		}
		data, err := os.ReadFile(*statePath)
		var state deviceState
		if err != nil || len(data) > 1<<20 || json.Unmarshal(data, &state) != nil || state.Token == "" || state.CoordinatorURL != config.CoordinatorURL {
			return errors.New("device identity does not match this coordinator")
		}
		var response struct {
			Device struct {
				ID   int64  `json:"id"`
				Name string `json:"name"`
			} `json:"device"`
			Version   int  `json:"protocol_version"`
			Available bool `json:"remote_execution_available"`
		}
		if err = request(ctx, client, config.CoordinatorURL, "/api/collaboration/device", state.Token, nil, &response); err != nil {
			return err
		}
		fmt.Fprintf(out, "Device %d (%s): authenticated, protocol %d, remote execution available: %t\n", response.Device.ID, response.Device.Name, response.Version, response.Available)
	case "run", "run-once":
		if config.Execution == nil {
			return errors.New("execution configuration is required")
		}
		return runAssignments(ctx, *config.Execution, *statePath, config.CoordinatorURL, client, out, flags.Arg(0) == "run-once")
	default:
		return errors.New("choose check, pair, status, run, or run-once")
	}
	return nil
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
