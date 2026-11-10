package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/Autumn-27/artex/teamsetup"
)

var setupEnvName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

func readJoinConfig(path string) (teamsetup.JoinConfig, error) {
	var j teamsetup.JoinConfig
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 64<<10 || json.Unmarshal(b, &j) != nil {
		return j, errors.New("join configuration is unavailable or invalid")
	}
	u, err := url.Parse(j.CoordinatorURL)
	if err != nil || j.Schema != 1 || j.TeamID < 1 || j.Version == "" || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || j.ServerName == "" || j.CAFile == "" || len(j.CertificateSHA256) != 64 {
		return j, errors.New("join configuration failed validation")
	}
	if _, err = hex.DecodeString(j.CertificateSHA256); err != nil {
		return j, errors.New("join certificate fingerprint is invalid")
	}
	return j, nil
}

func setupHTTPClient(j teamsetup.JoinConfig, joinPath string) (*http.Client, error) {
	caPath := j.CAFile
	if filepath.IsAbs(caPath) || filepath.Base(caPath) != caPath || caPath == "." || caPath == ".." || strings.ContainsAny(caPath, `/\\`) {
		return nil, errors.New("join CA must be a same-directory filename")
	}
	joinAbs, err := filepath.Abs(joinPath)
	if err != nil {
		return nil, errors.New("join path is invalid")
	}
	joinDir, err := filepath.EvalSymlinks(filepath.Dir(joinAbs))
	if err != nil {
		return nil, errors.New("join directory is unavailable")
	}
	caCandidate := filepath.Join(filepath.Dir(joinAbs), caPath)
	caResolved, err := filepath.EvalSymlinks(caCandidate)
	if err != nil || filepath.Dir(caResolved) != joinDir {
		return nil, errors.New("join CA must resolve within the join directory")
	}
	caPath = caResolved
	pemData, err := os.ReadFile(caPath)
	if err != nil {
		return nil, errors.New("join CA file is unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemData) {
		return nil, errors.New("join CA file is invalid")
	}
	pin, _ := hex.DecodeString(j.CertificateSHA256)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: j.ServerName, RootCAs: roots}
	tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("coordinator certificate is missing")
		}
		h := sha256.Sum256(cs.PeerCertificates[0].Raw)
		if !equalBytes(h[:], pin) {
			return errors.New("coordinator certificate fingerprint mismatch")
		}
		return nil
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
	return &http.Client{Transport: transport, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("coordinator redirects are not allowed") }}, nil
}
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var x byte
	for i := range a {
		x |= a[i] ^ b[i]
	}
	return x == 0
}

func writeSetupConfig(path string, cfg nodeConfig) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".node-setup-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil {
		return err
	}
	if ce != nil {
		return ce
	}
	if _, err = os.Lstat(path); err == nil {
		return errors.New("node config already exists; refusing to replace it")
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.Link(tmp, path)
}

func setupPrompt(r *bufio.Reader, out io.Writer, label string) (string, error) {
	fmt.Fprintf(out, "%s: ", label)
	s, e := r.ReadString('\n')
	return strings.TrimSpace(s), e
}

func runSetup(ctx context.Context, joinPath, configPath, statePath, name string, in io.Reader, out io.Writer) error {
	j, err := readJoinConfig(joinPath)
	if err != nil {
		return err
	}
	c, err := setupHTTPClient(j, joinPath)
	if err != nil {
		return err
	}
	defer c.CloseIdleConnections()
	caFile := j.CAFile
	if !filepath.IsAbs(caFile) {
		caFile = filepath.Join(filepath.Dir(joinPath), caFile)
	}
	caFile, _ = filepath.Abs(caFile)
	// Validate TLS, pinned leaf and coordinator identity before accepting configuration or a pairing code.
	var health struct {
		OK      bool   `json:"ok"`
		Service string `json:"service"`
		Version string `json:"version"`
	}
	if err = request(ctx, c, j.CoordinatorURL, "/api/health", "", nil, &health); err != nil {
		return err
	}
	if !health.OK || health.Service != "artex" || health.Version == "" {
		return errors.New("endpoint did not return a valid ARTEX health response")
	}
	if j.Version != version || j.Version != health.Version {
		return errors.New("node/coordinator version mismatch")
	}
	fmt.Fprintf(out, "Coordinator certificate SHA-256: %s\nVerify this fingerprint against the trusted team administrator before continuing.\n", strings.ToLower(j.CertificateSHA256))
	reader := bufio.NewReader(in)
	verified, e := setupPrompt(reader, out, "Fingerprint verified? type yes to continue (default no)")
	if e != nil && e != io.EOF {
		return e
	}
	if !strings.EqualFold(verified, "yes") {
		return errors.New("coordinator fingerprint was not confirmed")
	}
	stateExists := false
	var deviceID int64
	if _, e := os.Lstat(statePath); e == nil {
		stateExists = true
		var existing deviceState
		b, re := os.ReadFile(statePath)
		if re != nil || len(b) > 1<<20 || json.Unmarshal(b, &existing) != nil || existing.Token == "" || existing.CoordinatorURL != j.CoordinatorURL {
			return errors.New("existing identity belongs to a different coordinator")
		}
		var identity struct {
			Device struct {
				ID     int64 `json:"id"`
				TeamID int64 `json:"team_id"`
			} `json:"device"`
			Version int `json:"protocol_version"`
		}
		var stored struct {
			ID     int64 `json:"id"`
			TeamID int64 `json:"team_id"`
		}
		if json.Unmarshal(existing.Device, &stored) != nil || stored.ID < 1 {
			return errors.New("stored device identity is invalid")
		}
		// Legacy pair states keep team_id inside Device, without the outer field.
		if existing.TeamID == 0 {
			existing.TeamID = stored.TeamID
		}
		if existing.TeamID != j.TeamID {
			return errors.New("existing identity belongs to a different team")
		}
		if request(ctx, c, j.CoordinatorURL, "/api/collaboration/device", existing.Token, nil, &identity) != nil || identity.Device.ID != stored.ID || identity.Device.TeamID != j.TeamID {
			return errors.New("existing identity could not be verified with this coordinator")
		}
		deviceID = stored.ID
		fmt.Fprintln(out, "This node is already paired with the same coordinator; pairing skipped.")
	} else if !os.IsNotExist(e) {
		return errors.New("device identity path is unavailable")
	}
	cfg := nodeConfig{CoordinatorURL: j.CoordinatorURL, ServerName: j.ServerName, CAFile: caFile, SPKIPin: "", LANAddresses: j.LANAddresses, RelayURL: j.RelayURL, RelayRoom: j.RelayRoom, RelayPeer: j.RelayPeer, RelaySecretEnv: j.RelaySecretEnv}
	existingConfig := false
	if old, e := os.ReadFile(configPath); e == nil {
		var prior nodeConfig
		if len(old) > 64<<10 || json.Unmarshal(old, &prior) != nil || prior.CoordinatorURL != j.CoordinatorURL || (prior.ServerName != "" && prior.ServerName != j.ServerName) {
			return errors.New("existing node config does not match this coordinator; refusing overwrite")
		}
		priorCA := prior.CAFile
		if !filepath.IsAbs(priorCA) {
			priorCA = filepath.Join(filepath.Dir(configPath), priorCA)
		}
		priorCA, _ = filepath.Abs(priorCA)
		if priorCA != caFile {
			return errors.New("existing node CA does not match the join bundle; refusing overwrite")
		}
		cfg = prior
		cfg.CAFile = priorCA
		existingConfig = true
	} else if !os.IsNotExist(e) {
		return errors.New("node config is unavailable")
	}
	if stateExists && !existingConfig {
		return errors.New("existing identity has no matching node configuration; preserve it and restore its original node.json before setup")
	}
	r := reader
	choice := "1"
	if !existingConfig {
		fmt.Fprintln(out, "Choose: 1) connection only  2) configure independent pentest and reverse roles")
		choice, e = setupPrompt(r, out, "Selection (default 1)")
		if e != nil && e != io.EOF {
			return e
		}
		if choice == "" {
			choice = "1"
		}
	}
	if choice == "2" {
		fmt.Fprintln(out, "The templates contain no external tool authorization. Model credentials stay in this process.")
		key, e := setupPrompt(r, out, "Model id")
		if e != nil {
			return errors.New("model configuration incomplete")
		}
		if !nodeSafeName.MatchString(key) {
			return errors.New("invalid model id")
		}
		endpoint, e := setupPrompt(r, out, "Model endpoint (HTTPS; or HTTP on localhost/loopback)")
		if e != nil {
			return errors.New("model configuration incomplete")
		}
		eu, pe := url.Parse(endpoint)
		localHTTP := pe == nil && eu.Scheme == "http" && (strings.EqualFold(eu.Hostname(), "localhost") || (net.ParseIP(eu.Hostname()) != nil && net.ParseIP(eu.Hostname()).IsLoopback()))
		if pe != nil || (eu.Scheme != "https" && !localHTTP) || eu.Host == "" || eu.User != nil || eu.RawQuery != "" || eu.Fragment != "" {
			return errors.New("model endpoint must be HTTPS, or local loopback HTTP, with no userinfo/query/fragment")
		}
		model, e := setupPrompt(r, out, "Provider model name")
		if e != nil || model == "" {
			return errors.New("model configuration incomplete")
		}
		format, e := setupPrompt(r, out, "Format (openai, anthropic, openai-responses)")
		if e != nil {
			return e
		}
		if format != "openai" && format != "anthropic" && format != "openai-responses" {
			return errors.New("unsupported model format")
		}
		envName, e := setupPrompt(r, out, "API key env name (ARTEX_NODE_MODEL_KEY or ARTEX_NODE_<NAME>_API_KEY)")
		if e != nil || !validSetupKeyEnv(envName) {
			return errors.New("invalid API key environment variable name")
		}
		if _, exists := os.LookupEnv(envName); !exists {
			secret, se := readSetupSecret(r, in, out)
			if se != nil || secret == "" {
				return errors.New("model credential was not provided")
			}
			if err = os.Setenv(envName, secret); err != nil {
				return errors.New("could not set model credential for this process")
			}
			secret = ""
		}
		kind, e := setupPrompt(r, out, "Role set (pentest or reverse)")
		if e != nil || (kind != "pentest" && kind != "reverse") {
			return errors.New("choose pentest or reverse roles")
		}
		roles := map[string]localRoleConfig{}
		if kind == "pentest" {
			for _, role := range []string{"planner", "worker", "reviewer"} {
				roles[role] = localRoleConfig{Model: key, Capabilities: []string{}}
			}
		} else {
			for _, role := range []string{"reverse_planner", "reverse_static", "reverse_reviewer"} {
				roles[role] = localRoleConfig{Model: key, Capabilities: []string{}}
			}
		}
		work, _ := filepath.Abs("node-work")
		outbox, _ := filepath.Abs("node-outbox")
		cfg.Execution = &localExecutionConfig{Roles: roles, Models: map[string]localModelConfig{key: {Endpoint: endpoint, APIKeyEnv: envName, Model: model, Format: format}}, Commands: map[string]localCommandConfig{}, Branches: localBranchConfig{Enabled: true}, WorkDir: work, OutboxDir: outbox}
		if err = cfg.Execution.validate(); err != nil {
			return err
		}
	} else if choice != "1" {
		return errors.New("invalid setup choice")
	}
	if cfg.Execution != nil {
		if err = cfg.Execution.validate(); err != nil {
			return fmt.Errorf("local execution configuration is invalid: %w", err)
		}
		if !filepath.IsAbs(cfg.Execution.WorkDir) || !filepath.IsAbs(cfg.Execution.OutboxDir) {
			return errors.New("execution work_dir and outbox_dir must be absolute")
		}
		for id, m := range cfg.Execution.Models {
			if !validSetupKeyEnv(m.APIKeyEnv) && os.Getenv(m.APIKeyEnv) == "" {
				return fmt.Errorf("model %s: set its existing credential environment variable locally before setup; automatic secret input only supports ARTEX_NODE_*_API_KEY", id)
			}
			if os.Getenv(m.APIKeyEnv) == "" {
				fmt.Fprintf(out, "Model %s needs environment variable %s.\n", id, m.APIKeyEnv)
				secret, se := readSetupSecret(r, in, out)
				if se != nil || secret == "" {
					return errors.New("model credential was not provided; no pairing was attempted")
				}
				if !validSetupKeyEnv(m.APIKeyEnv) {
					return errors.New("configured model credential environment variable is not permitted")
				}
				if _, exists := os.LookupEnv(m.APIKeyEnv); exists {
					return errors.New("refusing to overwrite existing model key environment variable")
				}
				if err = os.Setenv(m.APIKeyEnv, secret); err != nil {
					return errors.New("could not set model key for this process")
				}
				secret = ""
			}
		}
	}
	if !stateExists {
		if err = preflightStatePath(statePath); err != nil {
			return err
		}
	}
	if !existingConfig {
		if err = writeSetupConfig(configPath, cfg); err != nil {
			return err
		}
	}
	if !stateExists {
		fmt.Fprintln(out, "Configuration validated and saved. Enter the one-time pairing code (retry setup if pairing fails).")
		token, e := readSetupSecret(r, in, out)
		if e != nil || token == "" {
			return errors.New("pairing code was not provided")
		}
		deviceName := name
		if deviceName == "" {
			deviceName, _ = os.Hostname()
		}
		var response struct {
			Device json.RawMessage `json:"device"`
			Token  string          `json:"device_token"`
		}
		input := map[string]any{"pairing_token": token, "name": deviceName, "capabilities": map[string]any{"os": runtime.GOOS, "arch": runtime.GOARCH, "execution_enabled": false}}
		if err = request(ctx, c, j.CoordinatorURL, "/api/collaboration/pair", "", input, &response); err != nil {
			return err
		}
		if response.Token == "" || !json.Valid(response.Device) {
			return errors.New("coordinator returned invalid device identity")
		}
		var d struct {
			ID     int64 `json:"id"`
			TeamID int64 `json:"team_id"`
		}
		_ = json.Unmarshal(response.Device, &d)
		if d.ID < 1 || d.TeamID != j.TeamID {
			return errors.New("coordinator returned a device for a different team or without a valid id; ask the administrator to revoke it and issue the correct team's code")
		}
		if err = saveState(statePath, deviceState{CoordinatorURL: j.CoordinatorURL, TeamID: j.TeamID, Token: response.Token, Device: response.Device}); err != nil {
			if retryErr := saveState(statePath, deviceState{CoordinatorURL: j.CoordinatorURL, TeamID: j.TeamID, Token: response.Token, Device: response.Device}); retryErr != nil {
				return fmt.Errorf("pairing succeeded for device %d but identity could not be saved; keep this directory writable and rerun setup with a newly issued pairing code: %w", d.ID, retryErr)
			}
		}
		deviceID = d.ID
	}
	fmt.Fprintf(out, "Setup complete for device %d.\n", deviceID)
	if cfg.Execution == nil {
		fmt.Fprintln(out, "Connection is ready; no execution roles are configured, so no work will run.")
		return nil
	}
	fmt.Fprintln(out, "Starting run can execute assigned work. Type yes to start now; default is no.")
	start, e := setupPrompt(r, out, "Start run now? (default no)")
	if e != nil && e != io.EOF {
		return e
	}
	if !strings.EqualFold(start, "yes") {
		fmt.Fprintln(out, "Run was not started. When ready, run artex-node run.")
		return nil
	}
	// Use the ordinary LAN-first/Relay-fallback transport for actual execution.
	runClient, dialer, err := clientFor(cfg)
	if err != nil {
		return err
	}
	defer dialer.CloseIdleConnections()
	return runAssignments(ctx, *cfg.Execution, statePath, cfg.CoordinatorURL, runClient, out, false)
}

func validSetupKeyEnv(s string) bool {
	return s == "ARTEX_NODE_MODEL_KEY" || (strings.HasPrefix(s, "ARTEX_NODE_") && strings.HasSuffix(s, "_API_KEY") && setupEnvName.MatchString(s) && len(s) > len("ARTEX_NODE__API_KEY"))
}

func preflightStatePath(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return errors.New("device identity already exists")
	} else if !os.IsNotExist(err) {
		return errors.New("device identity path is unavailable")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("device identity directory cannot be created")
	}
	f, err := os.CreateTemp(dir, ".artex-state-check-*")
	if err != nil {
		return errors.New("device identity directory is not writable; fix permissions before pairing")
	}
	n := f.Name()
	_ = f.Close()
	_ = os.Remove(n)
	return nil
}
