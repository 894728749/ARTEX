package teamsetup

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testController(t *testing.T) *Controller {
	t.Helper()
	c := New(t.Context(), filepath.Join(t.TempDir(), "access"), t.TempDir(), "fixture", Environment{OS: "linux", Arch: "amd64", Addresses: []Address{{IP: "192.168.50.4", CIDR: "192.168.50.0/24"}}}, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/health" {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, `{"ok":true,"service":"artex","version":"fixture"}`)
	}))
	// Bind only loopback while exercising real TLS, persistence and source filters.
	c.listen = func(string, string) (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }
	t.Cleanup(c.Close)
	return c
}
func testInput() Input {
	return Input{BindIP: "192.168.50.4", PublicIP: "192.168.50.4", Port: 18789, AllowedCIDR: "192.168.50.0/24"}
}
func enableTestController(t *testing.T, c *Controller) State {
	t.Helper()
	p, err := c.Prepare(1, testInput())
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.Apply(t.Context(), 1, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func TestManagedAccessPlanApplyRestoreDisable(t *testing.T) {
	c := testController(t)
	p, err := c.Prepare(1, testInput())
	if err != nil {
		t.Fatal(err)
	}
	if c.State().Enabled {
		t.Fatal("preview mutated listener")
	}
	if _, err = os.Stat(c.dir); !os.IsNotExist(err) {
		t.Fatal("preview wrote state")
	}
	if _, err = c.Apply(t.Context(), 2, p.ID); err == nil {
		t.Fatal("cross-team plan accepted")
	}
	s, err := c.Apply(t.Context(), 1, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Enabled || !s.LocalTLSVerified || len(s.Fingerprint) != 64 {
		t.Fatalf("bad state %+v", s)
	}
	before, err := os.ReadFile(filepath.Join(c.dir, "access.json"))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	c.state = State{}
	c.restore(t.Context())
	if !c.State().Enabled || c.State().Fingerprint != s.Fingerprint {
		t.Fatalf("restart lost trust: %+v", c.State())
	}
	if _, err = c.Disable(); err != nil {
		t.Fatal(err)
	}
	if c.State().Enabled {
		t.Fatal("disable did not close")
	}
	c.state = State{}
	c.restore(t.Context())
	if c.State().Enabled {
		t.Fatal("disabled listener restored")
	}
	next := enableTestController(t, c)
	if next.Fingerprint != s.Fingerprint {
		t.Fatal("disable unexpectedly rotated certificate")
	}
	var saved savedAccess
	_ = json.Unmarshal(before, &saved)
	if len(saved.PrivateKey) == 0 {
		t.Fatal("state missing key")
	}
}
func TestManagedAccessFailsClosed(t *testing.T) {
	for _, name := range []string{"persistence", "health", "expired_plan", "untrusted_input", "external"} {
		t.Run(name, func(t *testing.T) {
			c := testController(t)
			switch name {
			case "untrusted_input":
				for _, in := range []Input{{BindIP: "0.0.0.0", PublicIP: "192.168.50.4", Port: 18789, AllowedCIDR: "192.168.50.0/24"}, {BindIP: "192.168.50.4", PublicIP: "192.168.50.4", Port: 18789, AllowedCIDR: "0.0.0.0/0"}, {BindIP: "192.168.50.4", PublicIP: "8.8.8.8", Port: 18789, AllowedCIDR: "192.168.50.0/24"}} {
					if _, err := c.Prepare(1, in); err == nil {
						t.Fatal("unsafe plan accepted")
					}
				}
				return
			case "external":
				c.external = true
				if _, err := c.Prepare(1, testInput()); err == nil {
					t.Fatal("CLI entry overwritten")
				}
				if _, err := c.Disable(); err == nil {
					t.Fatal("CLI disabled")
				}
				return
			case "persistence":
				if err := os.WriteFile(c.dir, []byte("cannot be directory"), 0600); err != nil {
					t.Fatal(err)
				}
			case "health":
				c.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 500) })
			}
			var last net.Listener
			c.listen = func(string, string) (net.Listener, error) {
				var err error
				last, err = net.Listen("tcp", "127.0.0.1:0")
				return last, err
			}
			p, err := c.Prepare(1, testInput())
			if err != nil {
				t.Fatal(err)
			}
			if name == "expired_plan" {
				old := c.plans[p.ID]
				old.ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
				c.plans[p.ID] = old
			}
			if _, err = c.Apply(t.Context(), 1, p.ID); err == nil {
				t.Fatal("failure reported success")
			}
			if c.State().Enabled {
				t.Fatal("failure left enabled")
			}
			if last != nil {
				conn, err := net.DialTimeout("tcp", last.Addr().String(), time.Second)
				if err == nil {
					conn.Close()
					t.Fatal("failed apply left listener open")
				}
			}
		})
	}
}
func TestBundleContentsAndTamper(t *testing.T) {
	c := testController(t)
	s := enableTestController(t, c)
	binary := []byte("fixture node executable")
	sum := sha256.Sum256(binary)
	os.WriteFile(filepath.Join(c.binaryDir, "node-fixture"), binary, 0700)
	manifest, _ := json.Marshal(BinaryManifest{Version: "fixture", Binaries: []NodeBinary{{Platform: "linux-amd64", File: "node-fixture", SHA256: hex.EncodeToString(sum[:])}}})
	os.WriteFile(filepath.Join(c.binaryDir, "manifest.json"), manifest, 0600)
	b, err := c.Bundle(42, "linux-amd64")
	if err != nil {
		t.Fatal(err)
	}
	z, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string][]byte{}
	for _, f := range z.File {
		r, _ := f.Open()
		v, _ := io.ReadAll(r)
		r.Close()
		entries[f.Name] = v
		if bytes.Contains(v, []byte("PRIVATE KEY")) || bytes.Contains(v, []byte("device_token")) {
			t.Fatal("bundle contains secret")
		}
	}
	var join JoinConfig
	if json.Unmarshal(entries["join.json"], &join) != nil || join.TeamID != 42 || join.CertificateSHA256 != s.Fingerprint {
		t.Fatal("wrong join contract")
	}
	if !bytes.Equal(entries["artex-node"], binary) || !strings.Contains(string(entries["connect.sh"]), "-join join.json setup") {
		t.Fatal("missing startup resources")
	}
	os.WriteFile(filepath.Join(c.binaryDir, "node-fixture"), []byte("modified"), 0700)
	if _, err = c.Bundle(42, "linux-amd64"); err == nil {
		t.Fatal("tampered node accepted")
	}
}
func TestHostBridgeScriptBoundedAndPreview(t *testing.T) {
	c := testController(t)
	c.env.WSL = true
	c.env.Addresses = append(c.env.Addresses, Address{IP: "192.168.60.2", CIDR: "192.168.60.0/24", Host: true})
	in := testInput()
	in.PublicIP = "192.168.60.2"
	in.AllowedCIDR = "192.168.60.0/24"
	p, err := c.Prepare(1, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Apply(t.Context(), 1, p.ID); err != nil {
		t.Fatal(err)
	}
	script, err := c.HostScript()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"if (-not $Apply -and -not $Remove)", "192.168.60.0/24", "listenaddress=$listenIP", "-Profile Private,Domain", "No matching ownership record", "Existing rule or ownership record"} {
		if !strings.Contains(string(script), want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Contains(string(script), "0.0.0.0") || strings.Contains(string(script), "Invoke-Expression") {
		t.Fatal("overbroad host script")
	}
	if out := os.Getenv("ARTEX_HOST_SCRIPT_TEST_OUTPUT"); out != "" {
		if err = os.WriteFile(out, script, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
func TestRestoreInvalidSettingsDoesNotListen(t *testing.T) {
	c := testController(t)
	os.MkdirAll(c.dir, 0700)
	os.WriteFile(filepath.Join(c.dir, "access.json"), []byte("broken"), 0600)
	c.restore(context.Background())
	if c.State().Enabled || c.State().Error == "" {
		t.Fatal("invalid saved config not reported")
	}
}
