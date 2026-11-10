// Package teamsetup implements deterministic, local team onboarding operations.
// AI advice is deliberately outside this package and never executes commands.
package teamsetup

type JoinConfig struct {
	Schema            int      `json:"schema"`
	TeamID            int64    `json:"team_id"`
	Version           string   `json:"version"`
	CoordinatorURL    string   `json:"coordinator_url"`
	ServerName        string   `json:"server_name"`
	CAFile            string   `json:"ca_file"`
	CertificateSHA256 string   `json:"certificate_sha256"`
	LANAddresses      []string `json:"lan_addresses"`
	RelayURL          string   `json:"relay_url,omitempty"`
	RelayRoom         string   `json:"relay_room,omitempty"`
	RelayPeer         string   `json:"relay_peer,omitempty"`
	RelaySecretEnv    string   `json:"relay_secret_env,omitempty"`
}

type Address struct {
	IP        string `json:"ip"`
	Interface string `json:"interface"`
	CIDR      string `json:"cidr"`
	Host      bool   `json:"host"` // Windows host address detected from WSL.
}
type Environment struct {
	OS        string    `json:"os"`
	Arch      string    `json:"arch"`
	WSL       bool      `json:"wsl"`
	Distro    string    `json:"distro,omitempty"`
	Addresses []Address `json:"addresses"`
}
type Input struct {
	BindIP      string `json:"bind_ip"`
	PublicIP    string `json:"public_ip"`
	Port        int    `json:"port"`
	AllowedCIDR string `json:"allowed_cidr"`
}
type Plan struct {
	ID              string   `json:"id"`
	Input           Input    `json:"input"`
	Origin          string   `json:"origin"`
	Steps           []string `json:"steps"`
	NeedsHostBridge bool     `json:"needs_host_bridge"`
	ExpiresAt       string   `json:"expires_at"`
}
type State struct {
	Enabled          bool   `json:"enabled"`
	External         bool   `json:"external"`
	Origin           string `json:"origin,omitempty"`
	ListenAddress    string `json:"listen_address,omitempty"`
	AllowedCIDR      string `json:"allowed_cidr,omitempty"`
	Fingerprint      string `json:"fingerprint,omitempty"`
	ExpiresAt        string `json:"expires_at,omitempty"`
	NeedsHostBridge  bool   `json:"needs_host_bridge"`
	LocalTLSVerified bool   `json:"local_tls_verified"`
	Error            string `json:"error,omitempty"`
}
type NodeBinary struct {
	Platform string `json:"platform"`
	File     string `json:"file"`
	SHA256   string `json:"sha256"`
}
type BinaryManifest struct {
	Version  string       `json:"version"`
	Binaries []NodeBinary `json:"binaries"`
}
