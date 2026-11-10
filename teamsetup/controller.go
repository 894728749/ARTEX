package teamsetup

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

type savedAccess struct {
	Enabled     bool   `json:"enabled"`
	Input       Input  `json:"input"`
	Certificate []byte `json:"certificate"`
	PrivateKey  []byte `json:"private_key"`
}
type preparedPlan struct {
	Plan
	Team int64
}
type Controller struct {
	mu                      sync.Mutex
	dir, binaryDir, version string
	env                     Environment
	handler                 http.Handler
	external                bool
	plans                   map[string]preparedPlan
	saved                   savedAccess
	state                   State
	server                  *http.Server
	listen                  func(string, string) (net.Listener, error)
}

// New restores only managed settings. Explicit CLI TLS/Relay always owns its entry.
// Restore failures leave the ordinary administration listener usable.
func New(ctx context.Context, dir, binaryDir, version string, env Environment, external bool, handler http.Handler) *Controller {
	c := &Controller{dir: dir, binaryDir: binaryDir, version: version, env: env, external: external, handler: handler, plans: map[string]preparedPlan{}, state: State{External: external}, listen: net.Listen}
	c.restore(ctx)
	return c
}
func (c *Controller) restore(ctx context.Context) {
	if c.external {
		return
	}
	b, err := os.ReadFile(filepath.Join(c.dir, "access.json"))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil || len(b) > 65536 || json.Unmarshal(b, &c.saved) != nil {
		c.state.Error = "接入配置无法读取；未启动成员入口"
		return
	}
	if c.saved.Enabled {
		c.saved.Enabled = false
		if err = c.activate(ctx, c.saved.Input); err != nil {
			c.state.Error = "恢复成员入口失败：" + err.Error()
		}
	}
}
func (c *Controller) Environment() Environment {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.env
	e.Addresses = append([]Address{}, e.Addresses...)
	return e
}
func (c *Controller) State() State { c.mu.Lock(); defer c.mu.Unlock(); return c.state }
func (c *Controller) validate(in Input) (bool, error) {
	if in.Port < 1024 || in.Port > 65535 {
		return false, errors.New("成员端口须在 1024–65535 之间")
	}
	bind, public := net.ParseIP(in.BindIP), net.ParseIP(in.PublicIP)
	if bind == nil || public == nil || bind.To4() == nil || public.To4() == nil || !bind.IsPrivate() || !public.IsPrivate() {
		return false, errors.New("请选择检测到的局域网 IPv4 地址")
	}
	bindFound, publicFound, host := false, false, false
	for _, a := range c.env.Addresses {
		if a.IP == in.BindIP && !a.Host {
			bindFound = true
		}
		if a.IP == in.PublicIP {
			publicFound = true
			host = a.Host
		}
	}
	if !bindFound || !publicFound || (!host && in.BindIP != in.PublicIP) {
		return false, errors.New("地址不属于本机当前接口；请刷新检测")
	}
	_, subnet, err := net.ParseCIDR(in.AllowedCIDR)
	if err != nil || subnet.IP.To4() == nil || !subnet.Contains(public) {
		return false, errors.New("允许网段须是包含接入地址的私有 IPv4 网段")
	}
	ones, bits := subnet.Mask.Size()
	end := append(net.IP(nil), subnet.IP.To4()...)
	for i := 0; i < 4; i++ {
		end[i] |= ^subnet.Mask[i]
	}
	if bits != 32 || ones < 8 || !subnet.IP.IsPrivate() || !end.IsPrivate() {
		return false, errors.New("禁止对公网或全部地址开放入口")
	}
	if host && !c.env.WSL {
		return false, errors.New("主机地址仅适用于 WSL 桥接")
	}
	return host, nil
}
func (c *Controller) Prepare(team int64, in Input) (Plan, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.external {
		return Plan{}, errors.New("入口由启动参数管理，请使用高级手动配置")
	}
	bridge, err := c.validate(in)
	if err != nil {
		return Plan{}, err
	}
	now := time.Now()
	for id, p := range c.plans {
		if p.ExpiresAt < now.UTC().Format(time.RFC3339) {
			delete(c.plans, id)
		}
	}
	if len(c.plans) >= 32 {
		return Plan{}, errors.New("待确认方案过多，请稍后重试")
	}
	id := make([]byte, 16)
	if _, err = rand.Read(id); err != nil {
		return Plan{}, err
	}
	p := Plan{ID: hex.EncodeToString(id), Input: in, Origin: "https://" + net.JoinHostPort(in.PublicIP, strconv.Itoa(in.Port)), NeedsHostBridge: bridge, ExpiresAt: now.Add(5 * time.Minute).UTC().Format(time.RFC3339), Steps: []string{"为所选地址准备独立 TLS 证书，私钥仅保存在主端", "开启仅供成员和 Node 使用的受限入口；本机管理端和任务保持运行", "验证本机 TLS；由成员运行接入包后确认真正的设备连接"}}
	if bridge {
		p.Steps = append(p.Steps, "在 Windows 主机运行固定桥接脚本 -Apply，仅放行所选网段和端口；本向导不会修改主机防火墙")
	}
	c.plans[p.ID] = preparedPlan{Plan: p, Team: team}
	return p, nil
}
func (c *Controller) Apply(ctx context.Context, team int64, id string) (State, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.external {
		return c.state, errors.New("启动参数管理的入口不可修改")
	}
	p, ok := c.plans[id]
	if !ok || p.Team != team {
		return c.state, errors.New("方案不存在，请重新生成")
	}
	delete(c.plans, id)
	expiry, _ := time.Parse(time.RFC3339, p.ExpiresAt)
	if !time.Now().Before(expiry) {
		return c.state, errors.New("方案已过期，请重新生成")
	}
	if c.state.Enabled {
		if c.saved.Input == p.Input {
			return c.state, nil
		}
		return c.state, errors.New("已有成员入口；更改地址前请先停用并告知成员")
	}
	err := c.activate(ctx, p.Input)
	return c.state, err
}
func createCertificate(ip string) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "ARTEX team access"}, NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), IPAddresses: []net.IP{net.ParseIP(ip)}, BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), nil
}
func (c *Controller) persist(s savedAccess) error {
	if err := os.MkdirAll(c.dir, 0700); err != nil {
		return err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(c.dir, ".access-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, filepath.Join(c.dir, "access.json"))
}
func (c *Controller) activate(ctx context.Context, in Input) error {
	bridge, err := c.validate(in)
	if err != nil {
		return err
	}
	next := c.saved
	next.Input = in
	next.Enabled = true
	if len(next.Certificate) == 0 || c.saved.Input.PublicIP != in.PublicIP {
		next.Certificate, next.PrivateKey, err = createCertificate(in.PublicIP)
		if err != nil {
			return errors.New("生成证书失败")
		}
	}
	cert, err := tls.X509KeyPair(next.Certificate, next.PrivateKey)
	if err != nil {
		return errors.New("已保存证书无效；请检查受管接入目录")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	if err = leaf.VerifyHostname(in.PublicIP); err != nil {
		return errors.New("证书与接入地址不匹配")
	}
	if !time.Now().Before(leaf.NotAfter) {
		return errors.New("证书已到期；请停用后由管理员更新证书与成员信任")
	}
	listener, err := c.listen("tcp", net.JoinHostPort(in.BindIP, strconv.Itoa(in.Port)))
	if err != nil {
		return errors.New("所选地址无法监听或端口被占用")
	}
	_, allowed, _ := net.ParseCIDR(in.AllowedCIDR)
	probeIP, _, _ := net.SplitHostPort(listener.Addr().String())
	var bridgeNet *net.IPNet
	if bridge {
		for _, a := range c.env.Addresses {
			if a.IP == in.BindIP && !a.Host {
				_, bridgeNet, _ = net.ParseCIDR(a.CIDR)
			}
		}
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remote, _, _ := net.SplitHostPort(r.RemoteAddr)
		ip := net.ParseIP(remote)
		if ip == nil || !(allowed.Contains(ip) || ip.Equal(net.ParseIP(probeIP)) || (bridgeNet != nil && bridgeNet.Contains(ip))) {
			http.Error(w, "member network denied", http.StatusForbidden)
			return
		}
		c.handler.ServeHTTP(w, r)
	})
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}}
	go func() { _ = srv.Serve(tls.NewListener(listener, srv.TLSConfig)) }()
	success := false
	defer func() {
		if !success {
			_ = srv.Close()
		}
	}()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(next.Certificate)
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: in.PublicIP}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+listener.Addr().String()+"/api/health", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(req)
	if err != nil {
		return errors.New("本机 TLS 校验失败，未保存入口")
	}
	io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("成员健康检查失败，未保存入口")
	}
	if err = c.persist(next); err != nil {
		return errors.New("无法安全保存接入配置，已关闭新入口")
	}
	fingerprint := sha256.Sum256(cert.Certificate[0])
	c.saved = next
	c.server = srv
	c.state = State{Enabled: true, Origin: "https://" + net.JoinHostPort(in.PublicIP, strconv.Itoa(in.Port)), ListenAddress: listener.Addr().String(), AllowedCIDR: in.AllowedCIDR, Fingerprint: hex.EncodeToString(fingerprint[:]), ExpiresAt: leaf.NotAfter.UTC().Format(time.RFC3339), NeedsHostBridge: bridge, LocalTLSVerified: true}
	success = true
	return nil
}
func (c *Controller) Disable() (State, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.external {
		return c.state, errors.New("启动参数管理的入口不可停用")
	}
	next := c.saved
	next.Enabled = false
	if err := c.persist(next); err != nil {
		return c.state, errors.New("无法保存停用状态；入口保持原状")
	}
	if c.server != nil {
		_ = c.server.Close()
		c.server = nil
	}
	c.saved = next
	c.state.Enabled = false
	c.state.LocalTLSVerified = false
	return c.state, nil
}

// Close stops the process listener without changing its persisted startup policy.
func (c *Controller) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.server != nil {
		_ = c.server.Close()
		c.server = nil
	}
}
