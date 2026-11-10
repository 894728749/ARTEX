package teamsetup

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var supportedPlatforms = map[string]bool{"windows-amd64": true, "linux-amd64": true, "linux-arm64": true, "darwin-amd64": true, "darwin-arm64": true}

func (c *Controller) manifest() (BinaryManifest, error) {
	var m BinaryManifest
	b, err := os.ReadFile(filepath.Join(c.binaryDir, "manifest.json"))
	if err != nil {
		return m, errors.New("缺少成员接入资源，请安装同版本完整发行包或使用高级手动配置")
	}
	if len(b) > 32768 || json.Unmarshal(b, &m) != nil || m.Version != c.version {
		return m, errors.New("接入资源与主端版本不一致，请安装同版本完整发行包")
	}
	seen := map[string]bool{}
	for _, v := range m.Binaries {
		if !supportedPlatforms[v.Platform] || seen[v.Platform] || v.File != filepath.Base(v.File) || strings.ContainsAny(v.File, `/\`) || len(v.SHA256) != 64 {
			return m, errors.New("成员资源清单无效")
		}
		if _, err := hex.DecodeString(v.SHA256); err != nil {
			return m, errors.New("成员资源校验值无效")
		}
		seen[v.Platform] = true
	}
	return m, nil
}
func (c *Controller) Platforms() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []string{}
	m, err := c.manifest()
	if err != nil {
		return out
	}
	for _, v := range m.Binaries {
		if st, err := os.Stat(filepath.Join(c.binaryDir, v.File)); err == nil && st.Mode().IsRegular() {
			out = append(out, v.Platform)
		}
	}
	sort.Strings(out)
	return out
}
func (c *Controller) Bundle(team int64, platform string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.external || !c.state.Enabled {
		return nil, errors.New("请先准备受管成员入口；启动参数管理的入口使用高级手动配置")
	}
	m, err := c.manifest()
	if err != nil {
		return nil, err
	}
	var entry NodeBinary
	for _, v := range m.Binaries {
		if v.Platform == platform {
			entry = v
			break
		}
	}
	if entry.File == "" {
		return nil, errors.New("所选平台没有同版本 Node 接入资源")
	}
	root, err := filepath.EvalSymlinks(c.binaryDir)
	if err != nil {
		return nil, err
	}
	path, err := filepath.EvalSymlinks(filepath.Join(c.binaryDir, entry.File))
	if err != nil || filepath.Dir(path) != root {
		return nil, errors.New("Node 资源路径无效")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("无法读取 Node 资源")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 128<<20 {
		return nil, errors.New("Node 资源大小或类型无效")
	}
	binary, err := io.ReadAll(io.LimitReader(f, 128<<20+1))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(binary)
	if hex.EncodeToString(sum[:]) != strings.ToLower(entry.SHA256) {
		return nil, errors.New("Node 资源校验失败，拒绝生成接入包")
	}
	join := JoinConfig{Schema: 1, TeamID: team, Version: c.version, CoordinatorURL: c.state.Origin, ServerName: c.saved.Input.PublicIP, CAFile: "coordinator-ca.pem", CertificateSHA256: c.state.Fingerprint, LANAddresses: []string{strings.TrimPrefix(c.state.Origin, "https://")}}
	config, err := json.MarshalIndent(join, "", "  ")
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	write := func(name string, data []byte, mode os.FileMode) error {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetMode(mode)
		w, err := z.CreateHeader(h)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}
	name := "artex-node"
	if strings.HasPrefix(platform, "windows-") {
		name += ".exe"
	}
	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{{name, binary, 0755}, {"join.json", config, 0600}, {"coordinator-ca.pem", c.saved.Certificate, 0644}, {"README.txt", []byte("ARTEX 成员接入包\n解压到独立目录，运行 connect.cmd (Windows) 或 bash connect.sh (Linux/macOS)。\n先通过独立渠道向管理员核对页面显示的证书 SHA256，再输入管理员单独提供的一次性配对码。包内没有身份、配对码或模型密钥。\nsetup 只核验连接和本机配置；启动工作需要另行确认。仅连接模式不执行任务。生成角色也不会自动授权外部工具。\n配对后仍需主端分配任务/分支权限。模型密钥只在当前进程有效，后续启动需再次输入或在本机设置对应环境变量。\n浏览器的成员登录使用系统信任库，必要时请按组织规则单独导入公开证书；Node 不修改全局证书信任。\n本接入包用于 LAN/VPN；远程 Relay 请使用高级手动配置。\n"), 0644}}
	if strings.HasPrefix(platform, "windows-") {
		files = append(files, struct {
			name string
			data []byte
			mode os.FileMode
		}{"connect.cmd", []byte("@echo off\r\ncd /d \"%~dp0\"\r\nartex-node.exe -join join.json setup\r\npause\r\n"), 0644})
	} else {
		files = append(files, struct {
			name string
			data []byte
			mode os.FileMode
		}{"connect.sh", []byte("#!/usr/bin/env sh\nset -eu\ncd -- \"$(dirname -- \"$0\")\"\nexec ./artex-node -join join.json setup\n"), 0755})
	}
	for _, v := range files {
		if err := write(v.name, v.data, v.mode); err != nil {
			return nil, err
		}
	}
	if err = z.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
