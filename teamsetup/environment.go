package teamsetup

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Detect only reads local interface information. It does not probe remote hosts.
func Detect(ctx context.Context) Environment {
	e := Environment{OS: runtime.GOOS, Arch: runtime.GOARCH, Addresses: []Address{}}
	e.Distro = os.Getenv("WSL_DISTRO_NAME")
	e.WSL = runtime.GOOS == "linux" && e.Distro != ""
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, _ := iface.Addrs()
		for _, a := range addresses {
			ip, subnet, err := net.ParseCIDR(a.String())
			if err == nil && ip.To4() != nil && ip.IsPrivate() {
				e.Addresses = append(e.Addresses, Address{IP: ip.String(), Interface: iface.Name, CIDR: subnet.String()})
			}
		}
	}
	if e.WSL {
		// Constant read-only command: no request data or configuration is interpolated.
		readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		output, err := exec.CommandContext(readCtx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", `[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $ErrorActionPreference='Stop'; $active=@(Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' -and $_.IPv4DefaultGateway } | ForEach-Object { $_.InterfaceIndex }); ConvertTo-Json -Compress -InputObject @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.AddressState -eq 'Preferred' -and $active -contains $_.InterfaceIndex -and $_.InterfaceAlias -notmatch 'Loopback|vEthernet|WSL' } | Select-Object IPAddress,PrefixLength,InterfaceAlias)`).Output()
		if err == nil && len(output) < 65536 {
			var addresses []struct {
				IPAddress      string
				PrefixLength   int
				InterfaceAlias string
			}
			if json.Unmarshal(output, &addresses) == nil {
				for _, a := range addresses {
					ip := net.ParseIP(a.IPAddress)
					if ip == nil || ip.To4() == nil || !ip.IsPrivate() || a.PrefixLength < 8 || a.PrefixLength > 32 {
						continue
					}
					subnet := &net.IPNet{IP: ip.Mask(net.CIDRMask(a.PrefixLength, 32)), Mask: net.CIDRMask(a.PrefixLength, 32)}
					e.Addresses = append(e.Addresses, Address{IP: ip.String(), Interface: strings.TrimSpace(a.InterfaceAlias), CIDR: subnet.String(), Host: true})
				}
			}
		}
	}
	return e
}
