package teamsetup

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// HostScript returns a fixed operation template, never model-generated commands.
// Merely downloading or running it without -Apply does not alter the host.
func (c *Controller) HostScript() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.state.Enabled || !c.state.NeedsHostBridge || c.external {
		return nil, errors.New("当前入口不需要受管 WSL 桥接脚本")
	}
	in := c.saved.Input
	if _, err := c.validate(in); err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(c.state.Origin))
	id := hex.EncodeToString(digest[:8])
	script := fmt.Sprintf(`param([switch]$Apply,[switch]$Remove)
$ErrorActionPreference = 'Stop'
$listenIP = '%s'
$connectIP = '%s'
$port = %d
$remoteSubnet = '%s'
$ruleName = 'ARTEX-Team-%s'
$record = Join-Path $env:ProgramData ('ARTEX\' + $ruleName + '.json')
# Fixed LAN-only operation. WSL IP changes require a new plan/script.
if ($Apply -and $Remove) { throw 'Choose either -Apply or -Remove.' }
if (-not $Apply -and -not $Remove) {
 Write-Output "Preview: ${listenIP}:$port -> ${connectIP}:$port; firewall source $remoteSubnet"
 Write-Output 'Run PowerShell as Administrator and pass -Apply to create; -Remove rolls back only owned settings.'
 return
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator required.' }
$rows = @(& netsh interface portproxy show v4tov4)
if ($LASTEXITCODE -ne 0) { throw 'Cannot read existing portproxy rules.' }
$forward = @($rows | ForEach-Object { $cells = $_.Trim() -split '\s+'; if ($cells.Count -eq 4 -and $cells[0] -eq $listenIP -and $cells[1] -eq "$port") { ,$cells } })
$rule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
$owned = $false
if (Test-Path -LiteralPath $record) {
 $saved = Get-Content -LiteralPath $record -Raw | ConvertFrom-Json
 $owned = $saved.listen -eq $listenIP -and $saved.connect -eq $connectIP -and $saved.port -eq $port -and $saved.subnet -eq $remoteSubnet
}
if ($Remove) {
 if (-not $owned) { throw 'No matching ownership record; refusing to remove host settings.' }
 if ($forward.Count -ne 1 -or $forward[0][2] -ne $connectIP -or $forward[0][3] -ne "$port") { throw 'Forward changed; inspect manually.' }
 if ($rule) {
  $p = $rule | Get-NetFirewallPortFilter
  $a = $rule | Get-NetFirewallAddressFilter
  if ($p.LocalPort -ne "$port" -or $p.Protocol -ne 'TCP' -or $a.RemoteAddress -ne $remoteSubnet -or $a.LocalAddress -ne $listenIP) { throw 'Firewall changed; inspect manually.' }
  $rule | Remove-NetFirewallRule
 }
 & netsh interface portproxy delete v4tov4 listenaddress=$listenIP listenport=$port
 if ($LASTEXITCODE -ne 0) { throw 'Portproxy removal failed; ownership record retained.' }
 Remove-Item -LiteralPath $record
 return
}
if ($forward.Count -gt 0 -or $rule -or (Test-Path -LiteralPath $record)) { throw 'Existing rule or ownership record found. Inspect/remove the previous owned setup first; nothing overwritten.' }
if (Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue) { throw 'Port already in use; nothing overwritten.' }
if (-not (Get-NetIPAddress -AddressFamily IPv4 -IPAddress $listenIP -ErrorAction SilentlyContinue)) { throw 'Windows LAN IP changed; generate a new plan.' }
New-Item -ItemType Directory -Path (Split-Path $record) -Force | Out-Null
$createdForward = $false
$createdFirewall = $false
try {
 & netsh interface portproxy add v4tov4 listenaddress=$listenIP listenport=$port connectaddress=$connectIP connectport=$port
 if ($LASTEXITCODE -ne 0) { throw 'Portproxy creation failed.' }
 $createdForward = $true
 New-NetFirewallRule -Name $ruleName -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalAddress $listenIP -LocalPort $port -RemoteAddress $remoteSubnet -Profile Private,Domain | Out-Null
 $createdFirewall = $true
 @{listen=$listenIP;connect=$connectIP;port=$port;subnet=$remoteSubnet} | ConvertTo-Json | Set-Content -LiteralPath $record -Encoding UTF8
} catch {
 if ($createdFirewall) { Remove-NetFirewallRule -Name $ruleName }
 if ($createdForward) { & netsh interface portproxy delete v4tov4 listenaddress=$listenIP listenport=$port | Out-Null }
 throw
}
Write-Output 'Host bridge configured. This does not prove another device can connect. Run the member kit next.'
`, in.PublicIP, in.BindIP, in.Port, in.AllowedCIDR, id)
	return []byte(script), nil
}
