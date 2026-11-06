$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$summary = [ordered]@{
    platform = 'windows'
    evidence_type = 'configuration'
    external_probe_performed = $false
    ipv4_default_route_count = $null
    ipv6_default_route_count = $null
    dns_address_count = $null
    user_proxy_configured = $null
    proxy_credentials_in_configuration = $null
    observation_status = 'unknown'
    limitations = @('No approved egress baseline', 'No actual process traffic or DNS observation', 'WSL results are not Windows results')
    unavailable_checks = @()
}
try {
    # Read the route table once. An absent IPv6 default route is a valid count of 0;
    # querying that exact prefix through CIM would raise a no-matching-object error.
    $routes = @(Get-NetRoute -ErrorAction Stop)
    $summary.ipv4_default_route_count = @($routes | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' }).Count
    $summary.ipv6_default_route_count = @($routes | Where-Object { $_.DestinationPrefix -eq '::/0' }).Count
    $routes = $null
} catch { $summary.unavailable_checks += @('ipv4_routes','ipv6_routes') }
try {
    $dnsEntries = @(Get-DnsClientServerAddress -ErrorAction Stop)
    $summary.dns_address_count = @($dnsEntries | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ }).Count
} catch { $summary.unavailable_checks += 'dns_configuration' }
try {
    $proxySettings = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
    $summary.user_proxy_configured = [bool]($proxySettings.ProxyEnable -or $proxySettings.AutoConfigURL)
    $proxyText = [string]$proxySettings.ProxyServer
    $summary.proxy_credentials_in_configuration = [bool]($proxyText -match '(?i)[a-z][a-z0-9+.-]*://[^/@\s]+:[^/@\s]+@')
    $proxyText = $null
    $proxySettings = $null
} catch { $summary.unavailable_checks += 'user_proxy_configuration' }
$summary | ConvertTo-Json -Depth 4 -Compress
