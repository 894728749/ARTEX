param(
    [Parameter(Mandatory=$true)]
    [ValidatePattern('^[a-z0-9]{6,64}$')]
    [string]$TestId
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$attempted = 0
$resolved = 0
foreach ($index in 1..3) {
    foreach ($recordType in @('A', 'AAAA')) {
        $attempted += 1
        try {
            # Unique public DNS test names; no ICMP, target scans or file data.
            $null = Resolve-DnsName -Name "$index.$TestId.bash.ws" -Type $recordType -DnsOnly -QuickTimeout -ErrorAction Stop
            $resolved += 1
        } catch { }
    }
}
[ordered]@{
    scope = 'windows_system_dns_control'
    attempted = $attempted
    resolved = $resolved
    test_id = $TestId
    configuration_changed = $false
} | ConvertTo-Json -Compress
