# =============================================================================
#  Windows Detective - Network analysis
#  Powered by Bashar Salmo
#  WD-SELF-MARKER
# =============================================================================

function Get-WDNetstat {
    # Fallback when the NetTCPIP module is not available.
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($line in (& netstat.exe -ano 2>$null)) {
        if ($line -match '^\s*TCP\s+(\S+):(\d+)\s+(\S+):(\d+)\s+(\S+)\s+(\d+)') {
            $rows.Add([pscustomobject]@{ LocalAddress = $Matches[1].Trim('[', ']'); LocalPort = [int]$Matches[2]; RemoteAddress = $Matches[3].Trim('[', ']'); RemotePort = [int]$Matches[4]; State = $Matches[5]; OwningProcess = [int]$Matches[6] })
        }
    }
    return $rows
}

function Invoke-WDNetworkCollector {
    if (-not $script:WD.ProcessMap -or $script:WD.ProcessMap.Count -eq 0) {
        foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) { $script:WD.ProcessMap[[int]$p.ProcessId] = $p }
    }
    $pm = $script:WD.ProcessMap

    # ---- TCP connections
    $tcp = $null
    try { $tcp = @(Get-NetTCPConnection -ErrorAction Stop) } catch { $tcp = @(Get-WDNetstat) }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($c in $tcp) {
        $p = $pm[[int]$c.OwningProcess]
        $pname = ''; $ppath = ''; $cmd = ''
        if ($p) { $pname = $p.Name; $ppath = [string]$p.ExecutablePath; $cmd = [string]$p.CommandLine }
        $state = [string]$c.State
        if ($state -eq 'LISTENING') { $state = 'Listen' } elseif ($state -eq 'SYN_SENT') { $state = 'SynSent' } elseif ($state -eq 'CLOSE_WAIT') { $state = 'CloseWait' }
        $public = Test-WDPublicIp $c.RemoteAddress
        $rows.Add([pscustomobject][ordered]@{
            Protocol = 'TCP'; State = $state; LocalAddress = $c.LocalAddress; LocalPort = $c.LocalPort
            RemoteAddress = $c.RemoteAddress; RemotePort = $c.RemotePort; PublicRemote = $public
            PID = $c.OwningProcess; Process = $pname; Path = $ppath
        })
        if ([int]$c.OwningProcess -eq $PID) { continue }
        $ev = "$pname (PID $($c.OwningProcess)) $($c.LocalAddress):$($c.LocalPort) -> $($c.RemoteAddress):$($c.RemotePort) [$state] | $ppath | $cmd"
        if ($public) { Add-WDObserved -Type Ips -Value $c.RemoteAddress -Source "Connection from $pname" }

        if ($state -in @('Established', 'SynSent', 'CloseWait')) {
            if ($public -and $ppath -match $script:WDNoNetworkRx) {
                Add-Finding -Severity High -Category 'Network' -Title "Unusual process with internet connection: $pname" -Detail 'This binary normally never talks to the internet - typical of injected code, LOLBin payloads or C2.' -Evidence $ev -Mitre 'T1071.001,T1218' -Source 'TCP'
            } elseif ($public -and $ppath -match $script:WDScriptNetRx) {
                Add-Finding -Severity Medium -Category 'Network' -Title 'PowerShell holding an internet connection' -Evidence $ev -Mitre 'T1059.001,T1071.001' -Source 'TCP'
            }
            if ($public -and (Get-WDPathRisk $ppath) -eq 'High') {
                Add-Finding -Severity High -Category 'Network' -Title 'Process from high-risk path connected to the internet' -Evidence $ev -Mitre 'T1071.001' -Source 'TCP'
            }
            if ($public -and $script:WDSuspiciousPorts -contains [int]$c.RemotePort) {
                Add-Finding -Severity High -Category 'Network' -Title "Connection to port commonly used by C2 / reverse shells ($($c.RemotePort))" -Evidence $ev -Mitre 'T1571' -Source 'TCP'
            }
            if ($public -and [int]$c.LocalPort -eq 3389) {
                Add-Finding -Severity High -Category 'Network' -Title 'Inbound RDP session from a public IP address' -Evidence $ev -Mitre 'T1021.001,T1133' -Source 'TCP'
            }
            $tool = Get-WDToolMatch $pname
            if ($tool -and $public) {
                Add-Finding -Severity $tool.Severity -Category 'Network' -Title "Active internet connection by $($tool.Label)" -Evidence $ev -Mitre $tool.Mitre -Source 'TCP'
            }
        }
        if ($state -eq 'Listen' -and $c.LocalAddress -notmatch '^(127\.|::1$)' -and (Get-WDPathRisk $ppath) -ne 'None') {
            $info = Get-WDFileInfo $ppath
            if (-not $info -or -not $info.IsMicrosoft) {
                $sev = 'Medium'
                if ((Get-WDPathRisk $ppath) -eq 'High' -or ($info -and $info.SigStatus -ne 'Valid')) { $sev = 'High' }
                Add-Finding -Severity $sev -Category 'Network' -Title 'Process from user-writable path is listening on the network (possible bind shell / backdoor)' -Evidence $ev -Mitre 'T1571,T1205' -Source 'TCP'
            }
        }
    }
    Save-WDArtifact -Name 'TcpConnections' -Section 'Network' -Data $rows -Description 'TCP connections and listening ports with owning process'

    # ---- UDP listeners
    try {
        $udp = @(Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
            $p = $pm[[int]$_.OwningProcess]
            [pscustomobject][ordered]@{ LocalAddress = $_.LocalAddress; LocalPort = $_.LocalPort; PID = $_.OwningProcess; Process = $(if ($p) { $p.Name } else { '' }); Path = $(if ($p) { $p.ExecutablePath } else { '' }) }
        })
        Save-WDArtifact -Name 'UdpEndpoints' -Section 'Network' -Data $udp -Description 'UDP endpoints'
    } catch { }

    # ---- DNS client cache
    $dns = @()
    try {
        $dns = @(Get-DnsClientCache -ErrorAction Stop | Select-Object Entry, RecordName, @{ n = 'Type'; e = { [string]$_.Type } }, Data, TimeToLive)
    } catch {
        $cur = ''
        $dns = @(& ipconfig.exe /displaydns 2>$null | ForEach-Object {
            if ($_ -match 'Record Name[ .]*:\s*(\S+)') { $cur = $Matches[1] }
            elseif ($_ -match '(A \(Host\)|AAAA|CNAME) Record[ .]*:\s*(\S+)') { [pscustomobject]@{ Entry = $cur; RecordName = $cur; Type = $Matches[1]; Data = $Matches[2]; TimeToLive = '' } }
        })
    }
    Save-WDArtifact -Name 'DnsCache' -Section 'Network' -Data $dns -Description 'Recently resolved domains (DNS client cache)'
    foreach ($d in $dns) {
        Add-WDObserved -Type Domains -Value $d.Entry -Source 'DNS cache'
        if ($d.Data -and ([string]$d.Data -match '^\d{1,3}(\.\d{1,3}){3}$') -and (Test-WDPublicIp $d.Data)) { Add-WDObserved -Type Ips -Value $d.Data -Source "DNS answer for $($d.Entry)" }
        if ($d.Entry -match '(?i)(ngrok|trycloudflare\.com|serveo\.net|\.loca\.lt|localtunnel|duckdns\.org|portmap\.io|\.onion|pastebin\.com|transfer\.sh|temp\.sh|file\.io|gofile\.io|0x0\.st|api\.telegram\.org|discord(app)?\.com/api/webhooks|iplogger|ipinfo\.io|ip-api\.com|icanhazip|api\.ipify\.org|checkip\.amazonaws)') {
            $sev = 'Low'
            if ($d.Entry -match '(?i)(ngrok|trycloudflare|serveo|loca\.lt|localtunnel|portmap|\.onion|iplogger)') { $sev = 'Medium' }
            Add-Finding -Severity $sev -Category 'Network' -Title 'DNS cache contains tunnelling / paste / IP-lookup service' -Detail 'Malware commonly uses these for C2, payload hosting or discovering the public IP.' -Evidence "$($d.Entry) -> $($d.Data)" -Mitre 'T1102,T1016,T1572'
        }
    }

    # ---- hosts file
    $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $hostsRows = New-Object System.Collections.Generic.List[object]
    if (Test-Path -LiteralPath $hostsPath) {
        $hi = Get-Item -LiteralPath $hostsPath -Force
        Add-WDTimeline -Time $hi.LastWriteTime -Source 'Network' -Description 'hosts file last modified'
        foreach ($line in (Get-Content -LiteralPath $hostsPath -ErrorAction SilentlyContinue)) {
            $t = $line.Trim()
            if (-not $t -or $t.StartsWith('#')) { continue }
            $hostsRows.Add([pscustomobject]@{ Entry = $t })
            if ($t -match '^\s*(127\.0\.0\.1|::1)\s+localhost\s*$') { continue }
            if ($t -match $script:WDSecurityVendorRx) {
                Add-Finding -Severity High -Category 'Network' -Title 'hosts file redirects a security vendor / Microsoft domain' -Detail 'Used to block AV/EDR updates and telemetry.' -Evidence $t -Mitre 'T1562.001,T1565.001' -Time $hi.LastWriteTime
            } else {
                Add-Finding -Severity Low -Category 'Network' -Title 'Custom hosts file entry' -Evidence $t -Mitre 'T1565.001'
            }
        }
    }
    Save-WDArtifact -Name 'HostsFile' -Section 'Network' -Data $hostsRows -Description 'Active hosts file entries'

    # ---- Port proxy (netsh interface portproxy) - pivoting
    $pp = New-Object System.Collections.Generic.List[object]
    foreach ($kind in @('v4tov4', 'v4tov6', 'v6tov4', 'v6tov6')) {
        foreach ($v in (Get-WDRegValues "HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\$kind\tcp")) {
            $pp.Add([pscustomobject]@{ Type = $kind; Listen = $v.Name; ConnectTo = $v.Value })
            Add-Finding -Severity High -Category 'Network' -Title 'Port forwarding rule configured (netsh portproxy)' -Detail 'Frequently used to pivot / expose RDP through a compromised host.' -Evidence "$kind listen $($v.Name) -> $($v.Value)" -Mitre 'T1090'
        }
    }
    Save-WDArtifact -Name 'PortProxy' -Section 'Network' -Data $pp -Description 'netsh interface portproxy rules'

    # ---- Proxy settings (per user + WinHTTP)
    $proxy = New-Object System.Collections.Generic.List[object]
    foreach ($h in (Get-WDUserHives)) {
        $k = "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        $en = Get-WDRegValue $k 'ProxyEnable'; $srv = Get-WDRegValue $k 'ProxyServer'; $pac = Get-WDRegValue $k 'AutoConfigURL'
        $proxy.Add([pscustomobject]@{ User = $h.User; ProxyEnable = $en; ProxyServer = $srv; AutoConfigURL = $pac })
        if ($en -eq 1 -and $srv) {
            Add-Finding -Severity Low -Category 'Network' -Title 'User proxy configured' -Detail 'Validate against corporate proxy; malicious proxies enable traffic interception.' -Evidence "$($h.User): $srv" -Mitre 'T1090'
        }
        if ($pac) {
            $sev = 'Low'; if ($pac -match '(?i)^(file:|http://\d|https?://127\.)') { $sev = 'Medium' }
            Add-Finding -Severity $sev -Category 'Network' -Title 'Proxy auto-config (PAC) URL configured' -Evidence "$($h.User): $pac" -Mitre 'T1090'
        }
    }
    $winhttp = (& netsh.exe winhttp show proxy 2>$null) -join ' '
    $proxy.Add([pscustomobject]@{ User = 'WinHTTP (system)'; ProxyEnable = ''; ProxyServer = ($winhttp -replace '\s+', ' ').Trim(); AutoConfigURL = '' })
    Save-WDArtifact -Name 'ProxySettings' -Section 'Network' -Data $proxy -Description 'Per-user and WinHTTP proxy settings'

    # ---- Shares, SMB sessions, neighbours, routes, adapters, Wi-Fi
    try {
        $shares = @(Get-SmbShare -ErrorAction Stop | Select-Object Name, Path, Description, ScopeName, CurrentUsers, EncryptData)
        Save-WDArtifact -Name 'SmbShares' -Section 'Network' -Data $shares -Description 'Shared folders'
        foreach ($s in $shares) {
            if ($s.Name -notmatch '^(ADMIN\$|IPC\$|[A-Z]\$|print\$)$') {
                $sev = 'Info'; if ($s.Path -match '^[A-Za-z]:\\?$' -or $s.Path -match '(?i)\\Users\\?$') { $sev = 'Medium' }
                Add-Finding -Severity $sev -Category 'Network' -Title 'Non-default SMB share' -Evidence "$($s.Name) -> $($s.Path)" -Mitre 'T1021.002'
            }
        }
        Save-WDArtifact -Name 'SmbSessions' -Section 'Network' -Data @(Get-SmbSession -ErrorAction SilentlyContinue | Select-Object ClientComputerName, ClientUserName, NumOpens, SecondsExists, Dialect) -Description 'Inbound SMB sessions'
        Save-WDArtifact -Name 'SmbMappings' -Section 'Network' -Data @(Get-SmbMapping -ErrorAction SilentlyContinue | Select-Object LocalPath, RemotePath, Status) -Description 'Mapped network drives'
    } catch { Save-WDArtifact -Name 'SmbShares' -Section 'Network' -Data @(& net.exe share 2>$null | ForEach-Object { [pscustomobject]@{ Line = $_ } }) }
    try {
        Save-WDArtifact -Name 'ArpNeighbors' -Section 'Network' -Data @(Get-NetNeighbor -ErrorAction Stop | Where-Object { $_.State -ne 'Unreachable' -and $_.State -ne 'Permanent' } | Select-Object IPAddress, LinkLayerAddress, @{ n = 'State'; e = { [string]$_.State } }, InterfaceAlias) -Description 'ARP / neighbour cache'
        Save-WDArtifact -Name 'Routes' -Section 'Network' -Data @(Get-NetRoute -ErrorAction Stop | Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias) -Description 'Routing table'
        Save-WDArtifact -Name 'NetAdapters' -Section 'Network' -Data @(Get-NetIPConfiguration -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Interface = $_.InterfaceAlias; IPv4 = ($_.IPv4Address.IPAddress -join ','); Gateway = ($_.IPv4DefaultGateway.NextHop -join ','); DNS = ($_.DNSServer.ServerAddresses -join ',') } }) -Description 'Adapters, gateways and DNS servers'
    } catch { }
    $wifi = @(& netsh.exe wlan show profiles 2>$null | Where-Object { $_ -match ':\s*(.+)$' -and $_ -match 'Profile' } | ForEach-Object { [pscustomobject]@{ Profile = ($_ -split ':', 2)[1].Trim() } })
    Save-WDArtifact -Name 'WifiProfiles' -Section 'Network' -Data $wifi -Description 'Saved Wi-Fi networks (names only)'

    # ---- Firewall
    try {
        $profiles = @(Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked, LogFileName)
        Save-WDArtifact -Name 'FirewallProfiles' -Section 'Network' -Data $profiles -Description 'Windows Firewall profiles'
        foreach ($fp in $profiles) {
            if (-not $fp.Enabled -or [string]$fp.Enabled -eq 'False') {
                Add-Finding -Severity High -Category 'Posture' -Title "Windows Firewall disabled for $($fp.Name) profile" -Evidence "$($fp.Name): Enabled=$($fp.Enabled)" -Mitre 'T1562.004'
            }
        }
        $appFilters = @{}
        foreach ($af in @(Get-NetFirewallApplicationFilter -All -ErrorAction Stop)) { $appFilters[$af.InstanceID] = $af.Program }
        $fwRows = New-Object System.Collections.Generic.List[object]
        foreach ($r in @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop)) {
            $prog = [string]$appFilters[$r.InstanceID]
            $fwRows.Add([pscustomobject][ordered]@{ Name = $r.Name; DisplayName = $r.DisplayName; Program = $prog; Profile = [string]$r.Profile; Group = $r.Group })
            $expanded = [Environment]::ExpandEnvironmentVariables($prog)
            if ($prog -and $prog -ne 'Any' -and (Get-WDPathRisk $expanded) -ne 'None') {
                $info = Get-WDFileInfo $expanded
                if (-not $info.IsMicrosoft -and ((Get-WDPathRisk $expanded) -eq 'High' -or $info.SigStatus -ne 'Valid')) {
                    Add-Finding -Severity High -Category 'Network' -Title 'Inbound firewall allow-rule for program in user-writable path' -Evidence "$($r.DisplayName) -> $prog" -Mitre 'T1562.004'
                }
            }
        }
        Save-WDArtifact -Name 'FirewallInboundAllowRules' -Section 'Network' -Data $fwRows -Description 'Enabled inbound allow rules'
    } catch { Write-WDLog "Firewall query failed: $($_.Exception.Message)" WARN }

    # ---- RDP configuration
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $deny = Get-WDRegValue $ts 'fDenyTSConnections'
    $port = Get-WDRegValue "$ts\WinStations\RDP-Tcp" 'PortNumber'
    $nla = Get-WDRegValue "$ts\WinStations\RDP-Tcp" 'UserAuthentication'
    $script:WD.SystemInfo['RDP Enabled'] = [string]($deny -eq 0)
    if ($deny -eq 0) {
        Add-Finding -Severity Low -Category 'Posture' -Title 'Remote Desktop is enabled' -Evidence "fDenyTSConnections=0, port $port, NLA=$nla" -Mitre 'T1021.001'
        if ($nla -eq 0) { Add-Finding -Severity Medium -Category 'Posture' -Title 'RDP Network Level Authentication is disabled' -Evidence "UserAuthentication=0" -Mitre 'T1021.001' }
        if ($port -and $port -ne 3389) { Add-Finding -Severity Medium -Category 'Network' -Title "RDP listening on non-standard port $port" -Evidence "PortNumber=$port" -Mitre 'T1021.001' }
    }
    $shadow = Get-WDRegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'Shadow'
    if ($shadow -in @(2, 4)) { Add-Finding -Severity Medium -Category 'Posture' -Title 'RDP shadowing allowed without user consent' -Evidence "Shadow=$shadow" -Mitre 'T1021.001' }
}
