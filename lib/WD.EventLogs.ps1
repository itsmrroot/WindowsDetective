# =============================================================================
#  Windows Detective - Event log analysis
#  Powered by Bashar Salmo
#  WD-SELF-MARKER
#
#  Security (logons, brute force, accounts, groups, services, tasks, 4688, log
#  clearing), System (7045, 104, 7040), PowerShell (4104, 400), RDP (1149,
#  21-25, 1024), Defender (1116-1119, 5001, 5007, 5013), Sysmon (1,3,8,10,13,22,25),
#  Task Scheduler, BITS, WinRM, WMI-Activity and firewall rule changes.
# =============================================================================

$script:WDSystemAccountRx = '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|DWM-\d+|UMFD-\d+|-|.*\$)$'

function Invoke-WDEventLogCollector {
    Invoke-WDLogInventory
    Invoke-WDSecurityLog
    Invoke-WDSystemLog
    Invoke-WDPowerShellLogs
    Invoke-WDRdpLogs
    Invoke-WDDefenderLog
    Invoke-WDSysmonLog
    Invoke-WDMiscLogs
}

function Invoke-WDLogInventory {
    $names = @('Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell', 'PowerShellCore/Operational',
        'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-Windows Defender/Operational', 'Microsoft-Windows-TaskScheduler/Operational',
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational', 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
        'Microsoft-Windows-TerminalServices-RDPClient/Operational', 'Microsoft-Windows-Bits-Client/Operational', 'Microsoft-Windows-WinRM/Operational',
        'Microsoft-Windows-WMI-Activity/Operational', 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall', 'Microsoft-Windows-SMBServer/Security')
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($n in $names) {
        try {
            $l = Get-WinEvent -ListLog $n -ErrorAction Stop
            $oldest = $null
            try { $oldest = (Get-WinEvent -LogName $n -MaxEvents 1 -Oldest -ErrorAction Stop).TimeCreated } catch { }
            $rows.Add([pscustomobject][ordered]@{
                Log = $n; Enabled = $l.IsEnabled; Records = $l.RecordCount; SizeMB = [math]::Round($l.FileSize / 1MB, 1)
                MaxSizeMB = [math]::Round($l.MaximumSizeInBytes / 1MB, 1); OldestEventUtc = (ConvertTo-WDTimeString $oldest); LastWriteUtc = (ConvertTo-WDTimeString $l.LastWriteTime)
            })
            if ($n -eq 'Security' -and $oldest) {
                $script:WD.SystemInfo['Security Log Starts'] = ConvertTo-WDTimeString $oldest
                $boot = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).InstallDate
                if (((Get-Date) - $oldest).TotalDays -lt 2 -and $boot -and ((Get-Date) - $boot).TotalDays -gt 7 -and $l.RecordCount -lt 20000) {
                    Add-Finding -Severity Medium -Category 'Anti-Forensics' -Title 'Security log only covers the last few hours/days on an older system' -Detail 'Could indicate clearing or a very small maximum size - check for event 1102.' -Evidence "Oldest Security event $(ConvertTo-WDTimeString $oldest) UTC, $($l.RecordCount) records, max $([math]::Round($l.MaximumSizeInBytes / 1MB, 1)) MB" -Mitre 'T1070.001'
                }
            }
            if ($n -eq 'Microsoft-Windows-PowerShell/Operational' -and -not $l.IsEnabled) {
                Add-Finding -Severity Medium -Category 'Anti-Forensics' -Title 'PowerShell Operational log is disabled' -Evidence $n -Mitre 'T1562.002'
            }
        } catch { }
    }
    Save-WDArtifact -Name 'EventLogInventory' -Section 'Event Logs' -Data $rows -Description 'Key event logs, sizes and retention'

    $sbl = Get-WDRegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
    if ($sbl -ne 1) { Add-Finding -Severity Info -Category 'Visibility' -Title 'PowerShell Script Block Logging is not enforced by policy' -Detail 'Windows still logs "suspicious" blocks automatically, but full logging is recommended.' -Evidence 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' }
    $cmdAudit = Get-WDRegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled'
    if ($cmdAudit -ne 1) { Add-Finding -Severity Info -Category 'Visibility' -Title 'Command line is not recorded in process creation events (4688)' -Evidence 'ProcessCreationIncludeCmdLine_Enabled != 1' }
    try {
        $ap = & auditpol.exe /get /category:* 2>$null
        if ($ap) { [IO.File]::WriteAllLines((Join-Path $script:WD.RawDir 'AuditPolicy.txt'), [string[]]$ap) }
    } catch { }
}

function Invoke-WDSecurityLog {
    $max = $script:WD.Options.MaxEvents

    # ---- Successful logons
    $logons = New-Object System.Collections.Generic.List[object]
    $successByIp = @{}
    foreach ($e in (Get-WDEvents -LogName 'Security' -Id 4624 -Max ($max * 2))) {
        $d = $e.Data
        $type = [int]$d.LogonType
        if ($type -in @(0, 5) -or $d.TargetUserName -match $script:WDSystemAccountRx) { continue }
        $ip = [string]$d.IpAddress
        $row = [pscustomobject][ordered]@{
            TimeUtc = (ConvertTo-WDTimeString $e.Time); User = "$($d.TargetDomainName)\$($d.TargetUserName)"; LogonType = $type
            SourceIp = $ip; Workstation = $d.WorkstationName; AuthPackage = $d.AuthenticationPackageName; LogonProcess = $d.LogonProcessName
            Elevated = $d.ElevatedToken; ProcessName = $d.ProcessName
        }
        $logons.Add($row)
        $ev = "$($row.User) type $type from $ip ($($d.WorkstationName)) via $($d.AuthenticationPackageName)/$($d.LogonProcessName)"
        $public = Test-WDPublicIp $ip
        if ($ip -and $ip -ne '-' -and $ip -ne '::1' -and $ip -ne '127.0.0.1') {
            if (-not $successByIp.ContainsKey($ip)) { $successByIp[$ip] = $e.Time }
            if ($public) { Add-WDObserved -Type Ips -Value $ip -Source "Logon source ($($row.User))" }
        }
        if ($type -in @(2, 7, 10, 11) -or ($type -eq 3 -and $ip -and $ip -notin @('-', '::1', '127.0.0.1'))) {
            Add-WDTimeline -Time $e.Time -Source 'Security 4624' -Description "Logon type $type : $($row.User)" -Detail $ev
        }
        if ($type -eq 10) {
            $sev = 'Low'; if ($public) { $sev = 'High' }
            Add-Finding -Severity $sev -Category 'Logons' -Title "RDP logon (type 10)$(if ($public) { ' from public IP' })" -Evidence $ev -Mitre 'T1021.001,T1078' -Time $e.Time -Source 'Security 4624'
        }
        if ($type -eq 3 -and $public) {
            Add-Finding -Severity High -Category 'Logons' -Title 'Network logon from public IP address' -Evidence $ev -Mitre 'T1078,T1133' -Time $e.Time -Source 'Security 4624'
        }
        if ($type -eq 9 -and $d.LogonProcessName -match 'seclogo') {
            Add-Finding -Severity Medium -Category 'Logons' -Title 'NewCredentials logon (runas /netonly - also produced by pass-the-hash tools)' -Evidence "$ev | process $($d.ProcessName)" -Mitre 'T1550.002' -Time $e.Time -Source 'Security 4624'
        }
        if ($type -eq 8) {
            Add-Finding -Severity Medium -Category 'Logons' -Title 'Network logon with cleartext credentials (type 8)' -Evidence $ev -Mitre 'T1078' -Time $e.Time -Source 'Security 4624'
        }
        if ($type -eq 3 -and $d.AuthenticationPackageName -eq 'NTLM' -and $d.LmPackageName -match 'NTLM V1') {
            Add-Finding -Severity Medium -Category 'Logons' -Title 'NTLMv1 authentication accepted' -Evidence $ev -Mitre 'T1550.002' -Time $e.Time -Source 'Security 4624'
        }
    }
    Save-WDArtifact -Name 'Logons' -Section 'Event Logs' -Data $logons -Description 'Successful interactive / network / RDP logons (4624)'

    # ---- Failed logons: brute force & spraying
    $failed = @(Get-WDEvents -LogName 'Security' -Id 4625 -Max ($max * 2))
    $fRows = New-Object System.Collections.Generic.List[object]
    foreach ($e in $failed) {
        $d = $e.Data
        $fRows.Add([pscustomobject][ordered]@{ TimeUtc = (ConvertTo-WDTimeString $e.Time); User = "$($d.TargetDomainName)\$($d.TargetUserName)"; LogonType = $d.LogonType; SourceIp = $d.IpAddress; Workstation = $d.WorkstationName; Status = $d.Status; SubStatus = $d.SubStatus; Process = $d.ProcessName })
    }
    Save-WDArtifact -Name 'FailedLogons' -Section 'Event Logs' -Data $fRows -Description 'Failed logons (4625)'
    foreach ($g in ($fRows | Where-Object { $_.SourceIp -and $_.SourceIp -ne '-' } | Group-Object SourceIp)) {
        $users = @($g.Group | Select-Object -ExpandProperty User -Unique)
        $first = ($g.Group | Sort-Object TimeUtc | Select-Object -First 1).TimeUtc
        $last = ($g.Group | Sort-Object TimeUtc | Select-Object -Last 1).TimeUtc
        $ev = "$($g.Count) failures from $($g.Name) between $first and $last UTC against $($users.Count) account(s): $(($users | Select-Object -First 10) -join ', ')"
        if (Test-WDPublicIp $g.Name) { Add-WDObserved -Type Ips -Value $g.Name -Source 'Failed logon source' }
        if ($users.Count -ge 5 -and $g.Count -ge 10) {
            Add-Finding -Severity High -Category 'Logons' -Title 'Password spraying from single source' -Evidence $ev -Mitre 'T1110.003' -Time $first -Source 'Security 4625'
        } elseif ($g.Count -ge 10) {
            Add-Finding -Severity High -Category 'Logons' -Title 'Brute-force logon attempts from single source' -Evidence $ev -Mitre 'T1110' -Time $first -Source 'Security 4625'
        } else { continue }
        if ($successByIp.ContainsKey($g.Name)) {
            Add-Finding -Severity Critical -Category 'Logons' -Title 'Successful logon from an IP that was brute-forcing' -Evidence "$ev | successful logon at $(ConvertTo-WDTimeString $successByIp[$g.Name]) UTC" -Mitre 'T1110,T1078' -Time $successByIp[$g.Name] -Source 'Security 4624/4625'
        }
    }

    # ---- Explicit credentials
    $ex = New-Object System.Collections.Generic.List[object]
    foreach ($e in (Get-WDEvents -LogName 'Security' -Id 4648 -Max $max)) {
        $d = $e.Data
        if ($d.TargetUserName -match $script:WDSystemAccountRx) { continue }
        $ex.Add([pscustomobject][ordered]@{ TimeUtc = (ConvertTo-WDTimeString $e.Time); Subject = "$($d.SubjectDomainName)\$($d.SubjectUserName)"; TargetUser = "$($d.TargetDomainName)\$($d.TargetUserName)"; TargetServer = $d.TargetServerName; Process = $d.ProcessName; SourceIp = $d.IpAddress })
        if ($d.ProcessName -match '(?i)\\(powershell|pwsh|cmd|rundll32|wmic|psexec\w*|mstsc)\.exe$' -or ($d.TargetServerName -and $d.TargetServerName -notmatch '^(localhost|-)$')) {
            Add-WDTimeline -Time $e.Time -Source 'Security 4648' -Description "Explicit credentials used for $($d.TargetUserName) -> $($d.TargetServerName)" -Detail $d.ProcessName
        }
    }
    Save-WDArtifact -Name 'ExplicitCredentialLogons' -Section 'Event Logs' -Data $ex -Description 'Logons with explicit credentials (4648) - runas, lateral movement'

    # ---- Account & group changes
    $acctMap = @{
        4720 = @('High', 'User account created', 'T1136.001'); 4722 = @('Medium', 'User account enabled', 'T1098'); 4724 = @('Medium', 'Password reset by another account', 'T1098')
        4726 = @('Medium', 'User account deleted', 'T1531'); 4738 = @('Low', 'User account changed', 'T1098'); 4781 = @('Medium', 'Account renamed', 'T1098')
        4728 = @('High', 'Member added to global security group', 'T1098'); 4732 = @('High', 'Member added to local security group', 'T1098'); 4756 = @('High', 'Member added to universal security group', 'T1098')
        4740 = @('Low', 'Account locked out', 'T1110'); 4719 = @('High', 'System audit policy changed', 'T1562.002'); 4616 = @('Medium', 'System time changed', 'T1070.006')
        4794 = @('High', 'Attempt to set DSRM administrator password', 'T1098'); 4697 = @('Medium', 'Service installed (Security log)', 'T1543.003')
    }
    $acctRows = New-Object System.Collections.Generic.List[object]
    foreach ($e in (Get-WDEvents -LogName 'Security' -Id @($acctMap.Keys) -Max $max)) {
        $d = $e.Data; $m = $acctMap[[int]$e.Id]
        $sev = $m[0]; $title = $m[1]
        $ev = "Subject: $($d.SubjectDomainName)\$($d.SubjectUserName) | Target: $($d.TargetDomainName)\$($d.TargetUserName) $($d.MemberName) $($d.MemberSid)"
        $skip = $false
        switch ([int]$e.Id) {
            { $_ -in 4728, 4732, 4756 } {
                if ($d.TargetUserName -match '(?i)admin|remote desktop|remote management|backup operators|dnsadmins|account operators') { $sev = 'High' } else { $sev = 'Low' }
                $title = "$title '$($d.TargetUserName)'"
            }
            4616 {
                if ($d.ProcessName -match '(?i)\\(svchost|vmtoolsd|qemu-ga|VBoxService|prl_tools_service|xenguestagent|WindowsAzureGuestAgent)\.exe$' -or $d.SubjectUserSid -eq 'S-1-5-19') { $skip = $true }
                $ev = "$ev | $($d.PreviousTime) -> $($d.NewTime) by $($d.ProcessName)"
            }
            4697 {
                $ev = "$($d.ServiceName): $($d.ServiceFileName) (account $($d.ServiceAccount)) installed by $($d.SubjectUserName)"
                [void](Invoke-WDCommandCheck -Text $d.ServiceFileName -Source "Service install 4697 $($d.ServiceName)" -Time $e.Time -Category 'Persistence')
            }
            4738 { if ($d.TargetUserName -match '\$$') { $skip = $true } }
        }
        if ($skip) { continue }
        $acctRows.Add([pscustomobject][ordered]@{ TimeUtc = (ConvertTo-WDTimeString $e.Time); EventId = $e.Id; Event = $title; Detail = $ev })
        Add-Finding -Severity $sev -Category 'Accounts' -Title $title -Evidence $ev -Mitre $m[2] -Time $e.Time -Source "Security $($e.Id)"
    }
    Save-WDArtifact -Name 'AccountChanges' -Section 'Event Logs' -Data $acctRows -Description 'Account, group, audit-policy and time changes'

    # ---- Log cleared
    foreach ($e in (Get-WDEvents -LogName 'Security' -Id 1102 -Max 100 -Since (Get-Date).AddYears(-5))) {
        Add-Finding -Severity Critical -Category 'Anti-Forensics' -Title 'Security event log was cleared' -Evidence "Cleared by $($e.Data.SubjectDomainName)\$($e.Data.SubjectUserName)" -Mitre 'T1070.001' -Time $e.Time -Source 'Security 1102'
    }

    # ---- Scheduled tasks created / updated
    foreach ($e in (Get-WDEvents -LogName 'Security' -Id @(4698, 4702) -Max $max)) {
        $d = $e.Data
        $xml = [string]$d.TaskContent; if (-not $xml) { $xml = [string]$d.TaskContentNew }
        $cmd = ''
        if ($xml -match '(?s)<Command>(.*?)</Command>') { $cmd = [System.Net.WebUtility]::HtmlDecode($Matches[1]) }
        if ($xml -match '(?s)<Arguments>(.*?)</Arguments>') { $cmd += ' ' + [System.Net.WebUtility]::HtmlDecode($Matches[1]) }
        $verb = 'created'; if ($e.Id -eq 4702) { $verb = 'updated' }
        $ev = "$($d.TaskName) $verb by $($d.SubjectDomainName)\$($d.SubjectUserName): $cmd"
        Add-WDTimeline -Time $e.Time -Source "Security $($e.Id)" -Description "Scheduled task $verb : $($d.TaskName)" -Detail $cmd
        if ($d.TaskName -notlike '\Microsoft\*') {
            Add-Finding -Severity Low -Category 'Persistence' -Title "Scheduled task $verb (non-Microsoft)" -Evidence $ev -Mitre 'T1053.005' -Time $e.Time -Source "Security $($e.Id)"
        }
        [void](Invoke-WDCommandCheck -Text $cmd -Source "Task $verb $($d.TaskName)" -Time $e.Time -Category 'Persistence')
        if ((Get-WDPathRisk (Get-WDExecutablePath $cmd)) -eq 'High') {
            Add-Finding -Severity High -Category 'Persistence' -Title "Scheduled task $verb that runs from high-risk path" -Evidence $ev -Mitre 'T1053.005' -Time $e.Time -Source "Security $($e.Id)"
        }
    }

    # ---- Admin share access (lateral movement into this host)
    foreach ($e in (Get-WDEvents -LogName 'Security' -Id 5140 -Max $max)) {
        $d = $e.Data
        if ($d.ShareName -match '(?i)\\(ADMIN|C|D|E)\$$' -and $d.IpAddress -and $d.IpAddress -notin @('::1', '127.0.0.1')) {
            Add-Finding -Severity Medium -Category 'Lateral Movement' -Title 'Administrative share accessed over the network' -Evidence "$($d.SubjectDomainName)\$($d.SubjectUserName) from $($d.IpAddress) -> $($d.ShareName)" -Mitre 'T1021.002' -Time $e.Time -Source 'Security 5140'
        }
    }

    # ---- Process creation (4688)
    $pc = @(Get-WDEvents -LogName 'Security' -Id 4688 -Max ($max * 4))
    $pRows = New-Object System.Collections.Generic.List[object]
    foreach ($e in $pc) {
        $d = $e.Data
        $cmd = [string]$d.CommandLine
        if ("$cmd $($d.NewProcessName)" -match $script:WDSelfExclusionRx) { continue }
        $hits = 0
        if ($cmd) { $hits = Invoke-WDCommandCheck -Text $cmd -Source 'Security 4688' -Time $e.Time -Context "User $($d.SubjectUserName), parent $($d.ParentProcessName)" }
        Test-WDParentChild -ParentPath $d.ParentProcessName -ChildPath $d.NewProcessName -CommandLine $cmd -Source 'Security 4688' -Time $e.Time
        $tool = Get-WDToolMatch $d.NewProcessName
        if ($tool) { Add-Finding -Severity $tool.Severity -Category 'Execution' -Title "Process creation logged: $($tool.Label)" -Evidence "$($d.NewProcessName) $cmd (user $($d.SubjectUserName))" -Mitre $tool.Mitre -Time $e.Time -Source 'Security 4688' }
        if ($hits -gt 0 -or $tool -or (Get-WDPathRisk $d.NewProcessName) -eq 'High') {
            $pRows.Add([pscustomobject][ordered]@{ TimeUtc = (ConvertTo-WDTimeString $e.Time); User = $d.SubjectUserName; Process = $d.NewProcessName; Parent = $d.ParentProcessName; CommandLine = $cmd })
            Add-WDTimeline -Time $e.Time -Source 'Security 4688' -Description "Process: $(Split-Path $d.NewProcessName -Leaf)" -Detail $cmd -Severity 'Low'
        }
    }
    if ($pc.Count -eq 0) { Add-Finding -Severity Info -Category 'Visibility' -Title 'No process creation events (4688) - process auditing is not enabled' -Evidence 'auditpol /set /subcategory:"Process Creation" /success:enable' }
    Save-WDArtifact -Name 'ProcessCreationNotable' -Section 'Event Logs' -Data $pRows -Description 'Notable process creation events (4688)'
}

function Invoke-WDSystemLog {
    $max = $script:WD.Options.MaxEvents
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($e in (Get-WDEvents -LogName 'System' -Id 7045 -Max $max)) {
        $d = $e.Data
        $img = [string]$d.ImagePath
        $rows.Add([pscustomobject][ordered]@{ TimeUtc = (ConvertTo-WDTimeString $e.Time); Service = $d.ServiceName; ImagePath = $img; Type = $d.ServiceType; Start = $d.StartType; Account = $d.AccountName })
        $ev = "$($d.ServiceName): $img [$($d.ServiceType), $($d.StartType), $($d.AccountName)]"
        Add-WDTimeline -Time $e.Time -Source 'System 7045' -Description "Service installed: $($d.ServiceName)" -Detail $img -Severity 'Low'
        [void](Invoke-WDCommandCheck -Text $img -Source "Service install 7045 $($d.ServiceName)" -Time $e.Time -Category 'Persistence')
        if ($img -match '(?i)%comspec%|cmd(\.exe)?\s+/[ckr]|powershell|pwsh|mshta|rundll32|\\\\127\.0\.0\.1\\|echo\s') {
            Add-Finding -Severity High -Category 'Persistence' -Title 'Service installed that runs a command shell (PsExec / Impacket / C2-framework style)' -Evidence $ev -Mitre 'T1543.003,T1569.002' -Time $e.Time -Source 'System 7045'
        }
        if ($d.ServiceName -match '^(PSEXESVC|PAExec.*|RemComSvc|csexecsvc|BTOBTO)$') {
            Add-Finding -Severity Medium -Category 'Lateral Movement' -Title "Remote execution service installed ($($d.ServiceName))" -Evidence $ev -Mitre 'T1569.002,T1021.002' -Time $e.Time -Source 'System 7045'
        }
        $p = Get-WDExecutablePath $img
        if ((Get-WDPathRisk $p) -ne 'None') {
            Add-Finding -Severity High -Category 'Persistence' -Title 'Service installed from user-writable path' -Evidence $ev -Mitre 'T1543.003' -Time $e.Time -Source 'System 7045'
        }
        if (Test-WDVulnerableDriver $p) {
            Add-Finding -Severity Critical -Category 'Defense Evasion' -Title 'Known vulnerable driver installed (BYOVD - EDR killer)' -Evidence $ev -Mitre 'T1068,T1562.001' -Time $e.Time -Source 'System 7045'
        } elseif ([string]$d.ServiceType -match '(?i)kernel') {
            $info = Get-WDFileInfo $p
            if ($info.Exists -and $info.SigStatus -ne 'Valid') { Add-Finding -Severity High -Category 'Defense Evasion' -Title 'Unsigned kernel driver installed' -Evidence $ev -Mitre 'T1014,T1068' -Time $e.Time -Source 'System 7045' }
        }
    }
    Save-WDArtifact -Name 'ServiceInstalls' -Section 'Event Logs' -Data $rows -Description 'Service installations (System 7045)'

    foreach ($e in (Get-WDEvents -LogName 'System' -Id 104 -Max 100 -Since (Get-Date).AddYears(-5))) {
        $ch = $e.Data.Channel; if (-not $ch) { $ch = ($e.Data.Values -join ' ') }
        Add-Finding -Severity Critical -Category 'Anti-Forensics' -Title "Event log cleared: $ch" -Evidence "Cleared by $($e.Data.SubjectDomainName)\$($e.Data.SubjectUserName)" -Mitre 'T1070.001' -Time $e.Time -Source 'System 104'
    }
    foreach ($e in (Get-WDEvents -LogName 'System' -Id 7040 -Max $max)) {
        $vals = ($e.Data.Values -join ' ')
        if ($vals -match '(?i)(windows defender|windefend|security center|wscsvc|firewall|mpssvc|eventlog|sense|sysmon)' -and $vals -match '(?i)disabled') {
            Add-Finding -Severity High -Category 'Defense Evasion' -Title 'Security service start type changed to Disabled' -Evidence $vals -Mitre 'T1562.001' -Time $e.Time -Source 'System 7040'
        }
    }
    foreach ($e in (Get-WDEvents -LogName 'System' -Id @(6005, 6006, 6008, 1074) -Max 500)) {
        $desc = switch ([int]$e.Id) { 6005 { 'Event log service started (boot)' } 6006 { 'Clean shutdown' } 6008 { 'Unexpected shutdown' } 1074 { "Shutdown/restart initiated: $($e.Data.param1) $($e.Data.param7)" } }
        Add-WDTimeline -Time $e.Time -Source "System $($e.Id)" -Description $desc
    }
}

function Invoke-WDPowerShellLogs {
    $max = $script:WD.Options.MaxEvents
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($log in @('Microsoft-Windows-PowerShell/Operational', 'PowerShellCore/Operational')) {
        foreach ($e in (Get-WDEvents -LogName $log -Id 4104 -Max ($max * 2))) {
            $d = $e.Data
            $text = [string]$d.ScriptBlockText
            if ($d.Path -match $script:WDSelfExclusionRx -or $d.Path -match '(?i)\\lib\\WD\.[A-Za-z]+\.ps1$' -or $text -match 'WD-SELF-MARKER') { continue }
            $hits = Invoke-WDCommandCheck -Text $text -Source "PowerShell 4104 (ScriptBlockId $($d.ScriptBlockId))" -Time $e.Time -Context "Script path: $($d.Path)"
            if ($e.Level -eq 3) {
                Add-Finding -Severity Medium -Category 'Execution' -Title 'PowerShell engine flagged a script block as suspicious (4104 Warning)' -Evidence (Limit-WDText $text 1500) -Mitre 'T1059.001' -Time $e.Time -Source $log
            }
            if ($hits -gt 0 -or $e.Level -eq 3) {
                $rows.Add([pscustomobject][ordered]@{ TimeUtc = (ConvertTo-WDTimeString $e.Time); Log = $log; Path = $d.Path; ScriptBlockId = $d.ScriptBlockId; Part = "$($d.MessageNumber)/$($d.MessageTotal)"; Text = (Limit-WDText $text 4000) })
            }
        }
    }
    Save-WDArtifact -Name 'PowerShellScriptBlocks' -Section 'Event Logs' -Data $rows -Description 'Suspicious PowerShell script blocks (4104)'

    foreach ($e in (Get-WDEvents -LogName 'Windows PowerShell' -Id 400 -Max $max)) {
        $all = ($e.Data.Values -join "`n")
        $engine = ''; $hostApp = ''
        if ($all -match 'EngineVersion=([\d\.]+)') { $engine = $Matches[1] }
        if ($all -match 'HostApplication=([^\r\n]*)') { $hostApp = $Matches[1] }
        if ($hostApp -match $script:WDSelfExclusionRx) { continue }
        if ($engine -like '2.*') {
            Add-Finding -Severity Medium -Category 'Defense Evasion' -Title 'PowerShell 2.0 engine started (logging-evasion downgrade)' -Evidence $hostApp -Mitre 'T1562.010' -Time $e.Time -Source 'Windows PowerShell 400'
        }
        [void](Invoke-WDCommandCheck -Text $hostApp -Source 'Windows PowerShell 400 HostApplication' -Time $e.Time)
    }
}

function Invoke-WDRdpLogs {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($e in (Get-WDEvents -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -Id 1149)) {
        $u = $e.Data.Param1; $dom = $e.Data.Param2; $ip = $e.Data.Param3
        $rows.Add([pscustomobject][ordered]@{ TimeUtc = (ConvertTo-WDTimeString $e.Time); Event = '1149 RDP auth succeeded'; User = "$dom\$u"; Address = $ip; Session = '' })
        Add-WDTimeline -Time $e.Time -Source 'RDP 1149' -Description "RDP authentication: $dom\$u from $ip"
        if (Test-WDPublicIp $ip) {
            Add-WDObserved -Type Ips -Value $ip -Source 'RDP source'
            Add-Finding -Severity High -Category 'Logons' -Title 'RDP connection authenticated from public IP' -Evidence "$dom\$u from $ip" -Mitre 'T1021.001,T1133' -Time $e.Time -Source 'RDP 1149'
        }
    }
    $names = @{ 21 = 'Session logon'; 22 = 'Shell start'; 23 = 'Session logoff'; 24 = 'Session disconnected'; 25 = 'Session reconnected' }
    foreach ($e in (Get-WDEvents -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -Id @(21, 22, 23, 24, 25))) {
        $addr = [string]$e.Data.Address
        if ($addr -in @('LOCAL', '')) { continue }
        $rows.Add([pscustomobject][ordered]@{ TimeUtc = (ConvertTo-WDTimeString $e.Time); Event = "$($e.Id) $($names[[int]$e.Id])"; User = $e.Data.User; Address = $addr; Session = $e.Data.SessionID })
        Add-WDTimeline -Time $e.Time -Source "RDP $($e.Id)" -Description "$($names[[int]$e.Id]): $($e.Data.User) from $addr"
    }
    foreach ($e in (Get-WDEvents -LogName 'Microsoft-Windows-TerminalServices-RDPClient/Operational' -Id 1024)) {
        $target = $e.Data.Value
        $rows.Add([pscustomobject][ordered]@{ TimeUtc = (ConvertTo-WDTimeString $e.Time); Event = '1024 Outbound RDP'; User = ''; Address = $target; Session = '' })
        Add-WDTimeline -Time $e.Time -Source 'RDPClient 1024' -Description "Outbound RDP connection to $target" -Severity 'Low'
        Add-Finding -Severity Low -Category 'Lateral Movement' -Title 'Outbound RDP connection from this host' -Evidence $target -Mitre 'T1021.001' -Time $e.Time -Source 'RDPClient 1024'
    }
    Save-WDArtifact -Name 'RdpActivity' -Section 'Event Logs' -Data $rows -Description 'Inbound and outbound Remote Desktop activity'
}

function Invoke-WDDefenderLog {
    $log = 'Microsoft-Windows-Windows Defender/Operational'
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($e in (Get-WDEvents -LogName $log -Id @(1006, 1015, 1116, 1117, 1118, 1119, 5001, 5004, 5007, 5010, 5012, 5013) -Since (Get-Date).AddDays(-1 * [Math]::Max(90, $script:WD.Options.Days)))) {
        $d = $e.Data
        $threat = $d.'Threat Name'; $path = $d.Path; $proc = $d.'Process Name'; $user = $d.'Detection User'; $act = $d.'Action Name'
        if ($e.Id -in @(1006, 1015, 1116, 1117, 1118, 1119) -and (Test-WDSelfPath "$path $proc")) {
            Add-Finding -Severity Info -Category 'Tool' -Title "Antivirus flagged Windows Detective's own files ($threat)" -Detail 'The detection points at this tool, not at the host. Not an indicator of compromise.' -Evidence $path -Time $e.Time -Source "Defender $($e.Id)"
            continue
        }
        $rows.Add([pscustomobject][ordered]@{ TimeUtc = (ConvertTo-WDTimeString $e.Time); EventId = $e.Id; Threat = $threat; Severity = $d.'Severity Name'; Path = $path; Process = $proc; User = $user; Action = $act; OldValue = $d.'Old Value'; NewValue = $d.'New Value' })
        switch ([int]$e.Id) {
            { $_ -in 1006, 1015, 1116 } { Add-Finding -Severity High -Category 'Malware' -Title "Microsoft Defender detection: $threat" -Detail "Severity $($d.'Severity Name'), category $($d.'Category Name')" -Evidence "Path: $path | Process: $proc | User: $user" -Mitre 'T1204.002' -Time $e.Time -Source "Defender $($e.Id)"; foreach ($seg in ([string]$path -split ';')) { if ($seg -match '^file:_(.+)$') { $script:WD.SuspiciousFiles[$Matches[1]] = 'Defender detection' } } }
            1117 { Add-WDTimeline -Time $e.Time -Source 'Defender 1117' -Description "Defender action '$act' on $threat" -Detail $path -Severity 'Medium' }
            { $_ -in 1118, 1119 } { Add-Finding -Severity Critical -Category 'Malware' -Title "Defender FAILED to remediate: $threat" -Evidence "Path: $path | Action: $act | Error: $($d.'Error Description')" -Mitre 'T1204.002' -Time $e.Time -Source "Defender $($e.Id)" }
            5001 { Add-Finding -Severity High -Category 'Defense Evasion' -Title 'Defender real-time protection was disabled' -Evidence 'Event 5001' -Mitre 'T1562.001' -Time $e.Time -Source 'Defender 5001' }
            { $_ -in 5010, 5012 } { Add-Finding -Severity High -Category 'Defense Evasion' -Title 'Defender scanning disabled' -Evidence "Event $($e.Id)" -Mitre 'T1562.001' -Time $e.Time -Source "Defender $($e.Id)" }
            5013 { Add-Finding -Severity High -Category 'Defense Evasion' -Title 'Tamper Protection blocked a change to Defender (someone tried to disable it)' -Evidence "$($d.Value) $($d.'New Value')" -Mitre 'T1562.001' -Time $e.Time -Source 'Defender 5013' }
            5007 {
                $nv = [string]$d.'New Value'
                if ($nv -match '(?i)\\Exclusions\\(Paths|Processes|Extensions|IpAddresses)\\') {
                    $sev = 'Medium'; if ($nv -match '(?i)(\\users\\|\\temp\\|\\programdata\\|\\windows\\|[a-z]:\\?\s*=|\\Extensions\\\.?(exe|dll|ps1)\b|powershell|cmd\.exe)') { $sev = 'High' }
                    Add-Finding -Severity $sev -Category 'Defense Evasion' -Title 'Defender exclusion added' -Evidence $nv -Mitre 'T1562.001' -Time $e.Time -Source 'Defender 5007'
                } elseif ($nv -match '(?i)(DisableRealtimeMonitoring|DisableAntiSpyware|DisableBehaviorMonitoring|DisableIOAVProtection|DisableScriptScanning|TamperProtection|SpynetReporting|SubmitSamplesConsent)\s*=\s*0x[1-9]') {
                    Add-Finding -Severity High -Category 'Defense Evasion' -Title 'Defender protection setting weakened' -Evidence $nv -Mitre 'T1562.001' -Time $e.Time -Source 'Defender 5007'
                }
            }
        }
    }
    Save-WDArtifact -Name 'DefenderEvents' -Section 'Event Logs' -Data $rows -Description 'Microsoft Defender detections and configuration changes (90 days)'
}

function Invoke-WDSysmonLog {
    $log = 'Microsoft-Windows-Sysmon/Operational'
    if (-not (Test-WDLogExists $log)) { return }
    $script:WD.SystemInfo['Sysmon'] = 'Present'
    $max = $script:WD.Options.MaxEvents
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($e in (Get-WDEvents -LogName $log -Id 1 -Max ($max * 4))) {
        $d = $e.Data
        if ("$($d.CommandLine) $($d.ParentCommandLine)" -match $script:WDSelfExclusionRx) { continue }
        $hits = Invoke-WDCommandCheck -Text $d.CommandLine -Source 'Sysmon 1' -Time $e.Time -Context "User $($d.User), parent $($d.ParentImage)"
        Test-WDParentChild -ParentPath $d.ParentImage -ChildPath $d.Image -CommandLine $d.CommandLine -Source 'Sysmon 1' -Time $e.Time
        if ($d.Hashes -match 'SHA256=([0-9A-Fa-f]{64})') { Add-WDObserved -Type Hashes -Value $Matches[1] -Source "Sysmon: $($d.Image)" }
        if ($d.Hashes -match 'MD5=([0-9A-Fa-f]{32})') { Add-WDObserved -Type Hashes -Value $Matches[1] -Source "Sysmon: $($d.Image)" }
        $tool = Get-WDToolMatch $d.Image
        if (-not $tool -and $d.OriginalFileName) { $tool = Get-WDToolMatch $d.OriginalFileName }
        if ($tool) { Add-Finding -Severity $tool.Severity -Category 'Execution' -Title "Sysmon process creation: $($tool.Label)" -Evidence "$($d.Image) $($d.CommandLine)" -Mitre $tool.Mitre -Time $e.Time -Source 'Sysmon 1' }
        if ($hits -gt 0 -or $tool) { $rows.Add([pscustomobject][ordered]@{ TimeUtc = (ConvertTo-WDTimeString $e.Time); EventId = 1; Image = $d.Image; Detail = $d.CommandLine; Parent = $d.ParentImage; User = $d.User }) }
    }
    foreach ($e in (Get-WDEvents -LogName $log -Id 3 -Max ($max * 2))) {
        $d = $e.Data
        if (Test-WDPublicIp $d.DestinationIp) {
            Add-WDObserved -Type Ips -Value $d.DestinationIp -Source "Sysmon 3: $($d.Image)"
            if ($d.DestinationHostname) { Add-WDObserved -Type Domains -Value $d.DestinationHostname -Source "Sysmon 3: $($d.Image)" }
            if ($d.Image -match $script:WDNoNetworkRx) {
                Add-Finding -Severity High -Category 'Network' -Title "Sysmon: unusual process made internet connection ($(Split-Path $d.Image -Leaf))" -Evidence "$($d.Image) -> $($d.DestinationIp):$($d.DestinationPort) $($d.DestinationHostname)" -Mitre 'T1071.001,T1218' -Time $e.Time -Source 'Sysmon 3'
                $rows.Add([pscustomobject][ordered]@{ TimeUtc = (ConvertTo-WDTimeString $e.Time); EventId = 3; Image = $d.Image; Detail = "$($d.DestinationIp):$($d.DestinationPort) $($d.DestinationHostname)"; Parent = ''; User = $d.User })
            }
        }
    }
    foreach ($e in (Get-WDEvents -LogName $log -Id 8 -Max $max)) {
        $d = $e.Data
        if ($d.SourceImage -match '(?i)\\(MsMpEng|csrss|wininit|services|svchost|lsass|vmtoolsd|MsSense|SenseIR)\.exe$') { continue }
        $sev = 'Medium'; if ((Get-WDPathRisk $d.SourceImage) -ne 'None' -or $d.TargetImage -match '(?i)\\(lsass|explorer|svchost|winlogon)\.exe$') { $sev = 'High' }
        Add-Finding -Severity $sev -Category 'Defense Evasion' -Title 'Remote thread created in another process (injection)' -Evidence "$($d.SourceImage) -> $($d.TargetImage) (StartFunction $($d.StartFunction))" -Mitre 'T1055' -Time $e.Time -Source 'Sysmon 8'
    }
    foreach ($e in (Get-WDEvents -LogName $log -Id 10 -Max $max)) {
        $d = $e.Data
        if ($d.TargetImage -notmatch '(?i)\\lsass\.exe$') { continue }
        if ($d.SourceImage -match '(?i)\\(MsMpEng|wininit|csrss|svchost|lsm|wmiprvse|taskmgr|vmtoolsd|MsSense|SenseNdr|NisSrv|procexp64|Sysmon64|Sysmon|MRT|smartscreen|thor64)\.exe$') { continue }
        if ($d.GrantedAccess -match '(?i)^0x(1010|1410|1438|143a|1fffff|1f3fff|1f1fff|1f0fff|40|1418|147a)$') {
            Add-Finding -Severity Critical -Category 'Credential Access' -Title 'LSASS memory accessed with credential-dumping rights' -Evidence "$($d.SourceImage) -> lsass.exe GrantedAccess $($d.GrantedAccess) | CallTrace $(Limit-WDText $d.CallTrace 300)" -Mitre 'T1003.001' -Time $e.Time -Source 'Sysmon 10'
        }
    }
    foreach ($e in (Get-WDEvents -LogName $log -Id @(12, 13) -Max $max)) {
        $d = $e.Data
        if ($d.TargetObject -match '(?i)\\(CurrentVersion\\(Run|RunOnce|Policies\\Explorer\\Run)|Winlogon\\(Shell|Userinit)|Image File Execution Options\\.*\\Debugger|Services\\[^\\]+\\ImagePath|Lsa\\(Security|Authentication|Notification) Packages|AppInit_DLLs|InprocServer32)') {
            if ($d.Image -match '(?i)\\(msiexec|TrustedInstaller|svchost|services|MsMpEng|OneDriveSetup|OneDrive)\.exe$') { continue }
            Add-Finding -Severity Medium -Category 'Persistence' -Title 'Sysmon: autostart registry location modified' -Evidence "$($d.Image) set $($d.TargetObject) = $($d.Details)" -Mitre 'T1547.001,T1112' -Time $e.Time -Source "Sysmon $($e.Id)"
            [void](Invoke-WDCommandCheck -Text $d.Details -Source "Sysmon $($e.Id) registry value" -Time $e.Time -Category 'Persistence')
        }
    }
    foreach ($e in (Get-WDEvents -LogName $log -Id 22 -Max ($max * 2))) {
        $d = $e.Data
        Add-WDObserved -Type Domains -Value $d.QueryName -Source "Sysmon 22: $($d.Image)"
        if ($d.QueryName -match '(?i)(ngrok|trycloudflare\.com|serveo\.net|\.loca\.lt|pastebin\.com|transfer\.sh|temp\.sh|api\.telegram\.org|\.onion|iplogger|duckdns\.org|portmap\.io)') {
            Add-Finding -Severity Medium -Category 'Network' -Title 'DNS query to tunnelling / paste service' -Evidence "$($d.Image) -> $($d.QueryName)" -Mitre 'T1102,T1572' -Time $e.Time -Source 'Sysmon 22'
        }
    }
    foreach ($e in (Get-WDEvents -LogName $log -Id 25 -Max 200)) {
        Add-Finding -Severity High -Category 'Defense Evasion' -Title "Sysmon: process tampering ($($e.Data.Type))" -Evidence $e.Data.Image -Mitre 'T1055.012' -Time $e.Time -Source 'Sysmon 25'
    }
    Save-WDArtifact -Name 'SysmonNotable' -Section 'Event Logs' -Data $rows -Description 'Notable Sysmon events'
}

function Invoke-WDMiscLogs {
    foreach ($e in (Get-WDEvents -LogName 'Microsoft-Windows-TaskScheduler/Operational' -Id @(106, 141, 140))) {
        $verb = switch ([int]$e.Id) { 106 { 'registered' } 140 { 'updated' } 141 { 'deleted' } }
        $name = [string]$e.Data.TaskName
        Add-WDTimeline -Time $e.Time -Source "TaskScheduler $($e.Id)" -Description "Task $verb : $name" -Detail $e.Data.UserContext -Severity 'Low'
        if ($e.Id -eq 141 -and $name -notlike '\Microsoft\*') {
            Add-Finding -Severity Low -Category 'Anti-Forensics' -Title 'Non-Microsoft scheduled task deleted' -Evidence "$name by $($e.Data.UserName)" -Mitre 'T1053.005,T1070' -Time $e.Time -Source 'TaskScheduler 141'
        }
    }
    foreach ($e in (Get-WDEvents -LogName 'Microsoft-Windows-Bits-Client/Operational' -Id 59)) {
        $url = [string]$e.Data.url
        if (-not $url -or $url -match '(?i)(windowsupdate|microsoft\.com|msedge|office\.net|delivery\.mp|live\.com|bing\.com|adobe|google)') { continue }
        Add-WDTimeline -Time $e.Time -Source 'BITS 59' -Description "BITS transfer: $($e.Data.name)" -Detail $url -Severity 'Low'
        [void](Invoke-WDCommandCheck -Text $url -Source 'BITS transfer' -Time $e.Time -Category 'Network')
        if ($url -match '(?i)\.(exe|dll|ps1|bat|hta|vbs|zip|7z|rar|bin|dat)(\?|$)') {
            Add-Finding -Severity Medium -Category 'Network' -Title 'BITS used to download an executable / archive from a non-Microsoft source' -Evidence "$($e.Data.name): $url" -Mitre 'T1197,T1105' -Time $e.Time -Source 'BITS 59'
        }
    }
    foreach ($e in (Get-WDEvents -LogName 'Microsoft-Windows-WinRM/Operational' -Id 91 -Max 500)) {
        Add-Finding -Severity Medium -Category 'Lateral Movement' -Title 'Inbound WinRM / PowerShell remoting session' -Evidence (($e.Data.Values) -join ' ') -Mitre 'T1021.006' -Time $e.Time -Source 'WinRM 91'
    }
    foreach ($e in (Get-WDEvents -LogName 'Microsoft-Windows-WMI-Activity/Operational' -Id 5861 -Max 200)) {
        $all = ($e.Data.Values -join ' ')
        if ($all -match '(?i)SCM Event Log (Consumer|Filter)|BVTConsumer') { continue }
        Add-Finding -Severity High -Category 'Persistence' -Title 'WMI permanent event consumer registered (event 5861)' -Evidence (Limit-WDText $all 1200) -Mitre 'T1546.003' -Time $e.Time -Source 'WMI-Activity 5861'
        [void](Invoke-WDCommandCheck -Text $all -Source 'WMI-Activity 5861' -Time $e.Time -Category 'Persistence')
    }
    foreach ($e in (Get-WDEvents -LogName 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' -Id @(2004, 2097, 2003, 2082))) {
        $d = $e.Data
        if ($e.Id -in @(2004, 2097)) {
            $app = [string]$d.ApplicationPath
            if ($d.Direction -eq '1' -and $d.Action -eq '3' -and ((Get-WDPathRisk $app) -ne 'None' -or $d.LocalPorts -match '^(3389|445|5985|5986|22|4444)$')) {
                Add-Finding -Severity Medium -Category 'Network' -Title 'Inbound firewall allow-rule added' -Evidence "$($d.RuleName): app $app ports $($d.LocalPorts) by $($d.ModifyingApplication)" -Mitre 'T1562.004' -Time $e.Time -Source "Firewall $($e.Id)"
            }
        } elseif ($d.SettingType -eq '1' -and ($d.SettingValueString -eq 'No' -or $d.SettingValue -match '^0+$')) {
            Add-Finding -Severity High -Category 'Defense Evasion' -Title 'Windows Firewall was turned off' -Evidence "Profile $($d.ProfileChanged) by $($d.ModifyingApplication)" -Mitre 'T1562.004' -Time $e.Time -Source "Firewall $($e.Id)"
        }
    }
}
