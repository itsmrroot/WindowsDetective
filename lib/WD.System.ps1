# =============================================================================
#  Windows Detective - System profile & account analysis
#  Powered by Bashar Salmo
#  WD-SELF-MARKER
# =============================================================================

function Invoke-WDSystemCollector {
    $si = $script:WD.SystemInfo
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
    $tz = Get-CimInstance Win32_TimeZone -ErrorAction SilentlyContinue

    $si['Hostname']        = $env:COMPUTERNAME
    $si['Domain']          = [string]$cs.Domain
    $si['Domain Joined']   = [string]$cs.PartOfDomain
    $si['OS']              = "$($os.Caption) ($($os.OSArchitecture))"
    $si['OS Build']        = "$($os.Version) build $($os.BuildNumber)"
    $si['OS Installed']    = ConvertTo-WDTimeString $os.InstallDate
    $si['Last Boot (UTC)'] = ConvertTo-WDTimeString $os.LastBootUpTime
    if ($os.LastBootUpTime) { $si['Uptime'] = ((Get-Date) - $os.LastBootUpTime).ToString('d\d\ hh\h\ mm\m') }
    $si['Manufacturer']    = "$($cs.Manufacturer) $($cs.Model)"
    $si['BIOS Serial']     = [string]$bios.SerialNumber
    $si['Memory (GB)']     = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
    $si['Time Zone']       = [string]$tz.Caption
    $si['Collected By']    = "$env:USERDOMAIN\$env:USERNAME"
    $si['Elevated']        = [string]$script:WD.IsAdmin
    $si['PowerShell']      = [string]$PSVersionTable.PSVersion
    $ips = @()
    try { $ips = @(Get-NetIPAddress -ErrorAction Stop | Where-Object { $_.IPAddress -notmatch '^(127\.|::1|fe80)' } | ForEach-Object { "$($_.IPAddress) ($($_.InterfaceAlias))" }) } catch { }
    $si['IP Addresses']    = ($ips -join ', ')

    if ($os.LastBootUpTime) { Add-WDTimeline -Time $os.LastBootUpTime -Source 'System' -Description 'Last system boot' }
    if ($os.InstallDate) { Add-WDTimeline -Time $os.InstallDate -Source 'System' -Description 'Windows installed' }

    # Hotfixes / patch level
    $hf = @(Get-CimInstance Win32_QuickFixEngineering -ErrorAction SilentlyContinue | Select-Object HotFixID, Description, InstalledBy, InstalledOn)
    Save-WDArtifact -Name 'Hotfixes' -Section 'System' -Data $hf -Description 'Installed Windows updates'
    $latest = $hf | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($latest) {
        $si['Last Patch'] = $latest.InstalledOn.ToString('yyyy-MM-dd')
        $age = ((Get-Date) - $latest.InstalledOn).Days
        if ($age -gt 60) {
            Add-Finding -Severity Low -Category 'Posture' -Title "No Windows update installed for $age days" -Detail 'Unpatched hosts are a common initial-access vector.' -Evidence "Latest: $($latest.HotFixID) on $($si['Last Patch'])"
        }
    }

    # PATH hijacking: user-writable directories in the SYSTEM path
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $i = 0
    foreach ($dir in ($machinePath -split ';' | Where-Object { $_ })) {
        $i++
        $expanded = [Environment]::ExpandEnvironmentVariables($dir)
        if ((Get-WDPathRisk ($expanded.TrimEnd('\') + '\')) -ne 'None') {
            Add-Finding -Severity Medium -Category 'Persistence' -Title 'User-writable directory in the system PATH' -Detail "Entry #$i of machine PATH is writable by users; DLL/EXE planting there can hijack execution." -Evidence $expanded -Mitre 'T1574.007'
        }
    }
    $envVars = Get-ChildItem Env: | Select-Object Name, Value
    Save-WDArtifact -Name 'EnvironmentVariables' -Section 'System' -Data $envVars -Description 'Environment of the collecting session'

    # Installed software
    $sw = New-Object System.Collections.Generic.List[object]
    $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    foreach ($h in (Get-WDUserHives)) { $keys += "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Uninstall" }
    foreach ($k in $keys) {
        foreach ($item in @(Get-ChildItem -LiteralPath $k -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty -LiteralPath $item.PSPath -ErrorAction SilentlyContinue
            if (-not $p.DisplayName) { continue }
            $installed = $null
            if ($p.InstallDate -match '^\d{8}$') { try { $installed = [datetime]::ParseExact($p.InstallDate, 'yyyyMMdd', $null) } catch { } }
            $row = [pscustomobject][ordered]@{
                Name = $p.DisplayName; Version = $p.DisplayVersion; Publisher = $p.Publisher
                InstallDate = $(if ($installed) { $installed.ToString('yyyy-MM-dd') } else { '' })
                InstallLocation = $p.InstallLocation; Uninstall = $p.UninstallString; Scope = $(if ($k -like 'Registry::HKEY_USERS*') { 'User' } else { 'Machine' })
            }
            $sw.Add($row)
            if ($installed -and $installed -ge $script:WD.Since.Date) {
                Add-WDTimeline -Time $installed -Source 'Software' -Description "Software installed: $($p.DisplayName) $($p.DisplayVersion)" -Detail $p.Publisher
            }
            $tool = Get-WDToolMatch (($p.DisplayName -split '\s')[0])
            if ($tool) {
                $sev = $tool.Severity
                if ($installed -and $installed -ge $script:WD.Since.Date -and $tool.Kind -eq 'RMM') { $sev = 'High' }
                Add-Finding -Severity $sev -Category 'Software' -Title "Installed: $($tool.Label)" -Detail 'Verify this software is authorised on this host.' -Evidence "$($p.DisplayName) $($p.DisplayVersion) | $($p.Publisher) | installed $($row.InstallDate) | $($p.InstallLocation)" -Mitre $tool.Mitre -Time $installed
            }
        }
    }
    Save-WDArtifact -Name 'InstalledSoftware' -Section 'System' -Data ($sw | Sort-Object Name) -Description 'Uninstall registry keys (machine + per user)'
}

function Invoke-WDAccountCollector {
    # Local users
    $users = @()
    try {
        $users = @(Get-LocalUser -ErrorAction Stop | ForEach-Object {
            [pscustomobject][ordered]@{
                Name = $_.Name; Enabled = $_.Enabled; SID = [string]$_.SID; LastLogon = (ConvertTo-WDTimeString $_.LastLogon)
                PasswordLastSet = (ConvertTo-WDTimeString $_.PasswordLastSet); PasswordRequired = $_.PasswordRequired
                PasswordExpires = (ConvertTo-WDTimeString $_.PasswordExpires); Description = $_.Description
            }
        })
    } catch {
        Write-WDLog 'Get-LocalUser unavailable, falling back to WMI' WARN
        $users = @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject][ordered]@{ Name = $_.Name; Enabled = (-not $_.Disabled); SID = $_.SID; LastLogon = ''; PasswordLastSet = ''; PasswordRequired = $_.PasswordRequired; PasswordExpires = ''; Description = $_.Description }
        })
    }
    Save-WDArtifact -Name 'LocalUsers' -Section 'Accounts' -Data $users -Description 'Local SAM accounts'

    foreach ($u in $users) {
        if ($u.SID -match '-500$' -and $u.Enabled) {
            Add-Finding -Severity Medium -Category 'Accounts' -Title 'Built-in Administrator account is enabled' -Evidence "$($u.Name) (last logon $($u.LastLogon))" -Mitre 'T1078'
        }
        if ($u.SID -match '-501$' -and $u.Enabled) {
            Add-Finding -Severity High -Category 'Accounts' -Title 'Guest account is enabled' -Evidence $u.Name -Mitre 'T1078'
        }
        if ($u.Name -match '\$$') {
            Add-Finding -Severity High -Category 'Accounts' -Title 'Local account name ends with $ (hidden-account trick)' -Evidence "$($u.Name) SID $($u.SID)" -Mitre 'T1564.002,T1136.001'
        }
        if ($u.Enabled -and $u.PasswordRequired -eq $false) {
            Add-Finding -Severity Medium -Category 'Accounts' -Title 'Enabled local account does not require a password' -Evidence $u.Name -Mitre 'T1078'
        }
        if ($u.PasswordLastSet) { Add-WDTimeline -Time $u.PasswordLastSet -Source 'Accounts' -Description "Password set for local account $($u.Name)" }
    }

    # Accounts hidden from the logon screen
    foreach ($v in (Get-WDRegValues 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList')) {
        if ($v.Value -eq '0') {
            Add-Finding -Severity High -Category 'Accounts' -Title 'Account hidden from logon screen (SpecialAccounts\UserList)' -Evidence $v.Name -Mitre 'T1564.002'
        }
    }

    # Privileged group membership
    $members = New-Object System.Collections.Generic.List[object]
    foreach ($g in @('S-1-5-32-544', 'S-1-5-32-555', 'S-1-5-32-580', 'S-1-5-32-562')) {
        $grpName = $g
        try {
            $grp = Get-LocalGroup -SID $g -ErrorAction Stop
            $grpName = $grp.Name
            foreach ($m in @(Get-LocalGroupMember -SID $g -ErrorAction Stop)) {
                $members.Add([pscustomobject][ordered]@{ Group = $grpName; Member = $m.Name; Type = [string]$m.ObjectClass; Source = [string]$m.PrincipalSource; SID = [string]$m.SID })
            }
        } catch {
            # Get-LocalGroupMember breaks on orphaned SIDs; fall back to net.exe
            $name = switch ($g) { 'S-1-5-32-544' { 'Administrators' } 'S-1-5-32-555' { 'Remote Desktop Users' } 'S-1-5-32-580' { 'Remote Management Users' } default { 'Distributed COM Users' } }
            $out = & net.exe localgroup $name 2>$null
            if ($out) {
                $started = $false
                foreach ($line in $out) {
                    if ($line -match '^-{5,}') { $started = $true; continue }
                    if ($started -and $line -and $line -notmatch 'command completed') { $members.Add([pscustomobject][ordered]@{ Group = $name; Member = $line.Trim(); Type = ''; Source = 'net.exe'; SID = '' }) }
                }
            }
        }
    }
    Save-WDArtifact -Name 'PrivilegedGroupMembers' -Section 'Accounts' -Data $members -Description 'Administrators, Remote Desktop Users, Remote Management Users, DCOM Users'
    foreach ($m in $members) {
        if ($m.SID -match '-500$' -or $m.Member -match '\\Domain Admins$') { continue }
        $sev = 'Info'
        if ($m.Group -match 'Remote Desktop|Remote Management|DCOM|^S-1-5-32-5(55|80|62)') { $sev = 'Low' }
        if ($m.Member -match '\$$') { $sev = 'High' }
        Add-Finding -Severity $sev -Category 'Accounts' -Title "Member of privileged local group '$($m.Group)'" -Detail 'Confirm every member is expected.' -Evidence "$($m.Member) [$($m.Type), $($m.Source)]" -Mitre 'T1098'
    }

    # Profiles and interactive sessions
    $profiles = @(Get-WDProfiles | ForEach-Object { [pscustomobject][ordered]@{ User = $_.User; SID = $_.Sid; Path = $_.Path; Loaded = $_.Loaded; LastUseUtc = (ConvertTo-WDTimeString $_.LastUse) } })
    Save-WDArtifact -Name 'UserProfiles' -Section 'Accounts' -Data $profiles -Description 'User profiles on disk'
    foreach ($p in (Get-WDProfiles)) {
        $created = $null
        try { $created = (Get-Item -LiteralPath $p.Path -Force).CreationTime } catch { }
        if ($created -and $created -ge $script:WD.Since) {
            Add-Finding -Severity Medium -Category 'Accounts' -Title 'User profile created during the investigation window (first logon of new account)' -Evidence "$($p.User) -> $($p.Path) created $(ConvertTo-WDTimeString $created) UTC" -Mitre 'T1136.001,T1078' -Time $created
        }
    }
    $sessions = @()
    try {
        $q = & quser.exe 2>$null
        if ($q) { $sessions = @($q | Select-Object -Skip 1 | ForEach-Object { [pscustomobject]@{ Session = $_.Trim() } }) }
    } catch { }
    Save-WDArtifact -Name 'LoggedOnSessions' -Section 'Accounts' -Data $sessions -Description 'quser output'
}
