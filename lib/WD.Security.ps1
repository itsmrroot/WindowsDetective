# =============================================================================
#  Windows Detective - Security posture & defense evasion
#  Powered by Bashar Salmo
#  WD-SELF-MARKER
# =============================================================================

function Invoke-WDSecurityCollector {
    Invoke-WDDefenderStatus
    Invoke-WDDrivers
    Invoke-WDHardening
}

function Invoke-WDDefenderStatus {
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        $s = Get-MpComputerStatus -ErrorAction Stop
        $script:WD.SystemInfo['Defender'] = "RTP=$($s.RealTimeProtectionEnabled) Tamper=$($s.IsTamperProtected) Sig=$($s.AntivirusSignatureVersion)"
        foreach ($prop in @('AMRunningMode', 'AntivirusEnabled', 'RealTimeProtectionEnabled', 'BehaviorMonitorEnabled', 'IoavProtectionEnabled', 'OnAccessProtectionEnabled', 'IsTamperProtected', 'AntivirusSignatureLastUpdated', 'AntivirusSignatureVersion', 'FullScanEndTime', 'QuickScanEndTime')) {
            $rows.Add([pscustomobject]@{ Setting = $prop; Value = [string]$s.$prop })
        }
        if ($s.AMRunningMode -eq 'Normal' -or -not $s.AMRunningMode) {
            if (-not $s.RealTimeProtectionEnabled) { Add-Finding -Severity High -Category 'Defense Evasion' -Title 'Microsoft Defender real-time protection is OFF' -Evidence "RealTimeProtectionEnabled=$($s.RealTimeProtectionEnabled)" -Mitre 'T1562.001' }
            if (-not $s.BehaviorMonitorEnabled) { Add-Finding -Severity Medium -Category 'Defense Evasion' -Title 'Defender behaviour monitoring is OFF' -Evidence "BehaviorMonitorEnabled=$($s.BehaviorMonitorEnabled)" -Mitre 'T1562.001' }
            if (-not $s.IsTamperProtected) { Add-Finding -Severity Medium -Category 'Posture' -Title 'Defender Tamper Protection is OFF' -Evidence "IsTamperProtected=$($s.IsTamperProtected)" -Mitre 'T1562.001' }
            if ($s.AntivirusSignatureLastUpdated -and ((Get-Date) - $s.AntivirusSignatureLastUpdated).TotalDays -gt 7) {
                Add-Finding -Severity Medium -Category 'Posture' -Title 'Defender signatures are out of date' -Evidence "Last update $($s.AntivirusSignatureLastUpdated)" -Mitre 'T1562.001'
            }
        }
    } catch { Write-WDLog 'Defender status unavailable (third-party AV or Defender removed)' WARN }
    Save-WDArtifact -Name 'DefenderStatus' -Section 'Security' -Data $rows -Description 'Microsoft Defender status'

    # Exclusions: a favourite of attackers
    $ex = New-Object System.Collections.Generic.List[object]
    try {
        $p = Get-MpPreference -ErrorAction Stop
        foreach ($pair in @(@('Path', $p.ExclusionPath), @('Process', $p.ExclusionProcess), @('Extension', $p.ExclusionExtension), @('IpAddress', $p.ExclusionIpAddress))) {
            foreach ($v in @($pair[1])) {
                if (-not $v -or $v -match '^N/A') { continue }
                $ex.Add([pscustomobject]@{ Type = $pair[0]; Value = $v })
                $sev = 'Medium'
                if ($v -match '(?i)^[a-z]:\\?$|\\users\\?|\\temp\\?|\\appdata|\\programdata\\?$|\\windows\\?$|\\downloads|\\public|^\.?(exe|dll|ps1|bat|vbs|js)$|powershell|cmd\.exe|rundll32|regsvr32|mshta') { $sev = 'High' }
                Add-Finding -Severity $sev -Category 'Defense Evasion' -Title "Defender exclusion ($($pair[0]))" -Detail 'Attackers add exclusions so their tools are never scanned.' -Evidence $v -Mitre 'T1562.001'
            }
        }
        if ($p.DisableRealtimeMonitoring) { Add-Finding -Severity High -Category 'Defense Evasion' -Title 'Defender preference DisableRealtimeMonitoring is set' -Evidence 'Get-MpPreference' -Mitre 'T1562.001' }
        if ($p.DisableScriptScanning) { Add-Finding -Severity Medium -Category 'Defense Evasion' -Title 'Defender script scanning disabled' -Evidence 'DisableScriptScanning=True' -Mitre 'T1562.001' }
        if ($p.MAPSReporting -eq 0) { Add-Finding -Severity Low -Category 'Posture' -Title 'Defender cloud protection (MAPS) disabled' -Evidence 'MAPSReporting=0' -Mitre 'T1562.001' }
    } catch { }
    foreach ($k in @('Paths', 'Processes', 'Extensions')) {
        foreach ($v in (Get-WDRegValues "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\$k")) {
            if ($ex | Where-Object { $_.Value -eq $v.Name }) { continue }
            $ex.Add([pscustomobject]@{ Type = "$k (registry)"; Value = $v.Name })
            Add-Finding -Severity Medium -Category 'Defense Evasion' -Title "Defender exclusion in registry ($k)" -Evidence $v.Name -Mitre 'T1562.001'
        }
    }
    foreach ($pol in @('DisableAntiSpyware', 'DisableAntiVirus')) {
        if ((Get-WDRegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' $pol) -eq 1) { Add-Finding -Severity High -Category 'Defense Evasion' -Title "Defender disabled by policy ($pol=1)" -Evidence 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' -Mitre 'T1562.001' }
    }
    if ((Get-WDRegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' 'DisableRealtimeMonitoring') -eq 1) {
        Add-Finding -Severity High -Category 'Defense Evasion' -Title 'Defender real-time protection disabled by policy' -Evidence 'Real-Time Protection\DisableRealtimeMonitoring=1' -Mitre 'T1562.001'
    }
    Save-WDArtifact -Name 'DefenderExclusions' -Section 'Security' -Data $ex -Description 'Microsoft Defender exclusions'

    # Detection history
    try {
        $threats = @{}
        foreach ($t in @(Get-MpThreat -ErrorAction Stop)) { $threats[[string]$t.ThreatID] = $t.ThreatName }
        $det = @(Get-MpThreatDetection -ErrorAction Stop | ForEach-Object {
            [pscustomobject][ordered]@{ DetectedUtc = (ConvertTo-WDTimeString $_.InitialDetectionTime); Threat = $threats[[string]$_.ThreatID]; Resources = (@($_.Resources) -join ' ; '); Process = $_.ProcessName; User = $_.DomainUser; ActionSuccess = $_.ActionSuccess; Remediated = (ConvertTo-WDTimeString $_.RemediationTime) }
        })
        foreach ($d in $det) {
            if (Test-WDSelfPath $d.Resources) {
                Add-Finding -Severity Info -Category 'Tool' -Title "Antivirus flagged Windows Detective's own files ($($d.Threat))" -Detail 'The detection points at this tool, not at the host. Not an indicator of compromise.' -Evidence $d.Resources -Time $d.DetectedUtc
                continue
            }
            $sev = 'High'; if ($d.ActionSuccess -eq $false) { $sev = 'Critical' }
            Add-Finding -Severity $sev -Category 'Malware' -Title "Defender detection history: $($d.Threat)" -Evidence "$($d.Resources) | process $($d.Process) | user $($d.User) | remediated $($d.Remediated)" -Mitre 'T1204.002' -Time $d.DetectedUtc
            foreach ($r in ($d.Resources -split ' ; ')) { if ($r -match '^file:_(.+)$') { $script:WD.SuspiciousFiles[$Matches[1]] = 'Defender history' } }
        }
        Save-WDArtifact -Name 'DefenderDetections' -Section 'Security' -Data $det -Description 'Microsoft Defender detection history'
    } catch { }

    # Third-party security products
    try {
        $av = @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object {
            $state = '{0:X6}' -f [int]$_.productState
            [pscustomobject][ordered]@{ Product = $_.displayName; Path = $_.pathToSignedProductExe; Enabled = ($state.Substring(2, 2) -in @('10', '11')); UpToDate = ($state.Substring(4, 2) -eq '00'); State = $state }
        })
        Save-WDArtifact -Name 'AntivirusProducts' -Section 'Security' -Data $av -Description 'Registered antivirus products (Security Center)'
        $script:WD.SystemInfo['Antivirus'] = ($av | ForEach-Object { "$($_.Product) (enabled=$($_.Enabled))" }) -join ', '
        if ($av.Count -gt 0 -and -not ($av | Where-Object { $_.Enabled })) {
            Add-Finding -Severity High -Category 'Defense Evasion' -Title 'No enabled antivirus product registered' -Evidence $script:WD.SystemInfo['Antivirus'] -Mitre 'T1562.001'
        }
    } catch { }
}

function Invoke-WDDrivers {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($d in @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue)) {
        $path = Get-WDExecutablePath $d.PathName
        $info = Get-WDFileInfo $path
        $rows.Add([pscustomobject][ordered]@{ Name = $d.Name; State = $d.State; StartMode = $d.StartMode; Path = $path; Signature = $info.SigStatus; Signer = $info.Signer; Company = $info.Company; SHA256 = $info.SHA256; ModifiedUtc = (ConvertTo-WDTimeString $info.Modified) })
        $ev = "$($d.Name) [$($d.State)/$($d.StartMode)] $path | signer $($info.Signer) | sha256 $($info.SHA256)"
        if (Test-WDVulnerableDriver $path) {
            $sev = 'High'; if ($d.State -eq 'Running') { $sev = 'Critical' }
            Add-Finding -Severity $sev -Category 'Defense Evasion' -Title 'Known vulnerable / abused driver present (BYOVD)' -Detail 'Attackers load signed-but-vulnerable drivers to kill EDR and gain kernel access. Check loldrivers.io.' -Evidence $ev -Mitre 'T1068,T1562.001'
        }
        if ($info.Exists -and $d.State -eq 'Running' -and $info.SigStatus -ne 'Valid') {
            Add-Finding -Severity High -Category 'Defense Evasion' -Title 'Running kernel driver without valid signature' -Evidence $ev -Mitre 'T1014,T1553'
        }
        if ($path -and $path -notmatch '(?i)^[a-z]:\\windows\\' -and $d.State -eq 'Running') {
            $sev = 'Low'; if ((Get-WDPathRisk $path) -ne 'None') { $sev = 'High' }
            Add-Finding -Severity $sev -Category 'Defense Evasion' -Title 'Running driver loaded from outside C:\Windows' -Evidence $ev -Mitre 'T1014'
        }
        if ($info.Modified -and $info.Modified -ge $script:WD.Since.ToUniversalTime()) {
            Add-WDTimeline -Time $info.Modified -Source 'Drivers' -Description "Driver file modified: $($d.Name)" -Detail $path -Severity 'Low'
        }
    }
    Save-WDArtifact -Name 'Drivers' -Section 'Security' -Data $rows -Description 'Kernel drivers with signature status'
}

function Invoke-WDHardening {
    $rows = New-Object System.Collections.Generic.List[object]
    $add = { param($n, $v, $good) $rows.Add([pscustomobject][ordered]@{ Control = $n; Value = [string]$v; Expected = $good }) }

    $sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $lua = Get-WDRegValue $sys 'EnableLUA'; & $add 'UAC EnableLUA' $lua '1'
    if ($lua -eq 0) { Add-Finding -Severity High -Category 'Defense Evasion' -Title 'User Account Control is disabled' -Evidence 'EnableLUA=0' -Mitre 'T1548.002' }
    $cpba = Get-WDRegValue $sys 'ConsentPromptBehaviorAdmin'; & $add 'UAC ConsentPromptBehaviorAdmin' $cpba '2 or 5'
    if ($cpba -eq 0) { Add-Finding -Severity Medium -Category 'Defense Evasion' -Title 'UAC elevates administrators silently (no prompt)' -Evidence 'ConsentPromptBehaviorAdmin=0' -Mitre 'T1548.002' }
    $latfp = Get-WDRegValue $sys 'LocalAccountTokenFilterPolicy'; & $add 'LocalAccountTokenFilterPolicy' $latfp '0 / not set'
    if ($latfp -eq 1) { Add-Finding -Severity Medium -Category 'Lateral Movement' -Title 'LocalAccountTokenFilterPolicy=1 (remote admin with local accounts / pass-the-hash enabled)' -Evidence "$sys LocalAccountTokenFilterPolicy=1" -Mitre 'T1550.002' }

    $wd = Get-WDRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'; & $add 'WDigest UseLogonCredential' $wd '0 / not set'
    if ($wd -eq 1) { Add-Finding -Severity High -Category 'Credential Access' -Title 'WDigest cleartext credential caching enabled' -Detail 'Attackers set this so credential dumpers can read plaintext passwords from LSASS.' -Evidence 'UseLogonCredential=1' -Mitre 'T1003.001,T1112' }
    $ppl = Get-WDRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'; & $add 'LSA protection (RunAsPPL)' $ppl '1 or 2'
    if ($ppl -notin @(1, 2)) { Add-Finding -Severity Info -Category 'Posture' -Title 'LSA protection (RunAsPPL) not enabled' -Evidence "RunAsPPL=$ppl" -Mitre 'T1003.001' }
    $dra = Get-WDRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'DisableRestrictedAdmin'; & $add 'DisableRestrictedAdmin' $dra 'not set'
    if ($dra -eq 0) { Add-Finding -Severity Medium -Category 'Lateral Movement' -Title 'RDP Restricted Admin mode enabled (allows pass-the-hash over RDP)' -Evidence 'DisableRestrictedAdmin=0' -Mitre 'T1550.002' }
    $nolm = Get-WDRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash'; & $add 'NoLMHash' $nolm '1'
    if ($nolm -eq 0) { Add-Finding -Severity Medium -Category 'Posture' -Title 'LM hashes are stored' -Evidence 'NoLMHash=0' -Mitre 'T1003.002' }
    $lmc = Get-WDRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'; & $add 'LmCompatibilityLevel' $lmc '5'
    if ($null -ne $lmc -and $lmc -lt 3) { Add-Finding -Severity Medium -Category 'Posture' -Title 'NTLMv1/LM authentication allowed' -Evidence "LmCompatibilityLevel=$lmc" -Mitre 'T1557' }

    try {
        $smb = Get-SmbServerConfiguration -ErrorAction Stop
        & $add 'SMBv1 server' $smb.EnableSMB1Protocol 'False'
        if ($smb.EnableSMB1Protocol) { Add-Finding -Severity Medium -Category 'Posture' -Title 'SMBv1 server enabled' -Evidence 'EnableSMB1Protocol=True' -Mitre 'T1210' }
        & $add 'SMB signing required' $smb.RequireSecuritySignature 'True'
    } catch { }
    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        $cg = ($dg.SecurityServicesRunning -contains 1)
        & $add 'Credential Guard running' $cg 'True'
        & $add 'VBS status' $dg.VirtualizationBasedSecurityStatus '2'
    } catch { }
    try {
        foreach ($v in @(Get-BitLockerVolume -ErrorAction Stop)) { & $add "BitLocker $($v.MountPoint)" $v.ProtectionStatus 'On' }
    } catch { }
    $sb = $null
    try { $sb = Confirm-SecureBootUEFI -ErrorAction Stop } catch { }
    & $add 'Secure Boot' $sb 'True'
    $ps2 = $null
    try { $ps2 = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop).State } catch { }
    & $add 'PowerShell v2 feature' $ps2 'Disabled'
    if ([string]$ps2 -eq 'Enabled') { Add-Finding -Severity Low -Category 'Posture' -Title 'PowerShell 2.0 engine installed (logging-bypass downgrade possible)' -Evidence 'MicrosoftWindowsPowerShellV2Root=Enabled' -Mitre 'T1562.010' }
    $sysmon = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue | Select-Object -First 1
    & $add 'Sysmon installed' ([bool]$sysmon) 'True (recommended)'

    # Stored credentials
    $ck = (& cmdkey.exe /list 2>$null) -join "`n"
    $targets = @([regex]::Matches($ck, 'Target:\s*(.+)') | ForEach-Object { $_.Groups[1].Value.Trim() })
    & $add 'Saved credentials (cmdkey, current user)' $targets.Count '-'
    foreach ($p in (Get-WDProfiles)) {
        foreach ($f in @("$($p.Path)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")) {
            if (Test-Path -LiteralPath $f) {
                $pw = @(Select-String -LiteralPath $f -Pattern '(?i)(ConvertTo-SecureString\s+.*-AsPlainText|password\s*=\s*["''][^"'']{4,}|-Password\s+["''][^"'']{4,}|net\s+user\s+\S+\s+[^\s/]{4,})' -ErrorAction SilentlyContinue | Select-Object -First 5)
                foreach ($m in $pw) { Add-Finding -Severity Medium -Category 'Credential Access' -Title 'Plaintext credential in PowerShell history' -Evidence "$($p.User) line $($m.LineNumber): $(Limit-WDText $m.Line 200)" -Mitre 'T1552.001' }
            }
        }
    }
    foreach ($f in @("$env:SystemRoot\Panther\Unattend.xml", "$env:SystemRoot\Panther\Unattend\Unattend.xml", "$env:SystemRoot\System32\Sysprep\unattend.xml", "$env:SystemRoot\System32\Sysprep\Panther\unattend.xml")) {
        if ((Test-Path -LiteralPath $f) -and (Select-String -LiteralPath $f -Pattern '<Password>' -Quiet -ErrorAction SilentlyContinue)) {
            Add-Finding -Severity Low -Category 'Credential Access' -Title 'Unattend file containing a password' -Evidence $f -Mitre 'T1552.001'
        }
    }
    Save-WDArtifact -Name 'HardeningControls' -Section 'Security' -Data $rows -Description 'Security controls relevant to credential theft and lateral movement'
}
