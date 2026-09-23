# =============================================================================
#  Windows Detective - Detection rules & threat intelligence lists
#  Powered by Bashar Salmo
#  WD-SELF-MARKER
#
#  Command-line rules are applied to every command line / script the tool sees:
#  running processes, 4688, Sysmon 1, 4104 script blocks, services, scheduled
#  tasks, Run keys, WMI consumers, RunMRU, PSReadLine history and dropped scripts.
# =============================================================================

# Text containing these markers belongs to this tool (or its case output) and is never flagged.
# Case folders are named WDCase_<HOST>_<yyyyMMdd>_<HHmmss>. Only text that points into this run's tool/case
# folder or into such a case folder is treated as the tool's own activity (see Test-WDSelfText) - a bare
# keyword would let an attacker hide a command by simply mentioning the tool's name.
$script:WDCaseFolderRx = '(?i)\\WDCase_[A-Za-z0-9._-]+_\d{8}_\d{6}(\\|\.zip\b)'
$script:WDModulePathRx = '(?i)\\lib\\WD\.(Core|Rules|System|Processes|Network|Persistence|Execution|EventLogs|FileSystem|Security|Evidence|Report)\.ps1\b|\\WindowsDetective\.ps1\b|\\Run-WindowsDetective\.bat\b|\\tests\\Invoke-WDSelfTest\.ps1\b|\\rules\\detection-data\.json\b'

# Detection data (command-line rules, tool / RMM / driver intel) lives in rules\detection-data.json.
# Keeping attack patterns out of the PowerShell source stops AMSI from blocking the tool itself.
$script:WDDataPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'rules\detection-data.json'
$script:WDCommandRules = New-Object System.Collections.Generic.List[object]
$script:WDKnownTools = @{}
$script:WDRmmTools = @{}
$script:WDVulnerableDrivers = @()

function Import-WDDetectionData {
    param([string]$Path = $script:WDDataPath)
    $data = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
    $script:WDCommandRules.Clear()
    foreach ($r in $data.commandRules) {
        try {
            $rx = New-Object System.Text.RegularExpressions.Regex($r.pattern, ([System.Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant'))
            $script:WDCommandRules.Add([pscustomobject]@{ Id = $r.id; Severity = $r.severity; Mitre = $r.mitre; Title = $r.title; Regex = $rx })
        } catch { Write-Warning "Rule $($r.id) failed to compile: $($_.Exception.Message)" }
    }
    $script:WDKnownTools = @{}
    foreach ($p in $data.knownTools.PSObject.Properties) { $script:WDKnownTools[$p.Name] = @($p.Value.severity, $p.Value.label, $p.Value.mitre) }
    $script:WDRmmTools = @{}
    foreach ($p in $data.rmmTools.PSObject.Properties) { $script:WDRmmTools[$p.Name] = [string]$p.Value }
    $script:WDVulnerableDrivers = @($data.vulnerableDrivers | ForEach-Object { ([string]$_).ToLowerInvariant() })
    return @($data.commandRules).Count
}

function Test-WDCommandLine {
    param([string]$Text)
    $hits = New-Object System.Collections.Generic.List[object]
    if ([string]::IsNullOrWhiteSpace($Text)) { return $hits }
    if (Test-WDSelfText $Text) { return $hits }
    foreach ($r in $script:WDCommandRules) { if ($r.Regex.IsMatch($Text)) { $hits.Add($r) } }
    return $hits
}

# Decodes the payload of "powershell -EncodedCommand <base64>" so analysts see the real command.
function ConvertFrom-WDEncodedCommand {
    param([string]$Text)
    $m = [regex]::Match($Text, '(?i)\s[-/]e[a-z]*\s+["'']?([A-Za-z0-9+/]{20,}={0,2})')
    if (-not $m.Success) { return '' }
    try {
        $b64 = $m.Groups[1].Value
        while ($b64.Length % 4) { $b64 += '=' }
        $bytes = [System.Convert]::FromBase64String($b64)
        $decoded = [Text.Encoding]::Unicode.GetString($bytes)
        if ($decoded -match '[^\x09\x0A\x0D\x20-\x7E]{4,}') { $decoded = [Text.Encoding]::UTF8.GetString($bytes) }
        return $decoded.Trim([char]0)
    } catch { return '' }
}

# Runs all command rules against a text and raises one finding per matching rule.
function Invoke-WDCommandCheck {
    param([string]$Text, [string]$Source, $Time = $null, [string]$Context = '', [string]$Category = 'Execution', [switch]$NoDecode)
    $hits = Test-WDCommandLine $Text
    $decoded = ''
    if (-not $NoDecode -and ($hits | Where-Object { $_.Id -eq 'CMD-001' })) { $decoded = ConvertFrom-WDEncodedCommand $Text }
    $decodedHits = 0
    if ($decoded) { $decodedHits = Invoke-WDCommandCheck -Text $decoded -Source "$Source (decoded -EncodedCommand)" -Time $Time -Context $Context -Category $Category -NoDecode }
    foreach ($r in $hits) {
        $detail = "Rule $($r.Id) matched in $Source."
        if ($Context) { $detail += " $Context" }
        $sev = $r.Severity
        if ($decoded -and $r.Id -eq 'CMD-001') {
            $detail += " DECODED COMMAND: $(Limit-WDText $decoded 800)"
            # Plenty of legitimate software uses -EncodedCommand; stay High only when the payload is suspicious.
            if ($decodedHits -eq 0) { $sev = 'Medium'; $detail += ' (decoded payload matched no other rule)' }
        }
        Add-Finding -Severity $sev -Category $Category -Title $r.Title -Detail $detail -Evidence $Text -Mitre $r.Mitre -Time $Time -Source $Source
    }
    $count = $hits.Count + $decodedHits
    return $count
}

# ----------------------------------------------------------------------------- process relationships
$script:WDOfficeRx    = '(?i)\\(winword|excel|powerpnt|outlook|onenote|onenotem|msaccess|mspub|visio|wordpad|acrord32|acrobat|foxitpdfreader)\.exe$'
$script:WDShellRx     = '(?i)\\(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msbuild|schtasks|wmic|curl|installutil|msiexec|hh|forfiles|bash|wsl)\.exe$'
$script:WDServerAppRx = '(?i)\\(w3wp|httpd|nginx|php-cgi|sqlservr|tomcat\d*|umworkerprocess|exchangeowa)\.exe$'
$script:WDScriptHostRx = '(?i)\\(wscript|cscript|mshta)\.exe$'

function Test-WDParentChild {
    param([string]$ParentPath, [string]$ChildPath, [string]$CommandLine, [string]$Source, $Time = $null)
    if (-not $ParentPath -or -not $ChildPath) { return }
    $ev = "Parent: $ParentPath | Child: $ChildPath | $CommandLine"
    if (Test-WDSelfText $ev) { return }
    if ($ParentPath -match $script:WDOfficeRx -and $ChildPath -match $script:WDShellRx) {
        Add-Finding -Severity High -Category 'Execution' -Title 'Office / document reader spawned a shell or LOLBin' -Detail "Classic malicious-document behaviour ($Source)." -Evidence $ev -Mitre 'T1566.001,T1204.002' -Time $Time -Source $Source
    }
    if ($ParentPath -match $script:WDServerAppRx -and $ChildPath -match $script:WDShellRx) {
        Add-Finding -Severity Critical -Category 'Execution' -Title 'Server process spawned a shell (possible web shell)' -Detail "($Source)" -Evidence $ev -Mitre 'T1505.003' -Time $Time -Source $Source
    }
    if ($ParentPath -match '(?i)\\wmiprvse\.exe$' -and $ChildPath -match '(?i)\\(cmd|powershell|pwsh|mshta|rundll32|regsvr32)\.exe$') {
        Add-Finding -Severity Medium -Category 'Execution' -Title 'WMI provider host spawned a shell (remote WMI execution?)' -Detail "($Source)" -Evidence $ev -Mitre 'T1047' -Time $Time -Source $Source
    }
    if ($ParentPath -match '(?i)\\services\.exe$' -and $ChildPath -match '(?i)\\(cmd|powershell|pwsh|mshta|rundll32|regsvr32)\.exe$') {
        Add-Finding -Severity High -Category 'Execution' -Title 'Service Control Manager launched a shell (service-based execution, e.g. PsExec/Impacket)' -Detail "($Source)" -Evidence $ev -Mitre 'T1569.002' -Time $Time -Source $Source
    }
    if ($ParentPath -match $script:WDScriptHostRx -and $ChildPath -match '(?i)\\(powershell|pwsh|cmd|rundll32|regsvr32|msiexec|curl|bitsadmin|certutil)\.exe$') {
        Add-Finding -Severity High -Category 'Execution' -Title 'Script host (wscript/cscript/mshta) spawned a shell or LOLBin' -Detail "Typical of malicious JS/VBS/HTA droppers ($Source)." -Evidence $ev -Mitre 'T1059.005,T1059.007,T1218.005' -Time $Time -Source $Source
    }
    if ($ParentPath -match '(?i)\\explorer\.exe$' -and $ChildPath -match '(?i)\\(mshta|powershell|pwsh)\.exe$' -and $CommandLine -match '(?i)https?://|-e[a-z]*\s+[a-z0-9+/]{40,}') {
        Add-Finding -Severity High -Category 'Execution' -Title 'Explorer launched interpreter with remote/encoded payload (Run-dialog / ClickFix?)' -Detail "($Source)" -Evidence $ev -Mitre 'T1204.004' -Time $Time -Source $Source
    }
}

# ----------------------------------------------------------------------------- masquerading
# Legitimate location (relative to C:\Windows) of commonly impersonated system binaries.
$script:WDSystemBinaries = @{
    'svchost.exe' = 'system32|syswow64'; 'lsass.exe' = 'system32'; 'csrss.exe' = 'system32'; 'smss.exe' = 'system32'
    'wininit.exe' = 'system32'; 'winlogon.exe' = 'system32'; 'services.exe' = 'system32'; 'explorer.exe' = '.'
    'taskhostw.exe' = 'system32'; 'spoolsv.exe' = 'system32'; 'dllhost.exe' = 'system32|syswow64'; 'conhost.exe' = 'system32'
    'rundll32.exe' = 'system32|syswow64'; 'runtimebroker.exe' = 'system32'; 'sihost.exe' = 'system32'; 'dwm.exe' = 'system32'
    'ctfmon.exe' = 'system32|syswow64'; 'wmiprvse.exe' = 'system32\\wbem|syswow64\\wbem'; 'lsaiso.exe' = 'system32'
    'fontdrvhost.exe' = 'system32'; 'searchindexer.exe' = 'system32'; 'audiodg.exe' = 'system32'; 'userinit.exe' = 'system32|syswow64'
    'cmd.exe' = 'system32|syswow64'; 'powershell.exe' = 'system32\\windowspowershell\\v1\.0|syswow64\\windowspowershell\\v1\.0'
    'regsvr32.exe' = 'system32|syswow64'; 'mshta.exe' = 'system32|syswow64'; 'wscript.exe' = 'system32|syswow64'
    'cscript.exe' = 'system32|syswow64'; 'taskmgr.exe' = 'system32|syswow64'; 'smartscreen.exe' = 'system32'; 'wermgr.exe' = 'system32|syswow64'
}
$script:WDLookalikeNames = @(
    'scvhost.exe','svch0st.exe','svchosts.exe','svhost.exe','svchost32.exe','svchst.exe','svcshost.exe','lsasss.exe','lsas.exe',
    'lsass32.exe','lssas.exe','isass.exe','lsasvc.exe','csrsss.exe','csrs.exe','crss.exe','cssrs.exe','expl0rer.exe','explore.exe',
    'explorar.exe','iexplorer.exe','explorer32.exe','winlog0n.exe','winlogin.exe','wininit32.exe','taskhosts.exe','spoolsvc.exe',
    'servics.exe','services32.exe','smss32.exe','rundl32.exe','rundll.exe','runddl32.exe','dllhst.exe','dllhost32.exe',
    'conhost32.exe','ctfmom.exe','dwn.exe','winiogon.exe','svchosl.exe','taskmgr32.exe','mssecsvc.exe','wuaucltt.exe'
)

function Test-WDMasquerade {
    param([string]$Path)
    if (-not $Path) { return $null }
    # Normalise the path forms used by BAM, UserAssist and Amcache before comparing.
    $Path = [Environment]::ExpandEnvironmentVariables($Path) -replace '^\\\\\?\\', '' -replace '^(?i)\\Device\\HarddiskVolume\d+', 'C:' -replace '^(?i)%SystemRoot%', 'C:\Windows'
    $leaf = (Split-Path $Path -Leaf).ToLowerInvariant()
    if ($script:WDLookalikeNames -contains $leaf) { return "Filename '$leaf' imitates a Windows system binary" }
    if ($script:WDSystemBinaries.ContainsKey($leaf)) {
        $exp = $script:WDSystemBinaries[$leaf]
        # 32-bit copies live in SysWOW64 (x64) or SysArm32 / SyChpe32 (Windows on ARM).
        $exp = $exp -replace 'syswow64', '(syswow64|sysarm32|sychpe32)'
        if ($exp -eq '.') { $rx = '(?i)^[a-z]:\\windows\\[^\\]+$' } else { $rx = '(?i)^[a-z]:\\windows\\(' + $exp + ')\\[^\\]+$' }
        if ($Path -notmatch $rx -and $Path -notmatch '(?i)\\WinSxS\\') { return "System binary name '$leaf' running from non-standard location" }
    }
    return $null
}

# ----------------------------------------------------------------------------- tool intelligence
# Offensive / dual-use tools and RMM software are loaded from rules\detection-data.json.

function Get-WDToolMatch {
    param([string]$Name)
    if (-not $Name) { return $null }
    $leaf = ($Name -split '[\\/]')[-1].ToLowerInvariant()
    $leaf = $leaf -replace '-[0-9a-f]{8}\.pf$', ''
    $base = $leaf -replace '\.(exe|dll|sys|ps1|bat|cmd|msi|py|jar|com|scr)$', ''
    if ($script:WDKnownTools.ContainsKey($base)) {
        $t = $script:WDKnownTools[$base]
        return [pscustomobject]@{ Kind = 'Tool'; Severity = $t[0]; Label = $t[1]; Mitre = $t[2]; Name = $base }
    }
    foreach ($k in $script:WDRmmTools.Keys) {
        if ($base -eq $k -or $base.StartsWith($k + '_') -or ($k.Length -ge 6 -and $base.StartsWith($k))) {
            return [pscustomobject]@{ Kind = 'RMM'; Severity = 'Medium'; Label = "Remote access tool: $($script:WDRmmTools[$k])"; Mitre = 'T1219'; Name = $base }
        }
    }
    return $null
}

# Known vulnerable / abused kernel drivers (BYOVD, see loldrivers.io) are loaded from rules\detection-data.json.

function Test-WDVulnerableDriver {
    param([string]$Path)
    if (-not $Path) { return $false }
    return ($script:WDVulnerableDrivers -contains (Split-Path $Path -Leaf).ToLowerInvariant())
}

# Processes that should almost never talk to the internet.
$script:WDNoNetworkRx = '(?i)\\(rundll32|regsvr32|mshta|wscript|cscript|msbuild|installutil|regasm|regsvcs|notepad|calc|mspaint|write|certutil|cmstp|odbcconf|forfiles|hh|control|cmd|wmic|esentutl|expand|extrac32|findstr|xwizard)\.exe$'
$script:WDScriptNetRx = '(?i)\\(powershell|pwsh|powershell_ise)\.exe$'
$script:WDSuspiciousPorts = @(4444, 4445, 1337, 31337, 6666, 6667, 6697, 9001, 9030, 9050, 9150, 5552, 1604, 2323, 3333, 7443, 8443, 50050)

$script:WDSecurityVendorRx = '(?i)(microsoft\.com|windowsupdate|defender|msftncsi|symantec|norton|mcafee|kaspersky|eset|sophos|trendmicro|bitdefender|avast|avg\.com|malwarebytes|crowdstrike|sentinelone|carbonblack|cylance|virustotal|f-secure|paloaltonetworks|cortex|webroot)'

# ----------------------------------------------------------------------------- MITRE ATT&CK names
$script:WDMitreNames = @{
    'T1003' = 'OS Credential Dumping'; 'T1003.001' = 'LSASS Memory'; 'T1003.002' = 'Security Account Manager'; 'T1003.003' = 'NTDS'
    'T1003.004' = 'LSA Secrets'; 'T1014' = 'Rootkit'; 'T1016' = 'System Network Configuration Discovery'; 'T1021' = 'Remote Services'
    'T1021.001' = 'Remote Desktop Protocol'; 'T1021.002' = 'SMB/Windows Admin Shares'; 'T1021.003' = 'Distributed Component Object Model'
    'T1021.006' = 'Windows Remote Management'; 'T1027' = 'Obfuscated Files or Information'; 'T1027.010' = 'Command Obfuscation'
    'T1036' = 'Masquerading'; 'T1036.005' = 'Match Legitimate Name or Location'; 'T1036.007' = 'Double File Extension'
    'T1046' = 'Network Service Discovery'; 'T1047' = 'Windows Management Instrumentation'; 'T1048' = 'Exfiltration Over Alternative Protocol'
    'T1053.005' = 'Scheduled Task'; 'T1055' = 'Process Injection'; 'T1055.012' = 'Process Hollowing'; 'T1059' = 'Command and Scripting Interpreter'
    'T1059.001' = 'PowerShell'; 'T1059.003' = 'Windows Command Shell'; 'T1059.005' = 'Visual Basic'; 'T1059.007' = 'JavaScript'
    'T1068' = 'Exploitation for Privilege Escalation'; 'T1070' = 'Indicator Removal'; 'T1070.001' = 'Clear Windows Event Logs'
    'T1070.004' = 'File Deletion'; 'T1070.006' = 'Timestomp'; 'T1071.001' = 'Web Protocols'; 'T1078' = 'Valid Accounts'
    'T1082' = 'System Information Discovery'; 'T1087' = 'Account Discovery'; 'T1087.002' = 'Domain Account'; 'T1090' = 'Proxy'
    'T1090.003' = 'Multi-hop Proxy'; 'T1098' = 'Account Manipulation'; 'T1102' = 'Web Service'; 'T1105' = 'Ingress Tool Transfer'
    'T1110' = 'Brute Force'; 'T1110.003' = 'Password Spraying'; 'T1112' = 'Modify Registry'; 'T1127.001' = 'MSBuild'; 'T1133' = 'External Remote Services'
    'T1136.001' = 'Local Account'; 'T1137.002' = 'Office Test'; 'T1140' = 'Deobfuscate/Decode Files or Information'; 'T1197' = 'BITS Jobs'
    'T1204.002' = 'Malicious File'; 'T1204.004' = 'Malicious Copy and Paste'; 'T1218' = 'System Binary Proxy Execution'; 'T1218.005' = 'Mshta'
    'T1218.009' = 'Regsvcs/Regasm'; 'T1218.010' = 'Regsvr32'; 'T1218.011' = 'Rundll32'; 'T1219' = 'Remote Access Tools'
    'T1482' = 'Domain Trust Discovery'; 'T1485' = 'Data Destruction'; 'T1486' = 'Data Encrypted for Impact'; 'T1490' = 'Inhibit System Recovery'
    'T1505.003' = 'Web Shell'; 'T1543.003' = 'Windows Service'; 'T1546.002' = 'Screensaver'; 'T1546.003' = 'WMI Event Subscription'
    'T1546.007' = 'Netsh Helper DLL'; 'T1546.008' = 'Accessibility Features'; 'T1546.009' = 'AppCert DLLs'; 'T1546.010' = 'AppInit DLLs'
    'T1546.012' = 'Image File Execution Options Injection'; 'T1546.013' = 'PowerShell Profile'; 'T1546.015' = 'Component Object Model Hijacking'
    'T1547.001' = 'Registry Run Keys / Startup Folder'; 'T1547.002' = 'Authentication Package'; 'T1547.003' = 'Time Providers'
    'T1547.004' = 'Winlogon Helper DLL'; 'T1547.005' = 'Security Support Provider'; 'T1547.010' = 'Port Monitors'; 'T1547.014' = 'Active Setup'
    'T1548.002' = 'Bypass User Account Control'; 'T1550.002' = 'Pass the Hash'; 'T1552.001' = 'Credentials In Files'
    'T1553.005' = 'Mark-of-the-Web Bypass'; 'T1555' = 'Credentials from Password Stores'; 'T1555.003' = 'Credentials from Web Browsers'
    'T1556.002' = 'Password Filter DLL'; 'T1558' = 'Steal or Forge Kerberos Tickets'; 'T1558.003' = 'Kerberoasting'
    'T1560.001' = 'Archive via Utility'; 'T1562.001' = 'Disable or Modify Tools'; 'T1562.002' = 'Disable Windows Event Logging'
    'T1562.004' = 'Disable or Modify System Firewall'; 'T1562.010' = 'Downgrade Attack'; 'T1564.001' = 'Hidden Files and Directories'
    'T1564.002' = 'Hidden Users'; 'T1564.003' = 'Hidden Window'; 'T1565.001' = 'Stored Data Manipulation'; 'T1566.001' = 'Spearphishing Attachment'
    'T1567' = 'Exfiltration Over Web Service'; 'T1567.002' = 'Exfiltration to Cloud Storage'; 'T1569.002' = 'Service Execution'
    'T1572' = 'Protocol Tunneling'; 'T1574.001' = 'DLL'; 'T1574.002' = 'DLL Side-Loading'; 'T1574.007' = 'Path Interception by PATH Environment Variable'
    'T1574.009' = 'Path Interception by Unquoted Path'; 'T1587.001' = 'Malware'; 'T1588.002' = 'Tool'; 'T1620' = 'Reflective Code Loading'
    'T1649' = 'Steal or Forge Authentication Certificates'; 'T1543' = 'Create or Modify System Process'; 'T1053' = 'Scheduled Task/Job'
    'T1036.003' = 'Rename Legitimate Utilities'; 'T1036.004' = 'Masquerade Task or Service'; 'T1052.001' = 'Exfiltration over USB'
    'T1176' = 'Software Extensions'; 'T1205' = 'Traffic Signaling'; 'T1210' = 'Exploitation of Remote Services'; 'T1531' = 'Account Access Removal'
    'T1553' = 'Subvert Trust Controls'; 'T1557' = 'Adversary-in-the-Middle'; 'T1564' = 'Hide Artifacts'; 'T1571' = 'Non-Standard Port'
    'T1057' = 'Process Discovery'; 'T1018' = 'Remote System Discovery'; 'T1071' = 'Application Layer Protocol'; 'T1542' = 'Pre-OS Boot'
}

function Get-WDMitreName { param([string]$Id) if ($script:WDMitreNames.ContainsKey($Id)) { return $script:WDMitreNames[$Id] } return '' }
