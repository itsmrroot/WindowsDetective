<#
    Windows Detective - self test (Powered by Bashar Salmo)
    Validates the engine without touching the host: rules compile, benign command lines
    stay quiet, helpers behave, every MITRE id used has a name, and a demo report renders.
        .\tests\Invoke-WDSelfTest.ps1 [-ReportDir <folder>]
#>
param([string]$ReportDir = '')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
foreach ($lib in @('WD.Core.ps1', 'WD.Rules.ps1', 'WD.Execution.ps1', 'WD.Report.ps1')) { . (Join-Path $root "lib/$lib") }

$script:pass = 0; $script:fail = 0
function Assert-WD { param([bool]$Condition, [string]$Name) if ($Condition) { $script:pass++ } else { $script:fail++; Write-Host "FAIL: $Name" -ForegroundColor Red } }

New-WDContext -Options @{ Days = 30; CaseId = 'SELFTEST'; Analyst = 'selftest'; MaxEvents = 100; MaxHashBytes = 1MB; ToolRoot = $root }

# ---- detection data loads and every rule compiles
$dataPath = Join-Path $root 'rules/detection-data.json'
$ruleTotal = @(([IO.File]::ReadAllText($dataPath) | ConvertFrom-Json).commandRules).Count
$loaded = Import-WDDetectionData -Path $dataPath
Assert-WD ($loaded -gt 0 -and $script:WDCommandRules.Count -eq $ruleTotal) "all $ruleTotal rules compile"
Assert-WD ($script:WDKnownTools.Count -gt 50 -and $script:WDRmmTools.Count -gt 30 -and $script:WDVulnerableDrivers.Count -gt 50) 'tool / RMM / driver intel loaded'
Assert-WD (Test-WDVulnerableDriver 'C:\Windows\System32\drivers\RTCore64.sys') 'vulnerable driver match'

# ---- benign command lines must not raise Medium+ rule hits
$benign = @(
    '"C:\Program Files\Google\Chrome\Application\chrome.exe" --type=renderer'
    'C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule'
    'powershell.exe -NoProfile -File C:\Scripts\inventory.ps1'
    '"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n "C:\Users\bob\Documents\report.docx"'
    'C:\Windows\System32\msiexec.exe /V'
    '"C:\Program Files\Git\cmd\git.exe" pull'
    'net use Z: \\fileserver\share'
    'certutil -hashfile setup.exe SHA256'
    'schtasks /query /fo LIST'
    'powershell.exe -ExecutionPolicy RemoteSigned -File C:\a.ps1'
    '"C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NonInteractive -WindowStyle Normal'
    'Get-ChildItem -Path C:\Users -Recurse | Where-Object Name -like *.log'
)
foreach ($b in $benign) {
    $hits = @(Test-WDCommandLine $b | Where-Object { $_.Severity -ne 'Low' })
    Assert-WD ($hits.Count -eq 0) "benign stays quiet: $b -> $(($hits | ForEach-Object Id) -join ',')"
}
Assert-WD ((Test-WDCommandLine 'something WDCase_HOST_1 esentutl').Count -eq 0) 'self-exclusion marker'

# ---- helpers
Assert-WD ((Get-WDExecutablePath '"C:\Program Files\App\app.exe" -x') -eq 'C:\Program Files\App\app.exe') 'quoted exe path'
Assert-WD ((Get-WDExecutablePath 'C:\Tools\a b\run.exe /s') -eq 'C:\Tools\a b\run.exe') 'unquoted exe path with space'
Assert-WD (Test-WDPublicIp '8.8.8.8') 'public IPv4'
foreach ($ip in @('10.1.2.3', '192.168.1.1', '172.20.0.1', '127.0.0.1', '169.254.1.1', '::1', 'fe80::1', '-')) { Assert-WD (-not (Test-WDPublicIp $ip)) "private $ip" }
Assert-WD ((ConvertFrom-WDRot13 'Uryyb') -eq 'Hello') 'ROT13'
Assert-WD ((Get-WDPathRisk 'C:\Users\Public\x.exe') -eq 'High') 'path risk high'
Assert-WD ((Get-WDPathRisk 'C:\Users\bob\AppData\Local\Programs\x\x.exe') -eq 'User') 'path risk user'
Assert-WD ((Get-WDPathRisk 'C:\Program Files\x\x.exe') -eq 'None') 'path risk none'
Assert-WD ($null -ne (Test-WDMasquerade 'C:\Users\Public\svchost.exe')) 'masquerade wrong location'
Assert-WD ($null -eq (Test-WDMasquerade 'C:\Windows\System32\svchost.exe')) 'genuine svchost'
Assert-WD ((Get-WDToolMatch 'C:\x\AnyDesk.exe').Kind -eq 'RMM') 'RMM tool match'
Assert-WD ((Get-WDToolMatch 'RCLONE.EXE-1A2B3C4D.pf').Name -eq 'rclone') 'prefetch name tool match'
Assert-WD ((ConvertTo-WDTimeString '2026-01-02 03:04:05') -eq '2026-01-02 03:04:05') 'UTC strings not shifted'
Assert-WD (Test-WDSelfPath 'amsi:_C:\Users\X\Desktop\WindowsDetective-main\lib\WD.Rules.ps1') 'AV detection of own files recognised'
Assert-WD (-not (Test-WDSelfPath 'file:_C:\Users\X\Downloads\invoice.exe')) 'real detection not treated as self'
foreach ($ok in @('C:\Windows\SysArm32\cmd.exe', 'C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe', '\Device\HarddiskVolume3\Windows\System32\wscript.exe', '%SystemRoot%\System32\cmd.exe')) {
    Assert-WD ($null -eq (Test-WDMasquerade $ok)) "legitimate system path not masquerading: $ok"
}
$b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output "hello from selftest"'))
Assert-WD ((ConvertFrom-WDEncodedCommand "powershell.exe -NoProfile -EncodedCommand $b64") -eq 'Write-Output "hello from selftest"') 'encoded command is decoded'
$before = $script:WD.Findings.Count
[void](Invoke-WDCommandCheck -Text "powershell.exe -enc $b64" -Source 'selftest')
$enc = $script:WD.Findings | Where-Object { $_.Source -eq 'selftest' -and $_.Detail -match 'DECODED COMMAND: Write-Output' }
Assert-WD ($null -ne $enc) 'decoded command shown in finding detail'
Assert-WD ($enc.Severity -eq 'Medium') 'harmless encoded command is Medium, not High'
Assert-WD (Test-WDSelfPath 'C:\Users\X\Downloads\WindowsDetective-main (1)\lib\WD.Core.ps1') 'other extracted copy of the tool recognised'
$script:WD.Findings.Clear(); $script:WD.FindingIndex.Clear(); $script:WD.Timeline.Clear()
Assert-WD ((Get-WDFileInfo 'C:\Program Files\x\Update.exe"" \c').Exists -eq $false) 'malformed path handled without error'

# ---- tool code must not embed attack keywords that make antivirus (AMSI) block it
$bait = '(?i)(mimi' + 'katz|sekur' + 'lsa|cobalt' + 'strike|cobalt strike|download' + 'string|amsi' + 'utils|amsiinit' + 'failed|virtual' + 'alloc|invoke-' + 'shellcode)'
foreach ($f in @(Get-ChildItem (Join-Path $root 'lib') -Filter *.ps1) + @(Get-Item (Join-Path $root 'WindowsDetective.ps1'))) {
    Assert-WD ((Get-Content $f.FullName -Raw) -notmatch $bait) "no AMSI bait strings in $($f.Name)"
}

# ---- every MITRE id used in the code has a name
$ids = @{}
foreach ($f in @(Get-ChildItem (Join-Path $root 'lib') -Filter *.ps1) + @(Get-Item $dataPath)) {
    foreach ($m in [regex]::Matches((Get-Content $f.FullName -Raw), "['""](T\d{4}(\.\d{3})?(,T\d{4}(\.\d{3})?)*)['""]")) {
        foreach ($t in $m.Groups[1].Value -split ',') { $ids[$t] = $f.Name }
    }
}
foreach ($t in $ids.Keys) { Assert-WD ((Get-WDMitreName $t) -ne '') "MITRE name for $t ($($ids[$t]))" }

# ---- demo report
if (-not $ReportDir) { $ReportDir = Join-Path ([IO.Path]::GetTempPath()) 'WDCase_SELFTEST' }
New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
$script:WD.CaseDir = (Resolve-Path $ReportDir).ProviderPath
$script:WD.RawDir = Join-Path $script:WD.CaseDir 'raw'; New-Item -ItemType Directory -Path $script:WD.RawDir -Force | Out-Null
$script:WD.SystemInfo['Hostname'] = 'DEMO-LAPTOP'
Add-Finding -Severity High -Category 'Persistence' -Title 'Run key launches unsigned binary in user-writable location' -Evidence 'HKCU\...\Run -> updater = C:\Users\demo\AppData\Roaming\upd.exe' -Mitre 'T1547.001' -Time (Get-Date).AddHours(-5)
Add-Finding -Severity Medium -Category 'Network' -Title 'PowerShell holding an internet connection' -Evidence 'powershell.exe -> 203.0.113.10:443' -Mitre 'T1059.001,T1071.001'
Add-Finding -Severity Info -Category 'Visibility' -Title 'Process creation auditing not enabled' -Evidence 'auditpol'
Add-WDTimeline -Time (Get-Date).AddHours(-6) -Source 'Prefetch' -Description 'Program first run: UPD.EXE'
Save-WDArtifact -Name 'Demo' -Section 'System' -Data @([pscustomobject]@{ A = 1; B = '<script>x</script>' }) -Description 'demo'
$script:WD.CollectorStats.Add([pscustomobject]@{ Collector = 'demo'; Status = 'OK'; Seconds = 0; NewFindings = 3; Error = '' })
$report = Export-WDReport
$html = Get-Content $report -Raw
Assert-WD ($html -match 'Powered by <strong>Bashar Salmo</strong>') 'report branding'
Assert-WD ($html -notmatch '<script>x</script>') 'report escapes artifact HTML'
Assert-WD ($html -match 'SUSPICIOUS') 'report verdict'
$json = [regex]::Match($html, '<script id="wd-findings" type="application/json">(.*?)</script>').Groups[1].Value
Assert-WD (@($json | ConvertFrom-Json).Count -eq 3) 'embedded findings JSON parses'

Write-Host ''
Write-Host "Self-test: $script:pass passed, $script:fail failed. Demo report: $report" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
Write-Host 'Windows Detective - Powered by Bashar Salmo' -ForegroundColor Yellow
exit [int]($script:fail -gt 0)
