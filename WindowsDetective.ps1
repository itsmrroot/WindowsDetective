<#
.SYNOPSIS
    Windows Detective - live-response forensic triage & compromise assessment for Windows.
    Powered by Bashar Salmo

.DESCRIPTION
    Collects and analyses the artifacts an incident responder needs to decide whether a
    Windows host has been compromised: processes, network, persistence (30+ autostart
    locations), evidence of execution (Prefetch, BAM, ShimCache, Amcache, UserAssist,
    RunMRU), event logs (Security, System, PowerShell, RDP, Defender, Sysmon, ...),
    file system, USB, browser extensions, security posture, IOC and YARA matching.

    Produces a case folder with an interactive HTML report, findings (JSON/CSV), a unified
    timeline, raw CSV artifacts, exported EVTX logs, a SHA-256 manifest and a ZIP archive.

    The tool only reads from the host. Run it from external/USB media where possible and
    write the output to external media to minimise footprint on the evidence disk.

.PARAMETER OutputPath   Folder where each scan session is saved (default: the Reports folder inside the tool directory).
.PARAMETER Days         Investigation window in days (default 30).
.PARAMETER CaseId       Case / ticket reference printed in the report.
.PARAMETER Analyst      Name of the analyst (default: current user).
.PARAMETER Quick        Faster run: fewer events, no process owners, reduced file sweep.
.PARAMETER Deep         Thorough run: loaded DLL scan, System32 changes, deeper file sweep, 4x events.
.PARAMETER CollectRawArtifacts  Also copy registry hives, SRUM, WMI repository, browser history,
                        jump lists, Prefetch, Tasks, Defender MPLog and flagged files.
.PARAMETER MemoryDump   Capture physical memory first (needs tools\winpmem*.exe).
.PARAMETER LoadUserHives Mount NTUSER.DAT of users who are not logged on to analyse their registry.
.PARAMETER NoEvtx       Do not export .evtx files.
.PARAMETER NoZip        Do not create a ZIP archive of the case folder.
.PARAMETER MaxEvents    Base number of events read per query (default 5000).
.PARAMETER IocPath      Folder with IOC lists (hashes / IPs / domains, one per line).
.PARAMETER OpenReport   Open the HTML report when finished.

.EXAMPLE
    .\WindowsDetective.ps1 -CaseId IR-2026-042 -Analyst "Jane Doe" -OpenReport
.EXAMPLE
    .\WindowsDetective.ps1 -Deep -CollectRawArtifacts -MemoryDump -Days 90 -OutputPath E:\Evidence
#>
[CmdletBinding()]
param(
    [string]$OutputPath = '',
    [ValidateRange(1, 3650)][int]$Days = 30,
    [string]$CaseId = '',
    [string]$Analyst = "$env:USERDOMAIN\$env:USERNAME",
    [switch]$Quick,
    [switch]$Deep,
    [switch]$CollectRawArtifacts,
    [switch]$MemoryDump,
    [switch]$LoadUserHives,
    [switch]$NoEvtx,
    [switch]$NoZip,
    [ValidateRange(100, 1000000)][int]$MaxEvents = 5000,
    [string]$IocPath = '',
    [switch]$OpenReport
)

#Requires -Version 5.1
Set-StrictMode -Off
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$toolRoot = $PSScriptRoot
$loadErrors = @()
foreach ($lib in @('WD.Core.ps1', 'WD.Rules.ps1', 'WD.System.ps1', 'WD.Processes.ps1', 'WD.Network.ps1', 'WD.Persistence.ps1',
        'WD.Execution.ps1', 'WD.EventLogs.ps1', 'WD.FileSystem.ps1', 'WD.Security.ps1', 'WD.Evidence.ps1', 'WD.Report.ps1')) {
    try { . (Join-Path $toolRoot "lib\$lib") } catch { $loadErrors += "$lib : $($_.Exception.Message)" }
}
# A module blocked by antivirus (AMSI) or damaged in transit must stop the run - partial results would be misleading.
$requiredFunctions = @('New-WDContext', 'Import-WDDetectionData', 'Invoke-WDCommandCheck', 'Get-WDToolMatch', 'Test-WDVulnerableDriver', 'Get-WDMitreName',
    'Invoke-WDSystemCollector', 'Invoke-WDProcessCollector', 'Invoke-WDNetworkCollector', 'Invoke-WDPersistenceCollector', 'Invoke-WDExecutionCollector',
    'Invoke-WDEventLogCollector', 'Invoke-WDFileSystemCollector', 'Invoke-WDSecurityCollector', 'Invoke-WDIocCollector', 'Export-WDReport')
$missing = @($requiredFunctions | Where-Object { -not (Get-Command $_ -CommandType Function -ErrorAction SilentlyContinue) })
$ruleCount = 0
if ($missing.Count -eq 0) {
    try { $ruleCount = Import-WDDetectionData } catch { $loadErrors += "rules\detection-data.json : $($_.Exception.Message)" }
}
if ($missing.Count -gt 0 -or $ruleCount -eq 0) {
    Write-Host ''
    Write-Host 'Windows Detective could not load all of its modules - aborting so no misleading report is produced.' -ForegroundColor Red
    foreach ($e in $loadErrors) { Write-Host "  - $e" -ForegroundColor Red }
    if ($missing.Count) { Write-Host "  Missing functions: $($missing -join ', ')" -ForegroundColor Red }
    Write-Host '  If the message says "blocked by your antivirus software", antivirus quarantined part of the tool.' -ForegroundColor Yellow
    Write-Host '  Re-download it, check that all files in lib\ and rules\ are present, and if needed add a temporary' -ForegroundColor Yellow
    Write-Host '  Defender exclusion for the tool folder (standard practice for IR tooling).' -ForegroundColor Yellow
    exit 3
}

function Show-WDBanner {
    $banner = @'

  __        ___           _                     ____       _            _   _
  \ \      / (_)_ __   __| | _____      _____  |  _ \  ___| |_ ___  ___| |_(_)_   _____
   \ \ /\ / /| | '_ \ / _` |/ _ \ \ /\ / / __| | | | |/ _ \ __/ _ \/ __| __| \ \ / / _ \
    \ V  V / | | | | | (_| | (_) \ V  V /\__ \ | |_| |  __/ ||  __/ (__| |_| |\ V /  __/
     \_/\_/  |_|_| |_|\__,_|\___/ \_/\_/ |___/ |____/ \___|\__\___|\___|\__|_| \_/ \___|

'@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host ("        Forensic Triage & Compromise Assessment  v{0}" -f $script:WDVersion) -ForegroundColor Gray
    Write-Host '        Powered by Bashar Salmo' -ForegroundColor Yellow
    Write-Host ''
}

Show-WDBanner

if ([Environment]::OSVersion.Platform -ne 'Win32NT') {
    Write-Host 'Windows Detective must be run on Windows.' -ForegroundColor Red
    exit 1
}
if ($Quick -and $Deep) { Write-Host '-Quick and -Deep are mutually exclusive; using -Deep.' -ForegroundColor Yellow; $Quick = $false }

# Every scan session is saved under the tool's own Reports folder unless another location is given.
if (-not $OutputPath) { $OutputPath = Join-Path $toolRoot 'Reports' }
if (-not $IocPath) { $IocPath = Join-Path $toolRoot 'iocs' }
if (-not $CaseId) { $CaseId = 'WD-' + (Get-Date -Format 'yyyyMMdd-HHmmss') }
$effectiveMax = $MaxEvents
if ($Quick) { $effectiveMax = [Math]::Max(500, [int]($MaxEvents / 4)) }
if ($Deep) { $effectiveMax = $MaxEvents * 4 }

New-WDContext -Options @{
    Days = $Days; CaseId = $CaseId; Analyst = $Analyst; Quick = [bool]$Quick; Deep = [bool]$Deep
    CollectRaw = [bool]$CollectRawArtifacts; MemoryDump = [bool]$MemoryDump; LoadUserHives = [bool]$LoadUserHives
    MaxEvents = $effectiveMax; IocPath = $IocPath; ToolRoot = $toolRoot
    MaxHashBytes = $(if ($Quick) { 25MB } else { 150MB })
}

# Case folder layout
$script:WD.CaseName = 'WDCase_{0}_{1}' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss')
$script:WD.CaseDir = Join-Path $OutputPath $script:WD.CaseName
$script:WD.RawDir = Join-Path $script:WD.CaseDir 'raw'
$script:WD.EvtxDir = Join-Path $script:WD.CaseDir 'evtx'
$script:WD.FilesDir = Join-Path $script:WD.CaseDir 'files'
foreach ($d in @($script:WD.CaseDir, $script:WD.RawDir, $script:WD.EvtxDir, $script:WD.FilesDir)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
$script:WD.CaseDir = (Resolve-Path -LiteralPath $script:WD.CaseDir).ProviderPath
$script:WD.LogFile = Join-Path $script:WD.CaseDir 'collection.log'

Write-WDLog "$script:WDToolName v$script:WDVersion - $script:WDBrand" INFO
Write-WDLog "Case $CaseId | analyst $Analyst | host $env:COMPUTERNAME | window $Days days | output $($script:WD.CaseDir)" INFO
if (-not $script:WD.IsAdmin) {
    Write-WDLog 'NOT running as Administrator - Security log, Amcache, hidden tasks and other users will be missed. Re-run elevated for a complete investigation.' WARN
}
if ($script:WD.CaseDir.Substring(0, 2) -eq $env:SystemDrive) {
    Write-WDLog 'Output is on the system drive. For evidential work prefer external media (-OutputPath E:\Reports) to avoid overwriting deleted data.' WARN
}

$exitCode = 0
try {
    # Order of volatility: memory -> processes -> network -> the rest
    if ($MemoryDump) { Invoke-WDCollector 'Memory capture' { Invoke-WDMemoryCapture } }
    Invoke-WDCollector 'System profile'          { Invoke-WDSystemCollector }
    Invoke-WDCollector 'Processes'               { Invoke-WDProcessCollector }
    Invoke-WDCollector 'Network'                 { Invoke-WDNetworkCollector }
    Invoke-WDCollector 'Accounts'                { Invoke-WDAccountCollector }
    Invoke-WDCollector 'Persistence'             { Invoke-WDPersistenceCollector }
    Invoke-WDCollector 'Evidence of execution'   { Invoke-WDExecutionCollector }
    Invoke-WDCollector 'Event logs'              { Invoke-WDEventLogCollector }
    Invoke-WDCollector 'File system & devices'   { Invoke-WDFileSystemCollector }
    Invoke-WDCollector 'Security posture'        { Invoke-WDSecurityCollector }
    Invoke-WDCollector 'YARA scan'               { Invoke-WDYaraScan }
    Invoke-WDCollector 'IOC matching'            { Invoke-WDIocCollector }
    if (-not $NoEvtx) { Invoke-WDCollector 'EVTX export' { Invoke-WDEvtxExport } }
    if ($CollectRawArtifacts) { Invoke-WDCollector 'Raw artifact collection' { Invoke-WDRawArtifacts } }
}
catch {
    Write-WDLog "Fatal error: $($_.Exception.Message)" ERROR
    $exitCode = 2
}
finally {
    Dismount-WDUserHives
}

Write-WDLog 'Building report' STEP
$report = Export-WDReport
Write-WDManifest

$zip = ''
if (-not $NoZip) {
    try {
        $zip = "$($script:WD.CaseDir).zip"
        $items = @(Get-ChildItem -LiteralPath $script:WD.CaseDir -Force | Where-Object { $_.Name -ne 'memory' })
        Compress-Archive -LiteralPath $items.FullName -DestinationPath $zip -Force
        $zh = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
        Set-Content -LiteralPath "$zip.sha256" -Value "$zh  $(Split-Path $zip -Leaf)" -Encoding ASCII
        Write-WDLog "Case archive: $zip (SHA-256 $zh)" OK
        if ($script:WD.MemoryImage) { Write-WDLog 'Memory image is kept outside the ZIP (memory\physmem.raw) because of its size.' INFO }
    } catch { Write-WDLog "ZIP creation failed: $($_.Exception.Message)" WARN; $zip = '' }
}

# Console summary
$counts = Get-WDSeverityCounts
$verdict = Get-WDVerdict

# One line per scan session in Reports\scan_history.csv, so earlier sessions are easy to find and compare.
try {
    $history = Join-Path (Split-Path -Parent $script:WD.CaseDir) 'scan_history.csv'
    [pscustomobject][ordered]@{
        ScanStartUtc = (ConvertTo-WDTimeString $script:WD.StartTime); Host = $env:COMPUTERNAME; CaseId = $CaseId; Analyst = $Analyst
        Verdict = $verdict.Level; RiskScore = $verdict.Score; Critical = $counts.Critical; High = $counts.High; Medium = $counts.Medium
        Low = $counts.Low; Info = $counts.Info; ToolVersion = $script:WDVersion; Report = $report; Archive = $zip
    } | Export-Csv -LiteralPath $history -NoTypeInformation -Encoding UTF8 -Append
} catch { Write-WDLog "Could not update scan history: $($_.Exception.Message)" WARN }
$color = switch ($verdict.Css) { 'crit' { 'Red' } 'high' { 'DarkYellow' } 'med' { 'Yellow' } default { 'Green' } }
Write-Host ''
Write-Host ('=' * 78) -ForegroundColor DarkGray
Write-Host ("  VERDICT: {0}   (risk score {1}/100)" -f $verdict.Level, $verdict.Score) -ForegroundColor $color
Write-Host ("  Critical {0} | High {1} | Medium {2} | Low {3} | Info {4}" -f $counts.Critical, $counts.High, $counts.Medium, $counts.Low, $counts.Info)
Write-Host ''
foreach ($f in @($script:WD.Findings | Where-Object { $_.Severity -in @('Critical', 'High') } | Sort-Object Id | Select-Object -First 15)) {
    $c = 'DarkYellow'; if ($f.Severity -eq 'Critical') { $c = 'Red' }
    Write-Host ("  [{0}] {1,-8} {2}" -f $f.Id, $f.Severity, $f.Title) -ForegroundColor $c
}
Write-Host ''
Write-Host "  Report : $report" -ForegroundColor Cyan
Write-Host "  Case   : $($script:WD.CaseDir)" -ForegroundColor Cyan
Write-Host "  History: $(Join-Path (Split-Path -Parent $script:WD.CaseDir) 'scan_history.csv')" -ForegroundColor Cyan
if ($zip) { Write-Host "  Archive: $zip" -ForegroundColor Cyan }
Write-Host ('=' * 78) -ForegroundColor DarkGray
Write-Host '  Windows Detective - Powered by Bashar Salmo' -ForegroundColor Yellow
Write-Host ''

if ($OpenReport) { try { Start-Process $report } catch { } }
exit $exitCode
