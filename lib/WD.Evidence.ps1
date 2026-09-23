# =============================================================================
#  Windows Detective - IOC matching, YARA, memory capture & evidence preservation
#  Powered by Bashar Salmo
#  WD-SELF-MARKER
# =============================================================================

function Read-WDIocFile {
    param([string]$Path)
    $set = @{}
    if (-not (Test-Path -LiteralPath $Path)) { return $set }
    foreach ($line in (Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue)) {
        $t = ($line -split '#', 2)[0].Trim()
        if (-not $t) { continue }
        $parts = $t -split '[,;\t]', 2
        $key = $parts[0].Trim().ToLowerInvariant().TrimEnd('.')
        $desc = ''; if ($parts.Count -gt 1) { $desc = $parts[1].Trim() }
        $set[$key] = $desc
    }
    return $set
}

function Invoke-WDIocCollector {
    $dir = $script:WD.Options.IocPath
    if (-not $dir -or -not (Test-Path -LiteralPath $dir)) { Write-WDLog "IOC directory not found: $dir" WARN; return }
    $hashes = @{}; $ips = @{}; $domains = @{}
    foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter '*.txt' -File -ErrorAction SilentlyContinue)) {
        $set = Read-WDIocFile $f.FullName
        foreach ($k in $set.Keys) {
            if ($k -match '^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$') { $hashes[$k] = "$($set[$k]) [$($f.Name)]" }
            elseif ($k -match '^\d{1,3}(\.\d{1,3}){3}$' -or $k -match '^[0-9a-f:]+:[0-9a-f:]*$') { $ips[$k] = "$($set[$k]) [$($f.Name)]" }
            elseif ($k -match '^[a-z0-9\-\.\*]+\.[a-z]{2,}$') { $domains[$k] = "$($set[$k]) [$($f.Name)]" }
        }
    }
    Write-WDLog "Loaded IOCs: $($hashes.Count) hashes, $($ips.Count) IPs, $($domains.Count) domains" INFO

    # MD5/SHA1 IOCs require extra hashing of files we already looked at.
    $needMd5 = @($hashes.Keys | Where-Object { $_.Length -eq 32 }).Count -gt 0
    $needSha1 = @($hashes.Keys | Where-Object { $_.Length -eq 40 }).Count -gt 0
    if ($needMd5 -or $needSha1) {
        foreach ($info in @($script:WD.FileCache.Values)) {
            if (-not $info.Exists -or $info.Size -gt $script:WD.Options.MaxHashBytes) { continue }
            if ($needMd5) { try { Add-WDObserved -Type Hashes -Value (Get-FileHash -LiteralPath $info.Path -Algorithm MD5).Hash -Source $info.Path } catch { } }
            if ($needSha1) { try { Add-WDObserved -Type Hashes -Value (Get-FileHash -LiteralPath $info.Path -Algorithm SHA1).Hash -Source $info.Path } catch { } }
        }
    }

    $iocHits = New-Object System.Collections.Generic.List[object]
    foreach ($h in @($script:WD.Observed.Hashes.Keys)) {
        if ($hashes.ContainsKey($h)) {
            $iocHits.Add([pscustomobject]@{ Type = 'Hash'; Indicator = $h; SeenAt = $script:WD.Observed.Hashes[$h]; Intel = $hashes[$h] })
            Add-Finding -Severity Critical -Category 'IOC Match' -Title "Known-bad file hash found: $($hashes[$h])" -Evidence "$h at $($script:WD.Observed.Hashes[$h])" -Mitre ''
        }
    }
    foreach ($ip in @($script:WD.Observed.Ips.Keys)) {
        if ($ips.ContainsKey($ip)) {
            $iocHits.Add([pscustomobject]@{ Type = 'IP'; Indicator = $ip; SeenAt = $script:WD.Observed.Ips[$ip]; Intel = $ips[$ip] })
            Add-Finding -Severity Critical -Category 'IOC Match' -Title "Known-bad IP address observed: $($ips[$ip])" -Evidence "$ip ($($script:WD.Observed.Ips[$ip]))" -Mitre 'T1071'
        }
    }
    foreach ($d in @($script:WD.Observed.Domains.Keys)) {
        foreach ($ioc in $domains.Keys) {
            $hit = $false
            if ($ioc.StartsWith('*.')) { $hit = $d.EndsWith($ioc.Substring(1)) -or $d -eq $ioc.Substring(2) }
            else { $hit = ($d -eq $ioc -or $d.EndsWith(".$ioc")) }
            if ($hit) {
                $iocHits.Add([pscustomobject]@{ Type = 'Domain'; Indicator = $d; SeenAt = $script:WD.Observed.Domains[$d]; Intel = $domains[$ioc] })
                Add-Finding -Severity Critical -Category 'IOC Match' -Title "Known-bad domain observed: $($domains[$ioc])" -Evidence "$d matches $ioc ($($script:WD.Observed.Domains[$d]))" -Mitre 'T1071'
            }
        }
    }
    Save-WDArtifact -Name 'IocMatches' -Section 'Threat Intel' -Data $iocHits -Description 'Matches against the IOC lists in the iocs folder'

    # Export everything observed so it can be pivoted in a SIEM / TIP
    $obs = New-Object System.Collections.Generic.List[object]
    foreach ($t in @('Hashes', 'Ips', 'Domains')) { foreach ($k in $script:WD.Observed[$t].Keys) { $obs.Add([pscustomobject]@{ Type = $t; Value = $k; Source = $script:WD.Observed[$t][$k] }) } }
    try { $obs | Export-Csv -LiteralPath (Join-Path $script:WD.RawDir 'ObservedIndicators.csv') -NoTypeInformation -Encoding UTF8 } catch { }
    $script:WD.SystemInfo['Observed Indicators'] = "$($script:WD.Observed.Hashes.Count) hashes, $($script:WD.Observed.Ips.Count) public IPs, $($script:WD.Observed.Domains.Count) domains"
}

function Invoke-WDYaraScan {
    $root = $script:WD.Options.ToolRoot
    $yara = @(Get-ChildItem -LiteralPath (Join-Path $root 'tools') -Filter 'yara*.exe' -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch 'yarac' } | Select-Object -First 1)
    $rules = @(Get-ChildItem -LiteralPath (Join-Path $root 'rules') -Include '*.yar', '*.yara' -Recurse -File -ErrorAction SilentlyContinue)
    if ($yara.Count -eq 0 -or $rules.Count -eq 0) { Write-WDLog 'YARA scan skipped (place yara64.exe in tools\ and rules in rules\)' INFO; return }

    $targets = @{}
    foreach ($p in $script:WD.ProcessMap.Values) { if ($p.ExecutablePath) { $targets[[string]$p.ExecutablePath] = $true } }
    foreach ($a in $script:WD.Autoruns) { if ($a.ImagePath -and $a.Exists) { $targets[[string]$a.ImagePath] = $true } }
    foreach ($f in $script:WD.SuspiciousFiles.Keys) { $targets[$f] = $true }
    if ($script:WD.Artifacts.Contains('RecentFiles')) { foreach ($r in $script:WD.Artifacts['RecentFiles'].Rows) { $targets[$r.Path] = $true } }
    $list = @($targets.Keys | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) })
    $listFile = Join-Path $script:WD.RawDir 'yara_targets.txt'
    [IO.File]::WriteAllLines($listFile, [string[]]$list)
    Write-WDLog "YARA: scanning $($list.Count) files with $($rules.Count) rule file(s)" INFO

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rules) {
        $out = & $yara[0].FullName -w --scan-list $r.FullName $listFile 2>&1
        foreach ($line in $out) {
            if ($line -match '^(\S+)\s+(.+)$' -and (Test-Path -LiteralPath $Matches[2].Trim())) {
                $rule = $Matches[1]; $file = $Matches[2].Trim()
                $rows.Add([pscustomobject]@{ Rule = $rule; RuleFile = $r.Name; File = $file })
                $info = Get-WDFileInfo $file
                Add-Finding -Severity High -Category 'IOC Match' -Title "YARA rule matched: $rule" -Evidence "$file | sha256 $($info.SHA256) | rules $($r.Name)" -Mitre ''
            } elseif ($line -match '(?i)error') { Write-WDLog "YARA ($($r.Name)): $line" WARN }
        }
    }
    Save-WDArtifact -Name 'YaraMatches' -Section 'Threat Intel' -Data $rows -Description 'YARA matches on process images, autoruns and suspicious files'
}

function Invoke-WDMemoryCapture {
    $root = $script:WD.Options.ToolRoot
    $pmem = @(Get-ChildItem -LiteralPath (Join-Path $root 'tools') -Filter 'winpmem*.exe' -File -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($pmem.Count -eq 0) { Write-WDLog 'Memory capture requested but tools\winpmem*.exe not found - skipping' WARN; return }
    if (-not $script:WD.IsAdmin) { Write-WDLog 'Memory capture requires administrator rights - skipping' WARN; return }
    $drive = Get-PSDrive -Name ($script:WD.CaseDir.Substring(0, 1)) -ErrorAction SilentlyContinue
    $ram = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
    if ($drive -and $drive.Free -lt ($ram * 1.1)) { Write-WDLog "Not enough free space for a memory image ($([math]::Round($drive.Free / 1GB, 1)) GB free, $([math]::Round($ram / 1GB, 1)) GB RAM) - skipping" WARN; return }
    $out = Join-Path $script:WD.CaseDir 'memory\physmem.raw'
    New-Item -ItemType Directory -Path (Split-Path $out) -Force | Out-Null
    Write-WDLog "Capturing physical memory with $($pmem[0].Name) -> $out (this can take several minutes)" INFO
    & $pmem[0].FullName $out 2>&1 | Out-File -LiteralPath (Join-Path (Split-Path $out) 'winpmem.log') -Encoding UTF8
    if (Test-Path -LiteralPath $out) {
        $script:WD.MemoryImage = $out
        Write-WDLog "Memory image written ($([math]::Round((Get-Item -LiteralPath $out).Length / 1GB, 2)) GB)" OK
    } else { Write-WDLog 'Memory capture failed - see memory\winpmem.log' ERROR }
}

function Invoke-WDEvtxExport {
    $logs = @('Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell', 'Microsoft-Windows-Sysmon/Operational',
        'Microsoft-Windows-Windows Defender/Operational', 'Microsoft-Windows-TaskScheduler/Operational', 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational', 'Microsoft-Windows-TerminalServices-RDPClient/Operational', 'Microsoft-Windows-Bits-Client/Operational',
        'Microsoft-Windows-WinRM/Operational', 'Microsoft-Windows-WMI-Activity/Operational', 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall',
        'Microsoft-Windows-SMBServer/Security', 'Microsoft-Windows-CodeIntegrity/Operational', 'Microsoft-Windows-AppLocker/EXE and DLL', 'PowerShellCore/Operational')
    foreach ($l in $logs) {
        if (-not (Test-WDLogExists $l)) { continue }
        $file = Join-Path $script:WD.EvtxDir (($l -replace '[\\/:*?"<>| ]', '_') + '.evtx')
        & wevtutil.exe epl $l $file 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-WDLog "EVTX export failed for $l" WARN }
    }
}

function Invoke-WDRawArtifacts {
    if (-not $script:WD.IsAdmin) { Write-WDLog 'Raw artifact collection needs administrator rights - skipping' WARN; return }
    $dst = Join-Path $script:WD.FilesDir 'raw'
    $cfg = "$env:SystemRoot\System32\config"
    foreach ($h in @('SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY', 'DEFAULT')) {
        foreach ($suffix in @('', '.LOG1', '.LOG2')) { [void](Copy-WDLockedFile "$cfg\$h$suffix" "$dst\Registry\$h$suffix") }
    }
    foreach ($p in (Get-WDProfiles)) {
        foreach ($f in @('NTUSER.DAT', 'NTUSER.DAT.LOG1', 'NTUSER.DAT.LOG2')) { [void](Copy-WDLockedFile (Join-Path $p.Path $f) "$dst\Registry\Users\$($p.User)\$f") }
        foreach ($f in @('UsrClass.dat', 'UsrClass.dat.LOG1', 'UsrClass.dat.LOG2')) { [void](Copy-WDLockedFile (Join-Path $p.Path "AppData\Local\Microsoft\Windows\$f") "$dst\Registry\Users\$($p.User)\$f") }
        # Browser history databases
        $browsers = @{
            'Chrome' = 'AppData\Local\Google\Chrome\User Data\Default\History'; 'Edge' = 'AppData\Local\Microsoft\Edge\User Data\Default\History'
            'Brave' = 'AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\History'
        }
        foreach ($b in $browsers.Keys) { [void](Copy-WDLockedFile (Join-Path $p.Path $browsers[$b]) "$dst\Browser\$($p.User)\$b-History") }
        foreach ($ff in @(Get-ChildItem -LiteralPath (Join-Path $p.Path 'AppData\Roaming\Mozilla\Firefox\Profiles') -Directory -ErrorAction SilentlyContinue)) {
            [void](Copy-WDLockedFile (Join-Path $ff.FullName 'places.sqlite') "$dst\Browser\$($p.User)\Firefox-$($ff.Name)-places.sqlite")
        }
        # Jump lists & LNK
        foreach ($sub in @('AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations', 'AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations')) {
            $src = Join-Path $p.Path $sub
            if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination "$dst\JumpLists\$($p.User)\$(Split-Path $sub -Leaf)" -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
    [void](Copy-WDLockedFile "$env:SystemRoot\System32\sru\SRUDB.dat" "$dst\SRUM\SRUDB.dat")
    [void](Copy-WDLockedFile "$env:SystemRoot\System32\wbem\Repository\OBJECTS.DATA" "$dst\WMI\OBJECTS.DATA")
    [void](Copy-WDLockedFile "$env:SystemRoot\INF\setupapi.dev.log" "$dst\Logs\setupapi.dev.log")
    [void](Copy-WDLockedFile "$env:SystemRoot\System32\drivers\etc\hosts" "$dst\Logs\hosts")
    foreach ($m in @(Get-ChildItem -LiteralPath "$env:ProgramData\Microsoft\Windows Defender\Support" -Filter 'MPLog-*.log' -ErrorAction SilentlyContinue)) { [void](Copy-WDLockedFile $m.FullName "$dst\Defender\$($m.Name)") }
    Copy-Item -LiteralPath "$env:SystemRoot\Prefetch" -Destination "$dst\Prefetch" -Recurse -Force -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath "$env:SystemRoot\System32\Tasks" -Destination "$dst\Tasks" -Recurse -Force -ErrorAction SilentlyContinue
    # Quarantine copies of files flagged during analysis (for sandbox / reverse engineering).
    $q = Join-Path $script:WD.FilesDir 'suspicious'
    foreach ($f in @($script:WD.SuspiciousFiles.Keys | Select-Object -First 200)) {
        if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { continue }
        $info = Get-WDFileInfo $f
        if ($info.Size -gt 50MB) { continue }
        $name = if ($info.SHA256) { "$($info.SHA256).bin" } else { ((Split-Path $f -Leaf) + '.bin') }
        [void](Copy-WDLockedFile $f (Join-Path $q $name))
    }
    if (Test-Path -LiteralPath $q) { Set-Content -LiteralPath (Join-Path $q 'README.txt') -Value 'Files under suspicious\ are named <sha256>.bin and have been renamed to prevent accidental execution. Handle as live malware.' -Encoding UTF8 }
    Write-WDLog 'Raw artifacts collected (hives, SRUM, WMI repo, Prefetch, Tasks, browser history, jump lists, MPLog, suspicious files)' OK
}

function Write-WDManifest {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($f in @(Get-ChildItem -LiteralPath $script:WD.CaseDir -Recurse -File -Force -ErrorAction SilentlyContinue)) {
        if ($f.Name -eq 'manifest.sha256.csv') { continue }
        $h = ''
        try { $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash } catch { }
        $rows.Add([pscustomobject][ordered]@{ File = $f.FullName.Substring($script:WD.CaseDir.Length + 1); Bytes = $f.Length; SHA256 = $h; ModifiedUtc = (ConvertTo-WDTimeString $f.LastWriteTime) })
    }
    $rows | Export-Csv -LiteralPath (Join-Path $script:WD.CaseDir 'manifest.sha256.csv') -NoTypeInformation -Encoding UTF8
}
