# =============================================================================
#  Windows Detective - Evidence of execution
#  Powered by Bashar Salmo
#  WD-SELF-MARKER
#
#  Prefetch, BAM, ShimCache (AppCompatCache), Amcache, UserAssist, RunMRU
#  (ClickFix), PSReadLine console history and recent documents.
# =============================================================================

function Test-WDExecutedPath {
    # Common checks for any "this program ran" artifact.
    param([string]$Path, [string]$Source, $Time = $null, [string]$Extra = '', [switch]$NoPathCheck)
    if (-not $Path -or $Path -match $script:WDSelfExclusionRx) { return }
    $recent = ($null -eq $Time) -or (($Time -is [datetime]) -and $Time -ge $script:WD.Since.ToUniversalTime())
    $tool = Get-WDToolMatch $Path
    if ($tool) {
        $sev = $tool.Severity
        if (-not $recent -and $script:WDSeverityOrder[$sev] -lt 2) { $sev = 'Medium' }
        Add-Finding -Severity $sev -Category 'Execution' -Title "Evidence of execution: $($tool.Label)" -Detail "Artifact: $Source. $Extra" -Evidence $Path -Mitre $tool.Mitre -Time $Time -Source $Source
    }
    $masq = Test-WDMasquerade ($Path -replace '^\\Device\\HarddiskVolume\d+', 'C:')
    if ($masq -and $Path -match '\\') {
        Add-Finding -Severity High -Category 'Execution' -Title "Evidence of execution of masquerading binary: $masq" -Detail "Artifact: $Source." -Evidence $Path -Mitre 'T1036.005' -Time $Time -Source $Source
    }
    if (-not $NoPathCheck -and $recent -and (Get-WDPathRisk $Path) -eq 'High' -and $Path -match '(?i)\.(exe|scr|com|pif|bat|cmd|ps1|vbs|js|hta)$') {
        Add-Finding -Severity Medium -Category 'Execution' -Title 'Program executed from high-risk location' -Detail "Artifact: $Source. $Extra" -Evidence $Path -Mitre 'T1204.002' -Time $Time -Source $Source
    }
}

function Invoke-WDExecutionCollector {
    Invoke-WDPrefetch
    Invoke-WDBam
    Invoke-WDShimCache
    Invoke-WDAmcache
    Invoke-WDUserAssist
    Invoke-WDRunMru
    Invoke-WDPsReadLine
    Invoke-WDRecentFiles
}

function Invoke-WDPrefetch {
    $dir = Join-Path $env:SystemRoot 'Prefetch'
    $rows = New-Object System.Collections.Generic.List[object]
    $files = @(Get-ChildItem -LiteralPath $dir -Filter '*.pf' -Force -ErrorAction SilentlyContinue)
    if ($files.Count -eq 0) {
        $pfMode = Get-WDRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' 'EnablePrefetcher'
        if ($script:WD.IsAdmin -and $pfMode -ne 0) {
            Add-Finding -Severity Medium -Category 'Anti-Forensics' -Title 'Prefetch folder is empty although prefetching is enabled (possibly wiped)' -Evidence "EnablePrefetcher=$pfMode" -Mitre 'T1070.004'
        }
    }
    foreach ($f in $files) {
        $exe = $f.Name -replace '-[0-9A-F]{8}\.pf$', ''
        $rows.Add([pscustomobject][ordered]@{ Executable = $exe; FirstRunUtc = (ConvertTo-WDTimeString $f.CreationTime); LastRunUtc = (ConvertTo-WDTimeString $f.LastWriteTime); PrefetchFile = $f.Name })
        if ($f.LastWriteTime -ge $script:WD.Since) {
            Add-WDTimeline -Time $f.LastWriteTime -Source 'Prefetch' -Description "Program last run: $exe" -Detail $f.Name
            if ($f.CreationTime -ge $script:WD.Since) { Add-WDTimeline -Time $f.CreationTime -Source 'Prefetch' -Description "Program first run: $exe" -Detail $f.Name }
        }
        Test-WDExecutedPath -Path $exe -Source 'Prefetch' -Time $f.LastWriteTimeUtc -Extra "First run $(ConvertTo-WDTimeString $f.CreationTime) UTC."
    }
    Save-WDArtifact -Name 'Prefetch' -Section 'Execution' -Data ($rows | Sort-Object LastRunUtc -Descending) -Description 'Prefetch files (first/last run approximations)'
}

function Invoke-WDBam {
    $rows = New-Object System.Collections.Generic.List[object]
    $sidMap = @{}
    foreach ($p in (Get-WDProfiles)) { if ($p.Sid) { $sidMap[$p.Sid] = $p.User } }
    foreach ($base in @('HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings', 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings')) {
        foreach ($k in @(Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue)) {
            $sid = $k.PSChildName
            foreach ($v in (Get-WDRegValues $k.PSPath)) {
                if ($v.Name -in @('Version', 'SequenceNumber') -or -not ($v.Raw -is [byte[]])) { continue }
                $t = ConvertFrom-WDFileTime $v.Raw 0
                $rows.Add([pscustomobject][ordered]@{ User = $(if ($sidMap[$sid]) { $sidMap[$sid] } else { $sid }); Path = $v.Name; LastRunUtc = (ConvertTo-WDTimeString $t) })
                if ($t -and $t -ge $script:WD.Since.ToUniversalTime()) { Add-WDTimeline -Time $t -Source 'BAM' -Description "Program run by $($sidMap[$sid]): $(Split-Path $v.Name -Leaf)" -Detail $v.Name }
                Test-WDExecutedPath -Path $v.Name -Source 'BAM' -Time $t -Extra "User SID $sid."
            }
        }
    }
    Save-WDArtifact -Name 'BAM' -Section 'Execution' -Data ($rows | Sort-Object LastRunUtc -Descending) -Description 'Background Activity Moderator - last execution per user'
}

function Invoke-WDShimCache {
    $data = Get-WDRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' 'AppCompatCache'
    if (-not ($data -is [byte[]]) -or $data.Length -lt 64) { return }
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        $offset = [BitConverter]::ToInt32($data, 0)
        if ($offset -notin @(0x30, 0x34)) { Write-WDLog "ShimCache format header 0x$('{0:X}' -f $offset) not supported (Windows 10/11 only)" WARN; return }
        $i = 0
        while ($offset + 14 -lt $data.Length -and $i -lt 2048) {
            if ([Text.Encoding]::ASCII.GetString($data, $offset, 4) -ne '10ts') { break }
            $entrySize = [BitConverter]::ToInt32($data, $offset + 8)
            $pathLen = [BitConverter]::ToUInt16($data, $offset + 12)
            $path = [Text.Encoding]::Unicode.GetString($data, $offset + 14, $pathLen)
            $mod = ConvertFrom-WDFileTime $data ($offset + 14 + $pathLen)
            $rows.Add([pscustomobject][ordered]@{ Position = $i; Path = $path; FileModifiedUtc = (ConvertTo-WDTimeString $mod) })
            Test-WDExecutedPath -Path $path -Source 'ShimCache' -Time $null -Extra "ShimCache position $i (lower = more recent). Presence indicates the file existed/was shimmed, not necessarily executed." -NoPathCheck
            $offset += 12 + $entrySize
            $i++
        }
    } catch { Write-WDLog "ShimCache parse error: $($_.Exception.Message)" WARN }
    Save-WDArtifact -Name 'ShimCache' -Section 'Execution' -Data $rows -Description 'AppCompatCache entries (most recent first)'
}

function Invoke-WDAmcache {
    if (-not $script:WD.IsAdmin) { return }
    $src = Join-Path $env:SystemRoot 'AppCompat\Programs\Amcache.hve'
    if (-not (Test-Path -LiteralPath $src)) { return }
    $dstDir = Join-Path $script:WD.FilesDir 'Amcache'
    $dst = Join-Path $dstDir 'Amcache.hve'
    if (-not (Copy-WDLockedFile $src $dst)) { Write-WDLog 'Could not copy Amcache.hve' WARN; return }
    foreach ($log in @('Amcache.hve.LOG1', 'Amcache.hve.LOG2')) { [void](Copy-WDLockedFile (Join-Path (Split-Path $src) $log) (Join-Path $dstDir $log)) }
    # Parse a working copy so the preserved evidence copy stays untouched.
    $work = Join-Path $script:WD.FilesDir 'Amcache_parse.hve'
    Copy-Item -LiteralPath $dst -Destination $work -Force
    $mount = 'WD_Amcache'
    & reg.exe load "HKLM\$mount" $work 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-WDLog 'Amcache hive could not be mounted (kept raw copy for offline analysis)' WARN; Remove-Item -LiteralPath $work -Force -ErrorAction SilentlyContinue; return }
    $rows = New-Object System.Collections.Generic.List[object]
    # Raw .NET keys (disposed explicitly) instead of the registry provider, whose cached handles
    # would keep the hive mounted on the evidence host after parsing.
    $root = $null
    try {
        $root = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$mount\Root\InventoryApplicationFile")
        if ($root) {
            foreach ($name in $root.GetSubKeyNames()) {
                $k = $root.OpenSubKey($name)
                if (-not $k) { continue }
                try {
                    $path = [string]$k.GetValue('LowerCaseLongPath'); $fileName = [string]$k.GetValue('Name')
                    $sha1 = ([string]$k.GetValue('FileId')) -replace '^0000', ''
                    $lw = Get-WDRegKeyLastWriteFromKey $k
                    $rows.Add([pscustomobject][ordered]@{
                        Path = $path; Name = $fileName; SHA1 = $sha1; Publisher = [string]$k.GetValue('Publisher'); Product = [string]$k.GetValue('ProductName')
                        Version = [string]$k.GetValue('Version'); LinkDate = [string]$k.GetValue('LinkDate'); Size = $k.GetValue('Size'); KeyLastWriteUtc = (ConvertTo-WDTimeString $lw)
                    })
                    if ($sha1) { Add-WDObserved -Type Hashes -Value $sha1 -Source "Amcache: $path" }
                    if ($lw -and $lw -ge $script:WD.Since.ToUniversalTime()) { Add-WDTimeline -Time $lw -Source 'Amcache' -Description "Program recorded in Amcache: $fileName" -Detail "$path sha1 $sha1" }
                    Test-WDExecutedPath -Path $path -Source 'Amcache' -Time $lw -Extra "SHA1 $sha1." -NoPathCheck
                } finally { $k.Dispose() }
            }
        }
    } finally {
        if ($root) { $root.Dispose() }
        $unloaded = $false
        foreach ($attempt in 1..5) {
            [gc]::Collect(); [gc]::WaitForPendingFinalizers()
            & reg.exe unload "HKLM\$mount" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { $unloaded = $true; break }
            Start-Sleep -Milliseconds 500
        }
        if ($unloaded) {
            Get-ChildItem -LiteralPath $script:WD.FilesDir -Filter 'Amcache_parse.hve*' -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        } else {
            Write-WDLog "Could not unmount HKLM\$mount - it is released at the next reboot, or run: reg unload HKLM\$mount" WARN
        }
    }
    Save-WDArtifact -Name 'Amcache' -Section 'Execution' -Data $rows -Description 'Amcache InventoryApplicationFile (path + SHA1 of executed/installed programs)'
}

function ConvertFrom-WDRot13 {
    param([string]$Text)
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Text.ToCharArray()) {
        $c = [int]$ch
        if ($c -ge 65 -and $c -le 90) { $c = (($c - 65 + 13) % 26) + 65 }
        elseif ($c -ge 97 -and $c -le 122) { $c = (($c - 97 + 13) % 26) + 97 }
        [void]$sb.Append([char]$c)
    }
    return $sb.ToString()
}

$script:WDKnownFolders = @{
    '{6D809377-6AF0-444B-8957-A3773F02200E}' = '%ProgramFiles%'; '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}' = '%ProgramFiles(x86)%'
    '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}' = '%SystemRoot%\System32'; '{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}' = '%SystemRoot%\SysWOW64'
    '{F38BF404-1D43-42F2-9305-67DE0B28FC23}' = '%SystemRoot%'; '{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}' = '%ProgramData%\Start Menu\Programs'
    '{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}' = '%AppData%\Start Menu\Programs'; '{9E3995AB-1F9C-4F13-B827-48B24B6C7174}' = '%AppData%\Microsoft\Internet Explorer\Quick Launch\User Pinned'
    '{374DE290-123F-4565-9164-39C4925E467B}' = '%UserProfile%\Downloads'; '{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}' = '%UserProfile%\Desktop'
}

function Invoke-WDUserAssist {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($h in (Get-WDUserHives)) {
        $base = "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        foreach ($g in @(Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue)) {
            foreach ($v in (Get-WDRegValues "$($g.PSPath)\Count")) {
                if (-not ($v.Raw -is [byte[]]) -or $v.Raw.Length -lt 68) { continue }
                $name = ConvertFrom-WDRot13 $v.Name
                foreach ($kf in $script:WDKnownFolders.Keys) { if ($name.StartsWith($kf)) { $name = $script:WDKnownFolders[$kf] + $name.Substring($kf.Length) } }
                $count = [BitConverter]::ToInt32($v.Raw, 4)
                $focus = [BitConverter]::ToInt32($v.Raw, 12)
                $last = ConvertFrom-WDFileTime $v.Raw 60
                $rows.Add([pscustomobject][ordered]@{ User = $h.User; Program = $name; RunCount = $count; FocusTimeSec = [math]::Round($focus / 1000); LastRunUtc = (ConvertTo-WDTimeString $last) })
                if ($last -and $last -ge $script:WD.Since.ToUniversalTime()) { Add-WDTimeline -Time $last -Source 'UserAssist' -Description "$($h.User) launched (GUI): $(Split-Path $name -Leaf)" -Detail "$name (run count $count)" }
                Test-WDExecutedPath -Path $name -Source "UserAssist ($($h.User))" -Time $last -Extra "Run count $count."
            }
        }
    }
    Save-WDArtifact -Name 'UserAssist' -Section 'Execution' -Data ($rows | Sort-Object LastRunUtc -Descending) -Description 'GUI program launches per user (ROT13-decoded)'
}

function Invoke-WDRunMru {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($h in (Get-WDUserHives)) {
        $k = "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        if (-not (Test-Path -LiteralPath $k)) { continue }
        $lw = Get-WDRegKeyLastWrite $k
        $order = [string](Get-WDRegValue $k 'MRUList')
        foreach ($v in (Get-WDRegValues $k)) {
            if ($v.Name -eq 'MRUList') { continue }
            $cmd = $v.Value -replace '\\1$', ''
            $isNewest = ($order.Length -gt 0 -and $order.Substring(0, 1) -eq $v.Name)
            $t = $null; if ($isNewest) { $t = $lw }
            $rows.Add([pscustomobject][ordered]@{ User = $h.User; Slot = $v.Name; Command = $cmd; MostRecent = $isNewest; KeyLastWriteUtc = (ConvertTo-WDTimeString $lw) })
            $hits = Invoke-WDCommandCheck -Text $cmd -Source "Win+R Run dialog history ($($h.User))" -Time $t -Category 'Execution' -Context 'Typed or pasted into the Run dialog - the ClickFix / fake-CAPTCHA delivery path.'
            if ($cmd -match '(?i)\b(powershell|pwsh|mshta|curl|wscript|cscript|msiexec|bitsadmin|certutil|rundll32|regsvr32)\b') {
                $sev = 'Medium'
                if ($hits -gt 0 -or $cmd -match '(?i)https?://|\\\\[^\\]+\\|-e[a-z]*\s+[a-z0-9+/=]{20,}') { $sev = 'High' }
                Add-Finding -Severity $sev -Category 'Execution' -Title 'Interpreter / LOLBin launched from the Run dialog (ClickFix pattern)' -Detail 'Users are tricked into pasting such commands by fake CAPTCHA / "fix" pages.' -Evidence "$($h.User): $cmd" -Mitre 'T1204.004,T1059' -Time $t
            }
        }
        if ($lw -and $lw -ge $script:WD.Since.ToUniversalTime()) { Add-WDTimeline -Time $lw -Source 'RunMRU' -Description "Run dialog used by $($h.User)" }
    }
    Save-WDArtifact -Name 'RunMRU' -Section 'Execution' -Data $rows -Description 'Commands typed into Win+R (per user)'
}

function Invoke-WDPsReadLine {
    $rows = New-Object System.Collections.Generic.List[object]
    $dest = Join-Path $script:WD.FilesDir 'PSReadLine'
    foreach ($p in (Get-WDProfiles)) {
        $dir = Join-Path $p.Path 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine'
        foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter '*history*.txt' -Force -ErrorAction SilentlyContinue)) {
            [void](Copy-WDLockedFile $f.FullName (Join-Path $dest "$($p.User)_$($f.Name)"))
            Add-WDTimeline -Time $f.LastWriteTime -Source 'PSReadLine' -Description "PowerShell console history last written ($($p.User))" -Detail $f.FullName
            $n = 0
            foreach ($line in @(Get-Content -LiteralPath $f.FullName -ErrorAction SilentlyContinue)) {
                $n++
                if (-not $line.Trim()) { continue }
                $hits = Test-WDCommandLine $line
                if ($hits.Count -gt 0) {
                    $rows.Add([pscustomobject][ordered]@{ User = $p.User; Line = $n; Command = (Limit-WDText $line 500); Rules = (($hits | ForEach-Object { $_.Id }) -join ',') })
                    [void](Invoke-WDCommandCheck -Text $line -Source "PSReadLine history of $($p.User) line $n" -Category 'Execution' -Context 'Interactive PowerShell command typed on this host.')
                }
            }
        }
    }
    Save-WDArtifact -Name 'PSReadLineSuspicious' -Section 'Execution' -Data $rows -Description 'Suspicious lines in PowerShell console history (full copies under files\PSReadLine)'
}

function Invoke-WDRecentFiles {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($p in (Get-WDProfiles)) {
        $dir = Join-Path $p.Path 'AppData\Roaming\Microsoft\Windows\Recent'
        foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter '*.lnk' -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $script:WD.Since })) {
            $rows.Add([pscustomobject][ordered]@{ User = $p.User; Item = ($f.BaseName); OpenedUtc = (ConvertTo-WDTimeString $f.LastWriteTime); FirstOpenedUtc = (ConvertTo-WDTimeString $f.CreationTime) })
            Add-WDTimeline -Time $f.LastWriteTime -Source 'RecentDocs' -Description "$($p.User) opened: $($f.BaseName)"
            if ($f.BaseName -match '(?i)\.(iso|img|vhdx?|hta|js|jse|vbs|vbe|wsf|lnk|one|scr|xll|chm|library-ms|searchconnector-ms|url)$') {
                Add-Finding -Severity Medium -Category 'Execution' -Title 'User opened a file type commonly used for malware delivery' -Evidence "$($p.User): $($f.BaseName) at $(ConvertTo-WDTimeString $f.LastWriteTime) UTC" -Mitre 'T1204.002,T1553.005' -Time $f.LastWriteTime
            }
        }
    }
    Save-WDArtifact -Name 'RecentDocuments' -Section 'Execution' -Data ($rows | Sort-Object OpenedUtc -Descending) -Description 'Recently opened files/folders (Recent LNK) in the investigation window'
}
