# =============================================================================
#  Windows Detective - File system, USB & browser artifacts
#  Powered by Bashar Salmo
#  WD-SELF-MARKER
# =============================================================================

$script:WDInterestingExtRx = '(?i)\.(exe|dll|scr|com|pif|cpl|sys|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|bat|cmd|msi|msix|iso|img|vhd|vhdx|one|lnk|jar|chm|xll|library-ms|appref-ms)$'
$script:WDScriptExtRx     = '(?i)\.(ps1|psm1|vbs|vbe|js|jse|wsf|hta|bat|cmd)$'

function Get-WDZoneInfo {
    param([string]$Path)
    try {
        $z = Get-Content -LiteralPath $Path -Stream Zone.Identifier -ErrorAction Stop
        $o = [ordered]@{ ZoneId = ''; HostUrl = ''; ReferrerUrl = '' }
        foreach ($l in $z) {
            if ($l -match '^ZoneId=(\d)') { $o.ZoneId = $Matches[1] }
            elseif ($l -match '^HostUrl=(.*)') { $o.HostUrl = $Matches[1] }
            elseif ($l -match '^ReferrerUrl=(.*)') { $o.ReferrerUrl = $Matches[1] }
        }
        return [pscustomobject]$o
    } catch { return $null }
}

function Invoke-WDFileSystemCollector {
    if ($script:WD.Options.Quick) { Write-WDLog 'Quick mode: file-system sweep limited to Downloads/Desktop/Temp' INFO }
    $deep = [bool]$script:WD.Options.Deep
    $targets = New-Object System.Collections.Generic.List[object]
    foreach ($p in (Get-WDProfiles)) {
        foreach ($sub in @('Downloads', 'Desktop', 'AppData\Local\Temp')) { $targets.Add(@{ Path = (Join-Path $p.Path $sub); Depth = 3 }) }
        if (-not $script:WD.Options.Quick) {
            foreach ($sub in @('Documents', 'AppData\Roaming', 'AppData\Local', 'AppData\LocalLow', 'Music', 'Pictures', 'Videos')) {
                $d = 2; if ($deep) { $d = 5 }
                $targets.Add(@{ Path = (Join-Path $p.Path $sub); Depth = $d })
            }
        }
    }
    foreach ($sys in @("$env:SystemDrive\Users\Public", "$env:SystemRoot\Temp", "$env:SystemDrive\PerfLogs", "$env:SystemRoot\Tasks", "$env:SystemRoot\Tracing", "$env:SystemRoot\debug", "$env:SystemDrive\`$Recycle.Bin", "$env:SystemDrive\Intel", "$env:SystemDrive\Temp")) {
        $targets.Add(@{ Path = $sys; Depth = 4 })
    }
    if (-not $script:WD.Options.Quick) { $targets.Add(@{ Path = $env:ProgramData; Depth = 2 }) }

    $max = 8000; if ($deep) { $max = 40000 }
    $rows = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($t in $targets) {
        if (-not (Test-Path -LiteralPath $t.Path)) { continue }
        $items = @(Get-ChildItem -LiteralPath $t.Path -Recurse -Depth $t.Depth -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match $script:WDInterestingExtRx -and ($_.LastWriteTime -ge $script:WD.Since -or $_.CreationTime -ge $script:WD.Since) })
        foreach ($f in $items) {
            if ($rows.Count -ge $max) { break }
            if ($seen.ContainsKey($f.FullName) -or $f.FullName -match $script:WDSelfExclusionRx) { continue }
            $seen[$f.FullName] = $true
            if ($f.FullName -match '(?i)\\AppData\\Local\\(Microsoft\\(Edge|Teams|OneDrive|WindowsApps)|Google\\Chrome|Mozilla|Packages|Programs\\Microsoft VS Code|JetBrains|pip|npm-cache|NuGet)\\' -and $f.Extension -match '(?i)^\.(dll|js|lnk)$') { continue }
            $info = Get-WDFileInfo $f.FullName
            $zone = Get-WDZoneInfo $f.FullName
            $risk = Get-WDPathRisk $f.FullName
            $row = [pscustomobject][ordered]@{
                Path = $f.FullName; SizeKB = [math]::Round($f.Length / 1KB, 1); CreatedUtc = (ConvertTo-WDTimeString $f.CreationTime); ModifiedUtc = (ConvertTo-WDTimeString $f.LastWriteTime)
                Hidden = [bool]($f.Attributes -band [IO.FileAttributes]::Hidden); SHA256 = $info.SHA256; Signature = $info.SigStatus; Signer = $info.Signer
                ZoneId = $(if ($zone) { $zone.ZoneId } else { '' }); DownloadUrl = $(if ($zone) { $zone.HostUrl } else { '' }); Referrer = $(if ($zone) { $zone.ReferrerUrl } else { '' }); PathRisk = $risk
            }
            $rows.Add($row)
            $when = $f.CreationTime; if ($f.LastWriteTime -gt $when) { $when = $f.LastWriteTime }
            $ev = "$($f.FullName) | created $($row.CreatedUtc) UTC | sha256 $($info.SHA256) | sig $($info.SigStatus) $($info.Signer)"
            if ($zone -and $zone.HostUrl) { $ev += " | downloaded from $($zone.HostUrl)" }
            Add-WDTimeline -Time $f.CreationTime -Source 'FileSystem' -Description "File created: $($f.Name)" -Detail $f.FullName -Severity $(if ($risk -eq 'High') { 'Low' } else { 'Info' })

            $flagged = $false
            if ($f.Name -match '(?i)\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|rtf|csv|zip|rar|mp4|mp3)\s*\.(exe|scr|com|pif|js|jse|vbs|vbe|hta|bat|cmd|ps1|lnk|wsf)$' -or $f.Name -match '[\u202E]') {
                Add-Finding -Severity High -Category 'Files' -Title 'File with deceptive double extension / RTLO trick' -Evidence $ev -Mitre 'T1036.007' -Time $when; $flagged = $true
            }
            if ($info.IsPE -and $f.Extension -match '(?i)^\.(exe|scr|com|pif|dll|cpl|sys)$') {
                if ($info.SigStatus -eq 'HashMismatch') { Add-Finding -Severity High -Category 'Files' -Title 'Executable with tampered signature' -Evidence $ev -Mitre 'T1036' -Time $when; $flagged = $true }
                elseif ($info.SigStatus -ne 'Valid' -and $risk -eq 'High') { Add-Finding -Severity High -Category 'Files' -Title 'Unsigned executable dropped in high-risk location' -Evidence $ev -Mitre 'T1204.002,T1105' -Time $when; $flagged = $true }
                elseif ($info.SigStatus -ne 'Valid' -and $zone -and $zone.ZoneId -eq '3') { Add-Finding -Severity Medium -Category 'Files' -Title 'Unsigned executable downloaded from the internet' -Evidence $ev -Mitre 'T1204.002' -Time $when; $flagged = $true }
                elseif ($info.SigStatus -ne 'Valid' -and $risk -eq 'User' -and $f.Extension -match '(?i)^\.(exe|scr|com|pif)$') { Add-Finding -Severity Low -Category 'Files' -Title 'Unsigned executable in user profile' -Evidence $ev -Mitre 'T1204.002' -Time $when }
                if ($f.Extension -match '(?i)^\.(scr|pif|com)$') { Add-Finding -Severity Medium -Category 'Files' -Title "Rare executable type $($f.Extension) created recently" -Evidence $ev -Mitre 'T1204.002' -Time $when; $flagged = $true }
                if ($row.Hidden -and $f.Extension -match '(?i)^\.(exe|dll)$') { Add-Finding -Severity Medium -Category 'Files' -Title 'Hidden executable' -Evidence $ev -Mitre 'T1564.001' -Time $when; $flagged = $true }
                $tool = Get-WDToolMatch $f.Name
                if ($tool) { Add-Finding -Severity $tool.Severity -Category 'Files' -Title "Tool on disk: $($tool.Label)" -Evidence $ev -Mitre $tool.Mitre -Time $when; $flagged = $true }
                $masq = Test-WDMasquerade $f.FullName
                if ($masq -and $f.Extension -eq '.exe') { Add-Finding -Severity High -Category 'Files' -Title "Masquerading file: $masq" -Evidence $ev -Mitre 'T1036.005' -Time $when; $flagged = $true }
            }
            if ($f.Name -match $script:WDScriptExtRx) {
                if ($risk -eq 'High' -or ($zone -and $zone.ZoneId -eq '3')) {
                    Add-Finding -Severity Medium -Category 'Files' -Title "Script ($($f.Extension)) dropped in high-risk location or downloaded" -Evidence $ev -Mitre 'T1059' -Time $when; $flagged = $true
                }
                if ($f.Length -le 2MB) {
                    $content = ''
                    try { $content = [IO.File]::ReadAllText($f.FullName) } catch { }
                    $hits = @(Test-WDCommandLine $content)
                    if ($hits.Count -gt 0) {
                        # Script *content* matches are weaker evidence than executed command lines, so they are
                        # reported once per file and one severity level lower.
                        $worst = ($hits | Sort-Object { $script:WDSeverityOrder[$_.Severity] } | Select-Object -First 1).Severity
                        $sev = @{ Critical = 'High'; High = 'Medium'; Medium = 'Low'; Low = 'Low' }[$worst]
                        $titles = ($hits | ForEach-Object { "$($_.Id) $($_.Title)" }) -join '; '
                        $mitre = (($hits | ForEach-Object { $_.Mitre -split ',' }) | Select-Object -Unique) -join ','
                        Add-Finding -Severity $sev -Category 'Files' -Title "Script file contains suspicious code ($($hits.Count) rule(s))" -Detail "Matched: $titles. Review the script - admin and developer tools can trigger these rules too." -Evidence $ev -Mitre $mitre -Time $when -Source 'FileSystem'
                        $flagged = $true
                    }
                }
            }
            if ($f.Extension -match '(?i)^\.(iso|img|vhd|vhdx)$' -and $zone -and $zone.ZoneId -eq '3') {
                Add-Finding -Severity Medium -Category 'Files' -Title 'Disk image downloaded from the internet (MOTW bypass delivery)' -Evidence $ev -Mitre 'T1553.005' -Time $when; $flagged = $true
            }
            if ($f.Extension -match '(?i)^\.(one|chm|xll|hta|library-ms)$' -and $zone -and $zone.ZoneId -eq '3') {
                Add-Finding -Severity Medium -Category 'Files' -Title "Downloaded $($f.Extension) file (common malware lure)" -Evidence $ev -Mitre 'T1204.002' -Time $when; $flagged = $true
            }
            if ($f.Extension -eq '.lnk' -and $risk -ne 'None' -and $f.FullName -notmatch '(?i)\\(Recent|Start Menu|Quick Launch|SendTo)\\') {
                $target = Get-WDShortcutTarget $f.FullName
                if ((Invoke-WDCommandCheck -Text $target -Source "Shortcut $($f.FullName)" -Time $when -Category 'Files') -gt 0 -or $target -match '(?i)\\(powershell|cmd|mshta|wscript|cscript|rundll32)\.exe') {
                    Add-Finding -Severity High -Category 'Files' -Title 'Shortcut (.lnk) launches an interpreter - malicious LNK?' -Evidence "$($f.FullName) -> $target" -Mitre 'T1204.002' -Time $when; $flagged = $true
                }
            }
            if ($flagged) { $script:WD.SuspiciousFiles[$f.FullName] = 'FileSystem' }
        }
    }
    if ($rows.Count -ge $max) { Write-WDLog "File sweep capped at $max files" WARN }
    Save-WDArtifact -Name 'RecentFiles' -Section 'File System' -Data ($rows | Sort-Object CreatedUtc -Descending) -Description "Executables, scripts, disk images and shortcuts created/modified in the last $($script:WD.Options.Days) days in user-writable locations"

    Invoke-WDRansomwareCheck
    Invoke-WDShadowCopies
    Invoke-WDUsbHistory
    Invoke-WDBrowserExtensions
    if ($deep) { Invoke-WDSystem32Check }
}

function Invoke-WDRansomwareCheck {
    $noteRx = '(?i)(decrypt|ransom|restore[_-]?(my[_-]?)?files|how[_-]?to[_-]?(back|recover|restore|decrypt)|recover[_-]?files|your[_-]?files|!!!|read[_-]?me[_-]?now|_readme\.txt$|help[_-]?decrypt)'
    $hits = New-Object System.Collections.Generic.List[object]
    foreach ($p in (Get-WDProfiles)) {
        foreach ($sub in @('Desktop', 'Documents', 'Downloads', 'Pictures')) {
            foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $p.Path $sub) -Recurse -Depth 2 -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $noteRx -and $_.Extension -match '(?i)^\.(txt|html?|hta|rtf|url)$' } | Select-Object -First 50)) {
                $hits.Add([pscustomobject]@{ Path = $f.FullName; CreatedUtc = (ConvertTo-WDTimeString $f.CreationTime) })
            }
        }
    }
    $dirs = @($hits | ForEach-Object { Split-Path $_.Path -Parent } | Select-Object -Unique)
    if ($dirs.Count -ge 3) {
        Add-Finding -Severity Critical -Category 'Impact' -Title 'Probable ransom notes found in multiple folders' -Evidence (($hits | Select-Object -First 10 | ForEach-Object { $_.Path }) -join ' | ') -Mitre 'T1486'
    } elseif ($hits.Count -gt 0) {
        Add-Finding -Severity Low -Category 'Impact' -Title 'File names resembling ransom notes' -Evidence (($hits | Select-Object -First 5 | ForEach-Object { $_.Path }) -join ' | ') -Mitre 'T1486'
    }
    Save-WDArtifact -Name 'PossibleRansomNotes' -Section 'File System' -Data $hits -Description 'Files whose names look like ransom notes'
}

function Invoke-WDShadowCopies {
    try {
        $sc = @(Get-CimInstance Win32_ShadowCopy -ErrorAction Stop | Select-Object ID, VolumeName, @{ n = 'CreatedUtc'; e = { ConvertTo-WDTimeString $_.InstallDate } }, ClientAccessible)
        Save-WDArtifact -Name 'ShadowCopies' -Section 'File System' -Data $sc -Description 'Volume Shadow Copies (restore points)'
        $script:WD.SystemInfo['Shadow Copies'] = [string]$sc.Count
    } catch { }
}

function Invoke-WDUsbHistory {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($dev in @(Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -ErrorAction SilentlyContinue)) {
        foreach ($inst in @(Get-ChildItem -LiteralPath $dev.PSPath -ErrorAction SilentlyContinue)) {
            $fn = Get-WDRegValue $inst.PSPath 'FriendlyName'
            $rows.Add([pscustomobject][ordered]@{ Device = $dev.PSChildName; Serial = $inst.PSChildName; FriendlyName = $fn; FirstInstallUtc = ''; Source = 'USBSTOR' })
        }
    }
    foreach ($k in @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Portable Devices\Devices' -ErrorAction SilentlyContinue)) {
        $rows.Add([pscustomobject][ordered]@{ Device = $k.PSChildName; Serial = ''; FriendlyName = (Get-WDRegValue $k.PSPath 'FriendlyName'); FirstInstallUtc = ''; Source = 'Portable Devices' })
    }
    # First-install times from setupapi.dev.log
    $log = Join-Path $env:SystemRoot 'INF\setupapi.dev.log'
    if (Test-Path -LiteralPath $log) {
        $current = ''
        $lines = @()
        try { $lines = [IO.File]::ReadAllLines($log) } catch { Write-WDLog "setupapi.dev.log unreadable: $($_.Exception.Message)" WARN }
        foreach ($line in $lines) {
            if ($line -match '>>>\s+\[Device Install.*-\s+(USBSTOR\\[^\]]+)\]') { $current = $Matches[1]; continue }
            if ($current -and $line -match '>>>\s+Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})') {
                $t = [datetime]::ParseExact($Matches[1], 'yyyy/MM/dd HH:mm:ss', $null)
                $serial = ($current -split '\\')[-1]
                foreach ($r in $rows) { if ($r.Serial -and $serial -like "$($r.Serial)*") { $r.FirstInstallUtc = ConvertTo-WDTimeString $t } }
                if ($t -ge $script:WD.Since) {
                    Add-WDTimeline -Time $t -Source 'USB' -Description "USB storage first connected: $current" -Severity 'Low'
                    Add-Finding -Severity Low -Category 'Exfiltration' -Title 'New USB storage device connected during investigation window' -Evidence $current -Mitre 'T1052.001' -Time $t
                }
                $current = ''
            }
        }
    }
    Save-WDArtifact -Name 'UsbDevices' -Section 'File System' -Data $rows -Description 'USB mass-storage and portable devices ever connected'
}

function Invoke-WDBrowserExtensions {
    $rows = New-Object System.Collections.Generic.List[object]
    $bases = @(
        @{ Browser = 'Chrome'; Rel = 'AppData\Local\Google\Chrome\User Data' }, @{ Browser = 'Edge'; Rel = 'AppData\Local\Microsoft\Edge\User Data' },
        @{ Browser = 'Brave'; Rel = 'AppData\Local\BraveSoftware\Brave-Browser\User Data' }, @{ Browser = 'Opera'; Rel = 'AppData\Roaming\Opera Software\Opera Stable' }
    )
    foreach ($p in (Get-WDProfiles)) {
        foreach ($b in $bases) {
            $root = Join-Path $p.Path $b.Rel
            if (-not (Test-Path -LiteralPath $root)) { continue }
            foreach ($prof in @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(Default|Profile \d+)$' -or $b.Browser -eq 'Opera' })) {
                $extDir = Join-Path $prof.FullName 'Extensions'
                foreach ($ext in @(Get-ChildItem -LiteralPath $extDir -Directory -Force -ErrorAction SilentlyContinue)) {
                    $ver = Get-ChildItem -LiteralPath $ext.FullName -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                    if (-not $ver) { continue }
                    $mf = Join-Path $ver.FullName 'manifest.json'
                    $name = ''; $perms = ''; $update = ''
                    try {
                        $j = Get-Content -LiteralPath $mf -Raw -ErrorAction Stop | ConvertFrom-Json
                        $name = $j.name; $update = $j.update_url
                        $perms = (@($j.permissions) + @($j.host_permissions) | Where-Object { $_ -is [string] }) -join ' '
                    } catch { }
                    $rows.Add([pscustomobject][ordered]@{ User = $p.User; Browser = $b.Browser; Profile = $prof.Name; Id = $ext.Name; Name = $name; Version = $ver.Name; InstalledUtc = (ConvertTo-WDTimeString $ext.CreationTime); UpdateUrl = $update; Permissions = (Limit-WDText $perms 400) })
                    $store = (-not $update) -or $update -match '(?i)clients2\.google\.com|edge\.microsoft\.com'
                    if (-not $store) {
                        Add-Finding -Severity Medium -Category 'Browser' -Title 'Browser extension installed from outside the official store' -Evidence "$($p.User) $($b.Browser): $name ($($ext.Name)) update_url $update" -Mitre 'T1176' -Time $ext.CreationTime
                    }
                    if ($ext.CreationTime -ge $script:WD.Since -and $perms -match '(?i)(<all_urls>|\*://\*/\*|cookies|webRequest|nativeMessaging|debugger|clipboardRead)') {
                        Add-Finding -Severity Medium -Category 'Browser' -Title 'Recently installed browser extension with powerful permissions' -Evidence "$($p.User) $($b.Browser): $name ($($ext.Name)) perms: $(Limit-WDText $perms 300)" -Mitre 'T1176' -Time $ext.CreationTime
                    }
                }
            }
        }
    }
    Save-WDArtifact -Name 'BrowserExtensions' -Section 'Browser' -Data $rows -Description 'Chromium-based browser extensions per user'
}

function Invoke-WDSystem32Check {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($dir in @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64", "$env:SystemRoot")) {
        foreach ($f in @(Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Extension -match '(?i)^\.(exe|dll|sys)$' -and ($_.LastWriteTime -ge $script:WD.Since -or $_.CreationTime -ge $script:WD.Since) })) {
            $info = Get-WDFileInfo $f.FullName
            $rows.Add([pscustomobject][ordered]@{ Path = $f.FullName; CreatedUtc = (ConvertTo-WDTimeString $f.CreationTime); ModifiedUtc = (ConvertTo-WDTimeString $f.LastWriteTime); Signature = $info.SigStatus; Signer = $info.Signer; SHA256 = $info.SHA256 })
            if ($info.SigStatus -ne 'Valid') {
                Add-Finding -Severity High -Category 'Files' -Title 'Recently written unsigned binary in Windows system directory' -Evidence "$($f.FullName) ($($info.SigStatus)) sha256 $($info.SHA256)" -Mitre 'T1036.005,T1574.001' -Time $f.LastWriteTime
            }
        }
    }
    Save-WDArtifact -Name 'System32Changes' -Section 'File System' -Data $rows -Description 'Binaries in Windows directories changed during the window (Deep mode)'
}
