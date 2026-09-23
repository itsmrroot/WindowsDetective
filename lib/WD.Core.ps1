# =============================================================================
#  Windows Detective - Core engine
#  Powered by Bashar Salmo
#  WD-SELF-MARKER (lets the tool exclude its own activity from detections)
# =============================================================================

$script:WDVersion  = '1.3.0'
$script:WDToolName = 'Windows Detective'
$script:WDBrand    = 'Powered by Bashar Salmo'

$script:WDSeverityOrder  = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
$script:WDSeverityWeight = @{ Critical = 40; High = 15; Medium = 5; Low = 1; Info = 0 }

# Paths attackers love: world/user-writable, rarely used by legitimate installed software.
$script:WDHighRiskPathRx = '(?i)(\\Users\\Public\\|\\AppData\\Local\\Temp\\|\\Windows\\Temp\\|\\PerfLogs\\|\\\$Recycle\.Bin\\|\\Windows\\Tasks\\|\\Windows\\Tracing\\|\\Windows\\debug\\|\\Windows\\Fonts\\.+\.(exe|dll|ps1|bat|vbs|js)$|\\Windows\\IME\\.+\.exe$|\\Downloads\\|\\Temp\\|\\Tmp\\|\\ProgramData\\[^\\]+$|\\AppData\\Roaming\\[^\\]+$|\\AppData\\Local\\[^\\]+\.(exe|dll)$|\\Music\\|\\Videos\\|\\Pictures\\)'
$script:WDUserPathRx     = '(?i)(\\AppData\\|\\ProgramData\\|^[a-z]:\\Users\\|\\Device\\HarddiskVolume\d+\\Users\\)'
$script:WDPeExtRx        = '(?i)\.(exe|dll|sys|scr|com|cpl|ocx|drv|efi|mui|pif)$'

function Test-WDAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function New-WDContext {
    param([hashtable]$Options)
    $script:WD = [ordered]@{
        Options        = $Options
        Since          = (Get-Date).AddDays(-1 * [int]$Options.Days)
        StartTime      = Get-Date
        EndTime        = $null
        IsAdmin        = (Test-WDAdmin)
        CaseName       = ''
        CaseDir        = ''
        RawDir         = ''
        EvtxDir        = ''
        FilesDir       = ''
        LogFile        = ''
        Findings       = New-Object System.Collections.Generic.List[object]
        FindingIndex   = @{}
        Timeline       = New-Object System.Collections.Generic.List[object]
        MaxTimeline    = 60000
        Artifacts      = [ordered]@{}
        CollectorStats = New-Object System.Collections.Generic.List[object]
        FileCache      = @{}
        SystemInfo     = [ordered]@{}
        Profiles       = $null
        UserHives      = $null
        ProcessMap     = @{}
        Autoruns       = New-Object System.Collections.Generic.List[object]
        Observed       = @{ Hashes = @{}; Ips = @{}; Domains = @{} }
        SuspiciousFiles = @{}
        MemoryImage    = ''
        Allowlist      = New-Object System.Collections.Generic.List[object]
    }
}

# ----------------------------------------------------------------------------- logging
function Write-WDLog {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR','OK','STEP')][string]$Level = 'INFO')
    $line = '[{0}] [{1,-5}] {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Level, $Message
    $color = switch ($Level) { 'WARN' { 'Yellow' } 'ERROR' { 'Red' } 'OK' { 'Green' } 'STEP' { 'Cyan' } default { 'Gray' } }
    Write-Host $line -ForegroundColor $color
    if ($script:WD -and $script:WD.LogFile) {
        try { Add-Content -LiteralPath $script:WD.LogFile -Value $line -Encoding UTF8 } catch { }
    }
}

function Invoke-WDCollector {
    param([string]$Name, [scriptblock]$Script)
    Write-WDLog "Collecting: $Name" STEP
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $status = 'OK'; $err = ''
    $before = $script:WD.Findings.Count
    try { & $Script }
    catch {
        $status = 'ERROR'; $err = $_.Exception.Message
        Write-WDLog "$Name failed: $err" ERROR
    }
    $sw.Stop()
    $script:WD.CollectorStats.Add([pscustomobject][ordered]@{
        Collector = $Name
        Status    = $status
        Seconds   = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        NewFindings = $script:WD.Findings.Count - $before
        Error     = $err
    })
}

# ----------------------------------------------------------------------------- text / time helpers
function Limit-WDText {
    param([string]$Text, [int]$Max = 2000)
    if ($null -eq $Text) { return '' }
    $t = $Text.Trim()
    if ($t.Length -gt $Max) { return $t.Substring(0, $Max) + ' ...[truncated]' }
    return $t
}

function ConvertTo-WDTimeString {
    param($Time)
    if ($null -eq $Time) { return '' }
    if ($Time -is [datetime]) {
        if ($Time.Year -lt 1980) { return '' }
        return $Time.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    }
    if ([string]$Time -eq '') { return '' }
    # Strings produced by this tool are already UTC.
    $d = [datetime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse([string]$Time, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d.ToString('yyyy-MM-dd HH:mm:ss') }
    return ''
}

function ConvertTo-WDString {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [byte[]]) {
        $n = [Math]::Min($Value.Length, 64)
        return (($Value[0..($n - 1)] | ForEach-Object { $_.ToString('X2') }) -join '') + $(if ($Value.Length -gt 64) { '...' } else { '' })
    }
    if ($Value -is [array]) { return (($Value | ForEach-Object { [string]$_ }) -join '; ') }
    return [string]$Value
}

function ConvertFrom-WDFileTime {
    param([byte[]]$Bytes, [int]$Offset = 0)
    try {
        $ft = [BitConverter]::ToInt64($Bytes, $Offset)
        if ($ft -le 0) { return $null }
        return [DateTime]::FromFileTimeUtc($ft)
    } catch { return $null }
}

# ----------------------------------------------------------------------------- findings / timeline / artifacts
# Numbers glued to names (ttk_update_4309.bat) and GUIDs differ between otherwise identical events;
# they are masked in the grouping key so repeats collapse into one finding with an occurrence count.
function Get-WDGroupingKey {
    param([string]$Text)
    return (($Text -replace '\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?', '{GUID}') -replace '(?<=[_\-A-Za-z])\d{3,}(?=[._\\'' ]|$)', '#')
}

function Add-Finding {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Title,
        [string]$Detail = '',
        [string]$Evidence = '',
        [string]$Mitre = '',
        $Time = $null,
        [string]$Source = ''
    )
    $Evidence = Limit-WDText $Evidence 2000
    $key = ('{0}|{1}|{2}' -f $Category, $Title, (Get-WDGroupingKey $Evidence)).ToLowerInvariant()
    $ts = ConvertTo-WDTimeString $Time
    if ($script:WD.FindingIndex.ContainsKey($key)) {
        $f = $script:WD.FindingIndex[$key]
        $f.Occurrences++
        if ($ts -and (-not $f.FirstSeen -or $ts -lt $f.FirstSeen)) { $f.FirstSeen = $ts }
        if ($ts -and $ts -gt $f.LastSeen) { $f.LastSeen = $ts }
        if (-not $f.Allowlisted -and $script:WDSeverityOrder[$Severity] -lt $script:WDSeverityOrder[$f.Severity]) { $f.Severity = $Severity }
        return
    }
    $originalSeverity = $Severity
    $allow = $null
    if ($script:WD.Allowlist.Count -gt 0) { $allow = Test-WDAllowlisted "$Title`n$Evidence`n$Detail" }
    if ($allow) {
        $Severity = 'Info'
        $Detail = "ALLOWLISTED (was $originalSeverity) by rule '$($allow.Rule)'$(if ($allow.Reason) { " - $($allow.Reason)" }). $Detail"
    }
    $f = [pscustomobject][ordered]@{
        Id               = ''
        Severity         = $Severity
        Category         = $Category
        Title            = $Title
        Detail           = (Limit-WDText $Detail 1500)
        Evidence         = $Evidence
        Mitre            = $Mitre
        Source           = $Source
        FirstSeen        = $ts
        LastSeen         = $ts
        Occurrences      = 1
        Allowlisted      = [bool]$allow
        OriginalSeverity = $originalSeverity
    }
    $script:WD.FindingIndex[$key] = $f
    $script:WD.Findings.Add($f)
    if ($ts -and $Severity -ne 'Info') {
        Add-WDTimeline -Time $Time -Source "Finding/$Category" -Description $Title -Detail $Evidence -Severity $Severity
    }
}

# ----------------------------------------------------------------------------- allowlist
# iocs\allowlist.txt - one rule per line:  hash:<md5|sha1|sha256> | path:<wildcard> | text:<wildcard>
# optionally followed by " | reason". Matching findings are kept but downgraded to Info.
function Import-WDAllowlist {
    param([string]$Path)
    $script:WD.Allowlist.Clear()
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return 0 }
    foreach ($line in (Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue)) {
        $t = $line.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        $reason = ''
        if ($t -match '^(.*?)\s+\|\s+(.*)$') { $t = $Matches[1].Trim(); $reason = $Matches[2].Trim() }
        if ($t -match '^(?i)(hash|path|text):(.+)$') { $type = $Matches[1].ToLowerInvariant(); $pattern = $Matches[2].Trim() }
        elseif ($t -match '^[0-9A-Fa-f]{32}$|^[0-9A-Fa-f]{40}$|^[0-9A-Fa-f]{64}$') { $type = 'hash'; $pattern = $t }
        else { $type = 'text'; $pattern = $t }
        if ($type -ne 'hash') {
            if (-not $pattern.StartsWith('*')) { $pattern = '*' + $pattern }
            if (-not $pattern.EndsWith('*')) { $pattern = $pattern + '*' }
        }
        $script:WD.Allowlist.Add([pscustomobject]@{ Type = $type; Pattern = $pattern; Reason = $reason; Rule = $t; Hits = 0 })
    }
    return $script:WD.Allowlist.Count
}

function Test-WDAllowlisted {
    param([string]$Text)
    if (-not $Text) { return $null }
    foreach ($a in $script:WD.Allowlist) {
        $hit = $false
        if ($a.Type -eq 'hash') { $hit = $Text.IndexOf($a.Pattern, [StringComparison]::OrdinalIgnoreCase) -ge 0 }
        else { $hit = $Text -like $a.Pattern }
        if ($hit) { $a.Hits++; return $a }
    }
    return $null
}

function Add-WDTimeline {
    param($Time, [string]$Source, [string]$Description, [string]$Detail = '', [string]$Severity = 'Info')
    if ($script:WD.Timeline.Count -ge $script:WD.MaxTimeline) { return }
    $ts = ConvertTo-WDTimeString $Time
    if (-not $ts) { return }
    $script:WD.Timeline.Add([pscustomobject][ordered]@{
        TimeUtc     = $ts
        Severity    = $Severity
        Source      = $Source
        Description = (Limit-WDText $Description 300)
        Detail      = (Limit-WDText $Detail 600)
    })
}

function Save-WDArtifact {
    param([string]$Name, [string]$Section, $Data, [string]$Description = '')
    $rows = @($Data | Where-Object { $null -ne $_ })
    $script:WD.Artifacts[$Name] = [pscustomobject]@{ Name = $Name; Section = $Section; Description = $Description; Count = $rows.Count; Rows = $rows }
    if ($rows.Count -gt 0 -and $script:WD.RawDir) {
        try {
            $rows | Export-Csv -LiteralPath (Join-Path $script:WD.RawDir "$Name.csv") -NoTypeInformation -Encoding UTF8
        } catch { Write-WDLog "Could not export artifact $Name : $($_.Exception.Message)" WARN }
    }
}

function Add-WDObserved {
    param([ValidateSet('Hashes','Ips','Domains')][string]$Type, [string]$Value, [string]$Source)
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    $v = $Value.Trim().TrimEnd('.').ToLowerInvariant()
    $bucket = $script:WD.Observed[$Type]
    if (-not $bucket.ContainsKey($v)) { $bucket[$v] = $Source }
}

# ----------------------------------------------------------------------------- path / file helpers
# True when a path/text refers to this tool's own files (e.g. antivirus flagging the tool itself).
function Test-WDSelfPath {
    param([string]$Text)
    if (-not $Text) { return $false }
    $root = [string]$script:WD.Options.ToolRoot
    if ($root -and $Text.IndexOf($root, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    return ($Text -match '(?i)\\lib\\WD\.[A-Za-z]+\.ps1\b|\\WindowsDetective\.ps1\b|\\Invoke-WDSelfTest\.ps1\b|\\Run-WindowsDetective\.bat\b|\\rules\\detection-data\.json\b|WDCase_')
}

function Get-WDExecutablePath {
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return '' }
    $c = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    $c = $c -replace '^\\\?\?\\', ''
    if ($c -match '^(?i)\\SystemRoot\\') { $c = $env:SystemRoot + $c.Substring(11) }
    if ($c -match '^(?i)system32\\') { $c = Join-Path $env:SystemRoot $c }
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { return $c.Substring(1, $end - 1) }
        return $c.Trim('"')
    }
    $m = [regex]::Match($c, '^(?i)(.+?\.(exe|dll|sys|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|com|scr|cpl|msc|ocx))(?=\s|,|"|$)')
    if ($m.Success) { $p = $m.Groups[1].Value } else { $p = ($c -split '\s+')[0] }
    if ($p -and $p -notmatch '[\\/]' -and $env:SystemRoot) {
        foreach ($dir in @("$env:SystemRoot\System32", "$env:SystemRoot", "$env:SystemRoot\SysWOW64", "$env:SystemRoot\System32\wbem")) {
            $cand = Join-Path $dir $p
            if (Test-Path -LiteralPath $cand -PathType Leaf) { return $cand }
            if ($p -notmatch '\.') {
                $cand = "$cand.exe"
                if (Test-Path -LiteralPath $cand -PathType Leaf) { return $cand }
            }
        }
    }
    return $p
}

function Get-WDPathRisk {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return 'None' }
    if ($Path -match $script:WDHighRiskPathRx) { return 'High' }
    if ($Path -match $script:WDUserPathRx) { return 'User' }
    return 'None'
}

function Get-WDFileInfo {
    param([string]$Path, [switch]$NoSignature)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $p = $Path.Trim().Trim('"')
    if ($script:WD.FileCache.ContainsKey($p)) { return $script:WD.FileCache[$p] }
    $info = [pscustomobject][ordered]@{
        Path = $p; Exists = $false; Size = 0; Created = $null; Modified = $null
        SHA256 = ''; SigStatus = ''; Signer = ''; IsMicrosoft = $false; IsPE = ($p -match $script:WDPeExtRx)
        Company = ''; Description = ''; OriginalName = ''; IsAppAlias = $false
    }
    # Malformed command lines (stray quotes etc.) are not valid paths - record as missing.
    if ($p.IndexOfAny([IO.Path]::GetInvalidPathChars()) -ge 0 -or $p.IndexOfAny([char[]]'*?') -ge 0) {
        $script:WD.FileCache[$p] = $info
        return $info
    }
    try {
        if (Test-Path -LiteralPath $p -PathType Leaf -ErrorAction SilentlyContinue) {
            $fi = Get-Item -LiteralPath $p -Force -ErrorAction Stop
            $info.Exists   = $true
            # Store-app execution aliases (0-byte reparse stubs in ...\AppData\Local\Microsoft\WindowsApps)
            # cannot be read, hashed or signature-checked; the real binary lives in Program Files\WindowsApps.
            if (($fi.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $p -match '(?i)\\AppData\\Local\\Microsoft\\WindowsApps\\') {
                $info.IsAppAlias = $true
                $info.SigStatus = 'AppExecutionAlias'
                $script:WD.FileCache[$p] = $info
                return $info
            }
            $info.Size     = $fi.Length
            $info.Created  = $fi.CreationTimeUtc
            $info.Modified = $fi.LastWriteTimeUtc
            if ($fi.VersionInfo) {
                $info.Company      = [string]$fi.VersionInfo.CompanyName
                $info.Description  = [string]$fi.VersionInfo.FileDescription
                $info.OriginalName = [string]$fi.VersionInfo.OriginalFilename
            }
            if ($fi.Length -le $script:WD.Options.MaxHashBytes) {
                try { $info.SHA256 = (Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }
                if ($info.SHA256) { Add-WDObserved -Type Hashes -Value $info.SHA256 -Source $p }
            }
            if (-not $NoSignature -and ($info.IsPE -or $p -match '(?i)\.(ps1|psm1|msi|vbs|js)$')) {
                try {
                    $sig = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
                    $info.SigStatus = [string]$sig.Status
                    if ($sig.SignerCertificate) { $info.Signer = $sig.SignerCertificate.Subject }
                    $info.IsMicrosoft = ($info.SigStatus -eq 'Valid' -and $info.Signer -match 'O=Microsoft (Corporation|Windows)')
                } catch { $info.SigStatus = 'Error' }
            }
        }
    } catch { }
    $script:WD.FileCache[$p] = $info
    return $info
}

# Judges a binary by where it lives and whether it is properly signed.
function Get-WDBinaryVerdict {
    param($Info)
    if (-not $Info -or -not $Info.Exists -or $Info.IsAppAlias) { return $null }
    $risk = Get-WDPathRisk $Info.Path
    $unsigned = $Info.IsPE -and $Info.SigStatus -ne 'Valid'
    if ($Info.SigStatus -eq 'HashMismatch') { return @{ Severity = 'High'; Reason = 'binary signature is broken (file modified after signing)' } }
    if ($risk -eq 'High' -and $unsigned) { return @{ Severity = 'High'; Reason = 'unsigned binary in high-risk location' } }
    if ($risk -eq 'High' -and $Info.IsPE) { return @{ Severity = 'Medium'; Reason = 'signed binary running from high-risk location' } }
    if ($risk -eq 'High') { return @{ Severity = 'Medium'; Reason = 'script/file in high-risk location' } }
    if ($risk -eq 'User' -and $unsigned) { return @{ Severity = 'High'; Reason = 'unsigned binary in user-writable location' } }
    return $null
}

function Copy-WDLockedFile {
    param([string]$Source, [string]$Destination)
    if (-not (Test-Path -LiteralPath $Source)) { return $false }
    $dir = Split-Path -Parent $Destination
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    try { Copy-Item -LiteralPath $Source -Destination $Destination -Force -ErrorAction Stop; return $true } catch { }
    if ($script:WD.IsAdmin) {
        & esentutl.exe /y $Source /vss /d $Destination /o 2>&1 | Out-Null
        if (Test-Path -LiteralPath $Destination) { return $true }
    }
    return $false
}

# ----------------------------------------------------------------------------- registry helpers
function Get-WDRegValues {
    param([string]$Path)
    $out = New-Object System.Collections.Generic.List[object]
    try { $k = Get-Item -LiteralPath $Path -ErrorAction Stop } catch { return $out }
    foreach ($n in $k.GetValueNames()) {
        $v = $k.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $out.Add([pscustomobject]@{ Key = $Path; Name = $(if ($n) { $n } else { '(Default)' }); Value = (ConvertTo-WDString $v); Raw = $v })
    }
    return $out
}

function Get-WDRegValue {
    param([string]$Path, [string]$Name)
    try {
        $k = Get-Item -LiteralPath $Path -ErrorAction Stop
        return $k.GetValue($Name, $null)
    } catch { return $null }
}

$script:WDRegNative = $false
function Get-WDRegKeyLastWrite {
    param([string]$Path)
    if (-not $script:WDRegNative) {
        try {
            Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class WDRegNative {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int RegQueryInfoKey(Microsoft.Win32.SafeHandles.SafeRegistryHandle hKey, IntPtr lpClass, IntPtr lpcbClass,
        IntPtr lpReserved, IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen, IntPtr lpcbMaxClassLen, IntPtr lpcValues,
        IntPtr lpcbMaxValueNameLen, IntPtr lpcbMaxValueLen, IntPtr lpcbSecurityDescriptor, out long lpftLastWriteTime);
}
'@
            $script:WDRegNative = $true
        } catch { return $null }
    }
    try {
        $k = Get-Item -LiteralPath $Path -ErrorAction Stop
        try { return (Get-WDRegKeyLastWriteFromKey $k) } finally { $k.Dispose() }
    } catch { }
    return $null
}

function Get-WDRegKeyLastWriteFromKey {
    param($Key)
    if (-not $script:WDRegNative) { [void](Get-WDRegKeyLastWrite 'HKLM:\SOFTWARE') }
    if (-not $script:WDRegNative -or -not $Key) { return $null }
    try {
        $k = $Key
        $ft = [long]0
        $rc = [WDRegNative]::RegQueryInfoKey($k.Handle, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero,
            [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$ft)
        if ($rc -eq 0 -and $ft -gt 0) { return [DateTime]::FromFileTimeUtc($ft) }
    } catch { }
    return $null
}

function Get-WDProfiles {
    if ($null -ne $script:WD.Profiles) { return $script:WD.Profiles }
    $list = @()
    try {
        $list = @(Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { -not $_.Special -and $_.LocalPath -and (Test-Path -LiteralPath $_.LocalPath) } | ForEach-Object {
            [pscustomobject]@{ Sid = $_.SID; User = (Split-Path $_.LocalPath -Leaf); Path = $_.LocalPath; Loaded = $_.Loaded; LastUse = $_.LastUseTime }
        })
    } catch { }
    if ($list.Count -eq 0) {
        $list = @(Get-ChildItem "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') } |
            ForEach-Object { [pscustomobject]@{ Sid = ''; User = $_.Name; Path = $_.FullName; Loaded = $false; LastUse = $null } })
    }
    $script:WD.Profiles = $list
    return $list
}

# Returns one registry root per user profile (loaded hives, plus offline hives if -LoadUserHives).
function Get-WDUserHives {
    if ($null -ne $script:WD.UserHives) { return $script:WD.UserHives }
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($p in (Get-WDProfiles)) {
        if (-not $p.Sid) { continue }
        $root = "Registry::HKEY_USERS\$($p.Sid)"
        if (Test-Path -LiteralPath $root) {
            $list.Add([pscustomobject]@{ Sid = $p.Sid; User = $p.User; Root = $root; Profile = $p.Path; Temp = $false })
        } elseif ($script:WD.Options.LoadUserHives -and $script:WD.IsAdmin) {
            $nt = Join-Path $p.Path 'NTUSER.DAT'
            if (Test-Path -LiteralPath $nt) {
                $mount = 'WD_' + ($p.Sid -replace '[^0-9A-Za-z-]', '')
                & reg.exe load "HKU\$mount" $nt 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    Write-WDLog "Mounted offline hive for $($p.User)" INFO
                    $list.Add([pscustomobject]@{ Sid = $p.Sid; User = $p.User; Root = "Registry::HKEY_USERS\$mount"; Profile = $p.Path; Temp = $true })
                }
            }
        }
    }
    $script:WD.UserHives = $list
    return $list
}

function Dismount-WDUserHives {
    if (-not $script:WD -or -not $script:WD.UserHives) { return }
    foreach ($h in @($script:WD.UserHives | Where-Object { $_.Temp })) {
        [gc]::Collect(); [gc]::WaitForPendingFinalizers()
        & reg.exe unload ($h.Root -replace '^Registry::HKEY_USERS', 'HKU') 2>&1 | Out-Null
    }
}

# ----------------------------------------------------------------------------- event log helper
function Get-WDEvents {
    param([string]$LogName, [int[]]$Id, [int]$Max = 0, $Since = $null)
    if ($Max -le 0) { $Max = $script:WD.Options.MaxEvents }
    if ($null -eq $Since) { $Since = $script:WD.Since }
    $filter = @{ LogName = $LogName; StartTime = $Since }
    if ($Id) { $filter.Id = $Id }
    $out = New-Object System.Collections.Generic.List[object]
    try { $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $Max -ErrorAction Stop }
    catch {
        if ($_.Exception.Message -notmatch 'No events were found|could not be found|does not exist|There is not an event log') {
            Write-WDLog "Event query $LogName [$($Id -join ',')]: $($_.Exception.Message)" WARN
        }
        return $out
    }
    foreach ($e in $events) {
        $data = @{}
        try {
            $x = [xml]$e.ToXml()
            $i = 0
            foreach ($d in $x.GetElementsByTagName('Data')) {
                $i++
                $n = $d.GetAttribute('Name')
                if (-not $n) { $n = "Param$i" }
                $data[$n] = $d.InnerText
            }
            foreach ($u in $x.GetElementsByTagName('UserData')) {
                foreach ($c in $u.FirstChild.ChildNodes) { $data[$c.LocalName] = $c.InnerText }
            }
        } catch { }
        $out.Add([pscustomobject]@{
            Time = $e.TimeCreated; Id = $e.Id; Level = $e.Level; Log = $LogName
            RecordId = $e.RecordId; ProcessId = $e.ProcessId; Data = $data
        })
    }
    return $out
}

function Test-WDLogExists {
    param([string]$LogName)
    try { $l = Get-WinEvent -ListLog $LogName -ErrorAction Stop; return ($l.RecordCount -gt 0) } catch { return $false }
}

# ----------------------------------------------------------------------------- network helpers
function Test-WDPublicIp {
    param([string]$Ip)
    if ([string]::IsNullOrWhiteSpace($Ip)) { return $false }
    $s = ($Ip.Trim().Trim('[', ']') -replace '^::ffff:', '') -replace '%.*$', ''
    $addr = $null
    if (-not [System.Net.IPAddress]::TryParse($s, [ref]$addr)) { return $false }
    if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $b = $addr.GetAddressBytes()
        if ($b[0] -eq 10 -or $b[0] -eq 127 -or $b[0] -eq 0) { return $false }
        if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $false }
        if ($b[0] -eq 192 -and $b[1] -eq 168) { return $false }
        if ($b[0] -eq 169 -and $b[1] -eq 254) { return $false }
        if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return $false }
        if ($b[0] -ge 224) { return $false }
        return $true
    }
    $l = $s.ToLowerInvariant()
    if ($l -eq '::' -or $l -eq '::1' -or $l -match '^(fe[89ab]|f[cd]|ff)') { return $false }
    return $true
}
