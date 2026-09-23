# =============================================================================
#  Windows Detective - Live process analysis
#  Powered by Bashar Salmo
#  WD-SELF-MARKER
# =============================================================================

function Invoke-WDProcessCollector {
    $procs = @(Get-CimInstance Win32_Process -ErrorAction Stop)
    $byPid = @{}
    foreach ($p in $procs) { $byPid[[int]$p.ProcessId] = $p }
    $script:WD.ProcessMap = $byPid

    # Our own process tree is excluded from detections (but still inventoried).
    $selfPids = @{ $PID = $true }
    foreach ($p in $procs) { if ($selfPids.ContainsKey([int]$p.ParentProcessId)) { $selfPids[[int]$p.ProcessId] = $true } }

    $rows = New-Object System.Collections.Generic.List[object]
    $lsass = @()
    foreach ($p in $procs) {
        $procId = [int]$p.ProcessId
        $parent = $byPid[[int]$p.ParentProcessId]
        if ($parent -and $parent.CreationDate -and $p.CreationDate -and $parent.CreationDate -gt $p.CreationDate) { $parent = $null } # PID reuse
        $parentName = ''; $parentPath = ''
        if ($parent) { $parentName = $parent.Name; $parentPath = [string]$parent.ExecutablePath }
        elseif ($procId -gt 4) { $parentName = "(exited: $($p.ParentProcessId))" }

        $owner = ''
        if (-not $script:WD.Options.Quick) {
            try {
                $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
                if ($o.User) { $owner = "$($o.Domain)\$($o.User)" }
            } catch { }
        }
        $path = [string]$p.ExecutablePath
        $info = $null
        if ($path) { $info = Get-WDFileInfo $path }
        $row = [pscustomobject][ordered]@{
            PID = $procId; PPID = [int]$p.ParentProcessId; Name = $p.Name; Parent = $parentName; Owner = $owner
            StartedUtc = (ConvertTo-WDTimeString $p.CreationDate); Path = $path; CommandLine = [string]$p.CommandLine
            SHA256 = $(if ($info) { $info.SHA256 } else { '' }); Signature = $(if ($info) { $info.SigStatus } else { '' })
            Signer = $(if ($info) { $info.Signer } else { '' }); Company = $(if ($info) { $info.Company } else { '' })
            PathRisk = (Get-WDPathRisk $path); Session = $p.SessionId
        }
        $rows.Add($row)
        if ($p.Name -eq 'lsass.exe') { $lsass += $p }
        if ($selfPids.ContainsKey($procId)) { continue }

        $src = "Process $($p.Name) (PID $procId)"
        $ev = "PID $procId | $path | $($p.CommandLine) | parent: $parentName ($($p.ParentProcessId)) | user: $owner"
        $start = $p.CreationDate

        if ($path) {
            $masq = Test-WDMasquerade $path
            if ($masq) { Add-Finding -Severity Critical -Category 'Process' -Title "Masquerading process: $masq" -Evidence $ev -Mitre 'T1036.005' -Time $start -Source $src }
            if ($info -and -not $info.Exists) {
                Add-Finding -Severity High -Category 'Process' -Title 'Running process whose executable no longer exists on disk' -Detail 'Malware often deletes its image after start.' -Evidence $ev -Mitre 'T1070.004' -Time $start -Source $src
            }
            $v = Get-WDBinaryVerdict $info
            if ($v) { Add-Finding -Severity $v.Severity -Category 'Process' -Title "Running process: $($v.Reason)" -Evidence "$ev | signer: $($row.Signer) | sha256: $($row.SHA256)" -Mitre 'T1036,T1204.002' -Time $start -Source $src }
            if ($info -and $info.OriginalName -and $info.OriginalName -match '\.exe$' -and $info.OriginalName.ToLowerInvariant() -ne $p.Name.ToLowerInvariant() -and
                $info.OriginalName -match '^(?i)(powershell|cmd|psexec|procdump|rundll32|mimikatz|nc|rclone|certutil|anydesk|plink|7z)\.exe$') {
                Add-Finding -Severity High -Category 'Process' -Title 'Renamed well-known binary' -Detail "PE OriginalFilename is '$($info.OriginalName)'." -Evidence $ev -Mitre 'T1036.003' -Time $start -Source $src
            }
        }
        $tool = Get-WDToolMatch $p.Name
        if ($tool) { Add-Finding -Severity $tool.Severity -Category 'Process' -Title "Running: $($tool.Label)" -Evidence $ev -Mitre $tool.Mitre -Time $start -Source $src }

        # Relationship anomalies
        $pn = $p.Name.ToLowerInvariant()
        if ($pn -eq 'svchost.exe' -and $parent -and $parent.Name -ne 'services.exe' -and $parent.Name -ne 'svchost.exe' -and $parent.Name -ne 'MsMpEng.exe') {
            Add-Finding -Severity High -Category 'Process' -Title 'svchost.exe with unexpected parent' -Detail 'Genuine svchost.exe is started by services.exe.' -Evidence $ev -Mitre 'T1036.005' -Time $start -Source $src
        }
        if ($pn -eq 'lsass.exe' -and $parent -and $parent.Name -ne 'wininit.exe') {
            Add-Finding -Severity Critical -Category 'Process' -Title 'lsass.exe with unexpected parent' -Evidence $ev -Mitre 'T1036.005' -Time $start -Source $src
        }
        if ($pn -match '^(wscript|cscript|mshta)\.exe$') {
            Add-Finding -Severity Medium -Category 'Process' -Title "Script host $pn is running" -Detail 'Rarely legitimate on end-user machines; review the script it executes.' -Evidence $ev -Mitre 'T1059.005,T1059.007' -Time $start -Source $src
        }
        if ($parentPath) { Test-WDParentChild -ParentPath $parentPath -ChildPath $path -CommandLine $p.CommandLine -Source $src -Time $start }
        [void](Invoke-WDCommandCheck -Text $p.CommandLine -Source $src -Time $start -Category 'Process')

        if ($info -and -not $info.IsMicrosoft -and $p.CreationDate -and $p.CreationDate -ge $script:WD.Since) {
            Add-WDTimeline -Time $p.CreationDate -Source 'Process' -Description "Running process started: $($p.Name) (PID $procId)" -Detail "$path $($p.CommandLine)"
        }
    }
    if ($lsass.Count -gt 1) {
        Add-Finding -Severity Critical -Category 'Process' -Title 'Multiple lsass.exe processes' -Evidence (($lsass | ForEach-Object { "PID $($_.ProcessId) $($_.ExecutablePath)" }) -join ' | ') -Mitre 'T1036.005'
    }
    Save-WDArtifact -Name 'Processes' -Section 'Processes' -Data $rows -Description 'Running processes with hashes, signatures and command lines'

    # Process tree (text) for quick human review
    $tree = New-Object System.Text.StringBuilder
    $children = @{}
    foreach ($p in $procs) {
        $pp = [int]$p.ParentProcessId
        if (-not $children.ContainsKey($pp)) { $children[$pp] = New-Object System.Collections.Generic.List[object] }
        $children[$pp].Add($p)
    }
    $visited = @{}
    $walk = {
        param($node, $depth)
        if ($visited.ContainsKey([int]$node.ProcessId) -or $depth -gt 40) { return }
        $visited[[int]$node.ProcessId] = $true
        [void]$tree.AppendLine(('{0}{1} [{2}] {3}' -f ('  ' * $depth), $node.Name, $node.ProcessId, (Limit-WDText ([string]$node.CommandLine) 220)))
        if ($children.ContainsKey([int]$node.ProcessId)) { foreach ($c in $children[[int]$node.ProcessId]) { & $walk $c ($depth + 1) } }
    }
    foreach ($p in ($procs | Sort-Object ProcessId)) {
        if (-not $byPid.ContainsKey([int]$p.ParentProcessId) -or [int]$p.ParentProcessId -eq [int]$p.ProcessId) { & $walk $p 0 }
    }
    try { [IO.File]::WriteAllText((Join-Path $script:WD.RawDir 'ProcessTree.txt'), $tree.ToString()) } catch { }

    # Services running inside each svchost etc.
    try {
        $svc = @(Get-CimInstance Win32_Service -Filter "State='Running'" -ErrorAction Stop | Select-Object ProcessId, Name, DisplayName)
        Save-WDArtifact -Name 'ProcessServices' -Section 'Processes' -Data $svc -Description 'Running services and their host process'
    } catch { }

    if ($script:WD.Options.Deep) { Invoke-WDModuleScan }
}

# Deep mode: unsigned DLLs loaded from user-writable paths (DLL side-loading / injection).
function Invoke-WDModuleScan {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($proc in @(Get-Process -ErrorAction SilentlyContinue)) {
        if ($proc.Id -eq $PID) { continue }
        $mods = $null
        try { $mods = $proc.Modules } catch { continue }
        foreach ($m in $mods) {
            $f = [string]$m.FileName
            if (-not $f -or $f -match '(?i)\.exe$') { continue }
            if ((Get-WDPathRisk $f) -eq 'None') { continue }
            $info = Get-WDFileInfo $f
            $rows.Add([pscustomobject][ordered]@{ Process = $proc.ProcessName; PID = $proc.Id; Module = $f; SHA256 = $info.SHA256; Signature = $info.SigStatus; Signer = $info.Signer })
            if ($info.SigStatus -ne 'Valid') {
                Add-Finding -Severity High -Category 'Process' -Title 'Unsigned DLL from user-writable path loaded into a process' -Detail 'Possible DLL side-loading or injection.' -Evidence "$($proc.ProcessName) (PID $($proc.Id)) <- $f | sha256 $($info.SHA256)" -Mitre 'T1574.002,T1055'
            }
        }
    }
    Save-WDArtifact -Name 'UserPathModules' -Section 'Processes' -Data $rows -Description 'DLLs loaded from user-writable locations (Deep mode)'
}
