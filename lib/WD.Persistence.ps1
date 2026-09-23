# =============================================================================
#  Windows Detective - Persistence / autostart analysis
#  Powered by Bashar Salmo
#  WD-SELF-MARKER
#
#  Covers: Run keys, Startup folders, services, scheduled tasks (incl. hidden
#  Tarrask-style tasks), WMI subscriptions, IFEO / SilentProcessExit, Winlogon,
#  AppInit / AppCert DLLs, LSA packages, accessibility backdoors, netsh helpers,
#  print monitors, time providers, COM hijacks, Office test key, screensaver,
#  PowerShell profiles, Active Setup, BootExecute and BITS jobs.
# =============================================================================

$script:WDInterpreterRx = '(?i)\\(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|msiexec|certutil|bitsadmin|curl|conhost|forfiles)\.exe$|^(?i)(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)(\.exe)?$'

function Add-WDAutorun {
    param(
        [string]$Category, [string]$Location, [string]$Name, [string]$Command, [string]$User = '',
        [string]$Mitre = 'T1547.001', $KeyTime = $null, [string]$InterpreterSeverity = 'Medium', [switch]$TrustMicrosoftInterpreters
    )
    $path = Get-WDExecutablePath $Command
    $info = $null
    if ($path) { $info = Get-WDFileInfo $path }
    $row = [pscustomobject][ordered]@{
        Category = $Category; Location = $Location; Name = $Name; User = $User; Command = $Command; ImagePath = $path
        Exists = $(if ($info) { $info.Exists } else { $false }); SHA256 = $(if ($info) { $info.SHA256 } else { '' })
        Signature = $(if ($info) { $info.SigStatus } else { '' }); Signer = $(if ($info) { $info.Signer } else { '' })
        LastWriteUtc = (ConvertTo-WDTimeString $KeyTime)
    }
    $script:WD.Autoruns.Add($row)
    if (Test-WDSelfText $Command) { return }

    $src = "$Category | $Location | $Name"
    $ev = "[$Category] $Location -> $Name = $Command"
    # Microsoft-owned entries (tasks under \Microsoft\, Active Setup) legitimately use rundll32 & co.
    $skipRules = $TrustMicrosoftInterpreters -and $Command -notmatch '(?i)(\\users\\|\\programdata\\|\\temp\\|https?:|^\\\\)'
    if (-not $skipRules) { [void](Invoke-WDCommandCheck -Text $Command -Source $src -Time $KeyTime -Category 'Persistence') }

    $v = Get-WDBinaryVerdict $info
    if ($v) { Add-Finding -Severity $v.Severity -Category 'Persistence' -Title "$Category launches $($v.Reason)" -Evidence "$ev | sha256 $($row.SHA256) | signer $($row.Signer)" -Mitre $Mitre -Time $KeyTime -Source $src }

    if ($path -match $script:WDInterpreterRx -and -not $TrustMicrosoftInterpreters) {
        Add-Finding -Severity $InterpreterSeverity -Category 'Persistence' -Title "$Category launches a script interpreter / LOLBin" -Detail 'Autostarts that run cmd/PowerShell/mshta/rundll32 are a classic persistence pattern.' -Evidence $ev -Mitre $Mitre -Time $KeyTime -Source $src
    }
    # rundll32/regsvr32: evaluate the DLL they load
    if ($Command -match '(?i)(rundll32|regsvr32)(\.exe)?["'']?\s+(/s\s+)?["'']?([^,"'']+\.(dll|ocx|cpl|dat|tmp|bin|png|jpg|txt|log))') {
        $dll = [Environment]::ExpandEnvironmentVariables($Matches[4].Trim())
        $dInfo = Get-WDFileInfo $dll
        $dv = Get-WDBinaryVerdict $dInfo
        if ($dv) { Add-Finding -Severity $dv.Severity -Category 'Persistence' -Title "$Category loads DLL: $($dv.Reason)" -Evidence "$ev | DLL $dll sha256 $($dInfo.SHA256)" -Mitre "$Mitre,T1218.011" -Time $KeyTime -Source $src }
        if ($dll -notmatch '(?i)\.(dll|ocx|cpl)$') {
            Add-Finding -Severity High -Category 'Persistence' -Title "$Category loads a DLL disguised with a non-DLL extension" -Evidence $ev -Mitre 'T1218.011,T1036' -Time $KeyTime -Source $src
        }
    }
    $tool = Get-WDToolMatch $path
    if ($tool) {
        Add-Finding -Severity $tool.Severity -Category 'Persistence' -Title "$Category starts $($tool.Label)" -Evidence $ev -Mitre "$($tool.Mitre),$Mitre" -Time $KeyTime -Source $src
    }
    if ($path -and $info -and -not $info.Exists -and $path -match '^[A-Za-z]:\\') {
        Add-Finding -Severity Low -Category 'Persistence' -Title "$Category references a missing file" -Detail 'Leftover of removed software - or of cleaned-up malware.' -Evidence $ev -Mitre $Mitre -Time $KeyTime -Source $src
    }
    if ($KeyTime -and $KeyTime -is [datetime] -and $KeyTime -ge $script:WD.Since.ToUniversalTime() -and $Category -ne 'Service') {
        Add-WDTimeline -Time $KeyTime -Source 'Persistence' -Description "$Category location last modified: $Location" -Detail "$Name = $Command"
    }
}

function Invoke-WDPersistenceCollector {
    Invoke-WDRunKeys
    Invoke-WDStartupFolders
    Invoke-WDServices
    Invoke-WDScheduledTasks
    Invoke-WDWmiPersistence
    Invoke-WDRegistryHijacks
    Invoke-WDUserPersistence
    Invoke-WDBitsJobs
    Save-WDArtifact -Name 'Autoruns' -Section 'Persistence' -Data $script:WD.Autoruns -Description 'All autostart entries (registry, startup, services, tasks, WMI, ...)'
}

function Invoke-WDRunKeys {
    $keys = @(
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx', 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
        'SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
    )
    $roots = @([pscustomobject]@{ Root = 'HKLM:'; User = 'SYSTEM (HKLM)' })
    foreach ($h in (Get-WDUserHives)) { $roots += [pscustomobject]@{ Root = $h.Root; User = $h.User } }
    foreach ($r in $roots) {
        foreach ($k in $keys) {
            $full = "$($r.Root)\$k"
            if (-not (Test-Path -LiteralPath $full)) { continue }
            $lw = Get-WDRegKeyLastWrite $full
            foreach ($v in (Get-WDRegValues $full)) {
                if (-not $v.Value) { continue }
                Add-WDAutorun -Category 'Run key' -Location $full.Replace('Registry::', '') -Name $v.Name -Command $v.Value -User $r.User -KeyTime $lw -InterpreterSeverity 'High'
            }
            # RunOnceEx uses subkeys
            if ($k -like '*RunOnceEx') {
                foreach ($sub in @(Get-ChildItem -LiteralPath $full -ErrorAction SilentlyContinue)) {
                    foreach ($v in (Get-WDRegValues $sub.PSPath)) { if ($v.Value) { Add-WDAutorun -Category 'RunOnceEx' -Location $sub.Name -Name $v.Name -Command $v.Value -User $r.User -KeyTime $lw -InterpreterSeverity 'High' } }
                }
            }
        }
    }
}

function Get-WDShortcutTarget {
    param([string]$Path)
    try {
        if (-not $script:WDShell) { $script:WDShell = New-Object -ComObject WScript.Shell }
        $s = $script:WDShell.CreateShortcut($Path)
        return (('"{0}" {1}' -f $s.TargetPath, $s.Arguments).Trim())
    } catch { return '' }
}

function Invoke-WDStartupFolders {
    $folders = @([pscustomobject]@{ Path = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"; User = 'All users' })
    foreach ($p in (Get-WDProfiles)) { $folders += [pscustomobject]@{ Path = (Join-Path $p.Path 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'); User = $p.User } }
    foreach ($f in $folders) {
        foreach ($item in @(Get-ChildItem -LiteralPath $f.Path -Force -File -ErrorAction SilentlyContinue)) {
            if ($item.Name -eq 'desktop.ini') { continue }
            $cmd = $item.FullName
            if ($item.Extension -eq '.lnk') { $t = Get-WDShortcutTarget $item.FullName; if ($t -and $t -ne '""') { $cmd = $t } }
            Add-WDAutorun -Category 'Startup folder' -Location $f.Path -Name $item.Name -Command $cmd -User $f.User -KeyTime $item.LastWriteTimeUtc -InterpreterSeverity 'High'
            if ($item.Extension -match '(?i)^\.(vbs|vbe|js|jse|wsf|hta|bat|cmd|ps1|exe|scr|dll)$') {
                Add-Finding -Severity Medium -Category 'Persistence' -Title "Script or executable placed directly in Startup folder ($($item.Extension))" -Evidence "$($item.FullName) (created $(ConvertTo-WDTimeString $item.CreationTime) UTC)" -Mitre 'T1547.001' -Time $item.CreationTime
            }
        }
    }
}

function Invoke-WDServices {
    $services = @(Get-CimInstance Win32_Service -ErrorAction Stop)
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($s in $services) {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)"
        $dll = Get-WDRegValue "$key\Parameters" 'ServiceDll'
        if (-not $dll) { $dll = Get-WDRegValue $key 'ServiceDll' }
        $fail = Get-WDRegValue $key 'FailureCommand'
        $rows.Add([pscustomobject][ordered]@{ Name = $s.Name; DisplayName = $s.DisplayName; State = $s.State; StartMode = $s.StartMode; Account = $s.StartName; PathName = $s.PathName; ServiceDll = $dll; FailureCommand = $fail; PID = $s.ProcessId })
        if (-not $s.PathName) { continue }
        $trustSvc = ($s.Name -eq 'msiserver' -and $s.PathName -match '(?i)^[a-z]:\\windows\\system32\\msiexec\.exe /V$')
        Add-WDAutorun -Category 'Service' -Location "Service $($s.Name)" -Name $s.DisplayName -Command $s.PathName -User $s.StartName -Mitre 'T1543.003' -InterpreterSeverity 'High' -TrustMicrosoftInterpreters:$trustSvc
        if ($s.PathName -match '(?i)%comspec%|cmd(\.exe)?\s+/c|powershell|mshta|\\\\127\.0\.0\.1\\|\\\\localhost\\') {
            Add-Finding -Severity High -Category 'Persistence' -Title 'Service executes a command shell (PsExec / Impacket / C2-framework style)' -Evidence "$($s.Name): $($s.PathName)" -Mitre 'T1543.003,T1569.002'
        }
        if ($dll) {
            $d = [Environment]::ExpandEnvironmentVariables($dll)
            if ($d -notmatch '(?i)^[a-z]:\\windows\\(system32|syswow64)\\') {
                $info = Get-WDFileInfo $d
                $sev = 'Medium'; if (-not $info.IsMicrosoft) { $sev = 'High' }
                Add-Finding -Severity $sev -Category 'Persistence' -Title 'svchost ServiceDll outside System32' -Evidence "$($s.Name): $d | signer $($info.Signer) | sha256 $($info.SHA256)" -Mitre 'T1543.003'
            } else {
                $info = Get-WDFileInfo $d
                if ($info.Exists -and $info.SigStatus -ne 'Valid') { Add-Finding -Severity High -Category 'Persistence' -Title 'Unsigned ServiceDll in System32' -Evidence "$($s.Name): $d ($($info.SigStatus))" -Mitre 'T1543.003' }
            }
        }
        if ($fail) {
            Add-Finding -Severity Medium -Category 'Persistence' -Title 'Service recovery (FailureCommand) configured to run a program' -Evidence "$($s.Name): $fail" -Mitre 'T1543.003'
            [void](Invoke-WDCommandCheck -Text $fail -Source "Service $($s.Name) FailureCommand" -Category 'Persistence')
        }
        if ($s.PathName -notmatch '^\s*"' -and $s.PathName -match '^(?i)[a-z]:\\[^"]*\s[^"]*\.exe' -and $s.StartMode -eq 'Auto') {
            $exe = ($s.PathName -split '(?i)\.exe')[0]
            if ($exe -match '\s') { Add-Finding -Severity Low -Category 'Posture' -Title 'Unquoted service path with spaces (privilege-escalation vector)' -Evidence "$($s.Name): $($s.PathName)" -Mitre 'T1574.009' }
        }
    }
    Save-WDArtifact -Name 'Services' -Section 'Persistence' -Data $rows -Description 'All Win32 services'
}

function Invoke-WDScheduledTasks {
    $rows = New-Object System.Collections.Generic.List[object]
    $registered = @{}
    $tasks = @()
    try { $tasks = @(Get-ScheduledTask -ErrorAction Stop) } catch { Write-WDLog "Get-ScheduledTask failed: $($_.Exception.Message)" WARN }
    foreach ($t in $tasks) {
        $full = ($t.TaskPath + $t.TaskName)
        $registered[$full.ToLowerInvariant()] = $true
        $isMs = $t.TaskPath -like '\Microsoft\*'
        $regDate = $null
        if ($t.Date) { $d = [datetime]::MinValue; if ([datetime]::TryParse($t.Date, [ref]$d)) { $regDate = $d } }
        $triggers = (@($t.Triggers) | ForEach-Object { ($_.CimClass.CimClassName -replace 'MSFT_Task|Trigger', '') }) -join ','
        foreach ($a in @($t.Actions)) {
            $cmd = ''
            if ($a.CimClass.CimClassName -eq 'MSFT_TaskExecAction') { $cmd = ('"{0}" {1}' -f $a.Execute, $a.Arguments).Trim() }
            elseif ($a.ClassId) { $cmd = "COM handler $($a.ClassId) $($a.Data)" }
            $rows.Add([pscustomobject][ordered]@{
                Task = $full; State = [string]$t.State; Author = $t.Author; RunAs = $t.Principal.UserId; RunLevel = [string]$t.Principal.RunLevel
                Hidden = $t.Settings.Hidden; Registered = (ConvertTo-WDTimeString $regDate); Triggers = $triggers; Action = $cmd
            })
            if ($a.CimClass.CimClassName -ne 'MSFT_TaskExecAction') { continue }
            $exePath = Get-WDExecutablePath $a.Execute
            $trustMs = $isMs -and ($exePath -match '(?i)^[a-z]:\\windows\\' -or $exePath -notmatch '\\' -or (Get-WDFileInfo $exePath).IsMicrosoft)
            Add-WDAutorun -Category 'Scheduled task' -Location $full -Name $t.TaskName -Command $cmd -User $t.Principal.UserId -Mitre 'T1053.005' -KeyTime $regDate -InterpreterSeverity 'Medium' -TrustMicrosoftInterpreters:$trustMs
            if ($regDate -and $regDate -ge $script:WD.Since) {
                $sev = 'Low'; if (-not $isMs) { $sev = 'Medium' }
                Add-Finding -Severity $sev -Category 'Persistence' -Title 'Scheduled task registered during the investigation window' -Evidence "$full -> $cmd (author: $($t.Author), runs as $($t.Principal.UserId))" -Mitre 'T1053.005' -Time $regDate
            }
            if ($t.Settings.Hidden -and -not $isMs) {
                Add-Finding -Severity Medium -Category 'Persistence' -Title 'Hidden non-Microsoft scheduled task' -Evidence "$full -> $cmd" -Mitre 'T1053.005,T1564'
            }
            if ($isMs -and -not $trustMs) {
                Add-Finding -Severity High -Category 'Persistence' -Title 'Task under \Microsoft\ folder runs a binary outside C:\Windows (blending in)' -Evidence "$full -> $cmd" -Mitre 'T1053.005,T1036.004'
            }
        }
    }
    Save-WDArtifact -Name 'ScheduledTasks' -Section 'Persistence' -Data $rows -Description 'Scheduled tasks and their actions'

    # Tarrask-style hidden tasks: task in TaskCache without Security Descriptor, or task file without registration
    $tree = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree'
    foreach ($k in @(Get-ChildItem -LiteralPath $tree -Recurse -ErrorAction SilentlyContinue)) {
        $names = $k.GetValueNames()
        if ($names -contains 'Id' -and $names -notcontains 'SD') {
            Add-Finding -Severity High -Category 'Persistence' -Title 'Scheduled task with deleted security descriptor (hidden from schtasks - Tarrask technique)' -Evidence ($k.Name -replace '^.*\\Tree', '') -Mitre 'T1053.005,T1564'
        }
    }
    if ($script:WD.IsAdmin -and $tasks.Count -gt 0) {
        $taskDir = Join-Path $env:SystemRoot 'System32\Tasks'
        foreach ($f in @(Get-ChildItem -LiteralPath $taskDir -Recurse -File -Force -ErrorAction SilentlyContinue)) {
            $rel = $f.FullName.Substring($taskDir.Length).ToLowerInvariant()
            if (-not $registered.ContainsKey($rel)) {
                $content = ''
                try { $content = (Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop) } catch { }
                $cmd = ''
                if ($content -match '(?s)<Command>(.*?)</Command>') { $cmd = $Matches[1] }
                if ($content -match '(?s)<Arguments>(.*?)</Arguments>') { $cmd += ' ' + $Matches[1] }
                Add-Finding -Severity High -Category 'Persistence' -Title 'Task file on disk that is not visible to the Task Scheduler API (hidden task)' -Evidence "$($f.FullName) -> $cmd" -Mitre 'T1053.005,T1564' -Time $f.LastWriteTime
                [void](Invoke-WDCommandCheck -Text $cmd -Source "Hidden task $rel" -Category 'Persistence')
            }
        }
    }
}

function Invoke-WDWmiPersistence {
    $ns = 'root\subscription'
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($f in @(Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction Stop)) {
            $rows.Add([pscustomobject][ordered]@{ Type = 'Filter'; Name = $f.Name; Detail = $f.Query })
        }
        foreach ($c in @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer -ErrorAction Stop)) {
            $cls = $c.CimClass.CimClassName
            $detail = switch ($cls) {
                'CommandLineEventConsumer' { "$($c.ExecutablePath) $($c.CommandLineTemplate)" }
                'ActiveScriptEventConsumer' { "[$($c.ScriptingEngine)] $($c.ScriptFileName) $($c.ScriptText)" }
                default { $cls }
            }
            $rows.Add([pscustomobject][ordered]@{ Type = $cls; Name = $c.Name; Detail = $detail })
            if ($c.Name -in @('SCM Event Log Consumer', 'BVTConsumer') -and $cls -eq 'NTEventLogEventConsumer') { continue }
            if ($cls -in @('CommandLineEventConsumer', 'ActiveScriptEventConsumer')) {
                Add-Finding -Severity High -Category 'Persistence' -Title "WMI permanent event subscription ($cls)" -Detail 'Fileless persistence that survives reboots; rarely legitimate.' -Evidence "$($c.Name): $detail" -Mitre 'T1546.003'
                [void](Invoke-WDCommandCheck -Text $detail -Source "WMI consumer $($c.Name)" -Category 'Persistence')
                $script:WD.Autoruns.Add([pscustomobject][ordered]@{ Category = 'WMI consumer'; Location = $ns; Name = $c.Name; User = ''; Command = $detail; ImagePath = ''; Exists = ''; SHA256 = ''; Signature = ''; Signer = ''; LastWriteUtc = '' })
            } else {
                Add-Finding -Severity Low -Category 'Persistence' -Title "Non-default WMI event consumer ($cls)" -Evidence "$($c.Name): $detail" -Mitre 'T1546.003'
            }
        }
        foreach ($b in @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction Stop)) {
            $rows.Add([pscustomobject][ordered]@{ Type = 'Binding'; Name = [string]$b.Filter.Name; Detail = "$($b.Filter) -> $($b.Consumer)" })
        }
    } catch { Write-WDLog "WMI subscription query failed: $($_.Exception.Message)" WARN }
    Save-WDArtifact -Name 'WmiSubscriptions' -Section 'Persistence' -Data $rows -Description 'WMI event filters, consumers and bindings'
}

function Invoke-WDRegistryHijacks {
    # Winlogon
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $lw = Get-WDRegKeyLastWrite $wl
    $shell = [string](Get-WDRegValue $wl 'Shell')
    $userinit = [string](Get-WDRegValue $wl 'Userinit')
    if ($shell -and $shell.Trim().ToLowerInvariant() -notin @('explorer.exe', 'explorer.exe,')) {
        Add-Finding -Severity High -Category 'Persistence' -Title 'Winlogon Shell value modified' -Evidence "Shell = $shell" -Mitre 'T1547.004' -Time $lw
        Add-WDAutorun -Category 'Winlogon Shell' -Location $wl -Name 'Shell' -Command $shell -Mitre 'T1547.004' -KeyTime $lw
    }
    $ui = $userinit.Trim().TrimEnd(',').ToLowerInvariant()
    if ($userinit -and $ui -notin @('c:\windows\system32\userinit.exe', 'userinit.exe', "$($env:SystemRoot.ToLowerInvariant())\system32\userinit.exe")) {
        Add-Finding -Severity High -Category 'Persistence' -Title 'Winlogon Userinit value modified' -Evidence "Userinit = $userinit" -Mitre 'T1547.004' -Time $lw
        foreach ($part in ($userinit -split ',' | Where-Object { $_.Trim() })) { Add-WDAutorun -Category 'Winlogon Userinit' -Location $wl -Name 'Userinit' -Command $part.Trim() -Mitre 'T1547.004' -KeyTime $lw }
    }
    foreach ($n in @(Get-ChildItem -LiteralPath "$wl\Notify" -ErrorAction SilentlyContinue)) {
        $dll = Get-WDRegValue $n.PSPath 'DLLName'
        if ($dll) { Add-WDAutorun -Category 'Winlogon Notify' -Location $n.Name -Name $n.PSChildName -Command $dll -Mitre 'T1547.004' }
    }

    # AppInit_DLLs / AppCertDlls
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
        $ai = [string](Get-WDRegValue $k 'AppInit_DLLs')
        if ($ai.Trim()) {
            $load = Get-WDRegValue $k 'LoadAppInit_DLLs'
            $sev = 'Medium'; if ($load -eq 1) { $sev = 'High' }
            Add-Finding -Severity $sev -Category 'Persistence' -Title 'AppInit_DLLs configured (DLL injected into every GUI process)' -Evidence "$k AppInit_DLLs=$ai LoadAppInit_DLLs=$load" -Mitre 'T1546.010'
            foreach ($d in ($ai -split '[,\s]+' | Where-Object { $_ })) { Add-WDAutorun -Category 'AppInit_DLLs' -Location $k -Name 'AppInit_DLLs' -Command $d -Mitre 'T1546.010' }
        }
    }
    foreach ($v in (Get-WDRegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls')) {
        Add-Finding -Severity High -Category 'Persistence' -Title 'AppCertDlls entry (DLL loaded into processes calling CreateProcess)' -Evidence "$($v.Name) = $($v.Value)" -Mitre 'T1546.009'
        Add-WDAutorun -Category 'AppCertDlls' -Location 'Session Manager\AppCertDlls' -Name $v.Name -Command $v.Value -Mitre 'T1546.009'
    }

    # IFEO debuggers / GlobalFlag + SilentProcessExit
    $accessibility = @('sethc.exe', 'utilman.exe', 'osk.exe', 'magnify.exe', 'narrator.exe', 'displayswitch.exe', 'atbroker.exe')
    foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
        foreach ($k in @(Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue)) {
            $dbg = Get-WDRegValue $k.PSPath 'Debugger'
            $gf = Get-WDRegValue $k.PSPath 'GlobalFlag'
            $exe = $k.PSChildName.ToLowerInvariant()
            if ($dbg) {
                $sev = 'High'; if ($accessibility -contains $exe) { $sev = 'Critical' }
                if ($dbg -match '(?i)vsjitdebugger|windbg|procexp|taskmgr\.exe|systeminformer') { $sev = 'Low' }
                Add-Finding -Severity $sev -Category 'Persistence' -Title "Image File Execution Options debugger set for $exe" -Detail 'Launching the program runs the debugger instead - classic hijack / sticky-keys backdoor.' -Evidence "$exe Debugger = $dbg" -Mitre 'T1546.012,T1546.008' -Time (Get-WDRegKeyLastWrite $k.PSPath)
                Add-WDAutorun -Category 'IFEO Debugger' -Location $k.Name -Name $exe -Command $dbg -Mitre 'T1546.012'
            }
            if ($gf -and ([int]$gf -band 0x200)) {
                $mon = Get-WDRegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\$($k.PSChildName)" 'MonitorProcess'
                if ($mon) {
                    Add-Finding -Severity High -Category 'Persistence' -Title "SilentProcessExit monitor set for $exe" -Evidence "$exe MonitorProcess = $mon" -Mitre 'T1546.012'
                    Add-WDAutorun -Category 'SilentProcessExit' -Location $k.Name -Name $exe -Command $mon -Mitre 'T1546.012'
                }
            }
        }
    }

    # Accessibility binaries replaced (sticky keys)
    $cmdHash = (Get-WDFileInfo "$env:SystemRoot\System32\cmd.exe").SHA256
    $psHash = (Get-WDFileInfo "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe").SHA256
    $exHash = (Get-WDFileInfo "$env:SystemRoot\explorer.exe").SHA256
    foreach ($a in $accessibility) {
        $info = Get-WDFileInfo "$env:SystemRoot\System32\$a"
        if (-not $info.Exists) { continue }
        if ($info.SHA256 -and $info.SHA256 -in @($cmdHash, $psHash, $exHash)) {
            Add-Finding -Severity Critical -Category 'Persistence' -Title "Accessibility binary $a replaced by a shell (sticky-keys backdoor)" -Evidence "$($info.Path) sha256 $($info.SHA256)" -Mitre 'T1546.008'
        } elseif ($info.SigStatus -and $info.SigStatus -ne 'Valid') {
            Add-Finding -Severity Critical -Category 'Persistence' -Title "Accessibility binary $a is not validly signed" -Evidence "$($info.Path) signature=$($info.SigStatus) sha256 $($info.SHA256)" -Mitre 'T1546.008'
        }
    }

    # LSA packages / password filters
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $known = @('', '""', 'msv1_0', 'kerberos', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'negoexts', 'livessp', 'scecli', 'rassfm', 'msoidssp', 'wsauth', 'kdcsvc')
    foreach ($pair in @(@('Security Packages', 'T1547.005'), @('Authentication Packages', 'T1547.002'), @('Notification Packages', 'T1556.002'))) {
        foreach ($item in @(Get-WDRegValue $lsa $pair[0])) {
            foreach ($pkg in ([string]$item -split '[\s,]+')) {
                if ($known -notcontains $pkg.ToLowerInvariant().Trim('"')) {
                    Add-Finding -Severity High -Category 'Persistence' -Title "Unknown LSA $($pair[0]) entry" -Detail 'DLLs here run inside LSASS and can harvest plaintext credentials.' -Evidence "$($pair[0]): $pkg" -Mitre $pair[1]
                    Add-WDAutorun -Category "LSA $($pair[0])" -Location $lsa -Name $pkg -Command "$env:SystemRoot\System32\$pkg.dll" -Mitre $pair[1]
                }
            }
        }
    }
    foreach ($item in @(Get-WDRegValue "$lsa\OSConfig" 'Security Packages')) {
        foreach ($pkg in ([string]$item -split '[\s,]+')) {
            if ($pkg -and $known -notcontains $pkg.ToLowerInvariant()) { Add-Finding -Severity High -Category 'Persistence' -Title 'Unknown LSA OSConfig Security Package' -Evidence $pkg -Mitre 'T1547.005' }
        }
    }

    # BootExecute
    $be = @(Get-WDRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'BootExecute')
    foreach ($b in $be) { if ($b -and $b -notmatch '^(?i)autocheck autochk \*$') { Add-Finding -Severity Medium -Category 'Persistence' -Title 'Non-default BootExecute entry' -Evidence $b -Mitre 'T1547.001' } }

    # Netsh helpers, print monitors, time providers
    foreach ($v in (Get-WDRegValues 'HKLM:\SOFTWARE\Microsoft\NetSh')) {
        $p = $v.Value; if ($p -notmatch '\\') { $p = "$env:SystemRoot\System32\$p" }
        $info = Get-WDFileInfo $p
        if (-not $info.IsMicrosoft) {
            Add-Finding -Severity High -Category 'Persistence' -Title 'Non-Microsoft netsh helper DLL' -Evidence "$($v.Name) = $($v.Value) ($($info.SigStatus) $($info.Signer))" -Mitre 'T1546.007'
            Add-WDAutorun -Category 'Netsh helper' -Location 'HKLM\SOFTWARE\Microsoft\NetSh' -Name $v.Name -Command $p -Mitre 'T1546.007'
        }
    }
    foreach ($m in @(Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' -ErrorAction SilentlyContinue)) {
        $drv = Get-WDRegValue $m.PSPath 'Driver'
        if (-not $drv) { continue }
        $p = $drv; if ($p -notmatch '\\') { $p = "$env:SystemRoot\System32\$p" }
        $info = Get-WDFileInfo $p
        if ($info.Exists -and $info.SigStatus -ne 'Valid') {
            Add-Finding -Severity High -Category 'Persistence' -Title 'Unsigned print monitor DLL (loaded by spoolsv as SYSTEM)' -Evidence "$($m.PSChildName): $p" -Mitre 'T1547.010'
        }
        Add-WDAutorun -Category 'Print monitor' -Location $m.Name -Name $m.PSChildName -Command $p -Mitre 'T1547.010'
    }
    foreach ($tp in @(Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders' -ErrorAction SilentlyContinue)) {
        $dll = [Environment]::ExpandEnvironmentVariables([string](Get-WDRegValue $tp.PSPath 'DllName'))
        if ($dll -and $dll -notmatch '(?i)\\system32\\(w32time|vmictimeprovider)\.dll$') {
            Add-Finding -Severity High -Category 'Persistence' -Title 'Non-default W32Time time provider DLL' -Evidence "$($tp.PSChildName): $dll" -Mitre 'T1547.003'
            Add-WDAutorun -Category 'Time provider' -Location $tp.Name -Name $tp.PSChildName -Command $dll -Mitre 'T1547.003'
        }
    }

    # Active Setup
    foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components')) {
        foreach ($k in @(Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue)) {
            $stub = Get-WDRegValue $k.PSPath 'StubPath'
            if ($stub) { Add-WDAutorun -Category 'Active Setup' -Location $k.Name -Name $k.PSChildName -Command $stub -Mitre 'T1547.014' -TrustMicrosoftInterpreters }
        }
    }

    # Global PowerShell profiles
    foreach ($pp in @("$env:SystemRoot\System32\WindowsPowerShell\v1.0\profile.ps1", "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1", "$env:ProgramFiles\PowerShell\7\profile.ps1")) {
        if (Test-Path -LiteralPath $pp) {
            $fi = Get-Item -LiteralPath $pp -Force
            Add-Finding -Severity Medium -Category 'Persistence' -Title 'All-users PowerShell profile exists' -Detail 'Runs in every PowerShell session.' -Evidence "$pp (modified $(ConvertTo-WDTimeString $fi.LastWriteTime) UTC)" -Mitre 'T1546.013' -Time $fi.LastWriteTime
            [void](Invoke-WDCommandCheck -Text (Get-Content -LiteralPath $pp -Raw -ErrorAction SilentlyContinue) -Source "PowerShell profile $pp" -Category 'Persistence')
        }
    }
}

function Invoke-WDUserPersistence {
    foreach ($h in (Get-WDUserHives)) {
        $r = $h.Root
        # Per-user Winlogon shell
        $shell = Get-WDRegValue "$r\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 'Shell'
        if ($shell) { Add-Finding -Severity High -Category 'Persistence' -Title 'Per-user Winlogon Shell override' -Evidence "$($h.User): $shell" -Mitre 'T1547.004'; Add-WDAutorun -Category 'Winlogon Shell (user)' -Location "$r\...\Winlogon" -Name 'Shell' -Command $shell -User $h.User -Mitre 'T1547.004' }
        # Screensaver
        $scr = [string](Get-WDRegValue "$r\Control Panel\Desktop" 'SCRNSAVE.EXE')
        if ($scr -and $scr -notmatch '(?i)^([a-z]:\\windows\\(system32|syswow64)\\)?[a-z0-9_]+\.scr$') {
            Add-Finding -Severity High -Category 'Persistence' -Title 'Screensaver points to a non-system executable' -Evidence "$($h.User): $scr" -Mitre 'T1546.002'
            Add-WDAutorun -Category 'Screensaver' -Location "$r\Control Panel\Desktop" -Name 'SCRNSAVE.EXE' -Command $scr -User $h.User -Mitre 'T1546.002'
        }
        # Office test key
        $ot = Get-WDRegValue "$r\Software\Microsoft\Office test\Special\Perf" ''
        if ($ot) { Add-Finding -Severity High -Category 'Persistence' -Title 'Office Test persistence key present' -Evidence "$($h.User): $ot" -Mitre 'T1137.002'; Add-WDAutorun -Category 'Office Test' -Location 'Office test\Special\Perf' -Name '(Default)' -Command $ot -User $h.User -Mitre 'T1137.002' }
        # Load / Run under Windows NT\CurrentVersion\Windows
        foreach ($n in @('Load', 'Run')) {
            $v = Get-WDRegValue "$r\Software\Microsoft\Windows NT\CurrentVersion\Windows" $n
            if ($v) { Add-WDAutorun -Category "Windows\$n (user)" -Location "$r\...\Windows NT\CurrentVersion\Windows" -Name $n -Command $v -User $h.User -InterpreterSeverity 'High' }
        }
        # COM hijacking: per-user CLSID overrides pointing to user-writable locations
        foreach ($clsid in @(Get-ChildItem -LiteralPath "$r\Software\Classes\CLSID" -ErrorAction SilentlyContinue)) {
            foreach ($srv in @('InprocServer32', 'LocalServer32')) {
                $val = Get-WDRegValue "$($clsid.PSPath)\$srv" ''
                if (-not $val) { continue }
                $p = [Environment]::ExpandEnvironmentVariables((Get-WDExecutablePath $val))
                if ((Get-WDPathRisk $p) -eq 'None') { continue }
                $info = Get-WDFileInfo $p
                if ($info.Exists -and $info.SigStatus -ne 'Valid') {
                    Add-Finding -Severity High -Category 'Persistence' -Title 'Per-user COM object points to unsigned binary in user-writable path (COM hijack)' -Evidence "$($h.User): $($clsid.PSChildName)\$srv = $val" -Mitre 'T1546.015'
                    Add-WDAutorun -Category 'COM hijack' -Location "$($clsid.PSChildName)\$srv" -Name $clsid.PSChildName -Command $val -User $h.User -Mitre 'T1546.015'
                }
            }
        }
        # Per-user PowerShell profiles
        foreach ($pp in @("$($h.Profile)\Documents\WindowsPowerShell\profile.ps1", "$($h.Profile)\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1", "$($h.Profile)\Documents\PowerShell\Microsoft.PowerShell_profile.ps1")) {
            if (Test-Path -LiteralPath $pp) {
                $fi = Get-Item -LiteralPath $pp -Force
                Add-Finding -Severity Low -Category 'Persistence' -Title 'User PowerShell profile exists' -Evidence "$pp (modified $(ConvertTo-WDTimeString $fi.LastWriteTime) UTC)" -Mitre 'T1546.013' -Time $fi.LastWriteTime
                [void](Invoke-WDCommandCheck -Text (Get-Content -LiteralPath $pp -Raw -ErrorAction SilentlyContinue) -Source "PowerShell profile $pp" -Category 'Persistence')
            }
        }
    }
}

function Invoke-WDBitsJobs {
    $out = & bitsadmin.exe /list /allusers /verbose 2>$null
    if (-not $out) { return }
    $text = $out -join "`n"
    try { [IO.File]::WriteAllText((Join-Path $script:WD.RawDir 'BitsJobs.txt'), $text) } catch { }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($block in ($text -split '(?m)^GUID:')) {
        if ($block -notmatch 'DISPLAY:') { continue }
        $name = if ($block -match "DISPLAY:\s*'?([^'\r\n]*)") { $Matches[1] } else { '' }
        $notify = if ($block -match "NOTIFICATION COMMAND LINE:\s*(.+)") { $Matches[1].Trim() } else { '' }
        $owner = if ($block -match 'OWNER:\s*(\S+)') { $Matches[1] } else { '' }
        $files = ([regex]::Matches($block, '(https?://\S+)') | ForEach-Object { $_.Value }) -join ' '
        $rows.Add([pscustomobject][ordered]@{ Job = $name; Owner = $owner; Urls = $files; NotifyCommand = $notify })
        if ($notify -and $notify -notmatch '^(?i)none') {
            Add-Finding -Severity High -Category 'Persistence' -Title 'BITS job with notification command (BITS persistence)' -Evidence "$name ($owner): $notify" -Mitre 'T1197'
            [void](Invoke-WDCommandCheck -Text $notify -Source "BITS job $name" -Category 'Persistence')
        }
        if ($files -and $files -notmatch '(?i)(microsoft|windowsupdate|msedge|office|adobe|google)') {
            [void](Invoke-WDCommandCheck -Text $files -Source "BITS job $name" -Category 'Network')
        }
    }
    Save-WDArtifact -Name 'BitsJobs' -Section 'Persistence' -Data $rows -Description 'BITS transfer jobs (all users)'
}
