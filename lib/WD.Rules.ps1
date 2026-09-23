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
$script:WDSelfExclusionRx = '(?i)(WindowsDetective\.ps1|WDCase_|WD-SELF-MARKER|Run-WindowsDetective\.bat)'

#            Id         Severity   MITRE                     Title                                                        Regex
$script:WDCommandRuleDefs = @(
    @('CMD-001', 'High',     'T1059.001,T1027',   'Encoded PowerShell command',                                   '(powershell|pwsh)(\.exe)?["'']?\s(.*\s)?[-/]e[a-z]*\s+["'']?[A-Za-z0-9+/]{20,}={0,2}'),
    @('CMD-002', 'High',     'T1059.001,T1105',   'PowerShell download-and-execute cradle',                       '\b(iex|invoke-expression)\b.{0,300}(downloadstring|downloaddata|net\.webclient|invoke-webrequest|invoke-restmethod|\biwr\b|\birm\b|start-bitstransfer)|(downloadstring|invoke-webrequest|invoke-restmethod|\biwr\b|\birm\b|net\.webclient).{0,300}\|\s*(iex|invoke-expression)\b'),
    @('CMD-003', 'Medium',   'T1105',             'PowerShell web download',                                      '(downloadstring|downloadfile|downloaddata|net\.webclient|start-bitstransfer|invoke-webrequest\s|invoke-restmethod\s|\biwr\s+(-uri\s+)?["'']?https?:|\birm\s+(-uri\s+)?["'']?https?:)'),
    @('CMD-004', 'Medium',   'T1027,T1140',       'Base64 decoding in command or script',                         'frombase64string|\[convert\]::frombase64'),
    @('CMD-005', 'Medium',   'T1564.003',         'Hidden PowerShell window',                                     '(powershell|pwsh)(\.exe)?["'']?\s(.*\s)?[-/]w[a-z]*\s+["'']?(h[a-z]*|1)\b'),
    @('CMD-006', 'Low',      'T1059.001',         'PowerShell execution policy bypass',                           '(powershell|pwsh)(\.exe)?["'']?\s.*[-/]e[a-z]*\s+["'']?(bypass|unrestricted)\b'),
    @('CMD-007', 'High',     'T1105,T1140',       'Certutil used to download or decode files',                    'certutil(\.exe)?["'']?\s.*[-/](urlcache|verifyctl|decode|decodehex|encode)\b'),
    @('CMD-008', 'High',     'T1197',             'BITSAdmin transfer / notify-command abuse',                    'bitsadmin(\.exe)?["'']?\s.*/(transfer|addfile|setnotifycmdline|download)\b'),
    @('CMD-009', 'High',     'T1218.005',         'Mshta executing remote, inline or HTA script',                 'mshta(\.exe)?["'']?\s+.*(https?:|javascript:|vbscript:|\.hta\b)'),
    @('CMD-010', 'High',     'T1218.010',         'Regsvr32 scriptlet execution (Squiblydoo)',                    'regsvr32(\.exe)?["'']?\s.*[-/]i:.*(https?:|scrobj|\.sct)|regsvr32.*scrobj\.dll'),
    @('CMD-011', 'High',     'T1218.011',         'Rundll32 proxy execution of script / URL / INF',               'rundll32(\.exe)?["'']?\s.*(javascript:|vbscript:|mshtml(\.dll)?,\s*#?runhtmlapplication|url\.dll,\s*(openurl|fileprotocolhandler)|advpack\.dll,\s*(registerocx|launchinfsection)|ieadvpack\.dll|shell32\.dll,\s*shellexec_rundll|pcwutl\.dll|zipfldr\.dll,\s*routethecall|setupapi\.dll,\s*installhinfsection|syssetup\.dll)'),
    @('CMD-012', 'High',     'T1218.011',         'Rundll32 loading DLL from user-writable path',                 'rundll32(\.exe)?["'']?\s+["'']?[a-z]:\\(users|programdata|windows\\temp|perflogs|\$recycle)'),
    @('CMD-013', 'Critical', 'T1003.001',         'LSASS memory dump via comsvcs.dll MiniDump',                   'comsvcs(\.dll)?["'']?[,\s]+#?\s*(minidump|24)\b'),
    @('CMD-014', 'Critical', 'T1003.001',         'LSASS process dump tooling',                                   '(procdump(64)?|dumpert|nanodump|sqldumper|createdump|rdrleakdiag|handlekatz|ppldump).{0,200}lsass|[-/]ma\s+lsass|lsass.{0,60}\.dmp\b'),
    @('CMD-015', 'Critical', 'T1003',             'Mimikatz / credential theft keywords',                         '(sekur[l]sa::|lsadu[m]p::|kerbero[s]::(golden|ptt|list)|privilege::[d]ebug|token::[e]levate|crypto::[c]api|dpap[i]::|invoke-mimi[k]atz|\bmimi[k]atz\b|safety[k]atz|sharp[k]atz|pypy[k]atz|\blaza[g]ne\b)'),
    @('CMD-016', 'Critical', 'T1003.002',         'Registry hive dump (SAM / SECURITY / SYSTEM)',                 'reg(\.exe)?["'']?\s+(save|export)\s+["'']?(hklm|hkey_local_machine)\\(sam|security|system)\b'),
    @('CMD-017', 'High',     'T1003.003',         'NTDS / shadow-copy credential access',                         'ntdsutil.*(ifm|create\s+full|snapshot)|vssadmin(\.exe)?\s+create\s+shadow|diskshadow(\.exe)?\s+/s|esentutl(\.exe)?\s.*[/-]vss.*\\(ntds\.dit|sam|security|system)\b|\\ntds\.dit\b'),
    @('CMD-018', 'Critical', 'T1490',             'Backup / shadow-copy destruction (ransomware precursor)',      'vssadmin(\.exe)?["'']?\s+(delete\s+shadows|resize\s+shadowstorage)|wmic(\.exe)?["'']?\s+shadowcopy\s+delete|win32_shadowcopy.{0,80}(delete|remove-ciminstance)|wbadmin(\.exe)?["'']?\s+delete\s+(catalog|systemstatebackup|backup)|bcdedit(\.exe)?["'']?\s.*(recoveryenabled\s+(no|off)|bootstatuspolicy\s+ignoreallfailures)'),
    @('CMD-019', 'Critical', 'T1070.001',         'Event log clearing',                                           'wevtutil(\.exe)?["'']?\s+(cl|clear-log)\b|clear-eventlog|remove-eventlog|globalsession\.clearlog'),
    @('CMD-020', 'High',     'T1562.001',         'Microsoft Defender tampering',                                 'set-mppreference.*-disable\w+\s+(\$true|1)|add-mppreference.*-exclusion|disableantispyware|disablerealtimemonitoring|\bsc(\.exe)?\s+(stop|delete|config)\s+["'']?(windefend|sense|wdboot|wdfilter|wdnisdrv|wdnissvc)\b|mpcmdrun(\.exe)?.*-removedefinitions'),
    @('CMD-021', 'High',     'T1562.004',         'Windows Firewall disabled',                                    'netsh(\.exe)?.*(firewall\s+set\s+opmode\s+(mode=)?disable|advfirewall\s+set\s+\w+\s+state\s+off)|set-netfirewallprofile.*-enabled\s+(\$?false|0)'),
    @('CMD-022', 'High',     'T1090',             'Netsh port proxy / port forwarding',                           'netsh(\.exe)?.*interface\s+portproxy\s+(add|set)'),
    @('CMD-023', 'Low',      'T1082,T1087,T1016', 'Host / domain reconnaissance command',                         '\bwhoami(\.exe)?\s+/(all|priv|groups)|\bnltest(\.exe)?\s+/(domain_trusts|dclist|dsgetdc)|\bnet1?(\.exe)?\s+(group|localgroup)\s+["'']?(domain admins|administrators|enterprise admins|domain computers)|\bnet1?(\.exe)?\s+(view|session)\b|\bquser\b|\bquery\s+(user|session)\b|\bnetstat(\.exe)?\s+-an|\bipconfig(\.exe)?\s+/all|\bsysteminfo(\.exe)?\b|\bcmdkey(\.exe)?\s+/list|get-aduser\s+-filter\s+\*|get-adcomputer\s+-filter\s+\*'),
    @('CMD-024', 'High',     'T1087.002,T1482,T1558.003', 'Active Directory attack tooling',                      '\b(adfind|sharphound|invoke-bloodhound|powerview|get-domaintrust|invoke-userhunter|rubeus|kerberoast|asreproast|seatbelt|sharpup|winpeas|powerup|invoke-allchecks|certify|certipy|whisker|sharpdpapi|sharpchrome|kerbrute)\b'),
    @('CMD-025', 'Medium',   'T1021.002,T1021.006,T1047', 'Remote execution / lateral movement command',          '\b(psexec(64)?|paexec|remcom|csexec)(\.exe)?\s|wmic(\.exe)?["'']?\s+/node:|invoke-command\s+.*-computername|enter-pssession\s|winrs(\.exe)?\s+-r:|invoke-wmimethod.*-computername|invoke-(smbexec|wmiexec|psexec)'),
    @('CMD-026', 'Medium',   'T1053.005',         'Scheduled task created from command line',                     'schtasks(\.exe)?["'']?\s+/create|register-scheduledtask\s'),
    @('CMD-027', 'Medium',   'T1543.003',         'Service created from command line',                            '\bsc(\.exe)?["'']?\s+(\\\\\S+\s+)?create\s|\bnew-service\s'),
    @('CMD-028', 'High',     'T1547.001,T1546.012', 'Autostart registry key modified from command line',          '(reg(\.exe)?["'']?\s+add|set-itemproperty|new-itemproperty).*\\(currentversion\\(run|runonce|runonceex|policies\\explorer\\run|winlogon)|image file execution options|silentprocessexit|appinit_dlls)'),
    @('CMD-029', 'High',     'T1136.001,T1098',   'Local account created / added to privileged group',            '\bnet1?(\.exe)?\s+user\s+\S+\s+\S+.*\s/add\b|\bnet1?(\.exe)?\s+localgroup\s+["'']?(administrators|remote desktop users|remote management users)["'']?\s+\S+.*\s/add\b|\bnew-localuser\s|\badd-localgroupmember\s'),
    @('CMD-030', 'Medium',   'T1105',             'Command-line tool downloading a remote file',                  '\b(curl|wget)(\.exe)?["'']?\s+.*https?://|\bcurl(\.exe)?\s.*\|\s*(cmd|powershell|pwsh|iex)'),
    @('CMD-031', 'Medium',   'T1071.001',         'URL pointing to a raw public IP address',                      'https?://(?!127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)\d{1,3}(\.\d{1,3}){3}'),
    @('CMD-032', 'Medium',   'T1102,T1567',       'Reference to file-sharing / paste / tunnelling service',       '(pastebin\.com|paste\.ee|hastebin|ghostbin|transfer\.sh|temp\.sh|file\.io|gofile\.io|anonfiles|catbox\.moe|0x0\.st|ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|\.workers\.dev|serveo\.net|localtunnel|\.loca\.lt|duckdns\.org|ddns\.net|raw\.githubusercontent\.com|gist\.githubusercontent\.com|cdn\.discordapp\.com|discord(app)?\.com/api/webhooks|api\.telegram\.org|mega\.nz|mediafire\.com|dropboxusercontent\.com|iplogger\.|bit\.ly/|tinyurl\.com/)'),
    @('CMD-033', 'High',     'T1567.002',         'Cloud exfiltration tool (rclone / MEGA / restic)',             '\brclone(\.exe)?["'']?\s+(copy|sync|move|config)\b|\bmega(-put|cmd|client)\b|\brestic(\.exe)?\s+.*backup'),
    @('CMD-034', 'Medium',   'T1560.001',         'Password-protected archive creation (data staging)',           '\b(7z|7za|7zr|rar|winrar)(\.exe)?["'']?\s+a\s+.*\s-(p|hp)\S+'),
    @('CMD-035', 'Medium',   'T1047',             'WMI process creation',                                         'wmic(\.exe)?["'']?\s+.*process\s+call\s+create|invoke-wmimethod\s+.*win32_process.*create|invoke-cimmethod\s+.*win32_process.*create'),
    @('CMD-036', 'High',     'T1059.005,T1059.007', 'Script host running script from user-writable path',         '(wscript|cscript)(\.exe)?["'']?\s+.*\\(appdata|temp|downloads|users\\public|programdata)\\.*\.(js|jse|vbs|vbe|wsf|wsh)\b'),
    @('CMD-037', 'High',     'T1127.001,T1218.009', 'Trusted developer utility executing payload from user path', '\b(msbuild|installutil|regasm|regsvcs|csc|jsc|ilasm|msxsl|microsoft\.workflow\.compiler|cdb|ntsd|bginfo|presentationhost)(\.exe)?["'']?\s+.*\\(appdata|temp|users\\public|programdata|downloads)\\'),
    @('CMD-038', 'High',     'T1218',             'Signed binary proxy execution (LOLBin)',                       '\bodbcconf(\.exe)?\s+.*[-/]a\s|\bcmstp(\.exe)?\s+.*\.inf|\bforfiles(\.exe)?\s+.*[-/]c\s|\bpcalua(\.exe)?\s+-a|\bmsiexec(\.exe)?["'']?\s+.*[-/](i|package)\s+["'']?https?:|\bmsiexec(\.exe)?["'']?\s+.*[-/]y\s|\bhh(\.exe)?\s+https?:|\bmavinject(\.exe)?\s+.*[-/]injectrunning|\bsyncappvpublishingserver|\bxwizard(\.exe)?\s+runwizard|\bmsdt(\.exe)?\s+.*(ms-msdt|it_browseforfile)|\bdesktopimgdownldr|\bieexec(\.exe)?\s|\bwlrmdr(\.exe)?\s|\bfinger(\.exe)?\s+\S+@'),
    @('CMD-039', 'Critical', 'T1562.001',         'AMSI bypass attempt',                                          'amsi[u]tils|amsi[i]nitfailed|amsi[s]canbuffer|amsi[c]ontext|amsi\.dll.{0,100}(patch|virtual[p]rotect)'),
    @('CMD-040', 'High',     'T1055,T1620',       'Code injection / reflective loading API usage',                '(virtual[a]lloc(ex)?|writeprocess[m]emory|createremote[t]hread|ntcreate[t]hreadex|queueuser[a]pc|getdelegatefor[f]unctionpointer|reflection\.assembly\]::lo[a]d(file)?\(|\bdll[i]mport\b.{0,40}kernel32)'),
    @('CMD-041', 'Medium',   'T1562.010',         'PowerShell version 2 downgrade',                               '(powershell|pwsh)(\.exe)?["'']?\s+.*[-/]v[a-z]*\s+2(\.0)?\b'),
    @('CMD-042', 'Medium',   'T1027.010',         'Command-line obfuscation (carets / char codes / reversal)',    '([a-z]\^){4,}|(\[char\]\s*\(?\d{2,3}\)?\s*\+?\s*){4,}|\$env:comspec\[\d+|\[-1\.\.\s*-'),
    @('CMD-043', 'High',     'T1204.004',         'ClickFix / fake CAPTCHA paste-and-run lure',                   '(powershell|pwsh|mshta|cmd|curl|msiexec|wscript|conhost).{0,500}(captcha|not a robot|verification id|verify you are human|human verification|cloudflare verification|ray id:)'),
    @('CMD-044', 'High',     'T1548.002',         'UAC bypass technique',                                         '(ms-settings|mscfile|exefile|launcher\.systemsettings)\\shell\\open\\command|\\folder\\shell\\open\\command|cmstplua|icmluautil'),
    @('CMD-045', 'Critical', 'T1546.008',         'Accessibility binary replacement (sticky-keys backdoor)',      '\b(copy|move|xcopy|robocopy|takeown|icacls|ren|rename|copy-item)\b.*\\(sethc|utilman|osk|magnify|narrator|displayswitch|atbroker)\.exe|image file execution options\\(sethc|utilman|osk|magnify|narrator|displayswitch|atbroker)\.exe'),
    @('CMD-046', 'Medium',   'T1021.001',         'Remote Desktop enabled / opened from command line',            'fdenytsconnections.{0,40}\b0\b|enable-netfirewallrule.*remote\s*desktop|netsh.*(firewall|advfirewall).*(3389|remote\s*desktop)'),
    @('CMD-047', 'Medium',   'T1552.001',         'Searching files for credentials',                              '(findstr|select-string)\b.{0,80}(password|passwd|pwd=|cpassword|credential)|\bdir\b.{0,40}(\*pass\*|\*cred\*|\*\.kdbx)'),
    @('CMD-048', 'Low',      'T1564.001',         'Hiding files with system+hidden attributes',                   '\battrib(\.exe)?\s+.*\+h.*\+s|\battrib(\.exe)?\s+.*\+s.*\+h'),
    @('CMD-049', 'High',     'T1070',             'Anti-forensics (USN journal / wipe / timestomp)',              'fsutil(\.exe)?\s+usn\s+deletejournal|cipher(\.exe)?\s+/w:|\bsdelete(64)?(\.exe)?\s|\btimestomp\b'),
    @('CMD-050', 'High',     'T1090.003',         'Tor / onion routing',                                          '\btor(\.exe)?["'']?\s+.{0,40}(--|socks)|\.onion\b|torbrowser'),
    @('CMD-051', 'Critical', 'T1059.001',         'Offensive PowerShell / C2 framework',                          'invoke-(shell[c]ode|reflective[p]einjection|dll[i]njection|token[m]anipulation|powershell[t]cp|ps[i]nject|night[m]are|smb[e]xec|wmi[e]xec|the[h]ash|kerbero[a]st|ninja[c]opy|credential[i]njection|port[s]can|share[f]inder|in[v]eigh)|power[s]ploit|\bnish[a]ng\b|\bpower[c]at\b|cobalt[s]trike|cobalt\s+stri[k]e|brute\s?ra[t]el|\bsliver-[c]lient\b'),
    @('CMD-052', 'Critical', 'T1059',             'Reverse shell pattern',                                        'net\.sockets\.tcp[c]lient|\bnc(at|64)?(\.exe)?\s+.*-e\s+(cmd|powershell|/bin/sh)|\bsocat(\.exe)?\s+.*exec:|/dev/tcp/'),
    @('CMD-053', 'High',     'T1112,T1562.001',   'Security feature disabled via registry',                       '(reg(\.exe)?["'']?\s+add|set-itemproperty|new-itemproperty).*(disableantispyware|disablerealtimemonitoring|disablebehaviormonitoring|tamperprotection|enablelua|consentpromptbehavioradmin|uselogoncredential|disablerestrictedadmin|localaccounttokenfilterpolicy)'),
    @('CMD-054', 'High',     'T1555.003',         'Browser credential / cookie store access',                     '(copy|robocopy|xcopy|copy-item|esentutl)\b.{0,200}\\(login data|cookies|web data|local state|key4\.db|logins\.json)\b|vaultcmd(\.exe)?\s+/list'),
    @('CMD-055', 'High',     'T1219',             'Silent install / config of remote-access tool',                '(anydesk|rustdesk|screenconnect|atera|splashtop|netsupport|meshagent|simplehelp|teamviewer)[^\s]*\.(exe|msi)["'']?\s+.*(--install|--silent|/quiet|/qn|--start-with-win|--set-password)|anydesk.*--set-password'),
    @('CMD-056', 'Medium',   'T1070.004',         'Self-deletion pattern',                                        'ping\s+(-n\s+\d+\s+)?127\.0\.0\.1.*&\s*del\s|timeout\s+/t\s+\d+.*&\s*del\s|choice\s+/c\s+y\s+/n.*&\s*del\s')
)

$script:WDCommandRules = New-Object System.Collections.Generic.List[object]
foreach ($d in $script:WDCommandRuleDefs) {
    try {
        $rx = New-Object System.Text.RegularExpressions.Regex($d[4], ([System.Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant'))
        $script:WDCommandRules.Add([pscustomobject]@{ Id = $d[0]; Severity = $d[1]; Mitre = $d[2]; Title = $d[3]; Regex = $rx })
    } catch { Write-Warning "Rule $($d[0]) failed to compile: $($_.Exception.Message)" }
}

function Test-WDCommandLine {
    param([string]$Text)
    $hits = New-Object System.Collections.Generic.List[object]
    if ([string]::IsNullOrWhiteSpace($Text)) { return $hits }
    if ($Text -match $script:WDSelfExclusionRx) { return $hits }
    foreach ($r in $script:WDCommandRules) { if ($r.Regex.IsMatch($Text)) { $hits.Add($r) } }
    return $hits
}

# Runs all command rules against a text and raises one finding per matching rule.
function Invoke-WDCommandCheck {
    param([string]$Text, [string]$Source, $Time = $null, [string]$Context = '', [string]$Category = 'Execution')
    $hits = Test-WDCommandLine $Text
    foreach ($r in $hits) {
        $detail = "Rule $($r.Id) matched in $Source."
        if ($Context) { $detail += " $Context" }
        Add-Finding -Severity $r.Severity -Category $Category -Title $r.Title -Detail $detail -Evidence $Text -Mitre $r.Mitre -Time $Time -Source $Source
    }
    return $hits.Count
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
    if ($ev -match $script:WDSelfExclusionRx) { return }
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
    $leaf = (Split-Path $Path -Leaf).ToLowerInvariant()
    if ($script:WDLookalikeNames -contains $leaf) { return "Filename '$leaf' imitates a Windows system binary" }
    if ($script:WDSystemBinaries.ContainsKey($leaf)) {
        $exp = $script:WDSystemBinaries[$leaf]
        if ($exp -eq '.') { $rx = '(?i)^[a-z]:\\windows\\[^\\]+$' } else { $rx = '(?i)^[a-z]:\\windows\\(' + $exp + ')\\[^\\]+$' }
        if ($Path -notmatch $rx -and $Path -notmatch '(?i)\\WinSxS\\') { return "System binary name '$leaf' running from non-standard location" }
    }
    return $null
}

# ----------------------------------------------------------------------------- tool intelligence
# name (lowercase, no extension) -> @(Severity, Label, MITRE)
$script:WDKnownTools = @{
    'mimikatz' = @('Critical','Mimikatz credential dumper','T1003'); 'mimidrv' = @('Critical','Mimikatz driver','T1003')
    'pypykatz' = @('Critical','pypykatz credential dumper','T1003'); 'lazagne' = @('Critical','LaZagne password stealer','T1555')
    'nanodump' = @('Critical','nanodump LSASS dumper','T1003.001'); 'dumpert' = @('Critical','Dumpert LSASS dumper','T1003.001')
    'safetykatz' = @('Critical','SafetyKatz','T1003'); 'sharpkatz' = @('Critical','SharpKatz','T1003')
    'procdump' = @('Medium','Sysinternals ProcDump (often used to dump LSASS)','T1003.001'); 'procdump64' = @('Medium','Sysinternals ProcDump (often used to dump LSASS)','T1003.001')
    'rubeus' = @('Critical','Rubeus Kerberos attack tool','T1558'); 'kekeo' = @('Critical','Kekeo Kerberos tool','T1558')
    'seatbelt' = @('High','Seatbelt host recon','T1082'); 'sharphound' = @('High','SharpHound (BloodHound collector)','T1087.002')
    'bloodhound' = @('High','BloodHound','T1087.002'); 'adfind' = @('High','AdFind AD recon (ransomware favourite)','T1087.002')
    'kerbrute' = @('High','Kerbrute','T1110'); 'certify' = @('High','Certify AD CS abuse','T1649'); 'certipy' = @('High','Certipy AD CS abuse','T1649')
    'sharpup' = @('High','SharpUp privesc checker','T1068'); 'winpeas' = @('High','winPEAS privesc checker','T1068')
    'winpeasx64' = @('High','winPEAS privesc checker','T1068'); 'winpeasany' = @('High','winPEAS privesc checker','T1068')
    'crackmapexec' = @('High','CrackMapExec','T1021.002'); 'netexec' = @('High','NetExec','T1021.002'); 'nxc' = @('High','NetExec','T1021.002')
    'secretsdump' = @('Critical','Impacket secretsdump','T1003'); 'wmiexec' = @('High','Impacket wmiexec','T1047')
    'smbexec' = @('High','Impacket smbexec','T1021.002'); 'atexec' = @('High','Impacket atexec','T1053.005'); 'dcomexec' = @('High','Impacket dcomexec','T1021.003')
    'psexec' = @('Medium','Sysinternals PsExec','T1569.002'); 'psexec64' = @('Medium','Sysinternals PsExec','T1569.002')
    'psexesvc' = @('Medium','PsExec service (remote execution into this host)','T1569.002'); 'paexec' = @('High','PAExec remote execution','T1569.002')
    'remcom' = @('High','RemCom remote execution','T1569.002'); 'csexec' = @('High','CSExec remote execution','T1569.002')
    'chisel' = @('High','Chisel tunnel','T1572'); 'ligolo' = @('High','Ligolo tunnel','T1572'); 'ligolo-ng' = @('High','Ligolo-ng tunnel','T1572')
    'frpc' = @('High','FRP reverse proxy client','T1572'); 'frps' = @('High','FRP reverse proxy server','T1572'); 'gost' = @('High','GOST tunnel','T1572')
    'revsocks' = @('High','revsocks tunnel','T1572'); 'iox' = @('High','iox port forwarder','T1572'); 'plink' = @('Medium','PuTTY plink (SSH tunnelling)','T1572')
    'nc' = @('High','Netcat','T1059'); 'nc64' = @('High','Netcat','T1059'); 'ncat' = @('High','Ncat','T1059'); 'netcat' = @('High','Netcat','T1059'); 'socat' = @('High','socat','T1059')
    'ngrok' = @('High','ngrok tunnel','T1572'); 'cloudflared' = @('Medium','Cloudflare tunnel client','T1572')
    'rclone' = @('High','rclone (cloud exfiltration favourite)','T1567.002'); 'megasync' = @('Medium','MEGAsync','T1567.002')
    'megacmd' = @('High','MEGAcmd','T1567.002'); 'mega-put' = @('High','MEGA upload','T1567.002'); 'restic' = @('Medium','restic backup (possible exfil)','T1567')
    'nmap' = @('Medium','Nmap scanner','T1046'); 'masscan' = @('High','masscan','T1046'); 'advanced_ip_scanner' = @('Medium','Advanced IP Scanner (ransomware favourite)','T1046')
    'advanced_port_scanner' = @('Medium','Advanced Port Scanner','T1046'); 'netscan' = @('Medium','SoftPerfect NetScan (ransomware favourite)','T1046')
    'ipscan' = @('Medium','Angry IP Scanner','T1046'); 'processhacker' = @('Medium','Process Hacker (used to kill EDR)','T1562.001')
    'systeminformer' = @('Medium','System Informer (used to kill EDR)','T1562.001'); 'pchunter' = @('High','PC Hunter (EDR killer)','T1562.001')
    'pchunter64' = @('High','PC Hunter (EDR killer)','T1562.001'); 'gmer' = @('High','GMER (EDR killer)','T1562.001'); 'powertool' = @('High','PowerTool (EDR killer)','T1562.001')
    'defendercontrol' = @('High','Defender Control (disables Defender)','T1562.001'); 'dcontrol' = @('High','Defender Control (disables Defender)','T1562.001')
    'backstab' = @('Critical','Backstab EDR killer','T1562.001'); 'edrsandblast' = @('Critical','EDRSandblast','T1562.001')
    'terminator' = @('High','Terminator EDR killer (BYOVD)','T1562.001'); 'spyboy' = @('High','Spyboy EDR killer','T1562.001')
    'edrsilencer' = @('Critical','EDRSilencer','T1562.001'); 'tor' = @('High','Tor client','T1090.003'); 'meterpreter' = @('Critical','Metasploit Meterpreter','T1059')
    'msfvenom' = @('Critical','Metasploit payload generator','T1587.001'); 'beacon' = @('High','Possible Cobalt Strike beacon','T1071.001')
    'sdelete' = @('Medium','SDelete secure delete','T1070.004'); 'sdelete64' = @('Medium','SDelete secure delete','T1070.004')
    'wevtutil_clear' = @('High','Log clearing helper','T1070.001'); 'filezilla' = @('Low','FileZilla FTP client (possible exfil)','T1048')
    'winscp' = @('Low','WinSCP (possible exfil)','T1048'); 'pscp' = @('Low','PuTTY pscp (possible exfil)','T1048')
}

# Remote Monitoring & Management / remote access software (heavily abused for hands-on-keyboard access).
$script:WDRmmTools = @{
    'anydesk' = 'AnyDesk'; 'rustdesk' = 'RustDesk'; 'screenconnect.clientservice' = 'ScreenConnect'; 'screenconnect.windowsclient' = 'ScreenConnect'
    'connectwisecontrol.client' = 'ConnectWise Control'; 'atera' = 'Atera'; 'ateraagent' = 'Atera'; 'splashtop' = 'Splashtop'; 'srservice' = 'Splashtop'
    'strwinclt' = 'Splashtop'; 'client32' = 'NetSupport Manager (NetSupport RAT)'; 'pcicfgui' = 'NetSupport Manager'; 'meshagent' = 'MeshCentral agent'
    'tacticalrmm' = 'Tactical RMM'; 'tacticalagent' = 'Tactical RMM'; 'simplehelp' = 'SimpleHelp'; 'remote access' = 'SimpleHelp'
    'rutserv' = 'Remote Utilities'; 'rfusclient' = 'Remote Utilities'; 'ammyy' = 'Ammyy Admin'; 'aa_v3' = 'Ammyy Admin'; 'radmin' = 'Radmin'
    'rserver3' = 'Radmin server'; 'teamviewer' = 'TeamViewer'; 'teamviewer_service' = 'TeamViewer'; 'tv_w32' = 'TeamViewer'; 'tv_x64' = 'TeamViewer'
    'tvnserver' = 'TightVNC'; 'winvnc' = 'VNC server'; 'vncserver' = 'VNC server'; 'uvnc_service' = 'UltraVNC'; 'level' = 'Level RMM'
    'action1_agent' = 'Action1'; 'zaservice' = 'Zoho Assist'; 'zohomeeting' = 'Zoho Assist'; 'logmein' = 'LogMeIn'; 'lmiguardiansvc' = 'LogMeIn'
    'gotoassist' = 'GoTo Assist'; 'bomgar-scc' = 'BeyondTrust Remote Support'; 'dwagent' = 'DWService'; 'dwrcs' = 'DameWare'
    'remotepc' = 'RemotePC'; 'supremo' = 'Supremo'; 'supremoservice' = 'Supremo'; 'ninjarmmagent' = 'NinjaOne'; 'syncro' = 'Syncro'
    'agentmon' = 'Kaseya'; 'itsmservice' = 'ITarian'; 'parsec' = 'Parsec'; 'getscreen' = 'Getscreen.me'; 'fleetdeck_agent' = 'FleetDeck'
}

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

# Known vulnerable / abused kernel drivers (Bring Your Own Vulnerable Driver) - see loldrivers.io
$script:WDVulnerableDrivers = @(
    'rtcore64.sys','rtcore32.sys','dbutil_2_3.sys','dbutildrv2.sys','gdrv.sys','asio.sys','asio2.sys','asio3.sys','aswarpot.sys','kprocesshacker.sys',
    'procexp152.sys','zam64.sys','zamguard64.sys','mhyprot2.sys','mhyprot3.sys','iqvw64e.sys','winring0x64.sys','winring0.sys','truesight.sys',
    'rentdrv2.sys','gmer64.sys','cpuz141.sys','physmem.sys','speedfan.sys','atillk64.sys','msio64.sys','msio32.sys','glckio2.sys','winio64.sys',
    'winio32.sys','amifldrv64.sys','bs_def64.sys','elbycdio.sys','directio64.sys','viragt64.sys','wnbios.sys','ntiolib_x64.sys','capcom.sys',
    'fiddrv64.sys','rzpnk.sys','phymemx64.sys','pdfwkrnl.sys','nicm.sys','inpoutx64.sys','asrdrv101.sys','asrdrv102.sys','amdryzenmasterdriver.sys',
    'hpportiox64.sys','probmon.sys','sysdrv3s.sys','ktgn.sys','wfshbr64.sys','zemanaantimalware.sys','tfsysmon.sys','poortry.sys','stdcdrv64.sys',
    'hwrwdrv.sys','ene.sys','lgdcatcher.sys','echo_driver.sys','biontdrv.sys','appid.sys.bak','windbg.sys','ksapi64.sys','netfilter.sys'
)

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
