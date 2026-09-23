# Windows Detective

**Live-response forensic triage and compromise assessment for Windows.**
**Powered by Bashar Salmo**

Windows Detective answers the first question in any incident: *has this Windows machine been compromised, and how?*
In one run it collects and analyses the artifacts an incident responder would otherwise gather by hand. It produces an interactive HTML report with a verdict, prioritised findings mapped to MITRE ATT&CK, a unified timeline and a case folder you can use as evidence.

- Pure PowerShell 5.1: nothing to install, runs on every Windows 10/11 and Server 2016+ host
- Read-only: it never deletes, kills, quarantines or "fixes" anything on the host
- Works offline: the report is a single self-contained HTML file
- Takes a few minutes in standard mode

---

## Quick start

1. Copy the whole folder to a USB drive or network share. Don't install it on the suspect machine.
2. On the suspect laptop, right-click **`Run-WindowsDetective.bat`** and choose **Run as administrator**.
3. When it finishes, the report opens automatically. The case folder and ZIP are in `Cases\`.

Or from an elevated PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\WindowsDetective.ps1 -CaseId IR-2026-042 -Analyst "Jane Doe" -OutputPath E:\Cases -OpenReport
```

Full collection for a serious incident (memory first, deeper checks, raw evidence):

```powershell
.\WindowsDetective.ps1 -MemoryDump -Deep -CollectRawArtifacts -LoadUserHives -Days 90 -OutputPath E:\Cases
```

| Parameter | Purpose |
|---|---|
| `-Days <n>` | Investigation window (default 30) |
| `-CaseId`, `-Analyst` | Printed in the report for chain of custody |
| `-OutputPath` | Where the case folder is written. Use external media for evidential work. |
| `-Quick` | Fast triage: fewer events, smaller file sweep |
| `-Deep` | Loaded-DLL scan, System32 change check, deeper file sweep, 4x more events |
| `-CollectRawArtifacts` | Copy registry hives, Amcache, SRUM, WMI repository, browser history, jump lists, Prefetch, Tasks, Defender MPLog and flagged files |
| `-MemoryDump` | Capture RAM first (needs `tools\winpmem*.exe`) |
| `-LoadUserHives` | Also analyse the registry of users who are not logged on |
| `-NoEvtx` / `-NoZip` | Skip the EVTX export or the ZIP archive |
| `-MaxEvents <n>` | Events read per query (default 5000) |
| `-IocPath` | Folder of IOC lists (default `iocs\`) |

---

## What it investigates

| Area | Coverage |
|---|---|
| **Processes** | Hash and signature of every image, masquerading (e.g. `svchost.exe` running from the wrong folder, look-alike names), wrong parent processes, Office apps or web servers spawning shells, deleted images, renamed tools, 56 command-line detection rules, loaded DLLs from user paths (`-Deep`) |
| **Network** | TCP/UDP connections with owning process, LOLBins talking to the internet, C2 ports, bind shells, inbound RDP from public IPs, DNS cache (tunnels, paste sites, IP lookups), hosts file tampering, **netsh portproxy** pivots, proxies/PAC, shares, SMB sessions, ARP, routes, Wi-Fi, firewall profiles and rules, RDP configuration |
| **Persistence** | Run/RunOnce (machine and every user), Startup folders, services (ImagePath, ServiceDll, FailureCommand, unquoted paths), scheduled tasks including **hidden Tarrask-style tasks**, WMI subscriptions, IFEO/SilentProcessExit, Winlogon, AppInit/AppCert DLLs, LSA packages and password filters, sticky-keys backdoors, netsh helpers, print monitors, time providers, COM hijacks, Office Test key, screensaver, PowerShell profiles, Active Setup, BootExecute, BITS jobs |
| **Evidence of execution** | Prefetch, BAM, ShimCache (parsed), Amcache (parsed, SHA1), UserAssist (ROT13-decoded), **RunMRU / ClickFix** fake-CAPTCHA pastes, PSReadLine history, recent documents |
| **Event logs** | Logons (RDP, public IPs, NewCredentials/pass-the-hash, NTLMv1), **brute force and password spraying, including a later successful logon**, account and group changes, audit-policy and time changes, log clearing (1102/104), service installs (7045/4697), task creation (4698/4702), admin shares, process creation (4688), PowerShell 4104/400 (downgrade), RDP (1149, 21-25, outbound 1024), Defender (detections, failed remediation, exclusions, tamper attempts), Sysmon (1, 3, 8, 10 LSASS access, 12/13, 22, 25), Task Scheduler, BITS, WinRM, WMI-Activity 5861, firewall rule changes |
| **File system** | Executables, scripts, disk images, OneNote/CHM/XLL and LNK files created in user-writable locations during the window, with hash, signature and **Mark-of-the-Web download URL**; double extensions/RTLO, malicious shortcuts, ransom notes, shadow copies, USB history, browser extensions (sideloaded or high-permission) |
| **Security posture** | Defender status, exclusions and detection history, AV products, **BYOVD vulnerable drivers** and unsigned drivers, UAC, WDigest, LSA protection, RestrictedAdmin, LocalAccountTokenFilterPolicy, LM/NTLM settings, SMBv1, Credential Guard, BitLocker, Secure Boot, PowerShell v2, plaintext credentials in history/unattend files |
| **Accounts** | Local users, hidden/`$` accounts, enabled Guest/Administrator, privileged group members, new profiles, logged-on sessions |
| **Threat intel** | Matches file hashes (MD5/SHA1/SHA256), IPs and domains against `iocs\*.txt`. Runs YARA over process images, autoruns and suspicious files (`tools\yara64.exe` + `rules\`). Exports every observed indicator for SIEM pivoting. |
| **Remote-access abuse** | 50+ RMM/remote tools (AnyDesk, ScreenConnect, NetSupport, Atera, RustDesk, ...) plus offensive and dual-use tools (Mimikatz, Rubeus, AdFind, rclone, ngrok, Chisel, EDR killers ...) found in processes, software, Prefetch, BAM, Amcache and files |

The tool excludes its own activity from detections: its scripts, case folders and launcher are recognised by marker.

---

## Output

```
Cases\WDCase_<HOST>_<timestamp>\
  WindowsDetective_Report.html   interactive report (verdict, findings, ATT&CK, timeline, artifacts)
  findings.json / findings.csv   all findings with severity, evidence and MITRE ids
  timeline.csv                   unified UTC timeline from every source
  system_info.json               host profile
  collection.log                 what ran, when, and any errors
  collection_stats.csv           per-collector timing
  manifest.sha256.csv            SHA-256 of every output file (integrity / chain of custody)
  raw\                           every artifact as CSV, process tree, audit policy, BITS, observed indicators
  evtx\                          exported event logs for offline analysis (Hayabusa, Chainsaw, EvtxECmd)
  files\                         Amcache, PSReadLine histories, raw artifacts, flagged files (<sha256>.bin)
  memory\                        physical memory image (only with -MemoryDump, kept out of the ZIP)
WDCase_<HOST>_<timestamp>.zip + .zip.sha256
```

**Verdict logic:** any Critical finding means **COMPROMISED**, 3 or more High findings means **HIGHLY SUSPICIOUS**, any High means **SUSPICIOUS**, 5 or more Medium means **NEEDS REVIEW**, otherwise **NO STRONG INDICATORS**. The report also generates recommended next steps (containment, credential resets, ransomware handling, and so on) from what was found.

---

## Adding threat intelligence

- **IOCs:** put one indicator per line in `iocs\hashes.txt`, `iocs\ips.txt` or `iocs\domains.txt`, optionally followed by `, description`. `hashes.txt` ships with the harmless EICAR test hashes so you can test matching.
- **YARA:** place `yara64.exe` in `tools\` and add `.yar` files to `rules\`. Starter rules are included; community sets such as signature-base work as well.
- **Detection rules:** command-line rules live in `lib\WD.Rules.ps1` as `Id, Severity, MITRE, Title, Regex`, so you can add your own in one line.

## Testing

```powershell
.\tests\Invoke-WDSelfTest.ps1
```

The self-test validates rule compilation, false-positive resistance on common benign command lines, the helper functions, MITRE mapping completeness and report rendering. It runs on Windows PowerShell 5.1 and PowerShell 7 on any OS and doesn't touch the host.

## Forensic notes

- Run as **Administrator**. Without it the Security log, Amcache, hidden tasks and other users' data are unavailable, and the report warns you.
- Write output to **external media** (`-OutputPath E:\Cases`) to avoid overwriting deleted data on the evidence disk.
- Capture **memory first** (`-MemoryDump`) if you suspect fileless malware. Never reboot a suspect host before memory capture.
- Locked files (hives, Amcache, SRUM) are copied through Volume Shadow Copy (`esentutl /vss`).
- `-CollectRawArtifacts` copies the SAM and SECURITY hives, which contain credential material. Handle the case folder as sensitive evidence.
- This is automated triage, not a verdict of a court. Validate each High or Critical finding before acting on it.

## Project layout

```
WindowsDetective.ps1        entry point / orchestration
Run-WindowsDetective.bat    double-click launcher (self-elevates)
lib\WD.Core.ps1             context, findings, timeline, file/registry/event helpers
lib\WD.Rules.ps1            detection rules, tool/RMM/BYOVD intel, masquerading, MITRE names
lib\WD.System.ps1           host profile, patches, software, accounts
lib\WD.Processes.ps1        live process analysis
lib\WD.Network.ps1          connections, DNS, hosts, proxy, portproxy, firewall, RDP
lib\WD.Persistence.ps1      30+ autostart locations
lib\WD.Execution.ps1        Prefetch, BAM, ShimCache, Amcache, UserAssist, RunMRU, PSReadLine
lib\WD.EventLogs.ps1        Security/System/PowerShell/RDP/Defender/Sysmon/... analysis
lib\WD.FileSystem.ps1       file sweep, MOTW, ransom notes, USB, browser extensions
lib\WD.Security.ps1         Defender, drivers (BYOVD), hardening controls
lib\WD.Evidence.ps1         IOC matching, YARA, memory capture, EVTX export, raw artifacts, manifest
lib\WD.Report.ps1           HTML / JSON / CSV reporting
iocs\  rules\  tools\  tests\
```

## License

MIT - see [LICENSE](LICENSE).

---

**Windows Detective - Powered by Bashar Salmo**
