# =============================================================================
#  Windows Detective - Report generation (HTML, JSON, CSV)
#  Powered by Bashar Salmo
#  WD-SELF-MARKER
# =============================================================================

function ConvertTo-WDHtml { param($Text) return [System.Net.WebUtility]::HtmlEncode([string]$Text) }

function ConvertTo-WDJsonSafe {
    param($Data)
    $json = ConvertTo-Json -InputObject $Data -Depth 4 -Compress
    if (-not $json) { $json = '[]' }
    return $json.Replace('</', '<\/').Replace([string][char]0x2028, ('\' + 'u2028')).Replace([string][char]0x2029, ('\' + 'u2029'))
}

function Get-WDSeverityCounts {
    $c = [ordered]@{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
    foreach ($f in $script:WD.Findings) { $c[$f.Severity]++ }
    return $c
}

function Get-WDVerdict {
    $c = Get-WDSeverityCounts
    $score = 0
    foreach ($f in $script:WD.Findings) { $score += $script:WDSeverityWeight[$f.Severity] }
    $score = [Math]::Min(100, $score)
    if ($c.Critical -gt 0) { return [pscustomobject]@{ Level = 'COMPROMISED'; Css = 'crit'; Score = $score; Text = 'Critical indicators of compromise were found. Treat this host as compromised: contain it and start incident response now.' } }
    if ($c.High -ge 3) { return [pscustomobject]@{ Level = 'HIGHLY SUSPICIOUS'; Css = 'high'; Score = $score; Text = 'Multiple high-severity indicators were found. Compromise is likely until each one is explained.' } }
    if ($c.High -gt 0) { return [pscustomobject]@{ Level = 'SUSPICIOUS'; Css = 'high'; Score = $score; Text = 'High-severity indicators were found and need analyst validation.' } }
    if ($c.Medium -ge 5) { return [pscustomobject]@{ Level = 'NEEDS REVIEW'; Css = 'med'; Score = $score; Text = 'Several anomalies were found. None is conclusive on its own; review them together with the timeline.' } }
    return [pscustomobject]@{ Level = 'NO STRONG INDICATORS'; Css = 'ok'; Score = $score; Text = 'No strong indicators of compromise were detected. This does not prove the host is clean; review the timeline and consider memory/disk forensics if suspicion remains.' }
}

function Get-WDRecommendations {
    $c = Get-WDSeverityCounts
    $all = ($script:WD.Findings | ForEach-Object { "$($_.Category)|$($_.Title)|$($_.Mitre)" }) -join "`n"
    $r = New-Object System.Collections.Generic.List[string]
    if ($c.Critical -gt 0 -or $c.High -gt 0) {
        $r.Add('<b>Contain the host</b>: isolate it from the network (EDR network containment, or disconnect the cable / disable Wi-Fi) but keep it <b>powered on</b> to preserve volatile evidence.')
        if (-not $script:WD.MemoryImage) { $r.Add('<b>Capture memory before any reboot</b>: re-run with <code>-MemoryDump</code> (winpmem in tools\) or use your EDR live-response memory acquisition.') }
    }
    if ($all -match 'T1003|T1555|T1558|Credential Access|brute|spraying|WDigest') {
        $r.Add('<b>Assume credentials are stolen</b>: reset passwords for every account that logged on to this host, revoke sessions/refresh tokens (Entra ID / M365), rotate local admin passwords (LAPS). If domain admin credentials were exposed, plan a double KRBTGT reset.')
    }
    if ($all -match 'Persistence') { $r.Add('<b>Scope persistence before removing it</b>: document every entry in the Persistence findings and the Autoruns artifact, then hunt for the same names/hashes on other hosts before cleaning.') }
    if ($all -match 'T1219|Remote access tool') { $r.Add('<b>Validate remote-access tools</b> (AnyDesk, ScreenConnect, etc.) against the approved software list; unauthorised RMM tools are a top hands-on-keyboard vector. Review their own logs (e.g. AnyDesk ad.trace / connection_trace.txt).') }
    if ($all -match 'T1070\.001|log was cleared|Event log cleared') { $r.Add('<b>Local logs were tampered with</b>: retrieve the same period from your SIEM / Windows Event Forwarding and EDR telemetry.') }
    if ($all -match 'T1562\.001|Defender') { $r.Add('<b>Restore security controls</b>: remove unauthorised Defender exclusions, re-enable real-time and Tamper Protection, then run a Microsoft Defender Offline scan.') }
    if ($all -match 'T1490|T1486|ransom') { $r.Add('<b>Treat as a potential ransomware incident</b>: protect backups (take them offline), check other hosts for the same indicators and engage your IR retainer / cyber insurer.') }
    if ($all -match 'IOC Match|YARA') { $r.Add('<b>Block matched indicators</b> (hashes, IPs, domains) at EDR, proxy, DNS and firewall and hunt for them fleet-wide.') }
    if ($all -match 'Network|public IP') { $r.Add('<b>Review outbound traffic</b> for the public IPs in <code>raw\ObservedIndicators.csv</code> in firewall/proxy logs to identify C2 and exfiltration volume (SRUM in raw artifacts shows per-app bytes).') }
    if ($all -match 'Visibility') { $r.Add('<b>Close visibility gaps</b>: enable process creation auditing with command line, PowerShell Script Block Logging, and deploy Sysmon so future investigations have full telemetry.') }
    $r.Add('<b>Preserve this case folder</b> unchanged; verify integrity with <code>manifest.sha256.csv</code> and the archive hash, and record hand-overs for chain of custody.')
    $r.Add('<b>Validate every finding</b>: this is automated triage. Confirm each High/Critical item manually (hash lookup on VirusTotal, signer and path checks) before drawing conclusions.')
    return $r
}

function New-WDArtifactTable {
    param($Artifact, [int]$MaxRows = 250)
    $rows = @($Artifact.Rows)
    if ($rows.Count -eq 0) { return '<p class="muted">No entries.</p>' }
    $cols = @($rows[0].PSObject.Properties | ForEach-Object { $_.Name })
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="tablewrap"><table class="data"><thead><tr>')
    foreach ($c in $cols) { [void]$sb.Append('<th>' + (ConvertTo-WDHtml $c) + '</th>') }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($row in ($rows | Select-Object -First $MaxRows)) {
        [void]$sb.Append('<tr>')
        foreach ($c in $cols) { [void]$sb.Append('<td>' + (ConvertTo-WDHtml (Limit-WDText ([string]$row.$c) 400)) + '</td>') }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    if ($rows.Count -gt $MaxRows) { [void]$sb.Append("<p class=""muted"">Showing first $MaxRows of $($rows.Count) rows - full data in <code>raw\$($Artifact.Name).csv</code>.</p>") }
    return $sb.ToString()
}

function Export-WDReport {
    $script:WD.EndTime = Get-Date
    # Order and number findings
    $sorted = @($script:WD.Findings | Sort-Object @{ e = { $script:WDSeverityOrder[$_.Severity] } }, @{ e = { $_.LastSeen }; Descending = $true }, Category, Title)
    $i = 0
    foreach ($f in $sorted) { $i++; $f.Id = 'WD-{0:D4}' -f $i }

    # Machine-readable outputs
    $sorted | Export-Csv -LiteralPath (Join-Path $script:WD.CaseDir 'findings.csv') -NoTypeInformation -Encoding UTF8
    [IO.File]::WriteAllText((Join-Path $script:WD.CaseDir 'findings.json'), (ConvertTo-Json -InputObject @($sorted) -Depth 4), [Text.Encoding]::UTF8)
    $timeline = @($script:WD.Timeline | Sort-Object TimeUtc -Descending)
    $timeline | Export-Csv -LiteralPath (Join-Path $script:WD.CaseDir 'timeline.csv') -NoTypeInformation -Encoding UTF8
    $script:WD.SystemInfo | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $script:WD.CaseDir 'system_info.json') -Encoding UTF8
    $script:WD.CollectorStats | Export-Csv -LiteralPath (Join-Path $script:WD.CaseDir 'collection_stats.csv') -NoTypeInformation -Encoding UTF8

    # Timeline for the HTML: all non-Info events plus most recent Info events, capped
    $tlNotable = @($timeline | Where-Object { $_.Severity -ne 'Info' } | Select-Object -First 4000)
    $tlInfo = @($timeline | Where-Object { $_.Severity -eq 'Info' } | Select-Object -First ([Math]::Max(0, 6000 - $tlNotable.Count)))
    $tlHtml = @(@($tlNotable) + @($tlInfo) | Sort-Object TimeUtc -Descending)

    $counts = Get-WDSeverityCounts
    $verdict = Get-WDVerdict
    $recs = Get-WDRecommendations
    $o = $script:WD.Options
    $host_ = $env:COMPUTERNAME

    # MITRE summary
    $mitre = @{}
    foreach ($f in $sorted) {
        foreach ($t in ($f.Mitre -split ',' | Where-Object { $_ })) {
            $t = $t.Trim()
            if (-not $mitre.ContainsKey($t)) { $mitre[$t] = [pscustomobject]@{ Id = $t; Name = (Get-WDMitreName $t); Count = 0; Worst = 'Info' } }
            $mitre[$t].Count++
            if ($script:WDSeverityOrder[$f.Severity] -lt $script:WDSeverityOrder[$mitre[$t].Worst]) { $mitre[$t].Worst = $f.Severity }
        }
    }
    $mitreRows = @($mitre.Values | Sort-Object @{ e = { $script:WDSeverityOrder[$_.Worst] } }, @{ e = { $_.Count }; Descending = $true })

    $sb = New-Object System.Text.StringBuilder
    $css = Get-WDReportCss
    $js = Get-WDReportJs
    [void]$sb.Append(@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Windows Detective - $(ConvertTo-WDHtml $host_)</title>
<style>$css</style></head><body>
<header class="hero"><div class="hero-in">
  <div class="brand">
    <svg class="logo" viewBox="0 0 64 64" aria-hidden="true"><circle cx="26" cy="26" r="17" fill="none" stroke="currentColor" stroke-width="5"/><path d="M38.5 38.5 L56 56" stroke="currentColor" stroke-width="7" stroke-linecap="round"/><path d="M16 20h20M16 26h14M16 32h18" stroke="currentColor" stroke-width="3" stroke-linecap="round" opacity=".7"/></svg>
    <div><h1>Windows Detective</h1><div class="sub">Forensic Triage &amp; Compromise Assessment Report</div></div>
  </div>
  <div class="powered">Powered by <strong>Bashar Salmo</strong></div>
</div></header>
<nav class="toc"><div class="toc-in">
  <a href="#summary">Summary</a><a href="#actions">Actions</a><a href="#findings">Findings <span class="pill">$($sorted.Count)</span></a><a href="#mitre">ATT&amp;CK</a><a href="#timeline">Timeline</a><a href="#artifacts">Artifacts</a><a href="#collection">Collection</a>
</div></nav>
<main>
<section id="summary">
  <div class="verdict $($verdict.Css)">
    <div class="v-left"><div class="v-label">Verdict</div><div class="v-level">$($verdict.Level)</div><p>$(ConvertTo-WDHtml $verdict.Text)</p></div>
    <div class="v-score"><div class="score-num">$($verdict.Score)</div><div class="score-lbl">risk score / 100</div></div>
  </div>
  <div class="tiles">
    <div class="tile sev-Critical"><b>$($counts.Critical)</b><span>Critical</span></div>
    <div class="tile sev-High"><b>$($counts.High)</b><span>High</span></div>
    <div class="tile sev-Medium"><b>$($counts.Medium)</b><span>Medium</span></div>
    <div class="tile sev-Low"><b>$($counts.Low)</b><span>Low</span></div>
    <div class="tile sev-Info"><b>$($counts.Info)</b><span>Info</span></div>
  </div>
  <h2>Case details</h2>
  <div class="kv">
"@)
    $case = [ordered]@{
        'Case ID' = $o.CaseId; 'Analyst' = $o.Analyst; 'Tool' = "$script:WDToolName v$script:WDVersion ($script:WDBrand)"
        'Collection start (UTC)' = (ConvertTo-WDTimeString $script:WD.StartTime); 'Collection end (UTC)' = (ConvertTo-WDTimeString $script:WD.EndTime)
        'Duration' = ('{0:mm\:ss}' -f ($script:WD.EndTime - $script:WD.StartTime)); 'Investigation window' = "Last $($o.Days) days (since $(ConvertTo-WDTimeString $script:WD.Since) UTC)"
        'Mode' = $(if ($o.Deep) { 'Deep' } elseif ($o.Quick) { 'Quick' } else { 'Standard' }); 'Memory image' = $(if ($script:WD.MemoryImage) { 'Captured' } else { 'Not captured' })
    }
    foreach ($k in $case.Keys) { [void]$sb.Append("<div><span>$(ConvertTo-WDHtml $k)</span><b>$(ConvertTo-WDHtml $case[$k])</b></div>") }
    foreach ($k in $script:WD.SystemInfo.Keys) { [void]$sb.Append("<div><span>$(ConvertTo-WDHtml $k)</span><b>$(ConvertTo-WDHtml $script:WD.SystemInfo[$k])</b></div>") }
    [void]$sb.Append('</div>')
    if (-not $script:WD.IsAdmin) { [void]$sb.Append('<div class="warn">This collection ran <b>without administrator rights</b>. Security log, Amcache, hidden tasks, other users'' data and several other sources were unavailable. Re-run elevated for full coverage.</div>') }
    [void]$sb.Append('</section>')

    # Recommended actions
    [void]$sb.Append('<section id="actions"><h2>Recommended next steps</h2><ol class="actions">')
    foreach ($r in $recs) { [void]$sb.Append("<li>$r</li>") }
    [void]$sb.Append('</ol></section>')

    # Findings (rendered by JS)
    $cats = @($sorted | Select-Object -ExpandProperty Category -Unique | Sort-Object)
    [void]$sb.Append(@"
<section id="findings"><h2>Findings</h2>
<div class="controls">
  <div class="sevfilter">
    <button class="chip sev-Critical on" data-sev="Critical">Critical</button><button class="chip sev-High on" data-sev="High">High</button><button class="chip sev-Medium on" data-sev="Medium">Medium</button><button class="chip sev-Low on" data-sev="Low">Low</button><button class="chip sev-Info" data-sev="Info">Info</button>
  </div>
  <select id="fcat"><option value="">All categories</option>$(($cats | ForEach-Object { "<option>$(ConvertTo-WDHtml $_)</option>" }) -join '')</select>
  <input id="fsearch" type="search" placeholder="Search findings, evidence, ATT&amp;CK id...">
  <span id="fcount" class="muted"></span>
</div>
<div class="tablewrap"><table class="findings"><thead><tr><th>ID</th><th>Severity</th><th>Category</th><th>Finding</th><th>ATT&amp;CK</th><th>First seen (UTC)</th><th>Last seen (UTC)</th><th>#</th></tr></thead><tbody id="fbody"></tbody></table></div>
<p class="muted">Click a finding to see the evidence. Info items are hidden by default.</p>
</section>
"@)

    # MITRE
    [void]$sb.Append('<section id="mitre"><h2>MITRE ATT&amp;CK techniques observed</h2>')
    if ($mitreRows.Count -eq 0) { [void]$sb.Append('<p class="muted">No techniques mapped.</p>') }
    else {
        [void]$sb.Append('<div class="mitre-grid">')
        foreach ($m in $mitreRows) {
            $url = 'https://attack.mitre.org/techniques/' + ($m.Id -replace '\.', '/') + '/'
            [void]$sb.Append("<a class=""tech sev-$($m.Worst)"" href=""$url"" target=""_blank"" rel=""noopener""><b>$($m.Id)</b><span>$(ConvertTo-WDHtml $m.Name)</span><em>$($m.Count) finding(s)</em></a>")
        }
        [void]$sb.Append('</div>')
    }
    [void]$sb.Append('</section>')

    # Timeline
    [void]$sb.Append(@"
<section id="timeline"><h2>Timeline <span class="muted small">(UTC, newest first)</span></h2>
<div class="controls"><select id="tsev"><option value="Info">All events</option><option value="Low" selected>Low and above</option><option value="Medium">Medium and above</option><option value="High">High and above</option></select>
<input id="tsearch" type="search" placeholder="Search timeline..."><span id="tcount" class="muted"></span></div>
<div class="tablewrap"><table class="data"><thead><tr><th>Time (UTC)</th><th>Severity</th><th>Source</th><th>Event</th><th>Detail</th></tr></thead><tbody id="tbody"></tbody></table></div>
<button id="tmore" class="btn">Show more</button>
<p class="muted">$($timeline.Count) timeline events collected; full list in <code>timeline.csv</code>.</p>
</section>
"@)

    # Artifacts
    [void]$sb.Append('<section id="artifacts"><h2>Collected artifacts</h2><p class="muted">Every artifact is also saved as CSV under <code>raw\</code>. Click to expand.</p>')
    foreach ($sec in @($script:WD.Artifacts.Values | Select-Object -ExpandProperty Section -Unique)) {
        [void]$sb.Append("<h3>$(ConvertTo-WDHtml $sec)</h3>")
        foreach ($a in @($script:WD.Artifacts.Values | Where-Object { $_.Section -eq $sec })) {
            [void]$sb.Append("<details class=""art""><summary><b>$(ConvertTo-WDHtml $a.Name)</b> <span class=""pill"">$($a.Count)</span> <span class=""muted"">$(ConvertTo-WDHtml $a.Description)</span></summary>")
            [void]$sb.Append((New-WDArtifactTable $a))
            [void]$sb.Append('</details>')
        }
    }
    [void]$sb.Append('</section>')

    # Collection log
    [void]$sb.Append('<section id="collection"><h2>Collection log &amp; evidence integrity</h2>')
    [void]$sb.Append((New-WDArtifactTable ([pscustomobject]@{ Name = 'collection_stats'; Rows = $script:WD.CollectorStats.ToArray() }) 200))
    [void]$sb.Append('<p>All output files are hashed (SHA-256) in <code>manifest.sha256.csv</code>; the case archive hash is written next to the ZIP. The tool only reads from the system - it does not modify, delete or quarantine anything on the host (offline user hives are mounted read-only only with <code>-LoadUserHives</code>).</p>')
    [void]$sb.Append('</section></main>')
    [void]$sb.Append("<footer><div>$script:WDToolName v$script:WDVersion &middot; <b>Powered by Bashar Salmo</b></div><div class=""muted"">Generated $(ConvertTo-WDTimeString (Get-Date)) UTC on $(ConvertTo-WDHtml $host_) &middot; Automated triage - validate findings before acting.</div></footer>")

    $fjson = ConvertTo-WDJsonSafe @($sorted | Select-Object Id, Severity, Category, Title, Detail, Evidence, Mitre, Source, FirstSeen, LastSeen, Occurrences)
    $tjson = ConvertTo-WDJsonSafe @($tlHtml | Select-Object TimeUtc, Severity, Source, Description, Detail)
    [void]$sb.Append("<script id=""wd-findings"" type=""application/json"">$fjson</script>")
    [void]$sb.Append("<script id=""wd-timeline"" type=""application/json"">$tjson</script>")
    [void]$sb.Append("<script>$js</script></body></html>")

    $path = Join-Path $script:WD.CaseDir 'WindowsDetective_Report.html'
    [IO.File]::WriteAllText($path, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
    return $path
}

function Get-WDReportCss {
    return @'
:root{--bg:#f4f6f9;--card:#fff;--ink:#14202e;--muted:#5b6b7c;--line:#dde3ea;--hero:#0b1d33;--hero2:#12355b;--accent:#1f8fff;
--crit:#b3261e;--high:#e8590c;--med:#d4a106;--low:#1c6fd1;--info:#6b7a8c;--ok:#1e8e3e;--code:#eef2f7}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--card:#161b22;--ink:#e6edf3;--muted:#8b98a8;--line:#2a323d;--hero:#07111f;--hero2:#0e2745;--code:#1f2630;--med:#e3b341}}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 "Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif}
code{background:var(--code);padding:1px 5px;border-radius:4px;font:12px Consolas,"Cascadia Mono",monospace}
.hero{background:linear-gradient(120deg,var(--hero),var(--hero2));color:#fff}
.hero-in{max-width:1400px;margin:0 auto;padding:26px 24px;display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:16px}.logo{width:54px;height:54px;color:#7cc4ff}
.hero h1{margin:0;font-size:28px;letter-spacing:.5px}.sub{opacity:.8}
.powered{border:1px solid rgba(255,255,255,.35);border-radius:999px;padding:8px 16px;font-size:14px;background:rgba(255,255,255,.08)}
.powered strong{color:#7cc4ff}
.toc{position:sticky;top:0;z-index:5;background:var(--card);border-bottom:1px solid var(--line)}
.toc-in{max-width:1400px;margin:0 auto;padding:0 16px;display:flex;gap:4px;overflow-x:auto}
.toc a{color:var(--ink);text-decoration:none;padding:12px 12px;border-bottom:3px solid transparent;white-space:nowrap}.toc a:hover{border-color:var(--accent)}
main{max-width:1400px;margin:0 auto;padding:8px 24px 40px}
section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px 22px;margin:18px 0}
h2{margin:0 0 14px;font-size:20px}h3{margin:18px 0 8px;font-size:15px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px}
.muted{color:var(--muted)}.small{font-size:13px;font-weight:400}
.verdict{display:flex;justify-content:space-between;align-items:center;gap:20px;border-radius:10px;padding:18px 22px;color:#fff;flex-wrap:wrap}
.verdict.crit{background:linear-gradient(120deg,#8e1b15,var(--crit))}.verdict.high{background:linear-gradient(120deg,#b3410a,var(--high))}
.verdict.med{background:linear-gradient(120deg,#9b7600,#c99a06)}.verdict.ok{background:linear-gradient(120deg,#146c2e,var(--ok))}
.v-label{text-transform:uppercase;font-size:12px;letter-spacing:1px;opacity:.85}.v-level{font-size:30px;font-weight:700}.verdict p{margin:6px 0 0;max-width:820px}
.v-score{text-align:center;background:rgba(0,0,0,.18);border-radius:10px;padding:10px 20px}.score-num{font-size:40px;font-weight:700;line-height:1}.score-lbl{font-size:12px;opacity:.85}
.tiles{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:16px 0 8px}
.tile{border-radius:10px;padding:12px 14px;border:1px solid var(--line);border-left:6px solid var(--info);display:flex;flex-direction:column}
.tile b{font-size:26px}.tile span{color:var(--muted)}
.sev-Critical{--c:var(--crit)}.sev-High{--c:var(--high)}.sev-Medium{--c:var(--med)}.sev-Low{--c:var(--low)}.sev-Info{--c:var(--info)}
.tile.sev-Critical,.tile.sev-High,.tile.sev-Medium,.tile.sev-Low,.tile.sev-Info{border-left-color:var(--c)}
.kv{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:6px 18px}
.kv div{display:flex;flex-direction:column;border-bottom:1px dashed var(--line);padding:6px 0}.kv span{color:var(--muted);font-size:12px}.kv b{font-weight:600;word-break:break-word}
.warn{margin-top:14px;padding:12px 14px;border-radius:8px;background:rgba(232,89,12,.12);border:1px solid var(--high)}
.actions li{margin:6px 0}
.controls{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
.controls input,.controls select{padding:8px 10px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--ink);min-width:240px}
.chip{border:1px solid var(--c);color:var(--c);background:transparent;border-radius:999px;padding:5px 12px;cursor:pointer;font-weight:600}
.chip.on{background:var(--c);color:#fff}
.btn{margin-top:10px;padding:8px 14px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--ink);cursor:pointer}
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%}th,td{padding:7px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{background:var(--code);position:sticky;top:0;font-size:12px;text-transform:uppercase;letter-spacing:.4px;color:var(--muted)}
table.data td{font:12px Consolas,"Cascadia Mono",monospace;word-break:break-word;max-width:520px}
table.findings tr.f{cursor:pointer}table.findings tr.f:hover{background:var(--code)}
.sev{display:inline-block;min-width:70px;text-align:center;border-radius:6px;padding:2px 8px;font-weight:700;font-size:12px;color:#fff;background:var(--c)}
tr.d td{background:var(--code)}.d pre{white-space:pre-wrap;word-break:break-word;margin:6px 0;font:12px Consolas,"Cascadia Mono",monospace}
.d .lbl{font-weight:700;color:var(--muted);font-size:12px;text-transform:uppercase}
.pill{display:inline-block;background:var(--code);border-radius:999px;padding:0 8px;font-size:12px;color:var(--muted)}
.mitre-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:10px}
.tech{display:flex;flex-direction:column;text-decoration:none;color:var(--ink);border:1px solid var(--line);border-top:4px solid var(--c);border-radius:8px;padding:10px}
.tech span{font-size:13px}.tech em{font-size:12px;color:var(--muted);font-style:normal}
details.art{border:1px solid var(--line);border-radius:8px;margin:8px 0;padding:8px 12px}details.art summary{cursor:pointer}details.art[open] summary{margin-bottom:10px}
a.mt{color:var(--accent);text-decoration:none;margin-right:6px;white-space:nowrap}
footer{text-align:center;padding:24px;color:var(--ink)}footer b{color:var(--accent)}
@media (max-width:760px){.tiles{grid-template-columns:repeat(2,1fr)}main{padding:8px 10px}.controls input{min-width:0;flex:1}}
@media print{.toc,.controls,.btn{display:none}section{break-inside:avoid-page}details.art{display:none}body{background:#fff}}
'@
}

function Get-WDReportJs {
    return @'
(function(){
var F=JSON.parse(document.getElementById('wd-findings').textContent||'[]');
var T=JSON.parse(document.getElementById('wd-timeline').textContent||'[]');
var ORDER={Critical:0,High:1,Medium:2,Low:3,Info:4};
function esc(s){return (s==null?'':String(s)).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
function mitre(m){if(!m)return '';return m.split(',').filter(Boolean).map(function(t){t=t.trim();return '<a class="mt" target="_blank" rel="noopener" href="https://attack.mitre.org/techniques/'+t.replace('.','/')+'/">'+esc(t)+'</a>';}).join('');}
var sevOn={Critical:true,High:true,Medium:true,Low:true,Info:false};
var fb=document.getElementById('fbody'),fs=document.getElementById('fsearch'),fc=document.getElementById('fcat'),fn=document.getElementById('fcount');
function renderF(){
  var q=fs.value.toLowerCase(),cat=fc.value,h=[],n=0;
  F.forEach(function(f,i){
    if(!sevOn[f.Severity])return; if(cat&&f.Category!==cat)return;
    if(q&&(f.Id+' '+f.Title+' '+f.Evidence+' '+f.Detail+' '+f.Mitre+' '+f.Category).toLowerCase().indexOf(q)<0)return;
    n++;
    h.push('<tr class="f" data-i="'+i+'"><td>'+esc(f.Id)+'</td><td><span class="sev sev-'+f.Severity+'">'+f.Severity+'</span></td><td>'+esc(f.Category)+'</td><td>'+esc(f.Title)+'</td><td>'+mitre(f.Mitre)+'</td><td>'+esc(f.FirstSeen)+'</td><td>'+esc(f.LastSeen)+'</td><td>'+f.Occurrences+'</td></tr>');
  });
  fb.innerHTML=h.join('')||'<tr><td colspan="8" class="muted">No findings match the filter.</td></tr>';
  fn.textContent=n+' of '+F.length+' findings';
}
fb.addEventListener('click',function(e){
  var tr=e.target.closest('tr.f'); if(!tr||e.target.tagName==='A')return;
  var nx=tr.nextElementSibling; if(nx&&nx.classList.contains('d')){nx.remove();return;}
  var f=F[+tr.getAttribute('data-i')],d=document.createElement('tr');d.className='d';
  d.innerHTML='<td colspan="8">'+(f.Detail?'<div class="lbl">Detail</div><pre>'+esc(f.Detail)+'</pre>':'')+'<div class="lbl">Evidence</div><pre>'+esc(f.Evidence)+'</pre>'+(f.Source?'<div class="lbl">Source</div><pre>'+esc(f.Source)+'</pre>':'')+'</td>';
  tr.parentNode.insertBefore(d,tr.nextSibling);
});
document.querySelectorAll('.chip').forEach(function(b){b.addEventListener('click',function(){var s=b.getAttribute('data-sev');sevOn[s]=!sevOn[s];b.classList.toggle('on',sevOn[s]);renderF();});});
fs.addEventListener('input',renderF);fc.addEventListener('change',renderF);renderF();
var tb=document.getElementById('tbody'),ts=document.getElementById('tsearch'),tv=document.getElementById('tsev'),tn=document.getElementById('tcount'),tm=document.getElementById('tmore'),limit=500;
function renderT(){
  var q=ts.value.toLowerCase(),min=ORDER[tv.value],rows=T.filter(function(t){return ORDER[t.Severity]<=min&&(!q||(t.Source+' '+t.Description+' '+t.Detail).toLowerCase().indexOf(q)>=0);});
  tb.innerHTML=rows.slice(0,limit).map(function(t){return '<tr><td>'+esc(t.TimeUtc)+'</td><td><span class="sev sev-'+t.Severity+'">'+t.Severity+'</span></td><td>'+esc(t.Source)+'</td><td>'+esc(t.Description)+'</td><td>'+esc(t.Detail)+'</td></tr>';}).join('')||'<tr><td colspan="5" class="muted">No events.</td></tr>';
  tn.textContent=Math.min(limit,rows.length)+' of '+rows.length+' events shown';
  tm.style.display=rows.length>limit?'inline-block':'none';
}
tm.addEventListener('click',function(){limit+=500;renderT();});
ts.addEventListener('input',function(){limit=500;renderT();});tv.addEventListener('change',function(){limit=500;renderT();});renderT();
})();
'@
}
