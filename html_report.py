"""
reporting/html_report.py
HTML export — dark-theme, timeline chart, severity/endpoint filters,
copy-to-clipboard payloads, confidence bars.
Called by BaseScanner.run() after scan completion.
"""
from __future__ import annotations

import html as html_mod
import json
import time
from collections import defaultdict
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.scanner import BaseScanner


_SEV_COLORS = {
    "Critical": "#e74c3c",
    "High":     "#e67e22",
    "Medium":   "#3498db",
    "Low":      "#2ecc71",
}


def export_html(scanner: "BaseScanner", filename: str = None) -> str:
    """Export scan results to a self-contained HTML file.

    Args:
        scanner:  Completed BaseScanner instance.
        filename: Output path; auto-generated if omitted.

    Returns:
        Path of the written file.
    """
    if not filename:
        filename = f"scan_report_{int(time.time())}.html"

    def esc(s: object) -> str:
        return html_mod.escape(str(s))

    # ── Vulnerability rows (sorted by CVSS desc) ──────────────────────────
    rows = ""
    for i, v in enumerate(sorted(scanner.results, key=lambda x: x.cvss_score, reverse=True)):
        color        = _SEV_COLORS.get(v.severity, "#95a5a6")
        payload_esc  = esc(v.payload[:120])
        remediation  = v.remediation or ""
        rows += f"""
        <tr data-sev="{esc(v.severity)}" data-url="{esc(v.url)}">
          <td><span class="sev-badge" style="background:{color}">{esc(v.severity)}</span></td>
          <td>{esc(v.type)}</td>
          <td style="word-break:break-all;font-size:0.82em">{esc(v.url)}</td>
          <td><code>{esc(v.parameter)}</code></td>
          <td style="font-size:0.78em;word-break:break-all">
            <code id="payload-{i}">{payload_esc}</code>
            <button class="copy-btn" onclick="copyText('payload-{i}')" title="Copy payload">&#128203;</button>
          </td>
          <td style="font-size:0.82em">{esc(v.evidence[:120])}</td>
          <td>{esc(v.cvss_score)}</td>
          <td>
            <div class="conf-bar-wrap" title="{v.confidence_pct}%">
              <div class="conf-bar" style="width:{v.confidence_pct}%;background:{color}"></div>
            </div>
            <small>{v.confidence_pct}%</small>
          </td>
          <td>{esc(v.method)}</td>
          <td style="font-size:0.75em;color:#8b949e;max-width:200px;word-break:break-word"
              title="{esc(remediation)}">{esc(remediation[:80])}{'…' if len(remediation) > 80 else ''}</td>
          <td style="font-size:0.78em;color:#888">{esc(v.timestamp)}</td>
        </tr>"""

    # ── Summary rows ──────────────────────────────────────────────────────
    summary_rows = ""
    by_sev: dict = defaultdict(int)
    for v in scanner.results:
        by_sev[v.severity] += 1
    for sev in ["Critical", "High", "Medium", "Low"]:
        c = _SEV_COLORS.get(sev, "#95a5a6")
        summary_rows += (
            f'<tr><td style="color:{c};font-weight:bold">{sev}</td>'
            f'<td>{by_sev[sev]}</td></tr>'
        )

    # ── Timeline chart data ───────────────────────────────────────────────
    if scanner.results:
        sorted_vulns        = sorted(scanner.results, key=lambda x: x.timestamp)
        timeline_labels     = json.dumps([v.timestamp[11:19] for v in sorted_vulns])
        timeline_data_crit  = json.dumps([1 if v.severity == "Critical" else 0 for v in sorted_vulns])
        timeline_data_high  = json.dumps([1 if v.severity == "High"     else 0 for v in sorted_vulns])
        timeline_data_med   = json.dumps([1 if v.severity == "Medium"   else 0 for v in sorted_vulns])
        timeline_data_low   = json.dumps([1 if v.severity == "Low"      else 0 for v in sorted_vulns])
    else:
        timeline_labels     = "[]"
        timeline_data_crit  = "[]"
        timeline_data_high  = "[]"
        timeline_data_med   = "[]"
        timeline_data_low   = "[]"

    scan_time    = time.time() - scanner.scan_start
    waf_badge    = (
        f'<span>WAF: <b style="color:#e74c3c">{esc(scanner.waf_type)}</b></span>'
        if scanner.waf_detected else ""
    )
    auth_warning = (
        '<span style="color:#e74c3c">⚠ Auth failed — results may be incomplete</span>'
        if getattr(scanner, "_auth_failed", False) else ""
    )

    endpoints     = sorted({v.url for v in scanner.results})
    endpoint_opts = "".join(
        f'<option value="{esc(ep)}">{esc(ep)}</option>' for ep in endpoints
    )

    no_vulns_row = (
        '<tr><td colspan="11" style="text-align:center;color:#888;padding:30px">'
        "No vulnerabilities found</td></tr>"
    )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Scan Report — {esc(scanner.base_url)}</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9;padding:24px}}
    h1{{color:#58a6ff;margin-bottom:8px}}
    h2{{color:#8b949e;border-bottom:1px solid #21262d;padding-bottom:6px;margin:20px 0 10px}}
    table{{width:100%;border-collapse:collapse;margin-bottom:30px;font-size:0.88em}}
    th{{background:#161b22;color:#58a6ff;padding:10px;text-align:left;position:sticky;top:0;z-index:1}}
    td{{padding:7px 10px;border-bottom:1px solid #21262d;vertical-align:top}}
    tr:hover{{background:#161b22}}
    code{{background:#0d1117;border:1px solid #21262d;padding:2px 5px;border-radius:3px;
          color:#7ee787;font-size:0.9em}}
    .meta{{background:#161b22;padding:16px;border-radius:8px;margin-bottom:20px;
           display:flex;flex-wrap:wrap;gap:16px;align-items:center}}
    .meta span{{color:#8b949e}} .meta b{{color:#58a6ff}}
    .sev-badge{{display:inline-block;padding:2px 8px;border-radius:12px;
               font-size:0.78em;font-weight:bold;color:#fff}}
    .filter-bar{{margin-bottom:12px;display:flex;flex-wrap:wrap;gap:8px;align-items:center}}
    .filter-bar button{{background:#161b22;color:#8b949e;border:1px solid #30363d;
      padding:5px 13px;cursor:pointer;border-radius:20px;font-size:0.85em;transition:all 0.2s}}
    .filter-bar button:hover,.filter-bar button.active{{
      background:#1f6feb;color:#fff;border-color:#1f6feb}}
    .filter-bar select{{background:#161b22;color:#8b949e;border:1px solid #30363d;
      padding:5px 10px;border-radius:20px;font-size:0.85em}}
    .conf-bar-wrap{{background:#21262d;border-radius:4px;height:6px;width:80px;
                    display:inline-block;vertical-align:middle;margin-right:4px}}
    .conf-bar{{height:6px;border-radius:4px;transition:width 0.3s}}
    .copy-btn{{background:none;border:none;cursor:pointer;color:#8b949e;
               font-size:0.9em;margin-left:4px;padding:0 3px}}
    .copy-btn:hover{{color:#58a6ff}}
    .chart-wrap{{background:#161b22;border-radius:8px;padding:16px;
                 margin-bottom:24px;max-height:280px}}
    .toast{{position:fixed;bottom:20px;right:20px;background:#238636;color:#fff;
            padding:10px 18px;border-radius:8px;font-size:0.9em;
            opacity:0;pointer-events:none;transition:opacity 0.3s}}
  </style>
</head>
<body>
  <h1>&#128269; V28 Ultimate Security Scan Report</h1>
  <div class="meta">
    <span>Target: <b>{esc(scanner.base_url)}</b></span>
    <span>Scan Time: <b>{scan_time:.1f}s</b></span>
    <span>Requests: <b>{scanner.request_count}</b></span>
    <span>URLs Scanned: <b>{len(scanner.seen_urls)}</b></span>
    <span>Vulnerabilities: <b>{len(scanner.results)}</b></span>
    <span>Generated: <b>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</b></span>
    {waf_badge}
    {auth_warning}
  </div>

  <h2>Summary by Severity</h2>
  <table style="width:220px">
    <tr><th>Severity</th><th>Count</th></tr>
    {summary_rows}
  </table>

  <h2>Discovery Timeline</h2>
  <div class="chart-wrap">
    <canvas id="timelineChart" height="80"></canvas>
  </div>

  <h2>Vulnerabilities ({len(scanner.results)})</h2>
  <div class="filter-bar">
    <b style="color:#8b949e">Severity:</b>
    <button class="active" onclick="filterSev('', this)">All</button>
    <button onclick="filterSev('Critical', this)" style="color:#e74c3c">Critical</button>
    <button onclick="filterSev('High', this)"     style="color:#e67e22">High</button>
    <button onclick="filterSev('Medium', this)"   style="color:#3498db">Medium</button>
    <button onclick="filterSev('Low', this)"      style="color:#2ecc71">Low</button>
    <b style="color:#8b949e;margin-left:12px">Endpoint:</b>
    <select onchange="filterEndpoint(this.value)">
      <option value="">All endpoints</option>
      {endpoint_opts}
    </select>
  </div>

  <table id="vulnTable">
    <tr>
      <th>Severity</th><th>Type</th><th>URL</th><th>Param</th>
      <th>Payload</th><th>Evidence</th><th>CVSS</th><th>Confidence</th>
      <th>Method</th><th>Remediation</th><th>Time</th>
    </tr>
    {rows if rows else no_vulns_row}
  </table>

  <p style="color:#30363d;font-size:0.78em;margin-top:20px">
    Generated by V28 Ultimate Scanner &bull; For Authorized Testing Only
  </p>

  <div class="toast" id="toast">Copied!</div>

  <script>
    // Timeline chart
    new Chart(document.getElementById('timelineChart'), {{
      type: 'bar',
      data: {{
        labels: {timeline_labels},
        datasets: [
          {{label:'Critical', data:{timeline_data_crit}, backgroundColor:'#e74c3c'}},
          {{label:'High',     data:{timeline_data_high}, backgroundColor:'#e67e22'}},
          {{label:'Medium',   data:{timeline_data_med},  backgroundColor:'#3498db'}},
          {{label:'Low',      data:{timeline_data_low},  backgroundColor:'#2ecc71'}},
        ]
      }},
      options: {{
        responsive: true, maintainAspectRatio: false,
        plugins: {{
          legend: {{labels: {{color: '#8b949e'}}}},
          tooltip: {{mode: 'index'}}
        }},
        scales: {{
          x: {{stacked:true, ticks:{{color:'#8b949e',maxRotation:45}}, grid:{{color:'#21262d'}}}},
          y: {{stacked:true, ticks:{{color:'#8b949e',stepSize:1}},    grid:{{color:'#21262d'}}}}
        }}
      }}
    }});

    // Severity + endpoint filtering
    var _activeSev = '', _activeUrl = '';
    function filterSev(sev, btn) {{
      _activeSev = sev;
      document.querySelectorAll('.filter-bar button').forEach(b => b.classList.remove('active'));
      if (btn) btn.classList.add('active');
      filterRows();
    }}
    function filterEndpoint(ep) {{ _activeUrl = ep; filterRows(); }}
    function filterRows() {{
      document.querySelectorAll('#vulnTable tr[data-sev]').forEach(function(r) {{
        var sevOk = !_activeSev || r.dataset.sev === _activeSev;
        var urlOk = !_activeUrl || r.dataset.url === _activeUrl;
        r.style.display = (sevOk && urlOk) ? '' : 'none';
      }});
    }}

    // Copy to clipboard
    function copyText(id) {{
      var el = document.getElementById(id);
      var txt = el ? el.innerText : '';
      navigator.clipboard.writeText(txt).then(function() {{
        var t = document.getElementById('toast');
        t.style.opacity = '1';
        setTimeout(function() {{ t.style.opacity = '0'; }}, 1500);
      }});
    }}
  </script>
</body>
</html>"""

    with open(filename, "w") as f:
        f.write(html_content)
    print(f"[+] HTML report: {filename}")
    return filename


# ── Markdown export (bonus — lives here to keep reporting/ cohesive) ─────────

def export_md(scanner: "BaseScanner", filename: str = None) -> str:
    """Export scan results to a Markdown file (GitHub Issues / Notion friendly).

    Args:
        scanner:  Completed BaseScanner instance.
        filename: Output path; auto-generated if omitted.

    Returns:
        Path of the written file.
    """
    if not filename:
        filename = f"scan_report_{int(time.time())}.md"

    scan_time = time.time() - scanner.scan_start
    by_sev: dict = defaultdict(list)
    for v in scanner.results:
        by_sev[v.severity].append(v)

    lines = [
        "# 🔍 V28 Ultimate Security Scan Report",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Target** | `{scanner.base_url}` |",
        f"| **Scan Time** | {scan_time:.1f}s |",
        f"| **Requests** | {scanner.request_count} |",
        f"| **URLs Scanned** | {len(scanner.seen_urls)} |",
        f"| **Total Findings** | {len(scanner.results)} |",
        f"| **WAF Detected** | {'✅ ' + scanner.waf_type if scanner.waf_detected else 'No'} |",
        f"| **Generated** | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ["Critical", "High", "Medium", "Low"]:
        lines.append(f"| {sev} | {len(by_sev[sev])} |")
    lines.append("")

    if not scanner.results:
        lines.append("✅ **No vulnerabilities detected.**")
    else:
        sev_emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
        for sev in ["Critical", "High", "Medium", "Low"]:
            vulns = by_sev[sev]
            if not vulns:
                continue
            lines.append(f"## {sev_emoji.get(sev, '⚪')} {sev} ({len(vulns)})")
            lines.append("")
            for idx, v in enumerate(vulns, 1):
                lines += [
                    f"### {idx}. {v.type}",
                    "",
                    "| Field | Value |",
                    "|-------|-------|",
                    f"| **URL** | `{v.url}` |",
                    f"| **Parameter** | `{v.parameter}` |",
                    f"| **Method** | `{v.method}` |",
                    f"| **CVSS** | {v.cvss_score} |",
                    f"| **Confidence** | {v.confidence} ({v.confidence_pct}%) |",
                    f"| **Detected** | {v.timestamp} |",
                    "",
                    "**Payload**",
                    "```",
                    f"{v.payload[:300]}",
                    "```",
                    "",
                    f"**Evidence:** {v.evidence}",
                    "",
                    f"**Remediation:** {v.remediation or '_No remediation note_'}",
                    "",
                    f"**References:** {', '.join(v.references)}",
                    "",
                    "---",
                    "",
                ]

    lines.append("_Report generated by V28 Ultimate Scanner — For Authorized Testing Only_")

    with open(filename, "w") as f:
        f.write("\n".join(lines))
    print(f"[+] Markdown report: {filename}")
    return filename
