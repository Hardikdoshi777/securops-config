#!/usr/bin/env python3
"""
SecurOps — Security Dashboard + Enrollment Tracking
File: scripts/generate-report.py

Generates:
1. security-dashboard.html  — Full visual HTML dashboard
2. security-summary.md      — PR comment markdown
3. enrollment-tracking.json — Who has onboarded + their scan history
"""

import os
import json
import glob
from datetime import datetime, timezone
from pathlib import Path
from jinja2 import Template

# ─────────────────────────────────────────────────────────
# READ ENV FROM GITHUB ACTIONS
# ─────────────────────────────────────────────────────────
ACTOR          = os.environ.get("ACTOR", "unknown")
REPO           = os.environ.get("REPO", "unknown/repo")
RUN_ID         = os.environ.get("RUN_ID", "0")
RUN_URL        = os.environ.get("RUN_URL", "#")
EVENT          = os.environ.get("EVENT", "push")
REF            = os.environ.get("REF", "main")
TIMESTAMP      = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

RESULTS = {
    "secrets" : {"result": os.environ.get("SECRET_RESULT", "unknown"), "count": int(os.environ.get("SECRET_COUNT", 0) or 0), "tool": "Gitleaks",  "icon": "🔐", "label": "Secrets"},
    "sast"    : {"result": os.environ.get("SAST_RESULT",   "unknown"), "count": int(os.environ.get("SAST_COUNT",   0) or 0), "tool": "Semgrep",   "icon": "🔍", "label": "SAST"},
    "sca"     : {"result": os.environ.get("SCA_RESULT",    "unknown"), "count": int(os.environ.get("SCA_COUNT",    0) or 0), "tool": "Trivy",     "icon": "🛡️", "label": "SCA"},
    "dast"    : {"result": os.environ.get("DAST_RESULT",   "unknown"), "count": int(os.environ.get("DAST_COUNT",   0) or 0), "tool": "Nuclei",    "icon": "🌐", "label": "DAST"},
    "iac"     : {"result": os.environ.get("IAC_RESULT",    "unknown"), "count": int(os.environ.get("IAC_COUNT",    0) or 0), "tool": "Checkov",   "icon": "🏗️", "label": "IaC"},
}

total_issues  = sum(r["count"] for r in RESULTS.values())
all_passed    = all(r["result"] == "success" for r in RESULTS.values())
any_failed    = any(r["result"] == "failure"  for r in RESULTS.values())
gate_status   = "PASSED" if all_passed else "FAILED"
gate_color    = "#3fb950" if all_passed else "#f85149"

# ─────────────────────────────────────────────────────────
# LOAD SCAN FINDINGS (for detailed table)
# ─────────────────────────────────────────────────────────

def load_json(pattern):
    files = glob.glob(pattern, recursive=True)
    if not files:
        return {}
    try:
        with open(files[0]) as f:
            return json.load(f)
    except Exception:
        return {}

def load_jsonl(pattern):
    files = glob.glob(pattern, recursive=True)
    rows = []
    if not files:
        return rows
    try:
        with open(files[0]) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except Exception:
                        pass
    except Exception:
        pass
    return rows

findings = []

# SAST findings
sast_data = load_json("reports/report-sast/semgrep.json")
for r in sast_data.get("results", [])[:20]:
    sev = r.get("extra", {}).get("severity", "WARNING")
    findings.append({
        "tool": "Semgrep", "severity": "HIGH" if sev == "ERROR" else "MEDIUM",
        "title": r.get("check_id", "").split(".")[-1],
        "file": f"{r.get('path','')}:{r.get('start',{}).get('line','')}",
        "detail": r.get("extra", {}).get("message", "")[:120],
    })

# SCA findings
sca_data = load_json("reports/report-sca/trivy.json")
for res in sca_data.get("Results", []):
    for v in res.get("Vulnerabilities", [])[:10]:
        if v.get("Severity") in ["CRITICAL", "HIGH"]:
            findings.append({
                "tool": "Trivy", "severity": v.get("Severity"),
                "title": v.get("VulnerabilityID", ""),
                "file": res.get("Target", ""),
                "detail": f"{v.get('PkgName')} {v.get('InstalledVersion')} → fix: {v.get('FixedVersion','none')}",
            })

# DAST findings
nuclei_rows = load_jsonl("reports/report-dast/nuclei.json")
for r in nuclei_rows[:10]:
    sev = r.get("info", {}).get("severity", "info").upper()
    if sev in ["CRITICAL", "HIGH", "MEDIUM"]:
        findings.append({
            "tool": "Nuclei", "severity": sev,
            "title": r.get("info", {}).get("name", ""),
            "file": r.get("matched-at", r.get("host", "")),
            "detail": r.get("info", {}).get("description", "")[:120],
        })

# IaC findings
iac_data = load_json("reports/report-iac/checkov.json")
for c in iac_data.get("results", {}).get("failed_checks", [])[:10]:
    sev = c.get("severity", "MEDIUM")
    if sev in ["CRITICAL", "HIGH"]:
        findings.append({
            "tool": "Checkov", "severity": sev,
            "title": f"{c.get('check_id','')} — {c.get('check',{}).get('name','')}",
            "file": f"{c.get('repo_file_path','')}:{c.get('file_line_range',[0])[0]}",
            "detail": c.get("check", {}).get("guideline", "")[:120],
        })

# Sort by severity
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
findings.sort(key=lambda x: SEV_ORDER.get(x["severity"], 99))

# ─────────────────────────────────────────────────────────
# ENROLLMENT TRACKING
# ─────────────────────────────────────────────────────────

ENROLLMENT_FILE = "enrollment-tracking.json"

def load_enrollment():
    try:
        with open(ENROLLMENT_FILE) as f:
            return json.load(f)
    except Exception:
        return {"enrolled": {}, "scans": [], "stats": {}}

def update_enrollment(data):
    now = datetime.now(timezone.utc).isoformat()

    # Register developer as enrolled
    if ACTOR and ACTOR != "unknown":
        if ACTOR not in data["enrolled"]:
            data["enrolled"][ACTOR] = {
                "first_seen"  : now,
                "scan_count"  : 0,
                "issues_found": 0,
                "last_scan"   : now,
                "status"      : "enrolled",
            }
        dev = data["enrolled"][ACTOR]
        dev["scan_count"]   += 1
        dev["issues_found"] += total_issues
        dev["last_scan"]     = now

    # Record scan run
    data["scans"].append({
        "run_id"       : RUN_ID,
        "run_url"      : RUN_URL,
        "actor"        : ACTOR,
        "repo"         : REPO,
        "ref"          : REF,
        "event"        : EVENT,
        "timestamp"    : now,
        "gate"         : gate_status,
        "total_issues" : total_issues,
        "results"      : {k: {"result": v["result"], "count": v["count"]} for k, v in RESULTS.items()},
    })
    # Keep last 500 scans
    data["scans"] = data["scans"][-500:]

    # Update aggregate stats
    total_scans   = len(data["scans"])
    passed_scans  = sum(1 for s in data["scans"] if s.get("gate") == "PASSED")
    data["stats"] = {
        "total_scans"       : total_scans,
        "passed_scans"      : passed_scans,
        "failed_scans"      : total_scans - passed_scans,
        "pass_rate"         : round(passed_scans / total_scans * 100, 1) if total_scans else 0,
        "total_enrolled"    : len(data["enrolled"]),
        "total_issues_found": sum(s.get("total_issues", 0) for s in data["scans"]),
        "last_updated"      : now,
    }

    return data

# Load + update
enrollment = load_enrollment()
enrollment = update_enrollment(enrollment)

with open(ENROLLMENT_FILE, "w") as f:
    json.dump(enrollment, f, indent=2)
print(f"✅ Enrollment tracking updated — {len(enrollment['enrolled'])} developers")

# ─────────────────────────────────────────────────────────
# HTML DASHBOARD TEMPLATE
# ─────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🛡️ SecurOps Security Dashboard</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; background:#0d1117; color:#c9d1d9; min-height:100vh; }
  .header { background:linear-gradient(135deg,#1f2937,#111827); border-bottom:1px solid #30363d; padding:24px 32px; display:flex; align-items:center; gap:16px; }
  .header h1 { font-size:22px; font-weight:700; color:#f0f6fc; }
  .header .meta { color:#8b949e; font-size:13px; margin-top:4px; }
  .badge { padding:4px 10px; border-radius:12px; font-size:12px; font-weight:700; }
  .badge-pass { background:#1a4731; color:#3fb950; }
  .badge-fail { background:#4c1a1a; color:#f85149; }
  .content { padding:24px 32px; max-width:1400px; margin:0 auto; }

  /* Gate Banner */
  .gate-banner { border-radius:12px; padding:20px 28px; margin-bottom:24px; display:flex; align-items:center; gap:16px; }
  .gate-pass { background:#0d2818; border:1px solid #238636; }
  .gate-fail { background:#2d1117; border:1px solid #da3633; }
  .gate-icon { font-size:36px; }
  .gate-title { font-size:20px; font-weight:700; }
  .gate-sub { font-size:14px; color:#8b949e; margin-top:4px; }

  /* Scan Cards Grid */
  .scans-grid { display:grid; grid-template-columns:repeat(5,1fr); gap:16px; margin-bottom:24px; }
  .scan-card { background:#161b22; border:1px solid #30363d; border-radius:12px; padding:18px; }
  .scan-card.pass { border-top:3px solid #238636; }
  .scan-card.fail { border-top:3px solid #da3633; }
  .scan-card.unknown { border-top:3px solid #484f58; }
  .scan-tool { font-size:11px; color:#8b949e; text-transform:uppercase; letter-spacing:.8px; margin-bottom:6px; }
  .scan-label { font-size:15px; font-weight:600; color:#f0f6fc; margin-bottom:12px; }
  .scan-count { font-size:36px; font-weight:700; line-height:1; margin-bottom:6px; }
  .scan-count.pass { color:#3fb950; }
  .scan-count.fail { color:#f85149; }
  .scan-count.unknown { color:#484f58; }
  .scan-status { font-size:12px; font-weight:600; }
  .scan-status.pass { color:#3fb950; }
  .scan-status.fail { color:#f85149; }

  /* Two-col layout */
  .two-col { display:grid; grid-template-columns:2fr 1fr; gap:16px; margin-bottom:24px; }

  /* Section */
  .section { background:#161b22; border:1px solid #30363d; border-radius:12px; overflow:hidden; }
  .section-header { padding:14px 20px; border-bottom:1px solid #30363d; display:flex; justify-content:space-between; align-items:center; }
  .section-title { font-size:14px; font-weight:600; color:#f0f6fc; }
  .section-badge { font-size:12px; background:#21262d; color:#8b949e; padding:3px 10px; border-radius:10px; }

  /* Findings table */
  table { width:100%; border-collapse:collapse; }
  th { padding:10px 16px; text-align:left; font-size:11px; color:#8b949e; text-transform:uppercase; letter-spacing:.6px; border-bottom:1px solid #21262d; }
  td { padding:10px 16px; font-size:13px; border-bottom:1px solid #21262d; }
  tr:last-child td { border-bottom:none; }
  tr:hover td { background:#1c2128; }
  .sev { padding:3px 8px; border-radius:4px; font-size:11px; font-weight:700; }
  .sev-CRITICAL { background:#4c1a1a; color:#f85149; }
  .sev-HIGH     { background:#3d2000; color:#d29922; }
  .sev-MEDIUM   { background:#2d2000; color:#e3b341; }
  .sev-LOW      { background:#0d2818; color:#3fb950; }
  .tool-badge { padding:2px 8px; border-radius:4px; font-size:11px; background:#21262d; color:#8b949e; }
  .file-path { font-family:monospace; font-size:11px; color:#79c0ff; }
  .finding-title { color:#f0f6fc; font-weight:500; }
  .finding-detail { color:#8b949e; font-size:12px; margin-top:2px; }

  /* Enrollment table */
  .enroll-table td:first-child { font-weight:600; color:#f0f6fc; }
  .status-enrolled { color:#3fb950; }
  .status-inactive { color:#8b949e; }

  /* Stats row */
  .stats-row { display:grid; grid-template-columns:repeat(4,1fr); }
  .stat { padding:16px; text-align:center; border-right:1px solid #21262d; }
  .stat:last-child { border-right:none; }
  .stat-num { font-size:28px; font-weight:700; color:#58a6ff; }
  .stat-label { font-size:11px; color:#8b949e; margin-top:4px; text-transform:uppercase; letter-spacing:.6px; }

  /* Empty */
  .empty { padding:40px; text-align:center; color:#484f58; font-size:14px; }

  /* Footer */
  .footer { border-top:1px solid #21262d; padding:16px 32px; text-align:center; font-size:12px; color:#484f58; }
</style>
</head>
<body>

<div class="header">
  <span style="font-size:28px">🛡️</span>
  <div>
    <h1>SecurOps Security Dashboard</h1>
    <div class="meta">
      {{ repo }} · {{ ref }} · {{ event }} · {{ timestamp }}
      · <a href="{{ run_url }}" style="color:#58a6ff" target="_blank">View pipeline run →</a>
    </div>
  </div>
  <span class="badge {{ 'badge-pass' if all_passed else 'badge-fail' }}" style="margin-left:auto">
    {{ '✅ GATE PASSED' if all_passed else '❌ GATE FAILED' }}
  </span>
</div>

<div class="content">

  <!-- Gate Banner -->
  <div class="gate-banner {{ 'gate-pass' if all_passed else 'gate-fail' }}">
    <span class="gate-icon">{{ '✅' if all_passed else '❌' }}</span>
    <div>
      <div class="gate-title" style="color:{{ '#3fb950' if all_passed else '#f85149' }}">
        Security Gate {{ 'PASSED' if all_passed else 'FAILED' }}
      </div>
      <div class="gate-sub">
        {{ total_issues }} total issue(s) found across 5 scans ·
        Commit pushed by @{{ actor }}
      </div>
    </div>
  </div>

  <!-- Scan Cards -->
  <div class="scans-grid">
    {% for key, r in results.items() %}
    <div class="scan-card {{ r.result if r.result in ['pass','fail'] else ('pass' if r.result == 'success' else ('fail' if r.result == 'failure' else 'unknown')) }}">
      <div class="scan-tool">{{ r.tool }}</div>
      <div class="scan-label">{{ r.icon }} {{ r.label }}</div>
      <div class="scan-count {{ 'pass' if r.result == 'success' else ('fail' if r.result == 'failure' else 'unknown') }}">
        {{ r.count }}
      </div>
      <div class="scan-status {{ 'pass' if r.result == 'success' else ('fail' if r.result == 'failure' else 'unknown') }}">
        {{ '✅ Passed' if r.result == 'success' else ('❌ Failed' if r.result == 'failure' else '⏳ ' + r.result) }}
      </div>
    </div>
    {% endfor %}
  </div>

  <div class="two-col">

    <!-- Findings Table -->
    <div class="section">
      <div class="section-header">
        <span class="section-title">🔍 Findings</span>
        <span class="section-badge">{{ findings|length }} issues</span>
      </div>
      {% if findings %}
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Tool</th>
            <th>Issue</th>
            <th>Location</th>
          </tr>
        </thead>
        <tbody>
          {% for f in findings %}
          <tr>
            <td><span class="sev sev-{{ f.severity }}">{{ f.severity }}</span></td>
            <td><span class="tool-badge">{{ f.tool }}</span></td>
            <td>
              <div class="finding-title">{{ f.title[:60] }}</div>
              <div class="finding-detail">{{ f.detail[:100] }}</div>
            </td>
            <td><span class="file-path">{{ f.file[:50] }}</span></td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% else %}
      <div class="empty">🎉 No findings! All scans passed.</div>
      {% endif %}
    </div>

    <!-- Enrollment Panel -->
    <div class="section">
      <div class="section-header">
        <span class="section-title">👥 Enrollment Tracking</span>
        <span class="section-badge">{{ enrolled|length }} developers</span>
      </div>
      <!-- Stats -->
      <div class="stats-row">
        <div class="stat">
          <div class="stat-num">{{ enrolled|length }}</div>
          <div class="stat-label">Enrolled</div>
        </div>
        <div class="stat">
          <div class="stat-num">{{ stats.total_scans }}</div>
          <div class="stat-label">Scans Run</div>
        </div>
        <div class="stat">
          <div class="stat-num" style="color:{{ '#3fb950' if stats.pass_rate >= 80 else '#f85149' }}">
            {{ stats.pass_rate }}%
          </div>
          <div class="stat-label">Pass Rate</div>
        </div>
        <div class="stat">
          <div class="stat-num">{{ stats.total_issues_found }}</div>
          <div class="stat-label">Blocked</div>
        </div>
      </div>
      <!-- Developer table -->
      {% if enrolled %}
      <table class="enroll-table">
        <thead>
          <tr>
            <th>Developer</th>
            <th>Scans</th>
            <th>Last Seen</th>
          </tr>
        </thead>
        <tbody>
          {% for name, dev in enrolled.items() %}
          <tr>
            <td>@{{ name }}</td>
            <td>{{ dev.scan_count }}</td>
            <td style="font-size:11px; color:#8b949e;">{{ dev.last_scan[:10] }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% else %}
      <div class="empty">No developers enrolled yet</div>
      {% endif %}
    </div>
  </div>

  <!-- Recent Scans -->
  <div class="section">
    <div class="section-header">
      <span class="section-title">📈 Recent Scan History</span>
      <span class="section-badge">Last {{ [recent_scans|length, 10]|min }} runs</span>
    </div>
    {% if recent_scans %}
    <table>
      <thead>
        <tr><th>Time</th><th>Developer</th><th>Repo</th><th>Branch</th><th>Gate</th><th>Issues</th><th>Run</th></tr>
      </thead>
      <tbody>
        {% for s in recent_scans %}
        <tr>
          <td style="font-size:11px; color:#8b949e;">{{ s.timestamp[:16] }}</td>
          <td>@{{ s.actor }}</td>
          <td style="font-size:12px;">{{ s.repo }}</td>
          <td style="font-family:monospace; font-size:11px; color:#79c0ff;">{{ s.ref }}</td>
          <td>
            {% if s.gate == 'PASSED' %}
              <span style="color:#3fb950">✅ PASS</span>
            {% else %}
              <span style="color:#f85149">❌ FAIL</span>
            {% endif %}
          </td>
          <td>{{ s.total_issues }}</td>
          <td><a href="{{ s.run_url }}" style="color:#58a6ff; font-size:11px;" target="_blank">#{{ s.run_id[-6:] }}</a></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% else %}
    <div class="empty">No scan history yet</div>
    {% endif %}
  </div>

</div>

<div class="footer">
  🛡️ SecurOps · Powered by Gitleaks · Semgrep · Trivy · Nuclei · Checkov · Claude AI
  · Generated {{ timestamp }}
</div>

</body>
</html>"""

# ─────────────────────────────────────────────────────────
# RENDER DASHBOARD
# ─────────────────────────────────────────────────────────

recent_scans = list(reversed(enrollment.get("scans", [])))[:10]

html = Template(HTML_TEMPLATE).render(
    repo=REPO, ref=REF, event=EVENT, timestamp=TIMESTAMP,
    run_url=RUN_URL, actor=ACTOR,
    results=RESULTS, all_passed=all_passed, total_issues=total_issues,
    findings=findings,
    enrolled=enrollment.get("enrolled", {}),
    stats=enrollment.get("stats", {}),
    recent_scans=recent_scans,
)

with open("security-dashboard.html", "w") as f:
    f.write(html)
print("✅ Dashboard generated: security-dashboard.html")

# ─────────────────────────────────────────────────────────
# PR SUMMARY MARKDOWN
# ─────────────────────────────────────────────────────────

def result_emoji(r):
    return "✅" if r == "success" else ("❌" if r == "failure" else "⏳")

summary = f"""## 🛡️ SecurOps Security Scan Results

| Scan | Tool | Issues | Status |
|------|------|--------|--------|
| 🔐 Secrets | Gitleaks | {RESULTS['secrets']['count']} | {result_emoji(RESULTS['secrets']['result'])} {RESULTS['secrets']['result']} |
| 🔍 SAST | Semgrep | {RESULTS['sast']['count']} | {result_emoji(RESULTS['sast']['result'])} {RESULTS['sast']['result']} |
| 🛡️ SCA | Trivy | {RESULTS['sca']['count']} | {result_emoji(RESULTS['sca']['result'])} {RESULTS['sca']['result']} |
| 🌐 DAST | Nuclei | {RESULTS['dast']['count']} | {result_emoji(RESULTS['dast']['result'])} {RESULTS['dast']['result']} |
| 🏗️ IaC | Checkov | {RESULTS['iac']['count']} | {result_emoji(RESULTS['iac']['result'])} {RESULTS['iac']['result']} |

**Security Gate:** {"✅ PASSED — safe to merge" if all_passed else "❌ FAILED — merge blocked"}

> {f"🎉 All {len(RESULTS)} scans passed!" if all_passed else f"Fix {total_issues} issue(s) before merging. See [pipeline run]({RUN_URL}) for details."}

_SecurOps · {TIMESTAMP}_
"""

with open("security-summary.md", "w") as f:
    f.write(summary)
print("✅ PR summary generated: security-summary.md")
print(f"\n{'='*50}")
print(f"  Gate: {gate_status} | Issues: {total_issues} | Enrolled: {len(enrollment.get('enrolled', {}))}")
print(f"{'='*50}")
