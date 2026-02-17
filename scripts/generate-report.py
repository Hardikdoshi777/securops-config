#!/usr/bin/env python3
"""
SecurOps Report Generator
File: scripts/generate-report.py
Generates HTML security dashboard from scan results
"""

import json
import os
from datetime import datetime
from jinja2 import Template

TEMPLATE = """<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>SecurOps Security Dashboard</title>
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background:#0d1117; color:#c9d1d9; padding:30px; }
    h1 { color:#58a6ff; font-size:28px; margin-bottom:8px; }
    .meta { color:#8b949e; font-size:14px; margin-bottom:30px; }
    .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:16px; margin-bottom:32px; }
    .card { background:#161b22; border:1px solid #30363d; border-radius:8px; padding:20px; }
    .card h3 { color:#8b949e; font-size:12px; text-transform:uppercase; letter-spacing:1px; margin-bottom:8px; }
    .card .num { font-size:42px; font-weight:700; }
    .card.status .num { font-size:28px; padding-top:8px; }
    .critical { color:#f85149; }
    .high { color:#d29922; }
    .medium { color:#f0883e; }
    .low { color:#3fb950; }
    .pass { color:#3fb950; }
    .fail { color:#f85149; }
    .findings h2 { margin-bottom:16px; font-size:20px; }
    .finding { background:#161b22; border-left:4px solid #30363d; padding:16px; margin-bottom:12px; border-radius:6px; }
    .finding.critical { border-left-color:#f85149; }
    .finding.high { border-left-color:#d29922; }
    .finding.medium { border-left-color:#f0883e; }
    .badge { display:inline-block; padding:3px 10px; border-radius:4px; font-size:11px; font-weight:700; margin-right:8px; }
    .badge.critical { background:#f85149; color:#fff; }
    .badge.high { background:#d29922; color:#fff; }
    .badge.medium { background:#f0883e; color:#000; }
    .title { font-size:15px; font-weight:600; margin:8px 0; }
    .info { font-size:12px; color:#8b949e; }
    .code { background:#0d1117; border:1px solid #30363d; border-radius:4px; padding:10px; font-family:monospace; font-size:12px; margin-top:8px; overflow-x:auto; }
    .empty { text-align:center; padding:40px; color:#8b949e; }
  </style>
</head>
<body>
  <h1>🛡️ SecurOps Security Dashboard</h1>
  <div class="meta">Generated: {{ date }} | Repository: {{ repo }} | Branch: {{ branch }}</div>
  <div class="cards">
    <div class="card"><h3>Critical</h3><div class="num critical">{{ counts.critical }}</div></div>
    <div class="card"><h3>High</h3><div class="num high">{{ counts.high }}</div></div>
    <div class="card"><h3>Medium</h3><div class="num medium">{{ counts.medium }}</div></div>
    <div class="card"><h3>Total Issues</h3><div class="num">{{ counts.total }}</div></div>
    <div class="card status">
      <h3>Security Gate</h3>
      <div class="num {{ 'pass' if counts.critical == 0 and counts.high == 0 else 'fail' }}">
        {{ '✅ PASS' if counts.critical == 0 and counts.high == 0 else '❌ FAIL' }}
      </div>
    </div>
  </div>
  <div class="findings">
    <h2>🔍 Findings ({{ findings|length }})</h2>
    {% if findings %}
      {% for f in findings %}
      <div class="finding {{ f.severity|lower }}">
        <span class="badge {{ f.severity|lower }}">{{ f.severity }}</span>
        <span class="badge" style="background:#21262d">{{ f.tool }}</span>
        <div class="title">{{ f.title }}</div>
        <div class="info">📁 {{ f.file }} {% if f.line != 'N/A' %}| Line {{ f.line }}{% endif %}</div>
        {% if f.description %}<div class="info" style="margin-top:4px">{{ f.description }}</div>{% endif %}
        {% if f.code %}<div class="code">{{ f.code }}</div>{% endif %}
      </div>
      {% endfor %}
    {% else %}
      <div class="empty">🎉 No issues found! Your code is clean.</div>
    {% endif %}
  </div>
</body>
</html>"""

def load_semgrep(path):
    findings = []
    if not os.path.exists(path):
        return findings
    with open(path) as f:
        data = json.load(f)
    for r in data.get('results', []):
        sev = 'HIGH' if r['extra']['severity'] == 'ERROR' else 'MEDIUM'
        findings.append({
            'severity': sev, 'tool': 'Semgrep SAST',
            'title': r['extra']['message'],
            'description': r['extra'].get('metadata', {}).get('shortDescription', ''),
            'file': r['path'], 'line': r['start']['line'],
            'code': r['extra'].get('lines', '')
        })
    return findings

def load_trivy(path):
    findings = []
    if not os.path.exists(path):
        return findings
    with open(path) as f:
        data = json.load(f)
    for result in data.get('Results', []):
        for v in result.get('Vulnerabilities', []):
            findings.append({
                'severity': v['Severity'], 'tool': 'Trivy SCA',
                'title': f"{v.get('VulnerabilityID','?')} in {v.get('PkgName','?')}",
                'description': v.get('Title', ''),
                'file': result.get('Target', 'N/A'), 'line': 'N/A',
                'code': f"Installed: {v.get('InstalledVersion','?')} → Fix: {v.get('FixedVersion','No fix')}"
            })
    return findings

def main():
    findings = []
    findings += load_semgrep('reports/sast-report/semgrep.json')
    findings += load_trivy('reports/dependency-report/trivy.json')

    order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    findings.sort(key=lambda x: order.get(x['severity'], 99))

    counts = {
        'critical': sum(1 for f in findings if f['severity'] == 'CRITICAL'),
        'high':     sum(1 for f in findings if f['severity'] == 'HIGH'),
        'medium':   sum(1 for f in findings if f['severity'] == 'MEDIUM'),
        'total':    len(findings)
    }

    html = Template(TEMPLATE).render(
        date=datetime.now().strftime('%Y-%m-%d %H:%M UTC'),
        repo=os.getenv('GITHUB_REPOSITORY', 'your-org/your-repo'),
        branch=os.getenv('GITHUB_REF_NAME', 'main'),
        counts=counts, findings=findings
    )
    with open('security-dashboard.html', 'w') as f:
        f.write(html)

    passed = counts['critical'] == 0 and counts['high'] == 0
    md = f"""## 🛡️ SecurOps Security Scan

| | Count |
|---|---|
| 🔴 Critical | {counts['critical']} |
| 🟠 High | {counts['high']} |
| 🟡 Medium | {counts['medium']} |

**Status:** {'✅ PASS — safe to merge' if passed else '❌ FAIL — fix issues before merging'}
"""
    with open('security-summary.md', 'w') as f:
        f.write(md)

    print(f"✅ Dashboard: security-dashboard.html")
    print(f"📊 Critical: {counts['critical']} | High: {counts['high']} | Medium: {counts['medium']}")

if __name__ == '__main__':
    main()
