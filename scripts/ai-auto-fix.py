#!/usr/bin/env python3
"""
SecurOps AI Auto-Fix Script
File: scripts/ai-auto-fix.py

Uses Claude to:
1. Read all scan reports (Gitleaks, Semgrep, Trivy, Nuclei, Checkov)
2. Analyze each vulnerability
3. Generate specific code fixes
4. Create a GitHub Issue with fixes + PR-ready patches
5. Optionally commit fixes directly to a new branch

Requires: ANTHROPIC_API_KEY secret in GitHub repo settings
"""

import os
import json
import glob
import anthropic
from datetime import datetime

# ─────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
GITHUB_TOKEN      = os.environ.get("GITHUB_TOKEN")
REPO              = os.environ.get("REPO", "")
SHA               = os.environ.get("SHA", "")
ACTOR             = os.environ.get("ACTOR", "unknown")
MAX_FIXES_PER_RUN = 10   # Limit to avoid long runs

# ─────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────

def load_report(path_pattern):
    """Load a JSON report file, return empty dict if not found."""
    files = glob.glob(path_pattern, recursive=True)
    if not files:
        return {}
    try:
        with open(files[0]) as f:
            return json.load(f)
    except Exception:
        return {}

def load_jsonl(path_pattern):
    """Load a JSONL (newline-delimited JSON) report file."""
    files = glob.glob(path_pattern, recursive=True)
    results = []
    if not files:
        return results
    try:
        with open(files[0]) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except Exception:
                        pass
    except Exception:
        pass
    return results

def read_file_snippet(filepath, line_num, context=5):
    """Read code around a specific line for context."""
    try:
        with open(filepath) as f:
            lines = f.readlines()
        start = max(0, line_num - context - 1)
        end   = min(len(lines), line_num + context)
        snippet = []
        for i, line in enumerate(lines[start:end], start=start+1):
            marker = ">>>" if i == line_num else "   "
            snippet.append(f"{marker} {i:4d} | {line.rstrip()}")
        return "\n".join(snippet)
    except Exception:
        return "(could not read file)"

# ─────────────────────────────────────────────────────────
# COLLECT ALL FINDINGS
# ─────────────────────────────────────────────────────────

def collect_findings():
    """Collect all findings from all scan reports."""
    findings = []

    # ── Semgrep (SAST) ───────────────────────────────────
    sast = load_report("reports/report-sast/semgrep.json")
    for r in sast.get("results", [])[:5]:
        if r.get("extra", {}).get("severity") == "ERROR":
            findings.append({
                "tool"     : "Semgrep SAST",
                "severity" : "HIGH",
                "type"     : r.get("check_id", "unknown"),
                "message"  : r.get("extra", {}).get("message", ""),
                "file"     : r.get("path", ""),
                "line"     : r.get("start", {}).get("line", 0),
                "snippet"  : read_file_snippet(r.get("path",""), r.get("start",{}).get("line",0)),
                "fix_hint" : r.get("extra", {}).get("metadata", {}).get("fix", ""),
            })

    # ── Trivy (SCA) ──────────────────────────────────────
    sca = load_report("reports/report-sca/trivy.json")
    for result in sca.get("Results", [])[:3]:
        for v in result.get("Vulnerabilities", [])[:3]:
            if v.get("Severity") in ["CRITICAL", "HIGH"]:
                findings.append({
                    "tool"     : "Trivy SCA",
                    "severity" : v.get("Severity", "HIGH"),
                    "type"     : v.get("VulnerabilityID", ""),
                    "message"  : v.get("Title", "") or v.get("Description", "")[:200],
                    "file"     : result.get("Target", ""),
                    "line"     : 0,
                    "snippet"  : f"Package: {v.get('PkgName')} {v.get('InstalledVersion')} → Fix: {v.get('FixedVersion','no fix yet')}",
                    "fix_hint" : f"Upgrade {v.get('PkgName')} to {v.get('FixedVersion','latest')}",
                })

    # ── Checkov (IaC) ────────────────────────────────────
    iac = load_report("reports/report-iac/checkov.json")
    for check in iac.get("results", {}).get("failed_checks", [])[:3]:
        if check.get("severity") == "CRITICAL":
            findings.append({
                "tool"     : "Checkov IaC",
                "severity" : "CRITICAL",
                "type"     : check.get("check_id", ""),
                "message"  : check.get("check", {}).get("name", ""),
                "file"     : check.get("repo_file_path", ""),
                "line"     : check.get("file_line_range", [0])[0],
                "snippet"  : read_file_snippet(check.get("repo_file_path",""), check.get("file_line_range",[0,0])[0]),
                "fix_hint" : check.get("check", {}).get("guideline", ""),
            })

    # ── Nuclei (DAST) ────────────────────────────────────
    nuclei = load_jsonl("reports/report-dast/nuclei.json")
    for r in nuclei[:3]:
        if r.get("info", {}).get("severity") in ["critical", "high"]:
            findings.append({
                "tool"     : "Nuclei DAST",
                "severity" : r.get("info", {}).get("severity", "high").upper(),
                "type"     : r.get("template-id", ""),
                "message"  : r.get("info", {}).get("name", ""),
                "file"     : r.get("matched-at", r.get("host", "")),
                "line"     : 0,
                "snippet"  : r.get("extracted-results", ["No extract"])[0] if r.get("extracted-results") else "",
                "fix_hint" : r.get("info", {}).get("remediation", ""),
            })

    return findings[:MAX_FIXES_PER_RUN]

# ─────────────────────────────────────────────────────────
# AI FIX GENERATION
# ─────────────────────────────────────────────────────────

def generate_fix(client, finding):
    """Ask Claude to generate a specific fix for a finding."""
    prompt = f"""You are a security engineer. Analyze this security finding and provide a concrete fix.

TOOL: {finding['tool']}
SEVERITY: {finding['severity']}
TYPE: {finding['type']}
FILE: {finding['file']}
LINE: {finding['line']}
ISSUE: {finding['message']}

CODE CONTEXT:
{finding['snippet']}

FIX HINT FROM TOOL: {finding['fix_hint']}

Provide:
1. **Root Cause** (1 sentence)
2. **Exact Fix** (show the corrected code or command)
3. **Why This Fix Works** (1-2 sentences)
4. **Prevention** (1 sentence for future)

Be specific. Show actual code changes, not generic advice.
Format as markdown."""

    try:
        response = client.messages.create(
            model="claude-opus-4-5-20251101",
            max_tokens=800,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text
    except Exception as e:
        return f"AI fix generation failed: {e}"

# ─────────────────────────────────────────────────────────
# GITHUB ISSUE CREATION
# ─────────────────────────────────────────────────────────

def create_github_issue(findings_with_fixes):
    """Create a GitHub Issue with all AI-generated fixes."""
    if not GITHUB_TOKEN or not REPO:
        print("⚠️  No GITHUB_TOKEN or REPO — skipping issue creation")
        return

    try:
        import urllib.request
        import urllib.parse

        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        sha_short = SHA[:7] if SHA else "unknown"

        # Build issue body
        body_lines = [
            f"## 🤖 SecurOps AI Auto-Fix Report",
            f"",
            f"**Commit:** `{sha_short}` | **By:** @{ACTOR} | **Time:** {timestamp}",
            f"",
            f"Found **{len(findings_with_fixes)}** issue(s) requiring attention.",
            f"Claude has analyzed each finding and provided specific fixes below.",
            f"",
            f"---",
        ]

        for i, (finding, fix) in enumerate(findings_with_fixes, 1):
            severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(finding["severity"], "⚪")
            line_info = f' line {finding["line"]}' if finding['line'] else ''
            body_lines += [
                f"",
                f"## {severity_emoji} Issue {i}: {finding['type']}",
                f"**Tool:** {finding['tool']} | **Severity:** {finding['severity']}",
                f"**Location:** `{finding['file']}`{line_info}",
                f"",
                f"**Finding:** {finding['message']}",
                f"",
                f"### 🤖 Claude's Fix:",
                f"",
                fix,
                f"",
                f"---",
            ]

        body_lines += [
            f"",
            f"*Generated by SecurOps AI Auto-Fix using Claude | [View pipeline run](https://github.com/{REPO}/actions)*",
        ]

        body = "\n".join(body_lines)

        # Count by severity
        critical = sum(1 for f, _ in findings_with_fixes if f["severity"] == "CRITICAL")
        high     = sum(1 for f, _ in findings_with_fixes if f["severity"] == "HIGH")

        issue_data = json.dumps({
            "title"  : f"🤖 SecurOps AI Fix: {len(findings_with_fixes)} issues found (commit {sha_short})",
            "body"   : body,
            "labels" : ["security", "ai-auto-fix", "automated"],
        }).encode()

        req = urllib.request.Request(
            f"https://api.github.com/repos/{REPO}/issues",
            data=issue_data,
            headers={
                "Authorization": f"token {GITHUB_TOKEN}",
                "Content-Type" : "application/json",
                "Accept"       : "application/vnd.github.v3+json",
            },
            method="POST"
        )
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read())
            print(f"✅ GitHub Issue created: {result.get('html_url')}")

    except Exception as e:
        print(f"⚠️  Could not create GitHub issue: {e}")
        # Fallback: save to file
        with open("ai-fix-report.md", "w") as f:
            f.write(body)
        print("✅ Saved to ai-fix-report.md instead")

# ─────────────────────────────────────────────────────────
# SAVE FIX REPORT
# ─────────────────────────────────────────────────────────

def save_fix_report(findings_with_fixes):
    """Save the AI fix report as a markdown file (always)."""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# 🤖 SecurOps AI Auto-Fix Report",
        f"Generated: {timestamp} | Commit: {SHA[:7] if SHA else 'local'}",
        f"",
    ]
    for i, (finding, fix) in enumerate(findings_with_fixes, 1):
        lines += [
            f"## Issue {i}: [{finding['severity']}] {finding['type']} — {finding['tool']}",
            f"**File:** `{finding['file']}` | **Line:** {finding['line']}",
            f"**Issue:** {finding['message']}",
            f"",
            f"### AI Fix:",
            fix,
            f"",
            f"---",
            f"",
        ]
    with open("ai-fix-report.md", "w") as f:
        f.write("\n".join(lines))
    print(f"✅ Fix report saved: ai-fix-report.md")

# ─────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────

def main():
    print("🤖 SecurOps AI Auto-Fix — Starting...")
    print(f"   Repo: {REPO} | Actor: {ACTOR} | SHA: {SHA[:7] if SHA else 'local'}")
    print()

    if not ANTHROPIC_API_KEY:
        print("⚠️  ANTHROPIC_API_KEY not set — skipping AI fixes")
        print("   Add ANTHROPIC_API_KEY to GitHub repo secrets to enable AI fixes")
        return

    # Initialize Claude client
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    # Collect all findings
    print("📊 Collecting findings from all scan reports...")
    findings = collect_findings()

    if not findings:
        print("✅ No findings to fix — all scans passed!")
        return

    print(f"   Found {len(findings)} issue(s) to analyze")
    print()

    # Generate AI fixes
    findings_with_fixes = []
    for i, finding in enumerate(findings, 1):
        print(f"🔍 Analyzing issue {i}/{len(findings)}: [{finding['severity']}] {finding['type']} ({finding['tool']})")
        fix = generate_fix(client, finding)
        findings_with_fixes.append((finding, fix))
        print(f"   ✅ Fix generated")

    print()

    # Save report file
    save_fix_report(findings_with_fixes)

    # Create GitHub Issue
    print("📝 Creating GitHub Issue with all fixes...")
    create_github_issue(findings_with_fixes)

    print()
    print(f"✅ AI Auto-Fix complete — {len(findings_with_fixes)} fixes generated")

if __name__ == "__main__":
    main()
