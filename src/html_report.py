# pylint: disable=C0301
"""
HTML Report Generator for DevScrub Security Scanner

Generates standalone HTML reports with detailed vulnerability information,
documentation links, and proper styling without external dependencies.
"""

import html
from datetime import datetime
from typing import Dict, Any

def _get_css_styles() -> str:
    """Return the CSS styles for the HTML report."""
    return """
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #f7f7fa; margin: 0; }
        .container { max-width: 1100px; margin: 30px auto; background: #fff; border-radius: 10px; box-shadow: 0 2px 12px #0001; padding: 32px; }
        .header { text-align: center; margin-bottom: 24px; }
        .subtitle { color: #666; font-size: 1.1em; margin-top: 6px; }
        .summary-cards { display: flex; gap: 18px; justify-content: center; margin: 24px 0; flex-wrap: wrap; }
        .summary-card { background: #f3f6fa; border-radius: 8px; padding: 18px 28px; min-width: 120px; text-align: center; box-shadow: 0 1px 4px #0001; }
        .summary-card .number { font-size: 2.1em; font-weight: bold; margin-top: 6px; }
        .critical { color: #d32f2f; }
        .high { color: #f57c00; }
        .medium { color: #fbc02d; }
        .low { color: #388e3c; }
        .info { color: #1976d2; }
        .filters { margin: 18px 0 28px 0; text-align: center; }
        .filter-select { padding: 6px 12px; border-radius: 5px; border: 1px solid #bbb; margin: 0 8px; }
        .findings-section { margin-top: 32px; }
        .finding-item { background: #fafbfc; border-radius: 8px; box-shadow: 0 1px 4px #0001; margin-bottom: 22px; padding: 20px 22px; }
        .finding-header { display: flex; justify-content: space-between; align-items: center; }
        .finding-title { font-size: 1.15em; font-weight: 500; }
        .finding-meta { font-size: 0.98em; color: #888; }
        .severity-badge { border-radius: 4px; padding: 2px 10px; font-weight: bold; margin-right: 8px; }
        .severity-critical { background: #ffd6d6; color: #d32f2f; }
        .severity-high { background: #ffe0b2; color: #f57c00; }
        .severity-medium { background: #fff9c4; color: #fbc02d; }
        .severity-low { background: #dcedc8; color: #388e3c; }
        .severity-info { background: #bbdefb; color: #1976d2; }
        .tool-badge { background: #e3e3e3; border-radius: 4px; padding: 2px 8px; margin-left: 4px; font-size: 0.95em; }
        .finding-description { margin: 12px 0 0 0; font-size: 1.04em; }
        .footer { text-align: center; margin-top: 40px; color: #888; font-size: 0.98em; }
        .no-findings { text-align: center; color: #388e3c; font-size: 1.2em; margin: 40px 0; }
        .doc-link { color: #1976d2; text-decoration: none; margin-right: 12px; }
        .doc-link:hover { text-decoration: underline; }
        @media (max-width: 700px) {
            .container { padding: 8px; }
            .summary-cards { flex-direction: column; gap: 10px; }
            .finding-item { padding: 12px 6px; }
        }
    """

def _generate_documentation_links(finding: Dict[str, Any]) -> str:
    """Generate documentation links for a finding."""
    tool = finding.get("tool", "Unknown")
    pylint_code = finding.get("pylint_code")
    ruff_code = finding.get("ruff_code")
    ruff_url = finding.get("ruff_url")
    cwe = finding.get("cwe")
    cve = finding.get("cve")

    links = []

    if tool == "Pylint" and pylint_code:
        category = 'convention'  # default
        if pylint_code.startswith('E'):
            category = 'error'
        elif pylint_code.startswith('W'):
            category = 'warning'
        elif pylint_code.startswith('R'):
            category = 'refactor'

        pylint_link = f"https://pylint.readthedocs.io/en/latest/user_guide/messages/{category}/{pylint_code.lower()}.html"
        links.append(f'<div><a href="{pylint_link}" target="_blank" rel="noopener" class="doc-link" aria-label="Pylint Documentation">📖 Pylint: {pylint_code}</a></div>')

    elif tool == "Ruff" and ruff_code:
        if ruff_url:
            links.append(f'<div><a href="{ruff_url}" target="_blank" rel="noopener" class="doc-link" aria-label="Ruff Documentation">📖 Ruff: {ruff_code}</a></div>')
        else:
            rule_name = ruff_code.lower().replace('_', '-')
            ruff_link = f"https://docs.astral.sh/ruff/rules/{rule_name}/"
            links.append(f'<div><a href="{ruff_link}" target="_blank" rel="noopener" class="doc-link" aria-label="Ruff Documentation">📖 Ruff: {ruff_code}</a></div>')

    if cwe:
        cwe_id = html.escape(str(cwe))
        if cwe_id.startswith("CWE-"):
            cwe_link = f"https://cwe.mitre.org/data/definitions/{cwe_id[4:]}.html"
            links.append(f'<div><a href="{cwe_link}" target="_blank" rel="noopener" aria-label="CWE Reference">🔗 CWE: {cwe_id}</a></div>')
        else:
            links.append(f'<div>CWE: {cwe_id}</div>')

    if cve:
        cve_id = html.escape(str(cve))
        if cve_id.startswith("CVE-"):
            cve_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            links.append(f'<div><a href="{cve_link}" target="_blank" rel="noopener" aria-label="CVE Reference">🔗 CVE: {cve_id}</a></div>')
        else:
            links.append(f'<div>CVE: {cve_id}</div>')

    return ''.join(links)

def _generate_finding_html(finding: Dict[str, Any]) -> str:
    """Generate HTML for a single finding."""
    sev = finding.get("severity", "info").lower()
    tool = finding.get("tool", "Unknown")
    title = finding.get("title") or finding.get("description") or "Security Issue"

    if title.lower().startswith(f"{tool.lower()}: "):
        title = title[len(tool) + 2:]

    description = finding.get("description", "No description available.")
    file_path = finding.get("file_path")
    line_number = finding.get("line_number")

    finding_html = [
        f'<article class="finding-item" data-severity="{sev}" data-tool="{html.escape(tool.lower())}" tabindex="0" aria-label="Finding">',
        f'<div class="finding-header"><div class="finding-title">{html.escape(title)}</div>',
        f'<div class="finding-meta"><span class="severity-badge severity-{sev}">{sev.upper()}</span><span class="tool-badge">{html.escape(tool)}</span></div></div>',
        f'<div class="finding-description">{html.escape(description)}</div>',
        _generate_documentation_links(finding)
    ]

    if file_path:
        file_info = html.escape(str(file_path))
        if line_number:
            finding_html.append(f'<div>File: <span class="file-path">{file_info}</span> <span class="line-number">(line {line_number})</span></div>')
        else:
            finding_html.append(f'<div>File: <span class="file-path">{file_info}</span></div>')

    finding_html.append('</article>')
    return ''.join(finding_html)

def generate_html_report(scan_results: Dict[str, Any], output_path: str) -> str:
    """Generate a modern, robust HTML security report with accessibility and UX improvements."""
    # Count severities
    severity_levels = ["critical", "high", "medium", "low", "info"]
    severity_counts = {s: 0 for s in severity_levels}
    for f in scan_results.get("findings", []):
        sev = f.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    total_findings = len(scan_results.get("findings", []))
    tools = sorted(set(f.get("tool", "Unknown") for f in scan_results.get("findings", [])))
    present_severities = [s for s in severity_levels if severity_counts[s] > 0]

    # Generate HTML
    html_parts = [
        f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DevScrub Security Report</title>
    <style>{_get_css_styles()}</style>
</head>
<body>
<main class="container" aria-label="DevScrub Security Report">
    <header class="header">
        <h1>🔒 DevScrub Security Report</h1>
        <div class="subtitle">Advanced Security Scanner with Semantic Code Analysis</div>
        <div style="margin-top: 10px; font-size: 0.95em; opacity: 0.8;">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
    </header>
    <section class="summary-cards" aria-label="Summary">
        <div class="summary-card"><h3>Total</h3><div class="number">{total_findings}</div></div>
        <div class="summary-card"><h3>Critical</h3><div class="number critical" id="count-critical">{severity_counts['critical']}</div></div>
        <div class="summary-card"><h3>High</h3><div class="number high" id="count-high">{severity_counts['high']}</div></div>
        <div class="summary-card"><h3>Medium</h3><div class="number medium" id="count-medium">{severity_counts['medium']}</div></div>
        <div class="summary-card"><h3>Low</h3><div class="number low" id="count-low">{severity_counts['low']}</div></div>
        <div class="summary-card"><h3>Info</h3><div class="number info" id="count-info">{severity_counts['info']}</div></div>
    </section>
    <section class="filters" aria-label="Filters">
        <label for="severity-filter">Filter by Severity:</label>
        <select id="severity-filter" class="filter-select" onchange="filterFindings()" aria-label="Severity Filter">
            <option value="all">All</option>
            {''.join(f'<option value="{sev}">{sev.title()}</option>' for sev in present_severities)}
        </select>
        <label for="tool-filter" style="margin-left:18px;">Filter by Tool:</label>
        <select id="tool-filter" class="filter-select" onchange="filterFindings()" aria-label="Tool Filter">
            <option value="all">All</option>
            {''.join(f'<option value="{html.escape(tool.lower())}">{html.escape(tool)}</option>' for tool in tools)}
        </select>
    </section>""",
        '<section class="findings-section" aria-label="Findings">'
    ]

    if not scan_results.get("findings", []):
        html_parts.append('<div class="no-findings">✅ No Security Issues Found</div>')
    else:
        for finding in scan_results.get("findings", []):
            html_parts.append(_generate_finding_html(finding))

    html_parts.extend([
        '</section>',
        """
    <footer class="footer" aria-label="Footer">
        Generated by DevScrub Security Scanner<br>
        <a href="https://github.com/zaydons/DevScrub" target="_blank">https://github.com/zaydons/DevScrub</a>
    </footer>
</main>
<script>
function filterFindings() {
    const severity = document.getElementById('severity-filter').value;
    const tool = document.getElementById('tool-filter').value;
    document.querySelectorAll('.finding-item').forEach(item => {
        const sev = item.getAttribute('data-severity');
        const t = item.getAttribute('data-tool');
        item.style.display =
            (severity === 'all' || sev === severity) &&
            (tool === 'all' || t === tool) ? '' : 'none';
    });
}
</script>
</body>
</html>"""
    ])

    # Write to file
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(''.join(html_parts))
    return output_path
