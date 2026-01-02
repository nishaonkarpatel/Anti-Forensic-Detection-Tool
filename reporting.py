# reporting.py
import os
import csv
import json
import datetime
from pathlib import Path
from typing import List, Dict, Any
from html import escape

from findings import Finding, Severity, IndicatorType


def _severity_sort_key(sev: str) -> int:
    if sev == Severity.HIGH:
        return 0
    if sev == Severity.MEDIUM:
        return 1
    return 2


def generate_html_report(
    findings: List[Finding],
    out_path: str,
    case_meta: Dict[str, Any],
) -> str:
    """
    Generate an enhanced HTML report summarizing findings.
    Returns the path to the written file.
    """
    Path(os.path.dirname(out_path)).mkdir(parents=True, exist_ok=True)

    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Basic stats
    total = len(findings)
    sev_counts = {"high": 0, "medium": 0, "low": 0}
    module_counts: Dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        module_counts[f.module] = module_counts.get(f.module, 0) + 1

    # Sort for executive summary (top 10 by priority_score)
    top_findings = sorted(findings, key=lambda f: f.priority_score, reverse=True)[:10]

    # For detailed section: group by severity
    sorted_findings = sorted(
        findings,
        key=lambda f: (_severity_sort_key(f.severity), -f.priority_score),
    )

    def esc(x: Any) -> str:
        return escape(str(x)) if x is not None else ""

    html = []
    html.append("<!DOCTYPE html><html><head><meta charset='utf-8'>")
    html.append("<title>TraceHunter Report</title>")
    html.append(_get_css_styles())
    html.append("</head><body>")

    # Header
    html.append("<div class='header'>")
    html.append("<h1>🔍 TraceHunter Analysis Report</h1>")
    html.append(f"<p class='subtitle'>Generated: {esc(now)}</p>")
    html.append("</div>")

    html.append("<div class='container'>")

    # Case information
    html.append("<div class='section'>")
    html.append("<h2>📋 Case Information</h2>")
    html.append("<div class='info-grid'>")
    for k, v in case_meta.items():
        html.append(f"<div class='info-item'><strong>{esc(k)}:</strong> {esc(v)}</div>")
    html.append("</div></div>")

    # Executive Summary
    html.append("<div class='section'>")
    html.append("<h2>📊 Executive Summary</h2>")
    
    # Severity cards
    html.append("<div class='card-container'>")
    html.append(_create_severity_card("High", sev_counts.get("high", 0), "#d32f2f"))
    html.append(_create_severity_card("Medium", sev_counts.get("medium", 0), "#f57c00"))
    html.append(_create_severity_card("Low", sev_counts.get("low", 0), "#388e3c"))
    html.append("</div>")
    html.append("</div>")

    # Module breakdown
    html.append("<div class='section'>")
    html.append("<h2>🔧 Module Analysis</h2>")
    html.append("<table class='data-table'><thead><tr><th>Module</th><th>Count</th><th>Percentage</th></tr></thead><tbody>")
    for mod, cnt in sorted(module_counts.items(), key=lambda x: x[1], reverse=True):
        pct = (cnt / total * 100) if total > 0 else 0
        html.append(f"<tr><td>{esc(mod.upper())}</td><td>{cnt}</td><td>{pct:.1f}%</td></tr>")
    html.append("</tbody></table></div>")

    # Stego Summary
    stego_suspicious = sum(1 for f in findings if f.module == "stego" and f.indicator_type == IndicatorType.STEGO_SUSPICIOUS_IMAGE)
    stego_text = sum(1 for f in findings if f.module == "stego" and f.indicator_type == IndicatorType.STEGO_TEXT_PAYLOAD)
    stego_code = sum(1 for f in findings if f.module == "stego" and f.indicator_type == IndicatorType.STEGO_CODE_PAYLOAD)
    stego_zip = sum(1 for f in findings if f.module == "stego" and "zip" in (f.tags or []))

    if stego_suspicious + stego_text + stego_code + stego_zip > 0:
        html.append("<div class='section'>")
        html.append("<h2>🖼️ Steganography Analysis</h2>")
        html.append("<table class='data-table'><thead><tr><th>Category</th><th>Count</th></tr></thead><tbody>")
        html.append(f"<tr><td>Suspicious Images</td><td>{stego_suspicious}</td></tr>")
        html.append(f"<tr><td>Hidden Text Payloads</td><td>{stego_text}</td></tr>")
        html.append(f"<tr><td>Hidden Code Payloads</td><td>{stego_code}</td></tr>")
        html.append(f"<tr><td>ZIP-based Payloads</td><td>{stego_zip}</td></tr>")
        html.append("</tbody></table></div>")

    # Executive highlights
    if top_findings:
        html.append("<div class='section'>")
        html.append("<h2>⚠️ Top Priority Findings</h2>")
        html.append("<ol class='top-findings'>")
        for f in top_findings:
            cls = f"sev-{f.severity}"
            bullet = f.executive_summary_bullet or f.evidence_summary
            html.append(
                f"<li class='finding-item {cls}'>"
                f"<div class='finding-summary'>{esc(bullet)}</div>"
                f"<div class='finding-meta'>Score: {f.priority_score} | Module: {esc(f.module)} | ID: {esc(f.id)}</div>"
                f"</li>"
            )
        html.append("</ol></div>")

    # Detailed Findings
    html.append("<div class='section'>")
    html.append("<h2>🔬 Detailed Findings</h2>")
    
    for f in sorted_findings:
        cls = f"sev-{f.severity}"
        html.append("<div class='finding-detail'>")
        html.append(
            f"<h3 class='finding-title {cls}'>"
            f"<span class='finding-id'>{esc(f.id)}</span> "
            f"{esc(f.module)} / {esc(f.indicator_type)}"
            f"</h3>"
        )
        
        html.append("<div class='finding-content'>")
        html.append(f"<div class='meta-row'><strong>Severity:</strong> <span class='{cls}'>{esc(f.severity.upper())}</span></div>")
        html.append(f"<div class='meta-row'><strong>Priority Score:</strong> {f.priority_score}</div>")
        html.append(f"<div class='meta-row'><strong>Resource:</strong> <code>{esc(f.file_path or '')}</code></div>")
        if f.related_artifact:
            html.append(f"<div class='meta-row'><strong>Related Artifact:</strong> {esc(f.related_artifact)}</div>")
        html.append(f"<div class='summary-box'><strong>Summary:</strong> {esc(f.evidence_summary)}</div>")

        # Details table
        if f.details:
            html.append("<details class='details-section'><summary>View Technical Details</summary>")
            html.append("<table class='details-table'>")
            for k, v in f.details.items():
                # Format nested dicts/lists nicely
                if isinstance(v, (dict, list)):
                    import json
                    v_str = json.dumps(v, indent=2, default=str)
                    html.append(f"<tr><td><strong>{esc(k)}</strong></td><td><pre>{esc(v_str)}</pre></td></tr>")
                else:
                    html.append(f"<tr><td><strong>{esc(k)}</strong></td><td>{esc(v)}</td></tr>")
            html.append("</table></details>")
        
        html.append("</div></div>")

    html.append("</div>")  # end section
    html.append("</div>")  # end container
    
    # Footer
    html.append("<div class='footer'>")
    html.append("<p>Generated by TraceHunter - Anti Forensic Detection Tool</p>")
    html.append(f"<p>Report generated at {now}</p>")
    html.append("</div>")

    html.append("</body></html>")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("".join(html))

    return out_path


def _get_css_styles() -> str:
    """Return enhanced CSS styles for the report."""
    return """
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
        font-size: 14px; 
        line-height: 1.6;
        color: #333;
        background: #f5f5f5;
    }
    .header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 2rem;
        text-align: center;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    .header h1 { font-size: 2.5rem; margin-bottom: 0.5rem; }
    .subtitle { font-size: 1rem; opacity: 0.9; }
    .container { max-width: 1200px; margin: 2rem auto; padding: 0 1rem; }
    .section { 
        background: white; 
        margin-bottom: 2rem; 
        padding: 1.5rem;
        border-radius: 8px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    h2 { 
        color: #333; 
        margin-bottom: 1.5rem; 
        padding-bottom: 0.5rem;
        border-bottom: 2px solid #667eea;
        font-size: 1.5rem;
    }
    h3 { color: #444; margin-bottom: 1rem; font-size: 1.2rem; }
    .info-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
        gap: 1rem;
        margin-top: 1rem;
    }
    .info-item {
        padding: 0.75rem;
        background: #f8f9fa;
        border-left: 3px solid #667eea;
        border-radius: 4px;
    }
    .card-container {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 1.5rem;
        margin: 1.5rem 0;
    }
    .severity-card {
        background: white;
        padding: 1.5rem;
        border-radius: 8px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        text-align: center;
        border-top: 4px solid;
    }
    .severity-card h3 { margin-bottom: 0.5rem; font-size: 1rem; color: #666; }
    .severity-card .count { font-size: 3rem; font-weight: bold; margin: 0.5rem 0; }
    .data-table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 1rem;
    }
    .data-table th, .data-table td {
        padding: 0.75rem;
        text-align: left;
        border-bottom: 1px solid #e0e0e0;
    }
    .data-table th {
        background: #f8f9fa;
        font-weight: 600;
        color: #555;
    }
    .data-table tr:hover { background: #f8f9fa; }
    .top-findings {
        list-style: none;
        counter-reset: finding-counter;
    }
    .finding-item {
        counter-increment: finding-counter;
        padding: 1rem;
        margin-bottom: 1rem;
        border-left: 4px solid;
        background: #f8f9fa;
        border-radius: 4px;
    }
    .finding-item:before {
        content: counter(finding-counter) ". ";
        font-weight: bold;
        margin-right: 0.5rem;
    }
    .finding-summary { font-weight: 500; margin-bottom: 0.5rem; }
    .finding-meta { font-size: 0.9rem; color: #666; }
    .finding-detail {
        margin-bottom: 2rem;
        padding: 1.5rem;
        background: #f8f9fa;
        border-radius: 8px;
        border-left: 4px solid #ccc;
    }
    .finding-title {
        display: flex;
        align-items: center;
        margin-bottom: 1rem;
        font-size: 1.1rem;
    }
    .finding-id {
        background: #667eea;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 4px;
        font-size: 0.9rem;
        margin-right: 0.75rem;
        font-family: 'Courier New', monospace;
    }
    .finding-content { padding-left: 1rem; }
    .meta-row { margin-bottom: 0.5rem; }
    .summary-box {
        margin-top: 1rem;
        padding: 1rem;
        background: white;
        border-radius: 4px;
        border-left: 3px solid #667eea;
    }
    .details-section {
        margin-top: 1rem;
        padding: 1rem;
        background: white;
        border-radius: 4px;
    }
    .details-section summary {
        cursor: pointer;
        font-weight: 600;
        color: #667eea;
        user-select: none;
    }
    .details-section summary:hover { color: #764ba2; }
    .details-table {
        width: 100%;
        margin-top: 1rem;
    }
    .details-table td {
        padding: 0.5rem;
        vertical-align: top;
        border-bottom: 1px solid #e0e0e0;
    }
    .details-table td:first-child { width: 200px; font-weight: 600; }
    code, pre {
        font-family: 'Courier New', Courier, monospace;
        background: #f4f4f4;
        padding: 0.2rem 0.4rem;
        border-radius: 3px;
        font-size: 0.9em;
    }
    pre { padding: 1rem; overflow-x: auto; }
    .sev-high { color: #d32f2f; font-weight: bold; }
    .sev-medium { color: #f57c00; font-weight: bold; }
    .sev-low { color: #388e3c; font-weight: bold; }
    .finding-detail.sev-high { border-left-color: #d32f2f; }
    .finding-detail.sev-medium { border-left-color: #f57c00; }
    .finding-detail.sev-low { border-left-color: #388e3c; }
    .finding-item.sev-high { border-left-color: #d32f2f; }
    .finding-item.sev-medium { border-left-color: #f57c00; }
    .finding-item.sev-low { border-left-color: #388e3c; }
    .footer {
        background: #333;
        color: white;
        text-align: center;
        padding: 2rem;
        margin-top: 3rem;
    }
    .footer p { margin: 0.25rem 0; opacity: 0.8; }
</style>
"""


def _create_severity_card(label: str, count: int, color: str) -> str:
    """Create a severity statistics card."""
    return f"""
    <div class="severity-card" style="border-top-color: {color};">
        <h3>{label} Severity</h3>
        <div class="count" style="color: {color};">{count}</div>
    </div>
    """


def export_to_csv(findings: List[Finding], out_path: str) -> str:
    """
    Export findings to CSV format.
    Returns the path to the written file.
    """
    Path(os.path.dirname(out_path)).mkdir(parents=True, exist_ok=True)
    
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        
        # Header
        writer.writerow([
            "ID", "Module", "Indicator Type", "Severity", "Priority Score",
            "Resource Type", "File Path", "Related Artifact",
            "Evidence Summary", "Executive Summary", "Tags", "Created At"
        ])
        
        # Data rows
        for finding in sorted(findings, key=lambda f: f.priority_score, reverse=True):
            writer.writerow([
                finding.id,
                finding.module,
                finding.indicator_type,
                finding.severity,
                finding.priority_score,
                finding.resource_type,
                finding.file_path,
                finding.related_artifact or "",
                finding.evidence_summary,
                finding.executive_summary_bullet or "",
                ", ".join(finding.tags) if finding.tags else "",
                finding.created_at.isoformat()
            ])
    
    return out_path


def export_to_json(findings: List[Finding], out_path: str) -> str:
    """
    Export findings to JSON format.
    Returns the path to the written file.
    """
    Path(os.path.dirname(out_path)).mkdir(parents=True, exist_ok=True)
    
    findings_data = []
    for f in findings:
        findings_data.append({
            "id": f.id,
            "module": f.module,
            "indicator_type": f.indicator_type,
            "severity": f.severity,
            "priority_score": f.priority_score,
            "resource_type": f.resource_type,
            "file_path": f.file_path,
            "related_artifact": f.related_artifact,
            "evidence_summary": f.evidence_summary,
            "executive_summary_bullet": f.executive_summary_bullet,
            "details": f.details,
            "tags": f.tags,
            "created_at": f.created_at.isoformat()
        })
    
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({
            "findings": findings_data,
            "metadata": {
                "total_findings": len(findings),
                "export_time": datetime.datetime.utcnow().isoformat()
            }
        }, f, indent=2, default=str)
    
    return out_path


def export_to_markdown(findings: List[Finding], out_path: str, case_meta: Dict[str, Any]) -> str:
    """
    Export findings to Markdown format.
    Returns the path to the written file.
    """
    Path(os.path.dirname(out_path)).mkdir(parents=True, exist_ok=True)
    
    lines = []
    lines.append("# TraceHunter Analysis Report\n")
    lines.append(f"*Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}*\n\n")
    
    # Case info
    lines.append("## Case Information\n")
    for k, v in case_meta.items():
        lines.append(f"- **{k}**: {v}\n")
    lines.append("\n")
    
    # Summary statistics
    lines.append("## Summary Statistics\n")
    sev_counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    
    lines.append(f"- **Total Findings**: {len(findings)}\n")
    lines.append(f"- **High Severity**: {sev_counts['high']}\n")
    lines.append(f"- **Medium Severity**: {sev_counts['medium']}\n")
    lines.append(f"- **Low Severity**: {sev_counts['low']}\n\n")
    
    # Top findings
    lines.append("## Top Priority Findings\n")
    top_findings = sorted(findings, key=lambda f: f.priority_score, reverse=True)[:10]
    for i, f in enumerate(top_findings, 1):
        lines.append(f"{i}. **[{f.severity.upper()}]** {f.executive_summary_bullet or f.evidence_summary}\n")
        lines.append(f"   - ID: `{f.id}` | Score: {f.priority_score} | Module: {f.module}\n\n")
    
    # Detailed findings
    lines.append("## Detailed Findings\n")
    sorted_findings = sorted(findings, key=lambda f: (_severity_sort_key(f.severity), -f.priority_score))
    
    for f in sorted_findings:
        lines.append(f"### [{f.severity.upper()}] {f.id}\n")
        lines.append(f"**Module**: {f.module} | **Type**: {f.indicator_type}\n\n")
        lines.append(f"**Evidence**: {f.evidence_summary}\n\n")
        lines.append(f"**File**: `{f.file_path}`\n\n")
        if f.details:
            lines.append("**Details**:\n```json\n")
            import json
            lines.append(json.dumps(f.details, indent=2, default=str))
            lines.append("\n```\n\n")
        lines.append("---\n\n")
    
    with open(out_path, "w", encoding="utf-8") as f:
        f.writelines(lines)
    
    return out_path