"""Markdown report generator for BearStrike AI."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Dict, List


BASE_DIR = Path(__file__).resolve().parents[1]
OUTPUT_ROOT = BASE_DIR / "reports" / "output"


def _sanitize_slug(value: str) -> str:
    return "".join(char if char.isalnum() or char in ("-", "_") else "_" for char in value).strip("_")


def _severity_rank(severity: str) -> int:
    ordering = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return ordering.get(severity.strip().lower(), 5)


def _build_output_paths(target: str) -> Dict[str, Path]:
    now = dt.datetime.now(dt.UTC)
    target_slug = _sanitize_slug(target) or "target"
    date_dir = now.strftime("%Y-%m-%d")
    run_dir_name = now.strftime("run_%H%M%S")

    run_dir = OUTPUT_ROOT / target_slug / date_dir / run_dir_name
    report_path = run_dir / "report.md"
    findings_json_path = run_dir / "findings.json"
    metadata_json_path = run_dir / "metadata.json"

    return {
        "target_slug": Path(target_slug),
        "run_dir": run_dir,
        "report_path": report_path,
        "findings_json_path": findings_json_path,
        "metadata_json_path": metadata_json_path,
    }


def generate_markdown_report(target: str, findings: List[Dict[str, str]], summary: str) -> Path:
    """Generate report artifacts in an organized target/date/run folder structure."""
    paths = _build_output_paths(target)
    run_dir = paths["run_dir"]
    run_dir.mkdir(parents=True, exist_ok=True)

    generated_at = dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
    sorted_findings = sorted(findings, key=lambda item: _severity_rank(str(item.get("severity", "info"))))

    severity_totals: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in sorted_findings:
        key = str(finding.get("severity", "info")).strip().lower()
        if key not in severity_totals:
            key = "info"
        severity_totals[key] += 1

    report_lines = [
        f"# BearStrike AI Report - {target}",
        "",
        f"Generated (UTC): {generated_at}",
        f"Target: {target}",
        "",
        "## Executive Summary",
        summary.strip() or "No summary provided.",
        "",
        "## Severity Breakdown",
        f"- Critical: {severity_totals['critical']}",
        f"- High: {severity_totals['high']}",
        f"- Medium: {severity_totals['medium']}",
        f"- Low: {severity_totals['low']}",
        f"- Info: {severity_totals['info']}",
        "",
        "## Findings",
    ]

    if not sorted_findings:
        report_lines.extend(["- No findings recorded.", ""])
    else:
        for index, finding in enumerate(sorted_findings, start=1):
            title = finding.get("title", f"Finding {index}")
            severity = finding.get("severity", "Info")
            details = finding.get("details", "No details provided.")
            evidence = finding.get("evidence", "No evidence provided.")
            remediation = finding.get("remediation", "No remediation guidance provided.")

            report_lines.extend(
                [
                    f"### {index}. {title}",
                    f"- Severity: {severity}",
                    f"- Details: {details}",
                    f"- Evidence: {evidence}",
                    f"- Remediation: {remediation}",
                    "",
                ]
            )

    report_lines.extend(
        [
            "## Recommendations",
            "1. Verify each finding manually before disclosure.",
            "2. Re-test after remediation to confirm closure.",
            "3. Follow the target program's responsible disclosure policy.",
            "",
            "## Artifact Index",
            f"- Findings JSON: {paths['findings_json_path'].name}",
            f"- Metadata JSON: {paths['metadata_json_path'].name}",
            "",
        ]
    )

    metadata = {
        "target": target,
        "generated_utc": generated_at,
        "severity_totals": severity_totals,
        "findings_count": len(sorted_findings),
        "run_dir": str(run_dir),
    }

    paths["report_path"].write_text("\n".join(report_lines), encoding="utf-8")
    paths["findings_json_path"].write_text(json.dumps(sorted_findings, indent=2), encoding="utf-8")
    paths["metadata_json_path"].write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    return paths["report_path"]


if __name__ == "__main__":
    demo_findings = [
        {
            "title": "Exposed Admin Login Endpoint",
            "severity": "Medium",
            "details": "Potentially sensitive admin panel discovered at /admin.",
            "evidence": "HTTP 200 response with login form fields.",
            "remediation": "Restrict access with IP allowlist and MFA.",
        },
        {
            "title": "Outdated Server Banner",
            "severity": "Low",
            "details": "Web server leaks version information in headers.",
            "evidence": "Server: Apache/2.4.49",
            "remediation": "Hide server signature and patch to latest release.",
        },
    ]

    output_file = generate_markdown_report(
        target="example.com",
        findings=demo_findings,
        summary="Automated recon identified exposed attack surface requiring manual validation.",
    )
    print(f"Report saved to: {output_file}")

