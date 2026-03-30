"""Markdown reporting engine for BearStrike."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

try:  # pragma: no cover - import path compatibility for script/package execution
    from core.control_plane import (
        REPORTS_OUTPUT_DIR,
        get_high_value_targets,
        get_hunter_notes,
        list_prioritized_endpoints,
        normalize_target,
        research_query,
    )
except ImportError:  # pragma: no cover
    from control_plane import (  # type: ignore[no-redef]
        REPORTS_OUTPUT_DIR,
        get_high_value_targets,
        get_hunter_notes,
        list_prioritized_endpoints,
        normalize_target,
        research_query,
    )


def _target_slug(target: str) -> str:
    value = normalize_target(target)
    cleaned = "".join(ch if ch.isalnum() else "_" for ch in value).strip("_")
    return cleaned or "target"


def _collect_target_findings(endpoint_paths: List[str], limit_per_path: int = 4) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    seen = set()
    for path in endpoint_paths:
        safe_path = str(path or "").strip()
        if not safe_path:
            continue
        payload = research_query(endpoint_pattern=safe_path, limit=max(1, min(int(limit_per_path), 10)))
        for item in payload.get("items", []):
            key = (
                str(item.get("source") or "").strip().lower(),
                str(item.get("vulnerability_class") or "").strip().lower(),
                str(item.get("endpoint_pattern") or "").strip().lower(),
            )
            if key in seen:
                continue
            seen.add(key)
            findings.append(item)
    return findings


def build_target_report_markdown(target: str) -> str:
    normalized_target = normalize_target(target)
    priorities = list_prioritized_endpoints(normalized_target, limit=100)
    high_value = get_high_value_targets(normalized_target, limit=20, min_score=5)
    notes = get_hunter_notes(normalized_target, limit=30)

    endpoint_paths = [str(item.get("path_signature") or "") for item in high_value[:12]]
    findings = _collect_target_findings(endpoint_paths, limit_per_path=4)

    now_iso = datetime.now(timezone.utc).isoformat()
    lines: List[str] = [
        "# BearStrike Target Report",
        "",
        f"- Target: `{normalized_target}`",
        f"- Generated (UTC): `{now_iso}`",
        f"- High-value endpoints: `{len(high_value)}`",
        f"- Research-matched findings: `{len(findings)}`",
        "",
        "## Endpoint Priority Summary",
        f"- High: `{len(priorities.get('high', []))}`",
        f"- Medium: `{len(priorities.get('medium', []))}`",
        f"- Low: `{len(priorities.get('low', []))}`",
        "",
        "## Top High-Value Endpoints",
    ]

    if not high_value:
        lines.append("- No endpoint intelligence captured yet.")
    else:
        for item in high_value[:15]:
            score = int(item.get("score") or 0)
            method = str(item.get("method") or "GET")
            path = str(item.get("path_signature") or "/")
            ep_class = str(item.get("endpoint_class") or "general")
            lines.append(f"- [{score}] `{method} {path}` ({ep_class})")

    lines.extend(["", "## Research-Matched Findings"])
    if not findings:
        lines.append("- No direct matches yet for currently mapped endpoints.")
    else:
        for finding in findings[:40]:
            vuln = str(finding.get("vulnerability_class") or "general")
            endpoint = str(finding.get("endpoint_pattern") or "unknown-endpoint")
            method = str(finding.get("method") or "ANY")
            source = str(finding.get("source") or "research")
            confidence = float(finding.get("confidence") or 0.0)
            lines.append(
                f"- `{vuln}` on `{method} {endpoint}` "
                f"(source={source}, confidence={confidence:.2f})"
            )
            payload = str(finding.get("payload_snippet") or "").strip()
            if payload:
                lines.append("  - Payload snippet:")
                lines.append("    ```text")
                lines.append(f"    {payload[:400]}")
                lines.append("    ```")

    lines.extend(["", "## Hunter Notes"])
    if not notes:
        lines.append("- No operator notes saved.")
    else:
        for note in notes[:20]:
            conf = float(note.get("confidence") or 0.0)
            msg = str(note.get("message") or "").strip()
            lines.append(f"- ({conf:.2f}) {msg}")

    lines.extend(
        [
            "",
            "## Recommended Next Actions",
            "1. Validate top 3 high-score endpoints with authenticated and unauthenticated baselines.",
            "2. Retest only high-signal payloads and record each confirmation step.",
            "3. Add final evidence notes, then regenerate this report.",
            "",
        ]
    )
    return "\n".join(lines).strip() + "\n"


def generate_markdown_report(target: str) -> str:
    normalized_target = normalize_target(target)
    if not normalized_target:
        return "Failed to generate report: target is required."

    report = build_target_report_markdown(normalized_target)
    target_dir = REPORTS_OUTPUT_DIR / _target_slug(normalized_target)
    target_dir.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = target_dir / f"target_report_{stamp}.md"
    report_path.write_text(report, encoding="utf-8")

    preview = report[:900]
    return (
        f"Report generated successfully.\n"
        f"Saved to: {report_path}\n\n"
        f"Preview:\n{preview}"
    )
