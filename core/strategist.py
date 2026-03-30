"""Strategic intelligence layer for BearStrike.

This module turns control-plane data into prioritized, low-noise guidance
for autonomous or operator-driven hunting.
"""

from __future__ import annotations

from typing import Any, Dict, List

try:  # pragma: no cover - import path compatibility for script/package execution
    from core.control_plane import (
        get_high_value_targets,
        get_hunter_notes,
        list_prioritized_endpoints,
        normalize_target,
        research_query,
    )
except ImportError:  # pragma: no cover
    from control_plane import (  # type: ignore[no-redef]
        get_high_value_targets,
        get_hunter_notes,
        list_prioritized_endpoints,
        normalize_target,
        research_query,
    )


def _safe_score(value: Any) -> int:
    try:
        return max(0, min(10, int(value)))
    except (TypeError, ValueError):
        return 0


def _collect_research_hits(endpoint_paths: List[str], limit_per_path: int = 3) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    seen_keys = set()
    for path in endpoint_paths:
        path_value = str(path or "").strip()
        if not path_value:
            continue
        payload = research_query(endpoint_pattern=path_value, limit=max(1, min(int(limit_per_path), 10)))
        for item in payload.get("items", []):
            vuln = str(item.get("vulnerability_class") or "general").strip().lower()
            ep = str(item.get("endpoint_pattern") or "").strip().lower()
            key = (vuln, ep)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            findings.append(item)
    return findings


def build_strategy_bundle(target: str, limit: int = 10) -> Dict[str, Any]:
    normalized_target = normalize_target(target)
    safe_limit = max(1, min(int(limit), 50))

    high_value = get_high_value_targets(target=normalized_target, limit=safe_limit, min_score=5)
    grouped = list_prioritized_endpoints(target=normalized_target, limit=max(20, safe_limit * 2))
    notes = get_hunter_notes(target=normalized_target, limit=10)

    top_paths = [str(item.get("path_signature") or "") for item in high_value[:8]]
    research_hits = _collect_research_hits(top_paths, limit_per_path=3)

    avg_score = 0.0
    if high_value:
        avg_score = round(sum(_safe_score(item.get("score")) for item in high_value) / len(high_value), 2)

    risk_posture = "low"
    high_count = len(grouped.get("high", []))
    medium_count = len(grouped.get("medium", []))
    if high_count >= 5 or avg_score >= 8:
        risk_posture = "high"
    elif high_count > 0 or medium_count >= 4 or avg_score >= 6:
        risk_posture = "medium"

    return {
        "target": normalized_target,
        "risk_posture": risk_posture,
        "avg_score": avg_score,
        "high_value_targets": high_value,
        "priorities": grouped,
        "research_hits": research_hits,
        "hunter_notes": notes,
    }


def analyze_target_surface(target: str, limit: int = 10) -> str:
    bundle = build_strategy_bundle(target=target, limit=limit)
    normalized_target = str(bundle.get("target") or "")
    high_value = list(bundle.get("high_value_targets") or [])
    priorities = dict(bundle.get("priorities") or {})
    research_hits = list(bundle.get("research_hits") or [])
    notes = list(bundle.get("hunter_notes") or [])

    lines: List[str] = []
    lines.append(f"# BearStrike Strategist: {normalized_target or 'unknown-target'}")
    lines.append("")
    lines.append(
        f"Risk posture: {bundle.get('risk_posture', 'low')} | "
        f"avg endpoint score: {bundle.get('avg_score', 0)}"
    )
    lines.append(
        f"Priority bands: high={len(priorities.get('high', []))}, "
        f"medium={len(priorities.get('medium', []))}, "
        f"low={len(priorities.get('low', []))}"
    )
    lines.append("")

    lines.append("## Recommended Focus")
    if not high_value:
        lines.append("- No high-value endpoints yet. Run passive recon first (subfinder/httpx/whatweb/gau).")
    else:
        for idx, endpoint in enumerate(high_value[:5], start=1):
            method = str(endpoint.get("method") or "GET")
            path = str(endpoint.get("path_signature") or "/")
            score = _safe_score(endpoint.get("score"))
            ep_class = str(endpoint.get("endpoint_class") or "general")
            lines.append(f"{idx}. {method} {path} | score={score} | class={ep_class}")
    lines.append("")

    lines.append("## Research-Backed Vulnerability Hints")
    if not research_hits:
        lines.append("- No direct research-matched findings for mapped endpoints yet.")
    else:
        for item in research_hits[:8]:
            vuln = str(item.get("vulnerability_class") or "general")
            ep = str(item.get("endpoint_pattern") or "")
            method = str(item.get("method") or "ANY")
            lines.append(f"- {vuln} on {method} {ep}")
    lines.append("")

    lines.append("## Operator Notes")
    if not notes:
        lines.append("- No hunter notes saved.")
    else:
        for note in notes[:5]:
            confidence = float(note.get("confidence") or 0.0)
            lines.append(f"- ({confidence:.2f}) {str(note.get('message') or '').strip()}")
    lines.append("")

    lines.append("## Next Actions")
    lines.append("1. Validate top 3 high-score endpoints with auth and unauth baselines.")
    lines.append("2. Use minimal payload packs by endpoint class (IDOR/auth/SSRF/XSS/misconfig).")
    lines.append("3. Save strong observations with add_hunter_note() before report generation.")

    return "\n".join(lines).strip()
