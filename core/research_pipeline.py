"""Curated + verified research intelligence pipeline for BearStrike.

The pipeline is legal-safe by default:
- Loads curated findings from local seed files and built-in baseline.
- Supports on-demand refresh without active target scanning.
- Normalizes into control-plane schema for scoring/payload selection.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List

from control_plane import research_summary, store_research_findings

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
RESEARCH_SEED_PATH = DATA_DIR / "research_seed.json"
RESEARCH_EXTRA_PATH = DATA_DIR / "research_findings.local.jsonl"


def _now() -> float:
    return time.time()


def _baseline_curated_findings(now_ts: float) -> List[Dict[str, Any]]:
    day = 86400.0
    return [
        {
            "source": "curated-verified",
            "source_url": "https://owasp.org/API-Security/",
            "vulnerability_class": "idor-bola",
            "endpoint_pattern": "/api/user",
            "payload_snippet": "Swap object identifiers across same-role accounts.",
            "method": "GET",
            "exploitation_notes": "Validate horizontal and vertical authorization boundaries.",
            "confidence": 0.91,
            "discovered_at": now_ts - (2 * day),
            "meta": {"family": "access-control", "verified": True},
        },
        {
            "source": "curated-verified",
            "source_url": "https://portswigger.net/web-security/ssrf",
            "vulnerability_class": "ssrf",
            "endpoint_pattern": "/api/v1/fetch",
            "payload_snippet": "Test internal metadata and RFC1918 denial paths.",
            "method": "POST",
            "exploitation_notes": "Start with harmless canary targets and strict egress checks.",
            "confidence": 0.88,
            "discovered_at": now_ts - (4 * day),
            "meta": {"family": "request-routing", "verified": True},
        },
        {
            "source": "curated-verified",
            "source_url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            "vulnerability_class": "misconfig-debug-exposure",
            "endpoint_pattern": "/internal",
            "payload_snippet": "Probe debug flags and accidental environment leaks.",
            "method": "GET",
            "exploitation_notes": "Confirm reproducibility and remove false positives using controls.",
            "confidence": 0.79,
            "discovered_at": now_ts - (6 * day),
            "meta": {"family": "misconfig", "verified": True},
        },
        {
            "source": "curated-verified",
            "source_url": "https://owasp.org/www-project-web-security-testing-guide/",
            "vulnerability_class": "auth-bypass",
            "endpoint_pattern": "/auth",
            "payload_snippet": "Token/session confusion and privilege context checks.",
            "method": "POST",
            "exploitation_notes": "Cross-check account role transitions and stale token paths.",
            "confidence": 0.86,
            "discovered_at": now_ts - (8 * day),
            "meta": {"family": "auth-session", "verified": True},
        },
        {
            "source": "curated-verified",
            "source_url": "https://portswigger.net/web-security/cross-site-scripting",
            "vulnerability_class": "xss",
            "endpoint_pattern": "/search",
            "payload_snippet": "Context-aware payloads for reflected/stored sinks only.",
            "method": "GET",
            "exploitation_notes": "Use low-noise payload set and verify sink context before escalation.",
            "confidence": 0.74,
            "discovered_at": now_ts - (12 * day),
            "meta": {"family": "input-handling", "verified": True},
        },
    ]


def _load_json_seed(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(payload, dict) and isinstance(payload.get("items"), list):
        return [item for item in payload["items"] if isinstance(item, dict)]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def _load_jsonl_seed(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    findings: List[Dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            text = line.strip()
            if not text:
                continue
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                findings.append(payload)
    except OSError:
        return []
    return findings


def _filter_recent(findings: Iterable[Dict[str, Any]], days: int, now_ts: float) -> List[Dict[str, Any]]:
    min_ts = now_ts - (max(1, int(days)) * 86400)
    filtered: List[Dict[str, Any]] = []
    for item in findings:
        discovered_at = float(item.get("discovered_at") or now_ts)
        if discovered_at < min_ts:
            continue
        normalized = dict(item)
        normalized["discovered_at"] = discovered_at
        filtered.append(normalized)
    return filtered


def refresh_research_intel(days: int = 30) -> Dict[str, Any]:
    now_ts = _now()
    baseline = _baseline_curated_findings(now_ts)
    local_seed = _load_json_seed(RESEARCH_SEED_PATH)
    local_jsonl = _load_jsonl_seed(RESEARCH_EXTRA_PATH)

    merged = _filter_recent([*baseline, *local_seed, *local_jsonl], days=days, now_ts=now_ts)
    result = store_research_findings(merged, replace_window_days=days)
    summary = research_summary(days=days)
    return {
        "success": True,
        "mode": "curated_verified",
        "seed_sources": {
            "builtin": len(baseline),
            "json_seed": len(local_seed),
            "jsonl_seed": len(local_jsonl),
        },
        "ingest_result": result,
        "summary": summary,
    }

