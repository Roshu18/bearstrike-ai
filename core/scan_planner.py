"""Target-aware scan planning for BearStrike.

Planner focuses on low-noise sequencing, token efficiency, and high-signal
bug bounty paths (especially access control and API flaws).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from control_plane import infer_program_context, score_endpoint


def _normalize_target(target: str) -> str:
    value = str(target or "").strip()
    value = re.sub(r"^https?://", "", value, flags=re.IGNORECASE)
    return value.split("/")[0]


def _target_kind(target: str) -> str:
    value = _normalize_target(target)
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", value):
        return "ipv4"
    if ":" in value:
        return "ipv6"
    return "domain"


def _tool_available(name: str, statuses: Dict[str, str]) -> bool:
    direct = statuses.get(name)
    if direct is not None:
        return str(direct).lower() == "installed"
    return str(statuses.get(name.lower(), "not_installed")).lower() == "installed"


def _step(
    tool: str,
    reason: str,
    timeout: int,
    noise: str,
    token_cost: str,
    category: str = "recon",
    phase: str = "recon",
) -> Dict[str, Any]:
    return {
        "tool": tool,
        "reason": reason,
        "timeout_seconds": int(timeout),
        "noise": noise,
        "token_cost": token_cost,
        "category": category,
        "phase": phase,
    }


def _is_waf_detected(waf_status: str) -> bool:
    value = str(waf_status or "").strip().lower()
    if value in {"", "unknown", "pending (run detect_waf)", "no target selected"}:
        return False
    return "no waf" not in value


def _mode_limits(mode: str) -> Dict[str, int]:
    normalized = str(mode or "low_noise").strip().lower()
    if normalized == "aggressive":
        return {"max_steps": 10, "nuclei_timeout": 75, "xray_timeout": 90}
    if normalized == "balanced":
        return {"max_steps": 8, "nuclei_timeout": 60, "xray_timeout": 80}
    return {"max_steps": 6, "nuclei_timeout": 45, "xray_timeout": 65}


def _bug_hunt_focus() -> List[str]:
    return [
        "access-control-idor-bola",
        "auth-session-boundary-checks",
        "api-data-exposure-and-mass-assignment",
        "ssrf-open-redirect-request-routing",
        "xss-input-handling-and-context-breakout",
        "misconfiguration-sensitive-files-and-debug-surfaces",
    ]


def _manual_verification_tasks() -> List[str]:
    return [
        "Build authenticated and unauthenticated request baseline for each sensitive endpoint.",
        "Test horizontal and vertical authorization on object identifiers.",
        "Verify scanner hits with a second request and a benign control payload.",
        "Confirm impact evidence before escalation (data exposure, privilege shift, workflow abuse).",
    ]


def _seed_endpoints_for_scoring(target: str) -> List[Dict[str, str]]:
    normalized = _normalize_target(target)
    host_is_domain = "." in normalized and ":" not in normalized
    base = [
        {"endpoint": "/api/auth/login", "method": "POST"},
        {"endpoint": "/api/user/profile", "method": "GET"},
        {"endpoint": "/internal/health", "method": "GET"},
        {"endpoint": "/graphql", "method": "POST"},
        {"endpoint": "/admin", "method": "GET"},
    ]
    if host_is_domain:
        base.extend(
            [
                {"endpoint": "/api/v1/account?id=1001", "method": "GET"},
                {"endpoint": "/search?q=test", "method": "GET"},
            ]
        )
    return base


def build_scan_plan(
    target: str,
    tool_statuses: Dict[str, str],
    waf_status: str = "Unknown",
    mode: str = "low_noise",
) -> Dict[str, Any]:
    normalized_target = _normalize_target(target)
    target_type = _target_kind(normalized_target)
    normalized_mode = str(mode or "low_noise").strip().lower()

    limits = _mode_limits(normalized_mode)
    waf_detected = _is_waf_detected(waf_status)

    steps: List[Dict[str, Any]] = []
    warnings: List[str] = []
    program_context = infer_program_context(normalized_target, context=normalized_target)

    endpoint_scores: List[Dict[str, Any]] = []
    for candidate in _seed_endpoints_for_scoring(normalized_target):
        endpoint_scores.append(
            score_endpoint(
                target=normalized_target,
                endpoint=str(candidate.get("endpoint") or "/"),
                method=str(candidate.get("method") or "GET"),
                context=program_context.get("platform", "generic"),
            )
        )
    endpoint_scores.sort(key=lambda item: int(item.get("score", 0)), reverse=True)
    high_priority_count = sum(1 for item in endpoint_scores if str(item.get("priority_band")) == "high")


    if target_type == "domain" and _tool_available("subfinder", tool_statuses):
        steps.append(
            _step(
                "subfinder",
                "Passive subdomain discovery for attack-surface map without noisy traffic.",
                35,
                "low",
                "low",
                "recon",
                "discover",
            )
        )

    if target_type == "domain" and not _tool_available("subfinder", tool_statuses) and _tool_available("sublist3r", tool_statuses):
        steps.append(
            _step(
                "sublist3r",
                "Fallback passive subdomain discovery when subfinder is unavailable.",
                40,
                "low",
                "low",
                "recon",
                "discover",
            )
        )

    if target_type == "domain" and normalized_mode in {"balanced", "aggressive"} and _tool_available("amass", tool_statuses):
        steps.append(
            _step(
                "amass",
                "Broader passive+correlated domain mapping to catch hidden assets.",
                50,
                "low",
                "medium",
                "recon",
                "discover",
            )
        )

    if _tool_available("httpx", tool_statuses):
        steps.append(
            _step(
                "httpx",
                "Live host probing and protocol/title/tech baseline for prioritization.",
                25,
                "low",
                "low",
                "recon",
                "profile",
            )
        )

    if _tool_available("whatweb", tool_statuses):
        steps.append(
            _step(
                "whatweb",
                "Web technology fingerprinting to avoid irrelevant payload classes.",
                25,
                "low",
                "low",
                "recon",
                "profile",
            )
        )

    if target_type == "domain" and _tool_available("parsero", tool_statuses):
        steps.append(
            _step(
                "parsero",
                "robots.txt analysis for hidden and disallowed path intelligence.",
                20,
                "low",
                "low",
                "web",
                "endpoint-intel",
            )
        )

    if target_type == "domain" and _tool_available("gau", tool_statuses):
        steps.append(
            _step(
                "gau",
                "Historical URL collection for legacy endpoints and forgotten parameters.",
                35,
                "low",
                "medium",
                "web",
                "endpoint-intel",
            )
        )

    if target_type == "domain" and not _tool_available("gau", tool_statuses) and _tool_available("waybackurls", tool_statuses):
        steps.append(
            _step(
                "waybackurls",
                "Archive URL mining when gau is unavailable.",
                35,
                "low",
                "medium",
                "web",
                "endpoint-intel",
            )
        )

    if target_type == "domain" and _tool_available("katana", tool_statuses):
        steps.append(
            _step(
                "katana",
                "Light crawl for current endpoints to merge with passive URL intelligence.",
                35 if waf_detected else 45,
                "medium" if waf_detected else "low",
                "medium",
                "web",
                "endpoint-intel",
            )
        )

    if target_type == "domain" and _tool_available("arjun", tool_statuses):
        steps.append(
            _step(
                "arjun",
                "Parameter discovery for hidden input vectors on high-value endpoints.",
                40,
                "medium",
                "medium",
                "web",
                "parameter-mapping",
            )
        )

    if _tool_available("nmap", tool_statuses):
        steps.append(
            _step(
                "nmap",
                "Constrained service scan for exposed ports and service misconfiguration clues.",
                30 if normalized_mode == "low_noise" else 45,
                "medium",
                "medium",
                "recon",
                "service-map",
            )
        )

    if _tool_available("nuclei", tool_statuses):
        steps.append(
            _step(
                "nuclei",
                "Template scan after recon confidence; use constrained templates under WAF.",
                limits["nuclei_timeout"],
                "medium",
                "high",
                "scan",
                "vuln-scan",
            )
        )
        if waf_detected:
            warnings.append("WAF detected: keep request rates low and prioritize high-signal template subsets.")

    if normalized_mode in {"balanced", "aggressive"} and _tool_available("xray-suite-webscan", tool_statuses):
        steps.append(
            _step(
                "xray-suite-webscan",
                "Deeper web correlation scan once endpoint map and baseline checks are stable.",
                limits["xray_timeout"],
                "high",
                "high",
                "scan",
                "deep-scan",
            )
        )

    if normalized_mode == "aggressive" and _tool_available("zaproxy", tool_statuses):
        steps.append(
            _step(
                "zaproxy",
                "Automation-assisted baseline app scan after recon confidence is high.",
                55,
                "high",
                "high",
                "scan",
                "deep-scan",
            )
        )

    if normalized_mode == "aggressive" and _tool_available("commix", tool_statuses):
        steps.append(
            _step(
                "commix",
                "Targeted command-injection probe only on validated input vectors.",
                40,
                "high",
                "high",
                "exploit",
                "verification",
            )
        )

    selected = steps[: limits["max_steps"]]

    if not selected:
        warnings.append("No installed tools matched planner rules. Refresh tool status and install core recon tools.")

    high_cost = sum(1 for item in selected if item["token_cost"] == "high")
    if high_cost >= 2:
        estimated_token_cost = "high"
    elif high_cost == 1:
        estimated_token_cost = "medium"
    else:
        estimated_token_cost = "low"

    return {
        "target": normalized_target,
        "target_type": target_type,
        "mode": normalized_mode,
        "waf_status": waf_status,
        "waf_detected": waf_detected,
        "estimated_token_cost": estimated_token_cost,
        "recommended_steps": selected,
        "bug_hunt_focus": _bug_hunt_focus(),
        "manual_verification_tasks": _manual_verification_tasks(),
        "warnings": warnings,
        "execution_hint": "Prefer async flow: start_tool -> job_status -> job_result for long scans.",
        "token_budget_strategy": "Run phases sequentially; stop after first high-confidence path and verify manually.",
    }