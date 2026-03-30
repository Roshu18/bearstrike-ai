"""MCP server for BearStrike AI.

Exposes pentesting tools as MCP functions and enforces skills-first workflow
before any tool execution.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import queue
import re
import socket
import sqlite3
import sys
import time
import threading
from pathlib import Path
from typing import Any, Dict, List, Set

# Prefer system site-packages over conflicting user-site packages.
for _path in list(sys.path):
    normalized = _path.replace("\\", "/")
    if "/.local/lib/python" in normalized and "site-packages" in normalized:
        try:
            sys.path.remove(_path)
        except ValueError:
            pass

CORE_DIR = Path(__file__).resolve().parent
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from control_plane import (
    active_outstanding_jobs,
    DB_PATH,
    append_run_event,
    cache_stats as db_cache_stats,
    dedupe_stats as db_dedupe_stats,
    ensure_db,
    enforce_target_rotation,
    find_active_job_by_fingerprint,
    get_cached_response,
    list_prioritized_endpoints,
    purge_old_scan_data,
    queue_stats as db_queue_stats,
    record_run_job,
    request_fingerprint,
    research_query as db_research_query,
    research_summary as db_research_summary,
    score_endpoint as db_score_endpoint,
    storage_stats as db_storage_stats,
    upsert_request_cache,
    update_run_job,
    add_hunter_note,
)
from platform_profile import get_platform_profile
from research_pipeline import refresh_research_intel
from runtime_state import (
    discover_recent_target_folders,
    load_runtime_state,
    log_mcp_event,
    target_output_dir,
    target_slug,
    update_runtime_state,
)
from scan_planner import build_scan_plan
from skills_loader import build_skill_lookup, list_skills
from tool_registry import check_installed_tools, load_tools_config
from tool_runner import INTERACTIVE_OR_UNSAFE_TOOLS, build_tool_command_preview, run_tool
from reporting import generate_markdown_report
from strategist import analyze_target_surface

try:
    from mcp.server.fastmcp import FastMCP
except Exception as exc:  # pragma: no cover - environment dependency handling
    FastMCP = None  # type: ignore[assignment]
    FASTMCP_IMPORT_ERROR = exc
else:
    FASTMCP_IMPORT_ERROR = None

logging.getLogger("mcp.server.lowlevel.server").setLevel(logging.WARNING)
logging.getLogger("fastmcp").setLevel(logging.WARNING)

BASE_DIR = Path(__file__).resolve().parents[1]
CONFIG_PATH = BASE_DIR / "config.json"

MCP_BUILD_ID = "bearstrike-mcp-2026-03-29-r6"

COMPACT_TOOL_ALLOWLIST = {
    "nmap",
    "subfinder",
    "httpx",
    "whatweb",
    "nuclei",
    "wafw00f",
    "xray-suite-webscan",
}


def _env_int(name: str, default: int) -> int:
    try:
        return max(1, int(str(os.getenv(name, str(default))).strip()))
    except (TypeError, ValueError):
        return default


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "y", "on"}:
            return True
        if normalized in {"0", "false", "no", "n", "off"}:
            return False
    return default


DEFAULT_MCP_TOOL_TIMEOUT_SECONDS = _env_int("BEARSTRIKE_MCP_TOOL_TIMEOUT_SECONDS", 35)
MAX_MCP_TOOL_TIMEOUT_SECONDS = _env_int("BEARSTRIKE_MCP_TOOL_TIMEOUT_MAX_SECONDS", 90)
DEFAULT_MCP_MAX_RESPONSE_CHARS = _env_int("BEARSTRIKE_MCP_MAX_RESPONSE_CHARS", 12000)
DEFAULT_MCP_DIRECT_WAIT_SECONDS = _env_int("BEARSTRIKE_MCP_DIRECT_WAIT_SECONDS", 6)
WAF_CACHE_TTL_SECONDS = _env_int("BEARSTRIKE_WAF_CACHE_TTL_SECONDS", 300)
MCP_QUEUE_MAX_CONCURRENCY = _env_int("BEARSTRIKE_QUEUE_MAX_CONCURRENCY", 2)
MCP_HEAVY_PER_TARGET = _env_int("BEARSTRIKE_HEAVY_SCAN_PER_TARGET", 1)
MCP_HEAVY_COOLDOWN_SECONDS = _env_int("BEARSTRIKE_HEAVY_COOLDOWN_SECONDS", 45)

CACHE_TTL_PROFILE = {
    "low_noise": _env_int("BEARSTRIKE_CACHE_TTL_LOW_NOISE", 7200),
    "balanced": _env_int("BEARSTRIKE_CACHE_TTL_BALANCED", 2400),
    "aggressive": _env_int("BEARSTRIKE_CACHE_TTL_AGGRESSIVE", 600),
}

ENDPOINT_SCORE_THRESHOLDS = {
    "high": _env_int("BEARSTRIKE_ENDPOINT_SCORE_HIGH", 8),
    "medium": _env_int("BEARSTRIKE_ENDPOINT_SCORE_MEDIUM", 5),
}

HEAVY_TOOLS = {
    "nmap",
    "masscan",
    "rustscan",
    "nuclei",
    "xray-suite-webscan",
    "xray-suite-servicescan",
    "xray-suite-subdomain",
}

TARGET_COMPATIBILITY_DENY_PREFIXES = (
    "binary_",
    "password_",
)

PASSIVE_DNS_ENUM_TOOLS = {
    "amass",
    "assetfinder",
    "dnsenum",
    "dnsx",
    "subfinder",
    "sublist3r",
}

NON_WEB_DOMAIN_TOOLS = {
    "aircrack-ng",
    "bettercap",
    "hydra",
    "kismet",
    "medusa",
    "patator",
    "responder",
    "wifi_pentest",
}

# Prioritize commonly effective bug-hunting tools first (inspired by compact/effectiveness registries).
TOOL_PRIORITY_HINTS: Dict[str, int] = {
    "subfinder": 100,
    "amass": 95,
    "sublist3r": 92,
    "httpx": 100,
    "whatweb": 92,
    "wafw00f": 90,
    "gau": 94,
    "katana": 93,
    "arjun": 92,
    "waybackurls": 89,
    "ffuf": 95,
    "gobuster": 92,
    "dirsearch": 90,
    "nuclei": 100,
    "nikto": 86,
    "sqlmap": 90,
    "dalfox": 88,
    "xray-suite-webscan": 96,
}

_WAF_CACHE_LOCK = threading.Lock()
_WAF_CACHE: Dict[str, Dict[str, Any]] = {}
_EGRESS_PROBE_LOCK = threading.Lock()
_EGRESS_PROBE_CACHE: Dict[str, Any] = {"checked_at": 0.0, "ok": True}

MCP_TOOL_TIMEOUT_OVERRIDES: Dict[str, int] = {
    "nmap": _env_int("BEARSTRIKE_MCP_TIMEOUT_NMAP", 40),
    "httpx": _env_int("BEARSTRIKE_MCP_TIMEOUT_HTTPX", 28),
    "whatweb": _env_int("BEARSTRIKE_MCP_TIMEOUT_WHATWEB", 30),
    "wafw00f": _env_int("BEARSTRIKE_MCP_TIMEOUT_WAFW00F", 20),
    "subfinder": _env_int("BEARSTRIKE_MCP_TIMEOUT_SUBFINDER", 25),
    "nuclei": _env_int("BEARSTRIKE_MCP_TIMEOUT_NUCLEI", 45),
    "xray-suite-webscan": _env_int("BEARSTRIKE_MCP_TIMEOUT_XRAY_WEBSCAN", 90),
    "xray-suite-servicescan": _env_int("BEARSTRIKE_MCP_TIMEOUT_XRAY_SERVICESCAN", 90),
    "xray-suite-subdomain": _env_int("BEARSTRIKE_MCP_TIMEOUT_XRAY_SUBDOMAIN", 90),
}


def _clamp_mcp_timeout(seconds: int) -> int:
    return max(5, min(MAX_MCP_TOOL_TIMEOUT_SECONDS, int(seconds)))


def _resolve_mcp_tool_timeout(tool_name: str) -> int:
    normalized = tool_name.strip().lower()
    raw_timeout = MCP_TOOL_TIMEOUT_OVERRIDES.get(normalized, DEFAULT_MCP_TOOL_TIMEOUT_SECONDS)
    return _clamp_mcp_timeout(int(raw_timeout))



def _truncate_mcp_response(output: str) -> str:
    value = str(output or "")
    if len(value) <= DEFAULT_MCP_MAX_RESPONSE_CHARS:
        return value
    return (
        value[:DEFAULT_MCP_MAX_RESPONSE_CHARS]
        + f"\n\n[response truncated to {DEFAULT_MCP_MAX_RESPONSE_CHARS} chars for MCP responsiveness]"
    )


def _append_mcp_event(**kwargs: Any) -> None:
    payload = {
        "timestamp": float(kwargs.get("timestamp", time.time())),
        "tool": kwargs.get("tool", ""),
        "target": kwargs.get("target", ""),
        "status": kwargs.get("status", ""),
        "progress": kwargs.get("progress", ""),
        "preview": kwargs.get("preview", ""),
        "command": kwargs.get("command", ""),
    }
    try:
        log_mcp_event(payload)
    except Exception:
        # Telemetry must never break MCP request/response flow.
        pass

def _load_config() -> Dict[str, Any]:
    if not CONFIG_PATH.exists():
        return {"mcp_port": 8888}

    try:
        with CONFIG_PATH.open("r", encoding="utf-8-sig") as file:
            raw = file.read().strip()
            return json.loads(raw) if raw else {"mcp_port": 8888}
    except (json.JSONDecodeError, OSError):
        return {"mcp_port": 8888}


def _safe_tool_name(name: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(name or "").strip().lower())
    normalized = re.sub(r"-{2,}", "-", normalized)
    return normalized.strip("-_") or "tool"


def _is_port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", port))
            return True
        except OSError:
            return False


def _choose_mcp_port(preferred_port: int) -> int:
    if _is_port_available(preferred_port):
        return preferred_port

    for candidate in range(preferred_port + 1, preferred_port + 31):
        if _is_port_available(candidate):
            return candidate

    return preferred_port


def _normalize_target_for_waf(target: str) -> str:
    cleaned = target.strip()
    if cleaned.startswith("http://") or cleaned.startswith("https://"):
        return cleaned
    return f"https://{cleaned}"


def _waf_cache_key(target: str) -> str:
    value = target.strip().lower()
    value = re.sub(r"^https?://", "", value, flags=re.IGNORECASE)
    value = value.split("/")[0]
    parts = [part for part in value.split(".") if part]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return value


def _detect_waf_status(target: str) -> str:
    cache_key = _waf_cache_key(target)
    now = time.time()

    with _WAF_CACHE_LOCK:
        cached = _WAF_CACHE.get(cache_key)
        if cached and (now - float(cached.get("at", 0.0))) < WAF_CACHE_TTL_SECONDS:
            return str(cached.get("status") or "Unknown")

    output = run_tool("wafw00f", _normalize_target_for_waf(target), silent=True, timeout_seconds=20)
    clean_output = re.sub(r"\x1b\[[0-9;]*m", "", output)
    lowered = clean_output.lower()

    if "tool not found" in lowered:
        status = "wafw00f not available"
    elif "no waf" in lowered or "is not behind a waf" in lowered:
        status = "No WAF detected"
    elif "seems to be behind a waf or some sort of security solution" in lowered:
        status = "Generic WAF / Security solution"
    else:
        match = re.search(r"behind\s+(.+?)\s+waf", clean_output, flags=re.IGNORECASE)
        if match:
            candidate = match.group(1).strip()
            status = "Generic WAF / Security solution" if candidate.lower() in {"a", "an", "the"} else candidate
        else:
            match_simple = re.search(r"is behind\s+(.+)", clean_output, flags=re.IGNORECASE)
            if match_simple:
                candidate = match_simple.group(1).strip().splitlines()[0][:80]
                if "some sort of security solution" in candidate.lower():
                    status = "Generic WAF / Security solution"
                else:
                    status = candidate
            else:
                status = "Unknown"

    with _WAF_CACHE_LOCK:
        _WAF_CACHE[cache_key] = {"status": status, "at": now}

    return status



def create_mcp_server(
    port: int | None = None,
    host: str = "0.0.0.0",
    compact: bool = False,
) -> "FastMCP":
    if FastMCP is None:
        raise RuntimeError(
            "MCP SDK import failed. Fix dependencies and retry. "
            f"Original error: {FASTMCP_IMPORT_ERROR}"
        )

    config = _load_config()
    ensure_db()
    selected_port = int(port or config.get("mcp_port", 8888))

    queue_max_concurrency = max(1, int(config.get("queue_max_concurrency", MCP_QUEUE_MAX_CONCURRENCY)))
    queue_submission_cap = max(1, int(config.get("queue_submission_cap", queue_max_concurrency)))
    heavy_scan_per_target = max(1, int(config.get("heavy_scan_per_target", MCP_HEAVY_PER_TARGET)))
    heavy_cooldown_seconds = max(5, int(config.get("heavy_scan_cooldown_seconds", MCP_HEAVY_COOLDOWN_SECONDS)))

    cache_ttl_profile = dict(CACHE_TTL_PROFILE)
    raw_cache_profile = config.get("cache_ttl_profile")
    if isinstance(raw_cache_profile, dict):
        for key, value in raw_cache_profile.items():
            try:
                cache_ttl_profile[str(key)] = max(30, int(value))
            except (TypeError, ValueError):
                continue

    endpoint_score_thresholds = dict(ENDPOINT_SCORE_THRESHOLDS)
    raw_thresholds = config.get("endpoint_score_thresholds")
    if isinstance(raw_thresholds, dict):
        for key, value in raw_thresholds.items():
            try:
                endpoint_score_thresholds[str(key)] = int(value)
            except (TypeError, ValueError):
                continue

    try:
        direct_wait_seconds = max(1, min(int(config.get("mcp_direct_wait_seconds", DEFAULT_MCP_DIRECT_WAIT_SECONDS)), 45))
    except (TypeError, ValueError):
        direct_wait_seconds = DEFAULT_MCP_DIRECT_WAIT_SECONDS

    auto_start_on_target = _as_bool(config.get("auto_start_on_target", True), default=True)
    assume_user_authorized_targets = _as_bool(config.get("assume_user_authorized_targets", True), default=True)

    try:
        refresh_interval_hours = max(1, int(config.get("research_refresh_interval_hours", 24)))
    except (TypeError, ValueError):
        refresh_interval_hours = 24
    refresh_interval_seconds = refresh_interval_hours * 3600

    try:
        runtime_snapshot = load_runtime_state()
        last_refresh_at = float(runtime_snapshot.get("research_refreshed_at") or 0.0)
        if (time.time() - last_refresh_at) >= refresh_interval_seconds:
            refreshed = refresh_research_intel(days=30)
            update_runtime_state(
                research_refreshed_at=time.time(),
                research_findings_count=int((refreshed.get("summary") or {}).get("total_findings") or 0),
            )
    except Exception:
        # Research bootstrap should never block MCP startup.
        pass

    skills = list_skills()
    skill_lookup = build_skill_lookup(include_content=False)
    available_skill_names = [
        str(item.get("name", "")).strip().lower()
        for item in skills
        if item.get("name")
    ]

    required_skill_names = list(available_skill_names)
    if "planning" in required_skill_names:
        required_skill_names = ["planning"] + [name for name in required_skill_names if name != "planning"]

    skills_read: Set[str] = set()
    last_set_target_state = {"target": "", "at": 0.0}
    tool_execution_semaphore = threading.BoundedSemaphore(max(1, int(queue_max_concurrency)))
    heavy_state_lock = threading.Lock()
    heavy_active_by_target: Dict[str, int] = {}
    heavy_last_run_by_target: Dict[str, float] = {}

    def _mark_heavy_start(tool_name: str, target: str) -> str | None:
        tool_key = tool_name.strip().lower()
        if tool_key not in HEAVY_TOOLS:
            return None

        target_key = target.strip().lower()
        now = time.time()
        with heavy_state_lock:
            active = int(heavy_active_by_target.get(target_key, 0))
            if active >= int(heavy_scan_per_target):
                return f"Heavy scan limit reached for target {target_key}. Wait for running heavy scan to finish."

            last_at = float(heavy_last_run_by_target.get(target_key, 0.0))
            if last_at > 0 and (now - last_at) < int(heavy_cooldown_seconds):
                remaining = int(heavy_cooldown_seconds - (now - last_at))
                return f"Heavy scan cooldown active for {target_key}. Retry in ~{max(1, remaining)}s."

            heavy_active_by_target[target_key] = active + 1
        return None

    def _mark_heavy_end(tool_name: str, target: str) -> None:
        tool_key = tool_name.strip().lower()
        if tool_key not in HEAVY_TOOLS:
            return

        target_key = target.strip().lower()
        with heavy_state_lock:
            active = int(heavy_active_by_target.get(target_key, 0))
            if active <= 1:
                heavy_active_by_target.pop(target_key, None)
            else:
                heavy_active_by_target[target_key] = active - 1
            heavy_last_run_by_target[target_key] = time.time()

    def _skills_ready() -> bool:
        if not required_skill_names:
            return True
        return set(required_skill_names).issubset(skills_read)

    def _auto_bootstrap_required_skills() -> int:
        loaded = 0
        for skill_name in required_skill_names:
            resolved = _resolve_skill(skill_name, include_content=False)
            if resolved is None:
                continue
            canonical, _content, _meta = resolved
            if canonical not in skills_read:
                skills_read.add(canonical)
                loaded += 1
        return loaded

    def _guard_tool_execution() -> str | None:
        if _skills_ready():
            return None

        _auto_bootstrap_required_skills()
        if _skills_ready():
            return None

        if "planning" in required_skill_names and "planning" not in skills_read:
            return (
                "Skills-first enforcement: planning skill unavailable. "
                "Check skills directory and call bootstrap_skills() to inspect load status."
            )

        missing = [name for name in required_skill_names if name not in skills_read]
        return (
            "Skills-first enforcement: mandatory skills could not be auto-loaded. "
            f"Missing skills: {', '.join(missing)}"
        )

    def _canonical_skill_name(name: str) -> str:
        return name.strip().lower()

    def _resolve_skill(
        name: str,
        include_content: bool = True,
        max_chars: int | None = None,
    ) -> tuple[str, str, Dict[str, str]] | None:
        normalized = _canonical_skill_name(name)
        doc = skill_lookup.get(normalized)
        if doc is None:
            return None

        canonical = _canonical_skill_name(doc.name or doc.path.parent.name)
        content = ""
        if include_content:
            try:
                with doc.path.open("r", encoding="utf-8-sig") as file:
                    if max_chars is not None and max_chars > 0:
                        content = file.read(max_chars).strip()
                    else:
                        content = file.read().strip()
            except OSError:
                content = ""

        meta = {
            "name": doc.name,
            "description": doc.description,
            "path": str(doc.path),
        }
        return canonical, content, meta

    # Preload required skills at server startup so health() reports ready immediately.
    _auto_bootstrap_required_skills()

    def _single_line(text: str, limit: int = 240) -> str:
        normalized = " ".join(str(text or "").replace("\r", " ").replace("\n", " ").split())
        if len(normalized) <= limit:
            return normalized
        return normalized[: limit - 3] + "..."

    def _extract_subdomains_from_output(output: str, root_target: str, max_items: int = 200) -> List[str]:
        text = str(output or "")
        base_domain = _waf_cache_key(root_target)
        if not base_domain:
            return []

        pattern = re.compile(rf"\b(?:[a-zA-Z0-9-]+\.)+{re.escape(base_domain)}\b", re.IGNORECASE)
        seen: Set[str] = set()
        ordered: List[str] = []
        for match in pattern.finditer(text):
            host = str(match.group(0) or "").strip().strip(".").lower()
            if not host or host == base_domain:
                continue
            if host in seen:
                continue
            seen.add(host)
            ordered.append(host)
            if len(ordered) >= max(1, int(max_items)):
                break
        return ordered

    def _target_kind_for_campaign(target: str) -> str:
        value = str(target or "").strip().lower()
        value = re.sub(r"^https?://", "", value, flags=re.IGNORECASE).split("/")[0]
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", value):
            return "ipv4"
        if ":" in value and "." not in value:
            return "ipv6"
        return "domain"

    def _tool_priority_score(tool_name: str, category: str = "") -> int:
        base = int(TOOL_PRIORITY_HINTS.get(str(tool_name or "").strip().lower(), 50))
        cat = str(category or "").strip().lower()
        if cat in {"recon", "web"}:
            base += 10
        if cat in {"exploit"}:
            base += 5
        return base

    def _is_tool_target_compatible(tool_name: str, category: str, target: str) -> bool:
        name = str(tool_name or "").strip().lower()
        cat = str(category or "").strip().lower()
        target_kind = _target_kind_for_campaign(target)

        # Skip interactive/unsafe always.
        if name in INTERACTIVE_OR_UNSAFE_TOOLS:
            return False

        # Tools clearly intended for binaries/password/forensics are not web-domain hunt compatible.
        if cat in {"binary", "forensics", "wireless"}:
            return False
        if name.startswith(TARGET_COMPATIBILITY_DENY_PREFIXES):
            return False
        if name in {
            "angr", "gdb", "gdb-peda", "radare2", "ropgadget", "ropper", "ghidra",
            "john", "hashcat", "password-cracking", "password_cracking", "strings", "xxd",
        }:
            return False

        # For domain campaigns, include broad recon/web/exploit/misc/cloud tools.
        if target_kind == "domain":
            if name in NON_WEB_DOMAIN_TOOLS:
                return False
            return True

        # For IP targets keep network/web compatible tools, skip domain-specific passive enums.
        if target_kind in {"ipv4", "ipv6"} and name in {
            "subfinder",
            "sublist3r",
            "amass",
            "assetfinder",
            "dnsenum",
            "dnsx",
            "waybackurls",
            "gau",
        }:
            return False

        return True

    def _basic_egress_available(ttl_seconds: int = 30) -> bool:
        now = time.time()
        with _EGRESS_PROBE_LOCK:
            checked_at = float(_EGRESS_PROBE_CACHE.get("checked_at") or 0.0)
            cached_ok = bool(_EGRESS_PROBE_CACHE.get("ok", True))
            if (now - checked_at) < max(5, int(ttl_seconds)):
                return cached_ok

        ok = True
        try:
            socket.getaddrinfo("api.github.com", 443, type=socket.SOCK_STREAM)
        except Exception:
            ok = False

        with _EGRESS_PROBE_LOCK:
            _EGRESS_PROBE_CACHE["checked_at"] = now
            _EGRESS_PROBE_CACHE["ok"] = ok
        return ok

    def _infer_exec_status(output: str) -> str:
        lowered = output.lower()

        if "interactive/gui-oriented" in lowered and "disabled in mcp headless mode" in lowered:
            return "blocked"

        if "another bearstrike tool is already running" in lowered:
            return "busy"

        if "primary command timed out" in lowered and "fallback executed" in lowered:
            # Recovery path succeeded enough to continue flow.
            return "success"

        if "timed out" in lowered and "alternative" in lowered and "succeeded" in lowered:
            return "success"

        if "tool not found" in lowered or "tool execution timed out" in lowered:
            return "failed"
        if lowered.startswith("command failed") or "command failed (exit" in lowered:
            return "failed"
        return "success"

    def _update_mcp_runtime(
        *,
        tool_name: str,
        target: str,
        command: str,
        status: str,
        progress: str,
        response_preview: str,
        current_task: str,
    ) -> None:
        update_runtime_state(
            current_target=target,
            current_task=current_task,
            last_mcp_tool=tool_name,
            last_mcp_target=target,
            last_mcp_command=command,
            last_mcp_status=status,
            last_mcp_progress=progress,
            last_mcp_response_preview=response_preview,
        )
        _append_mcp_event(
            tool=tool_name,
            target=target,
            command=command,
            status=status,
            progress=progress,
            preview=response_preview,
        )

    def _execute_with_tracking(
        tool_name: str,
        target: str,
        timeout_seconds_override: int | None = None,
        wait_for_lock: bool = False,
    ) -> str:
        normalized_tool = tool_name.strip()
        normalized_target = target.strip()
        command_preview = build_tool_command_preview(normalized_tool, normalized_target)
        timeout_candidate = _resolve_mcp_tool_timeout(normalized_tool)
        if timeout_seconds_override is not None:
            try:
                timeout_candidate = int(timeout_seconds_override)
            except (TypeError, ValueError):
                timeout_candidate = _resolve_mcp_tool_timeout(normalized_tool)
        timeout_seconds = _clamp_mcp_timeout(timeout_candidate)

        heavy_guard = _mark_heavy_start(normalized_tool, normalized_target)
        if heavy_guard:
            _update_mcp_runtime(
                tool_name=normalized_tool,
                target=normalized_target,
                command=command_preview,
                status="busy",
                progress="queued: heavy scan guard",
                response_preview=_single_line(heavy_guard),
                current_task="tool queue busy",
            )
            return heavy_guard

        acquired_lock = False
        if wait_for_lock:
            tool_execution_semaphore.acquire()
            acquired_lock = True
        else:
            acquired_lock = tool_execution_semaphore.acquire(blocking=False)

        if not acquired_lock:
            _mark_heavy_end(normalized_tool, normalized_target)
            busy_message = (
                f"Concurrency limit reached ({queue_max_concurrency} active jobs). "
                "Wait for a slot, then retry."
            )
            _update_mcp_runtime(
                tool_name=normalized_tool,
                target=normalized_target,
                command=command_preview,
                status="busy",
                progress="queued: waiting for available execution slot",
                response_preview=_single_line(busy_message),
                current_task="tool queue busy",
            )
            return busy_message

        try:
            _update_mcp_runtime(
                tool_name=normalized_tool,
                target=normalized_target,
                command=command_preview,
                status="running",
                progress="1/3 validating request",
                response_preview="",
                current_task=f"running {normalized_tool} via mcp",
            )

            guard_message = _guard_tool_execution()
            if guard_message:
                _update_mcp_runtime(
                    tool_name=normalized_tool,
                    target=normalized_target,
                    command=command_preview,
                    status="blocked",
                    progress="1/3 blocked by skills guard",
                    response_preview=_single_line(guard_message),
                    current_task="idle",
                )
                return guard_message

            _update_mcp_runtime(
                tool_name=normalized_tool,
                target=normalized_target,
                command=command_preview,
                status="running",
                progress=f"2/3 executing command (timeout {timeout_seconds}s)",
                response_preview="",
                current_task=f"running {normalized_tool} via mcp",
            )

            try:
                output = run_tool(normalized_tool, normalized_target, silent=True, timeout_seconds=timeout_seconds)
            except Exception as exc:
                message = f"Internal error while running {normalized_tool}: {exc}"
                _update_mcp_runtime(
                    tool_name=normalized_tool,
                    target=normalized_target,
                    command=command_preview,
                    status="failed",
                    progress="3/3 execution crashed",
                    response_preview=_single_line(message),
                    current_task="idle",
                )
                return message

            final_status = _infer_exec_status(output)
            final_progress = "3/3 completed" if final_status == "success" else "3/3 completed with errors"
            mcp_output = _truncate_mcp_response(output)
            _update_mcp_runtime(
                tool_name=normalized_tool,
                target=normalized_target,
                command=command_preview,
                status=final_status,
                progress=final_progress,
                response_preview=_single_line(mcp_output),
                current_task="idle",
            )
            return mcp_output
        finally:
            if acquired_lock:
                tool_execution_semaphore.release()
            _mark_heavy_end(normalized_tool, normalized_target)

    mcp_jobs: Dict[str, Dict[str, Any]] = {}
    mcp_jobs_lock = threading.Lock()
    mcp_job_queue: queue.Queue[str] = queue.Queue(maxsize=500)
    mcp_job_counter = {"value": 0}
    max_mcp_jobs = 200
    mcp_worker_started = {"value": 0}
    mcp_worker_start_lock = threading.Lock()

    def _new_job_id() -> str:
        with mcp_jobs_lock:
            mcp_job_counter["value"] += 1
            sequence = mcp_job_counter["value"]
        return f"job-{int(time.time() * 1000)}-{sequence:05d}"

    def _prune_jobs() -> None:
        with mcp_jobs_lock:
            if len(mcp_jobs) <= max_mcp_jobs:
                return

            def _job_sort_key(item: tuple[str, Dict[str, Any]]) -> float:
                payload = item[1] if isinstance(item[1], dict) else {}
                return float(payload.get("created_at", 0.0) or 0.0)

            removable = [
                item
                for item in sorted(mcp_jobs.items(), key=_job_sort_key)
                if str((item[1] or {}).get("status", "")).lower() in {"success", "failed", "blocked", "busy"}
            ]
            overflow = max(0, len(mcp_jobs) - max_mcp_jobs)
            for job_id, _payload in removable[:overflow]:
                mcp_jobs.pop(job_id, None)

    def _job_snapshot(job: Dict[str, Any], include_output: bool = False, max_chars: int = 12000) -> Dict[str, Any]:
        payload = {
            "job_id": job.get("job_id"),
            "tool_name": job.get("tool_name"),
            "target": job.get("target"),
            "status": job.get("status"),
            "progress": job.get("progress"),
            "created_at": job.get("created_at"),
            "started_at": job.get("started_at"),
            "finished_at": job.get("finished_at"),
            "timeout_seconds": job.get("timeout_seconds"),
            "mode": job.get("mode", "low_noise"),
            "scope_tag": job.get("scope_tag", ""),
            "fingerprint": job.get("fingerprint", ""),
            "cache_hit": bool(job.get("cache_hit", False)),
            "deduped_to_job_id": job.get("deduped_to_job_id", ""),
            "error": job.get("error", ""),
        }
        if include_output:
            value = str(job.get("output", ""))
            safe_max = max(500, min(int(max_chars), 60000))
            payload["output"] = value[:safe_max]
            payload["output_truncated"] = len(value) > safe_max
        return payload

    def _set_job_fields(job_id: str, **changes: Any) -> None:
        with mcp_jobs_lock:
            job = mcp_jobs.get(job_id)
            if job is None:
                return
            job.update(changes)
            job["updated_at"] = time.time()

    def _outstanding_jobs_count() -> int:
        with mcp_jobs_lock:
            local_outstanding = sum(
                1
                for payload in mcp_jobs.values()
                if str((payload or {}).get("status", "")).strip().lower() in {"queued", "running"}
            )
        try:
            global_outstanding = int(active_outstanding_jobs().get("outstanding", 0))
        except Exception:
            global_outstanding = 0
        return max(local_outstanding, global_outstanding)

    def _enqueue_tool_job(
        *,
        tool_name: str,
        target: str,
        timeout_seconds: int | None,
        mode: str = "low_noise",
        scope_tag: str = "",
        source: str = "mcp",
    ) -> Dict[str, Any]:
        normalized_tool = tool_name.strip()
        normalized_target = target.strip()
        normalized_mode = str(mode or "low_noise").strip().lower()
        normalized_scope = str(scope_tag or "").strip().lower()

        timeout_candidate = _resolve_mcp_tool_timeout(normalized_tool)
        if timeout_seconds is not None:
            try:
                timeout_candidate = int(timeout_seconds)
            except (TypeError, ValueError):
                timeout_candidate = _resolve_mcp_tool_timeout(normalized_tool)
        safe_timeout = _clamp_mcp_timeout(timeout_candidate)

        fingerprint = request_fingerprint(
            tool_name=normalized_tool,
            target=normalized_target,
            params={"timeout_seconds": safe_timeout},
            mode=normalized_mode,
            scope_tag=normalized_scope,
        )

        active = find_active_job_by_fingerprint(fingerprint)
        if active is not None:
            active_job_id = str(active.get("job_id") or "").strip()
            with mcp_jobs_lock:
                active_in_memory = bool(active_job_id and active_job_id in mcp_jobs)

            if not active_in_memory and active_job_id:
                # Prevent cross-process/orphan dedupe loops where status exists in DB
                # but job output/progress is not reachable from this MCP process.
                update_run_job(
                    active_job_id,
                    status="failed",
                    finished_at=time.time(),
                    error="orphaned active job auto-closed (not present in current MCP process)",
                )
                append_run_event(
                    active_job_id,
                    "error",
                    "Auto-closed orphan active job before re-queue",
                    {"fingerprint": fingerprint},
                )
                active = None

        if active is not None:
            dedupe_record_id = f"dedupe-{int(time.time() * 1000)}-{fingerprint[:8]}"
            record_run_job(
                job_id=dedupe_record_id,
                source=source,
                tool_name=normalized_tool,
                target=normalized_target,
                params={"mode": normalized_mode, "scope_tag": normalized_scope},
                fingerprint=fingerprint,
                status="deduped",
                cache_hit=False,
                deduped_to_job_id=str(active.get("job_id") or ""),
            )
            append_run_event(
                str(active.get("job_id") or ""),
                "dedupe",
                f"Merged duplicate request for {normalized_tool} on {normalized_target}",
                {
                    "tool": normalized_tool,
                    "target": normalized_target,
                    "source": source,
                    "mode": normalized_mode,
                },
            )
            return {
                "success": True,
                "status": "deduped",
                "deduped": True,
                "job_id": str(active.get("job_id") or ""),
                "tool_name": normalized_tool,
                "target": normalized_target,
                "fingerprint": fingerprint,
                "mode": normalized_mode,
                "scope_tag": normalized_scope,
            }

        cached = get_cached_response(fingerprint)
        if cached is not None:
            cache_record_id = f"cache-{int(time.time() * 1000)}-{fingerprint[:8]}"
            record_run_job(
                job_id=cache_record_id,
                source=source,
                tool_name=normalized_tool,
                target=normalized_target,
                params={"mode": normalized_mode, "scope_tag": normalized_scope},
                fingerprint=fingerprint,
                status="success",
                cache_hit=True,
                deduped_to_job_id="",
                response_ref=str(cached.get("response_ref") or ""),
            )
            append_run_event(
                f"cache:{fingerprint[:12]}",
                "cache_hit",
                f"Served cached response for {normalized_tool} on {normalized_target}",
                {
                    "tool": normalized_tool,
                    "target": normalized_target,
                    "mode": normalized_mode,
                    "scope_tag": normalized_scope,
                },
            )
            return {
                "success": True,
                "status": "cached",
                "cached": True,
                "tool_name": normalized_tool,
                "target": normalized_target,
                "fingerprint": fingerprint,
                "summary": str(cached.get("summary") or ""),
                "response_ref": str(cached.get("response_ref") or ""),
                "response_excerpt": str(cached.get("response_excerpt") or ""),
                "expires_at": float(cached.get("expires_at") or 0.0),
            }

        if normalized_tool.lower() in PASSIVE_DNS_ENUM_TOOLS and not _basic_egress_available():
            message = (
                f"Network egress/DNS appears unavailable in this WSL session; skipped {normalized_tool} "
                f"to avoid repeated timeout loops."
            )
            append_run_event(
                f"precheck:{fingerprint[:12]}",
                "blocked",
                message,
                {"tool": normalized_tool, "target": normalized_target, "source": source},
            )
            return {
                "success": False,
                "status": "blocked_network",
                "error": message,
                "tool_name": normalized_tool,
                "target": normalized_target,
                "fingerprint": fingerprint,
            }

        outstanding_jobs = _outstanding_jobs_count()
        if outstanding_jobs >= int(queue_submission_cap):
            message = (
                f"Queue submission cap reached ({queue_submission_cap} outstanding jobs). "
                "Wait for running jobs to finish, then retry."
            )
            append_run_event(
                f"throttle:{fingerprint[:12]}",
                "throttled",
                message,
                {
                    "tool": normalized_tool,
                    "target": normalized_target,
                    "source": source,
                    "outstanding_jobs": outstanding_jobs,
                    "queue_submission_cap": queue_submission_cap,
                },
            )
            return {
                "success": False,
                "status": "throttled",
                "error": message,
                "tool_name": normalized_tool,
                "target": normalized_target,
                "fingerprint": fingerprint,
                "outstanding_jobs": outstanding_jobs,
                "queue_submission_cap": int(queue_submission_cap),
            }

        job_id = _new_job_id()
        now = time.time()
        job = {
            "job_id": job_id,
            "tool_name": normalized_tool,
            "target": normalized_target,
            "status": "queued",
            "progress": "queued: waiting for worker",
            "created_at": now,
            "started_at": None,
            "finished_at": None,
            "timeout_seconds": safe_timeout,
            "output": "",
            "error": "",
            "mode": normalized_mode,
            "scope_tag": normalized_scope,
            "fingerprint": fingerprint,
            "cache_hit": False,
            "deduped_to_job_id": "",
            "source": source,
            "updated_at": now,
        }

        with mcp_jobs_lock:
            mcp_jobs[job_id] = job

        record_run_job(
            job_id=job_id,
            source=source,
            tool_name=normalized_tool,
            target=normalized_target,
            params={"timeout_seconds": safe_timeout, "mode": normalized_mode, "scope_tag": normalized_scope},
            fingerprint=fingerprint,
            status="queued",
            cache_hit=False,
            deduped_to_job_id="",
        )
        append_run_event(
            job_id,
            "queued",
            f"Queued {normalized_tool} on {normalized_target}",
            {"mode": normalized_mode, "scope_tag": normalized_scope, "timeout_seconds": safe_timeout},
        )

        _ensure_mcp_job_worker()
        try:
            mcp_job_queue.put_nowait(job_id)
        except Exception:
            with mcp_jobs_lock:
                mcp_jobs.pop(job_id, None)
            update_run_job(job_id, status="failed", error="queue full")
            append_run_event(job_id, "error", "Tool queue is full")
            return {"success": False, "error": "tool queue is full, try again shortly"}

        queue_position = max(0, mcp_job_queue.qsize() - 1)
        return {
            "success": True,
            "status": "queued",
            "job_id": job_id,
            "queue_position": queue_position,
            "tool_name": normalized_tool,
            "target": normalized_target,
            "timeout_seconds": safe_timeout,
            "mode": normalized_mode,
            "scope_tag": normalized_scope,
            "fingerprint": fingerprint,
        }

    def _run_mcp_job(job_id: str) -> None:
        with mcp_jobs_lock:
            job = dict(mcp_jobs.get(job_id) or {})

        if not job:
            return

        tool_name = str(job.get("tool_name") or "").strip()
        target = str(job.get("target") or "").strip()
        timeout_seconds = job.get("timeout_seconds")
        fingerprint = str(job.get("fingerprint") or "")
        mode = str(job.get("mode") or "low_noise")
        scope_tag = str(job.get("scope_tag") or "")

        started_at = time.time()
        _set_job_fields(job_id, status="running", progress="2/3 executing command", started_at=started_at)
        update_run_job(job_id, status="running", started_at=started_at)
        append_run_event(job_id, "running", f"Running {tool_name} on {target}")

        try:
            output = _execute_with_tracking(
                tool_name,
                target,
                timeout_seconds_override=int(timeout_seconds) if timeout_seconds is not None else None,
                wait_for_lock=True,
            )
            status = _infer_exec_status(output)
            final_progress = "3/3 completed" if status == "success" else "3/3 completed with errors"
            finished_at = time.time()
            duration_ms = int((finished_at - started_at) * 1000)
            truncated_output = _truncate_mcp_response(output)
            summary = _single_line(truncated_output, limit=320)

            _set_job_fields(
                job_id,
                status=status,
                progress=final_progress,
                output=truncated_output,
                finished_at=finished_at,
                duration_ms=duration_ms,
            )
            update_run_job(
                job_id,
                status=status,
                finished_at=finished_at,
                duration_ms=duration_ms,
                error="",
            )
            append_run_event(job_id, "finished", f"{tool_name} -> {status}", {"duration_ms": duration_ms})

            if status == "success" and fingerprint:
                upsert_request_cache(
                    fingerprint=fingerprint,
                    tool=tool_name,
                    target=target,
                    params={"timeout_seconds": timeout_seconds},
                    mode=mode,
                    scope_tag=scope_tag,
                    status="success",
                    summary=summary,
                    response_ref="",
                    response_excerpt=summary,
                    ttl_profile=cache_ttl_profile,
                )
        except Exception as exc:
            finished_at = time.time()
            duration_ms = int((finished_at - started_at) * 1000)
            message = f"job runner error: {exc}"
            _set_job_fields(
                job_id,
                status="failed",
                progress="3/3 execution crashed",
                error=message,
                finished_at=finished_at,
                duration_ms=duration_ms,
            )
            update_run_job(
                job_id,
                status="failed",
                finished_at=finished_at,
                duration_ms=duration_ms,
                error=message,
            )
            append_run_event(job_id, "error", message)
        finally:
            _prune_jobs()

    def _mcp_job_worker() -> None:
        while True:
            job_id = mcp_job_queue.get()
            try:
                _run_mcp_job(job_id)
            finally:
                mcp_job_queue.task_done()

    def _ensure_mcp_job_worker() -> None:
        desired_workers = max(1, int(queue_max_concurrency))
        with mcp_worker_start_lock:
            current_workers = int(mcp_worker_started.get("value", 0))
            if current_workers >= desired_workers:
                return
            for idx in range(current_workers, desired_workers):
                thread = threading.Thread(
                    target=_mcp_job_worker,
                    name=f"bearstrike-mcp-job-worker-{idx + 1}",
                    daemon=True,
                )
                thread.start()
            mcp_worker_started["value"] = desired_workers

    def _is_terminal_job_status(status: str) -> bool:
        value = str(status or "").strip().lower()
        return value in {"success", "failed", "blocked", "busy", "cancelled", "canceled"}

    def _wait_for_job_terminal(job_id: str, wait_seconds: int) -> Dict[str, Any] | None:
        safe_wait = max(0.0, float(wait_seconds))
        if safe_wait <= 0:
            return None

        deadline = time.time() + safe_wait
        while time.time() <= deadline:
            with mcp_jobs_lock:
                snapshot = dict(mcp_jobs.get(job_id) or {})

            if not snapshot:
                return None

            if _is_terminal_job_status(str(snapshot.get("status") or "")):
                return snapshot

            time.sleep(0.25)

        return None

    def _recent_tools_for_target(target: str, lookback_hours: int = 24, limit: int = 500) -> Set[str]:
        normalized_target = str(target or "").strip().lower()
        if not normalized_target:
            return set()

        safe_hours = max(1, min(int(lookback_hours), 168))
        safe_limit = max(1, min(int(limit), 5000))
        cutoff = time.time() - (safe_hours * 3600)

        try:
            connection = sqlite3.connect(str(DB_PATH), timeout=5)
            connection.row_factory = sqlite3.Row
            try:
                rows = connection.execute(
                    """
                    SELECT DISTINCT LOWER(tool_name) AS tool_name
                    FROM run_jobs
                    WHERE LOWER(target) = ? AND created_at >= ?
                    ORDER BY created_at DESC
                    LIMIT ?
                    """,
                    [normalized_target, cutoff, safe_limit],
                ).fetchall()
            finally:
                connection.close()
        except sqlite3.Error:
            return set()

        tools_seen: Set[str] = set()
        for row in rows:
            try:
                value = str(dict(row).get("tool_name") or "").strip().lower()
            except Exception:
                value = ""
            if value:
                tools_seen.add(value)
        return tools_seen

    def _compact_hunt_response(payload: Dict[str, Any], verbose: bool = False) -> Dict[str, Any]:
        if bool(verbose):
            return payload

        root = dict(payload.get("root") or {})
        subdomain_discovery = dict(payload.get("subdomain_discovery") or {})
        subdomain_fanout = dict(payload.get("subdomain_fanout") or {})

        root["sample_job_ids"] = list(root.get("sample_job_ids") or [])[:8]
        root["deferred_tools"] = list(root.get("deferred_tools") or [])[:8]
        subdomain_discovery["sample"] = list(subdomain_discovery.get("sample") or [])[:10]
        subdomain_fanout["tools"] = list(subdomain_fanout.get("tools") or [])[:6]

        compact: Dict[str, Any] = {
            "success": bool(payload.get("success", False)),
            "target": str(payload.get("target") or ""),
            "waf_status": str(payload.get("waf_status") or "Unknown"),
            "mode": str(payload.get("mode") or ""),
            "strategy": str(payload.get("strategy") or ""),
            "message": str(payload.get("message") or ""),
            "continue_without_prompt": bool(payload.get("continue_without_prompt", True)),
            "next_phase": str(payload.get("next_phase") or "poll jobs via list_jobs/job_status/job_result"),
            "root": root,
            "subdomain_discovery": subdomain_discovery,
            "subdomain_fanout": subdomain_fanout,
        }

        if "phase_batch_size" in payload:
            compact["phase_batch_size"] = int(payload.get("phase_batch_size") or 0)
        if "campaign" in payload:
            compact["campaign"] = payload.get("campaign")
        if "excluded_reasons" in payload:
            compact["excluded_reasons"] = payload.get("excluded_reasons")
        return compact

    def _derive_signal_tool_hints(outputs: List[str]) -> List[str]:
        text = " ".join(str(item or "") for item in outputs).lower()
        if not text:
            return []

        hints: List[str] = []
        signal_map = [
            (["/api/", "graphql", "oauth", "token", "auth"], ["arjun", "ffuf", "nuclei", "dalfox", "sqlmap"]),
            (["parameter", "query", "=", "endpoint"], ["arjun", "ffuf", "dirsearch"]),
            (["403", "access denied", "blocked", "akamai", "cloudflare", "waf"], ["gau", "waybackurls", "katana", "whatweb"]),
            (["nmap scan report", "open", "tcp", "port"], ["nmap", "nuclei"]),
            (["http/", "server:", "title"], ["httpx", "whatweb", "nuclei"]),
        ]
        for keywords, tools_for_signal in signal_map:
            if any(keyword in text for keyword in keywords):
                hints.extend(tools_for_signal)

        ordered: List[str] = []
        seen: Set[str] = set()
        for name in hints:
            normalized = str(name or "").strip().lower()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            ordered.append(normalized)
        return ordered

    def _format_async_job_hint(job: Dict[str, Any]) -> str:
        job_id = str(job.get("job_id") or "").strip()
        status = str(job.get("status") or "queued").strip().lower()
        progress = _single_line(str(job.get("progress") or status), 120)
        return f"queued job_id={job_id} status={status} progress={progress} use=job_status/job_result"

    def _run_tool_with_async_guard(
        tool_name: str,
        target: str,
        timeout_seconds: int | None = None,
        mode: str = "low_noise",
        scope_tag: str = "direct",
        source: str = "direct_tool",
        wait_seconds: int | None = None,
    ) -> str:
        queued = _enqueue_tool_job(
            tool_name=tool_name,
            target=target,
            timeout_seconds=timeout_seconds,
            mode=mode,
            scope_tag=scope_tag,
            source=source,
        )

        if not bool(queued.get("success", False)):
            return str(queued.get("error") or "failed to queue tool request")

        status = str(queued.get("status") or "queued").strip().lower()
        command_preview = build_tool_command_preview(tool_name, target)
        update_runtime_state(
            current_target=target,
            current_task=f"{status} {tool_name} via mcp",
            last_mcp_tool=tool_name,
            last_mcp_target=target,
            last_mcp_command=command_preview,
            last_mcp_status=status,
            last_mcp_progress=f"{status}: queue-first execution",
            last_mcp_response_preview="",
        )

        if status == "cached":
            summary = str(queued.get("summary") or "").strip()
            excerpt = str(queued.get("response_excerpt") or "").strip()
            payload = f"[cache-hit] {summary}\n{excerpt}".strip()
            update_runtime_state(
                current_target=target,
                current_task="idle",
                last_mcp_status="cached",
                last_mcp_progress="cache-hit",
                last_mcp_response_preview=_single_line(payload, 180),
            )
            return _truncate_mcp_response(payload or "cache-hit")

        if status == "deduped":
            deduped_job_id = str(queued.get("job_id") or "").strip()
            if deduped_job_id:
                ready = _wait_for_job_terminal(deduped_job_id, int(wait_seconds or direct_wait_seconds))
                if ready and _is_terminal_job_status(str(ready.get("status") or "")):
                    output = str(ready.get("output") or "").strip()
                    if output:
                        return _truncate_mcp_response(output)
                    return _format_async_job_hint(ready)
            return f"deduped job_id={deduped_job_id or 'unknown'} use=job_status/job_result"

        job_id = str(queued.get("job_id") or "").strip()
        if not job_id:
            return "queued tool run but job_id was missing"

        ready = _wait_for_job_terminal(job_id, int(wait_seconds or direct_wait_seconds))

        if ready is None:
            hint = _format_async_job_hint({
                "job_id": job_id,
                "status": "queued",
                "progress": "queued: waiting for worker",
                "tool_name": tool_name,
                "target": target,
            })
            update_runtime_state(
                current_target=target,
                current_task=f"queued {tool_name} via mcp",
                last_mcp_status="queued",
                last_mcp_progress="queued: waiting for worker",
                last_mcp_response_preview=_single_line(hint, 180),
            )
            return hint

        output = str(ready.get("output") or "").strip()
        if output:
            return _truncate_mcp_response(output)

        return _format_async_job_hint(ready)
    mcp = FastMCP(
        name="BearStrike MCP",
        instructions=(
            "BearStrike MCP is model-agnostic and client-agnostic. "
            "Works with Claude Desktop, VS Code, Cursor, Antigravity, and any MCP-compatible client. "
            "AI must call bootstrap_skills first (or read required skills with get_skill). "
            "All direct tool calls are queue-first with short wait to prevent MCP transport stalls. "
            "For long scans, use start_tool + job_status + job_result explicitly. "
            "Planning skill must be read before offensive tool usage. "
            "Do not start autonomous/background hunting loops unless the user explicitly requests it. "
            "When a user asks to hunt, execute tools directly and return compact results only. "
            "If the user provides a target/URL/domain, immediately call hunt_target and start scanning. "
            "Treat user-provided target as authorized scope context unless the user explicitly says otherwise. "
            "Do not repeat legal/policy disclaimers once scope context is set in runtime state. "
            "Use full_hunt in adaptive mode by default (small phased batches selected by planner intelligence). "
            "Use full_hunt strategy=all only when user explicitly asks for broad queueing. "
            "After set_target, do not auto-run full_hunt by default; wait for explicit hunt/run command. "
            "Never end with follow-up questions like 'Would you like me to continue?' while actionable next steps remain. "
            "Do not repeatedly ask 'continue?'. Ask only if blocked by missing input or policy boundary. "
            "Avoid informational chatter by default; return concise action/result unless detailed reporting is explicitly requested."
        ),
        host=host,
        port=selected_port,
    )

    platform_profile = get_platform_profile()

    tools: List[dict] = load_tools_config()
    used_mcp_names: Set[str] = set()
    mcp_tool_aliases: Dict[str, List[str]] = {}
    mcp_registration_notes: List[str] = []

    @mcp.tool(name="health", description="Return MCP and session health info.")
    def health_tool() -> Dict[str, Any]:
        runtime = load_runtime_state()
        current_target = str(runtime.get("current_target") or "").strip()
        with mcp_jobs_lock:
            jobs_total = len(mcp_jobs)
            jobs_active = sum(1 for item in mcp_jobs.values() if str(item.get("status", "")).lower() in {"queued", "running"})

        manager = getattr(mcp, "_tool_manager", None)
        total_mcp_tools = len(getattr(manager, "_tools", {})) if manager is not None else len(used_mcp_names)

        return {
            "status": "ok",
            "build": MCP_BUILD_ID,
            "skills_ready": _skills_ready(),
            "registered_tools": len(tools),
            "wrapped_tool_count": len(used_mcp_names),
            "exposed_mcp_tools": total_mcp_tools,
            "compact_profile": compact,
            "queue_depth": mcp_job_queue.qsize(),
            "jobs_total": jobs_total,
            "jobs_active": jobs_active,
            "queue_max_concurrency": queue_max_concurrency,
            "queue_submission_cap": queue_submission_cap,
            "heavy_scan_per_target": heavy_scan_per_target,
            "heavy_cooldown_seconds": heavy_cooldown_seconds,
            "cache_ttl_profile": cache_ttl_profile,
            "cache_stats": db_cache_stats(),
            "dedupe_stats": db_dedupe_stats(),
            "queue_stats": db_queue_stats(),
            "storage_stats": db_storage_stats(),
            "db_path": str(DB_PATH),
            "platform_profile": platform_profile,
            "target_context": {
                "current_target": current_target,
                "target_slug": target_slug(current_target) if current_target else "",
                "target_output_dir": target_output_dir(current_target) if current_target else "",
                "recent_target_folders": discover_recent_target_folders(limit=25),
                "authorization_confirmed": bool(runtime.get("authorization_confirmed", assume_user_authorized_targets)),
                "authorization_target": str(runtime.get("authorization_target") or current_target),
                "authorization_program": str(runtime.get("authorization_program") or ""),
                "authorization_platform": str(runtime.get("authorization_platform") or ""),
            },
            "runtime": runtime,
        }

    @mcp.tool(name="list_tools", description="Return all available BearStrike tool names.")
    def list_tools_tool() -> List[str]:
        all_names = [str(tool.get("name", "")).strip() for tool in tools if tool.get("name")]
        if not compact:
            return all_names
        return [name for name in all_names if name in COMPACT_TOOL_ALLOWLIST]

    @mcp.tool(
        name="mcp_tool_inventory",
        description="Return exact MCP-exposed tool names, alias mapping, and collision notes.",
    )
    def mcp_tool_inventory_tool(include_aliases: bool = False, limit: int = 500) -> Dict[str, Any]:
        try:
            safe_limit = max(1, min(int(limit), 5000))
        except (TypeError, ValueError):
            safe_limit = 500

        manager = getattr(mcp, "_tool_manager", None)
        if manager is not None:
            exposed = sorted(list(getattr(manager, "_tools", {}).keys()))
        else:
            exposed = sorted(list(used_mcp_names))

        result: Dict[str, Any] = {
            "success": True,
            "compact_profile": compact,
            "registered_tools": len(tools),
            "exposed_count": len(exposed),
            "exposed_tools": exposed[:safe_limit],
            "truncated": len(exposed) > safe_limit,
            "collision_notes": list(mcp_registration_notes),
        }

        if include_aliases:
            result["aliases"] = dict(mcp_tool_aliases)

        return result

    @mcp.tool(name="tools_status", description="Return all tools with installed/not_installed status.")
    def tools_status_tool(refresh: bool = False) -> Dict[str, Any]:
        statuses = check_installed_tools(refresh=bool(refresh), quick=not bool(refresh))
        entries: List[Dict[str, str]] = []
        for tool in tools:
            name = str(tool.get("name", "")).strip()
            if not name:
                continue
            entries.append(
                {
                    "name": name,
                    "category": str(tool.get("category", "misc")),
                    "status": str(statuses.get(name, statuses.get(name.lower(), "not_installed"))),
                }
            )

        installed_count = sum(1 for item in entries if item["status"] == "installed")
        return {
            "success": True,
            "count": len(entries),
            "installed": installed_count,
            "not_installed": len(entries) - installed_count,
            "tools": entries,
        }

    @mcp.tool(name="plan_scan", description="Build a low-noise target-aware scan plan to reduce token burn.")
    def plan_scan_tool(target: str = "", mode: str = "low_noise") -> Dict[str, Any]:
        runtime = load_runtime_state()
        resolved_target = target.strip() or str(runtime.get("current_target") or "").strip()
        if not resolved_target:
            return {"success": False, "error": "target is required"}

        statuses = check_installed_tools(refresh=False, quick=True)
        waf_status = str(runtime.get("waf_status") or "Unknown")
        plan = build_scan_plan(
            target=resolved_target,
            tool_statuses=statuses,
            waf_status=waf_status,
            mode=mode,
        )
        return {
            "success": True,
            "plan": plan,
            "execution_policy": {
                "mode": "user_driven",
                "queue_first": True,
                "progress_hint": "use start_tool + job_status + job_result",
            },
        }

    @mcp.tool(name="score_endpoint", description="Deterministically score endpoint risk priority (1-10).")
    def score_endpoint_tool(target: str, endpoint: str, method: str = "GET", context: str = "") -> Dict[str, Any]:
        if not str(target).strip():
            return {"success": False, "error": "target is required"}
        result = db_score_endpoint(
            target=target,
            endpoint=endpoint,
            method=method,
            context=context,
            score_thresholds=endpoint_score_thresholds,
        )
        return {"success": True, **result}

    @mcp.tool(name="research_refresh", description="Refresh curated+verified research intel for recent findings window.")
    def research_refresh_tool(days: int = 30) -> Dict[str, Any]:
        safe_days = max(1, min(int(days), 90))
        return refresh_research_intel(days=safe_days)

    @mcp.tool(name="research_query", description="Query normalized research findings by class/pattern/free text.")
    def research_query_tool(q: str = "", vulnerability_class: str = "", endpoint_pattern: str = "", limit: int = 50) -> Dict[str, Any]:
        return {"success": True, **db_research_query(q=q, vulnerability_class=vulnerability_class, endpoint_pattern=endpoint_pattern, limit=limit)}

    @mcp.tool(name="cache_stats", description="Return cache stats for request fingerprint cache.")
    def cache_stats_tool() -> Dict[str, Any]:
        return {"success": True, **db_cache_stats()}

    @mcp.tool(name="dedupe_stats", description="Return dedupe collapse metrics for queued/running jobs.")
    def dedupe_stats_tool() -> Dict[str, Any]:
        return {"success": True, **db_dedupe_stats()}

    @mcp.tool(name="queue_stats", description="Return durable queue status counters.")
    def queue_stats_tool() -> Dict[str, Any]:
        payload = db_queue_stats()
        payload["in_memory_queue_depth"] = mcp_job_queue.qsize()
        payload["in_memory_jobs_total"] = len(mcp_jobs)
        payload["in_memory_jobs_outstanding"] = _outstanding_jobs_count()
        payload["queue_submission_cap"] = queue_submission_cap
        payload["queue_max_concurrency"] = queue_max_concurrency
        return {"success": True, **payload}

    @mcp.tool(name="hunt_options", description="Show available hunt strategies and token-saving defaults.")
    def hunt_options_tool() -> Dict[str, Any]:
        return {
            "success": True,
            "default_strategy": "adaptive",
            "default_mode": "balanced",
            "token_saving_defaults": {
                "full_hunt": {
                    "strategy": "adaptive",
                    "phase_batch_size": 2,
                    "fanout_tools_per_target": 2,
                    "verbose": False,
                }
            },
            "strategies": {
                "adaptive": "Planner-driven phased batches. Queues small sets, then expands based on results.",
                "diversified": "Category-balanced queueing (medium breadth).",
                "all": "Broad queueing across many installed tools.",
            },
            "recommended_calls": {
                "quiet_default": (
                    "full_hunt(target='example.com', strategy='adaptive', phase_batch_size=2, "
                    "fanout_tools_per_target=2, verbose=False)"
                ),
                "broad_queue": (
                    "full_hunt(target='example.com', strategy='all', max_tools=30, "
                    "fanout_tools_per_target=6, verbose=True)"
                ),
            },
        }

    @mcp.tool(name="purge_old_data", description="Purge scan/job/cache data older than N days (default: 7) to control DB growth.")
    def purge_old_data_tool(
        days: int = 7,
        include_research: bool = False,
        vacuum: bool = True,
        clear_all: bool = False,
    ) -> Dict[str, Any]:
        safe_days = max(1, min(int(days), 3650))
        result = purge_old_scan_data(
            older_than_days=safe_days,
            include_research=bool(include_research),
            vacuum=bool(vacuum),
            clear_all=bool(clear_all),
        )

        update_runtime_state(
            current_task="idle",
            last_mcp_tool="purge_old_data",
            last_mcp_target=f"older_than_days={safe_days}",
            last_mcp_command=(
                f"purge_old_data days={safe_days} include_research={bool(include_research)} "
                f"vacuum={bool(vacuum)} clear_all={bool(clear_all)}"
            ),
            last_mcp_status="success",
            last_mcp_progress="1/1 maintenance complete",
            last_mcp_response_preview=(
                f"{'Cleared all DB runtime data' if bool(clear_all) else f'Purged old data ({safe_days}d)'}."
                f" Reclaimed ~{result.get('reclaimed_mb', 0)} MB"
            ),
        )

        return {"success": True, **result}

    @mcp.tool(
        name="purge_scans",
        description="Alias of purge_old_data. Purge scan/job/cache records older than N days (default: 7).",
    )
    def purge_scans_tool(
        days: int = 7,
        include_research: bool = False,
        vacuum: bool = True,
        clear_all: bool = False,
    ) -> Dict[str, Any]:
        return purge_old_data_tool(days=days, include_research=include_research, vacuum=vacuum, clear_all=clear_all)

    @mcp.tool(name="smart_scan", description="Queue a score-driven phased low-noise scan workflow.")
    def smart_scan_tool(target: str, mode: str = "low_noise", max_steps: int = 4) -> Dict[str, Any]:
        resolved_target = str(target or "").strip() or str(load_runtime_state().get("current_target") or "").strip()
        if not resolved_target:
            return {"success": False, "error": "target is required"}

        statuses = check_installed_tools(refresh=False, quick=True)
        waf_status = str(load_runtime_state().get("waf_status") or "Unknown")
        plan = build_scan_plan(target=resolved_target, tool_statuses=statuses, waf_status=waf_status, mode=mode)

        queued: List[Dict[str, Any]] = []
        deduped: List[Dict[str, Any]] = []
        cached: List[Dict[str, Any]] = []

        safe_max_steps = max(1, min(int(max_steps), 8))
        for step in list(plan.get("recommended_steps") or [])[:safe_max_steps]:
            tool_name = str(step.get("tool") or "").strip()
            timeout_seconds = int(step.get("timeout_seconds") or _resolve_mcp_tool_timeout(tool_name))
            queued_result = _enqueue_tool_job(
                tool_name=tool_name,
                target=resolved_target,
                timeout_seconds=timeout_seconds,
                mode=mode,
                scope_tag="smart_scan",
                source="smart_scan",
            )
            if queued_result.get("status") == "deduped":
                deduped.append(queued_result)
            elif queued_result.get("status") == "cached":
                cached.append(queued_result)
            else:
                queued.append(queued_result)

        endpoint_priority = list_prioritized_endpoints(resolved_target, limit=100)
        return {
            "success": True,
            "target": resolved_target,
            "mode": mode,
            "plan": plan,
            "queued": queued,
            "deduped": deduped,
            "cached": cached,
            "endpoint_priority": endpoint_priority,
            "research_summary": db_research_summary(days=30),
            "execution_policy": {
                "mode": "user_driven",
                "queue_first": True,
                "output_style": "compact",
                "continue_without_prompt": True,
            },
        }

    @mcp.tool(name="list_skills", description="List available BearStrike skill playbooks.")
    def list_skills_tool() -> List[Dict[str, str]]:
        return skills

    @mcp.tool(name="get_skill", description="Get skill markdown content by name with safe size cap.")
    def get_skill_tool(name: str, max_chars: int = 12000) -> str:
        requested = name.strip()
        try:
            parsed_max_chars = int(max_chars)
        except (TypeError, ValueError):
            parsed_max_chars = 12000
        safe_max_chars = max(500, min(parsed_max_chars, 50000))

        update_runtime_state(
            last_mcp_tool="get_skill",
            last_mcp_target=requested,
            last_mcp_command=f"get_skill name={requested} max_chars={safe_max_chars}",
            last_mcp_status="running",
            last_mcp_progress="1/2 resolving skill",
            last_mcp_response_preview="",
            current_task="reading skill via mcp",
        )

        resolved = _resolve_skill(requested)
        if resolved is None:
            message = f"Skill not found: {requested}"
            update_runtime_state(
                last_mcp_tool="get_skill",
                last_mcp_target=requested,
                last_mcp_command=f"get_skill name={requested} max_chars={safe_max_chars}",
                last_mcp_status="failed",
                last_mcp_progress="2/2 skill lookup failed",
                last_mcp_response_preview=message,
                current_task="idle",
            )
            return message

        canonical, content, _meta = resolved
        skills_read.add(canonical)

        truncated = content
        suffix = ""
        if len(content) > safe_max_chars:
            truncated = content[:safe_max_chars]
            suffix = (
                "\n\n---\n"
                f"[truncated] showing first {safe_max_chars} chars. "
                "Call get_skill(name, max_chars=50000) for more."
            )

        update_runtime_state(
            last_mcp_tool="get_skill",
            last_mcp_target=canonical,
            last_mcp_command=f"get_skill name={requested} max_chars={safe_max_chars}",
            last_mcp_status="success",
            last_mcp_progress="2/2 skill loaded",
            last_mcp_response_preview=f"Loaded skill: {canonical}",
            current_task="idle",
        )
        return truncated + suffix

    @mcp.tool(
        name="bootstrap_skills",
        description="Mark mandatory skills as loaded quickly. Set include_content=true to return full markdown.",
    )
    def bootstrap_skills_tool(include_content: bool = False, max_chars: int = 12000) -> Dict[str, Any]:
        start_time = time.time()
        loaded: List[str] = []
        skill_summaries: List[Dict[str, str]] = []
        combined_blocks: List[str] = []
        total_chars = 0
        total_required = len(required_skill_names)

        try:
            parsed_max_chars = int(max_chars)
        except (TypeError, ValueError):
            parsed_max_chars = 12000
        safe_max_chars = max(500, min(parsed_max_chars, 50000))

        command_preview = (
            f"bootstrap_skills include_content={include_content} max_chars={safe_max_chars}"
        )

        update_runtime_state(
            last_mcp_tool="bootstrap_skills",
            last_mcp_target="skills",
            last_mcp_command=command_preview,
            last_mcp_status="running",
            last_mcp_progress=f"starting 0/{total_required}",
            last_mcp_response_preview="",
            current_task="bootstrapping skills",
        )

        for skill_name in required_skill_names:
            resolved = _resolve_skill(
                skill_name,
                include_content=include_content,
                max_chars=safe_max_chars if include_content else None,
            )
            if resolved is None:
                continue

            canonical, content, meta = resolved
            skills_read.add(canonical)
            loaded.append(canonical)
            skill_summaries.append(meta)

            if include_content and total_chars < safe_max_chars:
                block = f"## {meta['name']}\n{content}"
                remaining = safe_max_chars - total_chars
                if len(block) > remaining:
                    block = block[:remaining]
                combined_blocks.append(block)
                total_chars += len(block)

        result = {
            "required_skills": required_skill_names,
            "loaded_skills": sorted(set(loaded)),
            "skills_ready": _skills_ready(),
            "content_included": include_content,
            "skill_summaries": skill_summaries,
            "content": "\n\n".join(combined_blocks) if include_content else "",
            "note": "Use get_skill(name) for full markdown when needed." if not include_content else "",
            "elapsed_ms": int((time.time() - start_time) * 1000),
        }

        update_runtime_state(
            last_mcp_tool="bootstrap_skills",
            last_mcp_target="skills",
            last_mcp_command=command_preview,
            last_mcp_status="success",
            last_mcp_progress=f"completed {len(result['loaded_skills'])}/{total_required}",
            last_mcp_response_preview=(
                f"Bootstrapped {len(result['loaded_skills'])} skills in {result['elapsed_ms']}ms"
            ),
            current_task="idle",
        )
        return result

    @mcp.tool(
        name="skills_status",
        description="Show skills-read status and missing mandatory skills.",
    )
    def skills_status_tool() -> Dict[str, Any]:
        missing = [name for name in required_skill_names if name not in skills_read]
        return {
            "required_skills": required_skill_names,
            "read_skills": sorted(skills_read),
            "missing_skills": missing,
            "skills_ready": _skills_ready(),
        }

    @mcp.tool(name="set_target", description="Set active target. full_hunt runs only when explicitly requested.")
    def set_target_tool(
        target: str,
        auto_continue: bool = False,
        mode: str = "low_noise",
        max_steps: int = 4,
        strategy: str = "adaptive",
        verbose: bool = False,
    ) -> Dict[str, Any]:
        normalized = target.strip()
        if not normalized:
            return {"success": False, "error": "target is required"}

        now = time.time()
        cached_target = str(last_set_target_state.get("target") or "")
        cached_at = float(last_set_target_state.get("at") or 0.0)
        if cached_target.lower() == normalized.lower() and (now - cached_at) < 6:
            return {
                "success": True,
                "target": normalized,
                "waf_status": str(load_runtime_state().get("waf_status") or "pending (run detect_waf)"),
                "duplicate": True,
                "message": "Target already set recently.",
                "continue_without_prompt": bool(auto_continue),
            }

        last_set_target_state["target"] = normalized
        last_set_target_state["at"] = now

        update_runtime_state(
            current_target=normalized,
            waf_status="pending (run detect_waf)",
            current_task="idle",
            authorization_confirmed=assume_user_authorized_targets,
            authorization_target=normalized,
            authorization_program=str(load_runtime_state().get("authorization_program") or ""),
            authorization_platform=str(load_runtime_state().get("authorization_platform") or ""),
            last_mcp_tool="set_target",
            last_mcp_target=normalized,
            last_mcp_command=f"set_target target={normalized}",
            last_mcp_status="success",
            last_mcp_progress="1/1 target set",
            last_mcp_response_preview=f"Target set: {normalized}",
        )
        _append_mcp_event(
            tool="set_target",
            target=normalized,
            command=f"set_target target={normalized}",
            status="success",
            progress="1/1 target set",
            preview=f"Target set: {normalized}",
        )

        rotation_result = enforce_target_rotation(
            window_hours=24,
            threshold_targets=5,
            keep_recent_targets=1,
            delete_reports=True,
            vacuum=False,
        )
        if bool(rotation_result.get("triggered", False)):
            _append_mcp_event(
                tool="target_rotation",
                target=normalized,
                command="auto_cleanup targets>=5 in 24h keep_recent=1",
                status="success",
                progress="1/1 cleanup applied",
                preview=_single_line(
                    f"pruned={len(rotation_result.get('pruned_targets') or [])} "
                    f"kept={len(rotation_result.get('kept_targets') or [])}",
                    140,
                ),
            )

        if not bool(auto_continue):
            return {
                "success": True,
                "target": normalized,
                "waf_status": "pending (run detect_waf)",
                "duplicate": False,
                "message": "Target set successfully.",
                "continue_without_prompt": False,
                "authorization_confirmed": assume_user_authorized_targets,
                "rotation": rotation_result,
            }

        # Use adaptive campaign by default so MCP clients continue without flooding queue.
        should_auto_continue = bool(auto_continue) or bool(auto_start_on_target)
        if not should_auto_continue:
            return {
                "success": True,
                "target": normalized,
                "waf_status": "pending (run detect_waf)",
                "duplicate": False,
                "message": "Target set successfully.",
                "continue_without_prompt": False,
                "authorization_confirmed": assume_user_authorized_targets,
                "rotation": rotation_result,
            }

        hunt_result = full_hunt_tool(
            target=normalized,
            mode=mode,
            include_subdomains=True,
            max_subdomains=12,
            max_tools=6,
            strategy=strategy,
            fanout_tools_per_target=2,
            phase_batch_size=2,
            verbose=verbose,
        )
        queued_count = int(((hunt_result.get("root") or {}).get("counts") or {}).get("queued") or 0)
        deduped_count = int(((hunt_result.get("root") or {}).get("counts") or {}).get("deduped") or 0)
        cached_count = int(((hunt_result.get("root") or {}).get("counts") or {}).get("cached") or 0)
        waf_status = str(hunt_result.get("waf_status") or "Unknown")

        summary = (
            f"auto-continued: full_hunt queued={queued_count} "
            f"deduped={deduped_count} cached={cached_count}"
        )
        update_runtime_state(
            current_target=normalized,
            current_task="hunt-queued",
            last_mcp_tool="set_target",
            last_mcp_target=normalized,
            last_mcp_command=(
                f"set_target target={normalized} auto_continue=true mode={mode} via=full_hunt"
            ),
            last_mcp_status="success",
            last_mcp_progress="2/2 auto-continued hunt phases",
            last_mcp_response_preview=_single_line(summary, 180),
        )

        return {
            "success": True,
            "target": normalized,
            "waf_status": waf_status,
            "duplicate": False,
            "message": summary,
            "continue_without_prompt": True,
            "mode": mode,
            "queued": queued_count,
            "deduped": deduped_count,
            "cached": cached_count,
            "campaign": {
                "strategy": str(hunt_result.get("strategy") or "adaptive"),
                "subdomains": int(((hunt_result.get("subdomain_discovery") or {}).get("count") or 0)),
                "fanout_queued": int(((hunt_result.get("subdomain_fanout") or {}).get("counts") or {}).get("queued") or 0),
            },
            "rotation": rotation_result,
            "authorization_confirmed": assume_user_authorized_targets,
            "next_phase": "poll jobs via list_jobs/job_status/job_result",
        }


    @mcp.tool(name="detect_waf", description="Run wafw00f for current/explicit target and update runtime state.")
    def detect_waf_tool(target: str = "") -> Dict[str, Any]:
        resolved_target = target.strip() or str(load_runtime_state().get("current_target") or "").strip()
        if not resolved_target:
            return {"success": False, "error": "target is required"}

        update_runtime_state(
            last_mcp_tool="detect_waf",
            last_mcp_target=resolved_target,
            last_mcp_command=f"detect_waf target={resolved_target}",
            last_mcp_status="running",
            last_mcp_progress="1/2 running waf detection",
            last_mcp_response_preview="",
            current_task="running detect_waf via mcp",
        )
        _append_mcp_event(
            tool="detect_waf",
            target=resolved_target,
            command=f"detect_waf target={resolved_target}",
            status="running",
            progress="1/2 running waf detection",
            preview="",
        )

        try:
            status = _detect_waf_status(resolved_target)
        except Exception as exc:
            message = f"WAF detection failed: {exc}"
            update_runtime_state(
                last_mcp_tool="detect_waf",
                last_mcp_target=resolved_target,
                last_mcp_command=f"detect_waf target={resolved_target}",
                last_mcp_status="failed",
                last_mcp_progress="2/2 waf detection failed",
                last_mcp_response_preview=message,
                current_task="idle",
            )
            _append_mcp_event(
                tool="detect_waf",
                target=resolved_target,
                command=f"detect_waf target={resolved_target}",
                status="failed",
                progress="2/2 waf detection failed",
                preview=message,
            )
            return {"success": False, "target": resolved_target, "waf_status": "Unknown", "error": message}

        update_runtime_state(
            current_target=resolved_target,
            waf_status=status,
            last_mcp_tool="detect_waf",
            last_mcp_target=resolved_target,
            last_mcp_command=f"detect_waf target={resolved_target}",
            last_mcp_status="success",
            last_mcp_progress="2/2 waf detection complete",
            last_mcp_response_preview=f"WAF: {status}",
            current_task="idle",
        )
        _append_mcp_event(
            tool="detect_waf",
            target=resolved_target,
            command=f"detect_waf target={resolved_target}",
            status="success",
            progress="2/2 waf detection complete",
            preview=f"WAF: {status}",
        )
        return {"success": True, "target": resolved_target, "waf_status": status}

    @mcp.tool(
        name="authorize_target",
        description="Set authorization/scope context once so clients avoid repeated confirmation prompts.",
    )
    def authorize_target_tool(
        target: str,
        authorized: bool = True,
        program: str = "",
        platform: str = "",
        note: str = "",
    ) -> Dict[str, Any]:
        normalized_target = str(target or "").strip()
        if not normalized_target:
            return {"success": False, "error": "target is required"}

        confirmed = bool(authorized)
        update_runtime_state(
            authorization_confirmed=confirmed,
            authorization_target=normalized_target,
            authorization_program=str(program or "").strip(),
            authorization_platform=str(platform or "").strip(),
            authorization_note=str(note or "").strip(),
            last_mcp_tool="authorize_target",
            last_mcp_target=normalized_target,
            last_mcp_command=(
                f"authorize_target target={normalized_target} authorized={confirmed} "
                f"program={str(program or '').strip()} platform={str(platform or '').strip()}"
            ),
            last_mcp_status="success",
            last_mcp_progress="1/1 scope context saved",
            last_mcp_response_preview=_single_line(
                f"authorization_confirmed={confirmed} target={normalized_target}", 180
            ),
            current_task="idle",
        )
        _append_mcp_event(
            tool="authorize_target",
            target=normalized_target,
            command=(
                f"authorize_target target={normalized_target} authorized={confirmed} "
                f"program={str(program or '').strip()} platform={str(platform or '').strip()}"
            ),
            status="success",
            progress="1/1 scope context saved",
            preview=_single_line(f"authorization_confirmed={confirmed} target={normalized_target}", 180),
        )

        return {
            "success": True,
            "authorization_confirmed": confirmed,
            "target": normalized_target,
            "program": str(program or "").strip(),
            "platform": str(platform or "").strip(),
            "note": str(note or "").strip(),
        }

    @mcp.tool(
        name="continue_hunt",
        description="Continue next hunt phases for current/explicit target without asking for confirmation.",
    )
    def continue_hunt_tool(
        target: str = "",
        mode: str = "low_noise",
        max_steps: int = 4,
        strategy: str = "adaptive",
        verbose: bool = False,
    ) -> Dict[str, Any]:
        resolved_target = target.strip() or str(load_runtime_state().get("current_target") or "").strip()
        if not resolved_target:
            return {"success": False, "error": "target is required"}

        hunt_result = full_hunt_tool(
            target=resolved_target,
            mode=mode,
            include_subdomains=True,
            max_subdomains=20,
            max_tools=8,
            strategy=strategy,
            fanout_tools_per_target=2,
            phase_batch_size=2,
            verbose=verbose,
        )

        queued_count = int(((hunt_result.get("root") or {}).get("counts") or {}).get("queued") or 0)
        deduped_count = int(((hunt_result.get("root") or {}).get("counts") or {}).get("deduped") or 0)
        cached_count = int(((hunt_result.get("root") or {}).get("counts") or {}).get("cached") or 0)
        waf_status = str(hunt_result.get("waf_status") or "Unknown")

        summary = (
            f"continued hunt: detect_waf + smart_scan queued={queued_count} "
            f"deduped={deduped_count} cached={cached_count}"
        )

        update_runtime_state(
            current_target=resolved_target,
            current_task="hunt-queued",
            last_mcp_tool="continue_hunt",
            last_mcp_target=resolved_target,
            last_mcp_command=f"continue_hunt target={resolved_target} mode={mode} max_steps={int(max_steps)}",
            last_mcp_status="success",
            last_mcp_progress="1/1 continued hunt phases",
            last_mcp_response_preview=_single_line(summary, 180),
        )
        _append_mcp_event(
            tool="continue_hunt",
            target=resolved_target,
            command=f"continue_hunt target={resolved_target} mode={mode} max_steps={int(max_steps)}",
            status="success",
            progress="1/1 continued hunt phases",
            preview=_single_line(summary, 180),
        )

        return {
            "success": True,
            "target": resolved_target,
            "waf_status": waf_status,
            "message": summary,
            "continue_without_prompt": True,
            "mode": mode,
            "queued": queued_count,
            "deduped": deduped_count,
            "cached": cached_count,
            "campaign": {
                "strategy": str(hunt_result.get("strategy") or "adaptive"),
                "subdomains": int(((hunt_result.get("subdomain_discovery") or {}).get("count") or 0)),
                "fanout_queued": int(((hunt_result.get("subdomain_fanout") or {}).get("counts") or {}).get("queued") or 0),
            },
            "next_phase": "poll jobs via list_jobs/job_status/job_result",
        }

    @mcp.tool(
        name="full_hunt",
        description=(
            "Run a no-prompt hunt campaign. Default strategy is adaptive/phased (small smart batches). "
            "Use strategy=all for broad queueing across many tools."
        ),
    )
    def full_hunt_tool(
        target: str = "",
        mode: str = "balanced",
        include_subdomains: bool = True,
        max_subdomains: int = 20,
        max_tools: int = 0,
        strategy: str = "adaptive",
        include_categories: str = "recon,web,exploit,misc,cloud,binary,forensics,wireless",
        subdomain_wait_seconds: int = 30,
        fanout_tools_per_target: int = 2,
        phase_batch_size: int = 2,
        verbose: bool = False,
    ) -> Dict[str, Any]:
        resolved_target = target.strip() or str(load_runtime_state().get("current_target") or "").strip()
        if not resolved_target:
            return {"success": False, "error": "target is required"}

        # Normalize guardrails for queue health.
        safe_max_subdomains = max(0, min(int(max_subdomains), 120))
        safe_max_tools = max(0, min(int(max_tools), 180))
        safe_wait = max(3, min(int(subdomain_wait_seconds), 90))
        safe_fanout_tools = max(1, min(int(fanout_tools_per_target), 30))
        safe_phase_batch = max(1, min(int(phase_batch_size), 4))
        normalized_strategy = str(strategy or "adaptive").strip().lower()
        allowed_categories = {
            item.strip().lower()
            for item in str(include_categories or "").split(",")
            if item.strip()
        }

        set_result = set_target_tool(
            target=resolved_target,
            auto_continue=False,
            mode=mode,
            max_steps=4,
        )
        waf_result = detect_waf_tool(target=resolved_target)
        waf_status = str(waf_result.get("waf_status") or "Unknown")

        statuses = check_installed_tools(refresh=False, quick=True)

        candidate_entries: List[Dict[str, Any]] = []
        excluded_reasons: Dict[str, int] = {
            "category_filtered": 0,
            "not_installed": 0,
            "interactive_or_unsafe": 0,
            "target_incompatible": 0,
        }
        for tool in tools:
            raw_name = str(tool.get("name") or "").strip()
            if not raw_name:
                continue
            category = str(tool.get("category") or "misc").strip().lower()
            if allowed_categories and category not in allowed_categories:
                excluded_reasons["category_filtered"] += 1
                continue
            if str(statuses.get(raw_name, statuses.get(raw_name.lower(), "not_installed"))).lower() != "installed":
                excluded_reasons["not_installed"] += 1
                continue
            if raw_name in INTERACTIVE_OR_UNSAFE_TOOLS:
                excluded_reasons["interactive_or_unsafe"] += 1
                continue
            if not _is_tool_target_compatible(raw_name, category, resolved_target):
                excluded_reasons["target_incompatible"] += 1
                continue

            candidate_entries.append(
                {
                    "name": raw_name,
                    "category": category,
                    "priority": _tool_priority_score(raw_name, category),
                }
            )

        # Keep deterministic, high-value-first ordering.
        dedup: Dict[str, Dict[str, Any]] = {}
        for item in candidate_entries:
            name = str(item.get("name") or "")
            if name not in dedup or int(item.get("priority") or 0) > int(dedup[name].get("priority") or 0):
                dedup[name] = item
        ordered_entries = sorted(
            dedup.values(),
            key=lambda item: (-int(item.get("priority") or 0), str(item.get("category") or ""), str(item.get("name") or "")),
        )

        # Diversified strategy: take top tools per category first, then fill by priority.
        if normalized_strategy in {"diversified", "category-balanced"}:
            per_category_quota = 5 if safe_max_tools == 0 else max(1, min(6, safe_max_tools // max(1, len(allowed_categories) or 1)))
            by_cat_taken: Dict[str, int] = {}
            diversified: List[Dict[str, Any]] = []
            overflow: List[Dict[str, Any]] = []
            for item in ordered_entries:
                cat = str(item.get("category") or "misc")
                taken = int(by_cat_taken.get(cat, 0))
                if taken < per_category_quota:
                    diversified.append(item)
                    by_cat_taken[cat] = taken + 1
                else:
                    overflow.append(item)
            ordered_entries = diversified + overflow

        candidate_tools = [str(item.get("name") or "") for item in ordered_entries if item.get("name")]
        if safe_max_tools > 0:
            candidate_tools = candidate_tools[:safe_max_tools]

        if normalized_strategy in {"adaptive", "smart", "phased", "hexstyle"}:
            attempted_tools = _recent_tools_for_target(resolved_target, lookback_hours=24, limit=2000)
            adaptive_candidates = [name for name in candidate_tools if name.strip().lower() not in attempted_tools]
            if not adaptive_candidates:
                adaptive_candidates = list(candidate_tools)

            if safe_max_tools > 0:
                adaptive_candidates = adaptive_candidates[:safe_max_tools]

            adaptive_batch = safe_phase_batch
            if safe_max_tools > 0:
                adaptive_batch = min(adaptive_batch, max(1, safe_max_tools))

            selected_root_tools = adaptive_candidates[:adaptive_batch]
            if not selected_root_tools:
                selected_root_tools = candidate_tools[:adaptive_batch]

            if not selected_root_tools:
                return {
                    "success": False,
                    "error": "no compatible installed tools available for adaptive strategy",
                    "target": resolved_target,
                    "strategy": normalized_strategy,
                    "excluded_reasons": excluded_reasons,
                }

            root_counts = {"queued": 0, "deduped": 0, "cached": 0, "failed": 0, "throttled": 0, "blocked_network": 0}
            root_job_ids: List[str] = []
            root_cap_hit = False
            for tool_name in selected_root_tools:
                queued = _enqueue_tool_job(
                    tool_name=tool_name,
                    target=resolved_target,
                    timeout_seconds=_resolve_mcp_tool_timeout(tool_name),
                    mode=mode,
                    scope_tag="full_hunt_root_adaptive",
                    source="full_hunt",
                )
                status = str(queued.get("status") or "")
                if status in root_counts:
                    root_counts[status] += 1
                elif queued.get("success", False):
                    root_counts["queued"] += 1
                else:
                    root_counts["failed"] += 1
                if status == "throttled":
                    root_cap_hit = True
                    break
                job_id = str(queued.get("job_id") or "").strip()
                if job_id:
                    root_job_ids.append(job_id)

            discovered_subdomains: List[str] = []
            root_outputs: List[str] = []
            for job_id in root_job_ids:
                snapshot = _wait_for_job_terminal(job_id, safe_wait)
                output = str((snapshot or {}).get("output") or "")
                if not output:
                    continue
                root_outputs.append(output)
                for item in _extract_subdomains_from_output(
                    output=output,
                    root_target=resolved_target,
                    max_items=safe_max_subdomains,
                ):
                    if item not in discovered_subdomains:
                        discovered_subdomains.append(item)
                    if len(discovered_subdomains) >= safe_max_subdomains:
                        break
                if len(discovered_subdomains) >= safe_max_subdomains:
                    break

            subdomain_tool_used = ""
            if include_subdomains and safe_max_subdomains > 0 and not discovered_subdomains:
                discovery_candidates = [name for name in ["subfinder", "sublist3r", "amass"] if name in candidate_tools]
                if discovery_candidates:
                    subdomain_tool_used = discovery_candidates[0]
                    discover = _enqueue_tool_job(
                        tool_name=subdomain_tool_used,
                        target=resolved_target,
                        timeout_seconds=_resolve_mcp_tool_timeout(subdomain_tool_used),
                        mode=mode,
                        scope_tag="full_hunt_discovery_adaptive",
                        source="full_hunt",
                    )
                    discover_job_id = str(discover.get("job_id") or "").strip()
                    snapshot: Dict[str, Any] | None = None
                    if discover_job_id:
                        snapshot = _wait_for_job_terminal(discover_job_id, safe_wait)
                        if snapshot is None:
                            with mcp_jobs_lock:
                                snapshot = dict(mcp_jobs.get(discover_job_id) or {})
                    output = str((snapshot or {}).get("output") or "")
                    if output:
                        root_outputs.append(output)
                    discovered_subdomains = _extract_subdomains_from_output(
                        output=output,
                        root_target=resolved_target,
                        max_items=safe_max_subdomains,
                    )

            signal_hints = _derive_signal_tool_hints(root_outputs)
            planned_fanout: List[str] = []
            try:
                plan = build_scan_plan(
                    target=resolved_target,
                    tool_statuses=statuses,
                    waf_status=waf_status,
                    mode=mode,
                )
                used_tools = {str(item or "").strip().lower() for item in selected_root_tools}
                for step in list(plan.get("recommended_steps") or []):
                    step_tool = str((step or {}).get("tool") or "").strip().lower()
                    if not step_tool:
                        continue
                    if step_tool in used_tools:
                        continue
                    if step_tool not in [name.lower() for name in candidate_tools]:
                        continue
                    if step_tool in planned_fanout:
                        continue
                    planned_fanout.append(step_tool)
            except Exception:
                planned_fanout = []

            fallback_fanout = [
                "httpx",
                "whatweb",
                "wafw00f",
                "nuclei",
                "katana",
                "gau",
                "waybackurls",
                "arjun",
            ]

            fanout_order = signal_hints + planned_fanout + fallback_fanout
            candidate_lookup = {str(name or "").strip().lower(): str(name or "").strip().lower() for name in candidate_tools}
            fanout_tools: List[str] = []
            seen_fanout: Set[str] = set()
            for name in fanout_order:
                normalized = str(name or "").strip().lower()
                if not normalized or normalized in seen_fanout:
                    continue
                if normalized not in candidate_lookup:
                    continue
                seen_fanout.add(normalized)
                fanout_tools.append(normalized)
            fanout_tools = fanout_tools[: max(1, min(safe_fanout_tools, 3))]
            fanout_target_cap = max(0, min(safe_max_subdomains, 3))

            fanout_counts = {"queued": 0, "deduped": 0, "cached": 0, "failed": 0, "throttled": 0, "blocked_network": 0}
            fanout_cap_hit = False
            if include_subdomains and discovered_subdomains and fanout_tools and fanout_target_cap > 0:
                for subdomain in discovered_subdomains[:fanout_target_cap]:
                    if fanout_cap_hit:
                        break
                    for tool_name in fanout_tools:
                        queued = _enqueue_tool_job(
                            tool_name=tool_name,
                            target=subdomain,
                            timeout_seconds=_resolve_mcp_tool_timeout(tool_name),
                            mode=mode,
                            scope_tag="full_hunt_subdomain_adaptive",
                            source="full_hunt",
                        )
                        status = str(queued.get("status") or "")
                        if status in fanout_counts:
                            fanout_counts[status] += 1
                        elif queued.get("success", False):
                            fanout_counts["queued"] += 1
                        else:
                            fanout_counts["failed"] += 1
                        if status == "throttled":
                            fanout_cap_hit = True
                            break

            summary = (
                f"adaptive full_hunt queued root={root_counts['queued']} deduped={root_counts['deduped']} "
                f"cached={root_counts['cached']} failed={root_counts['failed']} throttled={root_counts['throttled']} "
                f"subdomains={len(discovered_subdomains)} fanout_queued={fanout_counts['queued']} "
                f"fanout_throttled={fanout_counts['throttled']}"
            )

            update_runtime_state(
                current_target=resolved_target,
                current_task="hunt-queued",
                last_mcp_tool="full_hunt",
                last_mcp_target=resolved_target,
                last_mcp_command=(
                    f"full_hunt target={resolved_target} mode={mode} include_subdomains={bool(include_subdomains)} "
                    f"strategy={normalized_strategy} max_subdomains={safe_max_subdomains} max_tools={safe_max_tools or 'all'} "
                    f"phase_batch_size={safe_phase_batch} fanout_tools_per_target={safe_fanout_tools}"
                ),
                last_mcp_status="success",
                last_mcp_progress="1/1 adaptive phased hunt queued",
                last_mcp_response_preview=_single_line(summary, 180),
            )
            _append_mcp_event(
                tool="full_hunt",
                target=resolved_target,
                command=(
                    f"full_hunt target={resolved_target} mode={mode} include_subdomains={bool(include_subdomains)} "
                    f"strategy={normalized_strategy} max_subdomains={safe_max_subdomains} max_tools={safe_max_tools or 'all'} "
                    f"phase_batch_size={safe_phase_batch} fanout_tools_per_target={safe_fanout_tools}"
                ),
                status="success",
                progress="1/1 adaptive phased hunt queued",
                preview=_single_line(summary, 180),
            )

            return _compact_hunt_response(
                {
                    "success": True,
                    "target": resolved_target,
                    "waf_status": waf_status,
                    "set_target": set_result,
                    "continue_without_prompt": True,
                    "mode": mode,
                    "strategy": normalized_strategy,
                    "phase_batch_size": safe_phase_batch,
                    "installed_candidates": len(candidate_tools),
                    "selected_root_tools": selected_root_tools,
                    "excluded_reasons": excluded_reasons,
                    "root": {
                        "counts": root_counts,
                        "sample_job_ids": root_job_ids[:20],
                        "queue_cap_hit": root_cap_hit,
                    },
                    "subdomain_discovery": {
                        "tool": subdomain_tool_used or "from_phase_outputs",
                        "count": len(discovered_subdomains),
                        "sample": discovered_subdomains[:25],
                    },
                    "subdomain_fanout": {
                        "tools": fanout_tools,
                        "counts": fanout_counts,
                        "queue_cap_hit": fanout_cap_hit,
                    },
                    "message": summary,
                    "next_phase": "call continue_hunt for next adaptive batch",
                },
                verbose=bool(verbose),
            )

        root_counts = {"queued": 0, "deduped": 0, "cached": 0, "failed": 0, "throttled": 0, "blocked_network": 0}
        root_job_ids: List[str] = []
        root_deferred_tools: List[str] = []
        root_cap_hit = False
        for tool_name in candidate_tools:
            queued = _enqueue_tool_job(
                tool_name=tool_name,
                target=resolved_target,
                timeout_seconds=_resolve_mcp_tool_timeout(tool_name),
                mode=mode,
                scope_tag="full_hunt_root",
                source="full_hunt",
            )
            status = str(queued.get("status") or "")
            if status in root_counts:
                root_counts[status] += 1
            elif queued.get("success", False):
                root_counts["queued"] += 1
            else:
                root_counts["failed"] += 1
            if status == "blocked_network":
                root_deferred_tools.append(tool_name)
            if status == "throttled":
                root_cap_hit = True
                root_deferred_tools.append(tool_name)
                break
            job_id = str(queued.get("job_id") or "").strip()
            if job_id:
                root_job_ids.append(job_id)

        discovered_subdomains: List[str] = []
        subdomain_tool_used = ""
        fanout_counts = {"queued": 0, "deduped": 0, "cached": 0, "failed": 0, "throttled": 0, "blocked_network": 0}
        fanout_cap_hit = False

        if include_subdomains and safe_max_subdomains > 0:
            discovery_candidates = [name for name in ["subfinder", "sublist3r", "amass"] if name in candidate_tools]
            if discovery_candidates:
                subdomain_tool_used = discovery_candidates[0]
                discover = _enqueue_tool_job(
                    tool_name=subdomain_tool_used,
                    target=resolved_target,
                    timeout_seconds=_resolve_mcp_tool_timeout(subdomain_tool_used),
                    mode=mode,
                    scope_tag="full_hunt_discovery",
                    source="full_hunt",
                )
                discover_job_id = str(discover.get("job_id") or "").strip()
                snapshot: Dict[str, Any] | None = None
                if discover_job_id:
                    snapshot = _wait_for_job_terminal(discover_job_id, safe_wait)
                    if snapshot is None:
                        with mcp_jobs_lock:
                            snapshot = dict(mcp_jobs.get(discover_job_id) or {})
                output = str((snapshot or {}).get("output") or "")
                discovered_subdomains = _extract_subdomains_from_output(
                    output=output,
                    root_target=resolved_target,
                    max_items=safe_max_subdomains,
                )

        preferred_fanout = [
            "httpx", "whatweb", "wafw00f", "nuclei", "nikto",
            "katana", "gau", "waybackurls", "arjun", "ffuf", "dirsearch",
            "sqlmap", "dalfox", "xray-suite-webscan",
        ]
        fanout_tools = [name for name in preferred_fanout if name in candidate_tools][:safe_fanout_tools]
        for subdomain in discovered_subdomains:
            if fanout_cap_hit:
                break
            for tool_name in fanout_tools:
                queued = _enqueue_tool_job(
                    tool_name=tool_name,
                    target=subdomain,
                    timeout_seconds=_resolve_mcp_tool_timeout(tool_name),
                    mode=mode,
                    scope_tag="full_hunt_subdomain",
                    source="full_hunt",
                )
                status = str(queued.get("status") or "")
                if status in fanout_counts:
                    fanout_counts[status] += 1
                elif queued.get("success", False):
                    fanout_counts["queued"] += 1
                else:
                    fanout_counts["failed"] += 1
                if status == "throttled":
                    fanout_cap_hit = True
                    break

        summary = (
            f"full_hunt queued root={root_counts['queued']} deduped={root_counts['deduped']} "
            f"cached={root_counts['cached']} failed={root_counts['failed']} throttled={root_counts['throttled']} "
            f"subdomains={len(discovered_subdomains)} fanout_queued={fanout_counts['queued']} "
            f"fanout_throttled={fanout_counts['throttled']}"
        )

        update_runtime_state(
            current_target=resolved_target,
            current_task="hunt-queued",
            last_mcp_tool="full_hunt",
            last_mcp_target=resolved_target,
            last_mcp_command=(
                f"full_hunt target={resolved_target} mode={mode} include_subdomains={bool(include_subdomains)} "
                f"strategy={normalized_strategy} max_subdomains={safe_max_subdomains} "
                f"max_tools={safe_max_tools or 'all'} fanout_tools_per_target={safe_fanout_tools}"
            ),
            last_mcp_status="success",
            last_mcp_progress="1/1 broad hunt queued",
            last_mcp_response_preview=_single_line(summary, 180),
        )
        _append_mcp_event(
            tool="full_hunt",
            target=resolved_target,
            command=(
                f"full_hunt target={resolved_target} mode={mode} include_subdomains={bool(include_subdomains)} "
                f"strategy={normalized_strategy} max_subdomains={safe_max_subdomains} "
                f"max_tools={safe_max_tools or 'all'} fanout_tools_per_target={safe_fanout_tools}"
            ),
            status="success",
            progress="1/1 broad hunt queued",
            preview=_single_line(summary, 180),
        )

        return _compact_hunt_response(
            {
                "success": True,
                "target": resolved_target,
                "waf_status": waf_status,
                "set_target": set_result,
                "continue_without_prompt": True,
                "mode": mode,
                "strategy": normalized_strategy,
                "installed_candidates": len(candidate_tools),
                "candidate_tools_preview": candidate_tools[:40],
                "excluded_reasons": excluded_reasons,
                "root": {
                    "counts": root_counts,
                    "sample_job_ids": root_job_ids[:20],
                    "deferred_tools": root_deferred_tools[:20],
                    "queue_cap_hit": root_cap_hit,
                },
                "subdomain_discovery": {
                    "tool": subdomain_tool_used or "none",
                    "count": len(discovered_subdomains),
                    "sample": discovered_subdomains[:25],
                },
                "subdomain_fanout": {
                    "tools": fanout_tools,
                    "counts": fanout_counts,
                    "queue_cap_hit": fanout_cap_hit,
                },
                "message": summary,
                "next_phase": "poll jobs via list_jobs/job_status/job_result",
            },
            verbose=bool(verbose),
        )

    @mcp.tool(name="session_state", description="Get BearStrike shared runtime state.")
    def session_state_tool() -> Dict[str, Any]:
        runtime = load_runtime_state()
        current_target = str(runtime.get("current_target") or "").strip()
        return {
            **runtime,
            "target_context": {
                "current_target": current_target,
                "target_slug": target_slug(current_target) if current_target else "",
                "target_output_dir": target_output_dir(current_target) if current_target else "",
                "recent_target_folders": discover_recent_target_folders(limit=25),
            },
        }

    @mcp.tool(name="start_tool", description="Queue a tool run with dedupe/cache guardrails and return immediately.")
    def start_tool(
        tool_name: str,
        target: str,
        timeout_seconds: int | None = None,
        mode: str = "low_noise",
        scope_tag: str = "",
    ) -> Dict[str, Any]:
        normalized_tool = tool_name.strip()
        normalized_target = target.strip()

        if not normalized_tool:
            return {"success": False, "error": "tool_name is required"}
        if not normalized_target:
            return {"success": False, "error": "target is required"}

        queued = _enqueue_tool_job(
            tool_name=normalized_tool,
            target=normalized_target,
            timeout_seconds=timeout_seconds,
            mode=mode,
            scope_tag=scope_tag,
            source="start_tool",
        )
        if not queued.get("success", False):
            return queued

        status = str(queued.get("status") or "queued")
        progress = "queued"
        if status == "deduped":
            progress = f"deduped to existing job {queued.get('job_id')}"
        elif status == "cached":
            progress = "served from cache"
        else:
            progress = f"job queued (position {queued.get('queue_position', 0)})"

        update_runtime_state(
            current_target=normalized_target,
            current_task=f"{status} {normalized_tool} via mcp",
            last_mcp_tool="start_tool",
            last_mcp_target=normalized_target,
            last_mcp_command=f"start_tool tool={normalized_tool} target={normalized_target} mode={mode} scope={scope_tag}",
            last_mcp_status=status,
            last_mcp_progress=progress,
            last_mcp_response_preview=_single_line(str(queued.get("summary") or queued.get("job_id") or "")),
        )
        _append_mcp_event(
            tool="start_tool",
            target=normalized_target,
            command=f"start_tool tool={normalized_tool} target={normalized_target} mode={mode} scope={scope_tag}",
            status=status,
            progress=progress,
            preview=_single_line(str(queued.get("summary") or queued.get("job_id") or "")),
        )
        return queued

    @mcp.tool(name="job_status", description="Get status/progress for a queued tool run job.")
    def job_status(job_id: str) -> Dict[str, Any]:
        with mcp_jobs_lock:
            job = dict(mcp_jobs.get(job_id.strip()) or {})
        if not job:
            return {"success": False, "error": f"job not found: {job_id}"}
        return {"success": True, "job": _job_snapshot(job, include_output=False)}

    @mcp.tool(name="job_result", description="Get final output for a queued job when completed.")
    def job_result(job_id: str, max_chars: int = 12000) -> Dict[str, Any]:
        with mcp_jobs_lock:
            job = dict(mcp_jobs.get(job_id.strip()) or {})
        if not job:
            return {"success": False, "error": f"job not found: {job_id}"}

        status = str(job.get("status") or "").lower()
        if status in {"queued", "running"}:
            return {
                "success": True,
                "ready": False,
                "job": _job_snapshot(job, include_output=False),
                "message": "job still in progress",
            }

        return {
            "success": True,
            "ready": True,
            "job": _job_snapshot(job, include_output=True, max_chars=max_chars),
        }

    @mcp.tool(name="list_jobs", description="List recent MCP tool jobs and their statuses.")
    def list_jobs(limit: int = 20, status: str = "") -> Dict[str, Any]:
        try:
            safe_limit = max(1, min(int(limit), 100))
        except (TypeError, ValueError):
            safe_limit = 20
        status_filter = status.strip().lower()

        with mcp_jobs_lock:
            entries = list(mcp_jobs.values())

        if status_filter:
            entries = [item for item in entries if str(item.get("status", "")).lower() == status_filter]

        entries.sort(key=lambda item: float(item.get("created_at", 0.0) or 0.0), reverse=True)
        return {
            "success": True,
            "count": len(entries),
            "jobs": [_job_snapshot(item, include_output=False) for item in entries[:safe_limit]],
        }

    @mcp.tool(name="execute_tool", description="Execute any registered tool by name against a target.")
    def execute_tool(
        tool_name: str,
        target: str,
        timeout_seconds: int | None = None,
        mode: str = "low_noise",
        scope_tag: str = "sync",
    ) -> str:
        normalized_tool = str(tool_name or "").strip()
        normalized_target = str(target or "").strip()
        if not normalized_tool or not normalized_target:
            return "tool_name and target are required"

        timeout_candidate = _resolve_mcp_tool_timeout(normalized_tool)
        if timeout_seconds is not None:
            try:
                timeout_candidate = int(timeout_seconds)
            except (TypeError, ValueError):
                timeout_candidate = _resolve_mcp_tool_timeout(normalized_tool)

        safe_timeout = _clamp_mcp_timeout(timeout_candidate)
        return _run_tool_with_async_guard(
            tool_name=normalized_tool,
            target=normalized_target,
            timeout_seconds=safe_timeout,
            mode=mode,
            scope_tag=scope_tag or "sync",
            source="execute_tool",
            wait_seconds=direct_wait_seconds,
        )

    @mcp.tool(name="add_hunter_note", description="Add a persistent hunter note for a target.")
    def handle_add_hunter_note(target: str, message: str, confidence: float = 0.0) -> Dict[str, Any]:
        try:
            note = add_hunter_note(target, message, confidence)
        except ValueError as exc:
            return {"success": False, "error": str(exc)}

        update_runtime_state(
            last_mcp_tool="add_hunter_note",
            last_mcp_target=str(note.get("target") or ""),
            last_mcp_command=(
                f"add_hunter_note target={str(target or '').strip()} "
                f"confidence={max(0.0, min(1.0, float(confidence or 0.0))):.2f}"
            ),
            last_mcp_status="success",
            last_mcp_progress="1/1 note saved",
            last_mcp_response_preview=_single_line(str(note.get("message") or ""), 180),
            current_task="idle",
        )
        return {"success": True, "note": note}

    @mcp.tool(name="get_target_report", description="Generate a comprehensive Markdown Bug Bounty vulnerability report for the target.")
    def handle_get_target_report(target: str) -> str:
        return generate_markdown_report(target)
        
    @mcp.tool(name="analyze_target_surface", description="Get strategic advice from the BearStrike internal strategist algorithm for the given target.")
    def handle_analyze_target_surface(target: str) -> str:
        return analyze_target_surface(target)

    for tool in tools:
        raw_name = str(tool.get("name", "")).strip()
        if not raw_name:
            continue
        if compact and raw_name not in COMPACT_TOOL_ALLOWLIST:
            continue

        base_mcp_name = _safe_tool_name(raw_name)
        mcp_name = base_mcp_name
        suffix = 2
        while mcp_name in used_mcp_names:
            mcp_name = f"{base_mcp_name}-{suffix}"
            suffix += 1

        if mcp_name != base_mcp_name:
            mcp_registration_notes.append(
                f"collision resolved: {raw_name} -> {mcp_name}"
            )

        used_mcp_names.add(mcp_name)
        mcp_tool_aliases.setdefault(raw_name, []).append(mcp_name)

        description = str(tool.get("description", "Run BearStrike tool."))

        def _runner(target: str, tool_name: str = raw_name) -> str:
            return _run_tool_with_async_guard(
                tool_name=tool_name,
                target=target,
                timeout_seconds=_resolve_mcp_tool_timeout(tool_name),
                mode="low_noise",
                scope_tag="direct-tool",
                source=f"tool:{tool_name}",
                wait_seconds=direct_wait_seconds,
            )

        _runner.__name__ = f"run_{mcp_name.replace('-', '_')}"
        _runner.__doc__ = f"Run {raw_name} against a target."

        mcp.tool(name=mcp_name, description=description)(_runner)

    return mcp


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="BearStrike MCP server")
    parser.add_argument("--host", default=os.getenv("BEARSTRIKE_MCP_HOST", "0.0.0.0"), help="MCP host (for SSE)")
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("BEARSTRIKE_MCP_PORT", "0")),
        help="Preferred MCP port for SSE mode",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default=os.getenv("MCP_TRANSPORT", "stdio"),
        help="MCP transport for client compatibility",
    )
    parser.add_argument("--compact", action="store_true", help="Register only essential tools for lightweight clients")
    return parser.parse_args()



def _status(message: str) -> None:
    """Write status messages to stderr so stdio JSON-RPC stream stays clean."""
    print(message, file=sys.stderr, flush=True)


def main() -> None:
    if FastMCP is None:
        _status(
            "Failed to start MCP server because MCP dependencies are not healthy.\n"
            f"Error: {FASTMCP_IMPORT_ERROR}"
        )
        return

    args = parse_args()
    config = _load_config()


    if args.transport == "stdio" and sys.stdin.isatty():
        _status("stdio mode is for MCP clients (Claude/Cursor/VS Code) only.")
        _status("For manual terminal test, run: python3 core/mcp_server.py --transport sse --port 8888")
        return

    preferred_port = int(args.port or config.get("mcp_port", 8888))
    selected_port = preferred_port

    if args.transport == "sse":
        selected_port = _choose_mcp_port(preferred_port)
        if selected_port != preferred_port:
            _status(f"[MCP] Port {preferred_port} is busy, using {selected_port} instead.")

    server = create_mcp_server(port=selected_port, host=args.host, compact=args.compact)

    update_runtime_state(mcp_port=selected_port, mcp_transport=args.transport, mcp_url=(f"http://127.0.0.1:{selected_port}/sse" if args.transport == "sse" else "stdio"), current_task="mcp-ready")

    _status(
        f"Starting BearStrike MCP server (transport={args.transport}, host={args.host}, "
        f"port={selected_port}, compact={args.compact})"
    )
    server.run(transport=args.transport)


if __name__ == "__main__":
    main()
