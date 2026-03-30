"""Flask dashboard backend for BearStrike AI."""

from __future__ import annotations

import json
import os
import queue
import re
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List

from flask import Flask, Response, jsonify, render_template, request, stream_with_context

try:
    from flask_socketio import SocketIO
except ImportError:
    SocketIO = None  # type: ignore[assignment]


BASE_DIR = Path(__file__).resolve().parents[1]
CORE_DIR = BASE_DIR / "core"
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from control_plane import (  # noqa: E402
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
    load_install_state,
    purge_old_scan_data,
    queue_stats as db_queue_stats,
    record_run_job,
    research_query as db_research_query,
    research_summary as db_research_summary,
    request_fingerprint,
    save_install_state,
    storage_stats as db_storage_stats,
    update_run_job,
    upsert_request_cache,
)
from runtime_state import load_runtime_state, update_runtime_state  # noqa: E402
from tool_registry import check_installed_tools, load_tools_config  # noqa: E402
from tool_runner import run_tool  # noqa: E402
from platform_profile import get_platform_profile  # noqa: E402
from research_pipeline import refresh_research_intel  # noqa: E402


MAX_RESULTS = 500
MAX_RUN_HISTORY = 300
RUN_COOLDOWN_SECONDS = 2
INSTALL_TIMEOUT_SECONDS = 900
TOOL_STATUS_SNAPSHOT_TTL_SECONDS = 30
WAF_CACHE_TTL_SECONDS = 300

JOBS_QUEUE_MAX = 500
JOBS_MAX_HISTORY = 300

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "dashboard" / "templates"),
    static_folder=str(BASE_DIR / "dashboard" / "static"),
)

socketio = SocketIO(app, cors_allowed_origins="*") if SocketIO else None

state: Dict[str, Any] = {
    "start_time": time.time(),
    "current_target": None,
    "waf_status": "No target selected",
    "scan_results": [],
    "run_history": [],
    "active_run": False,
    "last_run_at": 0.0,
    "last_target_set_at": 0.0,
}

_RUN_LOCK = Lock()
_INSTALL_LOCK = Lock()
_ACTIVE_INSTALLS: set[str] = set()

_TOOL_STATUS_SNAPSHOT_LOCK = Lock()
_TOOL_STATUS_SNAPSHOT: Dict[str, Any] = {
    "at": 0.0,
    "total_tools": 0,
    "installed_tools": 0,
}

_WAF_CACHE_LOCK = Lock()
_WAF_CACHE: Dict[str, Dict[str, Any]] = {}

_JOBS_LOCK = Lock()
_JOBS: Dict[str, Dict[str, Any]] = {}
_JOBS_COUNTER = 0
_JOBS_QUEUE: queue.Queue[str] = queue.Queue(maxsize=JOBS_QUEUE_MAX)
_JOBS_WORKER_STARTED = False
_JOBS_WORKER_START_LOCK = Lock()

PLATFORM_PROFILE = get_platform_profile()
ensure_db()


def _dashboard_queue_submission_cap() -> int:
    env_cap = str(os.environ.get("BEARSTRIKE_QUEUE_SUBMISSION_CAP", "")).strip()
    if env_cap:
        try:
            return max(1, int(env_cap))
        except ValueError:
            pass

    config = _load_config()
    try:
        return max(1, int(config.get("queue_submission_cap", config.get("queue_max_concurrency", 2))))
    except (TypeError, ValueError):
        return 2


def _sync_state_from_runtime() -> None:
    runtime = load_runtime_state()

    target = str(runtime.get("current_target") or "").strip()
    waf_status = str(runtime.get("waf_status") or "").strip()

    state["current_target"] = target or None
    state["waf_status"] = waf_status or "No target selected"


def _load_config() -> Dict[str, Any]:
    config_path = BASE_DIR / "config.json"
    if not config_path.exists():
        return {"dashboard_port": 3000, "dashboard_host": "0.0.0.0"}

    try:
        with config_path.open("r", encoding="utf-8-sig") as file:
            raw = file.read().strip()
            if not raw:
                return {"dashboard_port": 3000, "dashboard_host": "0.0.0.0"}
            return json.loads(raw)
    except (json.JSONDecodeError, OSError):
        return {"dashboard_port": 3000, "dashboard_host": "0.0.0.0"}


def _emit(event: str, payload: Dict[str, Any]) -> None:
    if socketio:
        socketio.emit(event, payload)


def _append_result(entry: Dict[str, Any]) -> None:
    state["scan_results"].append(entry)
    if len(state["scan_results"]) > MAX_RESULTS:
        state["scan_results"] = state["scan_results"][-MAX_RESULTS:]


def _append_run(entry: Dict[str, Any]) -> None:
    state["run_history"].append(entry)
    if len(state["run_history"]) > MAX_RUN_HISTORY:
        state["run_history"] = state["run_history"][-MAX_RUN_HISTORY:]


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
    now = time.time()
    key = _waf_cache_key(target)
    with _WAF_CACHE_LOCK:
        cached = _WAF_CACHE.get(key)
        if cached and (now - float(cached.get("at", 0.0))) < WAF_CACHE_TTL_SECONDS:
            return str(cached.get("status") or "Unknown")

    output = run_tool("wafw00f", _normalize_target_for_waf(target), silent=True)
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
        _WAF_CACHE[key] = {"status": status, "at": now}

    return status


def _is_port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", port))
            return True
        except OSError:
            return False


def _choose_port(preferred_port: int) -> int:
    if _is_port_available(preferred_port):
        return preferred_port

    for candidate in range(preferred_port + 1, preferred_port + 31):
        if _is_port_available(candidate):
            return candidate

    return preferred_port


def _status_for_tool_name(tool_name: str, statuses: Dict[str, str]) -> str:
    direct = statuses.get(tool_name)
    if direct:
        return direct

    lowered = tool_name.lower()
    return statuses.get(lowered, "not_installed")


def _invalidate_tool_status_snapshot() -> None:
    with _TOOL_STATUS_SNAPSHOT_LOCK:
        _TOOL_STATUS_SNAPSHOT["at"] = 0.0


def _get_tool_status_snapshot(force_refresh: bool = False) -> Dict[str, int]:
    now = time.time()
    with _TOOL_STATUS_SNAPSHOT_LOCK:
        age = now - float(_TOOL_STATUS_SNAPSHOT.get("at", 0.0))
        if (
            not force_refresh
            and _TOOL_STATUS_SNAPSHOT.get("at", 0.0) > 0
            and age < TOOL_STATUS_SNAPSHOT_TTL_SECONDS
        ):
            return {
                "total_tools": int(_TOOL_STATUS_SNAPSHOT.get("total_tools", 0)),
                "installed_tools": int(_TOOL_STATUS_SNAPSHOT.get("installed_tools", 0)),
            }

    tools = load_tools_config()
    statuses = check_installed_tools(refresh=force_refresh, quick=not force_refresh)
    total_tools = len(tools)
    installed_tools = sum(
        1
        for tool in tools
        if _status_for_tool_name(str(tool.get("name", "")).strip(), statuses) == "installed"
    )

    with _TOOL_STATUS_SNAPSHOT_LOCK:
        _TOOL_STATUS_SNAPSHOT["at"] = now
        _TOOL_STATUS_SNAPSHOT["total_tools"] = total_tools
        _TOOL_STATUS_SNAPSHOT["installed_tools"] = installed_tools

    return {"total_tools": total_tools, "installed_tools": installed_tools}


def _new_job_id() -> str:
    global _JOBS_COUNTER
    with _JOBS_LOCK:
        _JOBS_COUNTER += 1
        sequence = _JOBS_COUNTER
    return f"dash-job-{int(time.time() * 1000)}-{sequence:05d}"


def _job_snapshot(job: Dict[str, Any], include_output: bool = False, max_chars: int = 12000) -> Dict[str, Any]:
    payload = {
        "job_id": job.get("job_id"),
        "tool": job.get("tool"),
        "target": job.get("target"),
        "source": str(job.get("source") or "dashboard"),
        "status": job.get("status"),
        "progress": job.get("progress"),
        "created_at": job.get("created_at"),
        "started_at": job.get("started_at"),
        "finished_at": job.get("finished_at"),
        "timeout_seconds": job.get("timeout_seconds"),
        "mode": job.get("mode", "dashboard"),
        "scope_tag": job.get("scope_tag", "manual"),
        "fingerprint": job.get("fingerprint", ""),
        "retry_of": job.get("retry_of"),
        "cancel_requested": bool(job.get("cancel_requested", False)),
        "error": str(job.get("error") or ""),
    }
    if include_output:
        raw = str(job.get("output") or "")
        safe_max = max(500, min(int(max_chars), 60000))
        payload["output"] = raw[:safe_max]
        payload["output_truncated"] = len(raw) > safe_max
    return payload


def _parse_json_blob(raw: Any) -> Dict[str, Any]:
    blob = str(raw or "").strip()
    if not blob:
        return {}
    try:
        value = json.loads(blob)
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _db_job_from_row(row: sqlite3.Row) -> Dict[str, Any]:
    payload = dict(row)
    params = _parse_json_blob(payload.get("params_json"))
    status = str(payload.get("status") or "queued").strip().lower()
    progress = str(payload.get("last_event_message") or "").strip() or f"{status}: no event yet"

    try:
        timeout_seconds = int(params.get("timeout_seconds") or 0)
    except (TypeError, ValueError):
        timeout_seconds = 0

    return {
        "job_id": str(payload.get("job_id") or ""),
        "tool": str(payload.get("tool_name") or ""),
        "target": str(payload.get("target") or ""),
        "source": str(payload.get("source") or "mcp").strip().lower() or "mcp",
        "status": status,
        "progress": progress,
        "created_at": float(payload.get("created_at") or 0.0),
        "started_at": float(payload.get("started_at") or 0.0) or None,
        "finished_at": float(payload.get("finished_at") or 0.0) or None,
        "timeout_seconds": timeout_seconds,
        "mode": str(params.get("mode") or ""),
        "scope_tag": str(params.get("scope_tag") or ""),
        "fingerprint": str(payload.get("fingerprint") or ""),
        "retry_of": "",
        "cancel_requested": False,
        "error": str(payload.get("error") or ""),
        "response_ref": str(payload.get("response_ref") or ""),
    }


def _query_db_jobs(limit: int, status_filter: str = "", target_filter: str = "") -> List[Dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 400))
    normalized_status = str(status_filter or "").strip().lower()
    normalized_target = str(target_filter or "").strip().lower()
    clauses: List[str] = []
    params: List[Any] = []
    if normalized_status:
        clauses.append("LOWER(j.status) = ?")
        params.append(normalized_status)
    if normalized_target:
        clauses.append("LOWER(j.target) = ?")
        params.append(normalized_target)
    where_clause = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(safe_limit)

    query = f"""
        SELECT
            j.job_id,
            j.source,
            j.tool_name,
            j.target,
            j.params_json,
            j.fingerprint,
            j.status,
            j.created_at,
            j.started_at,
            j.finished_at,
            j.error,
            j.response_ref,
            (
                SELECT re.message
                FROM run_events re
                WHERE re.job_id = j.job_id
                ORDER BY re.id DESC
                LIMIT 1
            ) AS last_event_message
        FROM run_jobs j
        {where_clause}
        ORDER BY j.created_at DESC
        LIMIT ?
    """

    try:
        connection = sqlite3.connect(str(DB_PATH), timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute(query, params).fetchall()
        finally:
            connection.close()
    except sqlite3.Error:
        return []

    return [_db_job_from_row(row) for row in rows]


def _query_db_job(job_id: str) -> Dict[str, Any] | None:
    normalized = str(job_id or "").strip()
    if not normalized:
        return None

    query = """
        SELECT
            j.job_id,
            j.source,
            j.tool_name,
            j.target,
            j.params_json,
            j.fingerprint,
            j.status,
            j.created_at,
            j.started_at,
            j.finished_at,
            j.error,
            j.response_ref,
            (
                SELECT re.message
                FROM run_events re
                WHERE re.job_id = j.job_id
                ORDER BY re.id DESC
                LIMIT 1
            ) AS last_event_message
        FROM run_jobs j
        WHERE j.job_id = ?
        LIMIT 1
    """

    try:
        connection = sqlite3.connect(str(DB_PATH), timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            row = connection.execute(query, [normalized]).fetchone()
        finally:
            connection.close()
    except sqlite3.Error:
        return None

    if row is None:
        return None
    return _db_job_from_row(row)


def _db_job_output(job_id: str, max_chars: int = 12000) -> str:
    normalized = str(job_id or "").strip()
    if not normalized:
        return ""

    safe_max = max(500, min(int(max_chars), 60000))
    try:
        connection = sqlite3.connect(str(DB_PATH), timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute(
                """
                SELECT created_at, event_type, message
                FROM run_events
                WHERE job_id = ?
                ORDER BY id ASC
                LIMIT 200
                """,
                [normalized],
            ).fetchall()
            ref_row = connection.execute(
                "SELECT response_ref FROM run_jobs WHERE job_id = ? LIMIT 1",
                [normalized],
            ).fetchone()
        finally:
            connection.close()
    except sqlite3.Error:
        return ""

    lines: List[str] = []
    for row in rows:
        stamp = float(row["created_at"] or 0.0)
        event_type = str(row["event_type"] or "event").strip().lower()
        message = str(row["message"] or "").strip()
        if not message:
            continue
        lines.append(f"[{time.strftime('%H:%M:%S', time.localtime(stamp))}] {event_type}: {message}")

    response_ref = str((dict(ref_row) if ref_row is not None else {}).get("response_ref") or "").strip()
    if response_ref:
        lines.append(f"[artifact] {response_ref}")

    if not lines:
        return "No DB event output captured for this job yet."
    return "\n".join(lines)[:safe_max]


def _is_output_success(output: str) -> bool:
    lowered = str(output or "").lower()
    return not (
        lowered.startswith("tool not found")
        or lowered.startswith("tool execution timed out")
        or lowered.startswith("command failed")
    )


def _prune_jobs() -> None:
    with _JOBS_LOCK:
        if len(_JOBS) <= JOBS_MAX_HISTORY:
            return

        removable = [
            item
            for item in sorted(_JOBS.items(), key=lambda pair: float((pair[1] or {}).get("created_at", 0.0) or 0.0))
            if str((item[1] or {}).get("status", "")).lower() in {"success", "failed", "cancelled", "canceled"}
        ]
        overflow = max(0, len(_JOBS) - JOBS_MAX_HISTORY)
        for job_id, _payload in removable[:overflow]:
            _JOBS.pop(job_id, None)


def _set_job_fields(job_id: str, **changes: Any) -> None:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return
        job.update(changes)
        job["updated_at"] = time.time()


def _run_dashboard_job(job_id: str) -> None:
    with _JOBS_LOCK:
        job = dict(_JOBS.get(job_id) or {})

    if not job:
        return

    if bool(job.get("cancel_requested", False)):
        finished = time.time()
        _set_job_fields(job_id, status="cancelled", progress="cancelled before execution", finished_at=finished)
        update_run_job(job_id, status="cancelled", finished_at=finished)
        append_run_event(job_id, "cancelled", "Dashboard job cancelled before execution")
        return

    tool = str(job.get("tool") or "").strip().lower()
    target = str(job.get("target") or "").strip()
    timeout_seconds = int(job.get("timeout_seconds") or 45)
    fingerprint = str(job.get("fingerprint") or "")
    mode = str(job.get("mode") or "dashboard")
    scope_tag = str(job.get("scope_tag") or "manual")

    started = time.time()
    _set_job_fields(job_id, status="running", progress="2/3 executing command", started_at=started)
    update_run_job(job_id, status="running", started_at=started)
    append_run_event(job_id, "running", f"Dashboard running {tool} on {target}")
    update_runtime_state(current_target=target, current_task=f"running {tool} via dashboard job")

    try:
        output = run_tool(tool, target, silent=True, timeout_seconds=timeout_seconds)
        if bool(((_JOBS.get(job_id) or {}).get("cancel_requested", False))):
            finished = time.time()
            duration_ms = int((finished - started) * 1000)
            _set_job_fields(job_id, status="cancelled", progress="cancelled", output=output, finished_at=finished)
            update_run_job(job_id, status="cancelled", finished_at=finished, duration_ms=duration_ms)
            append_run_event(job_id, "cancelled", f"Dashboard cancelled {tool} on {target}")
            _append_result({"type": "job", "tool": tool, "target": target, "success": False, "message": f"{tool} cancelled"})
            _emit("job_update", {"job_id": job_id, "status": "cancelled", "tool": tool, "target": target})
            return

        success = _is_output_success(output)
        finished = time.time()
        duration_ms = int((finished - started) * 1000)
        status = "success" if success else "failed"
        _set_job_fields(
            job_id,
            status=status,
            progress="3/3 completed" if success else "3/3 completed with errors",
            output=output,
            finished_at=finished,
        )
        update_run_job(job_id, status=status, finished_at=finished, duration_ms=duration_ms)
        append_run_event(job_id, "finished", f"Dashboard {tool} finished with {status}", {"duration_ms": duration_ms})

        if success and fingerprint:
            preview = str(output or "")[:320]
            upsert_request_cache(
                fingerprint=fingerprint,
                tool=tool,
                target=target,
                params={"timeout_seconds": timeout_seconds},
                mode=mode,
                scope_tag=scope_tag,
                status="success",
                summary=preview,
                response_ref="",
                response_excerpt=preview,
            )

        run_record = {
            "timestamp": time.time(),
            "tool": tool,
            "target": target,
            "output": output,
            "success": success,
        }
        _append_run(run_record)
        _append_result(
            {
                "type": "run",
                "tool": tool,
                "target": target,
                "success": success,
                "message": output[:600],
            }
        )
        _emit("job_update", {"job_id": job_id, "status": status, "tool": tool, "target": target})
        _emit("tool_run", {"tool": tool, "target": target, "success": success, "message": output[:600]})
    except Exception as exc:
        finished = time.time()
        duration_ms = int((finished - started) * 1000)
        message = f"job runner error: {exc}"
        _set_job_fields(
            job_id,
            status="failed",
            progress="3/3 execution crashed",
            error=message,
            finished_at=finished,
        )
        update_run_job(job_id, status="failed", finished_at=finished, duration_ms=duration_ms, error=message)
        append_run_event(job_id, "error", message)
        _emit("job_update", {"job_id": job_id, "status": "failed", "tool": tool, "target": target})
    finally:
        _prune_jobs()
        update_runtime_state(current_task="idle")


def _jobs_worker() -> None:
    while True:
        job_id = _JOBS_QUEUE.get()
        try:
            _run_dashboard_job(job_id)
        finally:
            _JOBS_QUEUE.task_done()


def _ensure_jobs_worker() -> None:
    global _JOBS_WORKER_STARTED
    if _JOBS_WORKER_STARTED:
        return

    with _JOBS_WORKER_START_LOCK:
        if _JOBS_WORKER_STARTED:
            return
        thread = threading.Thread(target=_jobs_worker, name="bearstrike-dashboard-job-worker", daemon=True)
        thread.start()
        _JOBS_WORKER_STARTED = True


def _create_job(tool: str, target: str, timeout_seconds: int = 45, retry_of: str = "", mode: str = "dashboard", scope_tag: str = "manual") -> Dict[str, Any]:
    normalized_tool = tool.strip().lower()
    normalized_target = target.strip()
    safe_timeout = max(5, min(int(timeout_seconds), 300))
    normalized_mode = str(mode or "dashboard").strip().lower()
    normalized_scope = str(scope_tag or "manual").strip().lower()

    fingerprint = request_fingerprint(
        tool_name=normalized_tool,
        target=normalized_target,
        params={"timeout_seconds": safe_timeout},
        mode=normalized_mode,
        scope_tag=normalized_scope,
    )

    job = {
        "job_id": _new_job_id(),
        "tool": normalized_tool,
        "target": normalized_target,
        "status": "queued",
        "progress": "1/3 queued",
        "created_at": time.time(),
        "started_at": None,
        "finished_at": None,
        "timeout_seconds": safe_timeout,
        "mode": normalized_mode,
        "scope_tag": normalized_scope,
        "fingerprint": fingerprint,
        "output": "",
        "error": "",
        "cancel_requested": False,
        "retry_of": retry_of,
        "updated_at": time.time(),
    }

    with _JOBS_LOCK:
        _JOBS[job["job_id"]] = job

    record_run_job(
        job_id=job["job_id"],
        source="dashboard",
        tool_name=normalized_tool,
        target=normalized_target,
        params={"timeout_seconds": safe_timeout, "mode": normalized_mode, "scope_tag": normalized_scope},
        fingerprint=fingerprint,
        status="queued",
    )
    append_run_event(job["job_id"], "queued", f"Dashboard queued {normalized_tool} on {normalized_target}")

    _ensure_jobs_worker()
    _JOBS_QUEUE.put_nowait(job["job_id"])
    return job


def _compact_mcp_events(runtime: Dict[str, Any], limit: int = 20) -> List[Dict[str, Any]]:
    raw = runtime.get("mcp_events")
    if not isinstance(raw, list):
        return []

    safe_limit = max(1, min(int(limit), 100))
    compact: List[Dict[str, Any]] = []
    for item in raw[-safe_limit:]:
        if not isinstance(item, dict):
            continue
        compact.append(
            {
                "timestamp": float(item.get("timestamp") or 0.0),
                "tool": str(item.get("tool") or "")[:64],
                "target": str(item.get("target") or "")[:160],
                "status": str(item.get("status") or "")[:32],
                "progress": str(item.get("progress") or "")[:120],
                "preview": str(item.get("preview") or "")[:220],
                "command": str(item.get("command") or "")[:220],
            }
        )
    return compact


def _build_dashboard_snapshot() -> Dict[str, Any]:
    _sync_state_from_runtime()
    runtime = load_runtime_state()

    stats = _get_tool_status_snapshot(force_refresh=False)
    total_tools = int(stats.get("total_tools", 0))
    installed_tools = int(stats.get("installed_tools", 0))

    with _JOBS_LOCK:
        jobs = list(_JOBS.values())

    queued_jobs = sum(1 for item in jobs if str(item.get("status", "")).lower() == "queued")
    running_jobs = sum(1 for item in jobs if str(item.get("status", "")).lower() == "running")
    done_jobs = sum(1 for item in jobs if str(item.get("status", "")).lower() in {"success", "failed", "cancelled", "canceled"})

    db_cache = db_cache_stats()
    db_dedupe = db_dedupe_stats()
    db_queue = db_queue_stats()

    return {
        "status": "healthy",
        "uptime_seconds": round(time.time() - float(state["start_time"]), 1),
        "current_target": state["current_target"],
        "target_slug": str(runtime.get("target_slug") or ""),
        "target_output_dir": str(runtime.get("target_output_dir") or ""),
        "waf_status": state["waf_status"],
        "results_count": len(state["scan_results"]),
        "runs_count": len(state["run_history"]),
        "total_tools": total_tools,
        "installed_tools": installed_tools,
        "not_installed_tools": total_tools - installed_tools,
        "active_run": bool(state.get("active_run", False)),
        "jobs_total": len(jobs),
        "jobs_queued": queued_jobs,
        "jobs_running": running_jobs,
        "jobs_done": done_jobs,
        "jobs_queue_depth": _JOBS_QUEUE.qsize(),
        "cache_stats": db_cache,
        "dedupe_stats": db_dedupe,
        "queue_stats": db_queue,
        "storage_stats": db_storage_stats(),
        "platform": {
            "platform_kind": PLATFORM_PROFILE.get("platform_kind", "Unknown"),
            "system": PLATFORM_PROFILE.get("system", "Unknown"),
            "is_wsl": bool(PLATFORM_PROFILE.get("is_wsl", False)),
            "package_manager": PLATFORM_PROFILE.get("package_manager", "manual"),
            "python_command": PLATFORM_PROFILE.get("python_command", "python3"),
        },
        "last_mcp_tool": str(runtime.get("last_mcp_tool") or ""),
        "last_mcp_target": str(runtime.get("last_mcp_target") or ""),
        "last_mcp_command": str(runtime.get("last_mcp_command") or ""),
        "last_mcp_status": str(runtime.get("last_mcp_status") or "idle"),
        "last_mcp_progress": str(runtime.get("last_mcp_progress") or ""),
        "last_mcp_response_preview": str(runtime.get("last_mcp_response_preview") or ""),
        "mcp_events": _compact_mcp_events(runtime, limit=20),
    }


@app.get("/")
def index() -> str:
    return render_template("index.html")


@app.get("/api/tools")
def api_tools():
    refresh_flag = str(request.args.get("refresh", "0")).strip().lower() in {"1", "true", "yes", "on"}
    category_filter = str(request.args.get("category", "")).strip().lower()
    status_filter = str(request.args.get("status", "")).strip().lower()
    query_filter = str(request.args.get("q", "")).strip().lower()

    try:
        page = max(1, int(request.args.get("page", 1)))
    except (TypeError, ValueError):
        page = 1

    try:
        page_size = max(1, min(int(request.args.get("page_size", 25)), 200))
    except (TypeError, ValueError):
        page_size = 25

    tools: List[dict] = load_tools_config()
    statuses = check_installed_tools(refresh=refresh_flag, quick=not refresh_flag)

    enriched: List[Dict[str, Any]] = []
    for tool in tools:
        tool_name = str(tool.get("name", "")).strip()
        if not tool_name:
            continue

        tool_data = dict(tool)
        detected_status = _status_for_tool_name(tool_name, statuses)
        tool_data["status"] = detected_status
        enriched.append(tool_data)

        # Observed + user-managed install state persistence.
        save_install_state(
            tool_name=tool_name,
            detected_status=detected_status,
            user_state="observed",
            install_attempted=False,
        )

    installed_tools = sum(1 for tool in enriched if str(tool.get("status")) == "installed")
    with _TOOL_STATUS_SNAPSHOT_LOCK:
        _TOOL_STATUS_SNAPSHOT["at"] = time.time()
        _TOOL_STATUS_SNAPSHOT["total_tools"] = len(enriched)
        _TOOL_STATUS_SNAPSHOT["installed_tools"] = installed_tools

    filtered = enriched
    if category_filter and category_filter not in {"all", "*"}:
        filtered = [item for item in filtered if str(item.get("category", "")).strip().lower() == category_filter]

    if status_filter and status_filter not in {"all", "*"}:
        filtered = [item for item in filtered if str(item.get("status", "")).strip().lower() == status_filter]

    if query_filter:
        filtered = [
            item
            for item in filtered
            if query_filter in f"{item.get('name', '')} {item.get('description', '')} {item.get('category', '')}".lower()
        ]

    total_filtered = len(filtered)
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    page_items = filtered[start_idx:end_idx]
    total_pages = max(1, (total_filtered + page_size - 1) // page_size)

    categories = sorted({str(item.get("category", "misc")).strip().lower() or "misc" for item in enriched})

    return jsonify(
        {
            "tools": page_items,
            "meta": {
                "total": len(enriched),
                "total_filtered": total_filtered,
                "page": page,
                "page_size": page_size,
                "total_pages": total_pages,
                "category": category_filter or "all",
                "status": status_filter or "all",
                "q": query_filter,
                "categories": categories,
            },
        }
    )


@app.get("/api/planner")
def api_planner():
    from scan_planner import build_scan_plan

    payload_target = str(request.args.get("target", "")).strip()
    _sync_state_from_runtime()
    target = payload_target or str(state.get("current_target") or "").strip()
    if not target:
        return jsonify({"error": "target is required"}), 400

    mode = str(request.args.get("mode", "low_noise")).strip() or "low_noise"
    statuses = check_installed_tools(refresh=False, quick=True)
    plan = build_scan_plan(target=target, tool_statuses=statuses, waf_status=str(state.get("waf_status") or "Unknown"), mode=mode)
    return jsonify({"success": True, "plan": plan})


@app.get("/api/endpoints/prioritized")
def api_prioritized_endpoints():
    _sync_state_from_runtime()
    target = str(request.args.get("target", "")).strip() or str(state.get("current_target") or "").strip()
    if not target:
        return jsonify({"success": False, "error": "target is required"}), 400

    try:
        limit = max(1, min(int(request.args.get("limit", 100)), 500))
    except (TypeError, ValueError):
        limit = 100

    priorities = list_prioritized_endpoints(target=target, limit=limit)
    return jsonify({"success": True, "target": target, "priorities": priorities})


@app.get("/api/research/summary")
def api_research_summary():
    try:
        days = max(1, min(int(request.args.get("days", 30)), 90))
    except (TypeError, ValueError):
        days = 30
    summary = db_research_summary(days=days)
    return jsonify({"success": True, **summary})


@app.post("/api/research/refresh")
def api_research_refresh():
    payload = request.get_json(silent=True) or {}
    try:
        days = max(1, min(int(payload.get("days", 30)), 90))
    except (TypeError, ValueError):
        days = 30

    result = refresh_research_intel(days=days)
    return jsonify(result)


@app.get("/api/research/query")
def api_research_query():
    q = str(request.args.get("q", "")).strip()
    vulnerability_class = str(request.args.get("vulnerability_class", "")).strip()
    endpoint_pattern = str(request.args.get("endpoint_pattern", "")).strip()
    try:
        limit = max(1, min(int(request.args.get("limit", 50)), 500))
    except (TypeError, ValueError):
        limit = 50

    payload = db_research_query(
        q=q,
        vulnerability_class=vulnerability_class,
        endpoint_pattern=endpoint_pattern,
        limit=limit,
    )
    return jsonify({"success": True, **payload})


@app.get("/api/cache/stats")
def api_cache_stats():
    return jsonify({"success": True, **db_cache_stats()})


@app.get("/api/dedupe/stats")
def api_dedupe_stats():
    return jsonify({"success": True, **db_dedupe_stats()})


@app.get("/api/install/state")
def api_install_state():
    try:
        limit = max(1, min(int(request.args.get("limit", 1000)), 5000))
    except (TypeError, ValueError):
        limit = 1000
    items = load_install_state(limit=limit)
    return jsonify({"success": True, "count": len(items), "items": items})


@app.post("/api/maintenance/purge")
def api_maintenance_purge():
    payload = request.get_json(silent=True) or {}
    try:
        days = max(1, min(int(payload.get("days", 7)), 3650))
    except (TypeError, ValueError):
        days = 7

    include_research = bool(payload.get("include_research", False))
    vacuum = bool(payload.get("vacuum", True))
    clear_all = bool(payload.get("clear_all", False))

    result = purge_old_scan_data(
        older_than_days=days,
        include_research=include_research,
        vacuum=vacuum,
        clear_all=clear_all,
    )
    _append_result(
        {
            "type": "maintenance",
            "success": True,
            "message": (
                f"Cleared all DB runtime data (reclaimed ~{result.get('reclaimed_mb', 0)} MB)"
                if clear_all
                else f"Purged data older than {days} days (reclaimed ~{result.get('reclaimed_mb', 0)} MB)"
            ),
        }
    )
    return jsonify({"success": True, **result})


@app.get("/api/platform")
def api_platform():
    return jsonify({"success": True, "platform": PLATFORM_PROFILE})


@app.get("/api/dashboard")
def api_dashboard():
    return jsonify(_build_dashboard_snapshot())


@app.get("/api/dashboard/stream")
def api_dashboard_stream() -> Response:
    def generate():
        last_payload = None
        while True:
            payload = json.dumps(_build_dashboard_snapshot(), separators=(",", ":"))
            if payload != last_payload:
                yield f"data: {payload}\n\n"
                last_payload = payload
            else:
                yield ": keepalive\n\n"
            time.sleep(2)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/target")
def api_target():
    _sync_state_from_runtime()

    payload = request.get_json(silent=True) or {}
    target = str(payload.get("target", "")).strip()

    if not target:
        return jsonify({"error": "target is required"}), 400

    now = time.time()
    current_target = str(state.get("current_target") or "").strip()
    if current_target and current_target.lower() == target.lower():
        if now - float(state.get("last_target_set_at", 0.0)) < 10:
            return jsonify(
                {
                    "success": True,
                    "target": current_target,
                    "waf_status": state.get("waf_status", "Unknown"),
                    "duplicate": True,
                }
            )

    waf_status = _detect_waf_status(target)

    state["current_target"] = target
    state["waf_status"] = waf_status
    state["last_target_set_at"] = now
    _append_result({"type": "target", "message": f"Target set to {target} (WAF: {waf_status})"})
    _emit("target_updated", {"target": target, "waf_status": waf_status})

    update_runtime_state(current_target=target, waf_status=waf_status, current_task="idle")
    rotation_result = enforce_target_rotation(
        window_hours=24,
        threshold_targets=5,
        keep_recent_targets=1,
        delete_reports=True,
        vacuum=False,
    )

    return jsonify(
        {
            "success": True,
            "target": target,
            "waf_status": waf_status,
            "duplicate": False,
            "rotation": rotation_result,
        }
    )


@app.post("/api/run")
def api_run():
    _sync_state_from_runtime()

    payload = request.get_json(silent=True) or {}
    tool_name = str(payload.get("tool", "")).strip().lower()
    target = str(payload.get("target", state["current_target"] or "")).strip()

    if not tool_name:
        return jsonify({"error": "tool is required"}), 400
    if not target:
        return jsonify({"error": "target is required"}), 400

    now = time.time()
    with _RUN_LOCK:
        if bool(state.get("active_run", False)):
            return jsonify({"success": False, "error": "Another run is already in progress"}), 429

        if now - float(state.get("last_run_at", 0.0)) < RUN_COOLDOWN_SECONDS:
            return jsonify({"success": False, "error": "Run cooldown active. Please wait and retry."}), 429

        state["active_run"] = True
    update_runtime_state(current_target=target, current_task=f"running {tool_name} on {target}")

    try:
        output = run_tool(tool_name, target, silent=True)
        success = _is_output_success(output)

        run_record = {
            "timestamp": time.time(),
            "tool": tool_name,
            "target": target,
            "output": output,
            "success": success,
        }
        _append_run(run_record)

        _append_result(
            {
                "type": "run",
                "tool": tool_name,
                "target": target,
                "success": success,
                "message": output[:600],
            }
        )
        _emit("tool_run", {"tool": tool_name, "target": target, "success": success, "message": output[:600]})

        response = {"success": success, "tool": tool_name, "target": target, "output": output}
        return (jsonify(response), 200) if success else (jsonify(response), 400)
    finally:
        with _RUN_LOCK:
            state["active_run"] = False
            state["last_run_at"] = time.time()
        update_runtime_state(current_task="idle")


@app.post("/api/jobs/start")
def api_jobs_start():
    payload = request.get_json(silent=True) or {}
    tool_name = str(payload.get("tool", "")).strip().lower()
    target = str(payload.get("target", state.get("current_target") or "")).strip()
    mode = str(payload.get("mode", "dashboard")).strip().lower() or "dashboard"
    scope_tag = str(payload.get("scope_tag", "manual")).strip().lower() or "manual"

    if not tool_name:
        return jsonify({"success": False, "error": "tool is required"}), 400
    if not target:
        return jsonify({"success": False, "error": "target is required"}), 400

    try:
        timeout_seconds = int(payload.get("timeout_seconds", 45))
    except (TypeError, ValueError):
        timeout_seconds = 45

    safe_timeout = max(5, min(timeout_seconds, 300))
    fingerprint = request_fingerprint(
        tool_name=tool_name,
        target=target,
        params={"timeout_seconds": safe_timeout},
        mode=mode,
        scope_tag=scope_tag,
    )

    active = find_active_job_by_fingerprint(fingerprint)
    if active is not None:
        message = f"Merged with existing job {active.get('job_id')}"
        _append_result({"type": "job", "tool": tool_name, "target": target, "success": True, "message": message})
        return jsonify(
            {
                "success": True,
                "status": "deduped",
                "deduped": True,
                "job_id": str(active.get("job_id") or ""),
                "fingerprint": fingerprint,
                "message": message,
            }
        )

    cached = get_cached_response(fingerprint)
    if cached is not None:
        message = f"Served from cache for {tool_name} on {target}"
        _append_result({"type": "job", "tool": tool_name, "target": target, "success": True, "message": message})
        return jsonify(
            {
                "success": True,
                "status": "cached",
                "cached": True,
                "fingerprint": fingerprint,
                "summary": str(cached.get("summary") or ""),
                "response_ref": str(cached.get("response_ref") or ""),
                "response_excerpt": str(cached.get("response_excerpt") or ""),
                "expires_at": float(cached.get("expires_at") or 0.0),
                "message": message,
            }
        )

    queue_cap = _dashboard_queue_submission_cap()
    try:
        outstanding = int(active_outstanding_jobs().get("outstanding", 0))
    except Exception:
        outstanding = 0

    if outstanding >= queue_cap:
        message = (
            f"Queue submission cap reached ({queue_cap} outstanding jobs). "
            "Wait for running jobs to finish, then retry."
        )
        _append_result({"type": "job", "tool": tool_name, "target": target, "success": False, "message": message})
        return jsonify(
            {
                "success": False,
                "status": "throttled",
                "error": message,
                "queue_submission_cap": queue_cap,
                "outstanding_jobs": outstanding,
            }
        ), 429

    try:
        job = _create_job(
            tool=tool_name,
            target=target,
            timeout_seconds=safe_timeout,
            mode=mode,
            scope_tag=scope_tag,
        )
    except queue.Full:
        return jsonify({"success": False, "error": "job queue is full"}), 429

    queue_position = max(0, _JOBS_QUEUE.qsize() - 1)
    _emit("job_update", {"job_id": job["job_id"], "status": "queued", "tool": tool_name, "target": target})
    add_msg = f"Queued {tool_name} on {target} (job {job['job_id']})"
    _append_result({"type": "job", "tool": tool_name, "target": target, "success": True, "message": add_msg})

    return jsonify(
        {
            "success": True,
            "job_id": job["job_id"],
            "status": "queued",
            "queue_position": queue_position,
            "job": _job_snapshot(job, include_output=False),
        }
    )


@app.get("/api/jobs")
def api_jobs_list():
    try:
        limit = max(1, min(int(request.args.get("limit", 25)), 100))
    except (TypeError, ValueError):
        limit = 25
    status_filter = str(request.args.get("status", "")).strip().lower()
    target_filter = str(request.args.get("target", "")).strip().lower()

    with _JOBS_LOCK:
        memory_entries = list(_JOBS.values())

    if status_filter:
        memory_entries = [entry for entry in memory_entries if str(entry.get("status", "")).lower() == status_filter]
    if target_filter:
        memory_entries = [entry for entry in memory_entries if str(entry.get("target", "")).strip().lower() == target_filter]

    memory_jobs = [dict(entry, source="dashboard") for entry in memory_entries]
    db_jobs = _query_db_jobs(limit=max(limit * 4, 250), status_filter=status_filter, target_filter=target_filter)

    merged: Dict[str, Dict[str, Any]] = {}
    for job in db_jobs:
        key = str(job.get("job_id") or "").strip()
        if key:
            merged[key] = job
    for job in memory_jobs:
        key = str(job.get("job_id") or "").strip()
        if key:
            merged[key] = job

    entries = list(merged.values())
    entries.sort(key=lambda item: float(item.get("created_at", 0.0) or 0.0), reverse=True)
    return jsonify(
        {
            "success": True,
            "count": len(entries),
            "queue_depth": _JOBS_QUEUE.qsize(),
            "db_jobs_count": len(db_jobs),
            "memory_jobs_count": len(memory_jobs),
            "target_filter": target_filter,
            "jobs": [_job_snapshot(entry, include_output=False) for entry in entries[:limit]],
        }
    )


@app.get("/api/jobs/<job_id>")
def api_job_get(job_id: str):
    with _JOBS_LOCK:
        job = dict(_JOBS.get(job_id.strip()) or {})

    include_output = str(request.args.get("output", "0")).strip().lower() in {"1", "true", "yes", "on"}
    try:
        max_chars = int(request.args.get("max_chars", 12000))
    except (TypeError, ValueError):
        max_chars = 12000

    if job:
        job["source"] = "dashboard"
        return jsonify({"success": True, "job": _job_snapshot(job, include_output=include_output, max_chars=max_chars)})

    db_job = _query_db_job(job_id.strip())
    if db_job is None:
        return jsonify({"success": False, "error": f"job not found: {job_id}"}), 404

    if include_output:
        db_job["output"] = _db_job_output(job_id.strip(), max_chars=max_chars)
    return jsonify({"success": True, "job": _job_snapshot(db_job, include_output=include_output, max_chars=max_chars)})


@app.post("/api/jobs/<job_id>/retry")
def api_job_retry(job_id: str):
    with _JOBS_LOCK:
        original = dict(_JOBS.get(job_id.strip()) or {})
    if not original:
        return jsonify({"success": False, "error": f"job not found: {job_id}"}), 404

    status = str(original.get("status") or "").lower()
    if status in {"queued", "running"}:
        return jsonify({"success": False, "error": "cannot retry active job"}), 409

    try:
        new_job = _create_job(
            tool=str(original.get("tool") or ""),
            target=str(original.get("target") or ""),
            timeout_seconds=int(original.get("timeout_seconds") or 45),
            retry_of=str(original.get("job_id") or ""),
        )
    except queue.Full:
        return jsonify({"success": False, "error": "job queue is full"}), 429

    _emit("job_update", {"job_id": new_job["job_id"], "status": "queued", "tool": new_job["tool"], "target": new_job["target"]})
    return jsonify({"success": True, "job": _job_snapshot(new_job, include_output=False)})


@app.post("/api/jobs/<job_id>/cancel")
def api_job_cancel(job_id: str):
    normalized = job_id.strip()
    with _JOBS_LOCK:
        job = _JOBS.get(normalized)
        if not job:
            return jsonify({"success": False, "error": f"job not found: {job_id}"}), 404

        status = str(job.get("status") or "").lower()
        if status in {"success", "failed", "cancelled", "canceled"}:
            return jsonify({"success": False, "error": "job already finished"}), 409

        if status == "queued":
            job["status"] = "cancelled"
            job["progress"] = "cancelled before execution"
            job["cancel_requested"] = True
            job["finished_at"] = time.time()
            job["updated_at"] = time.time()
            _emit("job_update", {"job_id": normalized, "status": "cancelled", "tool": job.get("tool"), "target": job.get("target")})
            return jsonify({"success": True, "job": _job_snapshot(dict(job), include_output=False)})

        job["cancel_requested"] = True
        job["updated_at"] = time.time()

    _emit("job_update", {"job_id": normalized, "status": "cancel_requested"})
    return jsonify({"success": True, "message": "cancel requested", "job_id": normalized})


@app.get("/api/results")
def api_results():
    _sync_state_from_runtime()
    target_filter = str(request.args.get("target", "")).strip().lower()
    resolved_target = target_filter or str(state.get("current_target") or "").strip().lower()
    db_jobs: List[Dict[str, Any]] = []
    if resolved_target:
        db_jobs = _query_db_jobs(limit=80, target_filter=resolved_target)

    return jsonify(
        {
            "target": state["current_target"],
            "waf_status": state["waf_status"],
            "target_filter": resolved_target,
            "results": state["scan_results"],
            "runs": state["run_history"][-30:],
            "db_jobs": [_job_snapshot(entry, include_output=False) for entry in db_jobs[:80]],
        }
    )


@app.post("/api/install")
def api_install():
    payload = request.get_json(silent=True) or {}
    tool_name = str(payload.get("tool", "")).strip().lower()

    if not tool_name:
        return jsonify({"error": "tool is required"}), 400

    with _INSTALL_LOCK:
        if tool_name in _ACTIVE_INSTALLS:
            return jsonify({"error": f"Install already running for {tool_name}"}), 429
        _ACTIVE_INSTALLS.add(tool_name)

    try:
        tools = load_tools_config()
        tool_def = next((tool for tool in tools if str(tool.get("name", "")).lower() == tool_name), None)

        if not tool_def:
            return jsonify({"error": f"Unknown tool: {tool_name}"}), 404

        install_command = str(tool_def.get("install_command", "")).strip()
        if not install_command:
            return jsonify({"error": f"No install command for {tool_name}"}), 400

        if install_command.startswith("sudo "):
            install_command = install_command.replace("sudo ", "sudo -n ", 1)

        update_runtime_state(current_task=f"installing {tool_name}")

        return_code = 0
        try:
            result = subprocess.run(
                install_command,
                shell=True,
                capture_output=True,
                text=True,
                cwd=str(BASE_DIR),
                timeout=INSTALL_TIMEOUT_SECONDS,
            )
            return_code = result.returncode
            output = ((result.stdout or "") + (result.stderr or "")).strip()
            status = "installed" if result.returncode == 0 else "failed"
        except subprocess.TimeoutExpired as exc:
            timeout_note = f"Install timed out after {INSTALL_TIMEOUT_SECONDS}s"
            partial = ((exc.stdout or "") + (exc.stderr or "")).strip()
            output = f"{timeout_note}\n{partial}".strip()
            status = "failed"
            return_code = -1

        _append_result(
            {
                "type": "install",
                "tool": tool_name,
                "status": status,
                "output": output,
            }
        )
        _emit("install_result", {"tool": tool_name, "status": status, "output": output})
        _invalidate_tool_status_snapshot()

        detected_status = "installed" if status == "installed" else "not_installed"
        save_install_state(
            tool_name=tool_name,
            detected_status=detected_status,
            user_state="user_managed",
            install_result=status,
            output_ref="",
            install_attempted=True,
        )

        return jsonify(
            {
                "tool": tool_name,
                "status": status,
                "return_code": return_code,
                "output": output,
            }
        )
    finally:
        with _INSTALL_LOCK:
            _ACTIVE_INSTALLS.discard(tool_name)
        update_runtime_state(current_task="idle")


if __name__ == "__main__":
    config = _load_config()

    env_port = str(os.environ.get("BEARSTRIKE_DASHBOARD_PORT", "")).strip()
    preferred_port = int(env_port or config.get("dashboard_port", 3000))
    host = str(config.get("dashboard_host", "0.0.0.0")).strip() or "0.0.0.0"

    selected_port = _choose_port(preferred_port)
    if selected_port != preferred_port:
        print(f"[dashboard] Port {preferred_port} busy, switched to {selected_port}")

    update_runtime_state(
        dashboard_port=selected_port,
        dashboard_url=f"http://127.0.0.1:{selected_port}",
        current_task="dashboard-ready",
    )

    if socketio:
        socketio.run(app, host=host, port=selected_port, debug=False)
    else:
        app.run(host=host, port=selected_port, debug=False)
