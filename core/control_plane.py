"""Persistent control-plane storage and scoring for BearStrike."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import shutil
import threading
import time
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "bearstrike.db"
REPORTS_OUTPUT_DIR = BASE_DIR / "reports" / "output"

HIGH_RISK_PATH_HINTS = {
    "/api/auth": 10,
    "/auth": 9,
    "/api/user": 9,
    "/internal": 9,
    "/admin": 8,
    "/graphql": 8,
    "/api/v1": 7,
}

METHOD_WEIGHT = {
    "GET": 1,
    "POST": 3,
    "PUT": 3,
    "PATCH": 3,
    "DELETE": 3,
    "OPTIONS": 1,
    "HEAD": 1,
}

OBJECT_ID_PATTERNS = [
    re.compile(r"(^|[?&_/.-])(id|user_id|account_id|org_id|tenant_id)=", re.IGNORECASE),
    re.compile(r"/[0-9]{2,}(/|$)"),
    re.compile(r"/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(/|$)", re.IGNORECASE),
]

AUTH_BOUNDARY_HINTS = [
    "token",
    "session",
    "jwt",
    "authorization",
    "auth",
    "apikey",
    "api_key",
    "bearer",
    "cookie",
]

CACHE_TTL_PROFILE_DEFAULT = {
    "low_noise": 7200,
    "balanced": 2400,
    "aggressive": 600,
}

DEFAULT_SCORE_THRESHOLDS = {
    "high": 8,
    "medium": 5,
}

ACTIVE_JOB_STALE_SECONDS = 900

SCHEMA_STATEMENTS: Tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS research_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT NOT NULL,
        source_url TEXT DEFAULT '',
        vulnerability_class TEXT NOT NULL,
        endpoint_pattern TEXT DEFAULT '',
        payload_snippet TEXT DEFAULT '',
        method TEXT DEFAULT '',
        exploitation_notes TEXT DEFAULT '',
        confidence REAL DEFAULT 0.0,
        discovered_at REAL DEFAULT 0,
        ingested_at REAL NOT NULL,
        meta_json TEXT DEFAULT ''
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS endpoint_intel (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        path_signature TEXT NOT NULL,
        endpoint_class TEXT DEFAULT 'general',
        method TEXT DEFAULT 'GET',
        context TEXT DEFAULT '',
        score INTEGER NOT NULL,
        priority_band TEXT NOT NULL,
        research_hits INTEGER DEFAULT 0,
        last_seen REAL NOT NULL,
        last_tested REAL DEFAULT 0,
        source TEXT DEFAULT 'runtime',
        UNIQUE(target, path_signature, method)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS request_fingerprint_cache (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fingerprint TEXT NOT NULL UNIQUE,
        tool TEXT NOT NULL,
        target TEXT NOT NULL,
        params_json TEXT DEFAULT '{}',
        mode TEXT DEFAULT 'low_noise',
        scope_tag TEXT DEFAULT '',
        status TEXT NOT NULL,
        summary TEXT DEFAULT '',
        response_ref TEXT DEFAULT '',
        response_excerpt TEXT DEFAULT '',
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        expires_at REAL NOT NULL,
        hit_count INTEGER DEFAULT 0
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS tool_install_state (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tool_name TEXT NOT NULL UNIQUE,
        detected_status TEXT DEFAULT 'unknown',
        user_state TEXT DEFAULT 'observed',
        last_install_attempt_at REAL DEFAULT 0,
        last_install_result TEXT DEFAULT '',
        output_ref TEXT DEFAULT '',
        updated_at REAL NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS run_jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id TEXT NOT NULL UNIQUE,
        source TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        target TEXT NOT NULL,
        params_json TEXT DEFAULT '{}',
        fingerprint TEXT DEFAULT '',
        status TEXT NOT NULL,
        retries INTEGER DEFAULT 0,
        duration_ms INTEGER DEFAULT 0,
        cache_hit INTEGER DEFAULT 0,
        deduped_to_job_id TEXT DEFAULT '',
        created_at REAL NOT NULL,
        started_at REAL DEFAULT 0,
        finished_at REAL DEFAULT 0,
        error TEXT DEFAULT '',
        response_ref TEXT DEFAULT ''
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS run_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        message TEXT DEFAULT '',
        payload_json TEXT DEFAULT '{}',
        created_at REAL NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS hunter_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        message TEXT NOT NULL,
        confidence REAL DEFAULT 0.0,
        created_at REAL NOT NULL
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_research_findings_discovered_at ON research_findings(discovered_at);",
    "CREATE INDEX IF NOT EXISTS idx_research_findings_endpoint ON research_findings(endpoint_pattern);",
    "CREATE INDEX IF NOT EXISTS idx_endpoint_intel_target_priority ON endpoint_intel(target, priority_band, score DESC);",
    "CREATE INDEX IF NOT EXISTS idx_request_cache_tool_target ON request_fingerprint_cache(tool, target);",
    "CREATE INDEX IF NOT EXISTS idx_request_cache_expires ON request_fingerprint_cache(expires_at);",
    "CREATE INDEX IF NOT EXISTS idx_run_jobs_status_created ON run_jobs(status, created_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_run_jobs_fingerprint ON run_jobs(fingerprint);",
    "CREATE INDEX IF NOT EXISTS idx_run_events_job_created ON run_events(job_id, created_at);",
    "CREATE INDEX IF NOT EXISTS idx_hunter_notes_target ON hunter_notes(target, created_at DESC);",
)

_INIT_LOCK = threading.Lock()
_INITIALIZED = False


class _ManagedConnection(sqlite3.Connection):
    """SQLite connection that auto-closes when used as a context manager."""

    def __exit__(self, exc_type, exc_value, traceback):  # type: ignore[override]
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            try:
                self.close()
            except sqlite3.Error:
                pass


def now_ts() -> float:
    return time.time()


def normalize_target(target: str) -> str:
    value = str(target or "").strip().lower()
    value = re.sub(r"^https?://", "", value, flags=re.IGNORECASE)
    value = value.rstrip("/")
    return value


def target_slug(target: str) -> str:
    value = normalize_target(target)
    value = value.replace("https://", "").replace("http://", "")
    value = "".join(ch if ch.isalnum() else "_" for ch in value).strip("_")
    return value or "target"


def normalize_endpoint(endpoint: str) -> str:
    value = str(endpoint or "").strip()
    if not value:
        return "/"
    value = re.sub(r"^https?://[^/]+", "", value, flags=re.IGNORECASE)
    if not value.startswith("/"):
        value = f"/{value}"
    value = re.sub(r"/{2,}", "/", value)
    return value


def _json_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def ensure_db() -> None:
    global _INITIALIZED
    if _INITIALIZED:
        return

    with _INIT_LOCK:
        if _INITIALIZED:
            return

        DATA_DIR.mkdir(parents=True, exist_ok=True)
        REPORTS_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        connection = sqlite3.connect(str(DB_PATH))
        try:
            connection.execute("PRAGMA journal_mode=WAL;")
            connection.execute("PRAGMA synchronous=NORMAL;")
            connection.execute("PRAGMA temp_store=MEMORY;")
            for statement in SCHEMA_STATEMENTS:
                connection.execute(statement)
            connection.commit()
        finally:
            connection.close()

        # Keep control-plane writable even when components are started with mixed users (sudo/non-sudo).
        for writable_path in (DATA_DIR, DB_PATH, DB_PATH.with_suffix(".db-shm"), DB_PATH.with_suffix(".db-wal")):
            try:
                if writable_path.exists():
                    os.chmod(writable_path, 0o777 if writable_path.is_dir() else 0o666)
            except OSError:
                pass

        _INITIALIZED = True


def _connect() -> sqlite3.Connection:
    ensure_db()
    connection = sqlite3.connect(str(DB_PATH), timeout=15, factory=_ManagedConnection)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL;")
    connection.execute("PRAGMA synchronous=NORMAL;")
    return connection


def request_fingerprint(
    *,
    tool_name: str,
    target: str,
    params: Optional[Dict[str, Any]] = None,
    mode: str = "low_noise",
    scope_tag: str = "",
) -> str:
    normalized_tool = str(tool_name or "").strip().lower()
    normalized_target = normalize_target(target)
    normalized_mode = str(mode or "low_noise").strip().lower()
    normalized_scope = str(scope_tag or "").strip().lower()
    params_blob = _json_dumps(params or {})

    base = "|".join([normalized_tool, normalized_target, params_blob, normalized_mode, normalized_scope])
    return sha256(base.encode("utf-8")).hexdigest()


def _ttl_seconds_for_mode(mode: str, profile: Optional[Dict[str, int]] = None) -> int:
    merged = dict(CACHE_TTL_PROFILE_DEFAULT)
    if isinstance(profile, dict):
        for key, value in profile.items():
            try:
                merged[str(key)] = max(30, int(value))
            except (TypeError, ValueError):
                continue

    key = str(mode or "low_noise").strip().lower()
    return int(merged.get(key, merged["low_noise"]))


def find_active_job_by_fingerprint(
    fingerprint: str,
    statuses: Optional[Iterable[str]] = None,
    stale_seconds: int = ACTIVE_JOB_STALE_SECONDS,
) -> Optional[Dict[str, Any]]:
    normalized_statuses = [str(item).lower() for item in (statuses or ("queued", "running"))]
    placeholders = ",".join("?" for _ in normalized_statuses)
    query = f"""
        SELECT job_id, tool_name, target, status, created_at, started_at, finished_at, deduped_to_job_id
        FROM run_jobs
        WHERE fingerprint = ? AND LOWER(status) IN ({placeholders})
        ORDER BY created_at DESC
        LIMIT 1
    """

    with _connect() as connection:
        row = connection.execute(query, [fingerprint, *normalized_statuses]).fetchone()
        if row is None:
            return None

        payload = dict(row)
        created_at = float(payload.get("created_at") or 0.0)
        current = now_ts()
        if created_at > 0 and (current - created_at) > max(30, int(stale_seconds)):
            # Auto-close stale active jobs left behind by crashed/restarted sessions.
            connection.execute(
                """
                UPDATE run_jobs
                SET status = 'failed', finished_at = ?, error = ?
                WHERE job_id = ? AND LOWER(status) IN ({placeholders})
                """.replace("{placeholders}", placeholders),
                [
                    current,
                    f"stale active job auto-closed after {int(current - created_at)}s",
                    str(payload.get("job_id") or ""),
                    *normalized_statuses,
                ],
            )
            connection.commit()
            return None

    return payload


def _close_stale_active_jobs(connection: sqlite3.Connection, stale_seconds: int = ACTIVE_JOB_STALE_SECONDS) -> int:
    """Mark orphan queued/running jobs as failed so queue health stays truthful."""
    current = now_ts()
    safe_stale = max(30, int(stale_seconds))
    cutoff = current - safe_stale

    stale_rows = connection.execute(
        """
        SELECT job_id
        FROM run_jobs
        WHERE LOWER(status) IN ('queued', 'running')
          AND created_at > 0
          AND created_at < ?
        """,
        [cutoff],
    ).fetchall()

    if not stale_rows:
        return 0

    stale_ids = [str(row["job_id"] or "").strip() for row in stale_rows if str(row["job_id"] or "").strip()]
    if not stale_ids:
        return 0

    placeholders = ",".join("?" for _ in stale_ids)
    connection.execute(
        f"""
        UPDATE run_jobs
        SET status = 'failed',
            finished_at = ?,
            error = CASE
                WHEN error IS NULL OR TRIM(error) = '' THEN ?
                ELSE error
            END
        WHERE job_id IN ({placeholders})
        """,
        [current, f"stale active job auto-closed after {safe_stale}s", *stale_ids],
    )
    connection.commit()
    return len(stale_ids)


def active_outstanding_jobs(stale_seconds: int = ACTIVE_JOB_STALE_SECONDS) -> Dict[str, int]:
    """Return live queued/running counters after stale cleanup."""
    with _connect() as connection:
        _close_stale_active_jobs(connection, stale_seconds=stale_seconds)
        row = connection.execute(
            """
            SELECT
                SUM(CASE WHEN LOWER(status) = 'queued' THEN 1 ELSE 0 END) AS queued,
                SUM(CASE WHEN LOWER(status) = 'running' THEN 1 ELSE 0 END) AS running
            FROM run_jobs
            """
        ).fetchone()

    queued = int((row["queued"] if row and row["queued"] is not None else 0) or 0)
    running = int((row["running"] if row and row["running"] is not None else 0) or 0)
    return {"queued": queued, "running": running, "outstanding": queued + running}


def get_cached_response(fingerprint: str) -> Optional[Dict[str, Any]]:
    current = now_ts()
    with _connect() as connection:
        row = connection.execute(
            """
            SELECT fingerprint, tool, target, params_json, mode, scope_tag, status,
                   summary, response_ref, response_excerpt, expires_at, hit_count
            FROM request_fingerprint_cache
            WHERE fingerprint = ? AND status = 'success' AND expires_at > ?
            LIMIT 1
            """,
            [fingerprint, current],
        ).fetchone()
        if row is None:
            return None

        connection.execute(
            "UPDATE request_fingerprint_cache SET hit_count = hit_count + 1, updated_at = ? WHERE fingerprint = ?",
            [current, fingerprint],
        )
        connection.commit()

    return dict(row)


def upsert_request_cache(
    *,
    fingerprint: str,
    tool: str,
    target: str,
    params: Optional[Dict[str, Any]],
    mode: str,
    scope_tag: str,
    status: str,
    summary: str,
    response_ref: str,
    response_excerpt: str,
    ttl_profile: Optional[Dict[str, int]] = None,
) -> None:
    created = now_ts()
    ttl_seconds = _ttl_seconds_for_mode(mode, ttl_profile)
    expires_at = created + ttl_seconds
    params_blob = _json_dumps(params or {})

    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO request_fingerprint_cache(
                fingerprint, tool, target, params_json, mode, scope_tag, status,
                summary, response_ref, response_excerpt, created_at, updated_at, expires_at, hit_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            ON CONFLICT(fingerprint) DO UPDATE SET
                tool = excluded.tool,
                target = excluded.target,
                params_json = excluded.params_json,
                mode = excluded.mode,
                scope_tag = excluded.scope_tag,
                status = excluded.status,
                summary = excluded.summary,
                response_ref = excluded.response_ref,
                response_excerpt = excluded.response_excerpt,
                updated_at = excluded.updated_at,
                expires_at = excluded.expires_at
            """,
            [
                fingerprint,
                tool,
                normalize_target(target),
                params_blob,
                mode,
                scope_tag,
                status,
                summary,
                response_ref,
                response_excerpt,
                created,
                created,
                expires_at,
            ],
        )
        connection.commit()


def record_run_job(
    *,
    job_id: str,
    source: str,
    tool_name: str,
    target: str,
    params: Optional[Dict[str, Any]],
    fingerprint: str,
    status: str,
    retries: int = 0,
    cache_hit: bool = False,
    deduped_to_job_id: str = "",
    error: str = "",
    response_ref: str = "",
) -> None:
    created = now_ts()
    params_blob = _json_dumps(params or {})

    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO run_jobs(
                job_id, source, tool_name, target, params_json, fingerprint, status,
                retries, duration_ms, cache_hit, deduped_to_job_id, created_at,
                started_at, finished_at, error, response_ref
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, 0, 0, ?, ?)
            ON CONFLICT(job_id) DO UPDATE SET
                source = excluded.source,
                tool_name = excluded.tool_name,
                target = excluded.target,
                params_json = excluded.params_json,
                fingerprint = excluded.fingerprint,
                status = excluded.status,
                retries = excluded.retries,
                cache_hit = excluded.cache_hit,
                deduped_to_job_id = excluded.deduped_to_job_id,
                error = excluded.error,
                response_ref = excluded.response_ref
            """,
            [
                job_id,
                source,
                str(tool_name or "").strip().lower(),
                normalize_target(target),
                params_blob,
                fingerprint,
                str(status or "queued").strip().lower(),
                max(0, int(retries)),
                1 if cache_hit else 0,
                str(deduped_to_job_id or ""),
                created,
                str(error or ""),
                str(response_ref or ""),
            ],
        )
        connection.commit()


def update_run_job(job_id: str, **changes: Any) -> None:
    if not changes:
        return

    valid_fields = {
        "status",
        "retries",
        "duration_ms",
        "cache_hit",
        "deduped_to_job_id",
        "started_at",
        "finished_at",
        "error",
        "response_ref",
    }

    assignments: List[str] = []
    values: List[Any] = []
    for key, value in changes.items():
        if key not in valid_fields:
            continue
        assignments.append(f"{key} = ?")
        if key == "cache_hit":
            values.append(1 if bool(value) else 0)
        elif key in {"retries", "duration_ms"}:
            values.append(max(0, int(value)))
        elif key in {"started_at", "finished_at"}:
            values.append(float(value))
        else:
            values.append(value)

    if not assignments:
        return

    with _connect() as connection:
        connection.execute(
            f"UPDATE run_jobs SET {', '.join(assignments)} WHERE job_id = ?",
            [*values, job_id],
        )
        connection.commit()


def append_run_event(job_id: str, event_type: str, message: str, payload: Optional[Dict[str, Any]] = None) -> None:
    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO run_events(job_id, event_type, message, payload_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                str(job_id or ""),
                str(event_type or "info"),
                str(message or ""),
                _json_dumps(payload or {}),
                now_ts(),
            ],
        )
        connection.commit()


def list_recent_run_events(limit: int = 100) -> List[Dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 2000))
    with _connect() as connection:
        rows = connection.execute(
            """
            SELECT id, job_id, event_type, message, payload_json, created_at
            FROM run_events
            ORDER BY id DESC
            LIMIT ?
            """,
            [safe_limit],
        ).fetchall()

    items: List[Dict[str, Any]] = []
    for row in rows:
        payload = dict(row)
        raw = str(payload.get("payload_json") or "{}")
        try:
            payload["payload"] = json.loads(raw)
        except json.JSONDecodeError:
            payload["payload"] = {}
        payload.pop("payload_json", None)
        items.append(payload)
    return items


def cache_stats() -> Dict[str, Any]:
    current = now_ts()
    with _connect() as connection:
        total = int(connection.execute("SELECT COUNT(*) FROM request_fingerprint_cache").fetchone()[0])
        active = int(
            connection.execute(
                "SELECT COUNT(*) FROM request_fingerprint_cache WHERE expires_at > ?",
                [current],
            ).fetchone()[0]
        )
        expired = total - active
        hits = int(connection.execute("SELECT COALESCE(SUM(hit_count), 0) FROM request_fingerprint_cache").fetchone()[0])

    return {
        "total_entries": total,
        "active_entries": active,
        "expired_entries": max(0, expired),
        "cache_hits": hits,
    }


def dedupe_stats() -> Dict[str, Any]:
    with _connect() as connection:
        total_jobs = int(connection.execute("SELECT COUNT(*) FROM run_jobs").fetchone()[0])
        deduped = int(
            connection.execute(
                "SELECT COUNT(*) FROM run_jobs WHERE deduped_to_job_id IS NOT NULL AND deduped_to_job_id != ''"
            ).fetchone()[0]
        )
        cache_hits = int(connection.execute("SELECT COUNT(*) FROM run_jobs WHERE cache_hit = 1").fetchone()[0])

    ratio = (deduped / total_jobs) if total_jobs else 0.0
    return {
        "total_jobs": total_jobs,
        "deduped_jobs": deduped,
        "cache_hit_jobs": cache_hits,
        "dedupe_ratio": round(ratio, 4),
    }


def queue_stats() -> Dict[str, Any]:
    with _connect() as connection:
        _close_stale_active_jobs(connection, stale_seconds=ACTIVE_JOB_STALE_SECONDS)
        rows = connection.execute(
            "SELECT LOWER(status) AS status, COUNT(*) AS count FROM run_jobs GROUP BY LOWER(status)"
        ).fetchall()

    counters = {"queued": 0, "running": 0, "success": 0, "failed": 0, "cancelled": 0}
    for row in rows:
        key = str(row["status"] or "")
        if key in counters:
            counters[key] = int(row["count"])

    counters["total"] = sum(counters.values())
    return counters


def _matches_any_pattern(value: str, patterns: Iterable[re.Pattern[str]]) -> bool:
    return any(pattern.search(value) for pattern in patterns)


def infer_program_context(target: str, context: str = "") -> Dict[str, Any]:
    combined = f"{target} {context}".lower()
    platform = "generic"
    if "hackerone" in combined or "h1" in combined:
        platform = "hackerone"
    elif "bugcrowd" in combined:
        platform = "bugcrowd"
    elif "tryhackme" in combined or "thm" in combined:
        platform = "tryhackme"

    return {
        "platform": platform,
        "is_bug_bounty": platform in {"hackerone", "bugcrowd"},
        "is_training": platform == "tryhackme",
    }


def score_endpoint(
    *,
    target: str,
    endpoint: str,
    method: str = "GET",
    context: str = "",
    score_thresholds: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    normalized_target = normalize_target(target)
    normalized_endpoint = normalize_endpoint(endpoint)
    normalized_method = str(method or "GET").strip().upper() or "GET"
    context_text = str(context or "").strip()

    score = 1
    reasons: List[str] = []

    endpoint_lower = normalized_endpoint.lower()
    for path_hint, path_score in HIGH_RISK_PATH_HINTS.items():
        if path_hint in endpoint_lower:
            score = max(score, path_score)
            reasons.append(f"path-risk:{path_hint}")

    score += METHOD_WEIGHT.get(normalized_method, 1)
    reasons.append(f"method-weight:{normalized_method}")

    if _matches_any_pattern(normalized_endpoint, OBJECT_ID_PATTERNS):
        score += 2
        reasons.append("object-identifier-pattern")

    auth_blob = f"{normalized_endpoint} {context_text}".lower()
    if any(hint in auth_blob for hint in AUTH_BOUNDARY_HINTS):
        score += 2
        reasons.append("auth-boundary-hints")

    research_hits = count_research_hits_for_endpoint(normalized_endpoint, normalized_method)
    if research_hits > 0:
        boost = min(3, research_hits)
        score += boost
        reasons.append(f"research-hit-boost:{boost}")

    program_context = infer_program_context(normalized_target, context_text)
    if program_context["is_training"]:
        score = min(10, score + 1)
        reasons.append("training-target-bonus")

    score = max(1, min(10, score))

    thresholds = dict(DEFAULT_SCORE_THRESHOLDS)
    if isinstance(score_thresholds, dict):
        for key, value in score_thresholds.items():
            try:
                thresholds[str(key)] = int(value)
            except (TypeError, ValueError):
                continue

    if score >= int(thresholds.get("high", 8)):
        priority_band = "high"
    elif score >= int(thresholds.get("medium", 5)):
        priority_band = "medium"
    else:
        priority_band = "low"

    endpoint_class = "general"
    if "/auth" in endpoint_lower or "login" in endpoint_lower:
        endpoint_class = "auth"
    elif "graphql" in endpoint_lower:
        endpoint_class = "graphql"
    elif "/admin" in endpoint_lower or "/internal" in endpoint_lower:
        endpoint_class = "privileged"
    elif "upload" in endpoint_lower:
        endpoint_class = "file-upload"

    upsert_endpoint_intel(
        target=normalized_target,
        path_signature=normalized_endpoint,
        endpoint_class=endpoint_class,
        method=normalized_method,
        context=context_text,
        score=score,
        priority_band=priority_band,
        research_hits=research_hits,
        source="score_endpoint",
    )

    return {
        "target": normalized_target,
        "endpoint": normalized_endpoint,
        "method": normalized_method,
        "score": score,
        "priority_band": priority_band,
        "endpoint_class": endpoint_class,
        "research_hits": research_hits,
        "reasons": reasons,
        "program_context": program_context,
    }


def upsert_endpoint_intel(
    *,
    target: str,
    path_signature: str,
    endpoint_class: str,
    method: str,
    context: str,
    score: int,
    priority_band: str,
    research_hits: int,
    source: str,
) -> None:
    current = now_ts()
    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO endpoint_intel(
                target, path_signature, endpoint_class, method, context, score,
                priority_band, research_hits, last_seen, last_tested, source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
            ON CONFLICT(target, path_signature, method) DO UPDATE SET
                endpoint_class = excluded.endpoint_class,
                context = excluded.context,
                score = excluded.score,
                priority_band = excluded.priority_band,
                research_hits = excluded.research_hits,
                last_seen = excluded.last_seen,
                source = excluded.source
            """,
            [
                normalize_target(target),
                normalize_endpoint(path_signature),
                str(endpoint_class or "general"),
                str(method or "GET").upper(),
                str(context or ""),
                max(1, min(10, int(score))),
                str(priority_band or "low"),
                max(0, int(research_hits)),
                current,
                str(source or "runtime"),
            ],
        )
        connection.commit()


def list_prioritized_endpoints(target: str, limit: int = 100) -> Dict[str, List[Dict[str, Any]]]:
    safe_limit = max(1, min(int(limit), 1000))
    normalized_target = normalize_target(target)

    with _connect() as connection:
        rows = connection.execute(
            """
            SELECT target, path_signature, endpoint_class, method, context, score,
                   priority_band, research_hits, last_seen, last_tested
            FROM endpoint_intel
            WHERE target = ?
            ORDER BY score DESC, last_seen DESC
            LIMIT ?
            """,
            [normalized_target, safe_limit],
        ).fetchall()

    grouped: Dict[str, List[Dict[str, Any]]] = {"high": [], "medium": [], "low": []}
    for row in rows:
        item = dict(row)
        band = str(item.get("priority_band") or "low")
        grouped.setdefault(band, []).append(item)

    return grouped


def save_install_state(
    *,
    tool_name: str,
    detected_status: str,
    user_state: str,
    install_result: str = "",
    output_ref: str = "",
    install_attempted: bool = False,
) -> None:
    current = now_ts()
    attempt_at = current if install_attempted else 0

    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO tool_install_state(
                tool_name, detected_status, user_state,
                last_install_attempt_at, last_install_result, output_ref, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tool_name) DO UPDATE SET
                detected_status = excluded.detected_status,
                user_state = excluded.user_state,
                last_install_attempt_at = CASE
                    WHEN excluded.last_install_attempt_at > 0 THEN excluded.last_install_attempt_at
                    ELSE tool_install_state.last_install_attempt_at
                END,
                last_install_result = CASE
                    WHEN excluded.last_install_result != '' THEN excluded.last_install_result
                    ELSE tool_install_state.last_install_result
                END,
                output_ref = CASE
                    WHEN excluded.output_ref != '' THEN excluded.output_ref
                    ELSE tool_install_state.output_ref
                END,
                updated_at = excluded.updated_at
            """,
            [
                str(tool_name or "").strip().lower(),
                str(detected_status or "unknown"),
                str(user_state or "observed"),
                attempt_at,
                str(install_result or ""),
                str(output_ref or ""),
                current,
            ],
        )
        connection.commit()


def load_install_state(limit: int = 1000) -> List[Dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 5000))
    with _connect() as connection:
        rows = connection.execute(
            """
            SELECT tool_name, detected_status, user_state,
                   last_install_attempt_at, last_install_result, output_ref, updated_at
            FROM tool_install_state
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            [safe_limit],
        ).fetchall()
    return [dict(row) for row in rows]


def count_research_hits_for_endpoint(endpoint: str, method: str = "") -> int:
    pattern = normalize_endpoint(endpoint)
    method_value = str(method or "").strip().upper()

    with _connect() as connection:
        if method_value:
            row = connection.execute(
                """
                SELECT COUNT(*)
                FROM research_findings
                WHERE endpoint_pattern != ''
                  AND (? LIKE '%' || LOWER(endpoint_pattern) || '%')
                  AND (method = '' OR UPPER(method) = ?)
                """,
                [pattern.lower(), method_value],
            ).fetchone()
        else:
            row = connection.execute(
                """
                SELECT COUNT(*)
                FROM research_findings
                WHERE endpoint_pattern != ''
                  AND (? LIKE '%' || LOWER(endpoint_pattern) || '%')
                """,
                [pattern.lower()],
            ).fetchone()
    return int(row[0] if row else 0)


def store_research_findings(findings: Iterable[Dict[str, Any]], replace_window_days: int = 30) -> Dict[str, Any]:
    ingested_at = now_ts()
    min_discovered_at = ingested_at - (max(1, int(replace_window_days)) * 86400)

    inserted = 0
    with _connect() as connection:
        connection.execute(
            "DELETE FROM research_findings WHERE discovered_at >= ?",
            [min_discovered_at],
        )
        for item in findings:
            discovered_at = float(item.get("discovered_at") or ingested_at)
            connection.execute(
                """
                INSERT INTO research_findings(
                    source, source_url, vulnerability_class, endpoint_pattern,
                    payload_snippet, method, exploitation_notes, confidence,
                    discovered_at, ingested_at, meta_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    str(item.get("source") or "curated"),
                    str(item.get("source_url") or ""),
                    str(item.get("vulnerability_class") or "general"),
                    str(item.get("endpoint_pattern") or "").lower(),
                    str(item.get("payload_snippet") or ""),
                    str(item.get("method") or "").upper(),
                    str(item.get("exploitation_notes") or ""),
                    float(item.get("confidence") or 0.0),
                    discovered_at,
                    ingested_at,
                    _json_dumps(item.get("meta") or {}),
                ],
            )
            inserted += 1
        connection.commit()

    return {
        "inserted": inserted,
        "window_days": int(replace_window_days),
        "ingested_at": ingested_at,
    }


def research_summary(days: int = 30) -> Dict[str, Any]:
    safe_days = max(1, min(int(days), 180))
    since = now_ts() - (safe_days * 86400)

    with _connect() as connection:
        total = int(connection.execute("SELECT COUNT(*) FROM research_findings WHERE discovered_at >= ?", [since]).fetchone()[0])
        classes_rows = connection.execute(
            """
            SELECT vulnerability_class, COUNT(*) AS count
            FROM research_findings
            WHERE discovered_at >= ?
            GROUP BY vulnerability_class
            ORDER BY count DESC
            LIMIT 12
            """,
            [since],
        ).fetchall()
        endpoint_rows = connection.execute(
            """
            SELECT endpoint_pattern, COUNT(*) AS count
            FROM research_findings
            WHERE discovered_at >= ? AND endpoint_pattern != ''
            GROUP BY endpoint_pattern
            ORDER BY count DESC
            LIMIT 12
            """,
            [since],
        ).fetchall()

    return {
        "window_days": safe_days,
        "total_findings": total,
        "top_vulnerability_classes": [dict(row) for row in classes_rows],
        "top_endpoint_patterns": [dict(row) for row in endpoint_rows],
    }


def research_query(
    *,
    q: str = "",
    vulnerability_class: str = "",
    endpoint_pattern: str = "",
    limit: int = 50,
) -> Dict[str, Any]:
    safe_limit = max(1, min(int(limit), 500))
    clauses = []
    values: List[Any] = []

    if q.strip():
        clauses.append("(LOWER(vulnerability_class) LIKE ? OR LOWER(endpoint_pattern) LIKE ? OR LOWER(exploitation_notes) LIKE ?)")
        needle = f"%{q.strip().lower()}%"
        values.extend([needle, needle, needle])

    if vulnerability_class.strip():
        clauses.append("LOWER(vulnerability_class) = ?")
        values.append(vulnerability_class.strip().lower())

    if endpoint_pattern.strip():
        clauses.append("LOWER(endpoint_pattern) LIKE ?")
        values.append(f"%{endpoint_pattern.strip().lower()}%")

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    with _connect() as connection:
        rows = connection.execute(
            f"""
            SELECT source, source_url, vulnerability_class, endpoint_pattern,
                   payload_snippet, method, exploitation_notes, confidence,
                   discovered_at, ingested_at
            FROM research_findings
            {where_sql}
            ORDER BY discovered_at DESC
            LIMIT ?
            """,
            [*values, safe_limit],
        ).fetchall()

    return {
        "count": len(rows),
        "items": [dict(row) for row in rows],
    }

def storage_stats() -> Dict[str, Any]:
    ensure_db()
    size_bytes = 0
    try:
        size_bytes = int(DB_PATH.stat().st_size)
    except OSError:
        size_bytes = 0

    counts: Dict[str, int] = {}
    with _connect() as connection:
        for table in (
            "run_jobs",
            "run_events",
            "request_fingerprint_cache",
            "endpoint_intel",
            "research_findings",
            "tool_install_state",
        ):
            row = connection.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()
            counts[table] = int(row[0] if row else 0)

    return {
        "db_path": str(DB_PATH),
        "db_size_bytes": size_bytes,
        "db_size_mb": round(size_bytes / (1024 * 1024), 3),
        "rows": counts,
    }


def enforce_target_rotation(
    *,
    window_hours: int = 24,
    threshold_targets: int = 5,
    keep_recent_targets: int = 1,
    delete_reports: bool = True,
    vacuum: bool = False,
) -> Dict[str, Any]:
    """
    Auto-prune older targets when many different targets are scanned in a short window.

    Default policy:
    - If >=5 distinct targets seen in last 24h, keep only newest target data.
    - Remove DB/runtime rows for the older targets and optionally delete report folders.
    """
    ensure_db()

    safe_window_hours = max(1, min(int(window_hours), 168))
    safe_threshold = max(2, min(int(threshold_targets), 100))
    safe_keep = max(1, min(int(keep_recent_targets), 20))
    cutoff = now_ts() - (safe_window_hours * 3600)

    with _connect() as connection:
        rows = connection.execute(
            """
            SELECT target, MAX(created_at) AS last_seen, COUNT(*) AS runs
            FROM run_jobs
            WHERE created_at >= ?
            GROUP BY target
            ORDER BY last_seen DESC
            """,
            [cutoff],
        ).fetchall()

        recent_targets = [dict(row) for row in rows]
        distinct_count = len(recent_targets)
        if distinct_count < safe_threshold:
            return {
                "success": True,
                "triggered": False,
                "distinct_targets_in_window": distinct_count,
                "threshold_targets": safe_threshold,
                "window_hours": safe_window_hours,
                "kept_targets": [str(item.get("target") or "") for item in recent_targets[:safe_keep]],
                "pruned_targets": [],
                "deleted": {},
            }

        kept_targets = [str(item.get("target") or "") for item in recent_targets[:safe_keep]]
        pruned_targets = [str(item.get("target") or "") for item in recent_targets[safe_keep:]]
        if not pruned_targets:
            return {
                "success": True,
                "triggered": False,
                "distinct_targets_in_window": distinct_count,
                "threshold_targets": safe_threshold,
                "window_hours": safe_window_hours,
                "kept_targets": kept_targets,
                "pruned_targets": [],
                "deleted": {},
            }

        placeholders = ",".join("?" for _ in pruned_targets)
        params = list(pruned_targets)

        deleted: Dict[str, int] = {
            "run_events": 0,
            "run_jobs": 0,
            "request_fingerprint_cache": 0,
            "endpoint_intel": 0,
            "hunter_notes": 0,
        }

        cursor = connection.execute(
            f"""
            DELETE FROM run_events
            WHERE job_id IN (
                SELECT job_id FROM run_jobs WHERE target IN ({placeholders})
            )
            """,
            params,
        )
        deleted["run_events"] = int(cursor.rowcount or 0)

        cursor = connection.execute(
            f"DELETE FROM run_jobs WHERE target IN ({placeholders})",
            params,
        )
        deleted["run_jobs"] = int(cursor.rowcount or 0)

        cursor = connection.execute(
            f"DELETE FROM request_fingerprint_cache WHERE target IN ({placeholders})",
            params,
        )
        deleted["request_fingerprint_cache"] = int(cursor.rowcount or 0)

        cursor = connection.execute(
            f"DELETE FROM endpoint_intel WHERE target IN ({placeholders})",
            params,
        )
        deleted["endpoint_intel"] = int(cursor.rowcount or 0)

        cursor = connection.execute(
            f"DELETE FROM hunter_notes WHERE target IN ({placeholders})",
            params,
        )
        deleted["hunter_notes"] = int(cursor.rowcount or 0)
        connection.commit()

    removed_report_folders: List[str] = []
    if delete_reports:
        for target in pruned_targets:
            slug = target_slug(target)
            if not slug:
                continue
            folder = REPORTS_OUTPUT_DIR / slug
            try:
                resolved = folder.resolve()
                if folder.exists() and REPORTS_OUTPUT_DIR.resolve() in resolved.parents:
                    shutil.rmtree(resolved, ignore_errors=True)
                    removed_report_folders.append(str(resolved))
            except OSError:
                continue

    vacuumed = False
    vacuum_error = ""
    if vacuum:
        try:
            with sqlite3.connect(str(DB_PATH), timeout=30) as vacuum_conn:
                vacuum_conn.execute("VACUUM")
            vacuumed = True
        except sqlite3.Error as exc:
            vacuum_error = str(exc)

    return {
        "success": True,
        "triggered": True,
        "distinct_targets_in_window": distinct_count,
        "threshold_targets": safe_threshold,
        "window_hours": safe_window_hours,
        "kept_targets": kept_targets,
        "pruned_targets": pruned_targets,
        "removed_report_folders": removed_report_folders,
        "deleted": deleted,
        "vacuumed": vacuumed,
        "vacuum_error": vacuum_error,
    }


def purge_old_scan_data(
    *,
    older_than_days: int = 7,
    include_research: bool = False,
    vacuum: bool = True,
    clear_all: bool = False,
) -> Dict[str, Any]:
    ensure_db()

    safe_days = max(1, min(int(older_than_days), 3650))
    now = now_ts()
    cutoff = now - (safe_days * 86400)

    before = storage_stats()
    deleted: Dict[str, int] = {
        "run_events": 0,
        "run_jobs": 0,
        "request_fingerprint_cache": 0,
        "endpoint_intel": 0,
        "research_findings": 0,
        "tool_install_state": 0,
    }

    with _connect() as connection:
        if clear_all:
            cursor = connection.execute("DELETE FROM run_events")
            deleted["run_events"] = int(cursor.rowcount or 0)

            cursor = connection.execute("DELETE FROM run_jobs")
            deleted["run_jobs"] = int(cursor.rowcount or 0)

            cursor = connection.execute("DELETE FROM request_fingerprint_cache")
            deleted["request_fingerprint_cache"] = int(cursor.rowcount or 0)

            cursor = connection.execute("DELETE FROM endpoint_intel")
            deleted["endpoint_intel"] = int(cursor.rowcount or 0)

            cursor = connection.execute("DELETE FROM research_findings")
            deleted["research_findings"] = int(cursor.rowcount or 0)

            cursor = connection.execute("DELETE FROM tool_install_state")
            deleted["tool_install_state"] = int(cursor.rowcount or 0)
        else:
            cursor = connection.execute(
                "DELETE FROM run_events WHERE created_at < ?",
                [cutoff],
            )
            deleted["run_events"] = int(cursor.rowcount or 0)

            cursor = connection.execute(
                "DELETE FROM run_jobs WHERE created_at < ?",
                [cutoff],
            )
            deleted["run_jobs"] = int(cursor.rowcount or 0)

            cursor = connection.execute(
                "DELETE FROM request_fingerprint_cache WHERE expires_at < ? OR created_at < ?",
                [now, cutoff],
            )
            deleted["request_fingerprint_cache"] = int(cursor.rowcount or 0)

            cursor = connection.execute(
                "DELETE FROM endpoint_intel WHERE last_seen < ?",
                [cutoff],
            )
            deleted["endpoint_intel"] = int(cursor.rowcount or 0)

            if include_research:
                cursor = connection.execute(
                    "DELETE FROM research_findings WHERE discovered_at < ?",
                    [cutoff],
                )
                deleted["research_findings"] = int(cursor.rowcount or 0)

        connection.commit()
        try:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        except sqlite3.Error:
            pass

    vacuumed = False
    vacuum_error = ""
    if vacuum:
        try:
            with sqlite3.connect(str(DB_PATH), timeout=30) as vacuum_conn:
                vacuum_conn.execute("VACUUM")
            vacuumed = True
        except sqlite3.Error as exc:
            vacuum_error = str(exc)

    after = storage_stats()
    reclaimed_bytes = max(0, int(before.get("db_size_bytes", 0)) - int(after.get("db_size_bytes", 0)))

    return {
        "older_than_days": safe_days,
        "cutoff_epoch": cutoff,
        "clear_all": bool(clear_all),
        "deleted": deleted,
        "vacuumed": vacuumed,
        "vacuum_error": vacuum_error,
        "before": before,
        "after": after,
        "reclaimed_bytes": reclaimed_bytes,
        "reclaimed_mb": round(reclaimed_bytes / (1024 * 1024), 3),
    }

def add_hunter_note(target: str, message: str, confidence: float = 0.0) -> Dict[str, Any]:
    normalized_target = normalize_target(target)
    clean_message = str(message or "").strip()
    if not normalized_target:
        raise ValueError("target is required")
    if not clean_message:
        raise ValueError("message is required")

    safe_confidence = max(0.0, min(1.0, float(confidence or 0.0)))
    created_at = now_ts()
    with _connect() as connection:
        cursor = connection.execute(
            """
            INSERT INTO hunter_notes (target, message, confidence, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (normalized_target, clean_message[:5000], safe_confidence, created_at),
        )
        connection.commit()
        note_id = int(cursor.lastrowid or 0)

    return {
        "id": note_id,
        "target": normalized_target,
        "message": clean_message[:5000],
        "confidence": safe_confidence,
        "created_at": created_at,
    }


def get_hunter_notes(target: str, limit: int = 50) -> List[Dict[str, Any]]:
    normalized_target = normalize_target(target)
    safe_limit = max(1, min(int(limit), 500))
    with _connect() as connection:
        rows = connection.execute(
            "SELECT * FROM hunter_notes WHERE target = ? ORDER BY created_at DESC LIMIT ?",
            (normalized_target, safe_limit),
        ).fetchall()
    return [dict(r) for r in rows]


def get_high_value_targets(
    target: str = "",
    limit: int = 100,
    min_score: int = 1,
    priority_band: str = "",
) -> List[Dict[str, Any]]:
    normalized_target = normalize_target(target) if target else ""
    safe_limit = max(1, min(int(limit), 1000))
    safe_min_score = max(1, min(int(min_score), 10))
    normalized_band = str(priority_band or "").strip().lower()

    clauses: List[str] = ["score >= ?"]
    params: List[Any] = [safe_min_score]

    if normalized_target:
        clauses.append("target = ?")
        params.append(normalized_target)

    if normalized_band in {"high", "medium", "low"}:
        clauses.append("LOWER(priority_band) = ?")
        params.append(normalized_band)

    where_sql = " AND ".join(clauses)
    query = f"""
        SELECT *
        FROM endpoint_intel
        WHERE {where_sql}
        ORDER BY
            CASE LOWER(priority_band)
                WHEN 'high' THEN 1
                WHEN 'medium' THEN 2
                ELSE 3
            END ASC,
            score DESC,
            research_hits DESC,
            last_seen DESC
        LIMIT ?
    """
    params.append(safe_limit)

    with _connect() as connection:
        rows = connection.execute(query, params).fetchall()

    return [dict(r) for r in rows]
