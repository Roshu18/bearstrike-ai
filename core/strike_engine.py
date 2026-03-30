"""Autonomous strike engine for BearStrike."""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional

try:  # pragma: no cover - import path compatibility for script/package execution
    from core.control_plane import (
        add_hunter_note,
        append_run_event,
        get_high_value_targets,
        normalize_target,
    )
    from core.runtime_state import update_runtime_state
    from core.tool_registry import check_tool_installed
    from core.tool_runner import run_tool
except ImportError:  # pragma: no cover
    from control_plane import (  # type: ignore[no-redef]
        add_hunter_note,
        append_run_event,
        get_high_value_targets,
        normalize_target,
    )
    from runtime_state import update_runtime_state  # type: ignore[no-redef]
    from tool_registry import check_tool_installed  # type: ignore[no-redef]
    from tool_runner import run_tool  # type: ignore[no-redef]


_ACTIVE_HUNT: Optional[threading.Thread] = None
_HUNT_STOP_EVENT = threading.Event()
_HUNT_LOCK = threading.Lock()

_HUNT_STATE: Dict[str, Any] = {
    "running": False,
    "target": "",
    "mode": "low_noise",
    "started_at": 0.0,
    "finished_at": 0.0,
    "last_tool": "",
    "last_message": "",
    "loops": 0,
    "high_confidence_hits": 0,
    "stop_reason": "",
}


def _is_running() -> bool:
    return bool(_ACTIVE_HUNT and _ACTIVE_HUNT.is_alive())


def _event_job_id(target: str) -> str:
    return f"hunt:{normalize_target(target)}"


def _tool_available(name: str) -> bool:
    try:
        raw_status = check_tool_installed(name, refresh=False)
        if isinstance(raw_status, bool):
            return bool(raw_status)
        status = str(raw_status).strip().lower()
        return status in {"installed", "true", "1", "yes"}
    except Exception:
        return False


def _sleep_for_mode(mode: str) -> float:
    normalized = str(mode or "low_noise").strip().lower()
    if normalized == "aggressive":
        return 3.0
    if normalized == "balanced":
        return 6.0
    return 10.0


def _timeout_for_tool(tool_name: str) -> int:
    key = str(tool_name or "").strip().lower()
    if key in {"nuclei", "xray-suite-webscan"}:
        return 60
    if key in {"subfinder", "katana", "gau"}:
        return 35
    return 25


def _confidence_from_output(output: str) -> tuple[float, str]:
    text = str(output or "").lower()
    if not text:
        return 0.0, "empty-output"
    if "tool not found" in text or "timed out" in text:
        return 0.0, "execution-failed"

    high_markers = [
        "critical",
        "[critical]",
        "high severity",
        "remote code execution",
        "sql injection",
        "ssrf",
        "idor",
        "broken access control",
        "stored xss",
        "vulnerability found",
    ]
    medium_markers = [
        "open redirect",
        "sensitive information",
        "exposed",
        "misconfiguration",
        "possible",
        "potential",
    ]

    score = 0.0
    hits = []
    for marker in high_markers:
        if marker in text:
            score += 0.18
            hits.append(marker)
    for marker in medium_markers:
        if marker in text:
            score += 0.08
            hits.append(marker)

    score = max(0.0, min(1.0, score))
    reason = ",".join(hits[:4]) if hits else "no-positive-markers"
    return score, reason


def _pick_next_tool(mode: str, loop_index: int) -> str:
    # Low-noise rotating sequence. Heavy tools are sparse.
    normalized = str(mode or "low_noise").strip().lower()
    base = ["httpx", "whatweb", "subfinder", "gau", "katana"]
    heavy = ["nuclei", "xray-suite-webscan"]

    if normalized == "aggressive":
        plan = ["httpx", "whatweb", "subfinder", "gau", "katana", "nuclei", "xray-suite-webscan"]
    elif normalized == "balanced":
        plan = ["httpx", "whatweb", "subfinder", "gau", "katana", "nuclei"]
    else:
        plan = base + ["nuclei"]

    # Every few loops, allow one heavy pass.
    if loop_index > 0 and loop_index % 5 == 0:
        for candidate in heavy:
            if _tool_available(candidate):
                return candidate

    for offset in range(len(plan)):
        candidate = plan[(loop_index + offset) % len(plan)]
        if _tool_available(candidate):
            return candidate
    return ""


def _endpoint_target(base_target: str) -> str:
    high_targets = get_high_value_targets(target=base_target, limit=5, min_score=8)
    if not high_targets:
        return base_target

    first = high_targets[0]
    path = str(first.get("path_signature") or "").strip()
    if not path or path == "/":
        return base_target

    if base_target.startswith("http://") or base_target.startswith("https://"):
        return f"{base_target.rstrip('/')}{path}"
    return f"https://{base_target.rstrip('/')}{path}"


def _set_hunt_state(**changes: Any) -> None:
    with _HUNT_LOCK:
        _HUNT_STATE.update(changes)


def get_autonomous_hunt_state() -> Dict[str, Any]:
    with _HUNT_LOCK:
        return dict(_HUNT_STATE)


def _hunt_worker(target: str, mode: str = "low_noise", max_duration_seconds: int = 3600) -> None:
    normalized_target = normalize_target(target)
    mode_value = str(mode or "low_noise").strip().lower()
    max_duration = max(60, min(int(max_duration_seconds), 86400))
    started = time.time()
    event_id = _event_job_id(normalized_target)

    _set_hunt_state(
        running=True,
        target=normalized_target,
        mode=mode_value,
        started_at=started,
        finished_at=0.0,
        last_tool="",
        last_message="started",
        loops=0,
        high_confidence_hits=0,
        stop_reason="",
    )
    update_runtime_state(current_target=normalized_target, current_task=f"autonomous-hunt:{mode_value}")
    append_run_event(event_id, "started", f"Autonomous hunt started for {normalized_target}", {"mode": mode_value})

    try:
        # Lightweight startup fingerprinting.
        for startup_tool in ("wafw00f", "httpx", "whatweb"):
            if _HUNT_STOP_EVENT.is_set():
                break
            if not _tool_available(startup_tool):
                continue
            out = run_tool(startup_tool, normalized_target, silent=True, timeout_seconds=_timeout_for_tool(startup_tool))
            conf, reason = _confidence_from_output(out)
            _set_hunt_state(last_tool=startup_tool, last_message=f"startup:{reason}")
            append_run_event(
                event_id,
                "startup",
                f"{startup_tool} finished (confidence={conf:.2f}, reason={reason})",
            )
            if conf >= 0.92:
                note = add_hunter_note(
                    target=normalized_target,
                    message=f"High-confidence startup signal from {startup_tool}: {reason}",
                    confidence=conf,
                )
                _set_hunt_state(high_confidence_hits=1, stop_reason="high-confidence-hit")
                append_run_event(event_id, "success", f"Stopping hunt after startup hit: note_id={note.get('id')}")
                return
            time.sleep(_sleep_for_mode(mode_value))

        loop_index = 0
        while not _HUNT_STOP_EVENT.is_set():
            elapsed = time.time() - started
            if elapsed >= max_duration:
                _set_hunt_state(stop_reason="max-duration-reached")
                append_run_event(event_id, "finished", f"Stopped: max duration reached ({max_duration}s)")
                break

            tool_name = _pick_next_tool(mode_value, loop_index)
            if not tool_name:
                _set_hunt_state(stop_reason="no-available-tools", last_message="no tools available")
                append_run_event(event_id, "finished", "Stopped: no available tools in current environment")
                break

            resolved_target = _endpoint_target(normalized_target)
            _set_hunt_state(loops=loop_index + 1, last_tool=tool_name, last_message=f"running:{resolved_target}")
            update_runtime_state(current_target=normalized_target, current_task=f"autonomous {tool_name} on {resolved_target}")
            append_run_event(
                event_id,
                "running",
                f"Loop {loop_index + 1}: {tool_name} on {resolved_target}",
                {"loop": loop_index + 1, "tool": tool_name, "target": resolved_target},
            )

            output = run_tool(tool_name, resolved_target, silent=True, timeout_seconds=_timeout_for_tool(tool_name))
            confidence, reason = _confidence_from_output(output)
            append_run_event(
                event_id,
                "result",
                f"{tool_name} confidence={confidence:.2f} reason={reason}",
            )

            if confidence >= 0.92:
                note = add_hunter_note(
                    target=normalized_target,
                    message=f"Autonomous high-confidence signal from {tool_name}: {reason}",
                    confidence=confidence,
                )
                _set_hunt_state(high_confidence_hits=int(_HUNT_STATE.get("high_confidence_hits") or 0) + 1)
                _set_hunt_state(stop_reason="high-confidence-hit", last_message=f"note:{note.get('id')}")
                append_run_event(
                    event_id,
                    "success",
                    f"Stopping after high-confidence signal from {tool_name} (note_id={note.get('id')})",
                )
                break

            loop_index += 1
            time.sleep(_sleep_for_mode(mode_value))
    except Exception as exc:
        _set_hunt_state(stop_reason="exception", last_message=str(exc))
        append_run_event(event_id, "error", f"Autonomous hunt crashed: {exc}")
    finally:
        finished = time.time()
        _set_hunt_state(running=False, finished_at=finished)
        update_runtime_state(current_task="idle")
        append_run_event(event_id, "finished", f"Autonomous hunt finished at {finished}")


def start_autonomous_hunt(target: str, mode: str = "low_noise", max_duration_seconds: int = 3600) -> str:
    global _ACTIVE_HUNT
    normalized_target = normalize_target(target)
    if not normalized_target:
        return "target is required"

    with _HUNT_LOCK:
        if _ACTIVE_HUNT and _ACTIVE_HUNT.is_alive():
            state = dict(_HUNT_STATE)
            return (
                f"Autonomous hunt already running for {state.get('target', 'unknown')} "
                f"(mode={state.get('mode', 'low_noise')})."
            )

        _HUNT_STOP_EVENT.clear()
        _ACTIVE_HUNT = threading.Thread(
            target=_hunt_worker,
            args=(normalized_target, mode, max_duration_seconds),
            name="bearstrike-autonomous-hunt",
            daemon=True,
        )
        _ACTIVE_HUNT.start()

    return (
        f"Autonomous strike engine started for {normalized_target} "
        f"(mode={mode}, max_duration_seconds={max_duration_seconds})."
    )


def stop_autonomous_hunt() -> str:
    _HUNT_STOP_EVENT.set()
    return "Autonomous strike engine stop signal sent."
