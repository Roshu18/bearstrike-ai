"""Shared runtime state for BearStrike components.

This file allows main/dashboard/MCP/AI modules to share the same current target,
WAF status, AI model/provider, and active task information.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict

BASE_DIR = Path(__file__).resolve().parents[1]
RUNTIME_STATE_PATH = BASE_DIR / "runtime_state.json"
REPORTS_OUTPUT_ROOT = BASE_DIR / "reports" / "output"

DEFAULT_RUNTIME_STATE: Dict[str, Any] = {
    "current_target": "",
    "waf_status": "No target selected",
    "ai_provider": "local",
    "ai_model": "MCP / Local mode",
    "current_task": "idle",
    "target_slug": "",
    "target_output_dir": "",
    "dashboard_port": None,
    "dashboard_url": "",
    "mcp_port": None,
    "mcp_transport": "",
    "mcp_url": "",
    "last_mcp_tool": "",
    "last_mcp_target": "",
    "last_mcp_command": "",
    "last_mcp_status": "idle",
    "last_mcp_response_preview": "",
    "last_mcp_progress": "",
    "mcp_events": [],
    "updated_at": 0.0,
}


def target_slug(target: str) -> str:
    value = str(target or "").strip().lower()
    value = re.sub(r"^https?://", "", value, flags=re.IGNORECASE)
    value = value.split("/")[0]
    value = "".join(ch if ch.isalnum() else "_" for ch in value).strip("_")
    return value or "target"


def target_output_dir(target: str) -> str:
    normalized = str(target or "").strip()
    if not normalized:
        return ""
    return str((REPORTS_OUTPUT_ROOT / target_slug(normalized)).resolve())


def discover_recent_target_folders(limit: int = 20) -> list[dict]:
    safe_limit = max(1, min(int(limit), 200))
    if not REPORTS_OUTPUT_ROOT.exists():
        return []

    folders = []
    for entry in REPORTS_OUTPUT_ROOT.iterdir():
        if not entry.is_dir():
            continue
        try:
            last_modified = float(entry.stat().st_mtime)
        except OSError:
            last_modified = 0.0
        folders.append(
            {
                "slug": entry.name,
                "path": str(entry.resolve()),
                "last_modified": last_modified,
            }
        )
    folders.sort(key=lambda item: float(item.get("last_modified", 0.0)), reverse=True)
    return folders[:safe_limit]


def load_runtime_state() -> Dict[str, Any]:
    if not RUNTIME_STATE_PATH.exists():
        return dict(DEFAULT_RUNTIME_STATE)

    try:
        raw = RUNTIME_STATE_PATH.read_text(encoding="utf-8-sig").strip()
        data = json.loads(raw) if raw else {}
    except (OSError, json.JSONDecodeError):
        data = {}

    merged = dict(DEFAULT_RUNTIME_STATE)
    if isinstance(data, dict):
        merged.update(data)
    return merged


def save_runtime_state(state: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(DEFAULT_RUNTIME_STATE)
    merged.update(state)
    merged["updated_at"] = time.time()

    events = merged.get("mcp_events")
    if isinstance(events, list):
        merged["mcp_events"] = events[-50:]

    try:
        temp_path = RUNTIME_STATE_PATH.with_suffix(".tmp")
        temp_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
        temp_path.replace(RUNTIME_STATE_PATH)
    except OSError:
        # Runtime state sync should never crash the main app flow.
        pass

    return merged


def update_runtime_state(**changes: Any) -> Dict[str, Any]:
    state = load_runtime_state()
    state.update(changes)
    if "current_target" in changes:
        current_target = str(state.get("current_target") or "").strip()
        state["target_slug"] = target_slug(current_target) if current_target else ""
        state["target_output_dir"] = target_output_dir(current_target) if current_target else ""
    return save_runtime_state(state)


def reset_runtime_state() -> Dict[str, Any]:
    return save_runtime_state(dict(DEFAULT_RUNTIME_STATE))


def log_mcp_event(event: dict) -> dict:
    state = load_runtime_state()
    events = state.get("mcp_events") if isinstance(state.get("mcp_events"), list) else []
    events.append(event)
    state["mcp_events"] = events[-50:]
    return save_runtime_state(state)
