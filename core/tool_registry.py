"""Tool registry for BearStrike AI.

Loads tool definitions from tools/tools.json and checks whether each tool
is available in the system PATH or via check_command.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional, Tuple

BASE_DIR = Path(__file__).resolve().parents[1]
TOOLS_JSON_PATH = BASE_DIR / "tools" / "tools.json"

CHECK_CACHE_TTL_SECONDS = 300
PATH_BIN_CACHE_TTL_SECONDS = 60

_CONFIG_CACHE: List[dict] | None = None
_CONFIG_CACHE_MTIME_NS: int | None = None
_STATUS_CACHE: Dict[str, Tuple[str, float]] = {}
_STATUS_LOCK = Lock()

_PATH_BIN_CACHE: Tuple[set[str], float] = (set(), 0.0)


def _get_path_binary_index() -> set[str]:
    global _PATH_BIN_CACHE

    now = time.time()

    with _STATUS_LOCK:
        bins, at = _PATH_BIN_CACHE
        if bins and (now - at) < PATH_BIN_CACHE_TTL_SECONDS:
            return set(bins)

    resolved: set[str] = set()
    for raw_dir in str(os.getenv("PATH", "")).split(os.pathsep):
        directory = raw_dir.strip()
        if not directory:
            continue
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    try:
                        if not entry.is_file(follow_symlinks=False):
                            continue
                        name = entry.name.strip().lower()
                        if not name:
                            continue
                        resolved.add(name)
                    except OSError:
                        continue
        except OSError:
            continue

    with _STATUS_LOCK:
        _PATH_BIN_CACHE = (set(resolved), now)

    return resolved


def _normalize_python_command(command: str) -> str:
    value = command.strip()
    if value.startswith("python3 ") and shutil.which("python3") is None:
        return f'"{sys.executable}" ' + value[len("python3 "):]
    return value


def load_tools_config(tools_json_path: Path = TOOLS_JSON_PATH) -> List[dict]:
    global _CONFIG_CACHE, _CONFIG_CACHE_MTIME_NS

    try:
        stat = tools_json_path.stat()
        mtime_ns = int(stat.st_mtime_ns)
    except OSError:
        mtime_ns = None

    if (
        tools_json_path == TOOLS_JSON_PATH
        and _CONFIG_CACHE is not None
        and _CONFIG_CACHE_MTIME_NS is not None
        and mtime_ns == _CONFIG_CACHE_MTIME_NS
    ):
        return list(_CONFIG_CACHE)

    with tools_json_path.open("r", encoding="utf-8-sig") as file:
        data = json.load(file)

    if isinstance(data, dict) and "tools" in data and isinstance(data["tools"], list):
        tools = data["tools"]
    elif isinstance(data, list):
        tools = data
    else:
        raise ValueError("Invalid tools.json format: expected list or {'tools': [...]}.")

    if tools_json_path == TOOLS_JSON_PATH:
        _CONFIG_CACHE = list(tools)
        _CONFIG_CACHE_MTIME_NS = mtime_ns

    return list(tools)


def _check_command_available(command: str, timeout_seconds: int = 6) -> bool:
    command = command.strip()
    if not command:
        return False

    # Fast path: parse shell checks like "command -v foo || command -v bar"
    # without spawning subprocesses.
    if "command -v" in command:
        candidates = re.findall(r"command\s+-v\s+([A-Za-z0-9._+-]+)", command)
        if candidates:
            return any(bool(shutil.which(name.strip())) for name in candidates)

    command = _normalize_python_command(command)

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=max(1, int(timeout_seconds)),
            cwd=str(BASE_DIR),
        )
        return result.returncode == 0
    except Exception:
        return False


def _find_tool_definition(tool_name: str, tools: List[dict]) -> Optional[dict]:
    normalized = tool_name.strip().lower()
    for tool in tools:
        name = str(tool.get("name", "")).strip().lower()
        if name == normalized:
            return tool
    return None


def check_tool_installed(tool_name: str, tools: List[dict] | None = None, refresh: bool = False) -> str:
    normalized = tool_name.strip().lower()
    if not normalized:
        return "not_installed"

    now = time.time()
    with _STATUS_LOCK:
        cached = _STATUS_CACHE.get(normalized)
        if not refresh and cached and (now - cached[1]) < CHECK_CACHE_TTL_SECONDS:
            return cached[0]

    if tools is None:
        tools = load_tools_config()

    tool_def = _find_tool_definition(normalized, tools)
    if tool_def is None:
        status = "not_installed"
    else:
        check_command = str(tool_def.get("check_command", "")).strip()
        found_in_path = bool(shutil.which(normalized))
        found_by_check = False if found_in_path else _check_command_available(check_command)
        status = "installed" if (found_in_path or found_by_check) else "not_installed"

    with _STATUS_LOCK:
        _STATUS_CACHE[normalized] = (status, now)
    return status


def get_tool_statuses(tools: List[dict]) -> Dict[str, str]:
    statuses: Dict[str, str] = {}
    for tool in tools:
        tool_name = str(tool.get("name", "")).strip()
        if not tool_name:
            continue
        statuses[tool_name] = check_tool_installed(tool_name, tools=tools)
    return statuses


def print_tool_statuses(statuses: Dict[str, str]) -> None:
    print("BearStrike Tool Status")
    print("=" * 24)
    for tool_name, status in sorted(statuses.items()):
        print(f"{tool_name}: {status}")


def check_tool_installed_quick(tool_name: str, tools: List[dict] | None = None) -> str:
    normalized = tool_name.strip().lower()
    if not normalized:
        return "not_installed"

    now = time.time()
    with _STATUS_LOCK:
        cached = _STATUS_CACHE.get(normalized)
        if cached and (now - cached[1]) < CHECK_CACHE_TTL_SECONDS:
            return cached[0]

    if tools is None:
        tools = load_tools_config()

    tool_def = _find_tool_definition(normalized, tools)
    candidates = [normalized, normalized.replace("_", "-"), normalized.replace("-", "_")]

    if tool_def is not None:
        check_command = str(tool_def.get("check_command", "")).strip()
        if "command -v" in check_command:
            parsed = re.findall(r"command\s+-v\s+([A-Za-z0-9._+-]+)", check_command)
            candidates.extend(parsed)

    bins = _get_path_binary_index()
    status = "installed" if any(c.strip().lower() in bins for c in candidates if c.strip()) else "not_installed"

    with _STATUS_LOCK:
        _STATUS_CACHE[normalized] = (status, now)
    return status


def check_installed_tools(refresh: bool = False, quick: bool = False) -> Dict[str, str]:
    tools = load_tools_config()
    statuses: Dict[str, str] = {}
    for tool in tools:
        name = str(tool.get("name", "")).strip()
        if not name:
            continue

        if quick and not refresh:
            statuses[name] = check_tool_installed_quick(name, tools=tools)
        else:
            statuses[name] = check_tool_installed(name, tools=tools, refresh=refresh)

    return statuses


if __name__ == "__main__":
    try:
        tool_statuses = check_installed_tools(refresh=True)
        print_tool_statuses(tool_statuses)
    except Exception as exc:
        print(f"Error loading tool registry: {exc}")
