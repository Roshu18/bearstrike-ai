"""BearStrike AI entrypoint.

Starts terminal UI, dashboard backend, MCP server, and AI agent together.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, IO, List, Tuple


BASE_DIR = Path(__file__).resolve().parent
TERMINAL_DIR = BASE_DIR / "terminal"
CORE_DIR = BASE_DIR / "core"
CONFIG_PATH = BASE_DIR / "config.json"
LOGS_DIR = BASE_DIR / "logs"

if str(TERMINAL_DIR) not in sys.path:
    sys.path.insert(0, str(TERMINAL_DIR))
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from display import BannerLive  # noqa: E402
from runtime_state import load_runtime_state, reset_runtime_state, update_runtime_state  # noqa: E402
from tool_runner import run_tool  # noqa: E402


DEFAULT_CONFIG = {
    "ai_provider": "anthropic",
    "anthropic_api_key": "your-key-here",
    "claude_model": "claude-sonnet-4-20250514",
    "openai_api_key": "",
    "openai_model": "gpt-4o-mini",
    "openai_base_url": "https://api.openai.com/v1",
    "dashboard_port": 3000,
    "mcp_port": 8888,
    "auto_hunt": True,
    "default_target": "",
}


def _blue_tip(text: str) -> str:
    return f"\033[94m{text}\033[0m"


def load_config() -> Dict[str, Any]:
    if not CONFIG_PATH.exists():
        return dict(DEFAULT_CONFIG)

    try:
        raw = CONFIG_PATH.read_text(encoding="utf-8-sig").strip()
        data = json.loads(raw) if raw else {}
    except (OSError, json.JSONDecodeError):
        data = {}

    merged = dict(DEFAULT_CONFIG)
    merged.update(data)
    return merged


def _normalize_target_for_waf(target: str) -> str:
    cleaned = target.strip()
    if cleaned.startswith("http://") or cleaned.startswith("https://"):
        return cleaned
    return f"https://{cleaned}"


def _detect_waf_status(target: str) -> str:
    waf_target = _normalize_target_for_waf(target)
    output = run_tool("wafw00f", waf_target, silent=True)
    clean_output = re.sub(r"\x1b\[[0-9;]*m", "", output)
    lowered = clean_output.lower()

    if "tool not found" in lowered:
        return "wafw00f not available"
    if "no waf" in lowered or "is not behind a waf" in lowered:
        return "No WAF detected"
    if "seems to be behind a waf or some sort of security solution" in lowered:
        return "Generic WAF / Security solution"

    match = re.search(r"behind\s+(.+?)\s+waf", clean_output, flags=re.IGNORECASE)
    if match:
        candidate = match.group(1).strip()
        if candidate.lower() in {"a", "an", "the"}:
            return "Generic WAF / Security solution"
        return candidate

    match_simple = re.search(r"is behind\s+(.+)", clean_output, flags=re.IGNORECASE)
    if match_simple:
        value = match_simple.group(1).strip().splitlines()[0][:80]
        if "some sort of security solution" in value.lower():
            return "Generic WAF / Security solution"
        return value

    return "Unknown"


def _provider(config: Dict[str, Any]) -> str:
    return str(config.get("ai_provider", "anthropic")).strip().lower()


def _anthropic_ready(config: Dict[str, Any]) -> bool:
    key = str(config.get("anthropic_api_key", "")).strip()
    return bool(key and key != "your-key-here")


def _openai_ready(config: Dict[str, Any]) -> bool:
    key = str(config.get("openai_api_key", "")).strip()
    return bool(key)


def _ai_provider_ready(config: Dict[str, Any]) -> bool:
    provider = _provider(config)
    if provider == "anthropic":
        return _anthropic_ready(config)
    if provider in {"openai", "openai_compatible", "grok", "xai"}:
        return _openai_ready(config)
    return False


def _resolve_ai_model_display(config: Dict[str, Any]) -> str:
    provider = _provider(config)

    if provider == "anthropic":
        model = str(config.get("claude_model", DEFAULT_CONFIG["claude_model"])).strip()
        if _anthropic_ready(config):
            return f"{model} [anthropic]"
        return "MCP / Local mode"

    if provider in {"openai", "openai_compatible", "grok", "xai"}:
        model = str(config.get("openai_model", DEFAULT_CONFIG["openai_model"])).strip()
        if _openai_ready(config):
            return f"{model} [{provider}]"
        return "MCP / Local mode"

    return "MCP / Local mode"


def _open_log_handle(name: str) -> IO[str]:
    candidates = [LOGS_DIR, Path("/tmp/bearstrike-ai-logs")]
    for base in candidates:
        try:
            base.mkdir(parents=True, exist_ok=True)
            path = base / f"{name}.log"
            return path.open("a", encoding="utf-8")
        except OSError:
            continue

    # Last resort: discard subprocess logs instead of crashing startup.
    return open(os.devnull, "w", encoding="utf-8")


def start_process(
    command: List[str],
    cwd: Path,
    env: Dict[str, str] | None = None,
    stdout: IO[str] | int | None = None,
    stderr: IO[str] | int | None = None,
) -> subprocess.Popen[str]:
    return subprocess.Popen(command, cwd=str(cwd), env=env, stdout=stdout, stderr=stderr)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="BearStrike AI launcher")
    parser.add_argument("target", nargs="?", default="", help="Initial target")
    parser.add_argument("--standalone", action="store_true", help="Run only terminal + dashboard (no MCP, no AI loop)")
    parser.add_argument("--no-mcp", action="store_true", help="Skip MCP server startup")
    parser.add_argument("--no-ai-agent", action="store_true", help="Skip AI agent startup")
    parser.add_argument("--dashboard-port", type=int, default=0, help="Preferred dashboard port override")
    parser.add_argument("--mcp-port", type=int, default=0, help="Preferred MCP port override")
    return parser.parse_args()


def _banner_state_tuple(state: Dict[str, Any]) -> Tuple[str, ...]:
    events = state.get("mcp_events") or []
    last_event_status = ""
    if events and isinstance(events[-1], dict):
        last_event_status = str(events[-1].get("status") or "")

    return (
        str(state.get("current_target") or "").strip() or "not-set",
        str(state.get("waf_status") or "Unknown"),
        str(state.get("ai_model") or "MCP / Local mode"),
        str(state.get("current_task") or "idle"),
        str(state.get("target_output_dir") or "").strip(),
        str(state.get("dashboard_url") or "").strip(),
        str(state.get("mcp_url") or "").strip(),
        str(state.get("last_mcp_tool") or ""),
        str(state.get("last_mcp_target") or ""),
        str(state.get("last_mcp_command") or ""),
        str(state.get("last_mcp_status") or "idle"),
        str(state.get("last_mcp_progress") or ""),
        str(state.get("last_mcp_response_preview") or ""),
        str(len(events)),
        last_event_status,
    )


def _banner_kwargs_from_state(state: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "target": str(state.get("current_target") or "").strip() or "not-set",
        "waf_status": str(state.get("waf_status") or "Unknown"),
        "ai_model": str(state.get("ai_model") or "MCP / Local mode"),
        "current_task": str(state.get("current_task") or "idle"),
        "target_output_dir": str(state.get("target_output_dir") or "").strip(),
        "dashboard_url": str(state.get("dashboard_url") or "").strip(),
        "mcp_url": str(state.get("mcp_url") or "").strip(),
        "last_mcp_tool": str(state.get("last_mcp_tool") or ""),
        "last_mcp_target": str(state.get("last_mcp_target") or ""),
        "last_mcp_command": str(state.get("last_mcp_command") or ""),
        "last_mcp_status": str(state.get("last_mcp_status") or "idle"),
        "last_mcp_progress": str(state.get("last_mcp_progress") or ""),
        "last_mcp_response_preview": str(state.get("last_mcp_response_preview") or ""),
        "mcp_events": state.get("mcp_events") or [],
    }


def _render_banner_from_runtime_state(banner_live: BannerLive) -> Tuple[str, ...]:
    state = load_runtime_state()
    banner_live.update(**_banner_kwargs_from_state(state))
    return _banner_state_tuple(state)


def _check_started(name: str, proc: subprocess.Popen[str]) -> bool:
    time.sleep(1.0)
    if proc.poll() is not None:
        print(f"[main] {name} failed to start (exit {proc.returncode}).")
        return False
    print(f"[main] {name} started")
    return True


def main() -> None:
    args = parse_args()
    config = load_config()

    selected_target = args.target.strip() or str(config.get("default_target", "")).strip()

    if selected_target:
        waf_status = _detect_waf_status(selected_target)
    else:
        waf_status = "No target selected"

    reset_runtime_state()
    update_runtime_state(
        current_target=selected_target,
        waf_status=waf_status,
        ai_provider=_provider(config),
        ai_model=_resolve_ai_model_display(config),
        current_task="starting",
        dashboard_url="",
        mcp_url="",
    )

    banner_live = BannerLive()
    last_banner_state = _render_banner_from_runtime_state(banner_live)

    if not selected_target:
        print("No target passed. Set one in dashboard or run: python3 main.py <target>")

    if not _ai_provider_ready(config):
        print("AI API key is not configured; local mode + MCP mode still available.")

    print("Starting BearStrike components...")
    print(_blue_tip("Tip: run `python3 main.py --help` for all startup options."))

    processes: Dict[str, subprocess.Popen[str]] = {}
    log_handles: Dict[str, IO[str]] = {}

    try:
        dashboard_port = int(args.dashboard_port or config.get("dashboard_port", 3000))
        dashboard_env = os.environ.copy()
        dashboard_env["BEARSTRIKE_DASHBOARD_PORT"] = str(dashboard_port)

        log_handles["dashboard"] = _open_log_handle("dashboard")
        dashboard_proc = start_process(
            [sys.executable, "dashboard/server.py"],
            BASE_DIR,
            env=dashboard_env,
            stdout=log_handles["dashboard"],
            stderr=subprocess.STDOUT,
        )
        if _check_started("Dashboard", dashboard_proc):
            processes["dashboard"] = dashboard_proc
            dashboard_url = ""
            for _ in range(12):
                snapshot = load_runtime_state()
                dashboard_url = str(snapshot.get("dashboard_url") or "").strip()
                if dashboard_url:
                    break
                time.sleep(0.2)
            if dashboard_url:
                print(f"[main] Dashboard URL: {dashboard_url}")
        else:
            print("[main] Dashboard unavailable. Check port conflicts and try another --dashboard-port.")

        if not args.standalone and not args.no_mcp:
            mcp_port = int(args.mcp_port or config.get("mcp_port", 8888))
            mcp_env = os.environ.copy()
            mcp_env["MCP_TRANSPORT"] = "sse"
            mcp_env["BEARSTRIKE_MCP_PORT"] = str(mcp_port)

            log_handles["mcp"] = _open_log_handle("mcp")
            mcp_proc = start_process(
                [sys.executable, "core/mcp_server.py", "--port", str(mcp_port), "--transport", "sse"],
                BASE_DIR,
                env=mcp_env,
                stdout=log_handles["mcp"],
                stderr=subprocess.STDOUT,
            )
            if _check_started("MCP server", mcp_proc):
                processes["mcp"] = mcp_proc
                mcp_url = ""
                for _ in range(12):
                    snapshot = load_runtime_state()
                    mcp_url = str(snapshot.get("mcp_url") or "").strip()
                    if mcp_url:
                        break
                    time.sleep(0.2)
                if mcp_url:
                    print(f"[main] MCP SSE URL: {mcp_url}")

        auto_hunt = bool(config.get("auto_hunt", True))
        allow_ai = not args.standalone and not args.no_ai_agent

        if allow_ai and auto_hunt and selected_target and _ai_provider_ready(config):
            log_handles["ai_agent"] = _open_log_handle("ai_agent")
            ai_proc = start_process(
                [sys.executable, "core/ai_agent.py", selected_target],
                BASE_DIR,
                stdout=log_handles["ai_agent"],
                stderr=subprocess.STDOUT,
            )
            if _check_started("AI agent", ai_proc):
                processes["ai_agent"] = ai_proc
        elif allow_ai and auto_hunt and selected_target and not _ai_provider_ready(config):
            print("[main] AI agent skipped (API key not configured)")
        elif allow_ai and auto_hunt and not selected_target:
            print("[main] AI agent skipped (no target set)")

        update_runtime_state(current_task="idle")
        print("BearStrike is running. Press Ctrl+C to stop.")

        while True:
            for name, proc in list(processes.items()):
                if proc.poll() is not None:
                    print(f"[{name}] exited with code {proc.returncode}")
                    processes.pop(name)

            current = load_runtime_state()
            banner_state = _banner_state_tuple(current)
            if banner_state != last_banner_state:
                banner_live.update(**_banner_kwargs_from_state(current))
                last_banner_state = banner_state

            if not processes:
                print("All BearStrike components have exited.")
                break

            time.sleep(0.6)

    except KeyboardInterrupt:
        print("Shutting down BearStrike components...")
    finally:
        update_runtime_state(current_task="stopping")

        for proc in processes.values():
            if proc.poll() is None:
                proc.terminate()
        for proc in processes.values():
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()

        for handle in log_handles.values():
            try:
                handle.close()
            except Exception:
                pass

        banner_live.stop()
        update_runtime_state(current_task="stopped")


if __name__ == "__main__":
    main()
