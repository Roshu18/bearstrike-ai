"""Tool runner for BearStrike AI.

Runs installed pentesting tools against targets and returns command output.
Timeout resilience is prioritized so MCP clients do not hang.
"""

from __future__ import annotations

import argparse
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

CORE_DIR = Path(__file__).resolve().parent
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from platform_profile import get_platform_profile
from tool_registry import check_tool_installed, load_tools_config

BASE_DIR = Path(__file__).resolve().parents[1]
PLATFORM_PROFILE = get_platform_profile()
PYTHON_CMD = str(PLATFORM_PROFILE.get("python_command", "python3"))


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(str(os.getenv(name, str(default))).strip()))
    except (TypeError, ValueError):
        return default


DEFAULT_TOOL_TIMEOUT_SECONDS = _env_int("BEARSTRIKE_TOOL_TIMEOUT_SECONDS", 45)
MAX_EFFECTIVE_TIMEOUT_SECONDS = _env_int("BEARSTRIKE_TOOL_TIMEOUT_MAX_SECONDS", 90)
MIN_EFFECTIVE_TIMEOUT_SECONDS = _env_int("BEARSTRIKE_TOOL_TIMEOUT_MIN_SECONDS", 5)
MAX_TOOL_OUTPUT_CHARS = 20000
SAFE_EXECUTION_DEFAULT = str(os.getenv("BEARSTRIKE_SAFE_EXECUTION", "1")).strip().lower() in {"1", "true", "yes", "on"}
FORCE_REFRESH_ON_MISS = str(os.getenv("BEARSTRIKE_FORCE_REFRESH_ON_MISS", "0")).strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

# Tools that are interactive/GUI-first and usually hang in MCP/headless contexts.
INTERACTIVE_OR_UNSAFE_TOOLS = {
    "metasploit",
    "browser-agent",
    "burpsuite-alternative",
    "maltego",
    "wireshark",
    "kismet",
    "spiderfoot",
    "mitmproxy",
}


SAFE_COMMAND_OVERRIDES: Dict[str, str] = {
    "nmap": "nmap -F -Pn --max-retries 1 --host-timeout 30s <target>",
    "rustscan": "rustscan -a <target_host> --ulimit 500 -- -Pn -T4 --max-retries 1 --host-timeout 45s",
    "whatweb": "whatweb --no-errors <target_url>",
    "httpx": "httpx -u <target_url> -title -status-code -tech-detect -timeout 8 -retries 1",
    "subfinder": "subfinder -d <target_host> -silent -max-time 2",
    "amass": "amass enum -d <target_host> -passive -timeout 10",
    "nuclei": "nuclei -u <target_url> -timeout 5 -retries 1 -rl 50 -c 20",
    "katana": "katana -u <target_url> -silent",
    "gobuster": "gobuster dir -u <target_url> -w /usr/share/wordlists/dirb/common.txt -t 20 --timeout 10s",
    "ffuf": "ffuf -u <target_url>/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,204,301,302,307,401,403 -maxtime 45 -t 40",
    "feroxbuster": "feroxbuster -u <target_url> -w /usr/share/wordlists/dirb/common.txt --time-limit 45 -t 20 --quiet",
    "dirsearch": "dirsearch -u <target_url> --max-time 45 --quiet-mode",
    "wfuzz": "wfuzz -w /usr/share/wordlists/dirb/common.txt --hc 404 -Z <target_url>/FUZZ",
    "sqlmap": "sqlmap -u '<target_url>/item.php?id=1' --batch --timeout=10 --retries=1 --threads=3 --level=1 --risk=1",
    "theharvester": "theHarvester -d <target_host> -b all -l 100",
    "wpscan": "wpscan --url <target_url> --enumerate vp --request-timeout 10",
    "wafw00f": f"{PYTHON_CMD} tools/wafw00f/wafw00f/main.py <target_url>",
    "sublist3r": "sublist3r -d <target_host> -t 20 -n",
    "parsero": "parsero -u <target_url>",
    "joomscan": "joomscan --url <target_url> --ec",
    "vulnx": "vulnx -u <target_url> --timeout 15",
    "commix": "commix --url <target_url>/index.php?id=1 --batch --level=1 --timeout=10",
    "ldapdomaindump": "ldapdomaindump --help",
    "zaproxy": "zaproxy -cmd -quickurl <target_url> -quickprogress -quickout /tmp/bearstrike_zaproxy_report.html",
    "zap-cli": "zap-cli quick-scan --self-contained --spider <target_url>",
}

TIMEOUT_FALLBACKS: Dict[str, str] = {
    "nmap": "nmap -F -Pn --max-retries 1 --host-timeout 30s <target>",
    "httpx": "httpx -u <target_url> -title -status-code -tech-detect -timeout 8 -retries 1",
    "whatweb": "whatweb --no-errors <target_url>",
    "subfinder": "subfinder -d <target_host> -silent -max-time 1",
    "katana": "katana -u <target_url> -silent",
    "nuclei": "nuclei -u <target_url> -timeout 5 -retries 1 -rl 50 -c 20",
    "rustscan": "rustscan -a <target_host> --ulimit 500 -- -Pn -T4 --max-retries 1 --host-timeout 30s",
    "sublist3r": "sublist3r -d <target_host> -n",
    "parsero": "parsero -u <target_url>",
    "joomscan": "joomscan --url <target_url>",
    "commix": "commix --url <target_url>/index.php?id=1 --batch --level=1",
    "zaproxy": "whatweb --no-errors <target_url>",
    "zap-cli": "whatweb --no-errors <target_url>",
}

TIMEOUT_ALTERNATIVE_TOOLS: Dict[str, str] = {
    "nmap": "rustscan",
    "rustscan": "nmap",
    "nuclei": "whatweb",
    "whatweb": "httpx",
    "httpx": "whatweb",
    "gobuster": "feroxbuster",
    "feroxbuster": "dirsearch",
    "dirsearch": "gobuster",
    "ffuf": "wfuzz",
    "sublist3r": "subfinder",
    "parsero": "whatweb",
    "joomscan": "whatweb",
    "vulnx": "nuclei",
    "commix": "sqlmap",
    "zaproxy": "httpx",
    "zap-cli": "httpx",
}


def _find_tool_definition(tool_name: str) -> Optional[dict]:
    tools: List[dict] = load_tools_config()
    for tool in tools:
        if str(tool.get("name", "")).strip().lower() == tool_name.lower():
            return tool
    return None


def _target_host(target: str) -> str:
    value = str(target or "").strip()
    if not value:
        return value
    value = re.sub(r"^https?://", "", value, flags=re.IGNORECASE)
    return value.split("/")[0]


def _target_url(target: str) -> str:
    value = str(target or "").strip()
    if not value:
        return value
    if value.lower().startswith("http://") or value.lower().startswith("https://"):
        return value
    return f"https://{_target_host(value)}"


def _normalize_placeholders(template: str, target: str) -> str:
    host = _target_host(target)
    url = _target_url(target)

    command = str(template or "")
    command = command.replace("<target_host>", host)
    command = command.replace("<host>", host)
    command = command.replace("<domain>", host)
    command = command.replace("<target_url>", url)
    command = command.replace("<url>", url)
    command = command.replace("<target>", target)

    # Backward compatibility for generic placeholders.
    command = re.sub(r"<[^>]+>", target, command)
    # Guard against malformed templates that prepend protocol before <target>.
    command = re.sub(r"(?i)\bhttps?://https?://", "https://", command)
    return command


def _build_command(tool_name: str, target: str) -> str:
    normalized = tool_name.strip().lower()

    if SAFE_EXECUTION_DEFAULT and normalized in SAFE_COMMAND_OVERRIDES:
        return _normalize_placeholders(SAFE_COMMAND_OVERRIDES[normalized], target)

    tool_def = _find_tool_definition(normalized)
    if tool_def and tool_def.get("usage"):
        return _normalize_placeholders(str(tool_def["usage"]), target)

    return f"{normalized} {target}"


def _resolve_timeout_seconds(tool_name: str, explicit_timeout: int | None) -> int:
    raw_timeout = DEFAULT_TOOL_TIMEOUT_SECONDS

    if explicit_timeout is not None:
        try:
            raw_timeout = int(explicit_timeout)
        except (TypeError, ValueError):
            raw_timeout = DEFAULT_TOOL_TIMEOUT_SECONDS
    else:
        env_timeout = os.getenv("BEARSTRIKE_TOOL_TIMEOUT_SECONDS", "").strip()
        if env_timeout:
            try:
                raw_timeout = int(env_timeout)
            except ValueError:
                raw_timeout = DEFAULT_TOOL_TIMEOUT_SECONDS

        tool_def = _find_tool_definition(tool_name)
        if tool_def and str(tool_def.get("timeout_seconds", "")).strip():
            try:
                raw_timeout = int(tool_def.get("timeout_seconds"))
            except (TypeError, ValueError):
                pass

    return max(MIN_EFFECTIVE_TIMEOUT_SECONDS, min(MAX_EFFECTIVE_TIMEOUT_SECONDS, raw_timeout))


def _sanitize_command(command: str) -> str:
    value = " ".join(str(command or "").split())

    # Never allow interactive sudo prompts in MCP mode.
    if value.startswith("sudo "):
        value = value.replace("sudo ", "sudo -n ", 1)

    return value


def _terminate_process_tree(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return

    try:
        if os.name != "nt":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
    except Exception:
        pass

    deadline = time.time() + 2.0
    while time.time() < deadline:
        if process.poll() is not None:
            return
        time.sleep(0.05)

    try:
        if os.name != "nt":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except Exception:
        pass


def _run_command_with_timeout(command: str, timeout_seconds: int) -> Dict[str, object]:
    kwargs: Dict[str, object] = {
        "shell": True,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "cwd": str(BASE_DIR),
        "env": {**os.environ, "PYTHONUNBUFFERED": "1"},
    }

    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True

    process = subprocess.Popen(command, **kwargs)  # type: ignore[arg-type]

    try:
        stdout, stderr = process.communicate(timeout=max(1, int(timeout_seconds)))
        return {
            "stdout": stdout or "",
            "stderr": stderr or "",
            "returncode": int(process.returncode or 0),
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        raw_stdout = exc.stdout or ""
        raw_stderr = exc.stderr or ""
        partial_stdout = raw_stdout.decode("utf-8", errors="ignore") if isinstance(raw_stdout, bytes) else str(raw_stdout)
        partial_stderr = raw_stderr.decode("utf-8", errors="ignore") if isinstance(raw_stderr, bytes) else str(raw_stderr)
        _terminate_process_tree(process)
        return {
            "stdout": partial_stdout,
            "stderr": partial_stderr,
            "returncode": -9,
            "timed_out": True,
        }


def _truncate_output(output: str) -> str:
    value = str(output or "")
    if len(value) <= MAX_TOOL_OUTPUT_CHARS:
        return value
    return value[:MAX_TOOL_OUTPUT_CHARS] + (
        f"\n\n[output truncated to {MAX_TOOL_OUTPUT_CHARS} chars for responsiveness]"
    )


def _fallback_command_for_timeout(tool_name: str, target: str) -> str | None:
    template = TIMEOUT_FALLBACKS.get(tool_name.strip().lower())
    if not template:
        return None
    return _sanitize_command(_normalize_placeholders(template, target))


def _attempt_timeout_alternative(tool_name: str, target: str, base_timeout: int) -> str | None:
    alternative = TIMEOUT_ALTERNATIVE_TOOLS.get(tool_name.strip().lower())
    if not alternative:
        return None

    if check_tool_installed(alternative) != "installed":
        return None

    alt_command = _sanitize_command(_build_command(alternative, target))
    alt_timeout = max(6, min(12, base_timeout // 3 or 8))
    alt_result = _run_command_with_timeout(alt_command, alt_timeout)
    alt_output = f"{alt_result.get('stdout', '')}{alt_result.get('stderr', '')}".strip()

    if not alt_output:
        return None

    alt_output = _truncate_output(alt_output)
    if bool(alt_result.get("timed_out", False)):
        return (
            f"Primary tool '{tool_name}' timed out. Tried alternative '{alternative}' "
            f"(timeout {alt_timeout}s) but it also timed out.\n\nPartial output:\n{alt_output}"
        )

    return (
        f"Primary tool '{tool_name}' timed out. Alternative '{alternative}' succeeded "
        f"(timeout {alt_timeout}s).\n\n"
        f"Alternative command: {alt_command}\n"
        f"{alt_output}"
    )


def _format_command_failure(returncode: int, output: str) -> str:
    lowered = output.lower()
    if "sudo:" in lowered and "password" in lowered:
        return (
            "Command requires elevated privileges. Run with proper sudo permissions "
            "or choose non-root tool mode."
        )
    if "not found" in lowered and "command" in lowered:
        return "Tool binary was not found in PATH. Install it first or refresh tool status."
    return f"Command failed (exit {returncode})\n{output}"


def build_tool_command_preview(tool_name: str, target: str) -> str:
    """Return the command string that will be executed for a tool/target pair."""
    normalized_name = tool_name.strip().lower()
    command = _build_command(normalized_name, target)
    return _sanitize_command(command)


def run_tool(tool_name: str, target: str, silent: bool = False, timeout_seconds: int | None = None) -> str:
    """Run a tool against a target and return combined output as a string."""
    normalized_name = tool_name.strip().lower()

    if normalized_name == "mitmproxy":
        message = (
            "mitmproxy is long-running and interactive. Start it in a dedicated terminal: "
            "mitmdump --listen-host 127.0.0.1 --listen-port 8081 --set flow_detail=1"
        )
        if not silent:
            print(message)
        return message

    if normalized_name in INTERACTIVE_OR_UNSAFE_TOOLS:
        message = (
            f"Tool '{normalized_name}' is interactive/GUI-oriented and disabled in MCP headless mode. "
            "Use a CLI alternative tool."
        )
        if not silent:
            print(message)
        return message

    status = check_tool_installed(normalized_name)
    if status != "installed" and FORCE_REFRESH_ON_MISS:
        # Optional forced refresh prevents stale cache from blocking newly installed tools.
        status = check_tool_installed(normalized_name, refresh=True)

    if status != "installed":
        message = "Tool not found: install it first"
        if not silent:
            print(message)
        return message

    command = _sanitize_command(_build_command(normalized_name, target))
    effective_timeout = _resolve_timeout_seconds(normalized_name, timeout_seconds)

    result = _run_command_with_timeout(command, effective_timeout)
    timed_out = bool(result.get("timed_out", False))

    output = f"{result.get('stdout', '')}{result.get('stderr', '')}".strip()

    if timed_out:
        fallback = _fallback_command_for_timeout(normalized_name, target)
        if fallback and fallback != command:
            retry_timeout = max(8, min(20, effective_timeout // 2 or 12))
            retry = _run_command_with_timeout(fallback, retry_timeout)
            retry_output = f"{retry.get('stdout', '')}{retry.get('stderr', '')}".strip()
            if retry_output:
                message = (
                    f"Primary command timed out after {effective_timeout}s. "
                    f"Fallback executed (timeout {retry_timeout}s).\n\n"
                    f"Fallback command: {fallback}\n"
                    f"{_truncate_output(retry_output)}"
                )
                if not silent:
                    print(message)
                return message

        alternative_output = _attempt_timeout_alternative(normalized_name, target, effective_timeout)
        if alternative_output:
            if not silent:
                print(alternative_output)
            return alternative_output

        timeout_message = f"Tool execution timed out after {effective_timeout}s: {normalized_name}"
        if output:
            timeout_message += f"\n\nPartial output:\n{_truncate_output(output)}"
        if not silent:
            print(timeout_message)
        return timeout_message

    output = output or "No output returned."
    returncode = int(result.get("returncode", 0) or 0)

    if returncode != 0 and not output.lower().startswith("error"):
        output = _format_command_failure(returncode, output)

    output = _truncate_output(output)

    if not silent:
        print(output)
    return output


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run BearStrike tool commands")
    parser.add_argument("tool", nargs="?", default="nmap", help="Tool name (default: nmap)")
    parser.add_argument("target", nargs="?", default="127.0.0.1", help="Target host/domain")
    parser.add_argument("--timeout", type=int, default=None, help="Optional timeout override in seconds")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    run_tool(args.tool, args.target, timeout_seconds=args.timeout)
