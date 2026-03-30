"""Cross-platform bridge runner for the Xray Suite tools.

Provides a stable interface for:
- xray scanner modes (webscan/servicescan/subdomain)
- crawlergo
- headless browser DOM capture

Works on Linux-only setups and Windows/WSL environments.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SUITE_CONFIG_PATH = PROJECT_ROOT / "tools" / "xray_suite" / "config.yaml"
REPORTS_ROOT = PROJECT_ROOT / "reports" / "output" / "xray_suite"

LOCAL_WINDOWS_BUNDLE = PROJECT_ROOT / "tools" / "bin" / "windows" / "xray-suite"
LOCAL_LINUX_BUNDLE = PROJECT_ROOT / "tools" / "bin" / "linux" / "xray-suite"

TOOL_ALIASES = {
    "xray-suite-webscan": "xray",
    "xray-suite-servicescan": "xray",
    "xray-suite-subdomain": "xray",
    "xray-suite-crawlergo": "crawlergo",
    "xray-suite-headless-browser": "browser",
}


def _is_windows_host() -> bool:
    return sys.platform.startswith("win")


def _is_linux_host() -> bool:
    return sys.platform.startswith("linux")


def _is_wsl() -> bool:
    if not _is_linux_host():
        return False
    try:
        return "microsoft" in Path("/proc/version").read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        return False


def _candidate_windows_dep_dirs() -> List[Path]:
    candidates: List[Path] = []

    env_path = os.getenv("XRAY_SUITE_DEP_PATH", "").strip()
    if env_path:
        candidates.append(Path(env_path))

    if _is_wsl():
        candidates.extend(
            [
                Path("/mnt/c/Program Files/Penligent/resources/depency"),
                Path("/mnt/c/Program Files/Penligent/resources/dependency"),
                LOCAL_WINDOWS_BUNDLE,
            ]
        )
    else:
        candidates.extend(
            [
                LOCAL_WINDOWS_BUNDLE,
                Path(r"C:\Program Files\Penligent\resources\depency"),
                Path(r"C:\Program Files\Penligent\resources\dependency"),
                Path("/mnt/c/Program Files/Penligent/resources/depency"),
                Path("/mnt/c/Program Files/Penligent/resources/dependency"),
            ]
        )

    unique: List[Path] = []
    for item in candidates:
        if item not in unique:
            unique.append(item)
    return unique


def _candidate_linux_paths() -> Dict[str, List[Path | str]]:
    return {
        "xray": [LOCAL_LINUX_BUNDLE / "xray", "xray"],
        "crawlergo": [LOCAL_LINUX_BUNDLE / "crawlergo", "crawlergo"],
        "browser": [
            LOCAL_LINUX_BUNDLE / "chrome-headless-shell",
            "chrome-headless-shell",
            "google-chrome",
            "chromium",
            "chromium-browser",
        ],
    }


def _to_windows_path(path: Path) -> str:
    text = str(path)
    if text.startswith("/mnt/") and len(text) > 6:
        drive_letter = text[5].upper()
        tail = text[6:].replace("/", "\\")
        return f"{drive_letter}:{tail}"
    return text


def _run_command(command: List[str], timeout: int = 240, cwd: Optional[Path] = None) -> subprocess.CompletedProcess[str]:
    run_cwd = cwd or PROJECT_ROOT
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(run_cwd),
        )
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(command, 1, "", f"{exc}\n")


def _print_result(result: subprocess.CompletedProcess[str]) -> None:
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    if output:
        print(output)


def _ensure_local_windows_bundle() -> None:
    if os.getenv("XRAY_SUITE_DISABLE_LOCAL_SYNC", "").strip().lower() in {"1", "true", "yes"}:
        return

    sources = [
        Path(r"C:\Program Files\Penligent\resources\depency"),
        Path("/mnt/c/Program Files/Penligent/resources/depency"),
    ]
    source_root = next((src for src in sources if src.exists()), None)
    if source_root is None:
        return

    LOCAL_WINDOWS_BUNDLE.mkdir(parents=True, exist_ok=True)

    scanner_src = source_root / "scanner" / "scanner_windows_amd64.exe"
    crawler_src = source_root / "crawlergo.exe"
    chrome_src = source_root / "chrome-headless-shell"

    scanner_dst = LOCAL_WINDOWS_BUNDLE / "scanner" / "scanner_windows_amd64.exe"
    crawler_dst = LOCAL_WINDOWS_BUNDLE / "crawlergo.exe"
    chrome_dst = LOCAL_WINDOWS_BUNDLE / "chrome-headless-shell"

    try:
        if scanner_src.exists() and not scanner_dst.exists():
            scanner_dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(scanner_src, scanner_dst)
        if crawler_src.exists() and not crawler_dst.exists():
            shutil.copy2(crawler_src, crawler_dst)
        if chrome_src.exists() and not chrome_dst.exists():
            shutil.copytree(chrome_src, chrome_dst)
    except OSError:
        pass


def _resolve_windows_binary_paths() -> Dict[str, Path | str]:
    _ensure_local_windows_bundle()

    for dep in _candidate_windows_dep_dirs():
        scanner = dep / "scanner" / "scanner_windows_amd64.exe"
        crawlergo = dep / "crawlergo.exe"
        chrome = (
            dep
            / "chrome-headless-shell"
            / "win64-120.0.6098.0"
            / "chrome-headless-shell-win64"
            / "chrome-headless-shell.exe"
        )

        if not chrome.exists():
            generic = list((dep / "chrome-headless-shell").glob("**/chrome-headless-shell.exe"))
            if generic:
                chrome = generic[0]

        if scanner.exists() or crawlergo.exists() or chrome.exists():
            return {"dep": dep, "xray": scanner, "crawlergo": crawlergo, "browser": chrome}

    return {"dep": Path(""), "xray": Path(""), "crawlergo": Path(""), "browser": Path("")}


def _resolve_linux_binary_paths() -> Dict[str, Path | str]:
    resolved: Dict[str, Path | str] = {}
    for key, options in _candidate_linux_paths().items():
        resolved_value: Path | str = Path("")
        for option in options:
            if isinstance(option, Path):
                if option.exists() and os.access(option, os.X_OK):
                    resolved_value = option
                    break
            else:
                if shutil.which(option):
                    resolved_value = option
                    break
        resolved[key] = resolved_value
    return resolved


def _resolve_binary_paths() -> Dict[str, Path | str]:
    if _is_windows_host() or _is_wsl():
        return _resolve_windows_binary_paths()
    return _resolve_linux_binary_paths()


def _normalize_web_target(target: str) -> str:
    value = target.strip()
    if value.startswith("http://") or value.startswith("https://"):
        return value
    return f"https://{value}"


def _windows_powershell_path() -> Path:
    return Path("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")


def _run_browser(binary: Path | str, target: str, timeout: int = 240) -> subprocess.CompletedProcess[str]:
    base_flags = ["--headless", "--disable-gpu", "--disable-software-rasterizer", "--dump-dom", target]

    if isinstance(binary, str):
        command = [binary] + base_flags
        if _is_linux_host() and os.geteuid() == 0:
            command.insert(1, "--no-sandbox")
        return _run_command(command, timeout=timeout)

    browser_cwd = binary.parent if binary.exists() else PROJECT_ROOT

    if _is_wsl() and str(binary).startswith("/mnt/c/"):
        powershell = _windows_powershell_path()
        if powershell.exists():
            windows_binary = _to_windows_path(binary)
            ps_command = (
                f"& '{windows_binary}' --headless --disable-gpu "
                f"--disable-software-rasterizer --dump-dom '{target}'"
            )
            result = _run_command([str(powershell), "-NoProfile", "-Command", ps_command], timeout=timeout, cwd=browser_cwd)
            if result.returncode == 0 and (result.stdout or result.stderr):
                return result

    return _run_command([str(binary)] + base_flags, timeout=timeout, cwd=browser_cwd)


def check_tool(tool_name: str) -> int:
    paths = _resolve_binary_paths()

    if tool_name == "all":
        missing = [key for key in ("xray", "crawlergo", "browser") if not paths.get(key) or str(paths[key]) == ""]
        if missing:
            print(f"Missing Xray Suite binaries: {', '.join(missing)}")
            return 1
        print("Xray Suite binaries available: xray, crawlergo, headless-browser")
        return 0

    binary_key = TOOL_ALIASES.get(tool_name, tool_name)
    binary_path = paths.get(binary_key)
    if not binary_path or str(binary_path) == "":
        print(f"Missing binary for {tool_name}: {binary_key}")
        return 1

    print(f"OK: {tool_name} -> {binary_path}")
    return 0


def show_help(tool_name: str) -> int:
    paths = _resolve_binary_paths()

    if tool_name in ("xray-suite-webscan", "xray-webscan"):
        result = _run_command([str(paths["xray"]), "webscan", "-h"])
    elif tool_name in ("xray-suite-servicescan", "xray-servicescan"):
        result = _run_command([str(paths["xray"]), "servicescan", "-h"])
    elif tool_name in ("xray-suite-subdomain", "xray-subdomain"):
        result = _run_command([str(paths["xray"]), "subdomain", "-h"])
    elif tool_name in ("xray-suite-crawlergo", "crawlergo"):
        result = _run_command([str(paths["crawlergo"]), "-h"])
    elif tool_name in ("xray-suite-headless-browser", "headless-browser"):
        result = _run_browser(paths["browser"], "https://example.com")
    elif tool_name == "all":
        print("=== xray webscan ===")
        show_help("xray-webscan")
        print("\n=== xray servicescan ===")
        show_help("xray-servicescan")
        print("\n=== xray subdomain ===")
        show_help("xray-subdomain")
        print("\n=== crawlergo ===")
        show_help("crawlergo")
        print("\n=== headless-browser (dump-dom demo) ===")
        show_help("headless-browser")
        return 0
    else:
        print(f"Unknown help target: {tool_name}")
        return 1

    _print_result(result)
    return 0 if result.returncode == 0 else 1


def _xray_binary(paths: Dict[str, Path | str]) -> str:
    return str(paths["xray"])


def _target_slug(target: str) -> str:
    value = target.strip().lower()
    value = value.replace("https://", "").replace("http://", "")
    value = "".join(ch if ch.isalnum() else "_" for ch in value).strip("_")
    return value or "target"


def _new_output_file(prefix: str, target: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    target_dir = REPORTS_ROOT / _target_slug(target)
    target_dir.mkdir(parents=True, exist_ok=True)
    return target_dir / f"{prefix}_{stamp}.json"


def run_tool(tool_name: str, target: str) -> int:
    paths = _resolve_binary_paths()
    REPORTS_ROOT.mkdir(parents=True, exist_ok=True)

    normalized_web_target = _normalize_web_target(target)
    xray = _xray_binary(paths)

    if tool_name == "xray-suite-webscan":
        out_file = _new_output_file("xray_webscan", target)
        command = [xray, "--config", str(SUITE_CONFIG_PATH), "webscan", "--url", normalized_web_target, "--json-output", str(out_file)]
        result = _run_command(command, timeout=360)
    elif tool_name == "xray-suite-servicescan":
        out_file = _new_output_file("xray_servicescan", target)
        command = [xray, "--config", str(SUITE_CONFIG_PATH), "servicescan", "--target", target, "--json-output", str(out_file)]
        result = _run_command(command, timeout=360)
    elif tool_name == "xray-suite-subdomain":
        out_file = _new_output_file("xray_subdomain", target)
        command = [xray, "--config", str(SUITE_CONFIG_PATH), "subdomain", "--target", target, "--json-output", str(out_file)]
        result = _run_command(command, timeout=360)
    elif tool_name == "xray-suite-crawlergo":
        command = [str(paths["crawlergo"]), normalized_web_target]
        result = _run_command(command, timeout=300)
    elif tool_name == "xray-suite-headless-browser":
        result = _run_browser(paths["browser"], normalized_web_target, timeout=180)
    else:
        print(f"Unknown tool name: {tool_name}")
        return 1

    _print_result(result)
    return 0 if result.returncode == 0 else 1


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Xray Suite bridge utility")
    subparsers = parser.add_subparsers(dest="action", required=True)

    check_parser = subparsers.add_parser("check", help="Check binary availability")
    check_parser.add_argument("tool", help="Tool name or all")

    help_parser = subparsers.add_parser("help", help="Show tool help output")
    help_parser.add_argument("tool", help="Tool name or all")

    run_parser = subparsers.add_parser("run", help="Run a Xray Suite tool")
    run_parser.add_argument("tool", help="Tool name")
    run_parser.add_argument("target", help="Target URL/domain/IP")

    return parser.parse_args()


def main() -> int:
    args = _parse_args()

    if args.action == "check":
        return check_tool(args.tool)
    if args.action == "help":
        return show_help(args.tool)
    if args.action == "run":
        return run_tool(args.tool, args.target)

    print("Unknown action")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())