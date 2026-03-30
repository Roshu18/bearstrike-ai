"""Cross-platform profile detection for BearStrike."""

from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path
from typing import Any, Dict


def _read_os_release() -> Dict[str, str]:
    path = Path("/etc/os-release")
    data: Dict[str, str] = {}
    if not path.exists():
        return data
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return data

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip().lower()] = value.strip().strip('"')
    return data


def _is_wsl() -> bool:
    if os.getenv("WSL_DISTRO_NAME"):
        return True

    for path in ["/proc/version", "/proc/sys/kernel/osrelease"]:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="ignore").lower()
        except OSError:
            continue
        if "microsoft" in text or "wsl" in text:
            return True
    return False


def _python_command() -> str:
    if shutil.which("python3"):
        return "python3"
    if shutil.which("python"):
        return "python"
    return "python3"


def _package_manager(system_name: str, distro_id: str) -> str:
    if system_name == "Windows":
        if shutil.which("winget"):
            return "winget"
        if shutil.which("choco"):
            return "choco"
        if shutil.which("scoop"):
            return "scoop"
        return "manual"

    if system_name == "Darwin":
        return "brew" if shutil.which("brew") else "manual"

    if distro_id in {"kali", "ubuntu", "debian", "linuxmint", "parrot"}:
        return "apt"
    if distro_id in {"arch", "manjaro"}:
        return "pacman"
    if distro_id in {"fedora", "rhel", "rocky", "almalinux"}:
        return "dnf"
    if distro_id in {"opensuse", "sles"}:
        return "zypper"
    return "manual"


def get_platform_profile() -> Dict[str, Any]:
    system_name = platform.system() or "Unknown"
    release = platform.release() or ""
    machine = platform.machine() or ""

    os_release = _read_os_release() if system_name == "Linux" else {}
    distro_id = str(os_release.get("id", "")).lower()
    distro_like = str(os_release.get("id_like", "")).lower()
    distro_name = os_release.get("pretty_name") or distro_id or ""

    wsl_flag = _is_wsl() if system_name == "Linux" else False

    if wsl_flag:
        platform_kind = "WSL"
    elif system_name == "Windows":
        platform_kind = "Windows"
    elif system_name == "Linux" and distro_id == "kali":
        platform_kind = "Kali"
    elif system_name == "Linux":
        platform_kind = "Linux"
    elif system_name == "Darwin":
        platform_kind = "macOS"
    else:
        platform_kind = system_name

    profile = {
        "platform_kind": platform_kind,
        "system": system_name,
        "release": release,
        "machine": machine,
        "is_wsl": wsl_flag,
        "wsl_distro": os.getenv("WSL_DISTRO_NAME", "") if wsl_flag else "",
        "linux_distro": distro_name,
        "linux_id": distro_id,
        "linux_id_like": distro_like,
        "python_command": _python_command(),
        "package_manager": _package_manager(system_name, distro_id),
        "path_separator": os.pathsep,
    }
    return profile