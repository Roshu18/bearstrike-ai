"""Recon tool helpers for BearStrike AI."""

from __future__ import annotations

import sys
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[1] / "core"
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from tool_runner import run_tool  # noqa: E402


def run_recon(target: str) -> str:
    return run_tool("nmap", target)


if __name__ == "__main__":
    tgt = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    run_recon(tgt)
