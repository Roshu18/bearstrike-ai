"""Live terminal feed demo for BearStrike AI."""

from __future__ import annotations

import time
from collections import deque
from typing import Deque, List, Tuple

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

AI_COLOR = "bright_blue"
SUCCESS_COLOR = "bold green"
PROGRESS_COLOR = "bold yellow"
WARNING_COLOR = "bold red"

console = Console()


def _build_feed(entries: List[Tuple[str, str]]) -> Panel:
    table = Table(show_header=True, header_style="bold white", expand=True)
    table.add_column("Time", width=10)
    table.add_column("Event")

    for timestamp, message in entries:
        table.add_row(timestamp, message)

    return Panel(table, title="BearStrike Live Feed", border_style="cyan")


def demo_live_feed() -> None:
    """Show an animated stream of AI and tool events."""
    events = [
        f"[{AI_COLOR}][AI ->][/{AI_COLOR}] Target profiling started for example.com",
        f"[{PROGRESS_COLOR}][⟳][/{PROGRESS_COLOR}] Running nmap service scan",
        f"[{SUCCESS_COLOR}][✓][/{SUCCESS_COLOR}] Open ports identified: 80, 443",
        f"[{PROGRESS_COLOR}][⟳][/{PROGRESS_COLOR}] Launching ffuf content discovery",
        f"[{WARNING_COLOR}][!][/{WARNING_COLOR}] WAF signature detected on /login",
        f"[{AI_COLOR}][AI ->][/{AI_COLOR}] Switching to low-noise recon strategy",
        f"[{SUCCESS_COLOR}][✓][/{SUCCESS_COLOR}] Nuclei scan completed with 2 findings",
        f"[{PROGRESS_COLOR}][⟳][/{PROGRESS_COLOR}] Correlating evidence for report",
    ]

    feed: Deque[Tuple[str, str]] = deque(maxlen=8)

    with Live(_build_feed(list(feed)), refresh_per_second=8, console=console) as live:
        for idx, message in enumerate(events):
            timestamp = time.strftime("%H:%M:%S")
            feed.append((timestamp, message))
            live.update(_build_feed(list(feed)))
            time.sleep(0.9 if idx < len(events) - 1 else 0.4)


if __name__ == "__main__":
    demo_live_feed()
