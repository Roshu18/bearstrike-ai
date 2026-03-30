"""Rich terminal display components for BearStrike AI."""

from __future__ import annotations

import re
from datetime import datetime

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.markup import escape
from rich.panel import Panel
from rich.progress_bar import ProgressBar
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from colors import AI_MESSAGE_COLOR, BANNER_COLOR, BRAND_GRADIENT, ERROR_COLOR, SUCCESS_COLOR, WARNING_COLOR

console = Console()


def _gradient_text(value: str, palette: tuple[str, ...] = BRAND_GRADIENT) -> Text:
    text = Text()
    if not value:
        return text
    colors = tuple(palette) if palette else ("#ff8c00",)
    bucket = max(1, len(value) // max(1, len(colors)))
    for idx, ch in enumerate(value):
        color = colors[min(len(colors) - 1, idx // bucket)]
        text.append(ch, style=f"bold {color}")
    return text


def _brand_wordmark() -> Group:
    line1 = _gradient_text("BEARSTRIKE AI")
    line2 = Text("HIGH-SIGNAL PENTESTING CONSOLE", style="bold #ffd447")
    line3 = Text("MCP-FIRST | LOW-LATENCY | SKILLS-DRIVEN", style="bold #33d1ff")
    return Group(Align.center(line1), Align.center(line2), Align.center(line3))


def _single_line(value: str, limit: int = 120) -> str:
    text = " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split())
    if not text:
        return "none"
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _status_markup(status: str) -> str:
    normalized = str(status or "idle").strip().lower()
    color = AI_MESSAGE_COLOR

    if normalized in {"success", "completed"}:
        color = SUCCESS_COLOR
    elif normalized in {"failed", "error"}:
        color = ERROR_COLOR
    elif normalized in {"blocked", "warning"}:
        color = WARNING_COLOR

    return f"[{color}]{escape(_single_line(status or 'idle', 32))}[/{color}]"


def _parse_progress_fraction(progress: str) -> tuple[int, int] | None:
    match = re.search(r"(\d+)\s*/\s*(\d+)", str(progress or ""))
    if not match:
        return None

    done = int(match.group(1))
    total = int(match.group(2))
    if total <= 0:
        return None
    return max(0, done), total


def _progress_renderable(progress: str, status: str):
    normalized_status = str(status or "idle").strip().lower()
    parsed = _parse_progress_fraction(progress)

    if parsed is not None:
        done, total = parsed
        done = min(done, total)

        style = SUCCESS_COLOR
        if normalized_status in {"failed", "error", "blocked"}:
            style = ERROR_COLOR if normalized_status in {"failed", "error"} else WARNING_COLOR
        elif normalized_status in {"running"}:
            style = AI_MESSAGE_COLOR

        bar = ProgressBar(total=total, completed=done, width=42, complete_style=style, finished_style=SUCCESS_COLOR)
        label = Text(_single_line(progress, 72), style="white")
        return Group(label, bar)

    if normalized_status == "running":
        return Spinner("dots", text=_single_line(progress or "running", 72), style=AI_MESSAGE_COLOR)

    return Text(_single_line(progress or "idle", 72), style="white")


def _events_renderable(events: list[dict]) -> Panel:
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Time", width=9, style="bold white")
    table.add_column("Tool", width=14, style="white")
    table.add_column("Status", width=10, style="white")
    table.add_column("Preview", style="white")

    latest = sorted(events, key=lambda e: e.get("timestamp", 0), reverse=True)[:4]
    for ev in latest:
        ts = ev.get("timestamp", 0)
        try:
            ts_str = datetime.fromtimestamp(float(ts)).strftime("%H:%M:%S")
        except Exception:
            ts_str = "--:--:--"
        table.add_row(
            ts_str,
            escape(_single_line(ev.get("tool", ""), 14)),
            escape(_single_line(ev.get("status", ""), 10)),
            escape(_single_line(ev.get("preview", ""), 80)),
        )

    return Panel(table, title="MCP Events", border_style=AI_MESSAGE_COLOR, padding=(0, 1))


def build_banner_renderable(
    target: str = "not-set",
    waf_status: str = "Unknown",
    ai_model: str = "not-configured",
    current_task: str = "idle",
    target_output_dir: str = "",
    dashboard_url: str = "",
    mcp_url: str = "",
    last_mcp_tool: str = "",
    last_mcp_target: str = "",
    last_mcp_command: str = "",
    last_mcp_status: str = "idle",
    last_mcp_progress: str = "",
    last_mcp_response_preview: str = "",
    mcp_events: list[dict] | None = None,
):
    static_subtitle = Text(
        "MODEL-AGNOSTIC MCP SECURITY WORKFLOW",
        style="bold #ffb000",
    )

    header = Panel(
        Group(_brand_wordmark(), Align.center(static_subtitle)),
        box=box.HEAVY,
        border_style=BANNER_COLOR,
        padding=(1, 2),
    )

    info_table = Table(box=box.SIMPLE_HEAVY, expand=True)
    info_table.add_column("Field", style="bold white", width=20)
    info_table.add_column("Value", style="white")
    info_table.add_row("Current Target", escape(_single_line(target, 100)))
    info_table.add_row("WAF Status", f"[{WARNING_COLOR}]{escape(_single_line(waf_status, 120))}[/{WARNING_COLOR}]")
    info_table.add_row("AI Model", f"[{SUCCESS_COLOR}]{escape(_single_line(ai_model, 120))}[/{SUCCESS_COLOR}]")
    info_table.add_row("Current Task", escape(_single_line(current_task, 120)))
    info_table.add_row("Target Folder", escape(_single_line(target_output_dir or "not-created-yet", 140)))
    info_table.add_row("Dashboard URL", escape(_single_line(dashboard_url or "not-started", 120)))
    info_table.add_row("MCP URL", escape(_single_line(mcp_url or "not-started", 120)))
    info_table.add_row("Last MCP Tool", escape(_single_line(last_mcp_tool, 80)))
    info_table.add_row("Last MCP Target", escape(_single_line(last_mcp_target, 80)))
    info_table.add_row("Last Command", escape(_single_line(last_mcp_command, 140)))
    info_table.add_row("MCP Status", _status_markup(last_mcp_status))
    info_table.add_row("MCP Progress", _progress_renderable(last_mcp_progress, last_mcp_status))
    info_table.add_row("Last Response", escape(_single_line(last_mcp_response_preview, 180)))

    renderables = [header, info_table]
    if mcp_events:
        renderables.append(_events_renderable(mcp_events))

    return Group(*renderables)


def show_banner(
    target: str = "not-set",
    waf_status: str = "Unknown",
    ai_model: str = "not-configured",
    current_task: str = "idle",
    target_output_dir: str = "",
    dashboard_url: str = "",
    mcp_url: str = "",
    last_mcp_tool: str = "",
    last_mcp_target: str = "",
    last_mcp_command: str = "",
    last_mcp_status: str = "idle",
    last_mcp_progress: str = "",
    last_mcp_response_preview: str = "",
    mcp_events: list[dict] | None = None,
    clear_screen: bool = False,
) -> None:
    if clear_screen:
        console.clear()

    console.print(
        build_banner_renderable(
            target=target,
            waf_status=waf_status,
            ai_model=ai_model,
            current_task=current_task,
            target_output_dir=target_output_dir,
            dashboard_url=dashboard_url,
            mcp_url=mcp_url,
            last_mcp_tool=last_mcp_tool,
            last_mcp_target=last_mcp_target,
            last_mcp_command=last_mcp_command,
            last_mcp_status=last_mcp_status,
            last_mcp_progress=last_mcp_progress,
            last_mcp_response_preview=last_mcp_response_preview,
            mcp_events=mcp_events or [],
        )
    )


class BannerLive:
    def __init__(self) -> None:
        self._live: Live | None = None

    def start(self, **kwargs) -> None:
        if self._live is not None:
            return
        renderable = build_banner_renderable(**kwargs)
        self._live = Live(
            renderable,
            console=console,
            refresh_per_second=8,
            auto_refresh=False,
            transient=False,
            screen=False,
        )
        self._live.start()

    def update(self, **kwargs) -> None:
        if self._live is None:
            self.start(**kwargs)
            return
        self._live.update(build_banner_renderable(**kwargs), refresh=True)

    def stop(self) -> None:
        if self._live is None:
            return
        try:
            self._live.stop()
        except KeyboardInterrupt:
            # Ctrl+C during shutdown can interrupt Rich final refresh.
            pass
        except Exception:
            # Never let terminal UI teardown crash main shutdown flow.
            pass
        self._live = None


if __name__ == "__main__":
    show_banner(clear_screen=True)
