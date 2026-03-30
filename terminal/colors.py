"""Color constants for BearStrike AI terminal UI."""

from rich.console import Console

# Brand palette: fiery orange/yellow with cyber-green accents.
BANNER_COLOR = "bold #ff8c00"
AI_MESSAGE_COLOR = "bold #33d1ff"
SUCCESS_COLOR = "bold #28d17c"
WARNING_COLOR = "bold #ffc857"
ERROR_COLOR = "bold #ff5c5c"

# Optional helpers for gradient-style wordmarks.
BRAND_GRADIENT = ("#ff2d2d", "#ff5a00", "#ff8a00", "#ffb000", "#ffd447")


if __name__ == "__main__":
    console = Console()
    console.print("[BearStrike Banner Sample]", style=BANNER_COLOR)
    console.print("[AI] Recon module initialized.", style=AI_MESSAGE_COLOR)
    console.print("[SUCCESS] Scan completed.", style=SUCCESS_COLOR)
    console.print("[WARNING] WAF detected on target.", style=WARNING_COLOR)
    console.print("[ERROR] Exploit module failed.", style=ERROR_COLOR)