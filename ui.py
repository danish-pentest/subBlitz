#!/usr/bin/env python3
"""
subBlitz - Stylish terminal UI helpers.
"""
import time
from rich.console import Console
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.align import Align
from rich.theme import Theme

# ── Custom theme ─────────────────────────────────────────────
THEME = Theme({
    "brand":      "bold cyan",
    "accent":     "bold magenta",
    "success":    "bold green",
    "warning":    "bold yellow",
    "error":      "bold red",
    "muted":      "dim white",
    "engine":     "bold #7aa2f7",
    "subdomain":  "#9ece6a",
})

console = Console(theme=THEME, highlight=False)


BANNER = r"""


███████╗██╗   ██╗██████╗ ██████╗ ██╗     ██╗████████╗███████╗
██╔════╝██║   ██║██╔══██╗██╔══██╗██║     ██║╚══██╔══╝╚══███╔╝
███████╗██║   ██║██████╔╝██████╔╝██║     ██║   ██║     ███╔╝
╚════██║██║   ██║██╔══██╗██╔══██╗██║     ██║   ██║    ███╔╝
███████║╚██████╔╝██████╔╝██████╔╝███████╗██║   ██║   ███████╗
╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝   ╚══════╝
"""


def show_banner(version: str = "1.0") -> None:
    """Print the animated banner."""
    for line in BANNER.strip("\n").split("\n"):
        console.print(f"[brand]{line}[/brand]")
        time.sleep(0.03)

    tagline = Text()
    tagline.append("  Fast.  ", style="muted")
    tagline.append("•  ", style="accent")
    tagline.append("Multi-source.  ", style="muted")
    tagline.append("•  ", style="accent")
    tagline.append("Subdomain Recon.\n", style="muted")

    console.print(tagline)
    console.print(
        f"  [muted]v{version}[/muted]  [dim]│[/dim]  "
        f"[accent]github.com/danish-pentest/subBlitz[/accent]\n"
    )


def section(title: str) -> None:
    console.print()
    console.rule(f"[accent]{title}[/accent]", style="dim")
    console.print()


def info(msg: str) -> None:
    console.print(f"[brand][/brand]  {msg}")


def success(msg: str) -> None:
    console.print(f"[success]✔[/success]  {msg}")


def warn(msg: str) -> None:
    console.print(f"[warning]⚠[/warning]  {msg}")


def error(msg: str) -> None:
    console.print(f"[error]✘[/error]  {msg}")


def engine_status(engine: str, status: str) -> None:
    icons = {
        "start":  "[engine]⟳[/engine]",
        "ok":     "[success]✓[/success]",
        "empty":  "[muted]○[/muted]",
        "fail":   "[error]✗[/error]",
    }
    icon = icons.get(status, "•")
    console.print(f"  {icon}  [engine]{engine:<16}[/engine] [muted]{status}[/muted]")


def subdomain_found(engine: str, subdomain: str) -> None:
    console.print(
        f"  [success]└─▶[/success]  [subdomain]{subdomain}[/subdomain]  "
        f"[muted](via {engine})[/muted]"
    )


def summary_table(subdomains: list[str], engine_counts: dict) -> None:
    console.print()
    console.rule("[accent]Summary[/accent]", style="dim")
    console.print()

    stats = Table.grid(padding=(0, 2))
    stats.add_column(style="muted")
    stats.add_column(style="bold white")
    stats.add_row("Total subdomains", f"[success]{len(subdomains)}[/success]")
    stats.add_row("Engines used", f"[accent]{len(engine_counts)}[/accent]")
    console.print(Align.left(stats))

    if engine_counts:
        console.print()
        tbl = Table(
            title="Contributions",
            title_style="accent",
            border_style="dim",
            header_style="bold white",
            show_lines=False,
        )
        tbl.add_column("Engine", style="engine")
        tbl.add_column("Found", justify="right", style="success")
        for eng, cnt in sorted(engine_counts.items(), key=lambda x: -x[1]):
            tbl.add_row(eng, str(cnt))
        console.print(Align.left(tbl))
    console.print()


def make_progress() -> Progress:
    """Return a styled progress bar for enumeration."""
    return Progress(
        SpinnerColumn(style="accent"),
        TextColumn("[brand]{task.description}[/brand]"),
        BarColumn(bar_width=40, style="dim", complete_style="accent"),
        TextColumn("[muted]{task.completed}/{task.total}[/muted]"),
        console=console,
        transient=False,
    )
