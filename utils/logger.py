"""
FileAutopsy — Rich Logger
Color-coded output by severity level.
"""

from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel
from rich.text import Text
from rich import box

custom_theme = Theme({
    "info":     "cyan",
    "success":  "bold green",
    "warning":  "bold yellow",
    "critical": "bold red",
    "muted":    "dim white",
    "header":   "bold white",
    "label":    "bold blue",
    "value":    "white",
    "hash":     "dim cyan",
    "gps":      "bold magenta",
    "flag":     "bold red",
})

console = Console(theme=custom_theme)


def section(title: str, subtitle: str = ""):
    console.print()
    console.rule(f"[header]{title}[/header]", style="blue")
    if subtitle:
        console.print(f"  [muted]{subtitle}[/muted]")
    console.print()


def field(label: str, value, style: str = "value"):
    if value is None or value == "" or value == "N/A":
        console.print(f"  [label]{label:<28}[/label] [muted]—[/muted]")
    else:
        console.print(f"  [label]{label:<28}[/label] [{style}]{value}[/{style}]")


def flag(flag_name: str, message: str, level: str = "warning"):
    icons = {"info": "ℹ", "warning": "⚠", "critical": "✖"}
    icon = icons.get(level, "•")
    console.print(f"  [{level}]{icon} [{flag_name}][/{level}] [muted]{message}[/muted]")


def success(msg: str):
    console.print(f"  [success]✔ {msg}[/success]")


def info(msg: str):
    console.print(f"  [info]• {msg}[/info]")


def warning(msg: str):
    console.print(f"  [warning]⚠ {msg}[/warning]")


def critical(msg: str):
    console.print(f"  [critical]✖ {msg}[/critical]")


def banner():
    art = Text()
    art.append("  █████╗ ██╗   ██╗███████╗\n", style="bold blue")
    art.append(" ██╔══██╗██║   ██║██╔════╝\n", style="bold blue")
    art.append(" ███████║██║   ██║███████╗\n", style="bold cyan")
    art.append(" ██╔══██║╚██╗ ██╔╝╚════██║\n", style="bold cyan")
    art.append(" ██║  ██║ ╚████╔╝ ███████║\n", style="bold white")
    art.append(" ╚═╝  ╚═╝  ╚═══╝  ╚══════╝\n", style="bold white")
    art.append("  ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗\n", style="blue")
    art.append("  ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝\n", style="blue")
    art.append("  █████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗\n", style="cyan")
    art.append("  ██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║\n", style="cyan")
    art.append("  ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║\n", style="white")
    art.append("  ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝\n", style="white")
    art.append("\n  by Antony Vera Sanchez\n", style="dim cyan")

    console.print(Panel(
        art,
        subtitle="[muted]Digital Forensics Metadata Analyzer[/muted]",
        border_style="blue",
        box=box.DOUBLE_EDGE,
        padding=(0, 2),
    ))
    console.print()


def result_panel(title: str, content: str, level: str = "info"):
    styles = {"info": "blue", "warning": "yellow", "critical": "red", "success": "green"}
    console.print(Panel(content, title=title, border_style=styles.get(level, "blue")))
