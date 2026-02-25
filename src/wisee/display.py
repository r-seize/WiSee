"""
display.py — All Rich rendering.

Responsive: adapts columns to terminal width.
No emoji. English only.

Column layout by terminal width:
  < 90  (narrow) : #  IP  Name  Vendor  Latency
  90-129 (medium) : + MAC  TTL  OS
  130+   (wide)   : + Ports  Detail
"""

import shutil
from typing import Optional, TYPE_CHECKING

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.rule import Rule
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
    MofNCompleteColumn,
)
from rich import box

if TYPE_CHECKING:
    from .network import Device
    from .scanner import NmapResult

console = Console()

# ---------------------------------------------------------------------------
# Palette
# ---------------------------------------------------------------------------
C_BRAND    = "bold #00D4FF"
C_DIM      = "#4A5568"
C_IP       = "#63B3ED"
C_MAC      = "#B794F4"
C_VENDOR   = "#68D391"
C_RAND     = "#FC8181"          # randomized MAC
C_HOST     = "#FBD38D"
C_LATENCY  = "#A0AEC0"
C_TTL      = "#76E4F7"
C_OS       = "#F6AD55"
C_PORT_O   = "#68D391"
C_SERVICE  = "#76E4F7"
C_ERR      = "bold red"
C_WARN     = "bold yellow"
C_OK       = "bold green"

BANNER = r"""
 ██╗    ██╗██╗███████╗███████╗███████╗
 ██║    ██║██║██╔════╝██╔════╝██╔════╝
 ██║ █╗ ██║██║███████╗█████╗  █████╗
 ██║███╗██║██║╚════██║██╔══╝  ██╔══╝
 ╚███╔███╔╝██║███████║███████╗███████╗
  ╚══╝╚══╝ ╚═╝╚══════╝╚══════╝╚══════╝"""


# ---------------------------------------------------------------------------
# Terminal width helpers
# ---------------------------------------------------------------------------

def _term_width() -> int:
    return shutil.get_terminal_size((100, 40)).columns

def _is_wide() -> bool:
    return _term_width() >= 130

def _is_medium() -> bool:
    return _term_width() >= 90


# ---------------------------------------------------------------------------
# Banner & config panel
# ---------------------------------------------------------------------------

def print_banner(version: str = "0.1.0") -> None:
    console.print(Align.center(Text(BANNER, style="bold #00D4FF")))
    console.print(Align.center(Text(
        f"  Network discovery tool  |  v{version}  |  WiSee by r-seize\n",
        style="dim #00D4FF", justify="center",
    )))
    console.print(Rule(style=C_DIM))
    console.print()


def print_scan_info(
    interface: str,
    network: str,
    local_ip: str,
    timeout: float,
    enrich: bool = True,
    profile: str = "",
) -> None:
    lines = [
        f"  [dim]Interface  :[/dim]  [{C_IP}]{interface}[/]",
        f"  [dim]Network    :[/dim]  [{C_IP}]{network}[/]",
        f"  [dim]Local IP   :[/dim]  [{C_IP}]{local_ip}[/]",
        f"  [dim]ARP timeout:[/dim]  [{C_HOST}]{timeout}s[/]",
    ]
    if enrich:
        lines.append(f"  [dim]Enrichment :[/dim]  [{C_VENDOR}]mDNS / NetBIOS / UPnP / Banner[/]")
    if profile:
        lines.append(f"  [dim]Nmap profile:[/dim]  [{C_OS}]{profile}[/]")

    console.print(Panel(
        "\n".join(lines),
        title=f"[{C_BRAND}]Configuration[/]",
        border_style="#2D3748",
        padding=(0, 1),
    ))
    console.print()


# ---------------------------------------------------------------------------
# Progress bars
# ---------------------------------------------------------------------------

def make_progress(label: str = "ARP scan...") -> Progress:
    return Progress(
        SpinnerColumn("dots", style=C_BRAND),
        TextColumn(f"[dim]{label}[/dim]"),
        BarColumn(bar_width=None, style="#2D3748", complete_style="#00D4FF"),
        TimeElapsedColumn(),
        console=console, transient=True, expand=True,
    )


def make_step_progress(label: str, total: int, color: str = "#B794F4") -> tuple:
    p = Progress(
        SpinnerColumn("dots2", style=color),
        TextColumn(f"[dim]{label}[/dim]"),
        BarColumn(bar_width=None, style="#2D3748", complete_style=color),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console, transient=True, expand=True,
    )
    task = p.add_task(label, total=total)
    return p, task


def make_enrichment_progress(total: int) -> tuple:
    return make_step_progress("Phase 2/3 -- Enrichment...", total, "#B794F4")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _best_name(d: "Device") -> str:
    if d.device_name:
        return d.device_name
    if d.hostname and d.hostname != "-":
        return d.hostname
    return "-"


def _vendor_str(d: "Device") -> str:
    """Return vendor string, flagging randomized MACs clearly."""
    if d.mac_randomized:
        return f"[{C_RAND}]Randomized[/]"
    v = d.vendor if isinstance(d.vendor, str) else str(d.vendor)
    return v or "Unknown"


def _os_str(d: "Device") -> str:
    """Best OS guess: nmap first, TTL heuristic fallback."""
    if d.os_nmap:
        acc = f" ({d.os_accuracy}%)" if d.os_accuracy else ""
        return f"{d.os_nmap}{acc}"
    if d.os_ttl:
        return f"{d.os_ttl} [dim](TTL)[/dim]"
    return "-"


def _ports_str(d: "Device") -> str:
    """Compact open ports list from nmap results."""
    if not d.open_ports:
        return "-"
    parts = []
    for p in sorted(d.open_ports, key=lambda x: x.port)[:6]:  # max 6 in summary
        svc = f"/{p.service}" if p.service else ""
        parts.append(f"[{C_PORT_O}]{p.port}[/][dim]{svc}[/]")
    suffix = f"  [dim]+{len(d.open_ports) - 6} more[/]" if len(d.open_ports) > 6 else ""
    return "  ".join(parts) + suffix


# ---------------------------------------------------------------------------
# Main device table
# ---------------------------------------------------------------------------

def print_devices(devices: list["Device"], elapsed: float) -> None:
    if not devices:
        console.print(Panel(
            "[bold yellow]No devices detected.[/]\n"
            "[dim]Check your interface, or use --fast to reduce timeout.[/]",
            border_style="yellow", padding=(1, 2),
        ))
        return

    wide   = _is_wide()
    medium = _is_medium()
    count  = len(devices)
    s      = "s" if count != 1 else ""

    table = Table(
        title=f"[{C_BRAND}]Local network  --  {count} device{s} detected[/]",
        box=box.SIMPLE_HEAD,
        border_style="#2D3748",
        header_style=f"bold {C_BRAND}",
        show_lines=False,
        padding=(0, 1),
        expand=True,
    )

    # Always present
    table.add_column("#",        style="dim white",   width=3,  justify="right", no_wrap=True)
    table.add_column("IP",       style=C_IP,           width=15, no_wrap=True)
    table.add_column("Name",     style=C_HOST,          min_width=14, ratio=3)
    table.add_column("Vendor",   min_width=12,          ratio=3)

    # Medium+
    if medium:
        table.add_column("MAC",  style=C_MAC,           width=17, no_wrap=True)
        table.add_column("TTL",  style=C_TTL,           width=5,  justify="right", no_wrap=True)
        table.add_column("OS",   style=C_OS,             min_width=20, ratio=2)

    # Wide only
    if wide:
        table.add_column("Ports", min_width=16,          ratio=3)

    table.add_column("Latency",  style=C_LATENCY,       width=10, justify="right", no_wrap=True)

    for idx, d in enumerate(devices, start=1):
        lat  = f"{d.latency_ms} ms" if d.latency_ms is not None else "-"
        row  = [
            str(idx),
            d.ip,
            _best_name(d),
            _vendor_str(d),
        ]
        if medium:
            row.append(d.mac)
            row.append(str(d.ttl) if d.ttl is not None else "-")
            row.append(_os_str(d))
        if wide:
            row.append(_ports_str(d))
        row.append(lat)
        table.add_row(*row)

    console.print()
    console.print(table)
    console.print()
    console.print(Rule(
        f"[dim]Completed in [bold]{elapsed:.2f}s[/]  |  {count} active host{s}[/dim]",
        style=C_DIM,
    ))
    console.print()


# ---------------------------------------------------------------------------
# Nmap single-host detail panel
# ---------------------------------------------------------------------------

def print_nmap_result(result: "NmapResult") -> None:
    wide   = _is_wide()
    medium = _is_medium()

    if result.error and not result.open_ports:
        console.print(f"  [{C_ERR}]nmap error on {result.ip}: {result.error}[/]")
        return

    os_str   = f"  |  OS: [{C_OS}]{result.os_name}[/] ({result.os_accuracy}%)" if result.os_name else ""
    host_str = f"  [{C_HOST}]{result.hostname}[/]" if result.hostname else ""
    np       = len(result.open_ports)

    console.print(Rule(
        f"[{C_IP}]{result.ip}[/]{host_str}  |  "
        f"[{C_PORT_O}]{np} open port{'s' if np != 1 else ''}[/]{os_str}",
        style="#2D3748",
    ))

    if not result.open_ports:
        console.print("  [dim]No open ports found.[/]\n")
        return

    t = Table(
        box=box.SIMPLE, border_style="#2D3748",
        header_style=f"bold {C_BRAND}",
        show_lines=False, padding=(0, 1), expand=False,
    )
    t.add_column("Port",    style=C_PORT_O,  width=7,  justify="right", no_wrap=True)
    t.add_column("Proto",   style="dim",      width=5,  no_wrap=True)
    t.add_column("Service", style=C_SERVICE,  min_width=10)
    if medium:
        t.add_column("Product", style="white",    min_width=16, ratio=2)
    if wide:
        t.add_column("Version", style="dim white", min_width=10, ratio=1)

    for p in sorted(result.open_ports, key=lambda x: x.port):
        row = [str(p.port), p.protocol, p.service or "-"]
        if medium:
            row.append(p.product or "-")
        if wide:
            v = p.version
            if p.extra_info:
                v = f"{v} ({p.extra_info})" if v else p.extra_info
            row.append(v or "-")
        t.add_row(*row)

    console.print(t)
    console.print()


# ---------------------------------------------------------------------------
# Nmap summary across all hosts
# ---------------------------------------------------------------------------

def print_nmap_summary(
    devices: list["Device"],
    nmap_results: dict,
) -> None:
    wide   = _is_wide()
    medium = _is_medium()

    count = sum(1 for d in devices if nmap_results.get(d.ip) and nmap_results[d.ip].open_ports)

    console.print()
    console.print(Rule(
        f"[{C_BRAND}]Nmap results  --  {count} host{'s' if count != 1 else ''} with open ports[/]",
        style="#2D3748",
    ))
    console.print()

    t = Table(
        box=box.SIMPLE_HEAD, border_style="#2D3748",
        header_style=f"bold {C_BRAND}",
        show_lines=False, padding=(0, 1), expand=True,
    )
    t.add_column("IP",         style=C_IP,    width=15, no_wrap=True)
    if medium:
        t.add_column("Name",   style=C_HOST,  min_width=14, ratio=2)
    t.add_column("Open ports", min_width=10,  ratio=3)
    if wide:
        t.add_column("OS",     style=C_OS,    min_width=16, ratio=2)

    for d in devices:
        r = nmap_results.get(d.ip)
        if not r:
            continue
        ports_str = "  ".join(
            f"[{C_PORT_O}]{p.port}[/][dim]/{p.service or p.protocol}[/]"
            for p in sorted(r.open_ports, key=lambda x: x.port)
        ) or "[dim]-[/]"
        row = [d.ip]
        if medium:
            row.append(_best_name(d))
        row.append(ports_str)
        if wide:
            row.append(f"{r.os_name[:32]} ({r.os_accuracy}%)" if r.os_name else "-")
        t.add_row(*row)

    console.print(t)
    console.print()

    for d in devices:
        r = nmap_results.get(d.ip)
        if r and r.open_ports:
            # Push nmap OS + ports back into Device for the main table
            d.os_nmap       = r.os_name
            d.os_accuracy   = r.os_accuracy
            d.open_ports    = r.open_ports
            print_nmap_result(r)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def print_error(message: str) -> None:
    console.print(f"\n  [{C_ERR}]Error:[/]  {message}\n")

def print_warning(message: str) -> None:
    console.print(f"\n  [{C_WARN}]Warning:[/]  {message}\n")

def print_success(message: str) -> None:
    console.print(f"\n  [{C_OK}]Done:[/]  {message}\n")

def print_section(title: str) -> None:
    console.print(Rule(f"[{C_BRAND}]{title}[/]", style="#2D3748"))
    console.print()