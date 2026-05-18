#!/usr/bin/env python3
"""
WiSee - Local network discovery tool.

Usage:
  sudo $(which uv) run main.py scan
  sudo $(which uv) run main.py scan --nmap ports
  sudo $(which uv) run main.py scan --nmap os --fast-nmap
  sudo $(which uv) run main.py scan --export results.json
  uv run main.py interfaces
  uv run main.py profiles
"""

import sys
import json
import csv
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich import box

sys.path.insert(0, str(Path(__file__).parent / "src"))

from wisee import __version__
from wisee.core import run_scan
from wisee.scanner import PROFILES, nmap_available
from wisee.display import (
    print_banner, print_error, print_section,
    console, C_BRAND, C_IP, C_OS, C_DIM, C_HOST,
)

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"], max_content_width=110)


class WiSeeGroup(click.Group):
    def format_help(self, ctx, formatter):
        print_banner(__version__)
        super().format_help(ctx, formatter)


# ---------------------------------------------------------------------------
# CLI root
# ---------------------------------------------------------------------------

@click.group(cls=WiSeeGroup, context_settings=CONTEXT_SETTINGS)
@click.version_option(__version__, "-V", "--version", prog_name="WiSee")
def cli():
    """
    \b
    WiSee -- Local network discovery tool.

    Scans your LAN via ARP, enriches results with mDNS / NetBIOS / UPnP /
    banner grabbing, and optionally runs a deep nmap recon on each host.

    \b
    Quick start:
      sudo $(which uv) run main.py scan
      sudo $(which uv) run main.py scan --nmap ports
      sudo $(which uv) run main.py scan --nmap os --export report.json
    """


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--interface", "-i", default=None, metavar="IFACE",
              help="Network interface (e.g. eth0, wlan0). Auto-detected if omitted.")
@click.option("--fast", "-f", is_flag=True, default=False,
              help="Fast mode: reduced ARP timeout, enrichment disabled.")
@click.option("--no-enrich", is_flag=True, default=False,
              help="Disable enrichment phase (mDNS / NetBIOS / UPnP / banner).")
@click.option("--enrich-timeout", default=10.0, show_default=True, metavar="SECS",
              help="Time budget per device for enrichment.")
@click.option("--nmap", "nmap_profile", default=None, metavar="PROFILE",
              type=click.Choice(list(PROFILES.keys()), case_sensitive=False),
              help="Run nmap after ARP+enrichment. Profiles: " + ", ".join(PROFILES.keys()))
@click.option("--nmap-timeout", default=120, show_default=True, metavar="SECS",
              help="Per-host nmap timeout in seconds.")
@click.option("--no-banner", is_flag=True, default=False,
              help="Suppress the ASCII banner.")
@click.option("--quiet", "-q", is_flag=True, default=False,
              help="Quiet mode: only print the final table.")
@click.option("--export", "-e", default=None, metavar="FILE",
              type=click.Path(writable=True),
              help="Export results to JSON or CSV (auto-detected from extension).")
def scan(
    interface: Optional[str],
    fast: bool,
    no_enrich: bool,
    enrich_timeout: float,
    nmap_profile: Optional[str],
    nmap_timeout: int,
    no_banner: bool,
    quiet: bool,
    export: Optional[str],
):
    """
    Scan the local network.

    \b
    Phase 1  ARP broadcast       -- finds active hosts
    Phase 2  Enrichment          -- mDNS, NetBIOS, UPnP, HTTP/SSH banner
    Phase 3  Nmap deep scan      -- ports, services, OS  (--nmap <profile>)

    \b
    Requires raw-socket permissions:
      sudo $(which uv) run main.py scan
      # or once permanently:
      sudo setcap cap_net_raw+eip $(which python3)
    """
    if nmap_profile and not nmap_available():
        print_error(
            "nmap is not installed.\n"
            "  sudo apt install nmap    # Debian/Ubuntu\n"
            "  brew install nmap        # macOS"
        )
        sys.exit(1)

    devices = run_scan(
        interface           = interface,
        fast                = fast,
        no_banner           = no_banner,
        quiet               = quiet,
        enrich              = not no_enrich,
        enrich_timeout      = enrich_timeout,
        nmap_profile        = nmap_profile,
        nmap_timeout        = nmap_timeout,
    )

    if export and devices:
        _export_results(devices, export)

    sys.exit(0 if devices else 1)


# ---------------------------------------------------------------------------
# interfaces
# ---------------------------------------------------------------------------

@cli.command()
def interfaces():
    """List available network interfaces on this machine."""
    print_banner(__version__)

    try:
        from scapy.all import get_if_list, get_if_addr, get_if_hwaddr
    except ImportError:
        print_error("scapy is not installed.")
        sys.exit(1)

    ifaces = get_if_list()

    t = Table(
        title=f"[{C_BRAND}]Available network interfaces[/]",
        box=box.SIMPLE_HEAD,
        border_style="#2D3748",
        header_style=f"bold {C_BRAND}",
        padding=(0, 1),
        expand=False,
    )
    t.add_column("Interface", style=C_IP,       min_width=12)
    t.add_column("IP address", style="#68D391", min_width=15)
    t.add_column("MAC address", style="#B794F4", min_width=17)
    t.add_column("Status",     justify="center", width=8)

    for iface in ifaces:
        try:
            ip              = get_if_addr(iface) or "-"
            mac             = (get_if_hwaddr(iface) or "-").upper()
            status          = "up" if ip and ip != "0.0.0.0" else "down"
            status_str      = f"[green]{status}[/]" if status == "up" else f"[dim]{status}[/]"
        except Exception:
            ip, mac, status_str = "-", "-", "[dim]?[/]"
        t.add_row(iface, ip, mac, status_str)

    console.print()
    console.print(t)
    console.print()


# ---------------------------------------------------------------------------
# profiles
# ---------------------------------------------------------------------------

@cli.command()
def profiles():
    """List available nmap scan profiles."""
    print_banner(__version__)

    t = Table(
        title               = f"[{C_BRAND}]Nmap scan profiles[/]",
        box                 = box.SIMPLE_HEAD,
        border_style        = "#2D3748",
        header_style        = f"bold {C_BRAND}",
        padding             = (0, 1),
        expand              = False,
    )
    t.add_column("Profile",  style=C_OS,       min_width=10)
    t.add_column("Description", style="white", min_width=40)
    t.add_column("nmap args",   style="dim",   min_width=30)

    descriptions = {
        "quick":   "Top 100 TCP ports, no version detection. Fastest.",
        "ports":   "Top 500 TCP ports + service versions. Recommended.",
        "full":    "All 65535 TCP ports + service versions. Thorough.",
        "os":      "Top 500 ports + service + OS fingerprinting.",
        "stealth": "Top 200 ports, slow timing (T2). Less noisy.",
    }

    for name, cfg in PROFILES.items():
        args_str = " ".join(cfg["args"])
        t.add_row(name, descriptions.get(name, ""), args_str)

    console.print()
    console.print(t)
    console.print()
    console.print(
        f"  [dim]Usage example:  [/dim][{C_IP}]sudo $(which uv) run main.py scan --nmap ports[/]\n"
    )


# ---------------------------------------------------------------------------
# Export helper
# ---------------------------------------------------------------------------

def _export_results(devices, filepath: str) -> None:
    path = Path(filepath)
    ext  = path.suffix.lower()

    data = [
        {
            "ip":           d.ip,
            "mac":          d.mac,
            "vendor":       d.vendor,
            "hostname":     d.hostname,
            "device_name":  d.device_name,
            "device_detail":d.device_detail,
            "latency_ms":   d.latency_ms,
        }
        for d in devices
    ]

    if ext == ".csv":
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
    else:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    console.print(f"\n  [{C_BRAND}]Exported[/] {len(data)} records -> [{C_IP}]{path}[/]\n")


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()