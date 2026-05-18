#!/usr/bin/env python3
"""
wisee.cli - Click entry point.

Installed as the `wisee` command via pyproject.toml / setup.py.

Usage:
  wisee scan
  wisee scan --nmap ports
  wisee scan --nmap os --export report.json
  wisee interfaces
  wisee profiles
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

from wisee import __version__
from wisee.core import run_scan
from wisee.scanner import PROFILES, nmap_available
from wisee.display import (
    print_banner,
    print_error,
    print_risk_summary,
    print_diff_result,
    console,
    C_BRAND,
    C_IP,
    C_OS,
    C_DIM,
    C_HOST,
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
      sudo wisee scan
      sudo wisee scan --nmap ports
      sudo wisee scan --nmap os --export report.json
    """


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


@cli.command()
@click.option(
    "--interface", "-i", default  = None, metavar="IFACE",
    help                          = "Network interface (e.g. eth0, wlan0). Auto-detected if omitted.",
)
@click.option(
    "--fast", "-f", is_flag  = True, default=False,
    help                     = "Fast mode: reduced ARP timeout, enrichment disabled.",
)
@click.option(
    "--no-enrich", is_flag  = True, default=False,
    help                    = "Disable enrichment phase (mDNS / NetBIOS / UPnP / banner).",
)
@click.option(
    "--enrich-timeout", default  = 10.0, show_default=True, metavar="SECS",
    help                         = "Time budget per device for enrichment.",
)
@click.option(
    "--nmap", "nmap_profile", default  = None, metavar="PROFILE",
    type                               = click.Choice(list(PROFILES.keys()), case_sensitive=False),
    help                               = "Run nmap after ARP+enrichment. Profiles: " + ", ".join(PROFILES.keys()),
)
@click.option(
    "--nmap-timeout", default  = 120, show_default=True, metavar="SECS",
    help                       = "Per-host nmap timeout in seconds.",
)
@click.option(
    "--no-banner", is_flag  = True, default=False,
    help                    = "Suppress the ASCII banner.",
)
@click.option(
    "--quiet", "-q", is_flag  = True, default=False,
    help                      = "Quiet mode: only print the final table.",
)
@click.option(
    "--export", "-e", default  = None, metavar="FILE",
    type                       = click.Path(writable=True),
    help                       = "Export results to JSON or CSV (auto-detected from extension).",
)
@click.option(
    "--watch", "-w", is_flag  = True, default=False,
    help                      = "Continuous mode: re-scan every --interval seconds and report changes.",
)
@click.option(
    "--interval", default  = 30, show_default=True, metavar="SECS",
    help                   = "Seconds between scans in watch mode.",
)
@click.option(
    "--watch-count", default  = 0, show_default=True, metavar="N",
    help                      = "Stop after N scans in watch mode (0 = infinite).",
)
@click.option(
    "--show-risks", is_flag  = True, default=False,
    help                     = "Print a risk summary panel after the main table (devices with score > 20).",
)
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
    watch: bool,
    interval: int,
    watch_count: int,
    show_risks: bool,
):
    """
    Scan the local network.

    \b
    Phase 1  ARP broadcast       -- finds active hosts
    Phase 2  Enrichment          -- mDNS, NetBIOS, UPnP, HTTP/SSH banner
    Phase 3  Nmap deep scan      -- ports, services, OS  (--nmap <profile>)

    \b
    Requires raw-socket permissions:
      sudo wisee scan
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

    if watch:
        from wisee.watch import watch_mode
        print_banner(__version__)

        def _scan_fn():
            return run_scan(
                interface       = interface,
                fast            = fast,
                no_banner       = True,
                quiet           = quiet,
                enrich          = not no_enrich,
                enrich_timeout  = enrich_timeout,
                nmap_profile    = nmap_profile,
                nmap_timeout    = nmap_timeout,
            )

        watch_mode(_scan_fn, interval=interval, count=watch_count)
        return

    devices = run_scan(
        interface       = interface,
        fast            = fast,
        no_banner       = no_banner,
        quiet           = quiet,
        enrich          = not no_enrich,
        enrich_timeout  = enrich_timeout,
        nmap_profile    = nmap_profile,
        nmap_timeout    = nmap_timeout,
    )

    if show_risks and devices:
        print_risk_summary(devices)

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
        title         = f"[{C_BRAND}]Available network interfaces[/]",
        box           = box.SIMPLE_HEAD,
        border_style  = "#2D3748",
        header_style  = f"bold {C_BRAND}",
        padding       = (0, 1),
        expand        = False,
    )
    t.add_column("Interface",  style=C_IP,        min_width=12)
    t.add_column("IP address", style="#68D391",   min_width=15)
    t.add_column("MAC address", style="#B794F4",  min_width=17)
    t.add_column("Status",     justify="center",  width=8)

    for iface in ifaces:
        try:
            ip          = get_if_addr(iface) or "-"
            mac         = (get_if_hwaddr(iface) or "-").upper()
            status      = "up" if ip and ip != "0.0.0.0" else "down"
            status_str  = f"[green]{status}[/]" if status == "up" else f"[dim]{status}[/]"
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
        title         = f"[{C_BRAND}]Nmap scan profiles[/]",
        box           = box.SIMPLE_HEAD,
        border_style  = "#2D3748",
        header_style  = f"bold {C_BRAND}",
        padding       = (0, 1),
        expand        = False,
    )
    t.add_column("Profile",     style=C_OS,       min_width=10)
    t.add_column("Description", style="white",    min_width=40)
    t.add_column("nmap args",   style="dim",      min_width=30)

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
        f"  [dim]Usage example:  [/dim][{C_IP}]sudo wisee scan --nmap ports[/]\n"
    )


# ---------------------------------------------------------------------------
# Export helper
# ---------------------------------------------------------------------------


def _export_results(devices, filepath: str) -> None:
    path  = Path(filepath)
    ext   = path.suffix.lower()

    if ext == ".csv":
        rows = [
            {
                "ip":            d.ip,
                "mac":           d.mac,
                "vendor":        d.vendor,
                "hostname":      d.hostname,
                "device_name":   d.device_name,
                "device_detail": d.device_detail,
                "latency_ms":    d.latency_ms,
                "device_type":   d.device_type,
                "risk_score":    d.risk_score,
                "risk_flags":    " | ".join(d.risk_flags),
            }
            for d in devices
        ]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
    else:
        data = [
            {
                "ip":            d.ip,
                "mac":           d.mac,
                "vendor":        d.vendor,
                "hostname":      d.hostname,
                "device_name":   d.device_name,
                "device_detail": d.device_detail,
                "latency_ms":    d.latency_ms,
                "device_type":   d.device_type,
                "risk_score":    d.risk_score,
                "risk_flags":    d.risk_flags,
                "open_ports":    [
                    {"port": p.port, "protocol": p.protocol, "service": p.service}
                    for p in d.open_ports
                ],
            }
            for d in devices
        ]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    count = len(devices)
    console.print(f"\n  [{C_BRAND}]Exported[/] {count} records -> [{C_IP}]{path}[/]\n")


def _export_diff(result, filepath: str) -> None:
    path = Path(filepath)
    data = {
        "new_devices":     result.new_devices,
        "removed_devices": result.removed_devices,
        "changed_devices": [
            {
                "mac":     after.get("mac"),
                "before":  before,
                "after":   after,
                "changes": [
                    {"field": c.field, "before": c.before, "after": c.after}
                    for c in changes
                ],
            }
            for before, after, changes in result.changed_devices
        ],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    total = (
        len(result.new_devices)
        + len(result.removed_devices)
        + len(result.changed_devices)
    )
    console.print(f"\n  [{C_BRAND}]Exported[/] diff ({total} entries) -> [{C_IP}]{path}[/]\n")


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("scan_a", metavar="SCAN_A", type=click.Path(exists=True, readable=True))
@click.argument("scan_b", metavar="SCAN_B", type=click.Path(exists=True, readable=True))
@click.option(
    "--export", "-e", default  = None, metavar="FILE",
    type                       = click.Path(writable=True),
    help                       = "Export the diff report to JSON.",
)
def diff(scan_a: str, scan_b: str, export: Optional[str]):
    """
    Compare two exported JSON scan files and show what changed.

    \b
    Matches devices by MAC address across both scans and reports:
      - New devices    (present in SCAN_B but not SCAN_A)
      - Removed devices (present in SCAN_A but not SCAN_B)
      - Changed devices (IP / ports / name / vendor differ)

    \b
    Example:
      wisee diff morning.json evening.json
      wisee diff scan1.json scan2.json --export delta.json
    """
    from wisee.diff import load_scan, compute_diff

    try:
        data_a  = load_scan(scan_a)
        data_b  = load_scan(scan_b)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print_error(str(exc))
        sys.exit(1)

    result = compute_diff(data_a, data_b)
    print_diff_result(result, scan_a, scan_b)

    if export:
        _export_diff(result, export)

    sys.exit(0)


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()