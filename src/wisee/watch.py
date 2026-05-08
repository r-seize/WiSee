"""
watch.py -- Continuous scan with change detection.
"""

import time
from typing import Callable, Optional

from rich.progress import Progress, BarColumn, TextColumn
from rich.rule import Rule

from .network import Device
from .display import console, C_BRAND, C_DIM, C_IP


def _by_mac(devices: list[Device]) -> dict[str, Device]:
    return {d.mac: d for d in devices}


def _print_watch_diff(
    prev: dict[str, Device],
    curr: dict[str, Device],
    iteration: int,
) -> None:
    new_macs     = set(curr) - set(prev)
    gone_macs    = set(prev) - set(curr)
    changed_macs: set[str] = set()

    for mac in set(prev) & set(curr):
        p           = prev[mac]
        c           = curr[mac]
        prev_ports  = {port.port for port in p.open_ports}
        curr_ports  = {port.port for port in c.open_ports}
        if prev_ports != curr_ports or p.device_name != c.device_name:
            changed_macs.add(mac)

    total = len(new_macs) + len(gone_macs) + len(changed_macs)
    console.print(Rule(
        f"[{C_BRAND}]Scan {iteration}  --  {total} change{'s' if total != 1 else ''}[/]",
        style="#2D3748",
    ))

    for mac in sorted(new_macs):
        d    = curr[mac]
        name = d.device_name or (d.hostname if d.hostname != "-" else None) or "-"
        console.print(f"  [bold green]    NEW[/]  [{C_IP}]{d.ip:<16}[/]  {mac}  {d.vendor or '-'}  ({name})")

    for mac in sorted(gone_macs):
        d    = prev[mac]
        name = d.device_name or (d.hostname if d.hostname != "-" else None) or "-"
        console.print(f"  [bold red]   GONE[/]  [{C_IP}]{d.ip:<16}[/]  {mac}  {d.vendor or '-'}  ({name})")

    for mac in sorted(changed_macs):
        c    = curr[mac]
        name = c.device_name or (c.hostname if c.hostname != "-" else None) or "-"
        console.print(f"  [bold yellow]CHANGED[/]  [{C_IP}]{c.ip:<16}[/]  {mac}  {c.vendor or '-'}  ({name})")

    if not total:
        console.print(f"  [{C_DIM}]No changes detected.[/]")

    console.print()


def _countdown(seconds: int) -> None:
    with Progress(
        TextColumn(f"[{C_DIM}]Next scan in[/]"),
        BarColumn(bar_width=30, style="#2D3748", complete_style="#00D4FF"),
        TextColumn("[dim]{task.description}[/dim]"),
        console=console,
        transient=True,
        expand=False,
    ) as progress:
        task = progress.add_task(f"{seconds}s", total=seconds)
        for elapsed in range(1, seconds + 1):
            remaining = seconds - elapsed
            progress.update(task, completed=elapsed, description=f"{remaining}s")
            time.sleep(1)


def watch_mode(
    scan_fn: Callable[[], list[Device]],
    interval: int = 30,
    count: int = 0,
) -> None:
    """
    Run scan_fn in a loop every `interval` seconds.
    Prints a diff after each scan (starting from the second).
    Stops after `count` scans if count > 0, otherwise runs until Ctrl+C.
    """
    previous: Optional[dict[str, Device]] = None
    iteration = 0

    try:
        while True:
            iteration += 1
            devices = scan_fn()
            current = _by_mac(devices)

            if previous is not None:
                _print_watch_diff(previous, current, iteration)

            previous = current

            if count > 0 and iteration >= count:
                break

            _countdown(interval)

    except KeyboardInterrupt:
        console.print(f"\n  [{C_BRAND}]Watch mode stopped.[/]\n")
