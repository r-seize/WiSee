"""
core.py - Three-phase scan pipeline.

  Phase 1 : ARP broadcast   -> device list (+ TTL + MAC randomization)
  Phase 2 : Enrichment      -> mDNS / NetBIOS / UPnP / banner
  Phase 3 : Nmap deep scan  -> open ports / services / OS fingerprint (optional)
"""

import time
from typing import Optional

from .network import get_network_range, scan_arp, Device
from .enricher import enrich_all, EnrichmentResult
from .scanner import scan_hosts_parallel, nmap_available, PROFILES, NmapResult
from .display import (
    console,
    print_banner,
    print_scan_info,
    print_devices,
    print_nmap_summary,
    print_error,
    print_warning,
    print_section,
    make_progress,
    make_step_progress,
    make_enrichment_progress,
)
from . import __version__


def run_scan(
    interface: Optional[str]        = None,
    fast: bool                      = False,
    no_banner: bool                 = False,
    quiet: bool                     = False,
    enrich: bool                    = True,
    enrich_timeout: float           = 10.0,
    nmap_profile: Optional[str]     = None,
    nmap_timeout: int               = 120,
) -> list[Device]:
    """
    Full scan pipeline. Returns the list of discovered devices.

    nmap_profile: 'quick' | 'ports' | 'full' | 'os' | 'stealth' | None
    """
    if not no_banner:
        print_banner(__version__)

    try:
        network, local_ip, resolved_iface = get_network_range(interface)
    except (ValueError, RuntimeError) as exc:
        print_error(str(exc))
        return []

    arp_timeout = 1.0 if fast else 2.5

    if not quiet:
        profile_label = PROFILES[nmap_profile]["label"] if nmap_profile and nmap_profile in PROFILES else ""
        print_scan_info(
            interface   = resolved_iface,
            network     = network,
            local_ip    = local_ip,
            timeout     = arp_timeout,
            enrich      = enrich and not fast,
            profile     = profile_label,
        )

    start = time.perf_counter()

    # =========================================================================
    # Phase 1 - ARP  (+TTL, MAC randomization, vendor from vendors_db)
    # =========================================================================
    devices: list[Device]   = []
    phases                  = sum([1, enrich and not fast, bool(nmap_profile)])
    phase_label             = f"Phase 1/{phases} -- ARP scan..."

    p1          = make_progress(phase_label)
    p1_task     = p1.add_task("arp", total=None)

    try:
        with p1:
            try:
                devices = scan_arp(
                    network=network,
                    interface=resolved_iface,
                    timeout=arp_timeout,
                )
                p1.update(p1_task, completed=1, total=1)
            except PermissionError:
                print_error(
                    "Permission denied. Run with sudo or grant raw-socket rights:\n"
                    "  [dim cyan]sudo setcap cap_net_raw+eip $(which python3)[/dim cyan]"
                )
                return []
            except Exception as exc:
                print_error(str(exc))
                return []
    except KeyboardInterrupt:
        print_warning("Scan interrupted.")
        return []

    if not devices:
        if not quiet:
            print_devices([], time.perf_counter() - start)
        return []

    # =========================================================================
    # Phase 2 - Enrichment
    # =========================================================================
    if enrich and not fast:
        p2, p2_task = make_enrichment_progress(len(devices))

        def _on_enrich(done: int, total: int) -> None:
            p2.update(p2_task, completed=done)

        try:
            with p2:
                enrichments: dict[str, EnrichmentResult] = enrich_all(
                    ips                 = [d.ip for d in devices],
                    timeout_budget      = enrich_timeout,
                    progress_callback   = _on_enrich,
                )
        except KeyboardInterrupt:
            print_warning("Enrichment interrupted -- displaying partial results.")
            enrichments = {}

        for device in devices:
            r = enrichments.get(device.ip)
            if r:
                device.device_name   = r.best_name
                device.device_detail = r.detail

    arp_elapsed = time.perf_counter() - start

    # =========================================================================
    # Phase 3 - Nmap
    # =========================================================================
    nmap_results: dict[str, NmapResult] = {}

    if nmap_profile:
        if not nmap_available():
            print_warning(
                "nmap is not installed. Install it to enable deep scanning:\n"
                "  [dim cyan]sudo apt install nmap[/dim cyan]   # Debian/Ubuntu\n"
                "  [dim cyan]brew install nmap[/dim cyan]        # macOS"
            )
        else:
            p3, p3_task = make_step_progress(
                f"Phase 3/{phases} -- Nmap ({nmap_profile})...",
                total=len(devices),
                color="#F6AD55",
            )

            def _on_nmap(done: int, total: int) -> None:
                p3.update(p3_task, completed=done)

            try:
                with p3:
                    nmap_results = scan_hosts_parallel(
                        ips                 = [d.ip for d in devices],
                        profile             = nmap_profile,
                        timeout             = nmap_timeout,
                        progress_callback   = _on_nmap,
                    )
            except KeyboardInterrupt:
                print_warning("Nmap scan interrupted.")

            # Merge nmap results into Device objects
            for device in devices:
                r = nmap_results.get(device.ip)
                if r:
                    device.os_nmap      = r.os_name
                    device.os_accuracy  = r.os_accuracy
                    device.open_ports   = r.open_ports

    # =========================================================================
    # Device classification + risk scoring (skipped in fast mode)
    # =========================================================================
    if not fast:
        from .classifier import classify_device
        from .risk import score_device
        for device in devices:
            device.device_type             = classify_device(device)
            device.risk_score, device.risk_flags = score_device(device)

    # =========================================================================
    # Display - one final table with everything merged in
    # =========================================================================
    total_elapsed = time.perf_counter() - start

    if not quiet:
        print_devices(devices, total_elapsed)
        if nmap_results:
            print_nmap_summary(devices, nmap_results)

    return devices