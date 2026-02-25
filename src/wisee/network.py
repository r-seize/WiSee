"""
network.py — ARP scanning, TTL capture, and network helpers.
"""

import socket
import ipaddress
import subprocess
import re
from dataclasses import dataclass, field
from typing import Optional
import concurrent.futures
import ipaddress
from typing import Optional
from scapy.all import ARP, Ether, IP, ICMP, srp, sr1, conf, get_if_list, get_if_addr  # type: ignore


# ---------------------------------------------------------------------------
# TTL-based OS heuristic
# ---------------------------------------------------------------------------

def _guess_os_from_ttl(ttl: int) -> str:
    """
    Rough OS family inference from IP TTL.
    Initial TTL values by OS:
      255 : Cisco IOS, routers, some Unix
      128 : Windows
       64 : Linux, Android, macOS, iOS
       32 : older Windows (rare)
    We receive the TTL after N hops, so we round up to the nearest known value.
    """
    if ttl >= 200:
        return "Router / Network device"
    elif ttl >= 100:
        return "Windows"
    elif ttl >= 50:
        return "Linux / Android / macOS"
    else:
        return "Unknown"


# ---------------------------------------------------------------------------
# Device dataclass
# ---------------------------------------------------------------------------

@dataclass
class Device:
    ip:             str
    mac:            str
    hostname:       str
    vendor:         str
    mac_randomized: bool                = False
    latency_ms:     Optional[float]     = None   # plain float, never Decimal
    ttl:            Optional[int]       = None
    os_ttl:         str                 = ""       # heuristic from TTL
    device_name:    Optional[str]       = None
    device_detail:  Optional[str]       = None
    os_nmap:        str                 = ""
    os_accuracy:    int                 = 0
    open_ports:     list                = field(default_factory=list)  # list[PortInfo]


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def get_default_interface() -> str:
    try:
        iface = str(conf.iface)
        if iface and iface != "lo":
            return iface
    except Exception:
        pass

    for iface in get_if_list():
        if "lo" not in iface:
            ip = get_if_addr(iface)
            if ip and ip != "0.0.0.0":
                return iface
    raise RuntimeError("No network interface with a valid IP found")


def get_network_range(interface: Optional[str] = None) -> tuple[str, str, str]:
    """Return (network_cidr, local_ip, interface_name)."""
    iface    = interface or get_default_interface()
    local_ip = get_if_addr(iface)

    if not local_ip or local_ip == "0.0.0.0":
        raise ValueError(f"Interface {iface} has no valid IP address")

    prefix = 24
    try:
        out = subprocess.check_output(
            ["ip", "addr", "show", iface], text=True, stderr=subprocess.DEVNULL
        )
        m = re.search(r"inet\s+\d+\.\d+\.\d+\.\d+/(\d+)", out)
        if m:
            prefix = int(m.group(1))
    except Exception:
        pass

    network = ipaddress.ip_network(f"{local_ip}/{prefix}", strict=False)
    return str(network), local_ip, iface


def _resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "-"


# ---------------------------------------------------------------------------
# ARP scan
# ---------------------------------------------------------------------------
def _get_ttl_icmp(ip: str, timeout: float = 1.5) -> Optional[int]:
    """
    Sends an ICMP ping and reads the TTL from the IP response.
    This is where the TTL is available (IP layer of the ICMP response).
    """
    try:
        pkt     = IP(dst=ip) / ICMP()
        reply   = sr1(pkt, timeout=timeout, verbose=False)
        if reply and reply.haslayer(IP):
            return int(reply[IP].ttl)
    except Exception:
        pass
    return None


def scan_arp(
    network: str,
    interface: Optional[str]    = None,
    timeout: float              = 2.5,
) -> list:
    """
    Broadcast ARP + ping ICMP parallèle pour le TTL.
    """
    from .vendors_db import lookup, is_randomized

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    kwargs: dict = {"timeout": timeout, "verbose": False}
    if interface:
        kwargs["iface"] = interface

    answered, _ = srp(packet, **kwargs)

    # Collecte IP/MAC/latence depuis ARP
    arp_data = []
    for sent, received in answered:
        ip  = received.psrc
        mac = received.hwsrc.upper()

        # Latence depuis les timestamps ARP
        try:
            t_recv  = received.time
            t_sent  = sent.sent_time
            latency = round((float(t_recv) - float(t_sent)) * 1000, 2) \
                      if t_recv is not None and t_sent is not None else None
        except Exception:
            latency = None

        arp_data.append((ip, mac, latency))

    # Ping ICMP en parallèle pour récupérer le TTL
    ips = [d[0] for d in arp_data]
    ttl_map: dict[str, Optional[int]] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(ips), 20)) as pool:
        futures = {pool.submit(_get_ttl_icmp, ip, 1.5): ip for ip in ips}
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            try:
                ttl_map[ip] = future.result()
            except Exception:
                ttl_map[ip] = None

    # Assemblage final
    devices = []
    for (ip, mac, latency) in arp_data:
        ttl        = ttl_map.get(ip)
        randomized = is_randomized(mac)
        vendor     = lookup(mac)

        devices.append(Device(
            ip                  = ip,
            mac                 = mac,
            hostname            = _resolve_hostname(ip),
            vendor              = vendor,
            mac_randomized      = randomized,
            latency_ms          = latency,
            ttl                 = ttl,
            os_ttl              = _guess_os_from_ttl(ttl) if ttl is not None else "",
        ))

    devices.sort(key=lambda d: ipaddress.ip_address(d.ip))
    return devices