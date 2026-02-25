"""
scanner.py — Deep recon via nmap.

Runs nmap with increasing aggression depending on the chosen profile:
  quick   : -sn (ping sweep, already done via ARP — used for compatibility)
  ports   : -sS -T4 --top-ports 100   (top 100 TCP ports, fast)
  full    : -sS -sV -T4 -p 1-65535    (all TCP ports + service versions)
  os      : -sS -sV -O -T4 --top-ports 500  (service + OS detection)
  stealth : -sS -T2 --top-ports 200   (slower, less noisy)

Requires nmap to be installed:
  sudo apt install nmap   /   brew install nmap
"""

import subprocess
import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------

@dataclass
class PortInfo:
    port: int
    protocol: str          # tcp / udp
    state: str             # open / closed / filtered
    service: str           # http, ssh, ftp ...
    product: str           # Apache httpd, OpenSSH ...
    version: str           # 2.4.51, 8.9p1 ...
    extra_info: str        # OS hint, extra banner

    @property
    def display(self) -> str:
        parts = [self.service]
        if self.product:
            parts.append(self.product)
        if self.version:
            parts.append(self.version)
        return " ".join(parts)


@dataclass
class NmapResult:
    ip: str
    hostname: str                    = ""
    os_name: str                     = ""
    os_accuracy: int                 = 0
    os_family: str                   = ""
    ports: list[PortInfo]            = field(default_factory=list)
    mac: str                         = ""
    mac_vendor: str                  = ""
    status: str                      = "unknown"   # up / down
    raw_output: str                  = ""
    error: str                       = ""

    @property
    def open_ports(self) -> list[PortInfo]:
        return [p for p in self.ports if p.state == "open"]


# ---------------------------------------------------------------------------
# nmap profiles
# ---------------------------------------------------------------------------

PROFILES: dict[str, dict] = {
    "quick": {
        "label": "Quick  — top 100 ports, no version",
        "args":  ["-sS", "-T4", "--top-ports", "100", "--open"],
    },
    "ports": {
        "label": "Ports  — top 500 ports + service versions",
        "args":  ["-sS", "-sV", "-T4", "--top-ports", "500", "--open",
                  "--version-intensity", "3"],
    },
    "full": {
        "label": "Full   — all 65535 TCP ports + service versions",
        "args":  ["-sS", "-sV", "-T4", "-p", "1-65535", "--open",
                  "--version-intensity", "5"],
    },
    "os": {
        "label": "OS     — top 500 ports + service + OS detection",
        "args":  ["-sS", "-sV", "-O", "-T4", "--top-ports", "500", "--open",
                  "--version-intensity", "5", "--osscan-guess"],
    },
    "stealth": {
        "label": "Stealth — top 200 ports, slow timing (T2)",
        "args":  ["-sS", "-T2", "--top-ports", "200", "--open"],
    },
}


# ---------------------------------------------------------------------------

def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def _run_nmap(target: str, extra_args: list[str], timeout: int = 120) -> tuple[str, str]:
    """
    Run nmap and return (stdout_xml, stderr).
    Always requests XML output (-oX -) for reliable parsing.
    """
    cmd = ["nmap", "-oX", "-"] + extra_args + [target]
    try:
        result = subprocess.run(
            cmd,
            capture_output  = True,
            text            = True,
            timeout         = timeout,
        )
        return result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return "", "nmap timed out"
    except FileNotFoundError:
        return "", "nmap not found — install it: sudo apt install nmap"
    except Exception as exc:
        return "", str(exc)


def _parse_nmap_xml(xml_text: str, target_ip: str) -> NmapResult:
    """Parse nmap -oX XML output into a NmapResult."""
    result = NmapResult(ip=target_ip)

    if not xml_text.strip():
        result.error = "empty nmap output"
        return result

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        result.error = f"XML parse error: {exc}"
        return result

    host_elem = root.find("host")
    if host_elem is None:
        result.error = "host not found in nmap output"
        return result

    # Status
    status_elem = host_elem.find("status")
    if status_elem is not None:
        result.status = status_elem.get("state", "unknown")

    # Hostname
    hostnames = host_elem.find("hostnames")
    if hostnames is not None:
        hn = hostnames.find("hostname")
        if hn is not None:
            result.hostname = hn.get("name", "")

    # MAC (from address elements)
    for addr in host_elem.findall("address"):
        addr_type = addr.get("addrtype", "")
        if addr_type == "mac":
            result.mac = addr.get("addr", "")
            result.mac_vendor = addr.get("vendor", "")

    # Ports
    ports_elem = host_elem.find("ports")
    if ports_elem is not None:
        for port_elem in ports_elem.findall("port"):
            portid   = int(port_elem.get("portid", 0))
            protocol = port_elem.get("protocol", "tcp")

            state_elem  = port_elem.find("state")
            state       = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

            service_elem = port_elem.find("service")
            service  = ""
            product  = ""
            version  = ""
            extra    = ""
            if service_elem is not None:
                service = service_elem.get("name", "")
                product = service_elem.get("product", "")
                version = service_elem.get("version", "")
                extra   = service_elem.get("extrainfo", "")

            result.ports.append(PortInfo(
                port        = portid,
                protocol    = protocol,
                state       = state,
                service     = service,
                product     = product,
                version     = version,
                extra_info  = extra,
            ))

    # OS detection
    os_elem = host_elem.find("os")
    if os_elem is not None:
        best_match = None
        best_acc   = 0
        for match in os_elem.findall("osmatch"):
            acc = int(match.get("accuracy", 0))
            if acc > best_acc:
                best_acc   = acc
                best_match = match
        if best_match is not None:
            result.os_name     = best_match.get("name", "")
            result.os_accuracy = int(best_match.get("accuracy", 0))
            osclass = best_match.find("osclass")
            if osclass is not None:
                result.os_family = osclass.get("osfamily", "")

    return result


def scan_host(
    ip: str,
    profile: str = "ports",
    timeout: int = 120,
) -> NmapResult:
    """
    Run nmap against a single host with the given profile.
    Returns a populated NmapResult.
    """
    if not nmap_available():
        r           = NmapResult(ip=ip)
        r.error     = "nmap not installed"
        return r

    profile_cfg         = PROFILES.get(profile, PROFILES["ports"])
    xml_out, stderr     = _run_nmap(ip, profile_cfg["args"], timeout=timeout)

    result = _parse_nmap_xml(xml_out, ip)
    if stderr and not result.ports:
        result.error = stderr.strip().splitlines()[0] if stderr.strip() else ""
    result.raw_output = xml_out
    return result


def scan_hosts_parallel(
    ips: list[str],
    profile: str = "ports",
    timeout: int = 120,
    max_workers: int = 8,
    progress_callback=None,
) -> dict[str, NmapResult]:
    """
    Run nmap scans concurrently across multiple IPs.
    Returns dict[ip -> NmapResult].
    """
    import concurrent.futures

    results: dict[str, NmapResult] = {}
    completed = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {
            pool.submit(scan_host, ip, profile, timeout): ip
            for ip in ips
        }
        for future in concurrent.futures.as_completed(future_map):
            ip = future_map[future]
            try:
                results[ip] = future.result()
            except Exception as exc:
                r           = NmapResult(ip=ip)
                r.error     = str(exc)
                results[ip] = r
            completed += 1
            if progress_callback:
                progress_callback(completed, len(ips))

    return results