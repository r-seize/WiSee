"""
Device enrichment — runs multiple identification techniques in parallel
to find device names beyond what ARP + reverse DNS provides.

Techniques:
  1. mDNS/Bonjour   — multicast DNS, devices announce themselves on .local
  2. NetBIOS/NBNS   — Windows/Samba broadcast name service
  3. SSDP/UPnP      — router, TV, NAS announce friendly name + model
  4. Banner grab    — HTTP/HTTPS/SSH headers often contain device name
"""

import asyncio
import socket
import struct
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional
import concurrent.futures

# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class EnrichmentResult:
    ip: str
    mdns_name: Optional[str]        = None
    netbios_name: Optional[str]     = None
    upnp_name: Optional[str]        = None
    upnp_model: Optional[str]       = None
    banner_info: Optional[str]      = None

    @property
    def best_name(self) -> Optional[str]:
        """Return the most human-readable name found, in priority order."""
        return self.mdns_name or self.upnp_name or self.netbios_name or self.banner_info

    @property
    def detail(self) -> Optional[str]:
        """Secondary detail string (model, etc.)."""
        return self.upnp_model


# ─── 1. mDNS / Bonjour ───────────────────────────────────────────────────────

def _mdns_query(ip: str, timeout: float = 2.0) -> Optional[str]:
    """
    Send a unicast mDNS PTR query for <reversed-ip>.in-addr.arpa to the device.
    Many Apple / Google / Chromecast devices answer with their .local hostname.
    Falls back to a direct reverse lookup via mDNS port 5353.
    """
    # Build a minimal DNS PTR query
    reversed_ip = ".".join(reversed(ip.split(".")))
    query_name  = f"{reversed_ip}.in-addr.arpa"

    def encode_name(name: str) -> bytes:
        parts   = name.split(".")
        encoded = b""
        for part in parts:
            encoded += bytes([len(part)]) + part.encode()
        return encoded + b"\x00"

    transaction_id      = b"\xab\xcd"
    flags               = b"\x00\x00"          # standard query
    qdcount             = b"\x00\x01"
    ancount             = b"\x00\x00"
    nscount             = b"\x00\x00"
    arcount             = b"\x00\x00"
    header              = transaction_id + flags + qdcount + ancount + nscount + arcount
    qname               = encode_name(query_name)
    qtype               = b"\x00\x0c"   # PTR
    qclass              = b"\x00\x01"  # IN
    packet              = header + qname + qtype + qclass

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (ip, 5353))
        data, _ = sock.recvfrom(1024)
        sock.close()

        # Parse the answer section — look for a printable name
        # Skip header (12 bytes) + question section
        offset = 12
        # Skip question name
        while offset < len(data) and data[offset] != 0:
            if data[offset] & 0xC0 == 0xC0:
                offset += 2
                break
            offset += data[offset] + 1
        else:
            offset += 1
        offset += 4  # skip qtype + qclass

        if offset + 10 < len(data):
            # Skip answer name, type, class, ttl, rdlength
            # We just look for printable ASCII segments — hostname heuristic
            raw         = data[offset:]
            parts       = []
            i           = 0
            while i < len(raw):
                length = raw[i]
                if length == 0:
                    break
                if length & 0xC0 == 0xC0:
                    i += 2
                    break
                chunk = raw[i + 1: i + 1 + length]
                try:
                    parts.append(chunk.decode("utf-8"))
                except UnicodeDecodeError:
                    pass
                i += 1 + length
            if parts:
                name = ".".join(parts)
                # Strip trailing .local. or similar
                name = re.sub(r"\.(local|_tcp|_udp)\.?$", "", name, flags=re.I)
                # Filter garbage
                if 2 < len(name) < 80 and not name.startswith("_"):
                    return name
    except Exception:
        pass
    return None


# ─── 2. NetBIOS / NBNS ───────────────────────────────────────────────────────

def _netbios_query(ip: str, timeout: float = 2.0) -> Optional[str]:
    """
    Send a NetBIOS Name Service node status request (UDP 137).
    Returns the workstation / computer name if the host responds.
    """
    # NODE STATUS REQUEST packet
    packet = (
        b"\xab\xcd"          # transaction id
        b"\x00\x00"          # flags: query, non-recursive
        b"\x00\x01"          # questions: 1
        b"\x00\x00"          # answer RRs
        b"\x00\x00"          # authority RRs
        b"\x00\x00"          # additional RRs
        # Encoded "*" (wildcard) NBNS name: 32 bytes of "CA" repeated + \x00
        b"\x20"
        b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        b"\x00"
        b"\x00\x21"          # type: NBSTAT
        b"\x00\x01"          # class: IN
    )

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()

        # Response: skip 56 bytes of header, then read name count
        if len(data) < 57:
            return None
        num_names   = data[56]
        offset      = 57
        names       = []
        for _ in range(num_names):
            if offset + 18 > len(data):
                break
            raw_name    = data[offset: offset + 15].rstrip(b"\x00\x20")
            name_type   = data[offset + 15]
            flags       = struct.unpack(">H", data[offset + 16: offset + 18])[0]
            offset += 18
            try:
                decoded = raw_name.decode("ascii").strip()
                if decoded and name_type == 0x00 and not (flags & 0x8000):
                    # type 0x00 = workstation, not group flag = unique name
                    names.append(decoded)
            except UnicodeDecodeError:
                pass
        if names:
            return names[0]
    except Exception:
        pass
    return None


# ─── 3. SSDP / UPnP ──────────────────────────────────────────────────────────

def _ssdp_fetch(ip: str, timeout: float = 3.0) -> tuple[Optional[str], Optional[str]]:
    """
    Query a UPnP device description XML from http://ip:<port>/  
    Returns (friendly_name, model_name).
    
    Strategy:
      a) Send a unicast M-SEARCH to common UPnP ports (1900, 49152, 8080, 8200)
         to get the LOCATION header pointing to the XML description.
      b) Fetch that XML and parse <friendlyName> + <modelName>.
    """
    import urllib.request
    import urllib.error

    # Common UPnP description URL patterns to try directly
    candidate_urls = [
        f"http://{ip}:1900/",
        f"http://{ip}:49152/rootDesc.xml",
        f"http://{ip}:49153/rootDesc.xml",
        f"http://{ip}:8080/rootDesc.xml",
        f"http://{ip}:8200/rootDesc.xml",
        f"http://{ip}:80/rootDesc.xml",
        f"http://{ip}:8080/description.xml",
        f"http://{ip}:49152/description.xml",
    ]

    # First try a unicast M-SEARCH to port 1900 to get the real LOCATION
    try:
        msearch = (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {ip}:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 2\r\n"
            "ST: upnp:rootdevice\r\n"
            "\r\n"
        ).encode()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(msearch, (ip, 1900))
        response, _ = sock.recvfrom(4096)
        sock.close()
        text        = response.decode("utf-8", errors="ignore")
        loc_match   = re.search(r"LOCATION:\s*(\S+)", text, re.I)
        if loc_match:
            candidate_urls.insert(0, loc_match.group(1))
    except Exception:
        pass

    # Try each URL
    for url in candidate_urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "WiSee/0.2"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(8192).decode("utf-8", errors="ignore")
            friendly, model = _parse_upnp_xml(body)
            if friendly:
                return friendly, model
        except Exception:
            continue

    return None, None


def _parse_upnp_xml(xml_text: str) -> tuple[Optional[str], Optional[str]]:
    """Extract friendlyName and modelName from UPnP device description XML."""
    friendly    = None
    model       = None
    try:
        # Strip namespace for easier parsing
        xml_clean   = re.sub(r'\s+xmlns[^"]*"[^"]*"', '', xml_text)
        xml_clean   = re.sub(r'<\?xml[^?]*\?>', '', xml_clean).strip()
        root        = ET.fromstring(xml_clean)

        def find_text(tag: str) -> Optional[str]:
            for elem in root.iter():
                if elem.tag.lower().endswith(tag.lower()) and elem.text:
                    return elem.text.strip()
            return None

        friendly    = find_text("friendlyName")
        model       = find_text("modelName")
    except ET.ParseError:
        # Regex fallback
        m = re.search(r"<friendlyName>([^<]+)</friendlyName>", xml_text, re.I)
        if m:
            friendly = m.group(1).strip()
        m = re.search(r"<modelName>([^<]+)</modelName>", xml_text, re.I)
        if m:
            model = m.group(1).strip()
    return friendly, model


# ─── 4. Banner grabbing ───────────────────────────────────────────────────────

_BANNER_PORTS = [80, 8080, 443, 8443, 8200, 22, 21, 23, 5000, 8888, 9090]

def _banner_grab(ip: str, timeout: float = 2.0) -> Optional[str]:
    """
    Attempt quick TCP connects on common ports.
    For HTTP/HTTPS: read the Server header or <title> tag.
    For SSH: read the banner line.
    Returns a short human-readable string or None.
    """
    for port in _BANNER_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            if port == 22:
                banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
                sock.close()
                # "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"  →  "OpenSSH (Ubuntu)"
                m = re.search(r"SSH-[\d.]+-(\S+)", banner)
                if m:
                    info = m.group(1).replace("_", " ")
                    return f"SSH: {info}"

            elif port in (80, 8080, 5000, 8888, 9090, 8200):
                request = (
                    f"GET / HTTP/1.0\r\nHost: {ip}\r\n"
                    "User-Agent: WiSee/0.2\r\nConnection: close\r\n\r\n"
                )
                sock.sendall(request.encode())
                response = b""
                while True:
                    chunk = sock.recv(2048)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 8192:
                        break
                sock.close()
                text    = response.decode("utf-8", errors="ignore")
                result  = _extract_http_name(text)
                if result:
                    return result

            elif port in (443, 8443):
                import ssl
                ctx                     = ssl.create_default_context()
                ctx.check_hostname      = False
                ctx.verify_mode         = ssl.CERT_NONE
                tls                     = ctx.wrap_socket(sock, server_hostname=ip)
                request = (
                    f"GET / HTTP/1.0\r\nHost: {ip}\r\n"
                    "User-Agent: WiSee/0.2\r\nConnection: close\r\n\r\n"
                )
                tls.sendall(request.encode())
                response = b""
                while True:
                    chunk = tls.recv(2048)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 8192:
                        break
                tls.close()
                text        = response.decode("utf-8", errors="ignore")
                result      = _extract_http_name(text)
                if result:
                    return result

            else:
                sock.close()

        except Exception:
            continue

    return None


def _extract_http_name(http_text: str) -> Optional[str]:
    """Extract device name from HTTP response headers + body."""
    # Server header
    m = re.search(r"^Server:\s*(.+)$", http_text, re.M | re.I)
    if m:
        server = m.group(1).strip()
        # Filter generic/boring servers
        boring = {"Apache", "nginx", "lighttpd", "Microsoft-IIS", "cloudflare"}
        if not any(b.lower() in server.lower() for b in boring):
            return f"HTTP: {server[:60]}"

    # <title> tag
    m = re.search(r"<title[^>]*>([^<]{3,80})</title>", http_text, re.I)
    if m:
        title = m.group(1).strip()
        if title and len(title) > 2:
            return f"Web: {title[:60]}"

    # X-Powered-By or other revealing headers
    m = re.search(r"^X-Powered-By:\s*(.+)$", http_text, re.M | re.I)
    if m:
        return f"HTTP: {m.group(1).strip()[:60]}"

    return None


# ─── Orchestrator ─────────────────────────────────────────────────────────────

def enrich_device(ip: str, timeout_budget: float = 10.0) -> EnrichmentResult:
    """
    Run all 4 enrichment techniques concurrently for a single IP.
    timeout_budget is split across techniques.
    """
    result  = EnrichmentResult(ip=ip)
    t       = timeout_budget / 4  # rough per-technique budget

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        f_mdns    = pool.submit(_mdns_query,    ip, min(t, 2.5))
        f_netbios = pool.submit(_netbios_query, ip, min(t, 2.5))
        f_ssdp    = pool.submit(_ssdp_fetch,    ip, min(t, 4.0))
        f_banner  = pool.submit(_banner_grab,   ip, min(t, 2.0))

        try:
            result.mdns_name = f_mdns.result(timeout=t + 0.5)
        except Exception:
            pass
        try:
            result.netbios_name = f_netbios.result(timeout=t + 0.5)
        except Exception:
            pass
        try:
            upnp_name, upnp_model   = f_ssdp.result(timeout=t + 1.0)
            result.upnp_name        = upnp_name
            result.upnp_model       = upnp_model
        except Exception:
            pass
        try:
            result.banner_info = f_banner.result(timeout=t + 0.5)
        except Exception:
            pass

    return result


def enrich_all(
    ips: list[str],
    timeout_budget: float = 10.0,
    progress_callback=None,
) -> dict[str, EnrichmentResult]:
    """
    Enrich all IPs concurrently.
    Returns dict[ip -> EnrichmentResult].
    """
    results: dict[str, EnrichmentResult]    = {}
    completed                               = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(ips), 20)) as pool:
        future_to_ip = {
            pool.submit(enrich_device, ip, timeout_budget): ip
            for ip in ips
        }
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                results[ip] = future.result()
            except Exception:
                results[ip] = EnrichmentResult(ip=ip)
            completed += 1
            if progress_callback:
                progress_callback(completed, len(ips))

    return results