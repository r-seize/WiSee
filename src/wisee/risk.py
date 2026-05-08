"""
risk.py -- Security risk scoring per device.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .network import Device


def score_device(device: "Device") -> tuple[int, list[str]]:
    """
    Compute an additive risk score (0-100) and a list of human-readable flags.
    Must be called after classify_device() so device.device_type is set.
    """
    score               = 0
    flags: list[str]    = []

    ports = {p.port for p in device.open_ports}

    if 23 in ports:
        score += 30
        flags.append("Telnet open")
    if 21 in ports:
        score += 25
        flags.append("FTP open")
    if 80 in ports and 443 not in ports:
        score += 20
        flags.append("HTTP without HTTPS")
    if 22 in ports:
        score += 15
        flags.append("SSH exposed")
    if 445 in ports:
        score += 15
        flags.append("SMB exposed")
    if 3389 in ports:
        score += 10
        flags.append("RDP exposed")
    if device.device_type == "Unknown":
        score += 10
        flags.append("Unidentified device")
    if device.mac_randomized:
        score += 10
        flags.append("Randomized MAC")

    extra = max(0, len(ports) - 5)
    if extra > 0:
        score += min(20, extra * 5)
        flags.append(f"Many open ports ({len(ports)})")

    return min(100, score), flags


def risk_level(score: int) -> str:
    if score <= 20:
        return "Low"
    if score <= 50:
        return "Medium"
    if score <= 80:
        return "High"
    return "Critical"
