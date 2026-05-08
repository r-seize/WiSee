"""
classifier.py -- Heuristic device type classification.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .network import Device


# Vendor keyword rules in priority order.
# HP appears in both Printer and Computer; Printer has higher priority.
_VENDOR_RULES: list[tuple[list[str], str]] = [
    (["apple", "iphone", "ipad"],                                          "Apple device"),
    (["samsung", "xiaomi", "huawei", "oneplus"],                           "Android device"),
    (["synology", "qnap", "western digital"],                              "NAS"),
    (["canon", "epson", "hp", "brother"],                                  "Printer"),
    (["cisco", "ubiquiti", "mikrotik", "tp-link", "netgear", "d-link"],    "Network device"),
    (["raspberry pi"],                                                      "Raspberry Pi"),
    (["intel", "dell", "lenovo", "asus", "acer"],                          "Computer"),
    (["philips", "sonos", "chromecast", "google"],                         "Smart home"),
]


def classify_device(device: "Device") -> str:
    if device.mac_randomized:
        return "Mobile (randomized MAC)"

    vendor = (device.vendor or "").lower()
    for keywords, dtype in _VENDOR_RULES:
        if any(kw in vendor for kw in keywords):
            return dtype

    ports = {p.port for p in device.open_ports}
    if ports:
        if (80 in ports or 443 in ports) and 22 in ports:
            return "Server"
        if 9100 in ports:
            return "Printer"
        if 554 in ports or 8554 in ports:
            return "Camera"
        if 1883 in ports or 8883 in ports:
            return "IoT device"
        if ports == {22}:
            return "Server / Headless"

    if device.ttl is not None and device.ttl >= 200:
        return "Router / Network device"

    return "Unknown"
