"""
diff.py -- Compare two exported JSON scan files and report changes.
"""

import json
from dataclasses import dataclass, field


@dataclass
class DeviceChange:
    field:  str
    before: str
    after:  str


@dataclass
class DiffResult:
    new_devices:     list[dict]                                  = field(default_factory=list)
    removed_devices: list[dict]                                  = field(default_factory=list)
    # each entry: (before_device, after_device, list[DeviceChange])
    changed_devices: list[tuple[dict, dict, list[DeviceChange]]] = field(default_factory=list)


_COMPARE_FIELDS = ("ip", "vendor", "hostname", "device_name")


def load_scan(filepath: str) -> dict[str, dict]:
    """Load a JSON scan export and return a dict keyed by MAC address."""
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(f"{filepath} does not contain a JSON array")
    result: dict[str, dict] = {}
    for entry in data:
        mac = str(entry.get("mac") or "")
        if mac:
            result[mac] = entry
    return result


def compute_diff(scan_a: dict[str, dict], scan_b: dict[str, dict]) -> DiffResult:
    """
    Compare two scans keyed by MAC address.
    Returns new, removed, and changed devices.
    """
    macs_a = set(scan_a)
    macs_b = set(scan_b)

    new_devices     = [scan_b[mac] for mac in sorted(macs_b - macs_a)]
    removed_devices = [scan_a[mac] for mac in sorted(macs_a - macs_b)]
    changed_devices: list[tuple[dict, dict, list[DeviceChange]]] = []

    for mac in sorted(macs_a & macs_b):
        a = scan_a[mac]
        b = scan_b[mac]
        changes: list[DeviceChange] = []

        for fld in _COMPARE_FIELDS:
            va = str(a.get(fld) or "")
            vb = str(b.get(fld) or "")
            if va != vb:
                changes.append(DeviceChange(field=fld, before=va, after=vb))

        ports_a = sorted(p.get("port", 0) for p in (a.get("open_ports") or []))
        ports_b = sorted(p.get("port", 0) for p in (b.get("open_ports") or []))
        if ports_a != ports_b:
            changes.append(DeviceChange(
                field  = "open_ports",
                before = ", ".join(str(p) for p in ports_a) or "(none)",
                after  = ", ".join(str(p) for p in ports_b) or "(none)",
            ))

        if changes:
            changed_devices.append((a, b, changes))

    return DiffResult(
        new_devices     = new_devices,
        removed_devices = removed_devices,
        changed_devices = changed_devices,
    )
