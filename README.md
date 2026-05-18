# WiSee - Local Network Discovery Tool

```
 ██╗    ██╗██╗███████╗███████╗███████╗
 ██║    ██║██║██╔════╝██╔════╝██╔════╝
 ██║ █╗ ██║██║███████╗█████╗  █████╗
 ██║███╗██║██║╚════██║██╔══╝  ██╔══╝
 ╚███╔███╔╝██║███████║███████╗███████╗
  ╚══╝╚══╝ ╚═╝╚══════╝╚══════╝╚══════╝
```
[![Version](https://img.shields.io/badge/version-0.1.3-blue.svg)](https://github.com/r-seize/wisee/releases)
[![Python](https://img.shields.io/badge/python-3.10+-green.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-GPL-orange.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)]()

Scan your local network in seconds. Discovers devices via ARP, enriches them with mDNS / NetBIOS / UPnP / banner grabbing, classifies device types, scores security risk, and optionally runs deep nmap recon.

## Installation

### pipx (recommended)
```bash
curl -sSL https://raw.githubusercontent.com/r-seize/wisee/main/install.sh | bash
```
> This automatically creates the sudo symlink. `sudo wisee scan` works immediately.

**Manual pipx install** (requires extra step):
```bash
pipx install git+https://github.com/r-seize/wisee.git
sudo ln -sf ~/.local/bin/wisee /usr/local/bin/wisee
```

### .deb (Debian / Ubuntu)

Download the latest `.deb` from [Releases](https://github.com/r-seize/wisee/releases):

```bash
sudo dpkg -i wisee_0.1.3_all.deb
```

### tar.gz / pip

```bash
pip install https://github.com/r-seize/wisee/releases/download/v0.1.3/wisee-0.1.3.tar.gz
```

### From source

```bash
git clone https://github.com/r-seize/wisee.git
cd wisee
pipx install .
# or
uv pip install -e .
```

## Usage

```bash
sudo wisee scan                        # basic scan
sudo wisee scan --nmap ports           # + port scan (top 500)
sudo wisee scan --nmap os              # + OS detection
sudo wisee scan --fast                 # quick ARP only (no enrichment / classification)
sudo wisee scan --show-risks           # print risk summary panel after the table
sudo wisee scan --export results.json  # export to JSON
sudo wisee scan --export results.csv   # export to CSV

sudo wisee scan --watch                # continuous scan, report changes every 30s
sudo wisee scan --watch --interval 60  # continuous scan every 60s
sudo wisee scan --watch --watch-count 5  # stop after 5 scans

wisee diff scan1.json scan2.json       # compare two exported scans
wisee diff scan1.json scan2.json --export delta.json  # + export diff as JSON

wisee interfaces                       # list network interfaces
wisee profiles                         # list nmap profiles
wisee --help
```

## Scan phases

| Phase | What it does |
|-------|-------------|
| **1 - ARP** | Broadcast ARP → device list with MAC, vendor, TTL, latency |
| **2 - Enrichment** | mDNS · NetBIOS · UPnP · HTTP/SSH banner → device names |
| **3 - Nmap** | Port scan + service detection + OS fingerprint (optional) |
| **Post - Classify** | Heuristic device type from vendor / ports / TTL |
| **Post - Risk score** | Additive security risk score (0-100) with named flags |

## Device types

Automatically detected from vendor name, open ports, and TTL heuristic:

`Apple device` · `Android device` · `NAS` · `Printer` · `Network device` · `Raspberry Pi` · `Computer` · `Smart home` · `Server` · `Server / Headless` · `Camera` · `IoT device` · `Router / Network device` · `Mobile (randomized MAC)` · `Unknown`

## Risk scoring

Each device receives an additive risk score (0-100) based on exposed services:

| Flag | Score |
|------|-------|
| Telnet open (port 23) | +30 |
| FTP open (port 21) | +25 |
| HTTP without HTTPS (port 80, no 443) | +20 |
| SSH exposed (port 22) | +15 |
| SMB exposed (port 445) | +15 |
| RDP exposed (port 3389) | +10 |
| Unidentified device type | +10 |
| Randomized MAC | +10 |
| Many open ports (>5) | +5 each, max +20 |

Risk levels: **Low** (0-20) · **Medium** (21-50) · **High** (51-80) · **Critical** (81-100)

Use `--show-risks` to print a dedicated summary panel listing devices above score 20.

## Watch mode

```bash
sudo wisee scan --watch                  # re-scan every 30s, report changes
sudo wisee scan --watch --interval 120   # every 2 minutes
sudo wisee scan --watch --watch-count 10 # stop after 10 scans
```

Each cycle shows the full scan table, then a diff against the previous scan:
- **NEW** - device appeared since the last scan
- **GONE** - device disappeared
- **CHANGED** - open ports or device name changed

## Diff command

Compare any two JSON exports produced by `--export`:

```bash
wisee diff morning.json evening.json
wisee diff scan_before.json scan_after.json --export report.json
```

Devices are matched by MAC address. Changed fields (IP, vendor, hostname, device name, open ports) are shown inline.

## nmap profiles

| Profile | Description |
|---------|-------------|
| `quick` | Top 100 TCP ports, no version detection |
| `ports` | Top 500 TCP ports + service versions *(recommended)* |
| `full` | All 65535 TCP ports + service versions |
| `os` | Top 500 ports + service + OS fingerprinting |
| `stealth` | Top 200 ports, slow timing (T2) |


## Requirements

- Python >= 3.10
- `scapy`, `rich`, `click`
- `nmap` (optional, for Phase 3): `sudo apt install nmap`
- Raw socket permissions: run with `sudo`, or grant once:
  ```bash
  sudo setcap cap_net_raw+eip $(which python3)
  ```

## Uninstall

### pipx
```bash
pipx uninstall wisee
sudo rm -f /usr/local/bin/wisee
```

### .deb
```bash
sudo dpkg -r wisee
```

### pip
```bash
pip uninstall wisee
sudo rm -f /usr/local/bin/wisee
```

### From source
```bash
pipx uninstall wisee
# or
uv pip uninstall wisee
sudo rm -f /usr/local/bin/wisee
```

## About

We'd like to thank everyone who contributed ideas, tested the tool, or provided feedback during development. Your support is greatly appreciated!


If you have suggestions, feature requests, or improvements, please don't hesitate to open an issue or submit a pull request. Every contribution helps make WiSee better for everyone.