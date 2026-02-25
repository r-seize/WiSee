# WiSee - Local Network Discovery Tool

```
 ██╗    ██╗██╗███████╗███████╗███████╗
 ██║    ██║██║██╔════╝██╔════╝██╔════╝
 ██║ █╗ ██║██║███████╗█████╗  █████╗
 ██║███╗██║██║╚════██║██╔══╝  ██╔══╝
 ╚███╔███╔╝██║███████║███████╗███████╗
  ╚══╝╚══╝ ╚═╝╚══════╝╚══════╝╚══════╝
```
[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://github.com/VOTRE-USERNAME/filegen/releases)
[![Python](https://img.shields.io/badge/python-3.10+-green.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-GPL-orange.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)]()

Scan your local network in seconds. Discovers devices via ARP, enriches them with mDNS / NetBIOS / UPnP / banner grabbing, and optionally runs deep nmap recon.

## Installation

### pipx (recommended)

```bash
pipx install git+https://github.com/r-seize/wisee.git
```

### .deb (Debian / Ubuntu)

Download the latest `.deb` from [Releases](https://github.com/r-seize/wisee/releases):

```bash
sudo dpkg -i wisee_0.1.0_all.deb
```

### tar.gz / pip

```bash
pip install https://github.com/r-seize/wisee/releases/download/v0.1.0/wisee-0.1.0.tar.gz
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
sudo wisee scan --fast                 # quick ARP only
sudo wisee scan --export results.json  # export to JSON
sudo wisee scan --export results.csv   # export to CSV
wisee interfaces                       # list network interfaces
wisee profiles                         # list nmap profiles
wisee --help
```

## Scan phases

| Phase | What it does |
|-------|-------------|
| **1 — ARP** | Broadcast ARP → device list with MAC, vendor, TTL, latency |
| **2 — Enrichment** | mDNS · NetBIOS · UPnP · HTTP/SSH banner → device names |
| **3 — Nmap** | Port scan + service detection + OS fingerprint (optional) |

## nmap profiles

| Profile | Description |
|---------|-------------|
| `quick` | Top 100 TCP ports, no version detection |
| `ports` | Top 500 TCP ports + service versions *(recommended)* |
| `full` | All 65535 TCP ports + service versions |
| `os` | Top 500 ports + service + OS fingerprinting |
| `stealth` | Top 200 ports, slow timing (T2) |


## Requirements

- Python ≥ 3.10
- `scapy`, `rich`, `click`
- `nmap` (optional, for Phase 3): `sudo apt install nmap`
- Raw socket permissions: run with `sudo`, or grant once:
  ```bash
  sudo setcap cap_net_raw+eip $(which python3)
  ```

## About

We’d like to thank everyone who contributed ideas, tested the tool, or provided feedback during development. Your support is greatly appreciated!

If you have suggestions, feature requests, or improvements, please don’t hesitate to open an issue or submit a pull request. Every contribution helps make FileGen better for everyone.