# Flood OS Detector

A network packet capture and analysis tool that detects operating systems and devices on a network using various fingerprinting methods.

## Features

- VLAN-aware packet capture
- Multiple OS detection methods:
  - DHCP fingerprinting
  - mDNS service detection
  - SSDP (UPnP) device detection
  - TCP SYN fingerprinting
  - OUI (MAC address) analysis
- Persistent storage using LMDB
- Automatic cleanup of old entries
- Detailed logging

## Requirements

- Python 3.8+
- Scapy
- LMDB
- msgspec

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/flood-os-detector.git
cd flood-os-detector
```

2. Install dependencies:
```bash
uv pip install -r requirements.txt
```

## Usage

Run the packet capture with:
```bash
sudo /home/tsuruoka/.local/bin/uv run main.py <interface> [--clear-db]
```

Example:
```bash
sudo /home/tsuruoka/.local/bin/uv run main.py eth0
```

To clear the existing database and start fresh:
```bash
sudo /home/tsuruoka/.local/bin/uv run main.py eth0 --clear-db
```

## Project Structure

- `main.py` - Main packet capture and analysis script
- `analyze.py` - Analysis tools for captured data
- `p0f_signatures.py` - TCP SYN fingerprint signatures
- `models.py` - Data models and structures
- `docs/` - Project documentation
- `results/` - Analysis results and exports

## Development

Please read the development guidelines in `docs/development/guidelines.md` before contributing.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
