# Analysis Pipeline Architecture

## Overview
The analysis pipeline is designed as a modular system where each component processes JSON data in a streaming fashion, adding its own analysis results to the data stream. This architecture allows for flexible combination of different analysis methods and easy integration with shell-based tools.

## Pipeline Components

### 1. Data Source (`dump_json.py`)
- Reads from LMDB database
- Outputs JSON stream (one object per line)
- Each JSON object contains raw packet capture data

### 2. Analysis Modules

#### TCP Signature Analysis (`tcp_sig_analysis.py`)
- Input: JSON stream from `dump_json.py`
- Analysis: TCP SYN packet fingerprinting using p0f method
- Output: Adds `tcp_signature` field to JSON
- Key fields analyzed:
  - TCP options order
  - MSS
  - Window size
  - TTL
  - TOS

#### OUI Analysis (`oui_analysis.py`)
- Input: JSON stream from `dump_json.py`
- Analysis: MAC address vendor identification
- Output: Adds `vendor_info` field to JSON
- Uses nmap OUI database
- Maps vendors to device categories

#### Fingerbank Analysis (`fingerbank_analysis.py`)
- Input: JSON stream from `dump_json.py`
- Analysis: DHCP fingerprinting
- Output: Adds `fingerbank_detection` field to JSON
- Analyzes:
  - DHCP parameter request list (option 55)
  - DHCP vendor class identifier (option 60)
  - DHCP host name (option 12)
  - DHCP user class (option 77)

## Pipeline Usage

### Basic Pipeline
```bash
./dump_json.py | ./tcp_sig_analysis.py | ./oui_analysis.py | ./fingerbank_analysis.py > results.json
```

### Example Analysis Commands
```bash
# Count Linux devices
./dump_json.py | ./tcp_sig_analysis.py | jq 'select(.tcp_signature.os_type == "Linux")' | wc -l

# Find all Synology devices
./dump_json.py | ./oui_analysis.py | jq 'select(.vendor_info.vendor == "Synology")'

# Analyze DHCP fingerprints
./dump_json.py | ./fingerbank_analysis.py | jq 'select(.fingerbank_detection)'
```

## JSON Output Format

Each analysis module adds its results to the JSON object while preserving the original data:

```json
{
  "original_data": {
    "mac_address": "00:11:22:33:44:55",
    "first_seen": "2024-03-15T10:00:00",
    "last_seen": "2024-03-15T11:00:00",
    "vlan_id": 100,
    "mdns_services": { ... },
    "ssdp_headers": { ... }
  },
  "tcp_signature": {
    "os_type": "Linux",
    "confidence": 0.85,
    "details": { ... }
  },
  "vendor_info": {
    "vendor": "Synology",
    "category": "NAS",
    "confidence": 1.0
  },
  "fingerbank_detection": {
    "os_type": "Linux",
    "version": "4.15.0",
    "confidence": 0.90
  }
}
```

## Error Handling

Each analysis module:
- Continues processing on invalid JSON
- Logs errors to stderr
- Preserves original data even if analysis fails
- Uses non-blocking I/O for stream processing

## Performance Considerations

- Streaming processing for memory efficiency
- Parallel processing possible with `parallel` or similar tools
- Caching for OUI database lookups
- Batch processing for better performance

## Extending the Pipeline

To add a new analysis module:
1. Create a new Python script that reads JSON from stdin
2. Process each line as a JSON object
3. Add analysis results to the object
4. Output modified JSON to stdout
5. Document the new analysis method and its output format 