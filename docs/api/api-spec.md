# API Specification

## Component Interfaces

### 1. Packet Capture Module (`main.py`)
#### Input
- Network interface name
- Optional: Database clear flag

#### Output
- Stores data in LMDB with following structure:
```python
{
    'mac_address': str,
    'first_seen': float,
    'last_seen': float,
    'vlan_id': int,
    'tcp_signatures': List[str],
    'tcp_mss': List[str],
    'tcp_window_scale': List[str],
    'tcp_ttl': List[str],
    'tcp_window': List[str],
    'dhcp_hostname': str,
    'mdns_services': List[str],
    'ssdp_requests': List[str]
}
```

#### Error Handling
- Logs errors to `packet_capture.log`
- Continues operation on non-critical errors
- Graceful shutdown on critical errors

### 2. Analysis Engine (`analyze.py`)
#### Input
- LMDB database path
- Optional: Specific MAC address for targeted analysis

#### Output
- CSV file with columns:
  - MAC Address
  - First Seen
  - Last Seen
  - VLAN ID
  - Detected OS
  - Confidence Score
  - Device Type
  - Vendor Information

#### Error Handling
- Logs errors to `check_tcp_data.log`
- Skips problematic entries
- Continues processing remaining entries

### 3. Database Interface
#### Storage Format
- Key: MAC address (string)
- Value: MessagePack encoded device data

#### Operations
- Create/Update: `save_mac_entry(mac: str, entry: dict)`
- Read: `get_mac_entry(mac: str) -> dict`
- Cleanup: Automatic expiration after 24 hours of inactivity

### 4. Logging Interface
#### Log Files
- `packet_capture.log`: Packet capture operations
- `check_tcp_data.log`: Analysis operations
- `check_lmdb.log`: Database operations

#### Log Format
```
timestamp - level - message
```

## Data Formats

### 1. TCP Signature Format
```
port:port:window
```

### 2. P0F Signature Format
```
olen:ttl:tos:mss:win:opts:quirks:pclass
```

### 3. CSV Output Format
```csv
mac_address,first_seen,last_seen,vlan_id,detected_os,confidence_score,device_type,vendor
```

## Error Codes and Handling

### Database Errors
- `DB_ERROR_READ`: Failed to read from database
- `DB_ERROR_WRITE`: Failed to write to database
- `DB_ERROR_DECODE`: Failed to decode stored data

### Analysis Errors
- `ANALYSIS_ERROR_P0F`: Failed to match P0F signature
- `ANALYSIS_ERROR_TCP`: Failed to analyze TCP data
- `ANALYSIS_ERROR_VENDOR`: Failed to lookup vendor information

### Capture Errors
- `CAPTURE_ERROR_INTERFACE`: Interface access error
- `CAPTURE_ERROR_FILTER`: Packet filter error
- `CAPTURE_ERROR_PROCESS`: Packet processing error 