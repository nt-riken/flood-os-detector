# Component Specification

## Core Components

### 1. Packet Capture Module (`main.py`)
#### Purpose
- Captures network packets from specified interface
- Processes VLAN-tagged traffic
- Extracts fingerprints data and store it on LMDB
- Delete given period unseen MACs from LMDB
- Be careful, main.py has no analyze functions. And LMDB also includes only fingerprinting information.


#### Configuration
- Network interface name
- Optional database clear flag

#### Data Storage
- Stores in LMDB with structure:
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
- Logs to `packet_capture.log`
- Stop found error for debugging now

### 2. Analysis Engine (`analyze.py`)
#### Purpose
- Processes stored device data in LMDB
- Identifies operating systems
- Generates reports

#### Input
- LMDB database
- Input OUI file and fp file

#### Output
- CSV report with columns:
  - MAC Address ... found MAC address
  - First Seen
  - Last Seen
  - VLAN ID
  - Detected OS .. final result OS type
  - Device Type .. OUI vendor based purpose, very huristic
  - Vendor Information .. Vendor OUI

#### Error Handling
- Logs to `main.log`
- Stop when error occures for debugging now

### 3. Database Management
#### Storage
- LMDB database
- Key: MAC address
- Value: MessagePack encoded data. Using msgspec.

#### Operations
- Entry creation/update
- Entry retrieval
- Automatic cleanup (24h unseen expiration, checking period is 3-10 mins)

### 4. Logging System
#### Log Files
- `main.log`: All errors and warnings in main.py
- `analyze.log`: All errors and warnings in anlyze.py

#### Format
```
timestamp - level - code file name - line no - message
```

## Data Processing

### 1. TCP Analysis
- Capturing TCP SYN packets
- SYN packet processing
- Window size analysis
- TCP options extraction preserve options order

### 2. Protocol Analysis
- Capturing DHCP/mDNS/SSDP packets
- DHCP hostname and vendor_id extraction
- mDNS service detection
- SSDP request analysis

### 3. OS Detection current methods
- P0F TCP SYN signature matching
- Vendor database lookup
- mDNS special pattern matching
- DHCP special pattern matching
- SSDP special pattern matching

## Core Logic Protection

### Critical Components (DO NOT MODIFY)
1. **Packet Capture Logic**
   - Must capture TCP SYN packets
   - Must preserve TCP options order
   - Must capture specific UDP protocols (DHCP, mDNS, SSDP)

2. **Data Storage Format**
   - LMDB structure must remain unchanged
   - MessagePack encoding must be used
   - 24-hour expiration must be maintained

3. **OS Detection Methods**
   - P0F signature matching must be primary method
   - Secondary methods (mDNS, DHCP, SSDP) must remain as supplements
   - Weighted scoring system must be preserved

### Protected Data Flow
```
Network -> Packet Capture -> LMDB Storage -> Analysis -> CSV Output
```
- No direct network-to-analysis bypass allowed
- No modification of stored fingerprint data
- No alteration of analysis sequence

## Output Format Standards

### CSV Report Format (MANDATORY FIELDS)
```csv
mac_address,first_seen,last_seen,vlan_id,detected_os,device_type,vendor
```
- Field order must not change
- All fields must be present
- No additional fields without version update

### Field Definitions
- `mac_address`: Device MAC address
- `first_seen`: First detection timestamp
- `last_seen`: Last detection timestamp
- `vlan_id`: VLAN identifier
- `oui_purpose`: OUI-based device purpose
- `vendor`: Vendor information from OUI
- `detect_os`: list of each method's OS detection result
## Logging Standards

### Log File Requirements
- `main.log`: Main process operations
- `analyze.log`: Analysis operations
- No other log files without approval

### Log Format (MANDATORY)
```
timestamp - level - code file name - line no - message
```
- Format must not change
- All fields must be present
- Timestamp format: ISO 8601

### Required Log Events
1. **Main Process**
   - Interface initialization
   - Database operations
   - Critical errors
   - Process start/stop

2. **Analysis Process**
   - Analysis start/stop
   - Database access
   - OS detection results
   - Critical errors

