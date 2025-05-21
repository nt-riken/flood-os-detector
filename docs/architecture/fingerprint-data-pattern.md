# Fingerprint Data Pattern

This document defines the data patterns for various fingerprinting methods used in the Flood OS Detector project. All patterns follow the JSON style definition in `json-style-definition.md`.

## Core Principles
- Fields exist only when they have meaningful values
- No predefined null fields
- No empty value placeholders (0, [], {}, etc.)
- Each fingerprint type is stored in its own namespace

## Data Patterns

### 1. Basic MAC Entry
```json
{
    "mac_address": "00:11:22:33:44:55",
    "first_seen": 1234567890.123,
    "last_seen": 1234567890.123,
    "vlan_id": 1
}
```

### 2. DHCP Fingerprint
```json
{
    "dhcp_fingerprint": {
        "parameter_list": [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 121, 249, 33],
        "vendor_id": "MSFT 5.0",
        "hostname": "DESKTOP-ABC123",
        "user_class": "MSFT 5.0"
    }
}
```
- Only fields with actual values are included
- `parameter_list`: List of DHCP option numbers requested
- `vendor_id`: DHCP Option 60 value
- `hostname`: DHCP Option 12 value
- `user_class`: DHCP Option 77 value

### 3. mDNS Services
```json
{
    "mdns_fingerprint": {
        "device_info": {
            "model": "MacBookPro18,1",
            "osxvers": "20",
            "deviceid": "iPhone12,1",
            "osv": "15.0",
            "firmwarever": "17.0"
        },
        "workstation": true,
        "smb": true,
        "ipp": {
            "txtvers": "1.0",
            "URF": "CP1,MT1-3-4-5-8-9-10-11-12,OB9,OFU0,RS360",
            "TBCP": "T"
        },
        "services": [
            "_device-info._tcp.local",
            "_workstation._tcp.local",
            "_smb._tcp.local",
            "_ipp._tcp.local"
        ]
    }
}
```
- Only fields with actual values are included
- `device_info`: TXT records from _device-info._tcp.local
  - `osxvers`: macOS version (version = osxvers - 4)
  - `deviceid` and `osv`: iOS/iPadOS version
  - `firmwarever`: tvOS/HomeKit firmware version
- `workstation`: Boolean indicating presence of _workstation._tcp.local with Avahi cookie
- `smb`: Boolean indicating presence of _smb._tcp.local
- `ipp`: TXT records from _ipp._tcp.local for printer detection
- `services`: List of all discovered services for pattern detection

### 4. SSDP Headers
```json
{
    "ssdp_fingerprint": {
        "server": "Windows/10.0 UPnP/1.0 Windows-ConnectNow/1.0",
        "bootid": "1234567890",
        "mx": "2",
        "cache_control": "max-age=1800",
        "location": "http://192.168.1.100:1900/rootDesc.xml",
        "header_order": ["HOST", "MAN", "ST", "MX", "SERVER"],
        "header_casing": "ALL-CAPS"
    }
}
```
- Only headers with actual values are included
- `server`: OS-specific server string
- `bootid`: Present in Windows Vista+ and macOS/iOS
- `mx`: OS-specific MX value (Windows: 2, macOS/iOS: 3, Linux: 3+)
- `cache_control`: OS-specific max-age value
- `location`: OS-specific path and port
- `header_order`: List of headers in order of appearance
- `header_casing`: Header casing pattern (ALL-CAPS, mixed, lowercase)

### 5. TCP SYN Fingerprint
```json
{
    "tcp_syn": {
        "olen": "24",
        "ttl": "64",
        "tos": "0",
        "mss": "1460",
        "win": "65535",
        "opts": "mss,ws,nop,ts",
        "quirks": "ack+,push+",
        "pclass": "?"
    }
}
```
- All numeric values are stored as strings
- `olen`: Options length in bytes
- `ttl`: IP TTL value
- `tos`: IP TOS value
- `mss`: Maximum Segment Size (if present)
- `win`: TCP window size
- `opts`: Comma-separated list of TCP options
- `quirks`: Comma-separated list of TCP quirks
- `pclass`: p0f packet class (set by analysis)

### 6. OUI Analysis
```json
{
    "oui_analysis": {
        "vendor_name": "Apple, Inc.",
        "category": "Computer",
        "source": "nmap"
    }
}
```
- Only fields with actual values are included
- `source`: Either "nmap" or "manual_map"

## Implementation Guidelines

1. **Field Creation**
   - Create fields only when meaningful data is available
   - Use conditional logic to add fields
   - Remove fields when data becomes invalid

2. **Data Updates**
   - Update fields only with meaningful values
   - Remove fields when data expires
   - Maintain data consistency

3. **Error Handling**
   - Check field existence before access
   - Handle missing fields gracefully
   - Log data inconsistencies

## Example Complete Entry
```json
{
    "mac_address": "00:11:22:33:44:55",
    "first_seen": 1234567890.123,
    "last_seen": 1234567890.123,
    "vlan_id": 1,
    "dhcp_fingerprint": {
        "parameter_list": [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 121, 249, 33],
        "vendor_id": "MSFT 5.0"
    },
    "mdns_fingerprint": {
        "device_info": {
            "model": "MacBookPro18,1",
            "osxvers": "20"
        },
        "services": [
            "_device-info._tcp.local",
            "_smb._tcp.local"
        ]
    },
    "ssdp_fingerprint": {
        "server": "Windows/10.0 UPnP/1.0 Windows-ConnectNow/1.0",
        "mx": "2",
        "cache_control": "max-age=1800",
        "location": "http://192.168.1.100:1900/rootDesc.xml"
    },
    "tcp_syn": {
        "ttl": "64",
        "win": "65535",
        "opts": "mss,ws,nop,ts"
    },
    "oui_analysis": {
        "vendor_name": "Apple, Inc.",
        "source": "nmap"
    }
}
``` 