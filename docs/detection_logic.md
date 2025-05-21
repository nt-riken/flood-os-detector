# OS Detection Logic

## Overview
This document describes the detection methods used in the modular analysis pipeline. Each method is implemented as a separate analysis module that processes JSON data and adds its results to the output.

## Detection Methods

### 1. TCP Signature Analysis (`tcp_sig_analysis.py`)

#### Purpose
Detect operating systems using TCP SYN packet fingerprinting.

#### Signature Format
`olen:ttl:tos:mss:win:opts:quirks:pclass`

#### Required Fields
- TCP options list (maintains order)
- MSS value
- Window size
- TTL
- TOS

#### Analysis Method
1. Extract TCP signature components
2. Match against p0f signature database
3. Calculate confidence score
4. Add results to JSON

#### Output Format
```json
{
  "tcp_signature": {
    "os_type": "string",
    "confidence": float,
    "details": {
      "matched_signature": "string",
      "ttl": integer,
      "window_size": integer,
      "mss": integer,
      "options": ["string"]
    }
  }
}
```

### 2. OUI Analysis (`oui_analysis.py`)

#### Purpose
Identify device vendors and categorize devices based on MAC address OUI.

#### Analysis Method
1. Extract OUI from MAC address
2. Look up vendor in OUI database (from nmap)
3. Map vendor to device category
4. Add results to JSON

#### Output Format
```json
{
  "vendor_info": {
    "vendor": "string",
    "category": "string",
    "confidence": float,
    "details": {
      "oui": "string",
      "category_source": "string"
    }
  }
}
```

### 3. Fingerbank Analysis (`fingerbank_analysis.py`)

#### Purpose
Detect operating systems and device types using DHCP fingerprinting.

#### Required Fields
- DHCP parameter request list (option 55)
- DHCP vendor class identifier (option 60)
- DHCP host name (option 12)
- DHCP user class (option 77)

#### Analysis Method
1. Extract DHCP options
2. Match against Fingerbank database
3. Calculate confidence score
4. Add results to JSON

#### Output Format
```json
{
  "fingerbank_detection": {
    "os_type": "string",
    "version": "string",
    "confidence": float,
    "details": {
      "matched_fingerprint": "string",
      "dhcp_options": {
        "55": ["string"],
        "60": "string",
        "12": "string",
        "77": "string"
      }
    }
  }
}
```

### 4. mDNS Analysis

#### Purpose
Detect operating systems using mDNS service advertisements.

#### Required Services
- `<device-info>._tcp.local`
- `_smb._tcp.local`
- `_ipp._tcp.local`

#### Detection Rules

| Observation | Fingerprint | Deduced OS |
|-------------|-------------|------------|
| `<device-info>._tcp.local` with `osxvers` | `model`, `osxvers` | **macOS** (Version = `osxvers − 4`) |
| `<device-info>._tcp.local` with `deviceid`,`osv` | `model`=`iPhone*`/`iPad*`, `osv` | **iOS / iPadOS** |
| `<device-info>._tcp.local` with `firmwarever` | `model`=`AppleTV*` or HomeKit types | **tvOS / HomeKit** |
| `<workstation>._tcp.local` with `org.freedesktop.Avahi.cookie` | none of the Apple keys | **Linux** (Avahi) |
| `_smb._tcp.local` without `<device-info>` | no DNS-SD TXT records other than SMB | **Windows** |
| `_ipp._tcp.local` with `txtvers`, `URF=`, `TBCP=` | IPP printer stack | **Printer appliance** |
| Missing or malformed TXT records | non-standard mDNS stack | **IoT / embedded** |

### 5. SSDP Analysis

#### Purpose
Detect operating systems using SSDP headers.

#### Detection Rules

| Header | Windows | macOS / iOS | Linux |
|--------|---------|------------|-------|
| `SERVER` | `Windows/10.0 UPnP/1.0 Windows-ConnectNow/1.0` | `Darwin/18.2.0 UPnP/1.1` | `Linux/4.15.0-54-generic UPnP/1.0` |
| `BOOTID.UPNP.ORG` | present (Vista+) | present | often absent |
| `MX` | `MX: 2` | usually `MX: 3` | `MX: 3` or higher |
| `Cache-Control: max-age` | `max-age=1800` | `max-age=1800` | often shorter |
| Header order & casing | ALL-CAPS, ordered | mixed | lowercase or mixed |
| `LOCATION` path & port | `/rootDesc.xml` on 1900/5000 | `/DeviceDescription.xml` on 49152 | `/desc.xml` on ephemeral port |

## Pipeline Integration

Each detection method is implemented as a separate analysis module that:
1. Reads JSON from stdin
2. Processes each line as a JSON object
3. Adds analysis results to the object
4. Outputs modified JSON to stdout
5. Logs errors to stderr

## Error Handling

- Invalid JSON: Skip and log error
- Missing fields: Skip analysis, preserve original data
- Database errors: Log error, continue processing
- Analysis errors: Log error, include error in output

## Performance Considerations

- Streaming processing for memory efficiency
- Caching for database lookups
- Parallel processing support
- Batch processing options