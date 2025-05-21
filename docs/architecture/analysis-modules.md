# Analysis Modules Specification

## Common Interface

All analysis modules follow the same basic interface:
- Read JSON from stdin
- Process each line as a JSON object
- Add analysis results to the object
- Output modified JSON to stdout
- Log errors to stderr

## Module Specifications

### 1. TCP Signature Analysis (`tcp_sig_analysis.py`)

#### Purpose
Analyze TCP SYN packets to detect operating systems using p0f signature matching.

#### Input Requirements
- TCP SYN packet data in the input JSON
- Required fields:
  - TCP options (in order)
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

#### Input Requirements
- MAC address in the input JSON
- OUI database (from nmap)

#### Analysis Method
1. Extract OUI from MAC address
2. Look up vendor in OUI database
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

#### Input Requirements
- DHCP packet data in the input JSON
- Required fields:
  - Parameter request list (option 55)
  - Vendor class identifier (option 60)
  - Host name (option 12)
  - User class (option 77)

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

## Error Handling

### Common Error Types
1. Invalid JSON input
2. Missing required fields
3. Database lookup failures
4. Analysis errors

### Error Response
- Log error to stderr
- Preserve original data
- Continue processing next record
- Include error information in output if relevant

## Performance Optimization

### Caching
- OUI database cache
- p0f signature cache
- Fingerbank database cache

### Batch Processing
- Optional batch mode for better performance
- Configurable batch size
- Memory usage monitoring

## Configuration

Each module should support:
- Config file for thresholds
- Command-line arguments for basic settings
- Environment variables for deployment settings

## Testing

### Required Tests
1. Unit tests for each analysis method
2. Integration tests for pipeline
3. Performance tests
4. Error handling tests

### Test Data
- Sample JSON inputs
- Known good outputs
- Error cases
- Edge cases 