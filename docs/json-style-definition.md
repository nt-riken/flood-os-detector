# Data Format Specification

## Fingerprint JSON Style

### Core Principle
- Fields exist only when they have meaningful values
- No predefined null fields
- No empty value placeholders (0, [], {}, etc.)

### Rationale
1. **Data Integrity**
   - Only meaningful data is stored
   - Presence of a field indicates actual data
   - No ambiguity between null and empty values

2. **Storage Efficiency**
   - No wasted space storing null/empty values
   - Optimized for LMDB storage
   - Reduced memory footprint

3. **Analysis Clarity**
   - Simpler analysis logic
   - No need to check for null/empty values
   - Clear indication of available data

### Examples

#### Correct Usage
```json
{
    "mac_address": "00:11:22:33:44:55",
    "tcp_syn": {
        "ttl": "64",
        "win": "65535",
        "opts": "mss,ws,nop"
    }
}
```

#### Incorrect Usage
```json
{
    "mac_address": "00:11:22:33:44:55",
    "tcp_syn": {
        "ttl": "64",
        "win": "65535",
        "opts": "mss,ws,nop",
        "mss": null,           // Don't include null fields
        "quirks": []           // Don't include empty arrays
    }
}
```

### Implementation Guidelines

1. **Field Creation**
   - Only create fields when meaningful data is available
   - Use conditional logic to add fields
   - Document required vs optional fields

2. **Data Updates**
   - Remove fields when data becomes invalid
   - Update fields only with meaningful values
   - Maintain data consistency

3. **Error Handling**
   - Check for field existence before access
   - Handle missing fields gracefully
   - Log data inconsistencies

### Impact on Components

1. **Packet Capture (`main.py`)**
   - Only store fields with actual values
   - Remove fields when data expires
   - Maintain data integrity

2. **Analysis Engine (`analyze.py`)**
   - Check field existence before analysis
   - Handle missing fields appropriately
   - Document analysis assumptions

3. **Database Interface**
   - Optimize storage for actual data
   - Maintain data consistency
   - Handle field updates efficiently

### Migration and Compatibility

1. **Existing Data**
   - No migration needed for new data
   - Document handling of legacy data
   - Maintain backward compatibility

2. **Future Changes**
   - Document any format changes
   - Maintain version compatibility
   - Update analysis logic accordingly