# Shell Integration Guide

## Overview
The analysis pipeline is designed to work seamlessly with shell tools, particularly `jq` for JSON processing. This document provides examples and best practices for common analysis tasks.

## Basic Tools

### Required Tools
- `jq`: JSON processor
- `grep`: Text search
- `wc`: Line counting
- `sort`: Sorting
- `uniq`: Unique value counting
- `parallel`: Parallel processing (optional)

## Common Analysis Patterns

### 1. Device Counting

```bash
# Count total devices
./dump_json.py | wc -l

# Count devices by OS type
./dump_json.py | ./tcp_sig_analysis.py | jq -r '.tcp_signature.os_type' | sort | uniq -c

# Count devices by vendor
./dump_json.py | ./oui_analysis.py | jq -r '.vendor_info.vendor' | sort | uniq -c
```

### 2. Device Filtering

```bash
# Find all Linux devices
./dump_json.py | ./tcp_sig_analysis.py | jq 'select(.tcp_signature.os_type == "Linux")'

# Find devices with high confidence detection
./dump_json.py | ./tcp_sig_analysis.py | jq 'select(.tcp_signature.confidence > 0.8)'

# Find devices in specific VLAN
./dump_json.py | jq 'select(.vlan_id == 100)'
```

### 3. Data Extraction

```bash
# Extract MAC addresses and OS types
./dump_json.py | ./tcp_sig_analysis.py | jq -r '[.mac_address, .tcp_signature.os_type] | @tsv'

# Extract vendor information
./dump_json.py | ./oui_analysis.py | jq -r '[.mac_address, .vendor_info.vendor, .vendor_info.category] | @tsv'
```

### 4. Complex Analysis

```bash
# Find devices with conflicting OS detection
./dump_json.py | ./tcp_sig_analysis.py | ./fingerbank_analysis.py | \
  jq 'select(.tcp_signature.os_type != .fingerbank_detection.os_type)'

# Find devices with multiple detection methods
./dump_json.py | ./tcp_sig_analysis.py | ./fingerbank_analysis.py | \
  jq 'select(.tcp_signature and .fingerbank_detection)'
```

### 5. Parallel Processing

```bash
# Process in parallel (4 cores)
./dump_json.py | parallel --pipe -j 4 './tcp_sig_analysis.py' | \
  parallel --pipe -j 4 './oui_analysis.py' | \
  parallel --pipe -j 4 './fingerbank_analysis.py'
```

## Output Formatting

### 1. Table Format
```bash
# Create a table of OS types and counts
./dump_json.py | ./tcp_sig_analysis.py | \
  jq -r '[.tcp_signature.os_type, .mac_address] | @tsv' | \
  column -t
```

### 2. CSV Format
```bash
# Export to CSV
./dump_json.py | ./tcp_sig_analysis.py | \
  jq -r '[.mac_address, .tcp_signature.os_type, .tcp_signature.confidence] | @csv'
```

### 3. JSON Format
```bash
# Pretty print JSON
./dump_json.py | ./tcp_sig_analysis.py | jq '.'

# Extract specific fields
./dump_json.py | ./tcp_sig_analysis.py | jq '{mac: .mac_address, os: .tcp_signature.os_type}'
```

## Performance Tips

### 1. Pipeline Optimization
```bash
# Use tee to save intermediate results
./dump_json.py | tee raw.json | ./tcp_sig_analysis.py | tee tcp.json | ./oui_analysis.py
```

### 2. Memory Management
```bash
# Process in chunks
./dump_json.py | split -l 1000 --filter='./tcp_sig_analysis.py'
```

### 3. Caching
```bash
# Cache intermediate results
./dump_json.py | tee /tmp/raw.json | ./tcp_sig_analysis.py | tee /tmp/tcp.json
```

## Error Handling

### 1. Logging
```bash
# Log errors to file
./dump_json.py 2>errors.log | ./tcp_sig_analysis.py 2>>errors.log
```

### 2. Error Recovery
```bash
# Skip invalid JSON
./dump_json.py | jq -c '.' 2>/dev/null | ./tcp_sig_analysis.py
```

## Best Practices

1. Always use `-r` with `jq` when outputting raw strings
2. Use `tee` to save intermediate results
3. Process in chunks for large datasets
4. Use parallel processing for CPU-intensive tasks
5. Log errors to separate files
6. Use `column -t` for readable table output
7. Use `@tsv` or `@csv` for structured data output
8. Use `select()` for filtering
9. Use `map()` for transformations
10. Use `group_by()` for aggregations 