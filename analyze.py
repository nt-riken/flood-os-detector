#!/usr/bin/env python3

import json
import os
from datetime import datetime
import logging
from collections import defaultdict
import time
import jsonpickle
import csv
from typing import Optional, Dict, Any
from functools import wraps
from storage import LMDBStorage
from p0f_signatures import P0FMatcher

# Performance measuring decorator
def measure_time(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        # Only log if the function took more than 1 second
        if end_time - start_time > 1.0:
            logger.info(f"{func.__name__} took {end_time - start_time:.4f} seconds")
        return result
    return wrapper

# Configure logging
logging.basicConfig(level=logging.DEBUG,
                   format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s')
logger = logging.getLogger(__name__)

# Add exception formatter
def exception_formatter(exc_info):
    """Format exception with line numbers"""
    import traceback
    tb = traceback.extract_tb(exc_info[2])
    formatted_tb = []
    for frame in tb:
        formatted_tb.append(f"  File \"{frame.filename}\", line {frame.lineno}, in {frame.name}")
        formatted_tb.append(f"    {frame.line}")
    return "\n".join(formatted_tb)

# Override the default exception formatter
logging.Formatter.formatException = exception_formatter

class OSAnalyzer:
    def __init__(self):
        self.results_dir = 'results'
        try:
            self.p0f_matcher = P0FMatcher('p0f.fp')  # Load p0f signatures
            logger.info("Successfully loaded p0f signatures")
        except Exception as e:
            logger.error(f"Failed to load p0f signatures: {e}")
            self.p0f_matcher = None  # Set to None to indicate failure
        
        # Create results directory if it doesn't exist
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)

        # Initialize LMDB storage
        self.storage = LMDBStorage()
        logger.info("Successfully initialized LMDB storage")

        # Load vendor database
        self.vendor_db = self._load_vendor_db()

    def _load_vendor_db(self):
        """Load vendor database from Wireshark manuf file"""
        vendor_db = {}
        manuf_path = '/usr/share/wireshark/manuf'
        
        try:
            with open(manuf_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Split the line into parts
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        oui = parts[0].replace(':', '').lower()  # Remove colons and convert to lowercase
                        vendor = parts[1].strip()
                        
                        # Store the vendor name
                        vendor_db[oui] = vendor
            
            logger.info(f"Loaded {len(vendor_db)} vendor entries from Wireshark manuf file")
            return vendor_db
        except Exception as e:
            logger.error(f"Error loading vendor database from Wireshark manuf file: {e}")
            return {}

    def _get_vendor_info(self, mac_address):
        """Get vendor information from MAC address using Wireshark manuf database"""
        try:
            # Extract OUI (first 3 bytes of MAC)
            oui = ''.join(mac_address.split(':')[:3]).lower()
            vendor = self.vendor_db.get(oui, "Unknown")
            
            # If vendor is unknown, try to find a partial match
            if vendor == "Unknown":
                # Try with first 2 bytes
                partial_oui = ''.join(mac_address.split(':')[:2]).lower()
                for key in self.vendor_db:
                    if key.startswith(partial_oui):
                        return f"Unknown (Possible: {self.vendor_db[key]})"
            
            return vendor
        except Exception as e:
            logger.error(f"Error getting vendor info: {e}")
            return "Unknown"

    def get_mac_entry(self, mac_address: str) -> Optional[Dict]:
        """Get a MAC entry from LMDB storage"""
        logger.debug(f"\nGetting MAC entry for: {mac_address}")
        
        try:
            entry = self.storage.get_mac_entry(mac_address)
            if not entry:
                logger.debug(f"No entry found for MAC {mac_address}")
                return None
                
            # Convert MACEntry to dictionary
            entry_dict = entry.to_dict()
            logger.debug(f"Retrieved entry for MAC {mac_address}")
            return entry_dict
            
        except Exception as e:
            logger.error(f"Error getting MAC entry: {e}")
            return None

    def _save_analysis(self, mac, analysis):
        """Save analysis results for a MAC address"""
        try:
            # Create results directory if it doesn't exist
            if not os.path.exists(self.results_dir):
                os.makedirs(self.results_dir)
                
            # Save analysis to CSV file
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = os.path.join(self.results_dir, f'analysis_{timestamp}.csv')
            
            # Check if file exists to determine if we need to write header
            file_exists = os.path.exists(filename)
            
            with open(filename, 'a', newline='') as f:
                writer = csv.writer(f)
                
                # Write header only if file is new
                if not file_exists:
                    writer.writerow([
                        'MAC Address',
                        'Vendor',
                        'TTL Analysis',
                        'IP ID Analysis',
                        'DHCP Analysis',
                        'mDNS Analysis',
                        'SSDP Analysis',
                        'p0f Analysis',
                        'Device Type',
                        'Final OS'
                    ])
                
                # Write data
                writer.writerow([
                    mac,
                    analysis.get('vendor', ''),
                    analysis.get('ttl', ''),
                    analysis.get('ip_id', ''),
                    ', '.join(analysis.get('dhcp', [])),
                    ', '.join(analysis.get('mdns', [])),
                    ', '.join(analysis.get('ssdp', [])),
                    ', '.join(analysis.get('p0f', [])),
                    analysis.get('device_type', ''),
                    analysis.get('final_os', '')
                ])
                
            logger.info(f"Saved analysis for MAC {mac} to {filename}")
            
        except Exception as e:
            logger.error(f"Error saving analysis for MAC {mac}: {e}")

    def analyze_ip_id_sequence(self, ip_ids):
        """Analyze IP ID sequence for OS fingerprinting"""
        if not ip_ids:
            return "No IP ID values available"
            
        try:
            # Convert to integers
            ip_ids = [int(id) for id in ip_ids]
            
            # Calculate differences between consecutive IDs
            diffs = [ip_ids[i+1] - ip_ids[i] for i in range(len(ip_ids)-1)]
            
            # Analyze sequence
            if all(diff == 1 for diff in diffs):
                return "Windows (incremental)"
            elif all(diff == 0 for diff in diffs):
                return "Linux (constant)"
            elif all(diff >= 0 for diff in diffs):
                return "Linux (incremental)"
            else:
                return "Unknown (random)"
                
        except Exception as e:
            logger.error(f"Error analyzing IP ID sequence: {e}")
            return "Error analyzing IP ID sequence"

    def analyze_ttl(self, ttl_values, vendor_info=None, mdns_services=None):
        """Analyze TTL values for OS fingerprinting"""
        if not ttl_values:
            return "No TTL values available"
            
        try:
            # Convert to integers and filter out TTL=1 as it's not meaningful for OS detection in LAN
            meaningful_ttls = [int(ttl) for ttl in ttl_values if int(ttl) != 1]
            
            if not meaningful_ttls:
                return "No meaningful TTL values available"
            
            # Get most common TTL
            from collections import Counter
            ttl_counter = Counter(meaningful_ttls)
            most_common_ttl = ttl_counter.most_common(1)[0][0]
            
            # Analyze based on TTL value
            if most_common_ttl == 64:
                return "Linux/Unix"
            elif most_common_ttl == 128:
                return "Windows"
            elif most_common_ttl == 255:
                # TTL=255 could be network equipment or older Solaris
                # Check if we have other indicators
                if vendor_info and "cisco" in vendor_info.lower():
                    return "Network equipment"
                elif vendor_info and "juniper" in vendor_info.lower():
                    return "Network equipment"
                elif vendor_info and "solaris" in vendor_info.lower():
                    return "Solaris"
                else:
                    return "Network equipment (or older Solaris)"
            else:
                # Check for Apple devices
                if vendor_info and "apple" in vendor_info.lower():
                    return "macOS/iOS"
                # Check for mDNS services
                if mdns_services and any("apple" in service.lower() for service in mdns_services):
                    return "macOS/iOS"
                return f"Unknown (TTL: {most_common_ttl})"
                
        except Exception as e:
            logger.error(f"Error analyzing TTL values: {e}")
            return "Error analyzing TTL values"

    def analyze_dhcp(self, dhcp_options, vendor_class, hostname, user_class=None):
        """Analyze DHCP information for OS fingerprinting using comprehensive fingerprint matching
        
        Key elements analyzed:
        - DHCP Parameter Request List (Option 55)
        - DHCP Vendor Class Identifier (Option 60)
        - DHCP Host Name (Option 12) or DHCP User Class (Option 77)
        """
        results = []
        
        try:
            # 1. Analyze Parameter Request List (Option 55)
            if dhcp_options and 55 in dhcp_options:
                param_list = dhcp_options[55]
                # Windows typically requests these options in this order
                windows_params = [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 121, 249, 33]
                # Linux typically requests these options
                linux_params = [1, 3, 6, 12, 15, 28, 40, 41, 42, 119]
                # macOS/iOS typically requests these options
                apple_params = [1, 3, 6, 15, 7, 31, 33, 43, 44, 46, 47, 95, 252]
                
                if all(p in param_list for p in windows_params):
                    results.append("Windows")
                elif all(p in param_list for p in linux_params):
                    results.append("Linux")
                elif all(p in param_list for p in apple_params):
                    results.append("macOS/iOS")
            
            # 2. Analyze Vendor Class Identifier (Option 60)
            if vendor_class:
                vendor_class = vendor_class.lower()
                # Windows patterns
                if any(x in vendor_class for x in ["msft", "microsoft", "windows"]):
                    results.append("Windows")
                # Apple patterns
                elif any(x in vendor_class for x in ["apple", "macos", "ios"]):
                    results.append("macOS/iOS")
                # Android patterns
                elif any(x in vendor_class for x in ["android", "google"]):
                    results.append("Android")
                # Linux patterns
                elif any(x in vendor_class for x in ["linux", "ubuntu", "debian", "redhat"]):
                    results.append("Linux")
                # Network equipment patterns
                elif any(x in vendor_class for x in ["cisco", "juniper", "arista", "hp"]):
                    results.append("Network Equipment")
            
            # 3. Analyze Host Name (Option 12) or User Class (Option 77)
            if hostname:
                hostname = hostname.lower()
                if any(x in hostname for x in ["windows", "win", "pc"]):
                    results.append("Windows")
                elif any(x in hostname for x in ["mac", "apple", "imac", "macbook"]):
                    results.append("macOS/iOS")
                elif any(x in hostname for x in ["android", "galaxy", "samsung"]):
                    results.append("Android")
                elif any(x in hostname for x in ["linux", "ubuntu", "debian", "fedora"]):
                    results.append("Linux")
            
            if user_class:
                user_class = user_class.lower()
                if any(x in user_class for x in ["msft", "windows"]):
                    results.append("Windows")
                elif any(x in user_class for x in ["apple", "macos"]):
                    results.append("macOS/iOS")
                elif any(x in user_class for x in ["android"]):
                    results.append("Android")
                elif any(x in user_class for x in ["linux"]):
                    results.append("Linux")
            
            # Return unique results
            return list(set(results))
            
        except Exception as e:
            logger.error(f"Error analyzing DHCP information: {e}")
            return []

    def analyze_mdns(self, services, txt_records, hinfo_records):
        """Analyze mDNS information for OS fingerprinting"""
        results = []
        
        try:
            # Analyze services
            if services:
                for service in services:
                    service = service.lower()
                    if "apple" in service:
                        results.append("macOS/iOS")
                    elif "google" in service:
                        results.append("Android")
                    elif "microsoft" in service:
                        results.append("Windows")
                    elif "linux" in service:
                        results.append("Linux")
                        
            # Analyze TXT records
            if txt_records:
                for record in txt_records:
                    record = record.lower()
                    if "apple" in record:
                        results.append("macOS/iOS")
                    elif "google" in record:
                        results.append("Android")
                    elif "microsoft" in record:
                        results.append("Windows")
                    elif "linux" in record:
                        results.append("Linux")
                        
            # Analyze HINFO records
            if hinfo_records:
                for record in hinfo_records:
                    record = record.lower()
                    if "apple" in record:
                        results.append("macOS/iOS")
                    elif "google" in record:
                        results.append("Android")
                    elif "microsoft" in record:
                        results.append("Windows")
                    elif "linux" in record:
                        results.append("Linux")
                        
            # Return unique results
            return list(set(results))
            
        except Exception as e:
            logger.error(f"Error analyzing mDNS information: {e}")
            return []

    def analyze_ssdp(self, requests):
        """Analyze SSDP requests for OS fingerprinting"""
        results = []
        
        try:
            if requests:
                for request in requests:
                    request = request.lower()
                    if "windows" in request:
                        results.append("Windows")
                    elif "apple" in request:
                        results.append("macOS/iOS")
                    elif "android" in request:
                        results.append("Android")
                    elif "linux" in request:
                        results.append("Linux")
                        
            # Return unique results
            return list(set(results))
            
        except Exception as e:
            logger.error(f"Error analyzing SSDP requests: {e}")
            return []

    def analyze_vendor(self, vendor_info, dhcp_vendor_class=None, dhcp_hostname=None):
        """Analyze vendor information for OS fingerprinting"""
        results = []
        
        try:
            # Analyze vendor info
            if vendor_info:
                vendor_info = vendor_info.lower()
                if "apple" in vendor_info:
                    results.append("macOS/iOS")
                elif "microsoft" in vendor_info:
                    results.append("Windows")
                elif "google" in vendor_info:
                    results.append("Android")
                elif "linux" in vendor_info:
                    results.append("Linux")
                    
            # Analyze DHCP vendor class
            if dhcp_vendor_class:
                dhcp_vendor_class = dhcp_vendor_class.lower()
                if "msft" in dhcp_vendor_class:
                    results.append("Windows")
                elif "apple" in dhcp_vendor_class:
                    results.append("macOS/iOS")
                elif "android" in dhcp_vendor_class:
                    results.append("Android")
                elif "linux" in dhcp_vendor_class:
                    results.append("Linux")
                    
            # Analyze DHCP hostname
            if dhcp_hostname:
                dhcp_hostname = dhcp_hostname.lower()
                if "windows" in dhcp_hostname:
                    results.append("Windows")
                elif "mac" in dhcp_hostname or "apple" in dhcp_hostname:
                    results.append("macOS/iOS")
                elif "android" in dhcp_hostname:
                    results.append("Android")
                elif "linux" in dhcp_hostname:
                    results.append("Linux")
                    
            # Return unique results
            return list(set(results))
            
        except Exception as e:
            logger.error(f"Error analyzing vendor information: {e}")
            return []

    def determine_device_type(self, analysis):
        """Determine device type based on OUI and analysis results"""
        try:
            # First check OUI-based device types
            vendor = analysis.get('vendor', '').lower()
            
            # Network equipment manufacturers
            network_manufacturers = {
                'cisco': 'Network device',
                'juniper': 'Network device',
                'arista': 'Network device',
                'brocade': 'Network device',
                'extreme': 'Network device',
                'hp': 'Network device',  # HP networking equipment
                'dell': 'Network device',  # Dell networking equipment
                'fortinet': 'Network device',
                'palo alto': 'Network device',
                'check point': 'Network device'
            }
            
            # Printers and copiers
            printer_manufacturers = {
                'xerox': 'Printer/Copier',
                'canon': 'Printer/Copier',
                'brother': 'Printer/Copier',
                'ricoh': 'Printer/Copier',
                'kyocera': 'Printer/Copier',
                'lexmark': 'Printer/Copier',
                'epson': 'Printer/Copier',
                'seikoeps': 'Printer/Copier',
                'seiko epson': 'Printer/Copier',
                'konica': 'Printer/Copier',
                'minolta': 'Printer/Copier'
            }
            
            # IoT and smart home devices
            iot_manufacturers = {
                'nest': 'IoT device',
                'ring': 'IoT device',
                'arlo': 'IoT device',
                'wyze': 'IoT device',
                'philips hue': 'IoT device',
                'smartthings': 'IoT device',
                'wemo': 'IoT device',
                'tplink': 'IoT device',
                'dlink': 'IoT device',
                'belkin': 'IoT device',
                'amazon': 'IoT device',
                'google': 'IoT device',
                'apple': 'IoT device',  # Default for Apple IoT devices
                'omrontat': 'IoT device',
                'keyence': 'IoT device',
                'saxa': 'IoT device'
            }
            
            # Camera manufacturers
            camera_manufacturers = {
                'vivotek': 'Camera',
                'hikvision': 'Camera',
                'dahua': 'Camera',
                'axis': 'Camera',
                'bosch': 'Camera'
            }
            
            # Check for specific manufacturers
            for manufacturers, device_type in [
                (network_manufacturers, 'Network device'),
                (printer_manufacturers, 'Printer/Copier'),
                (iot_manufacturers, 'IoT device'),
                (camera_manufacturers, 'Camera')
            ]:
                for manufacturer in manufacturers:
                    if manufacturer in vendor:
                        return device_type
            
            # Special handling for Apple devices
            if 'apple' in vendor:
                # Check for AirPort devices (network equipment with Apple vendor)
                if "Network equipment" in analysis.get('ttl', ''):
                    return 'Network device'
                # Check for specific Apple device types
                if any(service in str(analysis.get('mdns_services', [])).lower() 
                      for service in ['_airplay', '_homekit']):
                    return 'IoT device'
                elif any(service in str(analysis.get('mdns_services', [])).lower() 
                        for service in ['_companion-link', '_apple-mobdev2']):
                    return 'Mobile device'
                else:
                    return 'Computer'
            
            # If OUI-based detection fails, use analysis-based detection
            if "Network equipment" in analysis.get('ttl', ''):
                return "Network equipment"
                
            # Check for mobile devices
            if "Android" in analysis.get('dhcp', []) or "Android" in analysis.get('mdns', []):
                return "Mobile device"
            if "iOS" in analysis.get('mdns', []):
                return "Mobile device"
                
            # Check for desktop/laptop
            if "Windows" in analysis.get('dhcp', []) or "Windows" in analysis.get('mdns', []):
                return "Desktop/Laptop"
            if "macOS" in analysis.get('dhcp', []) or "macOS" in analysis.get('mdns', []):
                return "Desktop/Laptop"
            if "Linux" in analysis.get('dhcp', []) or "Linux" in analysis.get('mdns', []):
                return "Desktop/Laptop"
                
            # Default to unknown
            return "Unknown"
            
        except Exception as e:
            logger.error(f"Error determining device type: {e}")
            return "Unknown"

    def determine_final_os(self, analysis):
        """Determine final OS based on weighted scoring of all indicators"""
        try:
            # Initialize scores
            scores = defaultdict(float)
            
            # Weight for each indicator
            weights = {
                'mdns': 4.0,      # mDNS is very reliable
                'ssdp': 3.5,      # SSDP is quite reliable
                'dhcp': 3.0,      # DHCP is reliable
                'p0f': 3.0,       # p0f is reliable
                'ttl': 2.5,       # TTL is somewhat reliable
                'vendor': 2.0,    # Vendor info is somewhat reliable
                'ip_id': 1.5,     # IP ID is less reliable
                'arp': 0.5        # ARP is least reliable
            }
            
            # Score each indicator
            for indicator, weight in weights.items():
                if indicator in analysis:
                    value = analysis[indicator]
                    if isinstance(value, list):
                        for os_type in value:
                            scores[os_type] += weight
                    else:
                        scores[value] += weight
                        
            # Get the OS with highest score
            if scores:
                return max(scores.items(), key=lambda x: x[1])[0]
            else:
                return "Unknown"
                
        except Exception as e:
            logger.error(f"Error determining final OS: {e}")
            return "Unknown"

    def analyze_p0f(self, tcp_signatures):
        """Analyze TCP signatures using p0f"""
        if not tcp_signatures or not self.p0f_matcher:
            return []
            
        try:
            results = []
            for signature in tcp_signatures:
                os_type = self.p0f_matcher.match(signature)
                if os_type:
                    results.append(os_type)
                    
            # Return unique results
            return list(set(results))
            
        except Exception as e:
            logger.error(f"Error analyzing p0f signatures: {e}")
            return []

    def analyze_tcp(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze TCP SYN fingerprint in p0f format"""
        result = {
            'ttl': None,
            'mss': None,
            'window': None,
            'options': None,
            'quirks': None,
            'p0f_match': None
        }
        
        if 'tcp_syn' not in entry:
            return result
            
        tcp_syn = entry['tcp_syn']
        
        # Store raw values
        result['ttl'] = tcp_syn.get('ttl')
        result['mss'] = tcp_syn.get('mss')
        result['window'] = tcp_syn.get('window')
        result['options'] = tcp_syn.get('options')
        result['quirks'] = tcp_syn.get('quirks')
        
        # Try to match with p0f signatures
        if self.p0f_matcher:
            try:
                # Convert our format to p0f signature string
                sig_str = f"{result['ttl']}:{result['window']}:{result['mss']}:{result['options']}:{result['quirks']}"
                match = self.p0f_matcher.match_signature(sig_str)
                if match:
                    result['p0f_match'] = {
                        'os': match.os_type,
                        'name': match.os_name,
                        'version': match.os_version
                    }
            except Exception as e:
                logger.error(f"Error matching p0f signature: {e}")
        
        return result

    @measure_time
    def analyze_entry(self, mac, entry):
        """Analyze a single MAC entry"""
        try:
            # Initialize analysis dictionary
            analysis = {}
            
            # Get vendor information
            vendor_info = self._get_vendor_info(mac)
            analysis['vendor'] = vendor_info
            
            # Analyze TTL values
            ttl_result = self.analyze_ttl(entry.ttl_values, vendor_info, entry.mdns_services)
            analysis['ttl'] = ttl_result
            
            # Analyze IP ID sequence
            ip_id_result = self.analyze_ip_id_sequence(entry.ip_id_values)
            analysis['ip_id'] = ip_id_result
            
            # Analyze DHCP information
            dhcp_result = self.analyze_dhcp(
                entry.dhcp_options,
                entry.dhcp_vendor_class,
                entry.dhcp_hostname,
                entry.dhcp_user_class
            )
            analysis['dhcp'] = dhcp_result
            
            # Analyze mDNS information
            mdns_result = self.analyze_mdns(
                entry.mdns_services,
                entry.mdns_txt_records,
                entry.mdns_hinfo
            )
            analysis['mdns'] = mdns_result
            
            # Analyze SSDP requests
            ssdp_result = self.analyze_ssdp(entry.ssdp_requests)
            analysis['ssdp'] = ssdp_result
            
            # Analyze p0f signatures
            p0f_result = self.analyze_p0f(entry.tcp_signatures)
            analysis['p0f'] = p0f_result
            
            # Analyze TCP characteristics
            tcp_result = self.analyze_tcp(entry)
            analysis['tcp'] = tcp_result
            
            # Determine device type
            device_type = self.determine_device_type(analysis)
            analysis['device_type'] = device_type
            
            # Determine final OS
            final_os = self.determine_final_os(analysis)
            analysis['final_os'] = final_os
            
            # Add MAC address to analysis
            analysis['mac_address'] = mac
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing entry for MAC {mac}: {e}")
            return None

    @measure_time
    def analyze_all(self):
        """Analyze all entries in the database"""
        try:
            results = []
            
            # Get all entries
            with self.storage.env.begin() as txn:
                cursor = txn.cursor()
                
                for key, value in cursor:
                    mac = key.decode()
                    logger.info(f"\nProcessing MAC: {mac}")
                    
                    # Log raw data
                    logger.info(f"Raw data length: {len(value)} bytes")
                    logger.info(f"Raw data (hex): {value.hex()}")
                    
                    # Unpack the entry
                    entry = self.storage._unpack_mac_entry(mac, value)
                    
                    # Log unpacked data
                    logger.info(f"Unpacked entry fields:")
                    logger.info(f"  TCP Signatures: {entry.tcp_signatures}")
                    logger.info(f"  TCP Options: {entry.tcp_options}")
                    logger.info(f"  MSS Values: {entry.mss_values}")
                    logger.info(f"  Window Scale: {entry.window_scale}")
                    logger.info(f"  TCP Window: {entry.tcp_window}")
                    logger.info(f"  TTL Values: {entry.ttl_values}")
                    logger.info(f"  DF Flags: {entry.df_flags}")
                    
                    # Analyze the entry
                    analysis = self.analyze_entry(mac, entry)
                    if analysis:
                        logger.info(f"Analysis result: {analysis}")
                        results.append(analysis)
                    else:
                        logger.warning(f"Failed to analyze MAC: {mac}")
                        
            # Save all results
            if results:
                self.save_results(results)
                logger.info(f"Analyzed {len(results)} devices")
            else:
                logger.warning("No devices found in the database")
                
            return results
            
        except Exception as e:
            logger.error(f"Error analyzing all entries: {e}")
            return []

    def save_results(self, results, output_file=None):
        """Save analysis results to CSV file"""
        try:
            # Create results directory if it doesn't exist
            if not os.path.exists(self.results_dir):
                os.makedirs(self.results_dir)
                
            # Use default filename if none provided
            if output_file is None:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_file = os.path.join(self.results_dir, f'analysis_{timestamp}.csv')
            
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow([
                    'MAC Address',
                    'Vendor',
                    'TTL Analysis',
                    'IP ID Analysis',
                    'DHCP Analysis',
                    'mDNS Analysis',
                    'SSDP Analysis',
                    'p0f Analysis',
                    'Device Type',
                    'Final OS'
                ])
                
                # Write data
                for result in results:
                    writer.writerow([
                        result.get('mac_address', ''),
                        result.get('vendor', ''),
                        result.get('ttl', ''),
                        result.get('ip_id', ''),
                        ', '.join(result.get('dhcp', [])),
                        ', '.join(result.get('mdns', [])),
                        ', '.join(result.get('ssdp', [])),
                        ', '.join(result.get('p0f', [])),
                        result.get('device_type', ''),
                        result.get('final_os', '')
                    ])
                    
            logger.info(f"Saved {len(results)} results to {output_file}")
            
        except Exception as e:
            logger.error(f"Error saving results: {e}")

def main():
    """Main function"""
    try:
        analyzer = OSAnalyzer()
        results = analyzer.analyze_all()
        
        if results:
            logger.info(f"Analysis completed. Found {len(results)} devices.")
        else:
            logger.warning("No devices found in the database.")
            
        # Ensure we close the storage properly
        analyzer.storage.close()
        
    except Exception as e:
        logger.error(f"Error in main: {e}")

if __name__ == "__main__":
    main() 