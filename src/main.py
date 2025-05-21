#!/usr/bin/env python3

import logging
import sys
import time
import os
import argparse
from datetime import datetime, timedelta
from scapy.config import conf
conf.use_pcap = True
from scapy.all import Ether, Dot1Q, sniff, IP, TCP, UDP, DHCP, DNS, Raw, AsyncSniffer
import lmdb
import cbor2
from typing import Optional
import shutil
import threading
import lz4.frame
from pyp0f.database import DATABASE
from pyp0f.fingerprint import fingerprint_tcp
from pyp0f.fingerprint.results import TCPResult

# Load p0f database once at module level
DATABASE.load()

# Global variables
last_cleanup_time = 0
packet_count = 0  # Add global packet counter
db_handle = {}  # Dictionary to share LMDB handle
write_lock = threading.Lock()  # Lock for LMDB write operations
logger = None  # Global logger instance

# Database configuration
DB_CONFIG = {
    'max_size_mb': 6144,  # Maximum database size in MB (6GB)
    'entry_expiration_hours': 24,  # MAC entries expire after 24 hours
    'cleanup_interval_seconds': 300  # Check for expired entries every 5 minutes
}

def setup_logging(debug: bool = False):
    """Configure logging with appropriate level"""
    global logger
    
    # Remove any existing handlers
    root = logging.getLogger()
    if root.handlers:
        for handler in root.handlers:
            root.removeHandler(handler)
    
    # Set the log level
    log_level = logging.DEBUG if debug else logging.INFO
    
    # Configure logging
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('packet_capture.log')
        ]
    )
    
    # Set scapy logging level
    if debug:
        conf.logLevel = logging.DEBUG
    else:
        conf.logLevel = logging.INFO
    
    # Get our logger after configuration
    logger = logging.getLogger(__name__)
    logger.setLevel(log_level)
    
    return logger

def create_mac_entry(mac: str) -> dict:
    """Create a new MAC entry"""
    return {
        'mac_address': mac,
        'first_seen': time.time(),
        'last_seen': time.time()
    }

def get_mac_entry(mac: str) -> dict:
    """Get MAC entry from LMDB"""
    try:
        with db_handle['env'].begin() as txn:
            data = txn.get(mac.encode())
            if data is None:
                logger.debug(f"Creating new entry for {mac}")
                return create_mac_entry(mac)
            # Decompress the data
            decompressed_data = lz4.frame.decompress(data)
            entry = cbor2.loads(decompressed_data)
            logger.debug(f"Retrieved existing entry for {mac}")
            return entry
    except Exception as e:
        logger.error(f"Error getting MAC entry: {e}")
        return create_mac_entry(mac)

def save_mac_entry(mac: str, entry: dict) -> None:
    """Save MAC entry to LMDB"""
    try:
        with write_lock:
            with db_handle['env'].begin(write=True) as txn:
                # Compress the data
                compressed_data = lz4.frame.compress(cbor2.dumps(entry))
                txn.put(mac.encode(), compressed_data)
    except Exception as e:
        logger.error(f"Error saving MAC entry: {e}")

def process_tcp_syn(pkt, entry: dict) -> None:
    """Process TCP SYN packet for OS detection using pyp0f"""
    try:
        # Get TCP fingerprint using pyp0f
        result = fingerprint_tcp(pkt)
        if result and result.match:
            label = result.match.record.label
            # Store pyp0f detection results
            entry['p0f_detect'] = {
                'os': label.name,
                'os_class': label.os_class,
                'flavor': label.flavor,
                'generic': label.is_generic
            }
            logger.debug(f"TCP SYN fingerprint for {entry['mac_address']}: {entry['p0f_detect']}")
    except Exception as e:
        logger.error(f"Error processing TCP SYN packet: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")

def process_dhcp_packet(pkt, entry: dict) -> None:
    """Process DHCP packet for OS detection"""
    dhcp = pkt[DHCP]
    
    # Initialize DHCP data
    dhcp_data = {}
    
    # Process DHCP options
    for opt in dhcp.options:
        if opt[0] == 'param_req_list':  # Option 55
            # Add each parameter number individually
            params = [str(param) for param in opt[1]]
            if params:
                dhcp_data['parameter_list'] = params
                    
        elif opt[0] == 'vendor_class_id':  # Option 60
            value = str(opt[1])
            if value:
                dhcp_data['vendor_id'] = [value]
                
        elif opt[0] == 'hostname':  # Option 12
            value = str(opt[1])
            if value:
                dhcp_data['hostname'] = [value]
                
        elif opt[0] == 'user_class':  # Option 77
            value = str(opt[1])
            if value:
                dhcp_data['user_class'] = [value]
    
    if dhcp_data:
        # Convert parameter_list values to integers for final storage
        if 'parameter_list' in dhcp_data:
            dhcp_data['parameter_list'] = [int(x) for x in dhcp_data['parameter_list']]
        
        # Store DHCP fingerprint data
        entry['dhcp_fingerprint'] = dhcp_data
        logger.debug(f"DHCP fingerprint for {entry['mac_address']}: {dhcp_data}")

def process_mdns_packet(pkt, entry: dict) -> None:
    """Process mDNS packet for OS detection"""
    dns = pkt[DNS]
    
    try:
        # Process both query and response packets
        logger.debug(f"Processing mDNS packet for MAC {entry['mac_address']}")
        
        # Initialize mdns_services if needed
        if 'mdns_services' not in entry:
            entry['mdns_services'] = {
                'records': set(),  # Set of original record strings
                'cache_flush': set()  # Set of boolean cache flush flags
            }
        
        # Process answers
        if hasattr(dns, 'an') and dns.an:
            logger.debug(f"Found {len(dns.an)} answer records")
            
            for rr in dns.an:
                try:
                    logger.debug(f"Processing answer record type {rr.type}")
                    # Check cacheflush field directly
                    if hasattr(rr, 'cacheflush'):
                        logger.debug(f"Record type {rr.type} - cacheflush type: {type(rr.cacheflush)}, value: {rr.cacheflush}")
                        cache_flush = bool(rr.cacheflush)
                        logger.debug(f"Record type {rr.type} - cacheflush: {cache_flush}")
                        if cache_flush:
                            entry['mdns_services']['cache_flush'].add(True)
                            logger.debug(f"Added cache_flush=True for record type {rr.type}")
                    else:
                        logger.debug("No cacheflush field found in record")
                    
                    # Process SRV records
                    if rr.type == 33:  # SRV record
                        if hasattr(rr, 'rdata') and hasattr(rr, 'rrname'):
                            try:
                                srv_str = f"{rr.rrname.decode('utf-8', errors='ignore')} SRV {rr.priority} {rr.weight} {rr.port} {rr.target.decode('utf-8', errors='ignore')}"
                                entry['mdns_services']['records'].add(srv_str)
                            except Exception as e:
                                logger.debug(f"Error processing SRV record: {e}")
                    
                    # Process PTR records
                    elif rr.type == 12:  # PTR record
                        if hasattr(rr, 'rdata') and hasattr(rr, 'rrname'):
                            try:
                                ptr_str = f"{rr.rrname.decode('utf-8', errors='ignore')} PTR {rr.rdata.decode('utf-8', errors='ignore')}"
                                entry['mdns_services']['records'].add(ptr_str)
                            except Exception as e:
                                logger.debug(f"Error processing PTR record: {e}")
                    
                    # Process TXT records
                    elif rr.type == 16:  # TXT record
                        if hasattr(rr, 'txt') and rr.txt:
                            try:
                                for item in rr.txt:
                                    if isinstance(item, bytes):
                                        txt_str = item.decode('utf-8', errors='ignore')
                                    else:
                                        txt_str = str(item)
                                    entry['mdns_services']['records'].add(txt_str)
                            except Exception as e:
                                logger.debug(f"Error processing TXT record: {e}")
                    
                except Exception as e:
                    logger.debug(f"Error processing mDNS answer: {e}")
                    continue
        
        # Process questions (queries) as well
        if hasattr(dns, 'qd') and dns.qd:
            logger.debug(f"Found {len(dns.qd)} question records")
            
            for q in dns.qd:
                try:
                    if hasattr(q, 'qname'):
                        qname = q.qname.decode('utf-8', errors='ignore')
                        qtype = q.qtype
                        q_str = f"{qname} QTYPE {qtype}"
                        entry['mdns_services']['records'].add(q_str)
                        entry['mdns_services']['cache_flush'].add(False)  # Queries don't have cache flush
                except Exception as e:
                    logger.debug(f"Error processing mDNS question: {e}")
                    continue
        
        # Remove mdns_services if empty
        if 'mdns_services' in entry and not entry['mdns_services']['records']:
            del entry['mdns_services']
            logger.debug("Removed empty mdns_services field")
        
        # Log the current state of mDNS services
        if 'mdns_services' in entry and entry['mdns_services']:
            logger.debug(f"Current mDNS services for {entry['mac_address']}: {entry['mdns_services']}")
            
    except Exception as e:
        logger.error(f"Error in mDNS processing: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")

def process_ssdp_packet(pkt, entry: dict) -> None:
    """Process SSDP packet for OS detection"""
    if Raw in pkt:
        raw = pkt[Raw].load.decode('utf-8', errors='ignore')
        
        # Parse headers
        headers = {}
        header_order = []  # Track header order
        for line in raw.split('\r\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                headers[key.lower()] = value
                header_order.append(key)  # Store original case
        
        # Initialize SSDP data
        ssdp_data = {}
        
        # Store header order if present
        if header_order:
            ssdp_data['header_order'] = header_order
        
        # Process headers
        if 'server' in headers:
            value = str(headers['server'])
            if value:
                ssdp_data['server'] = [value]
                
        if 'bootid.upnp.org' in headers:
            value = str(headers['bootid.upnp.org'])
            if value:
                ssdp_data['bootid'] = [value]
                
        if 'mx' in headers:
            value = str(headers['mx'])
            if value:
                ssdp_data['mx'] = [value]
                
        if 'cache-control' in headers:
            value = str(headers['cache-control'])
            if value:
                ssdp_data['cache_control'] = [value]
                
        if 'location' in headers:
            value = str(headers['location'])
            if value:
                ssdp_data['location'] = [value]
                
        if 'nt' in headers:
            value = str(headers['nt'])
            if value:
                ssdp_data['nt'] = [value]
                
        if 'nts' in headers:
            value = str(headers['nts'])
            if value:
                ssdp_data['nts'] = [value]
                
        if 'usn' in headers:
            value = str(headers['usn'])
            if value:
                ssdp_data['usn'] = [value]
                
        if 'st' in headers:
            value = str(headers['st'])
            if value:
                ssdp_data['st'] = [value]
                
        if 'ext' in headers:
            value = str(headers['ext'])
            if value:
                ssdp_data['ext'] = [value]
                
        if 'date' in headers:
            value = str(headers['date'])
            if value:
                ssdp_data['date'] = [value]
            
        # Add packet type
        if raw.startswith('M-SEARCH'):
            value = 'm-search'
        elif raw.startswith('NOTIFY'):
            value = 'notify'
        elif raw.startswith('HTTP/1.1'):
            value = 'response'
        else:
            value = None
            
        if value:
            ssdp_data['types'] = [value]
                
        # Only add ssdp_headers if we have data
        if ssdp_data:
            entry['ssdp_headers'] = ssdp_data
            logger.debug(f"SSDP headers for {entry['mac_address']}: {ssdp_data}")

def process_packet(pkt):
    """Process a captured packet"""
    global packet_count
    packet_count += 1
    
    try:
        logger.debug(f"Got packet #{packet_count}: {pkt.summary()}")
        
        # Check for VLAN tag
        if not Dot1Q in pkt:
            logger.debug(f"Packet #{packet_count} has no VLAN tag, skipping")
            return
            
        mac = pkt[Ether].src
        vlan_id = pkt[Dot1Q].vlan
        
        # Validate VLAN ID (1-4094)
        if vlan_id < 1 or vlan_id > 4094:
            logger.warning(f"Invalid VLAN ID {vlan_id} detected, skipping packet")
            return
        
        logger.debug(f"Processing packet #{packet_count}: VLAN={vlan_id}, MAC={mac}")
        
        entry = get_mac_entry(mac)
        entry['last_seen'] = time.time()
        entry['vlan_id'] = vlan_id
        
        # Process TCP packets for SYN fingerprinting
        if TCP in pkt:
            if pkt[TCP].flags & 0x02:  # SYN flag
                logger.debug(f"TCP SYN detected: VLAN={vlan_id}, MAC={mac}")
                process_tcp_syn(pkt, entry)
        
        # Process UDP packets
        elif UDP in pkt:
            udp = pkt[UDP]
            
            # DHCP fingerprinting
            if udp.sport in [67, 68] or udp.dport in [67, 68]:
                if DHCP in pkt:
                    logger.debug(f"DHCP packet detected: VLAN={vlan_id}, MAC={mac}")
                    process_dhcp_packet(pkt, entry)
            
            # mDNS detection
            elif udp.sport == 5353 or udp.dport == 5353:
                if DNS in pkt:
                    logger.debug(f"mDNS packet detected: VLAN={vlan_id}, MAC={mac}")
                    process_mdns_packet(pkt, entry)
            
            # SSDP detection
            elif udp.sport == 1900 or udp.dport == 1900:
                logger.debug(f"SSDP packet detected: VLAN={vlan_id}, MAC={mac}")
                process_ssdp_packet(pkt, entry)
        
        # Save the entry
        save_mac_entry(mac, entry)
        
        if packet_count % 100 == 0:
            logger.info(f"Processed {packet_count} packets")
            
    except Exception as e:
        logger.error(f"Error processing packet #{packet_count}: {e}")
        logger.error(f"Packet summary: {pkt.summary()}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        # Don't re-raise the exception to keep the sniffer running

def main():
    """Main function"""
    global packet_count, db_handle
    sniffer = None
    packet_count = 0  # Reset counter at start
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Network packet capture and OS detection')
    parser.add_argument('interface', help='Network interface to capture packets from')
    parser.add_argument('--clear-db', action='store_true', help='Clear the database before starting')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()
    
    # Setup logging based on debug flag and get logger
    logger = setup_logging(args.debug)
    
    logger.info(f"Main process started with PID: {os.getpid()}")
    logger.info(f"Parent process ID: {os.getppid()}")
    logger.info(f"Debug mode: {'enabled' if args.debug else 'disabled'}")
    
    interface = args.interface
    clear_db = args.clear_db
    
    # Initialize database
    logger.info("Initializing LMDB")
    db_path = os.path.abspath('mac_data.mdb')
    
    if clear_db:
        logger.info("Clearing database")
        if os.path.exists(db_path):
            shutil.rmtree(db_path)
    
    try:
        # Calculate map_size based on max_size_mb (convert MB to bytes)
        map_size = DB_CONFIG['max_size_mb'] * 1024 * 1024
        logger.info(f"Opening LMDB with map_size={map_size} bytes ({DB_CONFIG['max_size_mb']}MB)")
        db_handle['env'] = lmdb.open(db_path, max_dbs=0, map_size=map_size)
        
        # Set BPF filter to capture all relevant packets
        bpf_expr = (
            "vlan and ("
              "(tcp[tcpflags] & tcp-syn != 0) or "
              "(udp port 67 or udp port 68 or udp port 5353 or udp port 1900)"
            ")"
        )
        logger.info(f"Starting capture with filter: {bpf_expr}")
        
        # Create and start the sniffer
        sniffer = AsyncSniffer(
            iface=interface,
            filter=bpf_expr,
            prn=process_packet,
            store=0
        )
        
        logger.info("Starting packet capture...")
        sniffer.start()
        logger.info("Sniffer started successfully")
        
        # Main loop that can be interrupted
        while True:
            time.sleep(1)  # Check for signals every second
            if not sniffer.running:
                logger.error("Sniffer stopped unexpectedly!")
                break
            
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received")
    except Exception as e:
        logger.error(f"Error: {e}")
        logger.error(f"Error type: {type(e)}")
        logger.error(f"Error details: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 