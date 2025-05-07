#!/usr/bin/env python3

import logging
import sys
import time
import os
from datetime import datetime, timedelta
from scapy.config import conf
conf.use_pcap = True
from scapy.all import Ether, Dot1Q, sniff, IP, TCP, UDP, DHCP, DNS, Raw, AsyncSniffer
import lmdb
import msgspec
from typing import Optional, Dict, Set, List
import shutil
import threading

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('packet_capture.log')
    ]
)
logger = logging.getLogger(__name__)

# Global variables
last_cleanup_time = 0
packet_count = 0  # Add global packet counter
db_handle = {}  # Dictionary to share LMDB handle
write_lock = threading.Lock()  # Lock for LMDB write operations

# Database configuration
DB_CONFIG = {
    'max_size_mb': 6144,  # Maximum database size in MB (6GB)
    'entry_expiration_hours': 24,  # MAC entries expire after 24 hours
    'cleanup_interval_seconds': 300  # Check for expired entries every 5 minutes
}

def get_db_size_mb(db_path: str) -> float:
    """Get current database size in MB"""
    try:
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(db_path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                total_size += os.path.getsize(fp)
        return total_size / (1024 * 1024)  # Convert to MB
    except Exception as e:
        logger.error(f"Error getting database size: {e}")
        return 0

def cleanup_old_entries():
    """Remove expired MAC entries"""
    global last_cleanup_time
    current_time = time.time()
    
    # Check if enough time has passed since last cleanup
    if current_time - last_cleanup_time < DB_CONFIG['cleanup_interval_seconds']:
        logger.debug(f"Skipping cleanup - next cleanup in {DB_CONFIG['cleanup_interval_seconds'] - (current_time - last_cleanup_time):.0f} seconds")
        return
        
    logger.info(f"Starting cleanup of expired entries (last cleanup was {current_time - last_cleanup_time:.0f} seconds ago)")
    expiration_time = current_time - (DB_CONFIG['entry_expiration_hours'] * 3600)  # Convert hours to seconds
    
    # Use a single transaction for both reading and writing
    with write_lock:  # Acquire write lock
        with db_handle['env'].begin(write=True) as txn:
            # Get all entries and check expiration
            entries_to_remove = []
            cursor = txn.cursor()
            for key, value in cursor:
                entry = msgspec.msgpack.decode(value)
                if entry['last_seen'] < expiration_time:
                    entries_to_remove.append(key)
            cursor.close()
            
            # Remove expired entries
            for key in entries_to_remove:
                txn.delete(key)
    
    if entries_to_remove:
        logger.info(f"Cleanup completed. Removed {len(entries_to_remove)} expired entries")
    else:
        logger.info("No expired entries found")
        
    last_cleanup_time = current_time

def create_mac_entry(mac: str, vlan_id: Optional[int] = None) -> dict:
    """Create a new MAC entry dictionary with all detection methods"""
    return {
        'mac_address': mac,
        'first_seen': time.time(),
        'last_seen': time.time(),
        'vlan_id': vlan_id,
        
        # DHCP fingerprinting
        'dhcp_fingerprint': {
            'parameter_list': None,  # Option 55
            'vendor_id': None,       # Option 60
            'hostname': None,        # Option 12
            'user_class': None       # Option 77
        },
        
        # mDNS detection
        'mdns_services': {
            '_device-info._tcp.local': {'txt': {}, 'model': None, 'osxvers': None, 'deviceid': None, 'osv': None, 'firmwarever': None},
            '_smb._tcp.local': {'txt': {}},
            '_ipp._tcp.local': {'txt': {}},
            '_workstation._tcp.local': {'txt': {}}
        },
        
        # SSDP detection
        'ssdp_headers': {
            'server': None,
            'bootid': None,
            'mx': None,
            'cache_control': None,
            'location': None
        },
        
        # TCP SYN fingerprinting
        'tcp_syn': {
            'olen': None,
            'ttl': None,
            'tos': None,
            'mss': None,
            'win': None,
            'opts': None,
            'quirks': None,
            'pclass': None
        },
        
        # OUI analysis
        'oui_analysis': {
            'vendor_name': None,
            'category': None,
            'source': None  # 'nmap' or 'manual_map'
        }
    }

def get_mac_entry(mac: str) -> dict:
    """Get MAC entry from LMDB"""
    try:
        with db_handle['env'].begin() as txn:
            data = txn.get(mac.encode())
            if data is None:
                logger.debug(f"Creating new entry for {mac}")
                return create_mac_entry(mac)
            entry = msgspec.msgpack.decode(data)
            logger.debug(f"Retrieved existing entry for {mac}")
            return entry
    except Exception as e:
        logger.error(f"Error getting MAC entry: {e}")
        return create_mac_entry(mac)

def save_mac_entry(mac: str, entry: dict):
    """Save MAC entry to LMDB"""
    logger.info(f"Saving entry for {mac}")
    
    # Log LMDB environment status before operation
    try:
        env = db_handle['env']
        logger.debug(f"[LMDB] Status before save: map_size={env.info()['map_size']}, last_pgno={env.info()['last_pgno']}")
    except Exception as e:
        logger.error(f"[LMDB] Error checking status: {e}")
        return
        
    try:
        # Single transaction for save and verify
        with write_lock:  # Acquire write lock
            with db_handle['env'].begin(write=True) as txn:
                data = msgspec.msgpack.encode(entry)
                txn.put(mac.encode(), data)
                
                # Verify within the same transaction
                verify = txn.get(mac.encode())
                if verify:
                    logger.debug(f"Verified write for {mac} (size: {len(verify)} bytes)")
                else:
                    logger.error(f"Failed to verify write for {mac}")
                    raise Exception("Write verification failed")
            
    except Exception as e:
        logger.error(f"Error saving entry for {mac}: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return
        
    # Check if cleanup is needed, but don't do it here
    if time.time() - last_cleanup_time >= DB_CONFIG['cleanup_interval_seconds']:
        logger.debug("Cleanup needed, but skipping in save_mac_entry")

def process_dhcp_packet(pkt, entry: dict) -> None:
    """Process DHCP packet for OS detection"""
    dhcp = pkt[DHCP]
    for opt in dhcp.options:
        if opt[0] == 'param_req_list':  # Option 55
            entry['dhcp_fingerprint']['parameter_list'] = opt[1]
        elif opt[0] == 'vendor_class_id':  # Option 60
            entry['dhcp_fingerprint']['vendor_id'] = opt[1]
        elif opt[0] == 'hostname':  # Option 12
            entry['dhcp_fingerprint']['hostname'] = opt[1]
        elif opt[0] == 'user_class':  # Option 77
            entry['dhcp_fingerprint']['user_class'] = opt[1]
    
    if any(entry['dhcp_fingerprint'].values()):
        logger.info(f"DHCP fingerprint for {entry['mac_address']}: {entry['dhcp_fingerprint']}")

def process_mdns_packet(pkt, entry: dict) -> None:
    """Process mDNS packet for OS detection"""
    dns = pkt[DNS]
    if dns.qr == 0:  # Query
        for q in dns.qd:
            if q.qtype == 12:  # PTR
                service = q.qname.decode()
                if service in entry['mdns_services']:
                    # Update service information
                    if hasattr(pkt, 'an') and pkt.an:
                        for rr in pkt.an:
                            if rr.type == 16:  # TXT record
                                txt = {}
                                for item in rr.txt:
                                    try:
                                        key, value = item.decode().split('=', 1)
                                        txt[key] = value
                                    except:
                                        continue
                                entry['mdns_services'][service]['txt'] = txt
                                
                                # Extract specific fields for device-info
                                if service == '_device-info._tcp.local':
                                    entry['mdns_services'][service].update({
                                        'model': txt.get('model'),
                                        'osxvers': txt.get('osxvers'),
                                        'deviceid': txt.get('deviceid'),
                                        'osv': txt.get('osv'),
                                        'firmwarever': txt.get('firmwarever')
                                    })
                    
                    logger.info(f"mDNS service {service} for {entry['mac_address']}: {entry['mdns_services'][service]}")

def process_ssdp_packet(pkt, entry: dict) -> None:
    """Process SSDP packet for OS detection"""
    if Raw in pkt:
        raw = pkt[Raw].load.decode('utf-8', errors='ignore')
        if 'M-SEARCH' in raw:
            # Parse headers
            headers = {}
            for line in raw.split('\r\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            # Update SSDP headers
            entry['ssdp_headers'].update({
                'server': headers.get('server'),
                'bootid': headers.get('bootid.upnp.org'),
                'mx': headers.get('mx'),
                'cache_control': headers.get('cache-control'),
                'location': headers.get('location')
            })
            
            logger.info(f"SSDP headers for {entry['mac_address']}: {entry['ssdp_headers']}")

def process_tcp_syn(pkt, entry: dict) -> None:
    """Process TCP SYN packet for OS detection"""
    tcp = pkt[TCP]
    ip = pkt[IP]
    
    # Calculate options length
    olen = len(tcp.options) * 4 if hasattr(tcp, 'options') else 0
    
    # Get MSS if present
    mss = None
    opts = []
    if hasattr(tcp, 'options'):
        for opt in tcp.options:
            if opt[0] == 'MSS':
                mss = opt[1]
                opts.append('mss')
            elif opt[0] == 'WScale':
                opts.append('ws')
            elif opt[0] == 'NOP':
                opts.append('nop')
            elif opt[0] == 'SAckOK':
                opts.append('sok')
            elif opt[0] == 'Timestamp':
                opts.append('ts')
            else:
                opts.append(opt[0])
    
    # Record quirks
    quirks = []
    if tcp.flags & 0x10:  # ACK flag in SYN
        quirks.append('ack+')
    if tcp.flags & 0x20:  # URG flag in SYN
        quirks.append('urg+')
    if tcp.flags & 0x40:  # PSH flag in SYN
        quirks.append('push+')
    
    # Store fingerprint in p0f format
    entry['tcp_syn'].update({
        'olen': str(olen),
        'ttl': str(ip.ttl),
        'tos': str(ip.tos),
        'mss': str(mss) if mss else '*',
        'win': str(tcp.window),
        'opts': ','.join(opts),
        'quirks': ','.join(quirks) if quirks else '*',
        'pclass': '?'  # To be determined by p0f signature matching
    })
    
    logger.info(f"TCP SYN fingerprint for {entry['mac_address']}: {entry['tcp_syn']}")

def process_packet(pkt):
    """Process a captured packet"""
    global packet_count
    packet_count += 1
    
    logger.debug(f"Got packet #{packet_count}: {pkt.summary()}")
    
    if not Dot1Q in pkt:
        logger.debug(f"Packet #{packet_count} has no VLAN tag, skipping")
        return
        
    mac = pkt[Ether].src
    vlan_id = pkt[Dot1Q].vlan
    
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

def main():
    """Main function"""
    global packet_count, db_handle
    sniffer = None
    packet_count = 0  # Reset counter at start
    
    logger.info(f"Main process started with PID: {os.getpid()}")
    logger.info(f"Parent process ID: {os.getppid()}")
    
    if len(sys.argv) < 2:
        logger.error("Usage: python main.py <interface> [--clear-db]")
        sys.exit(1)
        
    interface = sys.argv[1]
    clear_db = len(sys.argv) > 2 and sys.argv[2] == '--clear-db'
    
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
    finally:
        # First stop the sniffer and wait for it to finish
        if sniffer:
            logger.info("Stopping sniffer...")
            try:
                if sniffer.running:
                    logger.info("Sniffer is still running, stopping...")
                    sniffer.stop(join=False)  # Stop without waiting
                    logger.info("Waiting for sniffer to finish...")
                    sniffer.join(timeout=0.5)  # Wait up to 0.5 seconds for thread to finish
                    logger.info("Sniffer stopped")
                else:
                    logger.info("Sniffer was already stopped")
            except Exception as e:
                logger.error(f"Error stopping sniffer: {e}")
            
            # Only close database after sniffer is fully stopped
            if 'env' in db_handle and db_handle['env'] is not None:
                try:
                    logger.info("Closing database...")
                    db_handle['env'].close()
                    db_handle['env'] = None  # Clear the handle
                    logger.info("Database closed")
                except Exception as e:
                    logger.error(f"Error closing database: {e}")

if __name__ == "__main__":
    main()
