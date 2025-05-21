#!/usr/bin/env python3

from scapy.all import *
from pyp0f.database import DATABASE
from pyp0f.fingerprint import fingerprint_tcp
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load p0f database
DATABASE.load()

def create_test_packets():
    """Create test TCP SYN packets with different OS signatures"""
    packets = []
    
    # Linux-like packet
    linux_pkt = IP(
        tos=0x10,
        flags=0x02,
        ttl=64
    ) / TCP(
        seq=1234567890,
        window=29200,
        options=[
            ("MSS", 1460),
            ("SAckOK", b""),
            ("Timestamp", (1234567890, 0)),
            ("NOP", None),
            ("WScale", 7)
        ]
    )
    packets.append(("Linux", linux_pkt))
    
    # Windows-like packet
    windows_pkt = IP(
        tos=0x00,
        flags=0x02,
        ttl=128
    ) / TCP(
        seq=1234567890,
        window=65535,
        options=[
            ("MSS", 1460),
            ("SAckOK", b""),
            ("Timestamp", (1234567890, 0)),
            ("NOP", None),
            ("WScale", 8)
        ]
    )
    packets.append(("Windows", windows_pkt))
    
    # macOS-like packet
    macos_pkt = IP(
        tos=0x00,
        flags=0x02,
        ttl=64
    ) / TCP(
        seq=1234567890,
        window=65535,
        options=[
            ("MSS", 1460),
            ("SAckOK", b""),
            ("Timestamp", (1234567890, 0)),
            ("NOP", None),
            ("WScale", 6)
        ]
    )
    packets.append(("macOS", macos_pkt))
    
    return packets

def test_pyp0f():
    """Test pyp0f detection with created packets"""
    packets = create_test_packets()
    
    for os_name, pkt in packets:
        try:
            # Get TCP fingerprint using pyp0f
            result = fingerprint_tcp(pkt)
            
            # Log the results
            logger.info(f"\nTesting {os_name} packet:")
            logger.info(f"Packet details: {pkt.summary()}")
            logger.info(f"TCP options: {pkt[TCP].options}")
            
            if result and result.match:
                label = result.match.record.label
                logger.info(f"pyp0f detection result:")
                logger.info(f"  OS: {label.name}")
                logger.info(f"  OS Class: {label.os_class}")
                logger.info(f"  Flavor: {label.flavor}")
                logger.info(f"  Generic: {label.is_generic}")
            else:
                logger.warning("No match found in p0f database")
                
        except Exception as e:
            logger.error(f"Error processing {os_name} packet: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")

if __name__ == "__main__":
    test_pyp0f() 