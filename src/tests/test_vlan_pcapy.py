#!/usr/bin/env python3

from scapy.config import conf
conf.use_pcap = True
from scapy.all import Ether, Dot1Q, sniff, IP, TCP, UDP
import logging
import sys
import time

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def process_packet(pkt):
    """Process a captured packet"""
    try:
        logger.info("=== New Packet Received ===")
        
        if Ether in pkt:
            logger.info(f"Source MAC: {pkt[Ether].src}")
            logger.info(f"Destination MAC: {pkt[Ether].dst}")
            logger.info(f"Ethernet type: {hex(pkt[Ether].type)}")
        
        if Dot1Q in pkt:
            logger.info(f"VLAN ID: {pkt[Dot1Q].vlan}")
            logger.info(f"VLAN priority: {pkt[Dot1Q].prio}")
            logger.info(f"VLAN type: {hex(pkt[Dot1Q].type)}")
        
        if IP in pkt:
            logger.info(f"Source IP: {pkt[IP].src}")
            logger.info(f"Destination IP: {pkt[IP].dst}")
        
        if TCP in pkt:
            logger.info(f"TCP source port: {pkt[TCP].sport}")
            logger.info(f"TCP destination port: {pkt[TCP].dport}")
        
        if UDP in pkt:
            logger.info(f"UDP source port: {pkt[UDP].sport}")
            logger.info(f"UDP destination port: {pkt[UDP].dport}")
            
        logger.info("-" * 50)
            
    except Exception as e:
        logger.error(f"Error processing packet: {e}")
        logger.error(f"Packet layers: {pkt.layers() if 'pkt' in locals() else 'No packet available'}")

def main():
    if len(sys.argv) < 2:
        logger.error("Usage: python test_vlan_pcapy.py <interface>")
        sys.exit(1)
        
    interface = sys.argv[1]
    
    try:
        # Set BPF filter
        bpf_expr = (
            "vlan and ("
              "(tcp[tcpflags] & tcp-syn != 0) or "
              "(udp port 67 or udp port 68 or udp port 5353 or udp port 1900)"
            ")"
        )
        logger.info(f"Starting capture on interface {interface} with filter: {bpf_expr}")
        logger.info("Press Ctrl+C to stop capture")
        
        # Use sniff with pcap backend
        packets = sniff(iface=interface,
                       filter=bpf_expr,
                       timeout=10,
                       prn=process_packet,
                       store=0)
        
        logger.info("Capture completed")
        
    except KeyboardInterrupt:
        logger.info("\nCapture stopped by user")
    except Exception as e:
        logger.error(f"Error: {e}")
        logger.error(f"Error type: {type(e)}")
        logger.error(f"Error details: {str(e)}")

if __name__ == "__main__":
    main() 