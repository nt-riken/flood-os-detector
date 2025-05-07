import time
from typing import Dict

def create_mac_entry(mac_address: str, vlan_id: int = None) -> Dict:
    """Create a new MAC entry dictionary"""
    return {
        'mac_address': mac_address,
        'vlan_id': vlan_id,
        'first_seen': time.time(),
        'last_seen': time.time(),
        'vendor_class_id': None,
        'ttl_values': [],  # List of TTL values
        'ip_id_values': [],  # List of IP ID values
        'df_flags': [],  # List of DF flags
        'tcp_options': [],  # List of TCP options in order
        'window_sizes': [],  # List of window sizes
        'dhcp_options': [],  # List of DHCP options
        'dhcp_parameter_list': [],  # List of DHCP parameters
        'dhcp_vendor_class': [],  # List of DHCP vendor classes
        'dhcp_hostname': None,  # DHCP hostname
        'mdns_services': [],  # List of mDNS services
        'mdns_txt_records': [],  # List of mDNS TXT records
        'mdns_hinfo': [],  # List of mDNS HINFO records
        'ssdp_requests': [],  # List of SSDP requests
        'arp_requests': [],  # List of ARP requests
        'arp_responses': [],  # List of ARP responses
        'tcp_signatures': [],  # List of TCP signatures
        'mss_values': [],  # List of observed MSS values
        'window_scale': [],  # List of observed window scale values
        'tcp_window': None,  # Latest TCP window size
        'tos_values': []  # List of TOS values
    } 