#!/usr/bin/env python3

import sys
import json
import logging
import csv
import signal
from pathlib import Path
from typing import Dict, Optional, Dict

# Configure logging
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger(__name__)

# Handle SIGPIPE gracefully
signal.signal(signal.SIGPIPE, signal.SIG_DFL)

class OUIAnalyzer:
    def __init__(self, oui_file: str = "oui.csv"):
        """Initialize OUI analyzer with database file."""
        self.oui_file = Path(oui_file)
        if not self.oui_file.exists():
            logger.error(f"OUI database file not found: {self.oui_file}")
            sys.exit(1)
        logger.info(f"Using OUI database: {self.oui_file}")
        self.oui_db: Dict[str, Dict[str, str]] = {}
        self._load_oui_db()

    def _load_oui_db(self) -> None:
        """Load OUI database from CSV file."""
        try:
            with open(self.oui_file, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                # Get header row
                headers = next(reader)
                for row in reader:
                    if len(row) >= 4:  # Need all fields: Registry, Assignment, Organization Name, Address
                        oui = row[1].strip().upper()  # Assignment column
                        self.oui_db[oui] = {
                            'registry': row[0].strip(),
                            'assignment': oui,
                            'organization_name': row[2].strip(),
                            'organization_address': row[3].strip()
                        }
                        if len(self.oui_db) <= 5:  # Log first 5 entries for verification
                            logger.info(f"Loaded OUI entry: {oui} -> {self.oui_db[oui]}")
            logger.info(f"Loaded {len(self.oui_db)} OUI entries")
        except Exception as e:
            logger.error(f"Error loading OUI database: {e}")
            sys.exit(1)

    def get_vendor_info(self, mac: str) -> Optional[Dict[str, str]]:
        """Get vendor information for MAC address."""
        try:
            # Extract OUI (first 6 characters) and normalize
            oui = mac.replace(':', '').replace('-', '')[:6].upper()
            vendor_info = self.oui_db.get(oui)
            if vendor_info:
                logger.debug(f"Found vendor info for MAC {mac}: {vendor_info}")
            else:
                logger.debug(f"No vendor info found for MAC {mac}")
            return vendor_info
        except Exception as e:
            logger.error(f"Error processing MAC {mac}: {e}")
            return None

    def is_random_mac(self, mac: str) -> bool:
        """Check if MAC address is likely to be randomly generated.
        
        Conditions for random MAC:
        1. 2nd least bit in first octet of OUI is 1
        2. Not in OUI list
        """
        try:
            # Extract OUI (first 6 characters) and normalize
            oui = mac.replace(':', '').replace('-', '')[:6].upper()
            
            # Check if OUI exists in database
            if oui in self.oui_db:
                return False
                
            # Convert first octet to integer and check 2nd least bit
            first_octet = int(oui[:2], 16)
            second_least_bit = (first_octet >> 1) & 1
            
            return second_least_bit == 1
        except Exception as e:
            logger.error(f"Error checking random MAC {mac}: {e}")
            return False

    def analyze(self, data: dict) -> dict:
        """Analyze MAC address and add vendor information."""
        try:
            mac = data.get('mac_address')
            if not mac:
                logger.warning("No MAC address in data")
                return data

            vendor_info = self.get_vendor_info(mac)
            if vendor_info:
                data['oui_analysis'] = vendor_info
                logger.debug(f"Added vendor info for MAC {mac}: {vendor_info}")
            
            # Add random MAC detection
            is_random = self.is_random_mac(mac)
            if is_random:
                if 'oui_analysis' not in data:
                    data['oui_analysis'] = {}
                data['oui_analysis']['is_random_mac'] = True
                logger.debug(f"Detected random MAC: {mac}")
            
            return data
        except Exception as e:
            logger.error(f"Error analyzing data: {e}")
            return data

def main():
    """Main function to process JSON stream."""
    analyzer = OUIAnalyzer()
    
    try:
        for line in sys.stdin:
            try:
                # Parse JSON
                data = json.loads(line.strip())
                
                # Analyze and output
                result = analyzer.analyze(data)
                try:
                    print(json.dumps(result, ensure_ascii=False))
                    sys.stdout.flush()
                except BrokenPipeError:
                    # Handle broken pipe gracefully
                    sys.exit(0)
                
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON: {e}")
                continue
            except Exception as e:
                logger.error(f"Error processing line: {e}")
                continue
                
    except KeyboardInterrupt:
        logger.info("Processing interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 