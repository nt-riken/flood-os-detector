#!/usr/bin/env python3

import os
import lmdb
import cbor2
import logging
import argparse
import json
import lz4.frame
from datetime import datetime
import sys

class CustomJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle sets and other non-JSON types"""
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

def setup_logging(debug: bool = False):
    """Configure logging with appropriate level"""
    # Remove any existing handlers
    root = logging.getLogger()
    if root.handlers:
        for handler in root.handlers:
            root.removeHandler(handler)
    
    # Set the log level
    log_level = logging.DEBUG if debug else logging.WARNING
    
    # Configure logging
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stderr),  # Send logs to stderr
            logging.FileHandler('dump_json.log', mode='a', encoding='utf-8')
        ]
    )
    
    # Get our logger after configuration
    logger = logging.getLogger(__name__)
    logger.setLevel(log_level)
    
    return logger

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Dump LMDB database contents as JSON stream')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()
    
    # Setup logging based on debug flag
    logger = setup_logging(args.debug)
    
    try:
        # Initialize LMDB
        db_path = os.path.abspath('mac_data.mdb')
        logger.debug(f"Opening database at: {db_path}")
        
        env = lmdb.open(db_path, max_dbs=1, map_size=1024 * 1024 * 1024)  # 1GB
        logger.debug("Database opened successfully")
        
        # Get database stats
        with env.begin() as txn:
            stat = env.stat()
            logger.debug(f"LMDB stats: {stat}")
            
            cursor = txn.cursor()
            logger.debug("Cursor created")
            
            # Get first entry to check if database is empty
            first = cursor.first()
            logger.debug(f"First entry exists: {first}")
            
            entry_count = 0
            total_compressed_size = 0
            total_decompressed_size = 0
            
            for key, value in cursor:
                entry_count += 1
                try:
                    mac = key.decode()
                    logger.debug(f"Processing MAC: {mac}")
                    # Skip LMDB internal keys
                    if mac == 'main':
                        logger.debug("Skipping 'main' key")
                        continue
                    
                    # Track sizes
                    compressed_size = len(value)
                    total_compressed_size += compressed_size
                    
                    try:
                        # Decompress and decode the data
                        decompressed_data = lz4.frame.decompress(value)
                        total_decompressed_size += len(decompressed_data)
                        
                        # Deserialize CBOR data
                        entry = cbor2.loads(decompressed_data)
                        entry['mac_address'] = mac
                        
                        # Serialize to JSON using custom encoder and print with newline
                        json_str = json.dumps(entry, cls=CustomJSONEncoder)
                        sys.stdout.write(json_str + "\n")
                        sys.stdout.flush()
                            
                        # Log compression ratio
                        ratio = (compressed_size / len(decompressed_data)) * 100
                        logger.debug(f"Entry compression ratio: {ratio:.1f}% (compressed: {compressed_size} bytes, decompressed: {len(decompressed_data)} bytes)")
                            
                    except Exception as e:
                        logger.error(f"Error processing entry for {mac}: {e}")
                except Exception as e:
                    logger.error(f"Error processing MAC {key}: {e}")
                    continue
            
            logger.debug(f"Total entries processed: {entry_count}")
            if entry_count > 0:
                avg_ratio = (total_compressed_size / total_decompressed_size) * 100
                logger.info(f"Total compressed size: {total_compressed_size} bytes")
                logger.info(f"Total decompressed size: {total_decompressed_size} bytes")
                logger.info(f"Average compression ratio: {avg_ratio:.1f}%")
    
    except Exception as e:
        logger.error(f"Error accessing LMDB: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
    finally:
        if 'env' in locals():
            env.close()
            logger.debug("Database closed")

if __name__ == "__main__":
    main() 