#!/usr/bin/env python3

import os
import lmdb
import cbor2
import logging
import binascii
import argparse
import lz4.frame
import json

def setup_logging(debug: bool = False):
    """Configure logging with appropriate level"""
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
            logging.StreamHandler(),
            logging.FileHandler('check_lmdb.log', mode='a', encoding='utf-8')
        ]
    )
    
    # Get our logger after configuration
    logger = logging.getLogger(__name__)
    logger.setLevel(log_level)
    
    return logger

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Check LMDB database contents')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()
    
    # Setup logging based on debug flag
    logger = setup_logging(args.debug)
    
    try:
        # Initialize LMDB
        db_path = os.path.abspath('mac_data.mdb')
        logger.debug(f"Opening database at: {db_path}")
        logger.debug(f"Database exists: {os.path.exists(db_path)}")
        if os.path.exists(db_path):
            logger.debug(f"Database directory contents: {os.listdir(db_path)}")
            data_path = os.path.join(db_path, 'data.mdb')
            if os.path.exists(data_path):
                logger.debug(f"Data file size: {os.path.getsize(data_path)} bytes")
        
        env = lmdb.open(db_path, max_dbs=1, map_size=1024 * 1024 * 1024)  # 1GB
        logger.debug("Database opened successfully")
        
        # Get database stats
        with env.begin() as txn:
            stat = env.stat()
            logger.debug(f"LMDB stats: {stat}")
            
            # Calculate LMDB usage ratio
            map_size = env.info()['map_size']
            used_pages = stat['psize'] * stat['entries']
            usage_ratio = (used_pages / map_size) * 100
            
            print(f"\nLMDB Usage Statistics:")
            print(f"Map size: {map_size / (1024*1024):.1f} MB")
            print(f"Used pages: {used_pages / (1024*1024):.1f} MB")
            print(f"Usage ratio: {usage_ratio:.1f}%")
            
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
                        entry = cbor2.loads(decompressed_data)
                        
                        # Print compression ratio for this entry
                        ratio = (compressed_size / len(decompressed_data)) * 100
                        print(f"{mac}: {entry}")
                        logger.debug(f"Entry compression ratio: {ratio:.1f}% (compressed: {compressed_size} bytes, decompressed: {len(decompressed_data)} bytes)")
                        
                        # Debug output for specific fields
                        if args.debug:
                            if 'dhcp_fingerprint' in entry:
                                logger.debug(f"DHCP fingerprint: {entry['dhcp_fingerprint']}")
                            if 'mdns_services' in entry:
                                logger.debug(f"mDNS services: {entry['mdns_services']}")
                            if 'ssdp_headers' in entry:
                                logger.debug(f"SSDP headers: {entry['ssdp_headers']}")
                            if 'tcp_syn' in entry:
                                logger.debug(f"TCP SYN: {entry['tcp_syn']}")
                            
                    except Exception as e:
                        # If any error occurs, show raw data
                        print(f"{mac}: [RAW DATA] {binascii.hexlify(value).decode()}")
                        logger.error(f"Error processing entry for {mac}: {e}")
                except Exception as e:
                    logger.error(f"Error processing MAC {key}: {e}")
                    continue
            
            logger.debug(f"Total entries processed: {entry_count}")
            if entry_count > 0:
                avg_ratio = (total_compressed_size / total_decompressed_size) * 100
                print(f"\nTotal entries in database: {entry_count}")
                print(f"Total compressed size: {total_compressed_size} bytes")
                print(f"Total decompressed size: {total_decompressed_size} bytes")
                print(f"Average compression ratio: {avg_ratio:.1f}%")
                
                # Print final LMDB usage statistics
                print(f"\nFinal LMDB Usage Statistics:")
                print(f"Map size: {map_size / (1024*1024):.1f} MB")
                print(f"Used pages: {used_pages / (1024*1024):.1f} MB")
                print(f"Usage ratio: {usage_ratio:.1f}%")
                print(f"Available space: {(map_size - used_pages) / (1024*1024):.1f} MB")
    
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