#!/usr/bin/env python3

import os
import lmdb
import msgspec
import logging
import binascii

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Changed to DEBUG level
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('check_lmdb.log', mode='a', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

def main():
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
            
            cursor = txn.cursor()
            logger.debug("Cursor created")
            
            # Get first entry to check if database is empty
            first = cursor.first()
            logger.debug(f"First entry exists: {first}")
            
            entry_count = 0
            for key, value in cursor:
                entry_count += 1
                try:
                    mac = key.decode()
                    logger.debug(f"Processing MAC: {mac}")
                    # Skip LMDB internal keys
                    if mac == 'main':
                        logger.debug("Skipping 'main' key")
                        continue
                        
                    try:
                        entry = msgspec.msgpack.decode(value)
                        print(f"{mac}: {entry}")
                        logger.debug(f"Successfully decoded entry for {mac}")
                    except msgspec.DecodeError as e:
                        # If decoding fails, show raw data
                        print(f"{mac}: [RAW DATA] {binascii.hexlify(value).decode()}")
                        logger.error(f"Decode error for {mac}: {e}")
                except Exception as e:
                    logger.error(f"Error processing MAC {key}: {e}")
                    continue
            
            logger.debug(f"Total entries processed: {entry_count}")
    
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