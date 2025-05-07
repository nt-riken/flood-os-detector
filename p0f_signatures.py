#!/usr/bin/env python3

import re
import os
import logging
from typing import List, Dict, Tuple, Optional

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class P0FSignature:
    def __init__(self, os_type: str, os_name: str, os_version: Optional[str], sig_str: str):
        self.os_type = os_type
        self.os_name = os_name
        self.os_version = os_version
        
        try:
            # Parse signature string components
            # Format: olen:ttl:tos:mss:win:opts:quirks:pclass
            components = sig_str.split(':')
            if len(components) < 8:
                raise ValueError(f"Invalid signature format: {sig_str}")
                
            # Parse TTL
            ttl_str = components[1]
            if ttl_str == '*':
                self.ttl = 0  # Any TTL is acceptable
                self.ttl_range = 0
            else:
                try:
                    self.ttl = int(ttl_str)
                    self.ttl_range = 0
                except ValueError:
                    logger.warning(f"Invalid TTL value: {ttl_str}")
                    self.ttl = 0
                    self.ttl_range = 0
                    
            # Parse window size expression and options
            win_str = components[4]
            if ',' in win_str:
                win_parts = win_str.split(',')
                self.win_expr = win_parts[0]  # e.g., "mss*10"
                try:
                    self.win_scale = int(win_parts[1])  # e.g., "4"
                except ValueError:
                    logger.warning(f"Invalid window scale: {win_parts[1]}")
                    self.win_scale = 0
            else:
                self.win_expr = win_str
                self.win_scale = 0
                
            # Parse TCP options
            self.opts = components[5].split(',')
            
            # Parse quirks
            self.quirks = components[6].split(',')
            
            logger.debug(f"Created signature: {self.os_name} {self.os_version} with window expr {self.win_expr}, scale {self.win_scale}")
            
        except Exception as e:
            logger.error(f"Error creating signature: {e}")
            raise

    def _calculate_window(self, mss: int) -> int:
        """Calculate expected window size based on MSS and window expression."""
        try:
            if not self.win_expr:
                return 0
                
            if self.win_expr.startswith('mss*'):
                try:
                    multiplier = int(self.win_expr[4:])
                    window = mss * multiplier
                    if self.win_scale:
                        window = window >> self.win_scale
                    logger.debug(f"Calculated window size: {window} (mss={mss}, multiplier={multiplier}, scale={self.win_scale})")
                    return window
                except ValueError:
                    logger.warning(f"Invalid window multiplier in expression: {self.win_expr}")
                    return 0
            else:
                try:
                    return int(self.win_expr)
                except ValueError:
                    logger.warning(f"Invalid window expression: {self.win_expr}")
                    return 0
        except Exception as e:
            logger.error(f"Error calculating window size: {e}")
            return 0

    def match(self, ttl, mss, window, tcp_options, quirks):
        """Match TCP parameters against this signature."""
        try:
            logger.debug(f"Matching signature for {self.os_name} {self.os_version}")
            logger.debug(f"TTL: expected={self.ttl} (±{self.ttl_range}), got={ttl}")
            logger.debug(f"Window: expected={self.win_expr}, scale={self.win_scale}, got={window}")
            logger.debug(f"TCP Options: expected={self.opts}, got={tcp_options}")
            logger.debug(f"Quirks: expected={self.quirks}, got={quirks}")
            
            # Check TTL
            if self.ttl != 0 and ttl != self.ttl:  # 0 means any TTL is acceptable
                logger.debug("TTL mismatch")
                return False
                
            # Check window size
            if self.win_expr.startswith('mss*'):
                try:
                    multiplier = int(self.win_expr[4:])
                    expected_window = mss * multiplier
                    if window != expected_window:
                        logger.debug(f"Window mismatch: expected {expected_window} (mss={mss} * {multiplier}), got {window}")
                        return False
                except ValueError:
                    logger.warning(f"Invalid window multiplier in expression: {self.win_expr}")
                    return False
            else:
                try:
                    expected_window = int(self.win_expr)
                    if window != expected_window:
                        logger.debug(f"Window mismatch: expected {expected_window}, got {window}")
                        return False
                except ValueError:
                    logger.warning(f"Invalid window expression: {self.win_expr}")
                    return False
                
            # Check TCP options
            if sorted(tcp_options) != sorted(self.opts):
                logger.debug("TCP options mismatch")
                return False
                
            # Check quirks
            if sorted(quirks) != sorted(self.quirks):
                logger.debug("Quirks mismatch")
                return False
                
            logger.debug("Signature matched!")
            return True
            
        except Exception as e:
            logger.error(f"Error in signature matching: {e}")
            return False

class P0FMatcher:
    def __init__(self, fp_file="docs/p0f.fp"):
        self.signatures = []
        self._load_signatures(fp_file)

    def _load_signatures(self, fp_file):
        """Load signatures from p0f.fp file."""
        try:
            if not os.path.exists(fp_file):
                logger.error(f"p0f.fp file not found at {fp_file}")
                return
                
            with open(fp_file, 'r') as f:
                in_syn_section = False
                current_os_type = None
                current_os_name = None
                current_os_version = None
                
                for line in f:
                    line = line.strip()
                    if not line or line.startswith(';') or line.startswith('#'):
                        continue
                        
                    if line == '[tcp:request]':
                        in_syn_section = True
                        continue
                    if line.startswith('['):
                        in_syn_section = False
                        continue
                    if not in_syn_section:
                        continue
                        
                    try:
                        if line.startswith('label = '):
                            label_parts = line[8:].strip().split(':')
                            if len(label_parts) >= 4 and label_parts[0] == 's':
                                current_os_type = label_parts[1]
                                current_os_name = label_parts[2]
                                current_os_version = ':'.join(label_parts[3:])
                        elif line.startswith('sig   = '):
                            if not current_os_type or not current_os_name:
                                continue
                                
                            sig_str = line[8:].strip()
                            try:
                                signature = P0FSignature(current_os_type, current_os_name, current_os_version, sig_str)
                                self.signatures.append(signature)
                            except ValueError as e:
                                logger.warning(f"Skipping invalid signature: {e}")
                            
                    except (ValueError, IndexError, UnboundLocalError) as e:
                        logger.warning(f"Skipping invalid signature: {e}")
                        
            logger.info(f"Loaded {len(self.signatures)} signatures from {fp_file}")
            
        except Exception as e:
            logger.error(f"Error loading signatures: {e}")

    def match_signature(self, ttl, mss, window, tcp_options, quirks):
        """Find matching signature for TCP parameters."""
        try:
            for sig in self.signatures:
                if sig.match(ttl, mss, window, tcp_options, quirks):
                    return sig
            logger.debug("No matching signature found")
            return None
        except Exception as e:
            logger.error(f"Error in signature matching: {e}")
            return None 