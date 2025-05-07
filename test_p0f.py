#!/usr/bin/env python3

import unittest
import os
import logging
from p0f_signatures import P0FSignature, P0FMatcher

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class TestP0FSignature(unittest.TestCase):
    def setUp(self):
        self.sig_str = "*:64:0:*:mss*10,4:mss,sok,ts,nop,ws:df,id+:0"
        try:
            self.sig = P0FSignature(
                os_type="unix",
                os_name="Linux",
                os_version="3.1-3.10",
                sig_str=self.sig_str
            )
        except Exception as e:
            logger.error(f"Error creating test signature: {e}")
            raise

    def test_parse_os_type(self):
        try:
            self.assertEqual(self.sig.os_type, "unix")
            self.assertEqual(self.sig.os_name, "Linux")
            self.assertEqual(self.sig.os_version, "3.1-3.10")
        except AssertionError as e:
            logger.error(f"Test failed: {e}")
            raise

    def test_parse_ttl(self):
        try:
            self.assertEqual(self.sig.ttl, 64)  # TTL value from signature string
            self.assertEqual(self.sig.ttl_range, 0)
        except AssertionError as e:
            logger.error(f"Test failed: {e}")
            raise

    def test_parse_window(self):
        try:
            self.assertEqual(self.sig.win_expr, "mss*10")
            self.assertEqual(self.sig.win_scale, 4)
        except AssertionError as e:
            logger.error(f"Test failed: {e}")
            raise

    def test_parse_opts(self):
        try:
            self.assertEqual(self.sig.opts, ["mss", "sok", "ts", "nop", "ws"])
        except AssertionError as e:
            logger.error(f"Test failed: {e}")
            raise

    def test_parse_quirks(self):
        try:
            self.assertEqual(self.sig.quirks, ["df", "id+"])
        except AssertionError as e:
            logger.error(f"Test failed: {e}")
            raise

    def test_match(self):
        try:
            # Test matching with sample values
            result = self.sig.match(
                ttl=64,
                mss=1460,
                window=912,  # (1460 * 10) >> 4
                tcp_options=["mss", "sok", "ts", "nop", "ws"],
                quirks=["df", "id+"]
            )
            self.assertTrue(result, "Signature should match the sample values")
        except AssertionError as e:
            logger.error(f"Test failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Error in test_match: {e}")
            raise

class TestP0FMatcher(unittest.TestCase):
    def setUp(self):
        try:
            self.matcher = P0FMatcher()
            if not self.matcher.signatures:
                logger.warning("No signatures loaded from p0f.fp file")
        except Exception as e:
            logger.error(f"Error setting up P0FMatcher: {e}")
            raise

    def test_load_signatures(self):
        try:
            self.assertTrue(len(self.matcher.signatures) > 0, "Should load at least one signature")
        except AssertionError as e:
            logger.error(f"Test failed: {e}")
            raise

    def test_signature_matching(self):
        try:
            # Test matching with sample values
            result = self.matcher.match_signature(
                ttl=64,
                mss=1460,
                window=912,  # (1460 * 10) >> 4
                tcp_options=["mss", "sok", "ts", "nop", "ws"],
                quirks=["df", "id+"]
            )
            self.assertIsNotNone(result, "Should find a matching signature")
            if result:
                self.assertEqual(result.os_type, "unix")
                self.assertEqual(result.os_name, "Linux")
        except AssertionError as e:
            logger.error(f"Test failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Error in test_signature_matching: {e}")
            raise

if __name__ == '__main__':
    try:
        unittest.main()
    except Exception as e:
        logger.error(f"Error running tests: {e}")
        raise 