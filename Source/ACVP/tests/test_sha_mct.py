"""NIST SHA-2/SHA-3 Monte Carlo tests compared against an independent oracle."""

import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from local_client import mct_digests


class HashOracle:
    def digest(self, algorithm, message, output_bits, key=b""):
        return hashlib.new(algorithm.lower().replace("sha2-", "sha").replace("sha3-", "sha3_"),
                           message).hexdigest().upper()


class MonteCarloTests(unittest.TestCase):
    def test_sha2_standard_matches_independent_hashlib(self):
        seed = bytes(range(32))
        results = mct_digests("SHA2-256", seed, "standard", HashOracle())
        self.assertEqual(len(results), 100)
        a = b = c = seed
        for _ in range(1000):
            result = hashlib.sha256(a + b + c).digest()
            a, b, c = b, c, result
        self.assertEqual(results[0]["md"], result.hex().upper())

    def test_sha3_alternate_matches_independent_hashlib(self):
        seed = b"A" * 16
        results = mct_digests("SHA3-256", seed, "alternate", HashOracle())
        self.assertEqual(len(results), 100)
        previous = seed
        for _ in range(1000):
            previous = hashlib.sha3_256(previous[:16].ljust(16, b"\x00")).digest()
        self.assertEqual(results[0]["md"], previous.hex().upper())

    def test_unsupported_mct_rejected(self):
        with self.assertRaises(ValueError):
            mct_digests("SHAKE-128", b"abc", "standard", HashOracle())


if __name__ == "__main__":
    unittest.main()
