"""Negative-case tests for the loopback-only ACVP-style SHA simulator."""
import importlib.util
from pathlib import Path
import unittest

SERVER = Path(__file__).resolve().parents[1] / "local_server.py"
spec = importlib.util.spec_from_file_location("qsc_local_server", SERVER)
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


class LocalServerTests(unittest.TestCase):
    def test_sha2_256_oracle_abc(self):
        self.assertEqual(
            server.calculate("sha256", b"abc", 256),
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
        )

    def test_wrong_digest_rejected(self):
        tests = [{"tcId": i + 1, "md": "00" * 32} for i in range(4)]
        body = [{"acvVersion": "1.0"}, {"vsId": 1, "testGroups": [{"tgId": 1, "tests": tests}]}]
        self.assertFalse(server.validate(1, body)["passed"])

    def test_correct_sha2_256_accepted(self):
        tests = [{"tcId": i + 1, "md": server.calculate("sha256", message, 256)}
                 for i, message in enumerate(server.TEST_MESSAGES)]
        body = [{"acvVersion": "1.0"}, {"vsId": 1, "testGroups": [{"tgId": 1, "tests": tests}]}]
        self.assertTrue(server.validate(1, body)["passed"])

    def test_hmac256_independent_oracle(self):
        import hashlib
        import hmac
        key = bytes(range(1, 34))
        expected = hmac.digest(key, b"abc", hashlib.sha256).hex().upper()
        self.assertEqual(server.calculate("sha256", b"abc", 256, key), expected)

    def test_hmac256_wrong_mac_rejected(self):
        ident = 8
        tests = [{"tcId": i + 1, "mac": "00" * 32} for i in range(4)]
        body = [{"acvVersion": "1.0"},
                {"vsId": ident, "testGroups": [{"tgId": 1, "tests": tests}]}]
        self.assertFalse(server.validate(ident, body)["passed"])

    def test_missing_vector_case_rejected(self):
        body = [{"acvVersion": "1.0"}, {"vsId": 1, "testGroups": [{"tgId": 1, "tests": []}]}]
        self.assertFalse(server.validate(1, body)["passed"])


if __name__ == "__main__":
    unittest.main()
