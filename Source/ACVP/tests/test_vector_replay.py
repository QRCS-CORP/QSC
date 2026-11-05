"""Offline ACVP vector schema and fail-closed adapter unit tests."""
import importlib.util
from pathlib import Path
import unittest

ADAPTER = Path(__file__).resolve().parents[1] / "local_client.py"
spec = importlib.util.spec_from_file_location("qsc_local_client", ADAPTER)
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


class Oracle:
    """Unit-test double: checks envelope schema without invoking native code."""
    def digest(self, algorithm, message, output_bits, key=b""):
        return "AB" * (output_bits // 8)


class VectorReplayTests(unittest.TestCase):
    def envelope(self, algorithm="SHA2-256", group_type="AFT", message="616263", bits=24):
        return [{"acvVersion": "1.0"}, {"vsId": 11, "algorithm": algorithm,
                "testGroups": [{"tgId": 3, "testType": group_type,
                                "tests": [{"tcId": 7, "len": bits, "msg": message}]}]}]

    def test_sha_aft_preserves_ids_and_digest(self):
        response = client.build_response(self.envelope(), Oracle())
        self.assertEqual(response[1]["vsId"], 11)
        self.assertEqual(response[1]["testGroups"][0]["tests"][0],
                         {"tcId": 7, "md": "AB" * 32})

    def test_sha_zero_length_with_padded_hex(self):
        response = client.build_response(self.envelope(message="00", bits=0), Oracle())
        self.assertEqual(response[1]["testGroups"][0]["tests"][0]["md"], "AB" * 32)

    def test_rejects_nonbyte_input(self):
        with self.assertRaisesRegex(ValueError, "byte-aligned"):
            client.build_response(self.envelope(message="80", bits=1), Oracle())

    def test_rejects_mct_for_unsupported_algorithms(self):
        with self.assertRaisesRegex(ValueError, "MCT is not implemented"):
            client.build_response(self.envelope(algorithm="SHAKE-128", group_type="MCT"), Oracle())

    def test_hmac_truncated_response(self):
        envelope = self.envelope("HMAC-SHA2-256")
        item = envelope[1]["testGroups"][0]["tests"][0]
        item.update({"key": "0A" * 16, "keyLen": 128, "macLen": 128})
        response = client.build_response(envelope, Oracle())
        self.assertEqual(response[1]["testGroups"][0]["tests"][0]["mac"], "AB" * 16)

    def test_hmac_empty_key_response_label(self):
        envelope = self.envelope("HMAC-SHA2-256")
        item = envelope[1]["testGroups"][0]["tests"][0]
        item.update({"key": "", "keyLen": 0, "macLen": 128})
        response = client.build_response(envelope, Oracle())
        self.assertIn("mac", response[1]["testGroups"][0]["tests"][0])

    def test_rejects_extra_nonzero_message_data(self):
        with self.assertRaisesRegex(ValueError, "Nonzero bytes"):
            client.build_response(self.envelope(message="616263FF", bits=24), Oracle())


if __name__ == "__main__":
    unittest.main()
