#!/usr/bin/env python3
# 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
# All Rights Reserved.
#  *
# NOTICE:
# This software and all accompanying materials are the exclusive property of
# Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
# and technical concepts contained herein are proprietary to QRCS and are
# protected under applicable Canadian, U.S., and international copyright,
# patent, and trade secret laws.
#  *
# CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
# - This software includes implementations of cryptographic primitives and
#   algorithms that are standardized or in the public domain, such as AES
#   and SHA-3, which are not proprietary to QRCS.
# - This software also includes cryptographic primitives, constructions, and
#   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
#   related components, which are proprietary to QRCS.
# - All source code, implementations, protocol compositions, optimizations,
#   parameter selections, and engineering work contained in this software are
#   original works of QRCS and are protected under this license.
#  *
# LICENSE AND USE RESTRICTIONS:
# - This software is licensed under the Quantum Resistant Cryptographic Solutions
#   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
# - Permission is granted solely for non-commercial evaluation, academic research,
#   cryptographic analysis, interoperability testing, and feasibility assessment.
# - Commercial use, production deployment, commercial redistribution, or
#   integration into products or services is strictly prohibited without a
#   separate written license agreement executed with QRCS.
# - Licensing and authorized distribution are solely at the discretion of QRCS.
#  *
# EXPERIMENTAL CRYPTOGRAPHY NOTICE:
# Portions of this software may include experimental, novel, or evolving
# cryptographic designs. Use of this software is entirely at the user's risk.
#  *
# DISCLAIMER:
# THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
# LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
# ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
#  *
# FULL LICENSE:
# This software is subject to the Quantum Resistant Cryptographic Solutions
# Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
# are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
#  *
# Written by: John G. Underhill
# Contact: contact@qrcscorp.ca
#

"""Named SP 800-56C HKDF ACVP AFT/VAL and security-boundary tests."""

import hashlib
import hmac
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from kda_hkdf_client import registration, response, SELECTION
from kdf_client import QscKdf
from local_client import build_response
from demo_client import registration as demo_registration, execute


def oracle(name: str, secret: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Independent HMAC-based HKDF expand oracle."""
    algorithm = {"SHA2-256": "sha256", "SHA2-384": "sha384", "SHA2-512": "sha512"}[name]
    prk = hmac.digest(salt, secret, algorithm)
    result = b""
    last = b""
    counter = 1
    while len(result) < length:
        last = hmac.digest(prk, last + info + bytes([counter]), algorithm)
        result += last
        counter += 1
    return result[:length]


def vectors(revision="Sp800-56Cr1", test_type="AFT", digest="SHA2-256"):
    """Create a representative NIST KDA-HKDF single-expansion vector set."""
    bits = 256
    u = {"partyId": "0102", "ephemeralData": "0304"}
    v = {"partyId": "AABB"}
    salt = bytes(range(32))
    secret = bytes(range(28))
    info = bytes.fromhex("01020304AABB") + bits.to_bytes(4, "big")
    expected = oracle(digest, secret, salt, info, bits // 8)
    case = {"tcId": 17, "kdfParameter": {"kdfType": "hkdf", "salt": salt.hex(),
            "z": secret.hex(), "l": bits},
            "fixedInfoPartyU": u, "fixedInfoPartyV": v}
    if test_type == "VAL":
        case["dkm"] = expected.hex()
    group = {"tgId": 5, "testType": test_type, "multiExpansion": False,
             "zLength": len(secret) * 8, "usesHybridSharedSecret": False,
             "kdfConfiguration": {"kdfType": "hkdf", "l": bits, "saltLen": len(salt) * 8,
                "saltMethod": "random", "fixedInfoPattern": "uPartyInfo||vPartyInfo||l",
                "fixedInfoEncoding": "concatenation", "hmacAlg": digest},
             "tests": [case]}
    return [{"acvVersion": "1.0"}, {"vsId": 83, "algorithm": "KDA",
            "mode": "HKDF", "revision": revision, "testGroups": [group]}]


class KdaHkdfSchemaTests(unittest.TestCase):
    def test_registration_requires_verified_drbg(self):
        for item in (None, "", "same", "pending", "not-validated"):
            with self.subTest(item=item), self.assertRaises(ValueError):
                registration(item)

    def test_registration_registers_r1_r2_bounded_capabilities(self):
        entries = registration("ACVP-123")
        self.assertEqual([x["revision"] for x in entries],
                         ["Sp800-56Cr1", "Sp800-56Cr2"])
        self.assertEqual(entries[0]["hmacAlg"], ["SHA2-256", "SHA2-384", "SHA2-512"])
        self.assertEqual(entries[0]["l"], 2048)
        self.assertFalse(entries[1]["usesHybridSharedSecret"])
        self.assertFalse(entries[1]["performMultiExpansionTests"])
        self.assertEqual(entries[0]["prereqVals"][0],
                         {"algorithm": "DRBG", "valValue": "ACVP-123"})

    def test_registration_checks_prerequisites(self):
        with self.assertRaises(ValueError):
            demo_registration((SELECTION,), "ACVP-123")
        with self.assertRaises(ValueError):
            demo_registration((SELECTION, "HMAC-SHA2-256", "HMAC-SHA2-384",
                               "HMAC-SHA2-512"), "ACVP-123")
        result = demo_registration(("SHA2-256", "SHA2-384", "SHA2-512",
                                    "HMAC-SHA2-256", "HMAC-SHA2-384", "HMAC-SHA2-512",
                                    SELECTION), "ACVP-123")
        self.assertEqual(result[1]["algorithms"][-2]["algorithm"], "KDA")

    def test_r1_aft_matches_independent_reference(self):
        inp = vectors()
        class Independent:
            def hkdf(self, digest, secret, salt, info, length):
                return oracle(digest, secret, salt, info, length)
        actual = build_response(inp, type("Q", (), {"kdf": Independent()})())
        self.assertEqual(actual[1]["testGroups"][0]["tests"][0]["dkm"],
                         oracle("SHA2-256", bytes(range(28)), bytes(range(32)),
                                bytes.fromhex("01020304AABB00000100"), 32).hex().upper())

    def test_r2_val_accepts_matching_and_rejects_invalid_dkm(self):
        inp = vectors("Sp800-56Cr2", "VAL")
        class Independent:
            def hkdf(self, digest, secret, salt, info, length):
                return oracle(digest, secret, salt, info, length)
        qsc = Independent()
        self.assertTrue(response(inp, qsc)[1]["testGroups"][0]["tests"][0]["testPassed"])
        inp[1]["testGroups"][0]["tests"][0]["dkm"] = "00" * 32
        self.assertFalse(response(inp, qsc)[1]["testGroups"][0]["tests"][0]["testPassed"])

    def test_reject_hybrid_and_multi_expansion(self):
        class Unused:
            pass
        for key in ("usesHybridSharedSecret", "multiExpansion"):
            inp = vectors("Sp800-56Cr2")
            inp[1]["testGroups"][0][key] = True
            with self.subTest(key=key), self.assertRaises(ValueError):
                response(inp, Unused())

    def test_reject_non_byte_length_and_unregistered_fixed_info(self):
        inp = vectors()
        inp[1]["testGroups"][0]["kdfConfiguration"]["l"] = 255
        with self.assertRaises(ValueError):
            response(inp, object())
        inp = vectors()
        inp[1]["testGroups"][0]["kdfConfiguration"]["fixedInfoPattern"] = "label||context"
        with self.assertRaises(ValueError):
            response(inp, object())

    def test_reject_invalid_salt_and_dkm_length(self):
        inp = vectors()
        inp[1]["testGroups"][0]["kdfConfiguration"]["saltMethod"] = "default"
        with self.assertRaises(ValueError):
            response(inp, object())
        inp = vectors(test_type="VAL")
        inp[1]["testGroups"][0]["tests"][0]["dkm"] = "AB"
        with self.assertRaises(ValueError):
            response(inp, type("Q", (), {"hkdf": lambda _, *args: bytes(32)})())

    def test_reject_non_string_kdf_configuration(self):
        inp = vectors()
        inp[1]["testGroups"][0]["kdfConfiguration"]["kdfType"] = 25
        with self.assertRaises(ValueError):
            response(inp, object())
        inp = vectors()
        inp[1]["testGroups"][0]["tests"][0]["kdfParameter"]["kdfType"] = 25
        with self.assertRaises(ValueError):
            response(inp, object())

    def test_reject_missing_library(self):
        with self.assertRaises(ValueError):
            build_response(vectors(), object())

    def test_mock_authenticated_demo_session_sanitizes_tokens(self):
        from test_demo_client import FakeTransport
        class KdaTransport(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "GET" and path == self.vector:
                    self.calls.append((method, path, token, body))
                    reply = vectors()
                    reply[1]["vsId"] = int(self.vector.rsplit("/", 1)[-1])
                    return reply
                return super().request(method, path, token, body)
        class Independent:
            def hkdf(self, digest, secret, salt, info, length):
                return oracle(digest, secret, salt, info, length)
        transport = KdaTransport()
        result = execute(transport, type("Q", (), {"kdf": Independent()})(),
                         "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                         ("SHA2-256", "SHA2-384", "SHA2-512", "HMAC-SHA2-256",
                          "HMAC-SHA2-384", "HMAC-SHA2-512", SELECTION),
                         poll_count=1, drbg_validation="ACVP-123")
        self.assertEqual(result["status"], "FAIL_INCOMPLETE_ALGORITHM_COVERAGE")
        self.assertNotIn("private-session-token", str(result))
        self.assertEqual(transport.calls[3][3][1]["testGroups"][0]["tests"][0]["tcId"], 17)


class KdaHkdfNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = os.environ.get("QSC_ACVP_HASH_LIBRARY")
        if not path or not Path(path).is_file():
            raise unittest.SkipTest("Native QSC SHA library unavailable")
        cls.qsc = QscKdf(Path(path))

    def test_sha256_native_aft(self):
        actual = response(vectors(), self.qsc)
        expected = oracle("SHA2-256", bytes(range(28)), bytes(range(32)),
                          bytes.fromhex("01020304AABB00000100"), 32)
        self.assertEqual(bytes.fromhex(actual[1]["testGroups"][0]["tests"][0]["dkm"]), expected)

    def test_sha384_native_aft(self):
        actual = response(vectors(digest="SHA2-384"), self.qsc)
        expected = oracle("SHA2-384", bytes(range(28)), bytes(range(32)),
                          bytes.fromhex("01020304AABB00000100"), 32)
        self.assertEqual(bytes.fromhex(actual[1]["testGroups"][0]["tests"][0]["dkm"]), expected)

    def test_2048_bit_derived_key_matches_independent_reference(self):
        for revision in ("Sp800-56Cr1", "Sp800-56Cr2"):
            inp = vectors(revision, digest="SHA2-256")
            group = inp[1]["testGroups"][0]
            group["kdfConfiguration"]["l"] = 2048
            group["tests"][0]["kdfParameter"]["l"] = 2048
            result = response(inp, self.qsc)
            actual = bytes.fromhex(result[1]["testGroups"][0]["tests"][0]["dkm"])
            expected = oracle("SHA2-256", bytes(range(28)), bytes(range(32)),
                              bytes.fromhex("01020304AABB00000800"), 256)
            self.assertEqual(actual, expected)

    def test_sha512_native_val(self):
        inp = vectors("Sp800-56Cr2", "VAL", "SHA2-512")
        actual = response(inp, self.qsc)
        self.assertTrue(actual[1]["testGroups"][0]["tests"][0]["testPassed"])


if __name__ == "__main__":
    unittest.main()
