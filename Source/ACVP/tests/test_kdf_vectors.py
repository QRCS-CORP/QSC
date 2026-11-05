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

"""Individually named PBKDF ACVP schema and independent KDF native tests."""

import hashlib
import hmac
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from kdf_client import QscKdf, pbkdf_registration, pbkdf_response
from local_client import build_response
from demo_client import registration


def vector(groups):
    return [{"acvVersion": "1.0"}, {"algorithm": "PBKDF", "revision": "1.0",
            "vsId": 47, "testGroups": groups}]


def group(algorithm="SHA2-256", tests=None):
    if tests is None:
        tests = [{"tcId": 9, "password": "password1", "salt": "01" * 16,
                  "keyLen": 256, "iterationCount": 12}]
    return {"tgId": 1, "testType": "AFT", "hmacAlg": algorithm, "tests": tests}


class KeyDerivationSchemaTests(unittest.TestCase):
    def test_pbkdf_registration_is_bounded_by_qsc_api(self):
        capability = pbkdf_registration()
        self.assertEqual(capability["algorithm"], "PBKDF")
        self.assertEqual(capability["capabilities"][0]["keyLen"][0]["max"], 512)
        self.assertEqual(capability["capabilities"][0]["hmacAlg"],
                         ["SHA2-256", "SHA2-384", "SHA2-512"])

    def test_pbkdf_requires_registered_sha_prerequisites(self):
        with self.assertRaises(ValueError):
            registration(("PBKDF", "SHA2-256"))
        registered = registration(("PBKDF", "SHA2-256", "SHA2-384", "SHA2-512"))
        self.assertEqual(registered[1]["algorithms"][0]["algorithm"], "PBKDF")

    def test_pbkdf_aft_response_uses_actual_derived_key(self):
        class Oracle:
            def pbkdf2(self, algorithm, password, salt, iterations, length):
                return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, length)
        output = pbkdf_response(vector([group()]), Oracle())
        actual = output[1]["testGroups"][0]["tests"][0]
        expected = hashlib.pbkdf2_hmac("sha256", b"password1", b"\x01" * 16, 12, 32)
        self.assertEqual(actual, {"tcId": 9, "derivedKey": expected.hex().upper()})

    def test_pbkdf_rejects_unknown_hash_and_test_type(self):
        with self.assertRaises(ValueError):
            pbkdf_response(vector([group("SHA-1")]), None)
        g = group()
        g["testType"] = "MCT"
        with self.assertRaises(ValueError):
            pbkdf_response(vector([g]), None)

    def test_pbkdf_rejects_excessive_derived_key_and_bit_length(self):
        g = group()
        g["tests"][0]["keyLen"] = 520
        with self.assertRaises(ValueError):
            pbkdf_response(vector([g]), None)
        g["tests"][0]["keyLen"] = 113
        with self.assertRaises(ValueError):
            pbkdf_response(vector([g]), None)

    def test_pbkdf_rejects_missing_and_malformed_inputs(self):
        g = group()
        g["tests"][0]["salt"] = "ABCDEFG"
        with self.assertRaises(ValueError):
            pbkdf_response(vector([g]), None)
        g["tests"][0]["salt"] = "01" * 16
        g["tests"][0].pop("password")
        with self.assertRaises(ValueError):
            pbkdf_response(vector([g]), None)

    def test_pbkdf_mock_authenticated_demo_session_and_token_redaction(self):
        from demo_client import execute
        from test_demo_client import FakeTransport

        class PbkdfTransport(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "GET" and path == self.vector:
                    self.calls.append((method, path, token, body))
                    reply = vector([group()])
                    reply[1]["vsId"] = int(self.vector.rsplit("/", 1)[-1])
                    return reply
                return super().request(method, path, token, body)

        class Oracle:
            def pbkdf2(self, algorithm, password, salt, iterations, length):
                return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, length)

        qsc = type("Q", (), {"kdf": Oracle()})()
        transport = PbkdfTransport()
        result = execute(transport, qsc, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                         ("SHA2-256", "SHA2-384", "SHA2-512", "PBKDF"), poll_count=1)
        self.assertEqual(result["status"], "FAIL_INCOMPLETE_ALGORITHM_COVERAGE")
        self.assertNotIn("private-session-token", str(result))
        submitted = transport.calls[3][3]
        self.assertEqual(submitted[1]["testGroups"][0]["tests"][0]["derivedKey"],
                         hashlib.pbkdf2_hmac("sha256", b"password1", b"\x01" * 16,
                                            12, 32).hex().upper())

    def test_pbkdf_requires_native_library_for_dispatch(self):
        with self.assertRaises(ValueError):
            build_response(vector([group()]), object())


class KeyDerivationNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        name = os.environ.get("QSC_ACVP_HASH_LIBRARY")
        if not name or not Path(name).is_file():
            raise unittest.SkipTest("Native QSC KDF qualification library unavailable")
        cls.qsc = QscKdf(Path(name))

    def test_pbkdf_sha256_multiple_block_outputs(self):
        for size in (14, 32, 48, 64):
            actual = self.qsc.pbkdf2("SHA2-256", b"password1", b"a" * 16, 100, size)
            expected = hashlib.pbkdf2_hmac("sha256", b"password1", b"a" * 16, 100, size)
            self.assertEqual(actual, expected)

    def test_pbkdf_sha384_nist_style_vectors(self):
        for count in (10, 123):
            actual = self.qsc.pbkdf2("SHA2-384", b"password2", b"z" * 24, count, 60)
            expected = hashlib.pbkdf2_hmac("sha384", b"password2", b"z" * 24, count, 60)
            self.assertEqual(actual, expected)

    def test_pbkdf_sha512_nist_style_vectors(self):
        actual = self.qsc.pbkdf2("SHA2-512", b"password3", bytes(range(32)), 300, 64)
        self.assertEqual(actual, hashlib.pbkdf2_hmac("sha512", b"password3", bytes(range(32)), 300, 64))

    def test_pbkdf_uses_native_qsc_in_vector_dispatch(self):
        qsc = type("Q", (), {"kdf": self.qsc})()
        answer = build_response(vector([group()]), qsc)
        derived = answer[1]["testGroups"][0]["tests"][0]["derivedKey"]
        self.assertEqual(derived, hashlib.pbkdf2_hmac("sha256", b"password1", b"\x01" * 16,
                                                      12, 32).hex().upper())

    def test_pbkdf_native_rejects_unavailable_key_sizes(self):
        with self.assertRaises(ValueError):
            self.qsc.pbkdf2("SHA2-256", b"password1", b"z" * 16, 2, 65)
        with self.assertRaises(ValueError):
            self.qsc.pbkdf2("SHA2-256", b"password1", b"z" * 16, 0, 32)

    def test_hkdf_sha256_rfc5869_case_one(self):
        secret, salt, info = bytes.fromhex("0b" * 22), bytes.fromhex("000102030405060708090a0b0c"), bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        actual = self.qsc.hkdf("SHA2-256", secret, salt, info, 42)
        expected = bytes.fromhex("3cb25f25faacd57a90434f64d0362f2a" +
                                 "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" + "34007208d5b887185865")
        self.assertEqual(actual, expected)

    def test_hkdf_sha256_empty_salt_and_info(self):
        secret = bytes.fromhex("0b" * 22)
        actual = self.qsc.hkdf("SHA2-256", secret, b"", b"", 42)
        expected = bytes.fromhex("8da4e775a563c18f715f802a063c5a31" +
                                 "b8a11f5c5ee1879ec3454e5f3c738d2d" + "9d201395faa4b61a96c8")
        self.assertEqual(actual, expected)

    def test_hkdf_sha384_independent_hmac_reference(self):
        import hashlib
        secret, salt, info = b"shared-secret-384", b"salt-384", b"fixed-info"
        prk = hmac.digest(salt, secret, "sha384")
        block = hmac.digest(prk, info + b"\x01", "sha384")
        self.assertEqual(self.qsc.hkdf("SHA2-384", secret, salt, info, 48), block)

    def test_hkdf_sha512_independent_hmac_reference(self):
        secret, salt, info = b"shared-secret-512", b"salt-512", b"info"
        prk = hmac.digest(salt, secret, "sha512")
        block = hmac.digest(prk, info + b"\x01", "sha512")
        self.assertEqual(self.qsc.hkdf("SHA2-512", secret, salt, info, 64), block)

    def test_hkdf_refuses_excessive_output(self):
        with self.assertRaises(ValueError):
            self.qsc.hkdf("SHA2-256", b"x", b"y", b"z", 255 * 32 + 1)


if __name__ == "__main__":
    unittest.main()
