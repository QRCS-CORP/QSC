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

"""Tests for Demo protocol orchestration and strict credential handling."""

import importlib.util
from pathlib import Path
import sys
import unittest

TOOL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_ROOT))
import demo_client as client


class FakeTransport:
    """Deterministic test-only server, returning ACVP-shaped responses."""

    def __init__(self, test_type="AFT", passes=True):
        self.test_type = test_type
        self.passes = passes
        self.calls = []
        self.session = client.DEMO_API + "/testSessions/42"
        self.vector = self.session + "/vectorSets/91"

    def request(self, method, path, token=None, body=None):
        self.calls.append((method, path, token, body))
        if path == client.DEMO_API + "/login":
            return [{"acvVersion": "1.0"}, {"accessToken": "private-login-token"}]
        if method == "POST" and path == client.DEMO_API + "/testSessions":
            return [{"acvVersion": "1.0"}, {"url": self.session, "accessToken": "private-session-token",
                      "vectorSetUrls": [self.vector]}]
        if method == "GET" and path == self.vector:
            return [{"acvVersion": "1.0"}, {"vsId": 91, "algorithm": "SHA2-256", "revision": "1.0",
                    "testGroups": [{"tgId": 4, "testType": self.test_type,
                                    "tests": [{"tcId": 9, "msg": "616263", "len": 24}]}]}]
        if method == "POST" and path == self.vector + "/results":
            return [{"acvVersion": "1.0"}, {"status": "received"}]
        if method == "GET" and path == self.session + "/results":
            return [{"acvVersion": "1.0"}, {"passed": self.passes,
                    "results": [{"vectorSetUrl": self.vector,
                                 "status": "passed" if self.passes else "failed"}]}]
        raise AssertionError(f"Unexpected request {method} {path}")


class Oracle:
    def digest(self, algorithm, message, output_bits, key=b""):
        return "AB" * (output_bits // 8)


class DemoClientTests(unittest.TestCase):
    def test_rfc6238_six_digit_example(self):
        self.assertEqual(client.totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59), "287082")

    def test_registration_is_byte_aligned_and_sample_only(self):
        registration = client.registration(("SHA2-256", "SHA3-256"))
        self.assertTrue(registration[1]["isSample"])
        self.assertEqual(registration[1]["algorithms"][1]["revision"], "2.0")
        self.assertEqual(registration[1]["algorithms"][0]["messageLength"][0]["increment"], 8)
        self.assertNotIn("performLargeDataTest", registration[1]["algorithms"][0])

    def test_hmac_and_shake_capabilities(self):
        selected = ("SHA2-256", "HMAC-SHA2-256", "SHAKE-256")
        capabilities = client.registration(selected)[1]["algorithms"]
        self.assertEqual(capabilities[1]["revision"], "2.0")
        self.assertEqual(capabilities[1]["macLen"][0]["max"], 256)
        self.assertEqual(capabilities[1]["prereqVals"][0]["valValue"], "same")
        self.assertEqual(capabilities[2]["revision"], "FIPS202")
        self.assertEqual(capabilities[2]["outputLen"][0]["increment"], 8)

    def test_hmac_requires_sha_prerequisite(self):
        with self.assertRaises(ValueError):
            client.registration(("HMAC-SHA2-256",))

    def test_registration_rejects_unsupported_algorithms(self):
        with self.assertRaises(ValueError):
            client.registration(("ML-DSA-44",))

    def test_rejects_cross_origin_and_parent_paths(self):
        for path in ("https://evil.test/acvp/v1/login", "//evil.test/acvp/v1/login",
                     "/acvp/v1/../login", "/acvp/v1/login?jwt=a", "/other/login"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                client.check_path(path)

    def test_session_execution_with_tokens_redacted_from_report(self):
        transport = FakeTransport()
        report = client.execute(transport, Oracle(), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                                ("SHA2-256",), poll_count=1)
        self.assertEqual(report["status"], "PASS_DEMO_SAMPLE")
        self.assertEqual(report["test_session"], "42")
        self.assertNotIn("private-login-token", str(report))
        self.assertNotIn("private-session-token", str(report))
        self.assertEqual(transport.calls[2][2], "private-session-token")
        self.assertEqual(transport.calls[3][3][1]["testGroups"][0]["tests"][0]["md"], "AB" * 32)

    def test_unsupported_vector_is_never_submitted(self):
        transport = FakeTransport(test_type="LDT")
        report = client.execute(transport, Oracle(), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                                ("SHA2-256",), poll_count=1)
        self.assertEqual(report["status"], "FAIL_OR_UNSUPPORTED_VECTOR")
        self.assertEqual(len(transport.calls), 3)
        self.assertNotIn("private-session-token", str(report))

    def test_demo_failure_verdict_is_not_promoted_to_pass(self):
        transport = FakeTransport(passes=False)
        report = client.execute(transport, Oracle(), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                                ("SHA2-256",), poll_count=1)
        self.assertEqual(report["status"], "FAIL_DEMO_VERDICT")


    def test_partial_successful_server_verdict_does_not_pass(self):
        class PartialTransport(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "GET" and path == self.session + "/results":
                    return [{"acvVersion": "1.0"}, {"passed": True, "results": []}]
                return super().request(method, path, token, body)

        result = client.execute(PartialTransport(), Oracle(),
                                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", ("SHA2-256",), poll_count=1)
        self.assertEqual(result["status"], "FAIL_DEMO_VERDICT")
        self.assertFalse(result["server_passed"])

    def test_verdict_requires_exactly_one_result_per_vector(self):
        session = client.DEMO_API + "/testSessions/42"
        vectors = {session + "/vectorSets/91", session + "/vectorSets/92"}
        def response(entries, passed=True):
            return {"passed": passed, "results": entries}
        one = {"vectorSetUrl": session + "/vectorSets/91", "status": "passed"}
        two = {"vectorSetUrl": session + "/vectorSets/92", "status": "passed"}
        extra = {"vectorSetUrl": session + "/vectorSets/93", "status": "passed"}
        self.assertEqual(client.reconcile_verdict(response([one, two]), vectors), "PASS")
        self.assertEqual(client.reconcile_verdict(response([one]), vectors), "FAIL")
        self.assertEqual(client.reconcile_verdict(response([one, one, two]), vectors), "FAIL")
        self.assertEqual(client.reconcile_verdict(response([one, two, extra]), vectors), "FAIL")
        self.assertEqual(client.reconcile_verdict(response([one, {**two, "status": "incomplete"}]), vectors), "FAIL")
        self.assertEqual(client.reconcile_verdict(response([one], False), vectors), "PENDING")
        self.assertEqual(client.reconcile_verdict(response([one, {**two, "status": "failed"}], False), vectors), "FAIL")
        self.assertEqual(client.reconcile_verdict({"passed": "true", "results": [one, two]}, vectors), "FAIL")

    def test_duplicate_registration_vector_url_fails_before_processing(self):
        class DuplicateTransport(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "POST" and path == client.DEMO_API + "/testSessions":
                    return [{"acvVersion": "1.0"}, {"url": self.session,
                            "vectorSetUrls": [self.vector, self.vector],
                            "accessToken": "private-session-token"}]
                return super().request(method, path, token, body)

        server = DuplicateTransport()
        with self.assertRaisesRegex(ValueError, "duplicate vector-set URL"):
            client.execute(server, Oracle(), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                           ("SHA2-256",), poll_count=1)
        self.assertFalse(any(method == "POST" and path.endswith("/results")
                             for method, path, _, _ in server.calls))

    def test_downloaded_vector_id_must_match_requested_id(self):
        class MismatchedTransport(FakeTransport):
            def request(self, method, path, token=None, body=None):
                result = super().request(method, path, token, body)
                if method == "GET" and path == self.vector:
                    result[1]["vsId"] = 99
                return result

        server = MismatchedTransport()
        report = client.execute(server, Oracle(), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                                ("SHA2-256",), poll_count=1)
        self.assertEqual(report["status"], "FAIL_OR_UNSUPPORTED_VECTOR")
        self.assertFalse(any(method == "POST" and path.endswith("/results")
                             for method, path, _, _ in server.calls))


    def test_ecc_session_cannot_pass_when_selected_modes_are_missing(self):
        class PartialEccTransport(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "GET" and path == self.vector:
                    return [{"acvVersion": "1.0"}, {"vsId": 91, "algorithm": "XECDH",
                            "mode": "keyVer", "revision": "RFC7748",
                            "testGroups": [{"tgId": 1, "testType": "AFT", "curve": "Curve25519",
                                            "tests": [{"tcId": 1, "publicKey": "09" + "00" * 31}]}]}]
                return super().request(method, path, token, body)

        class KeyVerifier:
            def xecdh_keyver(self, curve, value):
                return True

        oracle = Oracle()
        oracle.ecc = KeyVerifier()
        server = PartialEccTransport()
        report = client.execute(server, oracle, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                                ("XECDH",), poll_count=1, drbg_validation="DRBG-TEST-ID")
        self.assertEqual(report["status"], "FAIL_INCOMPLETE_ALGORITHM_COVERAGE")
        self.assertEqual(report["missing_algorithms"], [])
        self.assertEqual(report["missing_ecc_modes"], ["XECDH/SSC", "XECDH/keyGen"])
        self.assertFalse(any(method == "GET" and path == server.session + "/results"
                             for method, path, _, _ in server.calls))

    def test_sample_cannot_pass_with_missing_algorithm_vectors(self):
        server = FakeTransport()
        report = client.execute(server, Oracle(), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                                ("SHA2-256", "SHA3-256"), poll_count=1)
        self.assertEqual(report["status"], "FAIL_INCOMPLETE_ALGORITHM_COVERAGE")
        self.assertEqual(report["missing_algorithms"], ["SHA3-256"])
        self.assertFalse(report["server_passed"])
        self.assertFalse(any(method == "GET" and path == server.session + "/results"
                             for method, path, _, _ in server.calls))


if __name__ == "__main__":
    unittest.main()
