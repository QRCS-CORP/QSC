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

"""Mock server session submits three PQ key-generation vector sets consecutively."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from demo_client import DEMO_API, execute


class FakePQ:
    def keygen(self, *values):
        return b"\x01" * 32, b"\x02" * 64


class FakeQsc:
    kem = FakePQ()
    dsa = FakePQ()
    slh = FakePQ()


class FakeSession:
    def __init__(self):
        self.root = DEMO_API + "/testSessions/88"
        self.paths = [self.root + "/vectorSets/" + str(x) for x in (1, 2, 3)]
        self.algorithms = ("ML-KEM", "ML-DSA", "SLH-DSA")
        self.requests = []

    def request(self, method, path, token=None, body=None):
        self.requests.append((method, path, token, body))
        if path == DEMO_API + "/login":
            return [{"acvVersion": "1.0"}, {"accessToken": "PRIVATE_LOGIN_TOKEN"}]
        if method == "POST" and path == DEMO_API + "/testSessions":
            return [{"acvVersion": "1.0"}, {"url": self.root,
                    "accessToken": "PRIVATE_SESSION_TOKEN", "vectorSetUrls": self.paths}]
        if method == "GET" and path in self.paths:
            index = self.paths.index(path)
            algorithm = self.algorithms[index]
            parameter = ("ML-KEM-512", "ML-DSA-44", "SLH-DSA-SHAKE-128s")[index]
            testcase = ({"tcId": 1, "d": "AA" * 32, "z": "BB" * 32} if index == 0 else
                        {"tcId": 1, "seed": "AA" * 32} if index == 1 else
                        {"tcId": 1, "skSeed": "AA" * 16, "skPrf": "BB" * 16,
                         "pkSeed": "CC" * 16})
            return [{"acvVersion": "1.0"}, {"vsId": index + 1,
                    "algorithm": algorithm, "mode": "keyGen",
                    "revision": ("FIPS203", "FIPS204", "FIPS205")[index],
                    "testGroups": [{"tgId": 1, "testType": "AFT",
                                    "parameterSet": parameter, "tests": [testcase]}]}]
        if method == "POST" and path.endswith("/results"):
            return [{"acvVersion": "1.0"}, {}]
        if method == "GET" and path == self.root + "/results":
            return [{"acvVersion": "1.0"}, {"passed": True, "results": [
                {"status": "passed", "vectorSetUrl": path} for path in self.paths]}]
        raise ValueError("Unexpected mock transport endpoint")


class PqDemoSessionTests(unittest.TestCase):
    def test_pq_vector_sets_submitted_consecutively_and_tokens_redacted(self):
        server = FakeSession()
        selected = ("SHA3-256", "SHA3-512", "SHAKE-128", "SHAKE-256",
                    "ML-KEM", "ML-DSA", "SLH-DSA")
        result = execute(server, FakeQsc(), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                         selected, poll_count=1)
        self.assertEqual(result["status"], "FAIL_INCOMPLETE_ALGORITHM_COVERAGE")
        self.assertEqual([v["algorithm"] for v in result["vectors"]],
                         ["ML-KEM", "ML-DSA", "SLH-DSA"])
        posts = [path for method, path, _, _ in server.requests
                 if method == "POST" and path.endswith("/results")]
        self.assertEqual(posts, [path + "/results" for path in server.paths])
        self.assertNotIn("PRIVATE_LOGIN_TOKEN", str(result))
        self.assertNotIn("PRIVATE_SESSION_TOKEN", str(result))
        self.assertNotIn("0202", str(result))


if __name__ == "__main__":
    unittest.main()
