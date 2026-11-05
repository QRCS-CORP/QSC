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

"""SP 800-185 KMAC/cSHAKE offline response schema and native QSC KATs."""

import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from xof_client import QscXof, build_xof_response
from local_client import build_response

KEY = bytes(range(0x40, 0x60))
MSG = bytes.fromhex("00010203")


def vector(algorithm, group):
    return [{"acvVersion": "1.0"}, {"vsId": 43, "algorithm": algorithm,
            "revision": "1.0", "testGroups": [group]}]


class Oracle:
    def compute(self, algorithm, message, size, key=b"", customization=b"",
                function_name=b"", xof=False):
        return bytes([0xA5] * size)


class XofVectorTests(unittest.TestCase):
    def test_cshake_aft_schema(self):
        group = {"tgId": 1, "testType": "AFT", "hexCustomization": False,
                 "tests": [{"tcId": 7, "msg": "00010203", "len": 32, "outLen": 256,
                            "functionName": "", "customization": "Email Signature"}]}
        item = build_xof_response(vector("cSHAKE-128", group), Oracle())[1]["testGroups"][0]["tests"][0]
        self.assertEqual(item, {"tcId": 7, "md": "A5" * 32})

    def test_kmac_aft_schema_and_xof_mode(self):
        group = {"tgId": 2, "testType": "AFT", "hexCustomization": False, "xof": True,
                 "tests": [{"tcId": 3, "msg": "00010203", "msgLen": 32, "macLen": 256,
                            "key": KEY.hex(), "keyLen": 256, "customization": ""}]}
        item = build_xof_response(vector("KMAC-128", group), Oracle())[1]["testGroups"][0]["tests"][0]
        self.assertEqual(item, {"tcId": 3, "mac": "A5" * 32})

    def test_mvt_mct_and_bit_lengths_rejected(self):
        group = {"tgId": 1, "testType": "MVT", "tests": []}
        with self.assertRaises(ValueError):
            build_xof_response(vector("KMAC-128", group), Oracle())
        group["testType"] = "MCT"
        with self.assertRaises(ValueError):
            build_xof_response(vector("cSHAKE-128", group), Oracle())
        group["testType"] = "AFT"
        group["tests"] = [{"tcId": 1, "msg": "00", "len": 7, "outLen": 256}]
        with self.assertRaises(ValueError):
            build_xof_response(vector("cSHAKE-128", group), Oracle())

    def test_invalid_customization_and_key_rejected(self):
        group = {"tgId": 1, "testType": "AFT", "hexCustomization": True, "tests": []}
        with self.assertRaises(ValueError):
            build_xof_response(vector("cSHAKE-128", group), Oracle())
        group["hexCustomization"] = False
        group["tests"] = [{"tcId": 1, "msg": "", "msgLen": 0, "macLen": 256,
                           "keyLen": 256, "key": "AB", "customization": ""}]
        with self.assertRaises(ValueError):
            build_xof_response(vector("KMAC-128", group), Oracle())
        group["tests"][0]["key"] = "AB" * 32
        group["tests"][0]["customization"] = "é"
        with self.assertRaises(ValueError):
            build_xof_response(vector("KMAC-128", group), Oracle())


class XofNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = os.environ.get("QSC_ACVP_HASH_LIBRARY")
        if not path or not Path(path).is_file():
            raise unittest.SkipTest("QSC native SHA/KMAC library was not supplied")
        cls.qsc = QscXof(Path(path))

    def test_cshake128_nist_sample_1(self):
        value = self.qsc.compute("cSHAKE-128", MSG, 32, customization=b"Email Signature")
        self.assertEqual(value.hex().upper(),
                         "C1C36925B6409A04F1B504FCBCA9D82B4017277CB5ED2B2065FC1D3814D5AAF5")

    def test_cshake256_nist_sample_1(self):
        value = self.qsc.compute("cSHAKE-256", MSG, 64, customization=b"Email Signature")
        self.assertEqual(value.hex().upper(),
                         "D008828E2B80AC9D2218FFEE1D070C48B8E4C87BFF32C9699D5B6896EEE0EDD1"
                         "64020E2BE0560858D9C00C037E34A96937C561A74C412BB4C746469527281C8C")

    def test_kmac128_nist_sample_1(self):
        value = self.qsc.compute("KMAC-128", MSG, 32, key=KEY)
        self.assertEqual(value.hex().upper(),
                         "E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E")

    def test_kmac256_nist_sample_4(self):
        value = self.qsc.compute("KMAC-256", MSG, 64, key=KEY,
                                 customization=b"My Tagged Application")
        self.assertEqual(value.hex().upper(),
                         "20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7"
                         "F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD")

    def test_offline_dispatch_routes_to_native_qsc(self):
        group = {"tgId": 1, "testType": "AFT", "hexCustomization": False,
                 "tests": [{"tcId": 6, "msg": "00010203", "len": 32,
                            "outLen": 256, "customization": "Email Signature"}]}
        adapter = type("Q", (), {"xof": self.qsc})()
        response = build_response(vector("cSHAKE-128", group), adapter)
        self.assertEqual(response[1]["testGroups"][0]["tests"][0]["md"],
                         "C1C36925B6409A04F1B504FCBCA9D82B4017277CB5ED2B2065FC1D3814D5AAF5")


if __name__ == "__main__":
    unittest.main()
