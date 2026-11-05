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

"""ECC ACVP JSON response tests, independent interoperability and fail-closed parsing."""

from pathlib import Path
import os
import sys
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, x25519, x448
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ecc_client import QscEcc, build_ecc_response, build_kas_response, registration
from local_client import build_response


def vector(algorithm, mode, revision, group):
    return [{"acvVersion": "1.0"}, {"vsId": 27, "algorithm": algorithm,
            "mode": mode, "revision": revision, "testGroups": [group]}]


class MockEcc:
    def ecdsa_verify(self, *args):
        return True

    def ecdsa_keygen(self, curve):
        size = {"P-256": 32, "P-384": 48, "P-521": 66}[curve]
        return bytes([1]) * size, bytes([2]) * (2 * size)

    def ecdsa_keyver(self, curve, public):
        return bool(public[0])

    def eddsa_keygen(self, curve):
        size = 32 if curve == "ED-25519" else 57
        return bytes([3]) * size, bytes([4]) * size

    def eddsa_keyver(self, curve, public):
        return bool(public[0])

    def xecdh_keygen(self, curve):
        size = 32 if curve == "Curve25519" else 56
        return bytes([5]) * size, bytes([6]) * size

    def xecdh_keyver(self, curve, public):
        return bool(public[0])

    def eddsa_verify(self, *args):
        return True

    def xecdh_ssc(self, curve, server_public):
        return b"\xAB" * len(server_public), b"\xCD" * len(server_public)

    def ecdsa_sign_group(self, curve, messages):
        size = {"P-256": 32, "P-384": 48, "P-521": 66}[curve]
        return b"\xAA" * (2 * size), [(b"\x01" * size, b"\x02" * size) for _ in messages]

    def eddsa_sign_group(self, curve, messages):
        size = 32 if curve == "ED-25519" else 57
        sig_size = 64 if curve == "ED-25519" else 114
        return b"\xAA" * size, [b"\xBB" * sig_size for _ in messages]


class ECCVectorTests(unittest.TestCase):
    def test_ecc_capabilities_include_all_curves_and_supported_modes(self):
        modes = registration("ECDSA", "DRBG-TEST-ID")
        self.assertEqual([m["mode"] for m in modes], ["keyGen", "keyVer", "sigVer"])
        self.assertEqual(modes[0]["curve"], ["P-256", "P-384", "P-521"])
        self.assertEqual(registration("DetECDSA", "DRBG-TEST-ID")[0]["mode"], "sigGen")
        self.assertEqual(len(registration("EDDSA", "DRBG-TEST-ID")), 4)
        self.assertEqual(registration("EDDSA", "DRBG-TEST-ID", "keyVer")[0]["curve"],
                         ["ED-25519", "ED-448"])
        self.assertEqual([m["mode"] for m in registration("XECDH", "DRBG-TEST-ID")],
                         ["keyGen", "keyVer", "SSC"])
        self.assertIn("staticUnified", registration("KAS-ECC-SSC", "DRBG-TEST-ID")[0]["scheme"])
        self.assertEqual([x["curve"][0] for x in modes[2]["capabilities"]],
                         ["P-256", "P-384", "P-521"])

    def test_ecc_registration_requires_real_drbg_prerequisite(self):
        for claim in (None, "", "same"):
            with self.subTest(claim=claim), self.assertRaises(ValueError):
                registration("ECDSA", claim)

    def test_deterministic_ecdsa_signature_group_response(self):
        group = {"tgId": 5, "testType": "AFT", "curve": "P-384", "hashAlg": "SHA2-384",
                 "tests": [{"tcId": 1, "message": "AA"}, {"tcId": 2, "message": "BB"}]}
        answer = build_response(vector("DetECDSA", "sigGen", "FIPS186-5", group),
                                type("Q", (), {"ecc": MockEcc()})())
        result = answer[1]["testGroups"][0]
        self.assertEqual(result["qx"], "AA" * 48)
        self.assertEqual(result["qy"], "AA" * 48)
        self.assertEqual(result["tests"][1], {"tcId": 2, "r": "01" * 48, "s": "02" * 48})

    def test_eddsa_signature_group_response(self):
        group = {"tgId": 3, "testType": "AFT", "curve": "ED-25519", "preHash": False,
                 "tests": [{"tcId": 9, "message": ""}, {"tcId": 10, "message": "0123"}]}
        answer = build_ecc_response(vector("EDDSA", "sigGen", "1.0", group), MockEcc())
        result = answer[1]["testGroups"][0]
        self.assertEqual(result["q"], "AA" * 32)
        self.assertEqual(result["tests"][0], {"tcId": 9, "signature": "BB" * 64})
        self.assertEqual(len(result["tests"]), 2)

    def test_signing_rejects_unsupported_context_and_prehash(self):
        group = {"tgId": 3, "testType": "AFT", "curve": "ED-448", "preHash": False,
                 "tests": [{"tcId": 1, "message": "AA", "context": "11"}]}
        with self.assertRaises(ValueError):
            build_ecc_response(vector("EDDSA", "sigGen", "1.0", group), MockEcc())
        group["tests"][0].pop("context")
        group["preHash"] = True
        with self.assertRaises(ValueError):
            build_ecc_response(vector("EDDSA", "sigGen", "1.0", group), MockEcc())
        group = {"tgId": 3, "testType": "AFT", "curve": "P-256", "hashAlg": "SHA2-256",
                 "conformance": "SP800-106", "tests": [{"tcId": 1, "message": "AA"}]}
        with self.assertRaises(ValueError):
            build_ecc_response(vector("DetECDSA", "sigGen", "FIPS186-5", group), MockEcc())

    def test_ecdsa_signature_response_fields(self):
        group = {"tgId": 1, "testType": "AFT", "curve": "P-384",
                 "hashAlg": "SHA2-384", "tests": [{"tcId": 9, "message": "ABCD",
                 "qx": "01", "qy": "02", "r": "03", "s": "04"}]}
        result = build_response(vector("ECDSA", "sigVer", "FIPS186-5", group),
                                type("Q", (), {"ecc": MockEcc()})())
        self.assertEqual(result[1]["testGroups"][0]["tests"], [{"tcId": 9, "testPassed": True}])

    def test_ecdsa_rejects_wrong_hash_and_sp800_106(self):
        group = {"tgId": 1, "testType": "AFT", "curve": "P-256", "hashAlg": "SHA2-512", "tests": []}
        with self.assertRaises(ValueError):
            build_ecc_response(vector("ECDSA", "sigVer", "FIPS186-5", group), MockEcc())
        group["hashAlg"] = "SHA2-256"
        group["conformance"] = "SP800-106"
        with self.assertRaises(ValueError):
            build_ecc_response(vector("ECDSA", "sigVer", "FIPS186-5", group), MockEcc())

    def test_eddsa_pure_signature_response_and_prehash_rejection(self):
        group = {"tgId": 2, "curve": "ED-448", "testType": "AFT", "preHash": False,
                 "tests": [{"tcId": 7, "message": "0123", "q": "AA" * 57,
                            "signature": "BB" * 114}]}
        result = build_ecc_response(vector("EDDSA", "sigVer", "1.0", group), MockEcc())
        self.assertTrue(result[1]["testGroups"][0]["tests"][0]["testPassed"])
        group["preHash"] = True
        with self.assertRaises(ValueError):
            build_ecc_response(vector("EDDSA", "sigVer", "1.0", group), MockEcc())

    def test_xecdh_shared_secret_response(self):
        group = {"tgId": 1, "curve": "Curve25519", "testType": "AFT",
                 "tests": [{"tcId": 3, "publicServer": "01" * 32}]}
        response = build_ecc_response(vector("XECDH", "SSC", "RFC7748", group), MockEcc())
        self.assertEqual(response[1]["testGroups"][0]["tests"],
                         [{"tcId": 3, "publicIut": "AB" * 32, "z": "CD" * 32}])

    def test_kas_rejects_mqv_and_unsupported_hashz(self):
        group = {"tgId": 1, "testType": "AFT", "scheme": "fullMqv", "kasRole": "initiator",
                 "domainParameterGenerationMode": "P-384", "tests": []}
        with self.assertRaises(ValueError):
            build_kas_response(vector("KAS-ECC-SSC", None, "Sp800-56Ar3", group), MockEcc())
        group["scheme"] = "staticUnified"
        group["hashFunctionZ"] = "SHA2-384"
        with self.assertRaises(ValueError):
            build_kas_response(vector("KAS-ECC-SSC", None, "Sp800-56Ar3", group), MockEcc())

    def test_no_missing_ecc_library_or_unsupported_modes_accepted(self):
        group = {"tgId": 1, "curve": "P-256", "hashAlg": "SHA2-256", "testType": "AFT", "tests": []}
        with self.assertRaises(ValueError):
            build_response(vector("ECDSA", "sigVer", "FIPS186-5", group), object())
        with self.assertRaises(ValueError):
            build_ecc_response(vector("ECDSA", "keyGen", "1.0", group), MockEcc())

    def test_ecdsa_keygen_and_keyver_json_all_curves(self):
        for curve, width in (("P-256", 32), ("P-384", 48), ("P-521", 66)):
            with self.subTest(curve=curve):
                group = {"tgId": 1, "testType": "AFT", "curve": curve,
                         "secretGenerationMode": "testing candidates", "tests": [{"tcId": 1}]}
                reply = build_ecc_response(vector("ECDSA", "keyGen", "FIPS186-5", group), MockEcc())
                item = reply[1]["testGroups"][0]["tests"][0]
                self.assertEqual(len(item["d"]), 2 * width)
                self.assertEqual(len(item["qx"]), 2 * width)
                self.assertEqual(len(item["qy"]), 2 * width)
                group = {"tgId": 2, "testType": "AFT", "curve": curve,
                         "tests": [{"tcId": 2, "qx": "01" * width, "qy": "01" * width},
                                   {"tcId": 3, "qx": "00" * width, "qy": "00" * width}]}
                reply = build_ecc_response(vector("ECDSA", "keyVer", "FIPS186-5", group), MockEcc())
                self.assertEqual([t["testPassed"] for t in reply[1]["testGroups"][0]["tests"]],
                                 [True, False])

    def test_eddsa_keygen_and_keyver_json_both_curves(self):
        for curve, width in (("ED-25519", 32), ("ED-448", 57)):
            with self.subTest(curve=curve):
                group = {"tgId": 1, "curve": curve, "testType": "AFT",
                         "tests": [{"tcId": 1}]}
                answer = build_ecc_response(vector("EDDSA", "keyGen", "1.0", group), MockEcc())
                self.assertEqual(answer[1]["testGroups"][0]["tests"][0]["d"], "03" * width)
                group["tests"] = [{"tcId": 2, "q": "01" * width},
                                  {"tcId": 3, "q": "00" * width}]
                answer = build_ecc_response(vector("EDDSA", "keyVer", "1.0", group), MockEcc())
                self.assertEqual([t["testPassed"] for t in answer[1]["testGroups"][0]["tests"]],
                                 [True, False])

    def test_xecdh_keygen_and_keyver_json_both_curves(self):
        for curve, width in (("Curve25519", 32), ("Curve448", 56)):
            with self.subTest(curve=curve):
                group = {"tgId": 1, "curve": curve, "testType": "AFT", "tests": [{"tcId": 1}]}
                answer = build_ecc_response(vector("XECDH", "keyGen", "RFC7748", group), MockEcc())
                self.assertEqual(answer[1]["testGroups"][0]["tests"][0]["privateKey"], "05" * width)
                group["tests"] = [{"tcId": 2, "publicKey": "01" * width},
                                  {"tcId": 3, "publicKey": "00" * width}]
                answer = build_ecc_response(vector("XECDH", "keyVer", "RFC7748", group), MockEcc())
                self.assertEqual([t["testPassed"] for t in answer[1]["testGroups"][0]["tests"]],
                                 [True, False])

    def test_ecc_rejects_duplicate_case_and_group_identifiers(self):
        group = {"tgId": 1, "curve": "Curve25519", "testType": "AFT",
                 "tests": [{"tcId": 1}, {"tcId": 1}]}
        with self.assertRaises(ValueError):
            build_ecc_response(vector("XECDH", "keyGen", "RFC7748", group), MockEcc())
        group["tests"] = [{"tcId": 1}]
        request = vector("XECDH", "keyGen", "RFC7748", group)
        request[1]["testGroups"].append(group.copy())
        with self.assertRaises(ValueError):
            build_ecc_response(request, MockEcc())

    def test_ecc_unsupported_mode_and_generation_policy_fail_closed(self):
        group = {"tgId": 1, "curve": "P-384", "testType": "AFT", "tests": [{"tcId": 1}],
                 "secretGenerationMode": "extra bits"}
        with self.assertRaises(ValueError):
            build_ecc_response(vector("ECDSA", "keyGen", "FIPS186-5", group), MockEcc())
        with self.assertRaises(ValueError):
            registration("ECDSA", "DRBG-TEST-ID", "sigGen")
        with self.assertRaises(ValueError):
            registration("EDDSA", "same")

    def test_hex_parser_rejects_untrusted_lengths_and_spaces(self):
        group = {"tgId": 1, "testType": "AFT", "curve": "ED-25519", "preHash": False,
                 "tests": [{"tcId": 1, "message": "00 01", "q": "AA" * 32,
                            "signature": "BB" * 64}]}
        with self.assertRaises(ValueError):
            build_ecc_response(vector("EDDSA", "sigVer", "1.0", group), MockEcc())


class ECCNativeVectorTests(unittest.TestCase):
    """Directly exercise native QSC in the existing preliminary qualification library."""

    @classmethod
    def setUpClass(cls):
        path = os.environ.get("QSC_ACVP_ECC_LIBRARY")
        if not path or not Path(path).is_file():
            raise unittest.SkipTest("Native ECC library not supplied")
        cls.ecc = QscEcc(Path(path), require_complete=os.environ.get("QSC_ACVP_ECC_COMPLETE") == "1")

    def test_qsc_ecdsa_keygen_and_keyver_independent_all_curves(self):
        configurations = (("P-256", ec.SECP256R1(), 32),
                          ("P-521", ec.SECP521R1(), 66))
        for curve, oracle, size in configurations:
            with self.subTest(curve=curve):
                private, public = self.ecc.ecdsa_keygen(curve)
                derived = ec.derive_private_key(int.from_bytes(private, "big"), oracle)
                point = derived.public_key().public_numbers()
                self.assertEqual(public, point.x.to_bytes(size, "big") + point.y.to_bytes(size, "big"))
                self.assertTrue(self.ecc.ecdsa_keyver(curve, public))
                self.assertFalse(self.ecc.ecdsa_keyver(curve, bytes(size * 2)))

    def test_qsc_ecdsa_p384_keygen_and_keyver(self):
        if os.environ.get("QSC_ACVP_ECC_COMPLETE") != "1":
            self.skipTest("P-384 signer required for native key-generation and key-verification")
        private, public = self.ecc.ecdsa_keygen("P-384")
        reference = ec.derive_private_key(int.from_bytes(private, "big"), ec.SECP384R1())
        point = reference.public_key().public_numbers()
        self.assertEqual(public, point.x.to_bytes(48, "big") + point.y.to_bytes(48, "big"))
        self.assertTrue(self.ecc.ecdsa_keyver("P-384", public))
        self.assertFalse(self.ecc.ecdsa_keyver("P-384", bytes(96)))

    def test_qsc_eddsa_keygen_and_keyver_native_curves(self):
        for curve, parser in (("ED-25519", ed25519.Ed25519PrivateKey),
                              ("ED-448", ed448.Ed448PrivateKey)):
            with self.subTest(curve=curve):
                seed, public = self.ecc.eddsa_keygen(curve)
                oracle = parser.from_private_bytes(seed)
                expected = oracle.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                self.assertEqual(public, expected)
                self.assertTrue(self.ecc.eddsa_keyver(curve, public))
                self.assertFalse(self.ecc.eddsa_keyver(curve, bytes(len(public))))

    def test_qsc_xecdh_keygen_and_keyver_native_curves(self):
        for curve, parser in (("Curve25519", x25519.X25519PrivateKey),
                              ("Curve448", x448.X448PrivateKey)):
            with self.subTest(curve=curve):
                private, public = self.ecc.xecdh_keygen(curve)
                oracle = parser.from_private_bytes(private)
                expected = oracle.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                self.assertEqual(public, expected)
                self.assertTrue(self.ecc.xecdh_keyver(curve, public))
                self.assertFalse(self.ecc.xecdh_keyver(curve, bytes(len(public))))

    def test_qsc_ecdsa_p256_signature_verify_and_tamper_rejection(self):
        key = ec.derive_private_key(71, ec.SECP256R1())
        data = b"QSC ACVP P-256 signature verification test"
        signature = key.sign(data, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(signature)
        coords = key.public_key().public_numbers()
        args = ("P-256", data, f"{coords.x:064X}", f"{coords.y:064X}",
                f"{r:064X}", f"{s:064X}")
        self.assertTrue(self.ecc.ecdsa_verify(*args))
        self.assertFalse(self.ecc.ecdsa_verify("P-256", b"tampered", *args[2:]))

    def test_qsc_ecdsa_p384_signature_verify_and_tamper_rejection(self):
        if os.environ.get("QSC_ACVP_ECC_COMPLETE") != "1":
            self.skipTest("P-384 signing mandatory, source update pending")
        key = ec.derive_private_key(79, ec.SECP384R1())
        data = b"QSC ACVP P-384 signature verification test"
        signature = key.sign(data, ec.ECDSA(hashes.SHA384()))
        r, s = decode_dss_signature(signature)
        coords = key.public_key().public_numbers()
        args = ("P-384", data, f"{coords.x:096X}", f"{coords.y:096X}",
                f"{r:096X}", f"{s:096X}")
        self.assertTrue(self.ecc.ecdsa_verify(*args))
        self.assertFalse(self.ecc.ecdsa_verify("P-384", b"tampered", *args[2:]))
        result = build_ecc_response(vector("DetECDSA", "sigGen", "FIPS186-5",
            {"tgId": 13, "curve": "P-384", "hashAlg": "SHA2-384", "testType": "AFT",
             "tests": [{"tcId": 1, "message": "414243"}]}), self.ecc)
        item = result[1]["testGroups"][0]
        key = ec.EllipticCurvePublicNumbers(int(item["qx"], 16), int(item["qy"], 16),
                                            ec.SECP384R1()).public_key()
        key.verify(encode_dss_signature(int(item["tests"][0]["r"], 16),
                                        int(item["tests"][0]["s"], 16)),
                   b"ABC", ec.ECDSA(hashes.SHA384()))

    def test_qsc_deterministic_ecdsa_p256_signing_vectors(self):
        messages = [b"ACVP deterministic P256", b"ACVP deterministic P256", b"second vector"]
        group = {"tgId": 11, "curve": "P-256", "hashAlg": "SHA2-256", "testType": "AFT",
                 "tests": [{"tcId": index + 1, "message": m.hex()} for index, m in enumerate(messages)]}
        answer = build_ecc_response(vector("DetECDSA", "sigGen", "FIPS186-5", group), self.ecc)
        response = answer[1]["testGroups"][0]
        key = ec.EllipticCurvePublicNumbers(int(response["qx"], 16), int(response["qy"], 16),
                                            ec.SECP256R1()).public_key()
        for message, case in zip(messages, response["tests"]):
            key.verify(encode_dss_signature(int(case["r"], 16), int(case["s"], 16)),
                       message, ec.ECDSA(hashes.SHA256()))
        self.assertEqual(response["tests"][0]["r"], response["tests"][1]["r"])
        self.assertEqual(response["tests"][0]["s"], response["tests"][1]["s"])

    def test_qsc_deterministic_ecdsa_p521_signing_vectors(self):
        group = {"tgId": 12, "curve": "P-521", "hashAlg": "SHA2-512", "testType": "AFT",
                 "tests": [{"tcId": 1, "message": ""}, {"tcId": 2, "message": "414243"}]}
        result = build_ecc_response(vector("DetECDSA", "sigGen", "FIPS186-5", group), self.ecc)
        item = result[1]["testGroups"][0]
        key = ec.EllipticCurvePublicNumbers(int(item["qx"], 16), int(item["qy"], 16),
                                            ec.SECP521R1()).public_key()
        key.verify(encode_dss_signature(int(item["tests"][0]["r"], 16),
                                        int(item["tests"][0]["s"], 16)),
                   b"", ec.ECDSA(hashes.SHA512()))
        key.verify(encode_dss_signature(int(item["tests"][1]["r"], 16),
                                        int(item["tests"][1]["s"], 16)),
                   b"ABC", ec.ECDSA(hashes.SHA512()))

    def test_qsc_eddsa_ed25519_signature_generation(self):
        group = {"tgId": 5, "curve": "ED-25519", "testType": "AFT", "preHash": False,
                 "tests": [{"tcId": 1, "message": ""}, {"tcId": 2, "message": "414243"}]}
        answer = build_ecc_response(vector("EDDSA", "sigGen", "1.0", group), self.ecc)
        response = answer[1]["testGroups"][0]
        key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(response["q"]))
        key.verify(bytes.fromhex(response["tests"][0]["signature"]), b"")
        key.verify(bytes.fromhex(response["tests"][1]["signature"]), b"ABC")

    def test_qsc_eddsa_ed448_signature_generation(self):
        group = {"tgId": 5, "curve": "ED-448", "testType": "AFT", "preHash": False,
                 "tests": [{"tcId": 1, "message": ""}, {"tcId": 2, "message": "414243", "context": ""}]}
        answer = build_ecc_response(vector("EDDSA", "sigGen", "1.0", group), self.ecc)
        response = answer[1]["testGroups"][0]
        key = ed448.Ed448PublicKey.from_public_bytes(bytes.fromhex(response["q"]))
        key.verify(bytes.fromhex(response["tests"][0]["signature"]), b"")
        key.verify(bytes.fromhex(response["tests"][1]["signature"]), b"ABC")

    def test_qsc_ecdsa_p521_signature_verify_and_tamper_rejection(self):
        key = ec.derive_private_key(41, ec.SECP521R1())
        data = b"QSC ACVP P-521 signature verification test"
        signature = key.sign(data, ec.ECDSA(hashes.SHA512()))
        r, s = decode_dss_signature(signature)
        coords = key.public_key().public_numbers()
        args = ("P-521", data, f"{coords.x:0132X}", f"{coords.y:0132X}",
                f"{r:0132X}", f"{s:0132X}")
        self.assertTrue(self.ecc.ecdsa_verify(*args))
        self.assertFalse(self.ecc.ecdsa_verify("P-521", b"tampered", *args[2:]))

    def test_qsc_ed25519_signature_verify_and_tamper_rejection(self):
        private = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        message = b"ed25519 QSC ACVP"
        signature = private.sign(message)
        public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.assertTrue(self.ecc.eddsa_verify("ED-25519", message, public, signature))
        self.assertFalse(self.ecc.eddsa_verify("ED-25519", message + b"bad", public, signature))

    def test_qsc_ed448_signature_verify_and_tamper_rejection(self):
        private = ed448.Ed448PrivateKey.from_private_bytes(bytes(range(57)))
        message = b"ed448 QSC ACVP"
        signature = private.sign(message)
        public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.assertTrue(self.ecc.eddsa_verify("ED-448", message, public, signature))
        self.assertFalse(self.ecc.eddsa_verify("ED-448", message + b"bad", public, signature))

    def test_qsc_x25519_ssc_matches_independent_exchange(self):
        private = x25519.X25519PrivateKey.generate()
        server = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        public, secret = self.ecc.xecdh_ssc("Curve25519", server)
        expected = private.exchange(x25519.X25519PublicKey.from_public_bytes(public))
        self.assertEqual(secret, expected)

    def test_qsc_x448_ssc_matches_independent_exchange(self):
        private = x448.X448PrivateKey.generate()
        server = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        public, secret = self.ecc.xecdh_ssc("Curve448", server)
        expected = private.exchange(x448.X448PublicKey.from_public_bytes(public))
        self.assertEqual(secret, expected)

    def test_qsc_kas_ecc_static_unified_all_curves_aft_and_val(self):
        configurations = (("P-256", ec.SECP256R1(), 32),
                          ("P-384", ec.SECP384R1(), 48),
                          ("P-521", ec.SECP521R1(), 66))
        for name, curve, width in configurations:
            with self.subTest(curve=name):
                server = ec.derive_private_key(523, curve)
                coordinates = server.public_key().public_numbers()
                fields = {"staticPublicServerX": f"{coordinates.x:0{width * 2}X}",
                          "staticPublicServerY": f"{coordinates.y:0{width * 2}X}"}
                group = {"tgId": 1, "testType": "AFT", "scheme": "staticUnified",
                         "kasRole": "initiator", "domainParameterGenerationMode": name,
                         "tests": [{"tcId": 1, **fields}]}
                response = build_kas_response(
                    vector("KAS-ECC-SSC", None, "Sp800-56Ar3", group), self.ecc)
                values = response[1]["testGroups"][0]["tests"][0]
                x = int(values["staticPublicIutX"], 16)
                y = int(values["staticPublicIutY"], 16)
                public = ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
                self.assertEqual(bytes.fromhex(values["z"]), server.exchange(ec.ECDH(), public))
                other_private = ec.derive_private_key(703, curve)
                other_public = other_private.public_key().public_numbers()
                shared = other_private.exchange(ec.ECDH(), server.public_key())
                group["testType"] = "VAL"
                group["tests"] = [{"tcId": 2, **fields,
                                   "staticPrivateIut": f"{703:0{width * 2}X}",
                                   "staticPublicIutX": f"{other_public.x:0{width * 2}X}",
                                   "staticPublicIutY": f"{other_public.y:0{width * 2}X}",
                                   "z": shared.hex()}]
                accepted = build_kas_response(
                    vector("KAS-ECC-SSC", None, "Sp800-56Ar3", group), self.ecc)
                self.assertTrue(accepted[1]["testGroups"][0]["tests"][0]["testPassed"])
                group["tests"][0]["z"] = bytes(width).hex()
                rejected = build_kas_response(
                    vector("KAS-ECC-SSC", None, "Sp800-56Ar3", group), self.ecc)
                self.assertFalse(rejected[1]["testGroups"][0]["tests"][0]["testPassed"])



if __name__ == "__main__":
    unittest.main()
