"""Unsupported PQ capability and vector-set forms must always fail closed."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from demo_client import registration
from mldsa_client import build_mldsa_response
from slhdsa_client import build_slhdsa_response
from local_client import build_response


class FakeDsa:
    def keygen(self, name, seed):
        return b"\x01" * 1312, b"\x02" * 2560

    def sign(self, name, sk, message, context):
        return b"\x03" * 2420

    def verify(self, name, pk, message, context, signature):
        return signature[0] == 3


class FakeSlh:
    def keygen(self, name, skseed, skprf, pkseed):
        return b"\x01" * 32, b"\x02" * 64

    def sign(self, name, sk, message, context):
        return b"\x03" * 7856

    def verify(self, name, pk, message, context, signature):
        return len(signature) == 7856


def vector(algorithm, mode, revision, group):
    return [{"acvVersion": "1.0"}, {"vsId": 7, "algorithm": algorithm,
            "mode": mode, "revision": revision, "testGroups": [group]}]


class PqVectorModeTests(unittest.TestCase):
    def test_registration_is_restricted_to_supported_signature_interfaces(self):
        selection = ("SHA2-256", "SHA3-256", "SHA3-512", "SHAKE-128", "SHAKE-256",
                     "ML-KEM", "ML-DSA", "SLH-DSA")
        caps = registration(selection)[1]["algorithms"]
        self.assertEqual(len(caps), 13)
        for algorithm in ("ML-DSA", "SLH-DSA"):
            signing = next(c for c in caps if c.get("algorithm") == algorithm and c.get("mode") == "sigGen")
            self.assertEqual(signing["signatureInterfaces"], ["external"])
            self.assertEqual(signing["preHash"], ["pure"])
            self.assertEqual(signing["deterministic"], [True])

    def test_ml_dsa_seeded_keygen_vector(self):
        group = {"tgId": 1, "testType": "AFT", "parameterSet": "ML-DSA-44",
                 "tests": [{"tcId": 1, "seed": "AB" * 32}]}
        actual = build_mldsa_response(vector("ML-DSA", "keyGen", "FIPS204", group), FakeDsa())
        self.assertEqual(len(actual[1]["testGroups"][0]["tests"][0]["pk"]), 2624)

    def test_ml_dsa_rejects_randomized_siggen(self):
        group = {"tgId": 1, "testType": "AFT", "parameterSet": "ML-DSA-44",
                 "signatureInterface": "external", "preHash": "pure", "deterministic": False,
                 "keyFormat": "expanded", "tests": []}
        with self.assertRaises(ValueError):
            build_mldsa_response(vector("ML-DSA", "sigGen", "FIPS204-tr1", group), FakeDsa())

    def test_ml_dsa_rejects_internal_mu_siggen(self):
        group = {"tgId": 1, "testType": "AFT", "parameterSet": "ML-DSA-44",
                 "signatureInterface": "internal", "externalMu": True, "deterministic": True,
                 "keyFormat": "expanded", "tests": []}
        with self.assertRaises(ValueError):
            build_mldsa_response(vector("ML-DSA", "sigGen", "FIPS204-tr1", group), FakeDsa())

    def test_slhdsa_seeded_keygen_vector(self):
        group = {"tgId": 1, "testType": "AFT", "parameterSet": "SLH-DSA-SHAKE-128s",
                 "tests": [{"tcId": 1, "skSeed": "AB" * 16, "skPrf": "CD" * 16,
                            "pkSeed": "EF" * 16}]}
        actual = build_slhdsa_response(vector("SLH-DSA", "keyGen", "FIPS205", group), FakeSlh())
        self.assertEqual(len(actual[1]["testGroups"][0]["tests"][0]["sk"]), 128)

    def test_slhdsa_rejects_nondeterministic_signatures(self):
        group = {"tgId": 1, "testType": "AFT", "parameterSet": "SLH-DSA-SHAKE-128s",
                 "signatureInterface": "external", "preHash": "pure", "deterministic": False,
                 "tests": []}
        with self.assertRaises(ValueError):
            build_slhdsa_response(vector("SLH-DSA", "sigGen", "FIPS205", group), FakeSlh())

    def test_slhdsa_rejects_prehash(self):
        group = {"tgId": 1, "testType": "AFT", "parameterSet": "SLH-DSA-SHAKE-128s",
                 "signatureInterface": "external", "preHash": "preHash", "tests": []}
        with self.assertRaises(ValueError):
            build_slhdsa_response(vector("SLH-DSA", "sigVer", "FIPS205", group), FakeSlh())

    def test_global_dispatch_requires_configured_signature_libraries(self):
        group = {"tgId": 1, "testType": "AFT", "parameterSet": "ML-DSA-44", "tests": []}
        with self.assertRaises(ValueError):
            build_response(vector("ML-DSA", "keyGen", "FIPS204", group), object())
        group["parameterSet"] = "SLH-DSA-SHAKE-128s"
        with self.assertRaises(ValueError):
            build_response(vector("SLH-DSA", "keyGen", "FIPS205", group), object())


if __name__ == "__main__":
    unittest.main()
