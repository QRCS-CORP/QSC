"""Native ACVP-style vector-response checks for ML-DSA and SLH-DSA parameter sets."""

import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mldsa_client import PARAMETERS as MLDSA, QscMlDsa, build_mldsa_response
from slhdsa_client import PARAMETERS as SLH, QscSlhDsa, build_slhdsa_response


@unittest.skipUnless(os.environ.get("QSC_ACVP_PQ_LIBRARY"), "Compiled PQ library not supplied")
class PqSignatureNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        library = Path(os.environ["QSC_ACVP_PQ_LIBRARY"])
        cls.mldsa = QscMlDsa(library)
        cls.slhdsa = QscSlhDsa(library)

    def check_mldsa(self, param):
        seed = bytes(range(32))
        context = b"QSC-ACVP"
        message = b"QSC native ML-DSA vector replay"
        pk, sk = self.mldsa.keygen(param, seed)
        sig = self.mldsa.sign(param, sk, message, context)
        self.assertTrue(self.mldsa.verify(param, pk, message, context, sig))
        tampered = bytes([sig[0] ^ 1]) + sig[1:]
        self.assertFalse(self.mldsa.verify(param, pk, message, context, tampered))
        self.assertFalse(self.mldsa.verify(param, pk, message, context, sig[:-1]))
        self.assertFalse(self.mldsa.verify(param, pk, message, b"wrong", sig))
        key_group = {"tgId": 1, "testType": "AFT", "parameterSet": param,
                     "tests": [{"tcId": 1, "seed": seed.hex()}]}
        answer = build_mldsa_response([{"acvVersion": "1.0"}, {"vsId": 2,
            "algorithm": "ML-DSA", "mode": "keyGen", "revision": "FIPS204",
            "testGroups": [key_group]}], self.mldsa)[1]["testGroups"][0]["tests"][0]
        self.assertEqual(bytes.fromhex(answer["pk"]), pk)
        self.assertEqual(bytes.fromhex(answer["sk"]), sk)
        sign_group = {"tgId": 2, "testType": "AFT", "parameterSet": param,
                      "signatureInterface": "external", "preHash": "pure", "deterministic": True,
                      "keyFormat": "expanded", "tests": [{"tcId": 2, "sk": sk.hex(),
                      "message": message.hex(), "context": context.hex()}]}
        answer = build_mldsa_response([{"acvVersion": "1.0"}, {"vsId": 3,
            "algorithm": "ML-DSA", "mode": "sigGen", "revision": "FIPS204-tr1",
            "testGroups": [sign_group]}], self.mldsa)[1]["testGroups"][0]["tests"][0]
        self.assertEqual(bytes.fromhex(answer["signature"]), sig)
        ver_group = {"tgId": 3, "testType": "AFT", "parameterSet": param,
                     "signatureInterface": "external", "preHash": "pure", "tests": [
                         {"tcId": 3, "pk": pk.hex(), "message": message.hex(),
                          "context": context.hex(), "signature": sig.hex()},
                         {"tcId": 4, "pk": pk.hex(), "message": message.hex(),
                          "context": context.hex(), "signature": tampered.hex()}]}
        answers = build_mldsa_response([{"acvVersion": "1.0"}, {"vsId": 4,
            "algorithm": "ML-DSA", "mode": "sigVer", "revision": "FIPS204",
            "testGroups": [ver_group]}], self.mldsa)[1]["testGroups"][0]["tests"]
        self.assertTrue(answers[0]["testPassed"])
        self.assertFalse(answers[1]["testPassed"])

    def check_slhdsa(self, param):
        seedlen = SLH[param][-1] // 3
        sk_seed, sk_prf, pk_seed = (bytes([offset]) * seedlen for offset in (11, 12, 13))
        context = b"QSC"
        message = b"QSC native SLH-DSA vector replay"
        pk, sk = self.slhdsa.keygen(param, sk_seed, sk_prf, pk_seed)
        sig = self.slhdsa.sign(param, sk, message, context)
        self.assertTrue(self.slhdsa.verify(param, pk, message, context, sig))
        tampered = bytes([sig[0] ^ 1]) + sig[1:]
        self.assertFalse(self.slhdsa.verify(param, pk, message, context, tampered))
        self.assertFalse(self.slhdsa.verify(param, pk, message, context, sig[:-1]))
        key_group = {"tgId": 1, "testType": "AFT", "parameterSet": param,
                     "tests": [{"tcId": 1, "skSeed": sk_seed.hex(),
                                "skPrf": sk_prf.hex(), "pkSeed": pk_seed.hex()}]}
        answer = build_slhdsa_response([{"acvVersion": "1.0"}, {"vsId": 2,
            "algorithm": "SLH-DSA", "mode": "keyGen", "revision": "FIPS205",
            "testGroups": [key_group]}], self.slhdsa)[1]["testGroups"][0]["tests"][0]
        self.assertEqual(bytes.fromhex(answer["pk"]), pk)
        self.assertEqual(bytes.fromhex(answer["sk"]), sk)
        sign_group = {"tgId": 2, "testType": "AFT", "parameterSet": param,
                      "signatureInterface": "external", "preHash": "pure", "deterministic": True,
                      "tests": [{"tcId": 2, "sk": sk.hex(), "message": message.hex(),
                                 "context": context.hex()}]}
        answer = build_slhdsa_response([{"acvVersion": "1.0"}, {"vsId": 3,
            "algorithm": "SLH-DSA", "mode": "sigGen", "revision": "FIPS205",
            "testGroups": [sign_group]}], self.slhdsa)[1]["testGroups"][0]["tests"][0]
        self.assertEqual(bytes.fromhex(answer["signature"]), sig)
        ver_group = {"tgId": 3, "testType": "AFT", "parameterSet": param,
                     "signatureInterface": "external", "preHash": "pure", "tests": [
                         {"tcId": 3, "pk": pk.hex(), "message": message.hex(),
                          "context": context.hex(), "signature": sig.hex()},
                         {"tcId": 4, "pk": pk.hex(), "message": message.hex(),
                          "context": context.hex(), "signature": tampered.hex()},
                         {"tcId": 5, "pk": pk.hex(), "message": message.hex(),
                          "context": context.hex(), "signature": sig[:-1].hex()}]}
        answers = build_slhdsa_response([{"acvVersion": "1.0"}, {"vsId": 4,
            "algorithm": "SLH-DSA", "mode": "sigVer", "revision": "FIPS205",
            "testGroups": [ver_group]}], self.slhdsa)[1]["testGroups"][0]["tests"]
        self.assertEqual([item["testPassed"] for item in answers], [True, False, False])

    def test_mldsa44(self):
        self.check_mldsa("ML-DSA-44")

    def test_mldsa65(self):
        self.check_mldsa("ML-DSA-65")

    def test_mldsa87(self):
        self.check_mldsa("ML-DSA-87")

    def test_slhdsa128s(self):
        self.check_slhdsa("SLH-DSA-SHAKE-128s")

    def test_slhdsa128f(self):
        self.check_slhdsa("SLH-DSA-SHAKE-128f")

    def test_slhdsa192s(self):
        self.check_slhdsa("SLH-DSA-SHAKE-192s")

    def test_slhdsa192f(self):
        self.check_slhdsa("SLH-DSA-SHAKE-192f")

    def test_slhdsa256s(self):
        self.check_slhdsa("SLH-DSA-SHAKE-256s")

    def test_slhdsa256f(self):
        self.check_slhdsa("SLH-DSA-SHAKE-256f")


if __name__ == "__main__":
    unittest.main()
