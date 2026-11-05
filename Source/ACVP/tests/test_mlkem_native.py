"""Native QSC ML-KEM ACVP adapter checks for all three parameter sets."""

import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mlkem_client import PARAMETERS, QscMlKem, build_mlkem_response


@unittest.skipUnless(os.environ.get("QSC_ACVP_PQ_LIBRARY"), "QSC PQ library not provided")
class MlKemNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qsc = QscMlKem(Path(os.environ["QSC_ACVP_PQ_LIBRARY"]))

    def check_parameter(self, name):
        d = bytes(range(32))
        z = bytes(range(32, 64))
        m = bytes(reversed(range(32)))
        pk, sk = self.qsc.keygen(name, d, z)
        ciphertext, secret = self.qsc.encapsulate(name, pk, m)
        self.assertEqual(secret, self.qsc.decapsulate(name, sk, ciphertext))
        modified = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
        self.assertNotEqual(secret, self.qsc.decapsulate(name, sk, modified))
        group = {"tgId": 5, "testType": "AFT", "parameterSet": name,
                 "tests": [{"tcId": 1, "d": d.hex(), "z": z.hex()}]}
        answer = build_mlkem_response([{"acvVersion": "1.0"}, {
            "vsId": 21, "algorithm": "ML-KEM", "revision": "FIPS203", "mode": "keyGen",
            "testGroups": [group]}], self.qsc)[1]["testGroups"][0]["tests"][0]
        self.assertEqual(bytes.fromhex(answer["ek"]), pk)
        self.assertEqual(bytes.fromhex(answer["dk"]), sk)
        group = {"tgId": 5, "testType": "AFT", "parameterSet": name,
                 "function": "encapsulation", "tests": [{
                     "tcId": 2, "ek": pk.hex(), "m": m.hex()}]}
        answer = build_mlkem_response([{"acvVersion": "1.0"}, {
            "vsId": 22, "algorithm": "ML-KEM", "revision": "FIPS203-tr1", "mode": "encapDecap",
            "testGroups": [group]}], self.qsc)[1]["testGroups"][0]["tests"][0]
        self.assertEqual(bytes.fromhex(answer["c"]), ciphertext)
        self.assertEqual(bytes.fromhex(answer["k"]), secret)
        group = {"tgId": 5, "testType": "VAL", "parameterSet": name,
                 "function": "decapsulation", "keyFormat": "expanded", "tests": [{
                     "tcId": 3, "dk": sk.hex(), "c": ciphertext.hex()}, {
                     "tcId": 4, "dk": sk.hex(), "c": modified.hex()}]}
        answers = build_mlkem_response([{"acvVersion": "1.0"}, {
            "vsId": 23, "algorithm": "ML-KEM", "revision": "FIPS203-tr1", "mode": "encapDecap",
            "testGroups": [group]}], self.qsc)[1]["testGroups"][0]["tests"]
        self.assertEqual(bytes.fromhex(answers[0]["k"]), secret)
        self.assertNotEqual(bytes.fromhex(answers[1]["k"]), secret)

    def test_mlkem512_vector_roundtrip(self):
        self.check_parameter("ML-KEM-512")

    def test_mlkem768_vector_roundtrip(self):
        self.check_parameter("ML-KEM-768")

    def test_mlkem1024_vector_roundtrip(self):
        self.check_parameter("ML-KEM-1024")


if __name__ == "__main__":
    unittest.main()
