"""Independent AES-GCM and AES-ECB QSC native qualification vectors."""

import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aes_client import QscAes, build_aes_response, build_ecb_response


@unittest.skipUnless(os.environ.get('QSC_ACVP_AES_LIBRARY'), 'set QSC_ACVP_AES_LIBRARY for native tests')
class AesNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cls.AESGCM = AESGCM
        cls.Cipher = Cipher
        cls.algorithms = algorithms
        cls.modes = modes
        cls.qsc = QscAes(Path(os.environ['QSC_ACVP_AES_LIBRARY']))

    def test_gcm_all_supported_keys_and_lengths(self):
        for keylen in (16, 32):
            for length in (0, 1, 15, 16, 17, 32, 255, 1024, 8192):
                with self.subTest(keylen=keylen, length=length):
                    key = bytes(range(keylen))
                    iv = bytes(range(12))
                    aad = bytes(range(length % 64))
                    message = bytes((i & 255) for i in range(length))
                    valid, ciphertext, tag = self.qsc.transform(key, iv, aad, message)
                    expected = self.AESGCM(key).encrypt(iv, message, aad)
                    self.assertTrue(valid)
                    self.assertEqual(ciphertext + tag, expected)
                    passed, plaintext, _ = self.qsc.transform(key, iv, aad, ciphertext, tag)
                    self.assertTrue(passed)
                    self.assertEqual(plaintext, message)
                    invalid = bytes([tag[0] ^ 1]) + tag[1:]
                    passed, plaintext, _ = self.qsc.transform(key, iv, aad, ciphertext, invalid)
                    self.assertFalse(passed)
                    self.assertEqual(plaintext, b'')

    def test_ecb_single_block_oracle(self):
        for keylen in (16, 32):
            for encrypt in (True, False):
                key = bytes(range(keylen))
                block = bytes(range(16))
                cipher = self.Cipher(self.algorithms.AES(key), self.modes.ECB())
                context = cipher.encryptor() if encrypt else cipher.decryptor()
                self.assertEqual(self.qsc.ecb(key, block, encrypt), context.update(block) + context.finalize())

    def test_ecb_mct_matches_independent_first_and_second_outer_rounds(self):
        from aes_client import _ecb_mct
        for keylen in (16, 32):
            for encryption in (True, False):
                with self.subTest(keylen=keylen, encryption=encryption):
                    key = bytes(range(keylen))
                    block = bytes(range(16))
                    original_key, original_block = key, block
                    expected = []
                    for _ in range(2):
                        starting = block
                        current_key = key
                        cipher = self.Cipher(self.algorithms.AES(key), self.modes.ECB())
                        operation = cipher.encryptor() if encryption else cipher.decryptor()
                        for _ in range(1000):
                            penultimate = block
                            block = operation.update(block)
                        expected.append((current_key, starting, block))
                        key_material = block if keylen == 16 else penultimate + block
                        key = bytes(a ^ b for a, b in zip(key, key_material))
                    actual = _ecb_mct(self.qsc, original_key, original_block, encryption)
                    self.assertEqual(len(actual), 100)
                    for index, record in enumerate(expected):
                        self.assertEqual(actual[index]['key'], record[0].hex().upper())
                        self.assertEqual(actual[index]['pt' if encryption else 'ct'],
                                         record[1].hex().upper())
                        self.assertEqual(actual[index]['ct' if encryption else 'pt'],
                                         record[2].hex().upper())

    def test_cbc_matches_independent_aes_for_all_aligned_lengths(self):
        for keylen in (16, 32):
            for length in (16, 32, 48, 256, 8192):
                with self.subTest(keylen=keylen, length=length):
                    key = bytes(range(keylen))
                    iv = bytes(range(16))
                    pt = bytes(index & 0xFF for index in range(length))
                    cipher = self.Cipher(self.algorithms.AES(key), self.modes.CBC(iv))
                    ctx = cipher.encryptor()
                    ciphertext = ctx.update(pt) + ctx.finalize()
                    self.assertEqual(self.qsc.cbc(key, iv, pt, True), ciphertext)
                    self.assertEqual(self.qsc.cbc(key, iv, ciphertext, False), pt)

    def test_ctr_matches_independent_aes_at_boundary_and_rollover(self):
        for keylen in (16, 32):
            for length in (1, 15, 16, 17, 32, 63, 256, 8192):
                for iv in (bytes(range(16)), bytes.fromhex('00' * 15 + 'fe')):
                    with self.subTest(keylen=keylen, length=length, iv=iv.hex()):
                        key = bytes(range(keylen))
                        pt = bytes(index & 0xFF for index in range(length))
                        cipher = self.Cipher(self.algorithms.AES(key), self.modes.CTR(iv))
                        ctx = cipher.encryptor()
                        expected = ctx.update(pt) + ctx.finalize()
                        self.assertEqual(self.qsc.ctr(key, iv, pt), expected)
                        self.assertEqual(self.qsc.ctr(key, iv, expected), pt)

    def test_cbc_mct_reference_initial_rounds(self):
        from aes_client import _cbc_mct
        for keylen in (16, 32):
            for encrypt in (True, False):
                with self.subTest(keylen=keylen, encryption=encrypt):
                    key = bytes(range(keylen))
                    iv = bytes((index + 16) & 255 for index in range(16))
                    block = bytes((index + 32) & 255 for index in range(16))
                    original_key, original_iv, original_block = key, iv, block
                    expected = []
                    for _ in range(2):
                        start_key, start_iv, start_block = key, iv, block
                        previous_result = b''
                        for index in range(1000):
                            cipher = self.Cipher(self.algorithms.AES(key), self.modes.CBC(iv))
                            context = cipher.encryptor() if encrypt else cipher.decryptor()
                            result = context.update(block) + context.finalize()
                            next_input = iv if index == 0 else previous_result
                            iv = result if encrypt else block
                            previous_result, block = result, next_input
                        expected.append((start_key, start_iv, start_block, result))
                        key_material = result if keylen == 16 else block + result
                        key = bytes(left ^ right for left, right in zip(key, key_material))
                        iv = result
                    actual = _cbc_mct(self.qsc, original_key, original_iv,
                                      original_block, encrypt)
                    self.assertEqual(len(actual), 100)
                    for index, (k, v, b, result) in enumerate(expected):
                        record = actual[index]
                        self.assertEqual(record['key'], k.hex().upper())
                        self.assertEqual(record['iv'], v.hex().upper())
                        self.assertEqual(record['pt' if encrypt else 'ct'], b.hex().upper())
                        self.assertEqual(record['ct' if encrypt else 'pt'], result.hex().upper())

    def test_gcm_acvp_json_replay_against_independent_oracle(self):
        key = bytes(range(32))
        iv = bytes(range(12))
        aad = b'authenticated associated data'
        plaintext = b'QSC ACVP GCM qualification payload'
        encoded = self.AESGCM(key).encrypt(iv, plaintext, aad)
        group = {'tgId': 5, 'testType': 'AFT', 'direction': 'decrypt',
                 'keyLen': 256, 'ivLen': 96, 'ivGen': 'external', 'tagLen': 128,
                 'payloadLen': len(plaintext) * 8, 'aadLen': len(aad) * 8,
                 'tests': [{'tcId': 100, 'key': key.hex(), 'iv': iv.hex(),
                            'aad': aad.hex(), 'cipherText': encoded[:-16].hex(),
                            'tag': encoded[-16:].hex()}]}
        envelope = [{'acvVersion': '1.0'}, {'algorithm': 'ACVP-AES-GCM',
                    'vsId': 5, 'testGroups': [group]}]
        response = build_aes_response(envelope, self.qsc)
        self.assertEqual(response[1]['testGroups'][0]['tests'][0],
                         {'tcId': 100, 'pt': plaintext.hex().upper()})
        group['tests'][0]['tag'] = (bytes([encoded[-16] ^ 1]) + encoded[-15:]).hex()
        response = build_aes_response(envelope, self.qsc)
        self.assertEqual(response[1]['testGroups'][0]['tests'][0],
                         {'tcId': 100, 'testPassed': False})


if __name__ == '__main__':
    unittest.main()
