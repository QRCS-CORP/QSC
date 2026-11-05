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

"""ACVP CBC/CTR vector dispatch, validation and registration regression tests."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aes_client import build_cbc_response, build_ctr_response
from local_client import build_response
from demo_client import registration


class StubAes:
    """Deterministic stateless block-mode double for parsing tests."""

    def cbc(self, key, iv, payload, encryption):
        return bytes(v ^ 0x5A for v in payload)

    def ctr(self, key, iv, payload):
        return bytes(v ^ 0xA5 for v in payload)


class AesModesVectorTests(unittest.TestCase):
    """Check the JSON-level contracts without depending on a native library."""

    def cbc_request(self, test_type='AFT', direction='encrypt'):
        return [{'acvVersion': '1.0'}, {'vsId': 13, 'algorithm': 'ACVP-AES-CBC',
                'testGroups': [{'tgId': 2, 'testType': test_type, 'direction': direction,
                                'keyLen': 128, 'tests': [{'tcId': 8, 'key': '01' * 16,
                                'iv': '02' * 16, 'pt' if direction == 'encrypt' else 'ct': '03' * 16}]}]}]

    def ctr_request(self, test_type='AFT', direction='encrypt'):
        return [{'acvVersion': '1.0'}, {'vsId': 14, 'algorithm': 'ACVP-AES-CTR',
                'testGroups': [{'tgId': 4, 'testType': test_type, 'direction': direction,
                                'keyLen': 256, 'tests': [{'tcId': 7, 'key': '01' * 32,
                                'iv': '02' * 16, 'payloadLen': 136,
                                'pt' if direction == 'encrypt' else 'ct': '03' * 17}]}]}]

    def test_cbc_aft_unpadded(self):
        reply = build_cbc_response(self.cbc_request(), StubAes())
        self.assertEqual(reply[1]['testGroups'][0]['tests'][0], {'tcId': 8, 'ct': '59' * 16})

    def test_cbc_decrypt_unpadded(self):
        reply = build_cbc_response(self.cbc_request(direction='decrypt'), StubAes())
        self.assertEqual(reply[1]['testGroups'][0]['tests'][0], {'tcId': 8, 'pt': '59' * 16})

    def test_cbc_mct_records(self):
        reply = build_cbc_response(self.cbc_request(test_type='MCT'), StubAes())
        records = reply[1]['testGroups'][0]['tests'][0]['resultsArray']
        self.assertEqual(len(records), 100)
        self.assertEqual(records[0]['iv'], '02' * 16)
        self.assertEqual(records[0]['key'], '01' * 16)

    def test_cbc_reject_partial_block(self):
        body = self.cbc_request()
        body[1]['testGroups'][0]['tests'][0]['pt'] = '01' * 17
        with self.assertRaises(ValueError):
            build_cbc_response(body, StubAes())

    def test_cbc_reject_unsupported_type(self):
        body = self.cbc_request()
        body[1]['testGroups'][0]['testType'] = 'CTR'
        with self.assertRaises(ValueError):
            build_cbc_response(body, StubAes())

    def test_ctr_aft_partial_block(self):
        reply = build_ctr_response(self.ctr_request(), StubAes())
        self.assertEqual(reply[1]['testGroups'][0]['tests'][0], {'tcId': 7, 'ct': 'A6' * 17})

    def test_ctr_counter_type(self):
        reply = build_ctr_response(self.ctr_request(test_type='CTR', direction='decrypt'), StubAes())
        self.assertEqual(reply[1]['testGroups'][0]['tests'][0], {'tcId': 7, 'pt': 'A6' * 17})

    def test_ctr_reject_nonmatching_payload_length(self):
        body = self.ctr_request()
        body[1]['testGroups'][0]['tests'][0]['payloadLen'] = 128
        with self.assertRaises(ValueError):
            build_ctr_response(body, StubAes())

    def test_ctr_reject_mct(self):
        body = self.ctr_request('MCT')
        with self.assertRaises(ValueError):
            build_ctr_response(body, StubAes())

    def test_ctr_reject_missing_iv(self):
        body = self.ctr_request()
        del body[1]['testGroups'][0]['tests'][0]['iv']
        with self.assertRaises(ValueError):
            build_ctr_response(body, StubAes())

    def test_registration(self):
        caps = registration(('ACVP-AES-CBC', 'ACVP-AES-CTR'))[1]['algorithms']
        self.assertEqual(caps[0]['keyLen'], [128, 256])
        self.assertEqual(caps[1]['payloadLen'], [128])
        self.assertTrue(caps[1]['performCounterTests'])

    def test_shared_dispatch(self):
        class Qsc:
            aes = StubAes()
        self.assertEqual(build_response(self.ctr_request(), Qsc())[1]['testGroups'][0]['tests'][0]['ct'],
                         'A6' * 17)
        self.assertEqual(build_response(self.cbc_request(), Qsc())[1]['testGroups'][0]['tests'][0]['ct'],
                         '59' * 16)


class DemoAesModesTests(unittest.TestCase):
    """Process CBC and CTR consecutively through the authenticated controller."""

    def test_cbc_then_ctr_session_submissions(self):
        from demo_client import execute

        class Server:
            def __init__(self):
                self.session = '/acvp/v1/testSessions/212'
                self.submitted = []

            def request(self, method, path, token=None, body=None):
                if path.endswith('/login'):
                    return [{'acvVersion': '1.0'}, {'accessToken': 'protected-token'}]
                if method == 'POST' and path.endswith('/testSessions'):
                    return [{'acvVersion': '1.0'}, {'url': self.session,
                            'vectorSetUrls': [self.session + '/vectorSets/1',
                                              self.session + '/vectorSets/2']}]
                if method == 'GET' and path.endswith('vectorSets/1'):
                    envelope = AesModesVectorTests().cbc_request()
                    envelope[1]['vsId'] = 1
                    return envelope
                if method == 'GET' and path.endswith('vectorSets/2'):
                    envelope = AesModesVectorTests().ctr_request()
                    envelope[1]['vsId'] = 2
                    return envelope
                if method == 'POST' and path.endswith('/results'):
                    self.submitted.append(body[1]['vsId'])
                    return [{'acvVersion': '1.0'}, {'status': 'received'}]
                if method == 'GET' and path.endswith('/results'):
                    return [{'acvVersion': '1.0'}, {'passed': True,
                            'results': [{'status': 'passed', 'vectorSetUrl': self.session + '/vectorSets/1'}, {'status': 'passed', 'vectorSetUrl': self.session + '/vectorSets/2'}]}]
                raise AssertionError((method, path))

        class Qsc:
            aes = StubAes()

        server = Server()
        report = execute(server, Qsc(), 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
                         ('ACVP-AES-CBC', 'ACVP-AES-CTR'), poll_count=1)
        self.assertEqual(server.submitted, [1, 2])
        self.assertEqual(report['status'], 'PASS_DEMO_SAMPLE')
        self.assertNotIn('protected-token', str(report))


if __name__ == '__main__':
    unittest.main()
