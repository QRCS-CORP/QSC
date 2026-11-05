#!/usr/bin/env python3
"""Strict AES-GCM-128/256 ACVP AFT vector adapter to QSC's native C implementation."""

import ctypes
from pathlib import Path

ALGORITHM = 'ACVP-AES-GCM'
ECB_ALGORITHM = 'ACVP-AES-ECB'
CBC_ALGORITHM = 'ACVP-AES-CBC'
CTR_ALGORITHM = 'ACVP-AES-CTR'
MAX_CTR_PAYLOAD = 1048576
MAX_PAYLOAD = 8192
MAX_AAD = 65536


class QscAes:
    """Load the QSC AES bridge; holds no cryptographic state between calls."""

    def __init__(self, library: Path):
        self._dll = ctypes.CDLL(str(library.resolve()))
        self._execute = self._dll.qsc_acvp_aes_gcm_execute
        self._execute.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.c_void_p, ctypes.c_bool]
        self._execute.restype = ctypes.c_int
        self._ecb = self._dll.qsc_acvp_aes_ecb_block
        self._ecb.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                              ctypes.c_void_p, ctypes.c_void_p, ctypes.c_bool]
        self._ecb.restype = ctypes.c_int
        self._cbc = self._dll.qsc_acvp_aes_cbc_execute
        self._cbc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                              ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_bool]
        self._cbc.restype = ctypes.c_int
        self._ctr = self._dll.qsc_acvp_aes_ctrbe_execute
        self._ctr.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                              ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        self._ctr.restype = ctypes.c_int

    def ecb(self, key: bytes, block: bytes, encryption: bool) -> bytes:
        """Compute a single raw AES block using QSC, without padding."""
        if len(key) not in (16, 32) or len(block) != 16:
            raise ValueError('Unsupported AES-ECB key or block length')
        output = ctypes.create_string_buffer(16)
        result = self._ecb(ctypes.create_string_buffer(key), len(key),
                           ctypes.create_string_buffer(block), output, encryption)
        if result != 1:
            raise ValueError('QSC AES-ECB block operation failed')
        return output.raw

    def cbc(self, key: bytes, iv: bytes, payload: bytes, encryption: bool) -> bytes:
        """Use the raw CBC block API: ACVP does not use PKCS#7 padding."""
        if (len(key) not in (16, 32) or len(iv) != 16 or
                not 16 <= len(payload) <= MAX_PAYLOAD or len(payload) % 16):
            raise ValueError('Unsupported raw AES-CBC parameters')
        output = ctypes.create_string_buffer(len(payload))
        result = self._cbc(ctypes.create_string_buffer(key), len(key),
                           ctypes.create_string_buffer(iv), ctypes.create_string_buffer(payload),
                           len(payload), output, encryption)
        if result != 1:
            raise ValueError('QSC raw AES-CBC operation failed')
        return output.raw

    def ctr(self, key: bytes, iv: bytes, payload: bytes) -> bytes:
        """Transform using the existing big-endian 128-bit QSC AES-CTR API."""
        if (len(key) not in (16, 32) or len(iv) != 16 or
                not 1 <= len(payload) <= MAX_CTR_PAYLOAD):
            raise ValueError('Unsupported AES-CTR parameters')
        output = ctypes.create_string_buffer(len(payload))
        result = self._ctr(ctypes.create_string_buffer(key), len(key),
                           ctypes.create_string_buffer(iv), ctypes.create_string_buffer(payload),
                           len(payload), output)
        if result != 1:
            raise ValueError('QSC AES-CTR operation failed')
        return output.raw

    def transform(self, key: bytes, iv: bytes, aad: bytes, payload: bytes,
                  tag: bytes | None = None) -> tuple[bool, bytes, bytes]:
        """Encrypt or authenticate/decrypt; a missing tag means encryption."""
        if (len(key) not in (16, 32) or len(iv) != 12 or len(aad) > MAX_AAD or
                len(payload) > MAX_PAYLOAD or (tag is not None and len(tag) != 16)):
            raise ValueError('Unsupported AES-GCM capability')
        encryption = tag is None
        source = payload if encryption else payload + tag
        output_size = len(payload) + 16 if encryption else len(payload)
        output = ctypes.create_string_buffer(max(output_size, 1))
        result = self._execute(ctypes.create_string_buffer(key), len(key),
                               ctypes.create_string_buffer(iv), len(iv),
                               ctypes.create_string_buffer(aad), len(aad),
                               ctypes.create_string_buffer(source), len(payload),
                               output, encryption)
        if result not in (0, 1):
            raise RuntimeError('Unexpected QSC AES bridge return code')
        if not result:
            return False, b'', b''
        if encryption:
            return True, output.raw[:len(payload)], output.raw[len(payload):len(payload) + 16]
        return True, output.raw[:len(payload)], b''


def _required_hex(case: dict, field: str) -> bytes:
    """Strictly decode a required hex input; do not accept omitted fields."""
    value = case.get(field)
    if not isinstance(value, str) or len(value) % 2:
        raise ValueError('Missing or malformed ' + field)
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError('Invalid hex for ' + field) from exc


def _length(group: dict, field: str, data: bytes) -> None:
    """Check ACVP bit-length metadata against actual bytes."""
    bits = group.get(field)
    if type(bits) is not int or bits != len(data) * 8:
        raise ValueError('AES-GCM ' + field + ' does not match provided bytes')


def build_aes_response(envelope: list, aes: QscAes) -> list:
    """Answer only externally supplied 96-bit IV, full-tag GCM AFT vectors."""
    if (not isinstance(envelope, list) or len(envelope) != 2 or
            not isinstance(envelope[0], dict) or envelope[0].get('acvVersion') != '1.0' or
            not isinstance(envelope[1], dict)):
        raise ValueError('Malformed ACVP AES envelope')
    body = envelope[1]
    if body.get('algorithm') != ALGORITHM or type(body.get('vsId')) is not int:
        raise ValueError('Unsupported ACVP AES vector set')
    if not isinstance(body.get('testGroups'), list) or not body['testGroups']:
        raise ValueError('No AES-GCM test groups')
    groups = []
    for group in body['testGroups']:
        if (not isinstance(group, dict) or group.get('testType') != 'AFT' or
                group.get('direction') not in ('encrypt', 'decrypt') or
                group.get('ivGen') != 'external' or group.get('ivLen') != 96 or
                group.get('tagLen') != 128 or group.get('keyLen', group.get('keylen')) not in (128, 256) or
                type(group.get('tgId')) is not int or
                not isinstance(group.get('tests'), list)):
            raise ValueError('Unsupported AES-GCM group capability')
        items = []
        for case in group['tests']:
            if not isinstance(case, dict) or type(case.get('tcId')) is not int:
                raise ValueError('Invalid AES-GCM case identifier')
            key = _required_hex(case, 'key')
            iv = _required_hex(case, 'iv')
            aad = _required_hex(case, 'aad')
            payload = _required_hex(case, ('pt' if 'pt' in case else 'plainText') if group['direction'] == 'encrypt' else ('ct' if 'ct' in case else 'cipherText'))
            if len(key) * 8 != group.get('keyLen', group.get('keylen')):
                raise ValueError('AES-GCM key length mismatch')
            _length(group, 'aadLen', aad)
            _length(group, 'payloadLen', payload)
            if len(payload) > MAX_PAYLOAD or len(aad) > MAX_AAD:
                raise ValueError('AES-GCM input exceeds tested limit')
            if group['direction'] == 'encrypt':
                passed, ciphertext, mac = aes.transform(key, iv, aad, payload)
                if not passed:
                    raise ValueError('QSC AES-GCM encrypt failed')
                item = {'tcId': case['tcId'], 'iv': iv.hex().upper(), 'ct': ciphertext.hex().upper(),
                        'tag': mac.hex().upper()}
            else:
                tag = _required_hex(case, 'tag')
                passed, plaintext, _ = aes.transform(key, iv, aad, payload, tag)
                item = ({'tcId': case['tcId'], 'pt': plaintext.hex().upper()}
                        if passed else {'tcId': case['tcId'], 'testPassed': False})
            items.append(item)
        groups.append({'tgId': group['tgId'], 'tests': items})
    return [{'acvVersion': '1.0'}, {'vsId': body['vsId'], 'testGroups': groups}]


def _ecb_mct(aes: QscAes, key: bytes, block: bytes, encryption: bool) -> list[dict]:
    """100 x 1000 ECB Monte Carlo iterations per NIST ACVP symmetric rules."""
    answer = []
    for _ in range(100):
        starting_key = key
        starting_block = block
        penultimate = b''
        for index in range(1000):
            penultimate = block if index == 999 else penultimate
            block = aes.ecb(key, block, encryption)
        final = block
        answer.append({'key': starting_key.hex().upper(),
                       ('pt' if encryption else 'ct'): starting_block.hex().upper(),
                       ('ct' if encryption else 'pt'): final.hex().upper()})
        key_material = final if len(key) == 16 else penultimate + final
        key = bytes(left ^ right for left, right in zip(key, key_material))
    return answer


def build_ecb_response(envelope: list, aes: QscAes) -> list:
    """Execute byte-aligned AES-ECB AFT and Monte Carlo operations."""
    if (not isinstance(envelope, list) or len(envelope) != 2 or
            not isinstance(envelope[0], dict) or envelope[0].get('acvVersion') != '1.0' or
            not isinstance(envelope[1], dict)):
        raise ValueError('Malformed ACVP AES-ECB envelope')
    body = envelope[1]
    if (body.get('algorithm') != ECB_ALGORITHM or type(body.get('vsId')) is not int or
            not isinstance(body.get('testGroups'), list) or not body['testGroups']):
        raise ValueError('Invalid AES-ECB vector set')
    groups = []
    for group in body['testGroups']:
        if (not isinstance(group, dict) or type(group.get('tgId')) is not int or
                group.get('direction') not in ('encrypt', 'decrypt') or
                group.get('testType') not in ('AFT', 'MCT') or
                group.get('keyLen', group.get('keylen')) not in (128, 256) or
                not isinstance(group.get('tests'), list)):
            raise ValueError('Unsupported AES-ECB test group')
        encrypt = group['direction'] == 'encrypt'
        cases = []
        for case in group['tests']:
            if not isinstance(case, dict) or type(case.get('tcId')) is not int:
                raise ValueError('Invalid AES-ECB test case')
            key = _required_hex(case, 'key')
            source_name = 'pt' if encrypt else 'ct'
            block = _required_hex(case, source_name if source_name in case else ('plainText' if encrypt else 'cipherText'))
            if len(key) * 8 != group.get('keyLen', group.get('keylen')) or len(block) != 16:
                raise ValueError('AES-ECB key or block length mismatch')
            if group['testType'] == 'MCT':
                cases.append({'tcId': case['tcId'],
                              'resultsArray': _ecb_mct(aes, key, block, encrypt)})
            else:
                value = aes.ecb(key, block, encrypt)
                cases.append({'tcId': case['tcId'],
                              'ct' if encrypt else 'pt': value.hex().upper()})
        groups.append({'tgId': group['tgId'], 'tests': cases})
    return [{'acvVersion': '1.0'}, {'vsId': body['vsId'], 'testGroups': groups}]


def _cbc_mct(aes: QscAes, key: bytes, iv: bytes, block: bytes,
             encryption: bool) -> list[dict]:
    """NIST AES-CBC 100 x 1000 MCT with mode-specific chaining and key shuffle."""
    records = []
    for _ in range(100):
        start_key, start_iv, start_block = key, iv, block
        penultimate = b''
        for index in range(1000):
            output = aes.cbc(key, iv, block, encryption)
            if index == 0:
                next_input = iv
            else:
                next_input = penultimate
            # Encryption chains on the previous ciphertext; decryption chains
            # on the previous input ciphertext.
            iv = output if encryption else block
            penultimate, block = output, next_input
        final = penultimate
        # The preceding iteration output is needed to start the next outer round.
        # At j=999, 'block' is output[j-1].
        previous = block
        records.append({'key': start_key.hex().upper(), 'iv': start_iv.hex().upper(),
                        ('pt' if encryption else 'ct'): start_block.hex().upper(),
                        ('ct' if encryption else 'pt'): final.hex().upper()})
        material = final if len(key) == 16 else previous + final
        key = bytes(a ^ b for a, b in zip(key, material))
        iv, block = final, previous
    return records


def build_cbc_response(envelope: list, aes: QscAes) -> list:
    """Answer unpadded AES-CBC AFT and MCT vector sets; reject unknown modes."""
    if (not isinstance(envelope, list) or len(envelope) != 2 or
            not isinstance(envelope[0], dict) or envelope[0].get('acvVersion') != '1.0' or
            not isinstance(envelope[1], dict)):
        raise ValueError('Invalid AES-CBC envelope')
    body = envelope[1]
    if (body.get('algorithm') != CBC_ALGORITHM or type(body.get('vsId')) is not int or
            not isinstance(body.get('testGroups'), list) or not body['testGroups']):
        raise ValueError('Invalid AES-CBC vector set')
    groups = []
    for group in body['testGroups']:
        if (not isinstance(group, dict) or type(group.get('tgId')) is not int or
                group.get('direction') not in ('encrypt', 'decrypt') or
                group.get('testType') not in ('AFT', 'MCT') or
                type(group.get('keyLen')) is not int or group['keyLen'] not in (128, 256) or
                not isinstance(group.get('tests'), list)):
            raise ValueError('Unsupported AES-CBC group')
        encrypt = group['direction'] == 'encrypt'
        answers = []
        for case in group['tests']:
            if not isinstance(case, dict) or type(case.get('tcId')) is not int:
                raise ValueError('Malformed AES-CBC case')
            key = _required_hex(case, 'key')
            iv = _required_hex(case, 'iv')
            source = _required_hex(case, 'pt' if encrypt else 'ct')
            if (len(key) * 8 != group['keyLen'] or len(iv) != 16 or
                    not 16 <= len(source) <= MAX_PAYLOAD or len(source) % 16 or
                    (group['testType'] == 'MCT' and len(source) != 16)):
                raise ValueError('AES-CBC vector outside registered capability')
            if group['testType'] == 'MCT':
                answers.append({'tcId': case['tcId'],
                                'resultsArray': _cbc_mct(aes, key, iv, source, encrypt)})
            else:
                result = aes.cbc(key, iv, source, encrypt)
                answers.append({'tcId': case['tcId'], 'ct' if encrypt else 'pt': result.hex().upper()})
        groups.append({'tgId': group['tgId'], 'tests': answers})
    return [{'acvVersion': '1.0'}, {'vsId': body['vsId'], 'testGroups': groups}]


def build_ctr_response(envelope: list, aes: QscAes) -> list:
    """Answer byte-aligned AES-CTR AFT and counter-sequence tests."""
    if (not isinstance(envelope, list) or len(envelope) != 2 or
            not isinstance(envelope[0], dict) or envelope[0].get('acvVersion') != '1.0' or
            not isinstance(envelope[1], dict)):
        raise ValueError('Invalid AES-CTR envelope')
    body = envelope[1]
    if (body.get('algorithm') != CTR_ALGORITHM or type(body.get('vsId')) is not int or
            not isinstance(body.get('testGroups'), list) or not body['testGroups']):
        raise ValueError('Invalid AES-CTR vector set')
    groups = []
    for group in body['testGroups']:
        if (not isinstance(group, dict) or type(group.get('tgId')) is not int or
                group.get('direction') not in ('encrypt', 'decrypt') or
                group.get('testType') not in ('AFT', 'CTR') or
                type(group.get('keyLen')) is not int or group['keyLen'] not in (128, 256) or
                not isinstance(group.get('tests'), list)):
            raise ValueError('Unsupported AES-CTR group')
        encrypt = group['direction'] == 'encrypt'
        answers = []
        for case in group['tests']:
            if not isinstance(case, dict) or type(case.get('tcId')) is not int:
                raise ValueError('Malformed AES-CTR case')
            key = _required_hex(case, 'key')
            iv = _required_hex(case, 'iv')
            source = _required_hex(case, 'pt' if encrypt else 'ct')
            bits = case.get('payloadLen', group.get('payloadLen'))
            if (len(key) * 8 != group['keyLen'] or len(iv) != 16 or
                    type(bits) is not int or bits != len(source) * 8 or
                    not 1 <= len(source) <= MAX_CTR_PAYLOAD):
                raise ValueError('AES-CTR requires byte-aligned external-counter vectors')
            output = aes.ctr(key, iv, source)
            answers.append({'tcId': case['tcId'], 'ct' if encrypt else 'pt': output.hex().upper()})
        groups.append({'tgId': group['tgId'], 'tests': answers})
    return [{'acvVersion': '1.0'}, {'vsId': body['vsId'], 'testGroups': groups}]
