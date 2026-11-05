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

"""Strict ACVP PBKDF AFT responses and independent QSC HKDF primitive execution.

PBKDF is the NIST SP 800-132 adapter. HKDF here is an RFC 5869
primitive check, NOT a full SP 800-56C KDA ACVP response adapter.
"""

import ctypes
from pathlib import Path

PBKDF_ALGORITHM = "PBKDF"
HASHES = {"SHA2-256": (1, 32, "256"),
          "SHA2-384": (2, 48, "384"),
          "SHA2-512": (3, 64, "512")}


class KeyParameters(ctypes.Structure):
    """Match the public qsc_pbmac1_keyparams ABI; input pointers are borrowed."""

    _fields_ = [("password", ctypes.c_void_p), ("salt", ctypes.c_void_p),
                ("passwordlen", ctypes.c_size_t), ("saltlen", ctypes.c_size_t),
                ("iterations", ctypes.c_uint64), ("hash", ctypes.c_int),
                ("keylen", ctypes.c_size_t)]


class QscKdf:
    """Invoke QSC PBKDF2 and HKDF with bounded allocated buffers."""

    def __init__(self, library: Path):
        self._dll = ctypes.CDLL(str(library.resolve()))
        self._pbkdf = self._dll.qsc_pbmac1_derive_key
        self._pbkdf.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(KeyParameters)]
        self._pbkdf.restype = ctypes.c_bool
        for _, (identifier, hashlen, suffix) in HASHES.items():
            for verb in ("extract", "expand"):
                ref = getattr(self._dll, "qsc_hkdf" + suffix + "_" + verb)
                ref.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                ctypes.c_void_p, ctypes.c_size_t,
                                ctypes.c_void_p, ctypes.c_size_t]
                ref.restype = None

    def pbkdf2(self, hash_name: str, password: bytes, salt: bytes,
               iterations: int, length: int) -> bytes:
        """Derive at most 64 bytes; QSC refuses larger PBMAC1-derived keys."""
        if (hash_name not in HASHES or not 8 <= len(password) <= 128 or
                not 16 <= len(salt) <= 512 or type(iterations) is not int or
                not 1 <= iterations <= 10000000 or type(length) is not int or
                not 14 <= length <= 64):
            raise ValueError("Unsupported QSC PBKDF2 capability")
        password_buf = ctypes.create_string_buffer(password)
        salt_buf = ctypes.create_string_buffer(salt)
        result = ctypes.create_string_buffer(length)
        params = KeyParameters(ctypes.cast(password_buf, ctypes.c_void_p),
                               ctypes.cast(salt_buf, ctypes.c_void_p),
                               len(password), len(salt), iterations, HASHES[hash_name][0], length)
        if not self._pbkdf(result, length, ctypes.byref(params)):
            raise ValueError("QSC PBKDF2 derivation returned failure")
        return result.raw

    def hkdf(self, hash_name: str, secret: bytes, salt: bytes,
             info: bytes, length: int) -> bytes:
        """RFC 5869 extract+expand using QSC one-shot primitives."""
        if (hash_name not in HASHES or type(length) is not int or
                length < 1 or length > 255 * HASHES[hash_name][1] or
                len(secret) > 8192 or len(salt) > 8192 or len(info) > 8192):
            raise ValueError("Unsupported QSC HKDF input")
        hashlen = HASHES[hash_name][1]
        suffix = HASHES[hash_name][2]
        prk = ctypes.create_string_buffer(hashlen)
        secret_buf = ctypes.create_string_buffer(secret)
        salt_buf = ctypes.create_string_buffer(salt)
        getattr(self._dll, "qsc_hkdf" + suffix + "_extract")(
            prk, hashlen, secret_buf, len(secret), salt_buf, len(salt))
        output = ctypes.create_string_buffer(length)
        info_buf = ctypes.create_string_buffer(info)
        getattr(self._dll, "qsc_hkdf" + suffix + "_expand")(
            output, length, prk, hashlen, info_buf, len(info))
        return output.raw


def pbkdf_registration() -> dict:
    """Advertise only lengths and iterations accepted by qsc_pbmac1_derive_key."""
    domain = lambda low, high, step: [{"min": low, "max": high, "increment": step}]
    return {"algorithm": PBKDF_ALGORITHM, "revision": "1.0",
            "prereqVals": [{"algorithm": "SHA", "valValue": "same"}],
            "capabilities": [{"iterationCount": domain(10, 1000, 1),
                              "keyLen": domain(112, 512, 8),
                              "passwordLen": domain(8, 128, 1),
                              "saltLen": domain(128, 4096, 8),
                              "hmacAlg": list(HASHES)}]}


def pbkdf_response(envelope: list, qsc: QscKdf) -> list:
    """Process only valid byte-aligned PBKDF AFT prompts; reject all other modes."""
    if (not isinstance(envelope, list) or len(envelope) != 2 or
            not isinstance(envelope[0], dict) or envelope[0].get("acvVersion") != "1.0" or
            not isinstance(envelope[1], dict)):
        raise ValueError("Unrecognized ACVP envelope")
    body = envelope[1]
    if (body.get("algorithm") != PBKDF_ALGORITHM or body.get("revision") != "1.0" or
            type(body.get("vsId")) is not int or not isinstance(body.get("testGroups"), list) or
            len(body["testGroups"]) > 256):
        raise ValueError("Invalid PBKDF vector set")
    groups = []
    for group in body["testGroups"]:
        if (not isinstance(group, dict) or type(group.get("tgId")) is not int or
                group.get("testType") != "AFT" or group.get("hmacAlg") not in HASHES or
                not isinstance(group.get("tests"), list) or len(group["tests"]) > 10000):
            raise ValueError("Unsupported PBKDF test group")
        cases = []
        for case in group["tests"]:
            if not isinstance(case, dict) or type(case.get("tcId")) is not int:
                raise ValueError("Invalid PBKDF test case")
            length_bits = case.get("keyLen")
            password = case.get("password")
            salt_hex = case.get("salt")
            if (type(length_bits) is not int or length_bits % 8 or
                    not 112 <= length_bits <= 512 or
                    not isinstance(password, str) or not isinstance(salt_hex, str) or
                    len(salt_hex) > 1024 or len(salt_hex) % 2):
                raise ValueError("Unsupported PBKDF length or input type")
            try:
                password_bytes = password.encode("utf-8")
                salt = bytes.fromhex(salt_hex)
            except (ValueError, UnicodeError) as exc:
                raise ValueError("Malformed PBKDF input") from exc
            derived = qsc.pbkdf2(group["hmacAlg"], password_bytes, salt,
                                case.get("iterationCount"), length_bits // 8)
            cases.append({"tcId": case["tcId"], "derivedKey": derived.hex().upper()})
        groups.append({"tgId": group["tgId"], "tests": cases})
    return [{"acvVersion": "1.0"}, {"vsId": body["vsId"], "testGroups": groups}]
