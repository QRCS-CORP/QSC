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

"""Bounded, byte-oriented cSHAKE/KMAC ACVP AFT response adapters.

Only offline AFT inputs are currently accepted. Live registration requires
validation of Monte Carlo and verification test handling first.
"""

import ctypes as c
import hmac
from ecc_client import decode_hex

SUPPORTED = {"cSHAKE-128", "cSHAKE-256", "KMAC-128", "KMAC-256"}


def bounded_bits(value, minimum, maximum):
    """Convert a bounded byte-aligned ACVP bit length to bytes."""
    if type(value) is not int or value < minimum or value > maximum or value % 8 != 0:
        raise ValueError("Unsupported XOF bit length")
    return value // 8


def ascii_bytes(value):
    """Accept only the ASCII customization format advertised by the adapter."""
    if not isinstance(value, str) or len(value) > 161:
        raise ValueError("Invalid XOF customization")
    try:
        return value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("XOF customization is not ASCII") from exc


class QscXof:
    """Call existing QSC SHA3-derived one-shot functions with exact prototypes."""

    def __init__(self, library):
        self._dll = c.CDLL(str(library))
        for mode in ("128", "256"):
            for name in (f"qsc_cshake{mode}_compute", f"qsc_kmac{mode}_compute",
                         f"qsc_kmac_xof{mode}_compute"):
                operation = getattr(self._dll, name)
                operation.restype = None
                operation.argtypes = [c.c_void_p, c.c_size_t,
                                      c.c_void_p, c.c_size_t, c.c_void_p, c.c_size_t,
                                      c.c_void_p, c.c_size_t]

    def compute(self, algorithm, message, output_size, key=b"", customization=b"",
                function_name=b"", xof=False):
        """Return byte-exact cSHAKE or KMAC output from native QSC."""
        if algorithm not in SUPPORTED or not 1 <= output_size <= 512:
            raise ValueError("Unsupported XOF output request")
        suffix = algorithm.rsplit("-", 1)[1]
        if algorithm.startswith("cSHAKE-"):
            if key or xof:
                raise ValueError("Unsupported cSHAKE inputs")
            name = f"qsc_cshake{suffix}_compute"
            first, second, third = message, function_name, customization
        else:
            if function_name or len(key) < 32:
                raise ValueError("Unsupported KMAC key or function name")
            name = (f"qsc_kmac_xof{suffix}_compute" if xof else
                    f"qsc_kmac{suffix}_compute")
            first, second, third = message, key, customization
        result = c.create_string_buffer(output_size)
        first_buffer = c.create_string_buffer(first)
        second_buffer = c.create_string_buffer(second)
        third_buffer = c.create_string_buffer(third)
        getattr(self._dll, name)(result, output_size, first_buffer, len(first),
                                 second_buffer, len(second), third_buffer, len(third))
        return result.raw


def build_xof_response(envelope, qsc):
    """Process only supported ACVP SP 800-185 byte-aligned AFT vector groups."""
    if (not isinstance(envelope, list) or len(envelope) != 2 or
            envelope[0] != {"acvVersion": "1.0"} or not isinstance(envelope[1], dict)):
        raise ValueError("Invalid XOF vector envelope")
    body = envelope[1]
    algorithm = body.get("algorithm")
    if (algorithm not in SUPPORTED or body.get("revision") != "1.0" or
            type(body.get("vsId")) is not int or not isinstance(body.get("testGroups"), list)):
        raise ValueError("Unsupported XOF algorithm or revision")
    answer = []
    for group in body["testGroups"]:
        if (type(group.get("tgId")) is not int or group.get("testType") != "AFT" or
                group.get("hexCustomization", False) is not False or
                not isinstance(group.get("tests"), list)):
            raise ValueError("Unsupported XOF test group")
        is_kmac = algorithm.startswith("KMAC-")
        xof = group.get("xof", False)
        if is_kmac and type(xof) is not bool:
            raise ValueError("Invalid KMAC XOF mode")
        if not is_kmac and group.get("xof") is not None:
            raise ValueError("Unsupported cSHAKE XOF flag")
        cases = []
        for item in group["tests"]:
            if type(item.get("tcId")) is not int:
                raise ValueError("Missing XOF test identifier")
            msg_bits = item.get("msgLen", item.get("len"))
            msg_len = bounded_bits(msg_bits, 0, 65536)
            message = decode_hex(item.get("msg"), limit=8192)
            if len(message) != msg_len:
                raise ValueError("Inconsistent XOF message length")
            customization = ascii_bytes(item.get("customization", ""))
            if is_kmac:
                key_length = bounded_bits(item.get("keyLen"), 256, 4096)
                key = decode_hex(item.get("key"), expected=key_length)
                out_len = bounded_bits(item.get("macLen"), 256, 4096)
                mac = qsc.compute(algorithm, message, out_len, key=key,
                                  customization=customization, xof=xof)
                cases.append({"tcId": item["tcId"], "mac": mac.hex().upper()})
            else:
                function_name = ascii_bytes(item.get("functionName", ""))
                out_len = bounded_bits(item.get("outLen"), 8, 4096)
                digest = qsc.compute(algorithm, message, out_len,
                                     customization=customization,
                                     function_name=function_name)
                cases.append({"tcId": item["tcId"], "md": digest.hex().upper()})
        answer.append({"tgId": group["tgId"], "tests": cases})
    return [{"acvVersion": "1.0"}, {"vsId": body["vsId"], "testGroups": answer}]
