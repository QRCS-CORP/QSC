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

"""ACVP SP 800-56C HKDF standalone KDA adapter.

Supports non-hybrid, single-expansion, byte-aligned AFT/VAL for revisions
Sp800-56Cr1 and Sp800-56Cr2 with concatenated party identifiers and L.
This does not represent a NIST Demo validation or a validated DRBG.
"""

import hmac

from kdf_client import HASHES

MODE = "HKDF"
ALGORITHM = "KDA"
SELECTION = "KDA-HKDF"
REVISIONS = ("Sp800-56Cr1", "Sp800-56Cr2")
FIXED_INFO = "uPartyInfo||vPartyInfo||l"


def registration(drbg_validation: str) -> list[dict]:
    """Require independently verified DRBG prerequisite before live registration."""
    if (not isinstance(drbg_validation, str) or not drbg_validation.strip() or
            drbg_validation.lower() in ("same", "pending", "none", "not-validated")):
        raise ValueError("Verified external DRBG validation is required")
    capabilities = []
    for revision in REVISIONS:
        item = {
            "algorithm": ALGORITHM, "mode": MODE, "revision": revision,
            "prereqVals": [
                {"algorithm": "DRBG", "valValue": drbg_validation},
                {"algorithm": "HMAC", "valValue": "same"},
                {"algorithm": "SHA", "valValue": "same"}],
            "fixedInfoPattern": FIXED_INFO, "encoding": ["concatenation"],
            "hmacAlg": list(HASHES), "macSaltMethods": ["default", "random"],
            "z": [{"min": 224, "max": 65536, "increment": 8}], "l": 2048,
        }
        if revision == "Sp800-56Cr2":
            item.update({"usesHybridSharedSecret": False,
                         "performMultiExpansionTests": False,
                         "saltLens": [{"min": 8, "max": 512, "increment": 8}]})
        capabilities.append(item)
    return capabilities


def _hex(value, maximum=8192) -> bytes:
    """Decode a bounded, byte-aligned hex field, failing on malformed input."""
    if not isinstance(value, str) or len(value) > maximum * 2 or len(value) % 2:
        raise ValueError("Invalid ACVP hex field")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("Invalid ACVP hex field") from exc


def _party(party) -> bytes:
    """Concatenate required party ID with optional ephemeral data."""
    if not isinstance(party, dict) or "partyId" not in party:
        raise ValueError("Missing fixed-info party identifier")
    identity = _hex(party["partyId"], 512)
    if not identity:
        raise ValueError("Empty fixed-info party identifier")
    return identity + (_hex(party["ephemeralData"], 1024)
                       if "ephemeralData" in party else b"")


def response(envelope: list, qsc) -> list:
    """Compute AFT DKM and constant-time VAL comparisons using QSC HKDF."""
    if (not isinstance(envelope, list) or len(envelope) != 2 or
            not isinstance(envelope[0], dict) or envelope[0].get("acvVersion") != "1.0" or
            not isinstance(envelope[1], dict)):
        raise ValueError("Invalid ACVP KDA envelope")
    body = envelope[1]
    if (body.get("algorithm") != ALGORITHM or body.get("mode") != MODE or
            body.get("revision") not in REVISIONS or type(body.get("vsId")) is not int or
            not isinstance(body.get("testGroups"), list) or not 1 <= len(body["testGroups"]) <= 256):
        raise ValueError("Unsupported KDA-HKDF vector set")
    groups = []
    for group in body["testGroups"]:
        if not isinstance(group, dict):
            raise ValueError("Malformed KDA-HKDF group")
        configuration = group.get("kdfConfiguration")
        if (type(group.get("tgId")) is not int or group.get("testType") not in ("AFT", "VAL") or
                group.get("multiExpansion", False) is not False or
                group.get("usesHybridSharedSecret", False) is not False or
                not isinstance(configuration, dict) or
                configuration.get("kdfType") not in ("hkdf", "HKDF") or
                configuration.get("hmacAlg") not in HASHES or
                configuration.get("fixedInfoPattern") != FIXED_INFO or
                configuration.get("fixedInfoEncoding") != "concatenation" or
                configuration.get("saltMethod") not in ("default", "random") or
                not isinstance(group.get("tests"), list) or not 1 <= len(group["tests"]) <= 10000):
            raise ValueError("Unsupported KDA-HKDF configuration")
        bits = configuration.get("l")
        salt_bits = configuration.get("saltLen")
        z_bits = group.get("zLength")
        if (type(bits) is not int or bits % 8 or not 112 <= bits <= 2048 or
                type(salt_bits) is not int or salt_bits % 8 or not 8 <= salt_bits <= 65536 or
                type(z_bits) is not int or z_bits % 8 or not 224 <= z_bits <= 65536 or
                (body["revision"] == "Sp800-56Cr2" and salt_bits > 512)):
            raise ValueError("Unsupported KDA-HKDF length")
        cases = []
        for case in group["tests"]:
            if not isinstance(case, dict) or type(case.get("tcId")) is not int:
                raise ValueError("Malformed KDA-HKDF case")
            parameters = case.get("kdfParameter")
            if (not isinstance(parameters, dict) or
                    parameters.get("kdfType") not in ("hkdf", "HKDF") or
                    parameters.get("l") != bits or
                    "t" in parameters):
                raise ValueError("Unsupported KDA-HKDF case parameters")
            secret = _hex(parameters.get("z"))
            salt = _hex(parameters.get("salt"))
            if len(secret) * 8 != z_bits or len(salt) * 8 != salt_bits:
                raise ValueError("KDA-HKDF input bit length mismatch")
            if configuration["saltMethod"] == "default" and any(salt):
                raise ValueError("Default salt must be zero-filled")
            info = (_party(case.get("fixedInfoPartyU")) +
                    _party(case.get("fixedInfoPartyV")) + bits.to_bytes(4, "big"))
            derived = qsc.hkdf(configuration["hmacAlg"], secret, salt, info, bits // 8)
            if len(derived) != bits // 8:
                raise ValueError("Invalid HKDF output length")
            item = {"tcId": case["tcId"]}
            if group["testType"] == "VAL":
                expected = _hex(case.get("dkm"), 256)
                if len(expected) != len(derived):
                    raise ValueError("VAL expected DKM size mismatch")
                item["testPassed"] = hmac.compare_digest(expected, derived)
            else:
                item["dkm"] = derived.hex().upper()
            cases.append(item)
        groups.append({"tgId": group["tgId"], "tests": cases})
    return [{"acvVersion": "1.0"}, {"vsId": body["vsId"], "testGroups": groups}]
