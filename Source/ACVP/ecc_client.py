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

"""QSC elliptic-curve ACVP response adapters.

Supported: ECDSA sigVer, offline DetECDSA sigGen, pure EDDSA sigVer/sigGen, XECDH SSC AFT.
All curves are required. P-384 signing remains pending its updated source.
No cryptographic validation status is implied by constructing responses.
"""

import ctypes as c
import hmac
import os
import re
import secrets

NIST_CURVES = {"P-256": ("p256", 32, "SHA2-256"),
               "P-384": ("p384", 48, "SHA2-384"),
               "P-521": ("p521", 66, "SHA2-512")}
ED_CURVES = {"ED-25519": ("ed25519", 32, 64),
             "ED-448": ("ed448", 57, 114)}
X_CURVES = {"Curve25519": ("x25519", 32), "Curve448": ("x448", 56)}
HEX = re.compile(r"(?:[0-9a-fA-F]{2})*\Z")
MAX_MESSAGE = 65536
# FIPS 186-5 subgroup orders, used for rejection-sampled ECDSA test keys.
CURVE_ORDERS = {
    "P-256": int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16),
    "P-384": int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF"
                 "581A0DB248B0A77AECEC196ACCC52973", 16),
    "P-521": int("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                 "FA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16),
}


def decode_hex(value, expected=None, limit=MAX_MESSAGE):
    """Parse byte-exact ACVP hexadecimal values without accepting whitespace."""
    if not isinstance(value, str) or len(value) > limit * 2 or HEX.fullmatch(value) is None:
        raise ValueError("Invalid ACVP hex data")
    result = bytes.fromhex(value)
    if expected is not None and len(result) != expected:
        raise ValueError("Unexpected ACVP buffer length")
    return result


def fixed_integer(value, size):
    """Accept an ACVP nonnegative integer, left-padded to its curve width."""
    raw = decode_hex(value, limit=size + 1)
    if len(raw) == size + 1 and raw[0] == 0:
        raw = raw[1:]
    if len(raw) > size or len(raw) == 0:
        raise ValueError("Invalid elliptic-curve integer length")
    return raw.rjust(size, b"\x00")


def memory(value):
    """Create distinct caller-owned C memory for one input."""
    return c.create_string_buffer(value, max(1, len(value)))


def bind(library, name, result, arguments):
    """Bind a QSC symbol and its exact public calling convention."""
    method = getattr(library, name)
    method.argtypes = arguments
    method.restype = result
    return method


class QscEcc:
    """Call original QSC ECC APIs through a separate qualification library."""

    def __init__(self, library, require_complete=True):
        self._dll = c.CDLL(str(library))
        # The complete ECDSA target requires all three curves, including P-384.
        for name, _, _ in NIST_CURVES.values():
            if not require_complete and name == "p384":
                continue
            bind(self._dll, f"qsc_{name}_verify", c.c_bool,
                 [c.c_void_p, c.POINTER(c.c_size_t), c.c_void_p, c.c_size_t, c.c_void_p])
        for name, _, _ in NIST_CURVES.values():
            if require_complete or name != "p384":
                bind(self._dll, f"qsc_{name}_keypair", c.c_int32,
                     [c.c_void_p, c.c_void_p, c.c_void_p])
                bind(self._dll, f"qsc_{name}_sign", c.c_int32,
                     [c.c_void_p, c.POINTER(c.c_size_t), c.c_void_p, c.c_size_t, c.c_void_p])
                bind(self._dll, f"qsc_{name}_publickey_from_privatekey", c.c_int32,
                     [c.c_void_p, c.c_void_p])
        for name, _, _ in NIST_CURVES.values():
            bind(self._dll, f"qsc_{name}_generate_seeded_keypair", None,
                 [c.c_void_p, c.c_void_p, c.c_void_p])
            bind(self._dll, f"qsc_{name}_key_exchange", c.c_bool,
                 [c.c_void_p, c.c_void_p, c.c_void_p])
        for name, size, _ in ED_CURVES.values():
            bind(self._dll, f"qsc_{name}_generate_seeded_keypair", None,
                 [c.c_void_p, c.c_void_p, c.c_void_p])
            bind(self._dll, f"qsc_{name}_sign", c.c_bool,
                 [c.c_void_p, c.POINTER(c.c_size_t), c.c_void_p, c.c_size_t, c.c_void_p])
            bind(self._dll, f"qsc_{name}_verify", c.c_bool,
                 [c.c_void_p, c.POINTER(c.c_size_t), c.c_void_p, c.c_size_t, c.c_void_p])
        bind(self._dll, "qsc_acvp_eddsa_publickey_valid", c.c_bool,
             [c.c_void_p, c.c_size_t])
        for name, _ in X_CURVES.values():
            bind(self._dll, f"qsc_{name}_public_from_private", None, [c.c_void_p, c.c_void_p])
            bind(self._dll, f"qsc_{name}_key_exchange", c.c_bool,
                 [c.c_void_p, c.c_void_p, c.c_void_p])

    def ecdsa_keygen(self, curve):
        """Generate a test scalar using rejection sampling and derive Q through QSC.

        Scalar production is supplied by the host OS for the adapter, not a
        validated QSC DRBG. Live use requires an actual DRBG qualification.
        """
        name, size, _ = NIST_CURVES[curve]
        scalar = bytearray((secrets.randbelow(CURVE_ORDERS[curve] - 1) + 1).to_bytes(size, "big"))
        public = c.create_string_buffer(2 * size)
        try:
            status = getattr(self._dll, f"qsc_{name}_publickey_from_privatekey")(
                public, (c.c_ubyte * size).from_buffer(scalar))
            if status != 0 or not any(public.raw):
                raise ValueError("QSC ECDSA scalar-to-point generation failed")
            return bytes(scalar), public.raw
        finally:
            for index in range(size):
                scalar[index] = 0

    def ecdsa_keyver(self, curve, public):
        """Exercise the QSC ECDH point-validation path with valid scalar one."""
        size = NIST_CURVES[curve][1]
        try:
            return bool(self.ecdh_exchange(curve, public, (1).to_bytes(size, "big")))
        except ValueError:
            return False

    def eddsa_keygen(self, curve):
        """Return a generated EdDSA seed and its QSC-derived public key."""
        name, size, _ = ED_CURVES[curve]
        seed = bytearray(os.urandom(size))
        private = c.create_string_buffer(2 * size)
        public = c.create_string_buffer(size)
        try:
            getattr(self._dll, f"qsc_{name}_generate_seeded_keypair")(
                public, private, (c.c_ubyte * size).from_buffer(seed))
            if not any(public.raw) or not self.eddsa_keyver(curve, public.raw):
                raise ValueError("QSC EdDSA key generation failed")
            return bytes(seed), public.raw
        finally:
            c.memset(private, 0, 2 * size)
            for index in range(size):
                seed[index] = 0

    def eddsa_keyver(self, curve, public):
        """Check a point using QSC canonical-encoding, order and decode rules."""
        size = ED_CURVES[curve][1]
        return (len(public) == size and bool(self._dll.qsc_acvp_eddsa_publickey_valid(
            memory(public), size)))

    def xecdh_keygen(self, curve):
        """Generate a test XECDH scalar and obtain QSC's public key."""
        name, size = X_CURVES[curve]
        private = bytearray(os.urandom(size))
        public = c.create_string_buffer(size)
        try:
            getattr(self._dll, f"qsc_{name}_public_from_private")(
                public, (c.c_ubyte * size).from_buffer(private))
            if not any(public.raw):
                raise ValueError("XECDH key generation failed")
            return bytes(private), public.raw
        finally:
            for index in range(size):
                private[index] = 0

    def xecdh_keyver(self, curve, public):
        """Test whether the QSC exchange API accepts this RFC7748 public key."""
        name, size = X_CURVES[curve]
        if len(public) != size:
            return False
        shared = c.create_string_buffer(size)
        scalar = (1).to_bytes(size, "little")
        accepted = getattr(self._dll, f"qsc_{name}_key_exchange")(
            shared, memory(public), memory(scalar))
        return bool(accepted and any(shared.raw))

    def ecdsa_sign_group(self, curve, messages):
        """Sign one deterministic-ECDSA group using a fresh QSC seeded keypair.

        This is an offline ACVP-response adapter, not a claim of validated
        FIPS 186-5 key generation or approved random-bit generation.
        """
        name, size, _ = NIST_CURVES[curve]
        seed = bytearray(os.urandom(size))
        seed_view = (c.c_ubyte * size).from_buffer(seed)
        public = c.create_string_buffer(2 * size)
        private = c.create_string_buffer(3 * size)
        results = []
        try:
            status = getattr(self._dll, f"qsc_{name}_keypair")(public, private, seed_view)
            if status != 0 or not any(public.raw):
                raise ValueError("QSC ECDSA seeded key generation failed")
            for message in messages:
                signed = c.create_string_buffer(2 * size + len(message))
                length = c.c_size_t(0)
                status = getattr(self._dll, f"qsc_{name}_sign")(
                    signed, c.byref(length), memory(message), len(message), private)
                if status != 0 or length.value != len(message) + 2 * size:
                    raise ValueError("QSC ECDSA signing failed")
                if signed.raw[2 * size:] != message:
                    raise ValueError("QSC ECDSA signed-message mismatch")
                results.append((signed.raw[:size], signed.raw[size:2 * size]))
            return public.raw, results
        finally:
            c.memset(private, 0, 3 * size)
            for index in range(size):
                seed[index] = 0

    def eddsa_sign_group(self, curve, messages):
        """Generate one pure EdDSA keypair and sign the group's messages."""
        name, size, signature_size = ED_CURVES[curve]
        seed = bytearray(os.urandom(size))
        seed_view = (c.c_ubyte * size).from_buffer(seed)
        private = c.create_string_buffer(2 * size)
        public = c.create_string_buffer(size)
        results = []
        try:
            getattr(self._dll, f"qsc_{name}_generate_seeded_keypair")(
                public, private, seed_view)
            if not any(public.raw):
                raise ValueError("QSC EdDSA seeded key generation failed")
            for message in messages:
                signed = c.create_string_buffer(signature_size + len(message))
                length = c.c_size_t(0)
                passed = getattr(self._dll, f"qsc_{name}_sign")(
                    signed, c.byref(length), memory(message), len(message), private)
                if not passed or length.value != signature_size + len(message):
                    raise ValueError("QSC EdDSA signing failed")
                if signed.raw[signature_size:] != message:
                    raise ValueError("QSC EdDSA signed-message mismatch")
                results.append(signed.raw[:signature_size])
            return public.raw, results
        finally:
            c.memset(private, 0, 2 * size)
            for index in range(size):
                seed[index] = 0

    def ecdsa_verify(self, curve, message, qx, qy, r, s):
        """Verify QSC's R||S||message representation; return acceptance flag."""
        name, size, _ = NIST_CURVES[curve]
        public = fixed_integer(qx, size) + fixed_integer(qy, size)
        signed = fixed_integer(r, size) + fixed_integer(s, size) + message
        recovered = c.create_string_buffer(max(1, len(message)))
        length = c.c_size_t(0)
        result = getattr(self._dll, f"qsc_{name}_verify")(
            recovered, c.byref(length), memory(signed), len(signed), memory(public))
        return bool(result and length.value == len(message) and recovered.raw[:len(message)] == message)

    def eddsa_verify(self, curve, message, public, signature):
        """Verify pure EdDSA using QSC's signature-prefix API."""
        name, size, signature_size = ED_CURVES[curve]
        if len(public) != size or len(signature) != signature_size:
            raise ValueError("Invalid EDDSA key or signature length")
        signed = signature + message
        recovered = c.create_string_buffer(max(1, len(message)))
        length = c.c_size_t(0)
        result = getattr(self._dll, f"qsc_{name}_verify")(
            recovered, c.byref(length), memory(signed), len(signed), memory(public))
        return bool(result and length.value == len(message) and recovered.raw[:len(message)] == message)

    def ecdh_exchange(self, curve, peer, private):
        """Compute one SP800-56Ar3 ECDH Z or report an invalid public key."""
        name, size, _ = NIST_CURVES[curve]
        if len(peer) != 2 * size or len(private) != size:
            raise ValueError("Invalid ECDH scalar or point size")
        secret = c.create_string_buffer(size)
        passed = getattr(self._dll, f"qsc_{name}_key_exchange")(
            secret, memory(peer), memory(private))
        if not passed:
            raise ValueError("Invalid ECDH peer or scalar")
        return secret.raw

    def ecdh_generate(self, curve, peer):
        """Generate an IUT static key pair and compute staticUnified shared Z.

        The seed comes from OS entropy. It is not claimed as an ACVP-approved DRBG;
        therefore this operation stays offline until RNG prerequisites are met.
        """
        name, size, _ = NIST_CURVES[curve]
        if len(peer) != 2 * size:
            raise ValueError("Invalid ECDH peer size")
        seed = bytearray(os.urandom(size))
        seed_view = (c.c_ubyte * size).from_buffer(seed)
        private = c.create_string_buffer(size)
        public = c.create_string_buffer(2 * size)
        try:
            getattr(self._dll, f"qsc_{name}_generate_seeded_keypair")(
                public, private, seed_view)
            if not any(public.raw) or not any(private.raw):
                raise ValueError("ECDH seeded key generation failed")
            shared = self.ecdh_exchange(curve, peer, private.raw)
            return public.raw, shared
        finally:
            for index in range(size):
                seed[index] = 0
            c.memset(private, 0, size)

    def xecdh_ssc(self, curve, server_public):
        """Create a fresh ephemeral private scalar and compute the shared secret."""
        name, size = X_CURVES[curve]
        if len(server_public) != size:
            raise ValueError("Invalid server public-key length")
        private = bytearray(os.urandom(size))
        public = c.create_string_buffer(size)
        shared = c.create_string_buffer(size)
        private_buffer = (c.c_ubyte * size).from_buffer(private)
        try:
            getattr(self._dll, f"qsc_{name}_public_from_private")(public, private_buffer)
            result = getattr(self._dll, f"qsc_{name}_key_exchange")(
                shared, memory(server_public), private_buffer)
            if not result or not any(shared.raw):
                raise ValueError("XECDH peer rejected")
            return public.raw, shared.raw
        finally:
            for index in range(size):
                private[index] = 0


def registration(algorithm, drbg_validation, mode=None):
    """Register one exact, locally supported ECC operation with verified DRBG ID.

    A real DRBG validation number is required for live sessions. `same` is not
    accepted as an implicit claim. Missing QSC implementation symbols fail at
    library initialization; no curve is silently removed from registration.
    """
    if not isinstance(drbg_validation, str) or not drbg_validation.strip() or drbg_validation.strip().lower() == "same":
        raise ValueError("ECC registration requires a verified DRBG prerequisite")
    prereq = [{"algorithm": "DRBG", "valValue": drbg_validation.strip()}]
    prime_curves = list(NIST_CURVES)
    ed_curves = list(ED_CURVES)
    x_curves = list(X_CURVES)
    modes = {
        "ECDSA": ("keyGen", "keyVer", "sigVer"),
        "DetECDSA": ("sigGen",),
        "EDDSA": ("keyGen", "keyVer", "sigGen", "sigVer"),
        "XECDH": ("keyGen", "keyVer", "SSC"),
        "KAS-ECC-SSC": (None,),
    }
    if algorithm not in modes or (mode is not None and mode not in modes[algorithm]):
        raise ValueError("Unsupported ECC algorithm or operation")
    selected = (mode,) if mode is not None else modes[algorithm]
    capabilities = []
    for operation in selected:
        item = {"algorithm": algorithm, "revision": "FIPS186-5" if algorithm in ("ECDSA", "DetECDSA")
                else "Sp800-56Ar3" if algorithm == "KAS-ECC-SSC"
                else "RFC7748" if algorithm == "XECDH" else "1.0",
                "prereqVals": list(prereq)}
        if operation is not None:
            item["mode"] = operation
        if algorithm == "KAS-ECC-SSC":
            item["prereqVals"].append({"algorithm": "ECDSA", "valValue": "same"})
            item["scheme"] = {"staticUnified": {"kasRole": ["initiator", "responder"]}}
            item["domainParameterGenerationMethods"] = prime_curves
        elif algorithm in ("ECDSA", "DetECDSA"):
            item["prereqVals"].append({"algorithm": "SHA", "valValue": "same"})
            if algorithm == "DetECDSA" or operation in ("sigVer",):
                item["capabilities"] = [{"curve": [curve], "hashAlg": [values[2]]}
                                        for curve, values in NIST_CURVES.items()]
            else:
                item["curve"] = prime_curves
                if operation == "keyGen":
                    item["secretGenerationMode"] = ["testing candidates"]
        elif algorithm == "EDDSA":
            item["prereqVals"].append({"algorithm": "SHA", "valValue": "same"})
            if operation in ("sigGen", "sigVer"):
                # QSC's Ed448 interface supports the empty context only.
                item["pure"] = True
                item["preHash"] = False
                item["contextLength"] = [{"min": 0, "max": 0, "increment": 1}]
            item["curve"] = ed_curves
        else:
            item["curve"] = x_curves
        capabilities.append(item)
    return capabilities


def build_ecc_response(envelope, ecc):
    """Process the supported ACVP ECDSA, EDDSA and XECDH AFT operations.

    Every test-case ID must occur once. Malformed and unsupported modes fail
    closed. No vector is silently omitted from the response.
    """
    if (not isinstance(envelope, list) or len(envelope) != 2 or
            envelope[0] != {"acvVersion": "1.0"} or not isinstance(envelope[1], dict)):
        raise ValueError("Invalid ACVP envelope")
    body = envelope[1]
    algorithm = body.get("algorithm")
    mode = body.get("mode")
    revision = body.get("revision")
    operations = {"ECDSA": {"keyGen", "keyVer", "sigVer"},
                  "DetECDSA": {"sigGen"},
                  "EDDSA": {"keyGen", "keyVer", "sigGen", "sigVer"},
                  "XECDH": {"keyGen", "keyVer", "SSC"}}
    revisions = {"ECDSA": "FIPS186-5", "DetECDSA": "FIPS186-5",
                 "EDDSA": "1.0", "XECDH": "RFC7748"}
    if algorithm not in operations or mode not in operations[algorithm] or revision != revisions[algorithm]:
        raise ValueError("Unsupported ECC operation or revision")
    if type(body.get("vsId")) is not int or not isinstance(body.get("testGroups"), list):
        raise ValueError("Invalid vector set")
    groups = []
    seen_groups = set()
    seen_cases = set()
    for group in body["testGroups"]:
        if (not isinstance(group, dict) or type(group.get("tgId")) is not int or
                group["tgId"] in seen_groups or group.get("testType") != "AFT" or
                not isinstance(group.get("tests"), list) or group.get("conformance") is not None):
            raise ValueError("Unsupported or duplicate ECC test group")
        seen_groups.add(group["tgId"])
        curve = group.get("curve")
        if algorithm in ("ECDSA", "DetECDSA"):
            if curve not in NIST_CURVES:
                raise ValueError("Unsupported ECDSA curve")
            if mode in ("sigGen", "sigVer") and group.get("hashAlg") != NIST_CURVES[curve][2]:
                raise ValueError("Unsupported ECDSA hash")
            if mode == "keyGen" and group.get("secretGenerationMode") not in ("testing candidates", None):
                raise ValueError("Unsupported secret generation mode")
        elif algorithm == "EDDSA":
            if curve not in ED_CURVES:
                raise ValueError("Unsupported EDDSA curve")
            if mode in ("sigGen", "sigVer"):
                if group.get("preHash", group.get("prehash", False)) is not False:
                    raise ValueError("Unsupported EDDSA prehash")
        elif curve not in X_CURVES:
            raise ValueError("Unsupported XECDH curve")
        cases = []
        if mode == "sigGen":
            messages = []
            for item in group["tests"]:
                if (not isinstance(item, dict) or type(item.get("tcId")) is not int or
                        item["tcId"] in seen_cases or item.get("context") not in (None, "")):
                    raise ValueError("Unsupported signing case")
                seen_cases.add(item["tcId"])
                messages.append(decode_hex(item.get("message")))
            if algorithm == "DetECDSA":
                public, signatures = ecc.ecdsa_sign_group(curve, messages)
                size = NIST_CURVES[curve][1]
                if len(public) != 2 * size:
                    raise ValueError("Incomplete ECDSA group public key")
                group_result = {"tgId": group["tgId"], "qx": public[:size].hex().upper(),
                                "qy": public[size:].hex().upper()}
                cases = [{"tcId": item["tcId"], "r": r.hex().upper(), "s": sig_s.hex().upper()}
                         for item, (r, sig_s) in zip(group["tests"], signatures)]
            else:
                public, signatures = ecc.eddsa_sign_group(curve, messages)
                if len(public) != ED_CURVES[curve][1]:
                    raise ValueError("Incomplete EDDSA group public key")
                group_result = {"tgId": group["tgId"], "q": public.hex().upper()}
                cases = [{"tcId": item["tcId"], "signature": sig.hex().upper()}
                         for item, sig in zip(group["tests"], signatures)]
            if len(signatures) != len(messages):
                raise ValueError("Incomplete signing results")
            group_result["tests"] = cases
            groups.append(group_result)
            continue
        for item in group["tests"]:
            if (not isinstance(item, dict) or type(item.get("tcId")) is not int or
                    item["tcId"] in seen_cases):
                raise ValueError("Invalid or duplicate test-case ID")
            seen_cases.add(item["tcId"])
            result = {"tcId": item["tcId"]}
            if algorithm == "ECDSA":
                size = NIST_CURVES[curve][1]
                if mode == "keyGen":
                    private, public = ecc.ecdsa_keygen(curve)
                    if len(private) != size or len(public) != 2 * size:
                        raise ValueError("Incomplete ECDSA key generation")
                    result.update({"d": private.hex().upper(), "qx": public[:size].hex().upper(),
                                   "qy": public[size:].hex().upper()})
                elif mode == "keyVer":
                    public = fixed_integer(item.get("qx"), size) + fixed_integer(item.get("qy"), size)
                    result["testPassed"] = bool(ecc.ecdsa_keyver(curve, public))
                else:
                    message = decode_hex(item.get("message"))
                    result["testPassed"] = bool(ecc.ecdsa_verify(curve, message,
                        item.get("qx"), item.get("qy"), item.get("r"), item.get("s")))
            elif algorithm == "EDDSA":
                if mode == "keyGen":
                    seed, public = ecc.eddsa_keygen(curve)
                    if len(seed) != ED_CURVES[curve][1] or len(public) != len(seed):
                        raise ValueError("Incomplete EDDSA key generation")
                    result.update({"d": seed.hex().upper(), "q": public.hex().upper()})
                elif mode == "keyVer":
                    key = decode_hex(item.get("q"), expected=ED_CURVES[curve][1])
                    result["testPassed"] = bool(ecc.eddsa_keyver(curve, key))
                else:
                    if item.get("context") not in (None, ""):
                        raise ValueError("Unsupported EDDSA context")
                    message = decode_hex(item.get("message"))
                    key = decode_hex(item.get("q"), ED_CURVES[curve][1])
                    signature = decode_hex(item.get("signature"), ED_CURVES[curve][2])
                    result["testPassed"] = bool(ecc.eddsa_verify(curve, message, key, signature))
            elif mode == "keyGen":
                private, public = ecc.xecdh_keygen(curve)
                if len(private) != X_CURVES[curve][1] or len(public) != len(private):
                    raise ValueError("Incomplete XECDH key generation")
                result.update({"privateKey": private.hex().upper(), "publicKey": public.hex().upper()})
            elif mode == "keyVer":
                public = decode_hex(item.get("publicKey"), X_CURVES[curve][1])
                result["testPassed"] = bool(ecc.xecdh_keyver(curve, public))
            else:
                peer = decode_hex(item.get("publicServer"), X_CURVES[curve][1])
                public, secret = ecc.xecdh_ssc(curve, peer)
                if len(public) != len(peer) or len(secret) != len(peer):
                    raise ValueError("Incomplete XECDH shared secret")
                result.update({"publicIut": public.hex().upper(), "z": secret.hex().upper()})
            cases.append(result)
        groups.append({"tgId": group["tgId"], "tests": cases})
    return [{"acvVersion": "1.0"}, {"vsId": body["vsId"], "testGroups": groups}]


def build_kas_response(envelope, ecc):
    """Offline KAS-ECC-SSC staticUnified AFT/VAL; not a live registration."""
    if (not isinstance(envelope, list) or len(envelope) != 2 or
            envelope[0] != {"acvVersion": "1.0"} or not isinstance(envelope[1], dict)):
        raise ValueError("Invalid KAS vector envelope")
    body = envelope[1]
    if (body.get("algorithm") != "KAS-ECC-SSC" or
            body.get("revision") != "Sp800-56Ar3" or type(body.get("vsId")) is not int or
            not isinstance(body.get("testGroups"), list)):
        raise ValueError("Unsupported KAS-ECC-SSC vector")
    groups = []
    for group in body["testGroups"]:
        curve = group.get("domainParameterGenerationMode")
        test_type = group.get("testType")
        if (type(group.get("tgId")) is not int or curve not in NIST_CURVES or
                group.get("scheme") != "staticUnified" or
                group.get("kasRole") not in ("initiator", "responder") or
                group.get("hashFunctionZ") is not None or
                test_type not in ("AFT", "VAL") or
                not isinstance(group.get("tests"), list)):
            raise ValueError("KAS-ECC-SSC scheme or test group is not implemented")
        size = NIST_CURVES[curve][1]
        cases = []
        for item in group["tests"]:
            if type(item.get("tcId")) is not int:
                raise ValueError("Missing KAS test identifier")
            peer = fixed_integer(item.get("staticPublicServerX"), size) + \
                   fixed_integer(item.get("staticPublicServerY"), size)
            if test_type == "AFT":
                public, z = ecc.ecdh_generate(curve, peer)
                case = {"tcId": item["tcId"],
                        "staticPublicIutX": public[:size].hex().upper(),
                        "staticPublicIutY": public[size:].hex().upper(),
                        "z": z.hex().upper()}
            else:
                local_private = fixed_integer(item.get("staticPrivateIut"), size)
                expected = decode_hex(item.get("z"), expected=size)
                try:
                    z = ecc.ecdh_exchange(curve, peer, local_private)
                    passed = hmac.compare_digest(z, expected)
                except ValueError:
                    passed = False
                case = {"tcId": item["tcId"], "testPassed": passed}
            cases.append(case)
        groups.append({"tgId": group["tgId"], "tests": cases})
    return [{"acvVersion": "1.0"}, {"vsId": body["vsId"], "testGroups": groups}]
