#!/usr/bin/env python3
"""FIPS 204 ML-DSA ACVP adapter for QSC's parameter-specific APIs.

Current scope: seeded keyGen, external pure deterministic sigGen, external pure
sigVer. Internal-mu, randomized, preHash and seed-format sigGen are NOT advertised.
"""

import ctypes as c
from pathlib import Path

PARAMETERS = {
    "ML-DSA-44": (44, 1312, 2560, 2420),
    "ML-DSA-65": (65, 1952, 4032, 3309),
    "ML-DSA-87": (87, 2592, 4896, 4627),
}


def registration() -> list[dict]:
    """Describe only byte-aligned QSC operations implemented by the adapter."""
    prerequisites = [{"algorithm": "SHA", "valValue": "same"}]
    capability = {"parameterSets": list(PARAMETERS),
                  "messageLength": [{"min": 8, "max": 65536, "increment": 8}],
                  "contextLength": [{"min": 0, "max": 2040, "increment": 8}]}
    return [
        {"algorithm": "ML-DSA", "mode": "keyGen", "revision": "FIPS204",
         "prereqVals": prerequisites, "parameterSets": list(PARAMETERS)},
        {"algorithm": "ML-DSA", "mode": "sigGen", "revision": "FIPS204-tr1",
         "prereqVals": prerequisites, "capabilities": [capability],
         "deterministic": [True], "signatureInterfaces": ["external"],
         "preHash": ["pure"], "keyFormats": ["expanded"]},
        {"algorithm": "ML-DSA", "mode": "sigVer", "revision": "FIPS204",
         "prereqVals": prerequisites, "capabilities": [capability],
         "signatureInterfaces": ["external"], "preHash": ["pure"]},
    ]


def _bytes(value: dict, name: str, exact: int | None = None, maximum: int = 8192) -> bytes:
    """Validate hex field length and encoding before any call into native code."""
    encoded = value.get(name)
    if not isinstance(encoded, str) or len(encoded) % 2 or len(encoded) > maximum * 2:
        raise ValueError(f"Invalid ML-DSA {name} encoding")
    if exact is not None and len(encoded) != exact * 2:
        raise ValueError(f"Invalid ML-DSA {name} length")
    try:
        data = bytes.fromhex(encoded)
    except ValueError as exc:
        raise ValueError(f"Invalid ML-DSA {name} encoding") from exc
    if (exact is not None and len(data) != exact) or len(data) > maximum:
        raise ValueError(f"Invalid ML-DSA {name} length")
    return data


def _buffer(data: bytes) -> c.Array:
    """Keep native input buffers alive through their individual C calls."""
    return c.create_string_buffer(data, max(len(data), 1))


class QscMlDsa:
    """Bind QSC FIPS 204 seed, attached signature, and external context APIs."""

    def __init__(self, library: Path):
        self._dll = c.CDLL(str(library.resolve()))
        self._ops = {}
        for name, (level, _, _, _) in PARAMETERS.items():
            prefix = f"qsc_mldsa{level}_"
            gen = getattr(self._dll, prefix + "seeded_generate_keypair")
            gen.argtypes = [c.c_void_p] * 3
            gen.restype = None
            sign = getattr(self._dll, prefix + "sign_ex")
            sign.argtypes = [c.c_void_p, c.POINTER(c.c_size_t), c.c_void_p,
                             c.c_size_t, c.c_void_p, c.c_size_t, c.c_void_p, c.c_void_p]
            sign.restype = c.c_bool
            verify = getattr(self._dll, prefix + "verify_ex")
            verify.argtypes = [c.c_void_p, c.POINTER(c.c_size_t), c.c_void_p,
                               c.c_size_t, c.c_void_p, c.c_size_t, c.c_void_p]
            verify.restype = c.c_bool
            self._ops[name] = gen, sign, verify

    def keygen(self, parameter: str, seed: bytes) -> tuple[bytes, bytes]:
        """Derive a FIPS204 signing/verification pair from the provided 32-byte seed."""
        _, public_len, secret_len, _ = PARAMETERS[parameter]
        if len(seed) != 32:
            raise ValueError("ML-DSA seed must contain 32 bytes")
        public = c.create_string_buffer(public_len)
        private = c.create_string_buffer(secret_len)
        self._ops[parameter][0](public, private, _buffer(seed))
        return public.raw, private.raw

    def sign(self, parameter: str, sk: bytes, message: bytes, context: bytes) -> bytes:
        """Generate an external-pure deterministic detached ML-DSA signature."""
        _, _, secret_len, signature_len = PARAMETERS[parameter]
        if len(sk) != secret_len or len(message) > 8192 or len(context) > 255:
            raise ValueError("Unsupported ML-DSA signing input length")
        output = c.create_string_buffer(signature_len + len(message))
        result_len = c.c_size_t(0)
        if not self._ops[parameter][1](output, c.byref(result_len), _buffer(message),
                                       len(message), _buffer(context), len(context),
                                       _buffer(sk), None):
            raise ValueError("QSC deterministic ML-DSA signing failed")
        if result_len.value != signature_len + len(message):
            raise ValueError("QSC ML-DSA signing returned an invalid length")
        return output.raw[:signature_len]

    def verify(self, parameter: str, pk: bytes, message: bytes,
               context: bytes, signature: bytes) -> bool:
        """Verify an external-pure detached signature using QSC's attached interface."""
        _, public_len, _, signature_len = PARAMETERS[parameter]
        if (len(pk) != public_len or
                len(message) > 8192 or len(context) > 255):
            raise ValueError("Unsupported ML-DSA verification input length")
        if len(signature) != signature_len:
            return False
        attached = _buffer(signature + message)
        recovered = c.create_string_buffer(max(1, len(message)))
        recovered_len = c.c_size_t(0)
        result = self._ops[parameter][2](recovered, c.byref(recovered_len),
                                         _buffer(context), len(context), attached,
                                         len(signature) + len(message), _buffer(pk))
        return bool(result and recovered_len.value == len(message) and
                    recovered.raw[:len(message)] == message)


def build_mldsa_response(envelope: list, qsc: QscMlDsa) -> list:
    """Process only explicitly supported keyGen, sigGen and sigVer vector groups."""
    if (not isinstance(envelope, list) or len(envelope) != 2 or
            not isinstance(envelope[0], dict) or envelope[0].get("acvVersion") != "1.0" or
            not isinstance(envelope[1], dict)):
        raise ValueError("Invalid ML-DSA vector envelope")
    body = envelope[1]
    mode = body.get("mode")
    allowed = {"keyGen": "FIPS204", "sigGen": "FIPS204-tr1", "sigVer": "FIPS204"}
    if (body.get("algorithm") != "ML-DSA" or allowed.get(mode) != body.get("revision") or
            type(body.get("vsId")) is not int or not isinstance(body.get("testGroups"), list)):
        raise ValueError("Unsupported ML-DSA vector set")
    groups = []
    for group in body["testGroups"]:
        if (not isinstance(group, dict) or group.get("parameterSet") not in PARAMETERS or
                type(group.get("tgId")) is not int or
                group.get("testType") != "AFT" or not isinstance(group.get("tests"), list)):
            raise ValueError("Unsupported ML-DSA vector group")
        if mode != "keyGen" and (group.get("signatureInterface") != "external" or
                                 group.get("preHash") != "pure" or
                                 group.get("externalMu") is not None):
            raise ValueError("Unsupported ML-DSA signature interface")
        if mode == "sigGen" and (group.get("deterministic") is not True or
                                 group.get("keyFormat") != "expanded"):
            raise ValueError("Unsupported ML-DSA signing mode or key format")
        parameter = group["parameterSet"]
        _, public_len, private_len, signature_len = PARAMETERS[parameter]
        cases = []
        for case in group["tests"]:
            if not isinstance(case, dict) or type(case.get("tcId")) is not int:
                raise ValueError("Invalid ML-DSA case identifier")
            answer = {"tcId": case["tcId"]}
            if mode == "keyGen":
                pk, sk = qsc.keygen(parameter, _bytes(case, "seed", 32))
                answer.update(pk=pk.hex().upper(), sk=sk.hex().upper())
            else:
                message = _bytes(case, "message")
                context = _bytes(case, "context", maximum=255)
                if mode == "sigGen":
                    signature = qsc.sign(parameter, _bytes(case, "sk", private_len),
                                         message, context)
                    answer["signature"] = signature.hex().upper()
                else:
                    answer["testPassed"] = qsc.verify(parameter, _bytes(case, "pk", public_len),
                                                       message, context,
                                                       _bytes(case, "signature", maximum=signature_len + 512))
            cases.append(answer)
        groups.append({"tgId": group["tgId"], "tests": cases})
    return [{"acvVersion": "1.0"}, {"vsId": body["vsId"], "testGroups": groups}]
