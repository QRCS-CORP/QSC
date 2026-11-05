#!/usr/bin/env python3
"""Strict FIPS 203 ML-KEM ACVP vector adapter for QSC parameter-specific APIs.

No cryptographic implementation is duplicated here. Key material is processed in
memory and must never be included in sanitized execution reports or CI logs.
"""

import ctypes as c
from pathlib import Path

PARAMETERS = {
    "ML-KEM-512": (512, 800, 1632, 768),
    "ML-KEM-768": (768, 1184, 2400, 1088),
    "ML-KEM-1024": (1024, 1568, 3168, 1568),
}


def registration() -> list[dict]:
    """Register FIPS 203 keyGen and the supported tr1 KEM modes only."""
    prerequisite = [{"algorithm": "SHA", "valValue": "same"}]
    return [
        {"algorithm": "ML-KEM", "mode": "keyGen", "revision": "FIPS203",
         "prereqVals": prerequisite, "parameterSets": list(PARAMETERS)},
        {"algorithm": "ML-KEM", "mode": "encapDecap", "revision": "FIPS203-tr1",
         "prereqVals": prerequisite, "parameterSets": list(PARAMETERS),
         "functions": ["encapsulation", "decapsulation"], "keyFormats": ["expanded"]},
    ]


def _bytes(case: dict, name: str, length: int) -> bytes:
    """Validate a required ACVP hex value before passing it to native QSC."""
    value = case.get(name)
    if not isinstance(value, str) or len(value) != length * 2:
        raise ValueError(f"Invalid ML-KEM {name} length")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"Invalid ML-KEM {name} encoding") from exc


def _buffer(data: bytes) -> c.Array:
    """Make a mutable, caller-owned native input buffer for the duration of a call."""
    return c.create_string_buffer(data, max(len(data), 1))


class QscMlKem:
    """Bind QSC's native, independently compiled ML-KEM parameter sets."""

    def __init__(self, library: Path):
        self._dll = c.CDLL(str(library.resolve()))
        self._operations = {}
        for name, (level, _, _, _) in PARAMETERS.items():
            prefix = f"qsc_kyber{level}_"
            generate = getattr(self._dll, prefix + "generate_seeded_keypair")
            generate.argtypes = [c.c_void_p] * 4
            generate.restype = None
            encapsulate = getattr(self._dll, prefix + "seeded_encapsulate")
            encapsulate.argtypes = [c.c_void_p] * 4
            encapsulate.restype = None
            decapsulate = getattr(self._dll, prefix + "decapsulate")
            decapsulate.argtypes = [c.c_void_p] * 3
            decapsulate.restype = c.c_bool
            self._operations[name] = (generate, encapsulate, decapsulate)

    def keygen(self, parameter: str, d: bytes, z: bytes) -> tuple[bytes, bytes]:
        """Generate expanded encapsulation/decapsulation keys from 32-byte seeds."""
        _, pklen, sklen, _ = PARAMETERS[parameter]
        if len(d) != 32 or len(z) != 32:
            raise ValueError("ML-KEM keyGen seed length must be 32 bytes")
        pk = c.create_string_buffer(pklen)
        sk = c.create_string_buffer(sklen)
        self._operations[parameter][0](pk, sk, _buffer(d), _buffer(z))
        return pk.raw, sk.raw

    def encapsulate(self, parameter: str, ek: bytes, m: bytes) -> tuple[bytes, bytes]:
        """Produce deterministic ciphertext and shared secret from supplied m."""
        _, pklen, _, ctlen = PARAMETERS[parameter]
        if len(ek) != pklen or len(m) != 32:
            raise ValueError("ML-KEM encapsulation input size mismatch")
        secret = c.create_string_buffer(32)
        ct = c.create_string_buffer(ctlen)
        self._operations[parameter][1](secret, ct, _buffer(ek), _buffer(m))
        return ct.raw, secret.raw

    def decapsulate(self, parameter: str, dk: bytes, ct: bytes) -> bytes:
        """Run FIPS 203 implicit-rejection decapsulation (invalid ciphertext is valid input)."""
        _, _, sklen, ctlen = PARAMETERS[parameter]
        if len(dk) != sklen or len(ct) != ctlen:
            raise ValueError("ML-KEM decapsulation input size mismatch")
        secret = c.create_string_buffer(32)
        if not self._operations[parameter][2](secret, _buffer(ct), _buffer(dk)):
            raise ValueError("QSC rejected the supplied ML-KEM decapsulation key")
        return secret.raw


def build_mlkem_response(envelope: list, qsc: QscMlKem) -> list:
    """Run supported NIST ML-KEM AFT/VAL groups and reject unknown capabilities."""
    if (not isinstance(envelope, list) or len(envelope) != 2 or
            not isinstance(envelope[0], dict) or envelope[0].get("acvVersion") != "1.0" or
            not isinstance(envelope[1], dict)):
        raise ValueError("Invalid ACVP ML-KEM envelope")
    body = envelope[1]
    mode = body.get("mode")
    revision = body.get("revision")
    if (body.get("algorithm") != "ML-KEM" or
            (mode, revision) not in (("keyGen", "FIPS203"),
                                     ("encapDecap", "FIPS203-tr1")) or
            type(body.get("vsId")) is not int or
            not isinstance(body.get("testGroups"), list)):
        raise ValueError("Unsupported ML-KEM vector set")
    response_groups = []
    for group in body["testGroups"]:
        if (not isinstance(group, dict) or
                type(group.get("tgId")) is not int or
                not isinstance(group.get("tests"), list) or
                group.get("parameterSet") not in PARAMETERS):
            raise ValueError("Invalid ML-KEM test group")
        parameter = group["parameterSet"]
        function = group.get("function")
        test_type = group.get("testType")
        if mode == "keyGen":
            if test_type != "AFT" or function is not None:
                raise ValueError("Unsupported ML-KEM keyGen test group")
        elif ((function == "encapsulation" and test_type != "AFT") or
              (function == "decapsulation" and test_type != "VAL") or
              function not in ("encapsulation", "decapsulation") or
              (function == "decapsulation" and group.get("keyFormat") != "expanded")):
            raise ValueError("Unsupported ML-KEM KEM test group")
        _, eklen, dklen, ctlen = PARAMETERS[parameter]
        cases = []
        for case in group["tests"]:
            if not isinstance(case, dict) or type(case.get("tcId")) is not int:
                raise ValueError("Invalid ML-KEM case identifier")
            answer = {"tcId": case["tcId"]}
            if mode == "keyGen":
                ek, dk = qsc.keygen(parameter, _bytes(case, "d", 32), _bytes(case, "z", 32))
                answer.update(ek=ek.hex().upper(), dk=dk.hex().upper())
            elif function == "encapsulation":
                ct, secret = qsc.encapsulate(parameter, _bytes(case, "ek", eklen), _bytes(case, "m", 32))
                answer.update(c=ct.hex().upper(), k=secret.hex().upper())
            else:
                secret = qsc.decapsulate(parameter, _bytes(case, "dk", dklen), _bytes(case, "c", ctlen))
                answer["k"] = secret.hex().upper()
            cases.append(answer)
        response_groups.append({"tgId": group["tgId"], "tests": cases})
    return [{"acvVersion": "1.0"}, {"vsId": body["vsId"], "testGroups": response_groups}]
