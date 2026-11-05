#!/usr/bin/env python3
"""FIPS 205 SLH-DSA SHAKE ACVP external-pure deterministic vector adapter."""

import ctypes as c
from pathlib import Path

PARAMETERS = {
    "SLH-DSA-SHAKE-128s": ("128s", 32, 64, 7856, 48),
    "SLH-DSA-SHAKE-128f": ("128f", 32, 64, 17088, 48),
    "SLH-DSA-SHAKE-192s": ("192s", 48, 96, 16224, 72),
    "SLH-DSA-SHAKE-192f": ("192f", 48, 96, 35664, 72),
    "SLH-DSA-SHAKE-256s": ("256s", 64, 128, 29792, 96),
    "SLH-DSA-SHAKE-256f": ("256f", 64, 128, 49856, 96),
}


def registration() -> list[dict]:
    """Advertise only SHAKE family and external-pure deterministic signatures."""
    prerequisite = [{"algorithm": "SHAKE", "valValue": "same"}]
    capability = {"parameterSets": list(PARAMETERS),
                  "messageLength": [{"min": 8, "max": 65536, "increment": 8}],
                  "contextLength": [{"min": 0, "max": 2040, "increment": 8}]}
    return [
        {"algorithm": "SLH-DSA", "mode": "keyGen", "revision": "FIPS205",
         "prereqVals": prerequisite, "parameterSets": list(PARAMETERS)},
        {"algorithm": "SLH-DSA", "mode": "sigGen", "revision": "FIPS205",
         "prereqVals": prerequisite, "capabilities": [capability],
         "signatureInterfaces": ["external"], "preHash": ["pure"], "deterministic": [True]},
        {"algorithm": "SLH-DSA", "mode": "sigVer", "revision": "FIPS205",
         "prereqVals": prerequisite, "capabilities": [capability],
         "signatureInterfaces": ["external"], "preHash": ["pure"]},
    ]


def _bytes(case: dict, field: str, exact: int | None = None, maximum: int = 8192) -> bytes:
    """Validate required hex before submitting to native code."""
    value = case.get(field)
    if not isinstance(value, str) or len(value) % 2 or len(value) > maximum * 2:
        raise ValueError(f"Invalid SLH-DSA {field} encoding")
    if exact is not None and len(value) != exact * 2:
        raise ValueError(f"Invalid SLH-DSA {field} length")
    try:
        data = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"Invalid SLH-DSA {field} encoding") from exc
    if len(data) > maximum or (exact is not None and len(data) != exact):
        raise ValueError(f"Invalid SLH-DSA {field} size")
    return data


def _buffer(value: bytes) -> c.Array:
    """Allocate mutable native input storage for the operation's lifetime."""
    return c.create_string_buffer(value, max(1, len(value)))


class QscSlhDsa:
    """Bind QSC's six FIPS 205 SHAKE key-generation/signature implementations."""

    def __init__(self, library: Path):
        self._dll = c.CDLL(str(library.resolve()))
        self._ops = {}
        for name, (parameter, _, _, _, _) in PARAMETERS.items():
            prefix = "qsc_slhdsa_shake" + parameter + "_"
            gen = getattr(self._dll, prefix + "generate_seeded_keypair")
            gen.argtypes = [c.c_void_p, c.c_void_p, c.c_void_p]
            gen.restype = c.c_bool
            sign = getattr(self._dll, prefix + "sign_deterministic")
            sign.argtypes = [c.c_void_p, c.POINTER(c.c_size_t), c.c_void_p,
                             c.c_size_t, c.c_void_p, c.c_size_t, c.c_void_p]
            sign.restype = c.c_bool
            verify = getattr(self._dll, prefix + "verify")
            verify.argtypes = [c.c_void_p, c.c_size_t, c.c_void_p,
                               c.c_size_t, c.c_void_p, c.c_size_t, c.c_void_p]
            verify.restype = c.c_bool
            self._ops[name] = (gen, sign, verify)

    def keygen(self, parameter: str, sk_seed: bytes, sk_prf: bytes,
               pk_seed: bytes) -> tuple[bytes, bytes]:
        """Derive public/private keys from skSeed || skPrf || pkSeed."""
        _, pklen, sklen, _, seedlen = PARAMETERS[parameter]
        if any(len(x) != seedlen // 3 for x in (sk_seed, sk_prf, pk_seed)):
            raise ValueError("SLH-DSA key-generation seed length mismatch")
        public = c.create_string_buffer(pklen)
        private = c.create_string_buffer(sklen)
        if not self._ops[parameter][0](public, private, _buffer(sk_seed + sk_prf + pk_seed)):
            raise ValueError("QSC SLH-DSA key generation failed")
        return public.raw, private.raw

    def sign(self, parameter: str, secret: bytes, message: bytes, context: bytes) -> bytes:
        """Generate deterministic external-pure SLH-DSA signature."""
        _, _, secret_len, signature_len, _ = PARAMETERS[parameter]
        if len(secret) != secret_len or len(message) > 8192 or len(context) > 255:
            raise ValueError("Unsupported SLH-DSA signing input length")
        signature = c.create_string_buffer(signature_len)
        output_len = c.c_size_t(0)
        if not self._ops[parameter][1](signature, c.byref(output_len), _buffer(message),
                                       len(message), _buffer(context), len(context),
                                       _buffer(secret)) or output_len.value != signature_len:
            raise ValueError("QSC SLH-DSA deterministic signature failed")
        return signature.raw

    def verify(self, parameter: str, public: bytes, message: bytes,
               context: bytes, signature: bytes) -> bool:
        """Verify a signature; malformed signature lengths represent verification failure."""
        _, public_len, _, signature_len, _ = PARAMETERS[parameter]
        if len(public) != public_len or len(message) > 8192 or len(context) > 255:
            raise ValueError("Unsupported SLH-DSA verification input length")
        if len(signature) != signature_len:
            return False
        return bool(self._ops[parameter][2](_buffer(signature), len(signature),
                                            _buffer(message), len(message),
                                            _buffer(context), len(context), _buffer(public)))


def build_slhdsa_response(envelope: list, qsc: QscSlhDsa) -> list:
    """Execute FIPS205 AFT groups with supported external-pure signature forms."""
    if (not isinstance(envelope, list) or len(envelope) != 2 or
            not isinstance(envelope[0], dict) or envelope[0].get("acvVersion") != "1.0" or
            not isinstance(envelope[1], dict)):
        raise ValueError("Invalid SLH-DSA ACVP envelope")
    body = envelope[1]
    mode = body.get("mode")
    if (body.get("algorithm") != "SLH-DSA" or mode not in ("keyGen", "sigGen", "sigVer") or
            body.get("revision") != "FIPS205" or type(body.get("vsId")) is not int or
            not isinstance(body.get("testGroups"), list)):
        raise ValueError("Unsupported SLH-DSA vector set")
    groups = []
    for group in body["testGroups"]:
        if (not isinstance(group, dict) or group.get("parameterSet") not in PARAMETERS or
                type(group.get("tgId")) is not int or
                group.get("testType") != "AFT" or not isinstance(group.get("tests"), list)):
            raise ValueError("Unsupported SLH-DSA group")
        if mode != "keyGen" and (group.get("signatureInterface") != "external" or
                                 group.get("preHash") != "pure"):
            raise ValueError("Unsupported SLH-DSA signature interface")
        if mode == "sigGen" and group.get("deterministic") is not True:
            raise ValueError("Unsupported SLH-DSA randomized signing")
        parameter = group["parameterSet"]
        _, public_len, secret_len, signature_len, seedlen = PARAMETERS[parameter]
        cases = []
        for case in group["tests"]:
            if not isinstance(case, dict) or type(case.get("tcId")) is not int:
                raise ValueError("Invalid SLH-DSA test case identifier")
            answer = {"tcId": case["tcId"]}
            if mode == "keyGen":
                public, secret = qsc.keygen(parameter, _bytes(case, "skSeed", seedlen // 3),
                                            _bytes(case, "skPrf", seedlen // 3),
                                            _bytes(case, "pkSeed", seedlen // 3))
                answer.update(pk=public.hex().upper(), sk=secret.hex().upper())
            else:
                message = _bytes(case, "message")
                context = _bytes(case, "context", maximum=255)
                if mode == "sigGen":
                    signature = qsc.sign(parameter, _bytes(case, "sk", secret_len),
                                         message, context)
                    answer["signature"] = signature.hex().upper()
                else:
                    signature = _bytes(case, "signature", maximum=signature_len + 512)
                    answer["testPassed"] = qsc.verify(parameter, _bytes(case, "pk", public_len),
                                                       message, context, signature)
            cases.append(answer)
        groups.append({"tgId": group["tgId"], "tests": cases})
    return [{"acvVersion": "1.0"}, {"vsId": body["vsId"], "testGroups": groups}]
