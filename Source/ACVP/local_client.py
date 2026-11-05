#!/usr/bin/env python3
"""Execute SHA AFT vectors from the local simulator with QSC's C implementations."""

import argparse
import ctypes
import json
from pathlib import Path
from urllib.request import Request, urlopen

from kdf_client import pbkdf_response
from kda_hkdf_client import response as kda_hkdf_response
from ecc_client import build_ecc_response, build_kas_response
from xof_client import QscXof, SUPPORTED as XOF_ALGORITHMS, build_xof_response
from mlkem_client import build_mlkem_response
from mldsa_client import build_mldsa_response
from slhdsa_client import build_slhdsa_response
from aes_client import (ALGORITHM as AES_GCM, ECB_ALGORITHM as AES_ECB,
                        CBC_ALGORITHM as AES_CBC, CTR_ALGORITHM as AES_CTR,
                        build_aes_response, build_ecb_response,
                        build_cbc_response, build_ctr_response)

ALGORITHMS = {
    "SHA2-256": ("qsc_sha256_compute", 32, False),
    "SHA2-384": ("qsc_sha384_compute", 48, False),
    "SHA2-512": ("qsc_sha512_compute", 64, False),
    "SHA3-256": ("qsc_sha3_compute256", 32, False),
    "SHA3-512": ("qsc_sha3_compute512", 64, False),
    "SHAKE-128": ("qsc_shake128_compute", None, True),
    "SHAKE-256": ("qsc_shake256_compute", None, True),
    "HMAC-SHA2-256": ("qsc_hmac256_compute", 32, False),
    "HMAC-SHA2-384": ("qsc_hmac384_compute", 48, False),
    "HMAC-SHA2-512": ("qsc_hmac512_compute", 64, False),
}


class QSC:
    """C ABI binding for the verified one-shot QSC SHA functions."""

    def __init__(self, library: Path):
        self._dll = ctypes.CDLL(str(library.resolve()))
        self.xof = QscXof(library.resolve())
        for method, _, xof in ALGORITHMS.values():
            operation = getattr(self._dll, method)
            operation.restype = None
            if method.startswith("qsc_hmac"):
                operation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                      ctypes.c_void_p, ctypes.c_size_t]
            else:
                operation.argtypes = ([ctypes.c_void_p, ctypes.c_size_t,
                                       ctypes.c_void_p, ctypes.c_size_t] if xof else
                                      [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t])

    def digest(self, algorithm: str, message: bytes, output_bits: int, key: bytes = b"") -> str:
        """Return upper-case hex, with byte-aligned lengths strictly enforced."""
        method, digest_size, xof = ALGORITHMS[algorithm]
        if xof:
            if output_bits <= 0 or output_bits % 8:
                raise ValueError("Unsupported SHAKE output bit length")
            digest_size = output_bits // 8
        elif digest_size * 8 != output_bits:
            raise ValueError("SHA digest size mismatch")
        output = ctypes.create_string_buffer(digest_size)
        message_buffer = ctypes.create_string_buffer(message)
        method_ref = getattr(self._dll, method)
        if method.startswith("qsc_hmac"):
            method_ref(output, message_buffer, len(message), ctypes.create_string_buffer(key), len(key))
        elif xof:
            method_ref(output, digest_size, message_buffer, len(message))
        else:
            method_ref(output, message_buffer, len(message))
        return output.raw.hex().upper()



def mct_digests(algorithm: str, seed: bytes, version: str, qsc: QSC) -> list[dict]:
    """Execute NIST SHA-2/SHA-3 Monte Carlo tests on QSC, 100 by 1000 rounds."""
    if algorithm not in ("SHA2-256", "SHA2-384", "SHA2-512", "SHA3-256", "SHA3-512"):
        raise ValueError("MCT is not implemented for this algorithm")
    if version not in ("standard", "alternate"):
        raise ValueError("Unsupported MCT version")
    digest_bits = ALGORITHMS[algorithm][1] * 8
    if not seed or len(seed) > 8192:
        raise ValueError("Unsupported MCT seed length")
    initial_length = len(seed)
    answer = []
    for _ in range(100):
        if algorithm.startswith("SHA2-"):
            first = second = third = seed
            for _ in range(1000):
                message = first + second + third
                if version == "alternate":
                    message = message[:initial_length].ljust(initial_length, b"\x00")
                output = bytes.fromhex(qsc.digest(algorithm, message, digest_bits))
                first, second, third = second, third, output
        else:
            output = seed
            for _ in range(1000):
                message = output
                if version == "alternate":
                    message = message[:initial_length].ljust(initial_length, b"\x00")
                output = bytes.fromhex(qsc.digest(algorithm, message, digest_bits))
        answer.append({"md": output.hex().upper()})
        seed = output
    return answer

def build_response(envelope: list, qsc: QSC) -> list:
    """Convert a supported ACVP AFT/VOT request to a response, rejecting gaps."""
    if (not isinstance(envelope, list) or len(envelope) != 2 or
            not isinstance(envelope[0], dict) or envelope[0].get("acvVersion") != "1.0" or
            not isinstance(envelope[1], dict)):
        raise ValueError("Unsupported ACVP envelope")
    body = envelope[1]
    algorithm = body.get("algorithm")
    if algorithm == "KDA":
        kdf = getattr(qsc, "kdf", None)
        if kdf is None:
            raise ValueError("KDA-HKDF requires a QSC KDF library")
        return kda_hkdf_response(envelope, kdf)
    if algorithm == "PBKDF":
        kdf = getattr(qsc, "kdf", None)
        if kdf is None:
            raise ValueError("PBKDF requires a QSC KDF library")
        return pbkdf_response(envelope, kdf)
    if algorithm in XOF_ALGORITHMS:
        xof = getattr(qsc, "xof", None)
        if xof is None:
            raise ValueError("cSHAKE/KMAC requires a QSC SHA3 library")
        return build_xof_response(envelope, xof)
    if algorithm == "KAS-ECC-SSC":
        ecc = getattr(qsc, "ecc", None)
        if ecc is None:
            raise ValueError("KAS-ECC-SSC requires a QSC ECC library")
        return build_kas_response(envelope, ecc)
    if algorithm in ("ECDSA", "DetECDSA", "EDDSA", "XECDH"):
        ecc = getattr(qsc, "ecc", None)
        if ecc is None:
            raise ValueError("ECC library was not configured")
        return build_ecc_response(envelope, ecc)
    if algorithm == "SLH-DSA":
        slh = getattr(qsc, "slh", None)
        if slh is None:
            raise ValueError("SLH-DSA library was not configured")
        return build_slhdsa_response(envelope, slh)
    if algorithm == "ML-DSA":
        dsa = getattr(qsc, "dsa", None)
        if dsa is None:
            raise ValueError("ML-DSA library was not configured")
        return build_mldsa_response(envelope, dsa)
    if algorithm == "ML-KEM":
        kem = getattr(qsc, "kem", None)
        if kem is None:
            raise ValueError("ML-KEM library was not configured")
        return build_mlkem_response(envelope, kem)
    if algorithm in (AES_GCM, AES_ECB, AES_CBC, AES_CTR):
        aes = getattr(qsc, 'aes', None)
        if aes is None:
            raise ValueError('AES library was not configured')
        if algorithm == AES_GCM:
            return build_aes_response(envelope, aes)
        if algorithm == AES_ECB:
            return build_ecb_response(envelope, aes)
        if algorithm == AES_CBC:
            return build_cbc_response(envelope, aes)
        return build_ctr_response(envelope, aes)
    if algorithm not in ALGORITHMS:
        raise ValueError(f"Unsupported ACVP algorithm: {algorithm}")
    if type(body.get("vsId")) is not int or not isinstance(body.get("testGroups"), list):
        raise ValueError("Missing vector set identifier or groups")
    default_bits = ALGORITHMS[algorithm][1]
    groups = []
    for group in body["testGroups"]:
        if group.get("testType") not in ("AFT", "VOT", "MCT"):
            raise ValueError(f"Unsupported {algorithm} test type {group.get('testType')}")
        if type(group.get("tgId")) is not int or not isinstance(group.get("tests"), list):
            raise ValueError("Missing group identifier or cases")
        cases = []
        for item in group["tests"]:
            if type(item.get("tcId")) is not int or not isinstance(item.get("msg"), str):
                raise ValueError("Missing case identifier or message")
            bits = item.get("len", item.get("msgLen", group.get("msgLen")))
            if type(bits) is not int or bits < 0 or bits % 8:
                raise ValueError("QSC adapter only accepts byte-aligned messages")
            encoded = bytes.fromhex(item["msg"])
            count = bits // 8
            if len(encoded) < count:
                raise ValueError("Message buffer shorter than requested bit length")
            if any(encoded[count:]):
                raise ValueError("Nonzero bytes beyond requested message length")
            message = encoded[:count]
            if group.get("testType") == "MCT":
                if bits == 0:
                    raise ValueError("MCT requires a nonempty seed")
                cases.append({"tcId": item["tcId"], "resultsArray": mct_digests(
                    algorithm, message, group.get("mctVersion", "standard"), qsc)})
                continue
            key = b""
            if algorithm.startswith("HMAC-"):
                if not isinstance(item.get("key"), str):
                    raise ValueError("Missing HMAC key")
                key = bytes.fromhex(item["key"])
                key_bits = item.get("keyLen", group.get("keyLen", len(key) * 8))
                if type(key_bits) is not int or key_bits != len(key) * 8:
                    raise ValueError("HMAC key length does not match key bytes")
            output_bits = item.get("outLen", item.get("macLen", group.get("macLen", default_bits * 8 if default_bits is not None else None)))
            if (type(output_bits) is not int or output_bits <= 0 or
                    output_bits % 8 or (default_bits is not None and output_bits > default_bits * 8)):
                raise ValueError("Unsupported digest/MAC output length")
            if output_bits > 65536:
                raise ValueError("Output length exceeds offline qualification limit")
            # For fixed-length hashes, a shorter digest is not a supported SHA operation.
            if not algorithm.startswith(("HMAC-", "SHAKE-")) and output_bits != default_bits * 8:
                raise ValueError("Fixed hash length does not match algorithm")
            value = qsc.digest(algorithm, message, default_bits * 8 if algorithm.startswith("HMAC-") else output_bits, key)
            if algorithm.startswith("HMAC-"):
                value = value[:output_bits // 4]
            cases.append({"tcId": item["tcId"], "mac" if algorithm.startswith("HMAC-") else "md": value})
        groups.append({"tgId": group["tgId"], "tests": cases})
    return [{"acvVersion": "1.0"}, {"vsId": body["vsId"], "testGroups": groups}]


def execute(url: str, qsc: QSC) -> list[dict]:
    """Fetch and submit each locally generated vector set in fixed order."""
    result = []
    from urllib.parse import urlsplit
    endpoint = urlsplit(url)
    if endpoint.scheme != "http" or endpoint.hostname != "127.0.0.1":
        raise ValueError("Local simulator client accepts only IPv4 loopback HTTP")
    for ident in range(1, len(ALGORITHMS) + 1):
        address = f"{url}/acvp/v1/testSessions/1/vectorSets/{ident}"
        with urlopen(address, timeout=15) as response:
            envelope = json.load(response)
        results = build_response(envelope, qsc)
        request = Request(address + "/results", data=json.dumps(results).encode("utf-8"),
                          headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(request, timeout=15) as response:
            verdict = json.load(response)
        result.append({"algorithm": envelope[1]["algorithm"], **verdict})
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--aes-library", type=Path)
    parser.add_argument("--url", default="http://127.0.0.1:8717")
    parser.add_argument("--vectors", type=Path, help="Offline ACVP vector-set input JSON")
    parser.add_argument("--response", type=Path, help="Required output file for offline response")
    args = parser.parse_args()
    qsc = QSC(args.library)
    if args.aes_library is not None:
        from aes_client import QscAes
        qsc.aes = QscAes(args.aes_library)
    if args.vectors is not None:
        root = Path(__file__).resolve().parents[2]
        if args.response is None or args.response.resolve().is_relative_to(root):
            parser.error("Offline response must be written outside the repository")
        response = build_response(json.loads(args.vectors.read_text(encoding="utf-8")), qsc)
        args.response.parent.mkdir(parents=True, exist_ok=True)
        args.response.write_text(json.dumps(response, indent=2) + "\n", encoding="utf-8")
        print(f"ACVP response generated; NOT submitted or NIST-validated: {args.response}")
        return 0
    report = execute(args.url, qsc)
    print(json.dumps(report, indent=2))
    return 0 if all(x.get("passed") for x in report) else 1


if __name__ == "__main__":
    raise SystemExit(main())
