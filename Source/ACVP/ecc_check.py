#!/usr/bin/env python3
"""Independent ECC cross-implementation qualification against cryptography.

Offline evidence only: NOT NIST ACVP test vectors or a NIST validation verdict.
ECDSA P-384 remains a mandatory complete-suite target; preliminary runs may flag it PENDING.
The oracle is not linked into QSC and is only a qualification-tool dependency.
"""

import argparse
import ctypes as c
import datetime as dt
import json
from pathlib import Path
import subprocess
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, x25519, x448
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

ROOT = Path(__file__).resolve().parents[2]
OPERATIONS = (
    "ECDH-P256", "ECDH-P384", "ECDH-P521",
    "ECDSA-P256", "ECDSA-P384", "ECDSA-P521",
    "X25519", "X448", "Ed25519", "Ed448",
)
CURVES = {
    "P256": (ec.SECP256R1(), 32, hashes.SHA256()),
    "P384": (ec.SECP384R1(), 48, hashes.SHA384()),
    "P521": (ec.SECP521R1(), 66, hashes.SHA512()),
}


def buffer(data: bytes) -> c.Array:
    """Return mutable caller-owned memory suitable for QSC's pointer ABI."""
    return c.create_string_buffer(bytes(data), max(1, len(data)))


def bind(lib: c.CDLL, name: str, return_type: object, signature: list) -> object:
    """Bind one explicitly named QSC API using its documented calling convention."""
    operation = getattr(lib, name)
    operation.argtypes = signature
    operation.restype = return_type
    return operation


def test_ecdh(lib: c.CDLL, curve_name: str) -> int:
    """Check public derivation, two exchange directions and invalid peer rejection."""
    curve, key_bytes, _ = CURVES[curve_name]
    prefix = "qsc_p" + curve_name[1:].lower()
    derive = bind(lib, prefix + "_public_from_private", None, [c.c_void_p, c.c_void_p])
    exchange = bind(lib, prefix + "_key_exchange", c.c_bool,
                    [c.c_void_p, c.c_void_p, c.c_void_p])
    cases = 0
    for a, b in ((3, 7), (1234567, 7654321)):
        private_a = a.to_bytes(key_bytes, "big")
        private_b = b.to_bytes(key_bytes, "big")
        ref_a = ec.derive_private_key(a, curve)
        ref_b = ec.derive_private_key(b, curve)
        public_a = ref_a.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:]
        public_b = ref_b.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:]
        output_a = c.create_string_buffer(2 * key_bytes)
        derive(output_a, buffer(private_a))
        if output_a.raw != public_a:
            raise AssertionError(f"{curve_name} public derivation mismatch")
        cases += 1
        output_b = c.create_string_buffer(2 * key_bytes)
        derive(output_b, buffer(private_b))
        if output_b.raw != public_b:
            raise AssertionError(f"{curve_name} peer derivation mismatch")
        cases += 1
        for local_private, peer_public, reference_private, reference_peer in (
            (private_a, public_b, ref_a, ref_b),
            (private_b, public_a, ref_b, ref_a),
        ):
            secret = c.create_string_buffer(key_bytes)
            passed = exchange(secret, buffer(peer_public), buffer(local_private))
            expected = reference_private.exchange(ec.ECDH(), reference_peer.public_key())
            if not passed or secret.raw != expected:
                raise AssertionError(f"{curve_name} shared secret mismatch")
            cases += 1
        secret = c.create_string_buffer(key_bytes)
        if exchange(secret, buffer(bytes(2 * key_bytes)), buffer(private_a)):
            raise AssertionError(f"{curve_name} invalid peer accepted")
        cases += 1
    return cases


def test_ecdsa(lib: c.CDLL, curve_name: str) -> int:
    """Cross-check RFC6979 signer and verification with an independent EC library."""
    curve, key_bytes, digest = CURVES[curve_name]
    prefix = "qsc_p" + curve_name[1:].lower()
    derive = bind(lib, prefix + "_publickey_from_privatekey", c.c_int32,
                  [c.c_void_p, c.c_void_p])
    sign = bind(lib, prefix + "_sign_scalar", c.c_int32,
                [c.c_void_p, c.POINTER(c.c_size_t), c.c_void_p, c.c_size_t, c.c_void_p])
    verify = bind(lib, prefix + "_verify", c.c_bool,
                  [c.c_void_p, c.POINTER(c.c_size_t), c.c_void_p, c.c_size_t, c.c_void_p])
    cases = 0
    for scalar in (3, 1729):
        key = scalar.to_bytes(key_bytes, "big")
        reference = ec.derive_private_key(scalar, curve)
        expected_public = reference.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:]
        actual_public = c.create_string_buffer(2 * key_bytes)
        if derive(actual_public, buffer(key)) != 0 or actual_public.raw != expected_public:
            raise AssertionError(f"{curve_name} ECDSA public key mismatch")
        cases += 1
        message = b"QSC offline ECC independent interoperability check" + bytes([scalar & 255])
        smsg = c.create_string_buffer(2 * key_bytes + len(message))
        smsg_length = c.c_size_t(0)
        result = sign(smsg, c.byref(smsg_length), buffer(message), len(message), buffer(key))
        if result != 0 or smsg_length.value != len(smsg.raw):
            raise AssertionError(f"{curve_name} ECDSA signing returned {result}")
        raw = smsg.raw[:2 * key_bytes]
        r = int.from_bytes(raw[:key_bytes], "big")
        s = int.from_bytes(raw[key_bytes:], "big")
        reference.public_key().verify(encode_dss_signature(r, s), message, ec.ECDSA(digest))
        cases += 1
        recovered = c.create_string_buffer(len(message))
        recovered_length = c.c_size_t(0)
        if not verify(recovered, c.byref(recovered_length), smsg, len(smsg.raw), actual_public):
            raise AssertionError(f"{curve_name} ECDSA self verification rejected")
        if recovered_length.value != len(message) or recovered.raw != message:
            raise AssertionError(f"{curve_name} ECDSA recovered message mismatch")
        cases += 1
        independent_der = reference.sign(message, ec.ECDSA(digest))
        ir, ins = decode_dss_signature(independent_der)
        independent_raw = (ir.to_bytes(key_bytes, "big") +
                           ins.to_bytes(key_bytes, "big") + message)
        recovered_length = c.c_size_t(0)
        if not verify(recovered, c.byref(recovered_length), buffer(independent_raw),
                      len(independent_raw), actual_public):
            raise AssertionError(f"{curve_name} ECDSA independent signature rejected")
        cases += 1
        tampered = bytearray(smsg.raw)
        tampered[0] ^= 1
        recovered_length = c.c_size_t(0)
        if verify(recovered, c.byref(recovered_length), buffer(tampered),
                  len(tampered), actual_public):
            raise AssertionError(f"{curve_name} ECDSA tampered signature accepted")
        cases += 1
    return cases


def test_xdh(lib: c.CDLL, kind: str) -> int:
    """Verify X25519/X448 public generation and both shared-secret directions."""
    key_bytes = 32 if kind == "X25519" else 56
    reference_type = x25519.X25519PrivateKey if kind == "X25519" else x448.X448PrivateKey
    prefix = "qsc_" + kind.lower()
    derive = bind(lib, prefix + "_public_from_private", None, [c.c_void_p, c.c_void_p])
    exchange = bind(lib, prefix + "_key_exchange", c.c_bool,
                    [c.c_void_p, c.c_void_p, c.c_void_p])
    cases = 0
    for offset in (1, 2):
        a = bytes(((i * 7 + offset * 11) & 255) for i in range(key_bytes))
        b = bytes(((i * 13 + offset * 19) & 255) for i in range(key_bytes))
        ref_a = reference_type.from_private_bytes(a)
        ref_b = reference_type.from_private_bytes(b)
        public_a = ref_a.public_key().public_bytes(serialization.Encoding.Raw,
                                                    serialization.PublicFormat.Raw)
        public_b = ref_b.public_key().public_bytes(serialization.Encoding.Raw,
                                                    serialization.PublicFormat.Raw)
        for private, expected_public in ((a, public_a), (b, public_b)):
            actual = c.create_string_buffer(key_bytes)
            derive(actual, buffer(private))
            if actual.raw != expected_public:
                raise AssertionError(f"{kind} public derivation mismatch")
            cases += 1
        for private, peer, expected in ((a, public_b, ref_a.exchange(ref_b.public_key())),
                                        (b, public_a, ref_b.exchange(ref_a.public_key()))):
            secret = c.create_string_buffer(key_bytes)
            if not exchange(secret, buffer(peer), buffer(private)) or secret.raw != expected:
                raise AssertionError(f"{kind} shared-secret mismatch")
            cases += 1
    return cases


def test_eddsa(lib: c.CDLL, kind: str) -> int:
    """Verify EdDSA key generation, QSC signature and independent signature."""
    key_bytes = 32 if kind == "Ed25519" else 57
    sig_bytes = 64 if kind == "Ed25519" else 114
    reference_type = ed25519.Ed25519PrivateKey if kind == "Ed25519" else ed448.Ed448PrivateKey
    prefix = "qsc_" + kind.lower()
    gen = bind(lib, prefix + "_generate_seeded_keypair", None,
               [c.c_void_p, c.c_void_p, c.c_void_p])
    sign = bind(lib, prefix + "_sign", c.c_bool,
                [c.c_void_p, c.POINTER(c.c_size_t), c.c_void_p, c.c_size_t, c.c_void_p])
    verify = bind(lib, prefix + "_verify", c.c_bool,
                  [c.c_void_p, c.POINTER(c.c_size_t), c.c_void_p, c.c_size_t, c.c_void_p])
    cases = 0
    for offset in (1, 2):
        seed = bytes((i * 9 + offset) & 255 for i in range(key_bytes))
        reference = reference_type.from_private_bytes(seed)
        expected_public = reference.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        public = c.create_string_buffer(key_bytes)
        secret = c.create_string_buffer(key_bytes * 2)
        gen(public, secret, buffer(seed))
        if public.raw != expected_public:
            raise AssertionError(f"{kind} public derivation mismatch")
        cases += 1
        message = b"QSC EdDSA interoperability vector" + bytes([offset])
        signed = c.create_string_buffer(sig_bytes + len(message))
        signed_length = c.c_size_t(0)
        if not sign(signed, c.byref(signed_length), buffer(message), len(message), secret):
            raise AssertionError(f"{kind} signature-generation failure")
        if signed_length.value != len(signed.raw):
            raise AssertionError(f"{kind} signature-output length mismatch")
        reference.public_key().verify(signed.raw[:sig_bytes], message)
        cases += 1
        output = c.create_string_buffer(len(message))
        output_length = c.c_size_t(0)
        if not verify(output, c.byref(output_length), signed, len(signed.raw), public):
            raise AssertionError(f"{kind} self signature rejected")
        cases += 1
        independent_signed = reference.sign(message) + message
        output_length = c.c_size_t(0)
        if not verify(output, c.byref(output_length), buffer(independent_signed),
                      len(independent_signed), public):
            raise AssertionError(f"{kind} independent signature rejected")
        cases += 1
        tampered = bytearray(signed.raw)
        tampered[0] ^= 1
        output_length = c.c_size_t(0)
        if verify(output, c.byref(output_length), buffer(tampered), len(tampered), public):
            raise AssertionError(f"{kind} corrupted signature accepted")
        cases += 1
    return cases


def execute_one(library: Path, algorithm: str) -> int:
    """Run a single test family in an isolated process to contain native faults."""
    lib = c.CDLL(str(library.resolve()))
    if algorithm == "ECDH-P256":
        return test_ecdh(lib, "P256")
    if algorithm == "ECDH-P384":
        return test_ecdh(lib, "P384")
    if algorithm == "ECDH-P521":
        return test_ecdh(lib, "P521")
    if algorithm == "ECDSA-P256":
        return test_ecdsa(lib, "P256")
    if algorithm == "ECDSA-P384":
        return test_ecdsa(lib, "P384")
    if algorithm == "ECDSA-P521":
        return test_ecdsa(lib, "P521")
    if algorithm == "X25519":
        return test_xdh(lib, "X25519")
    if algorithm == "X448":
        return test_xdh(lib, "X448")
    if algorithm == "Ed25519":
        return test_eddsa(lib, "Ed25519")
    if algorithm == "Ed448":
        return test_eddsa(lib, "Ed448")
    raise ValueError("Unsupported ECC operation")


def main() -> int:
    """Run each named test directly and produce fail-closed evidence outside source."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--single", choices=OPERATIONS)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    if not args.library.is_file():
        parser.error("Built ECC shared library not found")
    if args.single:
        try:
            count = execute_one(args.library, args.single)
            print(json.dumps({"algorithm": args.single, "status": "PASS", "cases": count}))
            return 0
        except Exception as exc:
            print(json.dumps({"algorithm": args.single, "status": "FAIL", "cases": 0,
                              "diagnostic": f"{type(exc).__name__}: {exc}"}))
            return 1
    if args.output is None or args.output.resolve().is_relative_to(ROOT):
        parser.error("Provide an evidence directory outside the repository")
    args.output.mkdir(parents=True, exist_ok=True)
    records = []
    available = c.CDLL(str(args.library.resolve()))

    def run_named(name: str) -> None:
        """Run one named native test in an independent process."""
        command = [sys.executable, str(Path(__file__).resolve()),
                   "--library", str(args.library), "--single", name]
        try:
            run = subprocess.run(command, capture_output=True, text=True,
                                 timeout=args.timeout, check=False)
            record = json.loads(run.stdout.strip())
            if run.returncode != 0 or record.get("status") != "PASS":
                record["status"] = "FAIL"
                record.setdefault("diagnostic", run.stderr.strip() or f"exit={run.returncode}")
        except (subprocess.TimeoutExpired, ValueError, OSError) as exc:
            record = {"algorithm": name, "status": "FAIL", "cases": 0,
                      "diagnostic": f"{type(exc).__name__}: {exc}"}
        records.append(record)
        print(f"[{record['status']}] {name}: {record.get('cases', 0)} checks", flush=True)

    run_named("ECDH-P256")
    run_named("ECDH-P384")
    run_named("ECDH-P521")
    run_named("ECDSA-P256")
    if hasattr(available, "qsc_p384_sign_scalar"):
        run_named("ECDSA-P384")
    else:
        records.append({"algorithm": "ECDSA-P384", "status": "PENDING_SOURCE_UPDATE",
                        "cases": 0, "diagnostic": "Required P-384 signer not present in preliminary library"})
    run_named("ECDSA-P521")
    run_named("X25519")
    run_named("X448")
    run_named("Ed25519")
    run_named("Ed448")
    data = {
        "type": "OFFLINE_ECC_CROSS_IMPLEMENTATION_NOT_ACVTS",
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "oracle": "cryptography library",
        "algorithms": records,
        "not_run": (["ECDSA-P384 (source in active development)"] if not hasattr(available, "qsc_p384_sign_scalar") else []) +
                   ["NIST server ACVP vectors"],
        "status": ("PASS_WITH_COVERAGE_GAPS" if all(r["status"] == "PASS" for r in records)
                   else "PENDING_SOURCE_UPDATE" if all(r["status"] in ("PASS", "PENDING_SOURCE_UPDATE") for r in records)
                   else "FAIL"),
    }
    (args.output / "ecc-results.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    (args.output / "ecc-report.md").write_text(
        "# QSC offline ECC independent verification\n\n"
        "Not a NIST ACVP validation. ECDSA P-384 is tested only when built.\n\n" +
        "\n".join(f"- {r['algorithm']}: {r['status']} ({r.get('cases', 0)} checks) "
                  f"{r.get('diagnostic', '')}" for r in records) +
        f"\n\nOverall: {data['status']}\n", encoding="utf-8")
    return 0 if data["status"] in ("PASS_WITH_COVERAGE_GAPS", "PENDING_SOURCE_UPDATE") else 1


if __name__ == "__main__":
    sys.exit(main())
