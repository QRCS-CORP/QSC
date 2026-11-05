#!/usr/bin/env python3
"""Dedicated QSC FIPS 203/204/205 API smoke tests, not ACVP validation.

The deterministic inputs below test round trips and negative cases only.
They do not replace official NIST test vectors or independent KATs.
"""

import argparse
import ctypes as c
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
ALGORITHMS = (
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
    "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
    "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f",
)
KEM_SIZES = {512: (800, 1632, 768), 768: (1184, 2400, 1088),
             1024: (1568, 3168, 1568)}
MLDSA_SIZES = {44: (1312, 2560, 2420), 65: (1952, 4032, 3309),
               87: (2592, 4896, 4627)}
SLH_SIZES = {"128s": (32, 64, 7856, 48), "128f": (32, 64, 17088, 48),
             "192s": (48, 96, 16224, 72), "192f": (48, 96, 35664, 72),
             "256s": (64, 128, 29792, 96), "256f": (64, 128, 49856, 96)}


def buf(data: bytes) -> c.Array:
    """Allocate caller-owned mutable storage with the expected QSC pointer lifetime."""
    return c.create_string_buffer(bytes(data), max(1, len(data)))


def bind(library: c.CDLL, name: str, result: object, signature: list) -> object:
    """Bind exactly one exported QSC function with explicit ABI types."""
    method = getattr(library, name)
    method.argtypes = signature
    method.restype = result
    return method


def check_kem(library: c.CDLL, level: int) -> int:
    """Check deterministic KEM key generation, encapsulation, decapsulation, tamper."""
    public_size, private_size, ciphertext_size = KEM_SIZES[level]
    prefix = f"qsc_kyber{level}_"
    generate = bind(library, prefix + "generate_seeded_keypair", None,
                    [c.c_void_p, c.c_void_p, c.c_void_p, c.c_void_p])
    encapsulate = bind(library, prefix + "seeded_encapsulate", None,
                       [c.c_void_p, c.c_void_p, c.c_void_p, c.c_void_p])
    decapsulate = bind(library, prefix + "decapsulate", c.c_bool,
                       [c.c_void_p, c.c_void_p, c.c_void_p])
    checks = 0
    for offset in (1, 2):
        seed_d = buf(bytes((x + offset) & 255 for x in range(32)))
        seed_z = buf(bytes((x * 3 + offset) & 255 for x in range(32)))
        public = c.create_string_buffer(public_size)
        secret = c.create_string_buffer(private_size)
        generate(public, secret, seed_d, seed_z)
        if public.raw == bytes(public_size) or secret.raw == bytes(private_size):
            raise AssertionError("ML-KEM key generation returned an empty key")
        checks += 1
        randomizer = buf(bytes((x * 11 + offset) & 255 for x in range(32)))
        ct = c.create_string_buffer(ciphertext_size)
        sender = c.create_string_buffer(32)
        receiver = c.create_string_buffer(32)
        encapsulate(sender, ct, public, randomizer)
        if not decapsulate(receiver, ct, secret) or sender.raw != receiver.raw:
            raise AssertionError("ML-KEM encapsulation/decapsulation disagreement")
        checks += 1
        corrupted = bytearray(ct.raw)
        corrupted[0] ^= 0x80
        rejected = c.create_string_buffer(32)
        decapsulate(rejected, buf(corrupted), secret)
        if rejected.raw == sender.raw:
            raise AssertionError("ML-KEM corrupted ciphertext reproduced valid secret")
        checks += 1
    return checks


def random_bytes(output: int, count: int) -> bool:
    """Supply true OS entropy to a test-only RNG callback; no state is retained."""
    c.memmove(output, os.urandom(count), count)
    return True


RNG = c.CFUNCTYPE(c.c_bool, c.c_void_p, c.c_size_t)


def check_mldsa(library: c.CDLL, level: int) -> int:
    """Check attached signatures, message recovery and corruption rejection."""
    public_size, private_size, signature_size = MLDSA_SIZES[level]
    prefix = f"qsc_mldsa{level}_"
    generate = bind(library, prefix + "seeded_generate_keypair", None,
                    [c.c_void_p, c.c_void_p, c.c_void_p])
    sign = bind(library, prefix + "sign", c.c_bool,
                [c.c_void_p, c.POINTER(c.c_size_t), c.c_void_p,
                 c.c_size_t, c.c_void_p, RNG])
    verify = bind(library, prefix + "verify", c.c_bool,
                  [c.c_void_p, c.POINTER(c.c_size_t), c.c_void_p,
                   c.c_size_t, c.c_void_p])
    entropy = RNG(random_bytes)
    seed = buf(bytes(range(32)))
    public = c.create_string_buffer(public_size)
    private = c.create_string_buffer(private_size)
    generate(public, private, seed)
    if public.raw == bytes(public_size):
        raise AssertionError("ML-DSA key generation returned an empty public key")
    checks = 1
    for message in (b"QSC FIPS 204 API smoke", b"QSC second message"):
        sm = c.create_string_buffer(signature_size + len(message))
        length = c.c_size_t(0)
        if not sign(sm, c.byref(length), buf(message), len(message), private, entropy):
            raise AssertionError("ML-DSA signing failed")
        if length.value != len(sm.raw):
            raise AssertionError("ML-DSA signature length mismatch")
        checks += 1
        recovered = c.create_string_buffer(len(message))
        recovered_length = c.c_size_t(0)
        if not verify(recovered, c.byref(recovered_length), sm, length.value, public):
            raise AssertionError("ML-DSA signed message rejected")
        if recovered_length.value != len(message) or recovered.raw != message:
            raise AssertionError("ML-DSA message recovery incorrect")
        checks += 1
        modified = bytearray(sm.raw)
        modified[0] ^= 0x01
        recovered_length = c.c_size_t(0)
        if verify(recovered, c.byref(recovered_length), buf(modified), len(modified), public):
            raise AssertionError("ML-DSA corrupted signature accepted")
        checks += 1
    return checks


def check_slhdsa(library: c.CDLL, parameter: str) -> int:
    """Exercise deterministic FIPS 205 signatures and negative verification."""
    public_size, private_size, sig_size, seed_size = SLH_SIZES[parameter]
    prefix = "qsc_slhdsa_shake" + parameter + "_"
    generate = bind(library, prefix + "generate_seeded_keypair", c.c_bool,
                    [c.c_void_p, c.c_void_p, c.c_void_p])
    sign = bind(library, prefix + "sign_deterministic", c.c_bool,
                [c.c_void_p, c.POINTER(c.c_size_t), c.c_void_p,
                 c.c_size_t, c.c_void_p, c.c_size_t, c.c_void_p])
    verify = bind(library, prefix + "verify", c.c_bool,
                  [c.c_void_p, c.c_size_t, c.c_void_p,
                   c.c_size_t, c.c_void_p, c.c_size_t, c.c_void_p])
    seed = buf(bytes(x & 255 for x in range(seed_size)))
    public = c.create_string_buffer(public_size)
    private = c.create_string_buffer(private_size)
    if not generate(public, private, seed):
        raise AssertionError("SLH-DSA key generation failed")
    checks = 1
    message = b"QSC FIPS 205 API smoke"
    context = b"QSC"
    signature = c.create_string_buffer(sig_size)
    sig_length = c.c_size_t(0)
    if not sign(signature, c.byref(sig_length), buf(message), len(message),
                buf(context), len(context), private):
        raise AssertionError("SLH-DSA signing failed")
    if sig_length.value != sig_size:
        raise AssertionError("SLH-DSA signature length mismatch")
    checks += 1
    if not verify(signature, sig_size, buf(message), len(message),
                  buf(context), len(context), public):
        raise AssertionError("SLH-DSA signature rejected")
    checks += 1
    tampered = bytearray(signature.raw)
    tampered[0] ^= 0x01
    if verify(buf(tampered), sig_size, buf(message), len(message),
              buf(context), len(context), public):
        raise AssertionError("SLH-DSA corrupted signature accepted")
    checks += 1
    if verify(signature, sig_size, buf(message), len(message),
              buf(b"BAD"), 3, public):
        raise AssertionError("SLH-DSA invalid context accepted")
    checks += 1
    return checks


def execute_one(library: Path, algorithm: str) -> int:
    """Dispatch a single named FIPS 203/204/205 API test family."""
    dll = c.CDLL(str(library.resolve()))
    if algorithm == "ML-KEM-512":
        return check_kem(dll, 512)
    if algorithm == "ML-KEM-768":
        return check_kem(dll, 768)
    if algorithm == "ML-KEM-1024":
        return check_kem(dll, 1024)
    if algorithm == "ML-DSA-44":
        return check_mldsa(dll, 44)
    if algorithm == "ML-DSA-65":
        return check_mldsa(dll, 65)
    if algorithm == "ML-DSA-87":
        return check_mldsa(dll, 87)
    if algorithm == "SLH-DSA-SHAKE-128s":
        return check_slhdsa(dll, "128s")
    if algorithm == "SLH-DSA-SHAKE-128f":
        return check_slhdsa(dll, "128f")
    if algorithm == "SLH-DSA-SHAKE-192s":
        return check_slhdsa(dll, "192s")
    if algorithm == "SLH-DSA-SHAKE-192f":
        return check_slhdsa(dll, "192f")
    if algorithm == "SLH-DSA-SHAKE-256s":
        return check_slhdsa(dll, "256s")
    if algorithm == "SLH-DSA-SHAKE-256f":
        return check_slhdsa(dll, "256f")
    raise ValueError("Unknown QSC post-quantum test")


def main() -> int:
    """Process test families individually and write consolidated smoke evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--single", choices=ALGORITHMS)
    parser.add_argument("--timeout", type=int, default=240)
    args = parser.parse_args()
    if not args.library.is_file():
        parser.error("Missing dedicated QSC PQ library")
    if args.single:
        try:
            count = execute_one(args.library, args.single)
            print(json.dumps({"algorithm": args.single, "status": "PASS", "checks": count}))
            return 0
        except Exception as exc:
            print(json.dumps({"algorithm": args.single, "status": "FAIL", "checks": 0,
                              "diagnostic": f"{type(exc).__name__}: {exc}"}))
            return 1
    if args.output is None or args.output.resolve().is_relative_to(ROOT):
        parser.error("Qualification output must be outside source directory")
    args.output.mkdir(parents=True, exist_ok=True)
    records = []

    def run_named(name: str) -> None:
        """Execute one named API family in its own process and record its result."""
        command = [sys.executable, str(Path(__file__).resolve()),
                   "--single", name, "--library", str(args.library)]
        try:
            run = subprocess.run(command, capture_output=True, text=True,
                                 timeout=args.timeout, check=False)
            record = json.loads(run.stdout.strip())
            if run.returncode != 0 or record.get("status") != "PASS":
                record["status"] = "FAIL"
                record.setdefault("diagnostic", run.stderr.strip() or f"exit={run.returncode}")
        except (subprocess.TimeoutExpired, ValueError, OSError) as exc:
            record = {"algorithm": name, "status": "FAIL", "checks": 0,
                      "diagnostic": f"{type(exc).__name__}: {exc}"}
        records.append(record)
        print(f"[{record['status']}] {name}: {record.get('checks', 0)} checks", flush=True)

    run_named("ML-KEM-512")
    run_named("ML-KEM-768")
    run_named("ML-KEM-1024")
    run_named("ML-DSA-44")
    run_named("ML-DSA-65")
    run_named("ML-DSA-87")
    run_named("SLH-DSA-SHAKE-128s")
    run_named("SLH-DSA-SHAKE-128f")
    run_named("SLH-DSA-SHAKE-192s")
    run_named("SLH-DSA-SHAKE-192f")
    run_named("SLH-DSA-SHAKE-256s")
    run_named("SLH-DSA-SHAKE-256f")
    data = {"type": "OFFLINE_PQ_SELF_CONSISTENCY_NOT_ACVTS",
            "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "algorithms": records,
            "status": "PASS_SMOKE_ONLY" if all(r["status"] == "PASS" for r in records) else "FAIL"}
    (args.output / "pq-results.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    (args.output / "pq-report.md").write_text(
        "# Dedicated post-quantum API smoke tests\n\nNot NIST vectors or an ACVP verdict.\n\n" +
        "\n".join(f"- {r['algorithm']}: {r['status']} ({r.get('checks', 0)} checks) "
                  f"{r.get('diagnostic', '')}" for r in records) +
        f"\n\nOverall: {data['status']}\n", encoding="utf-8")
    return 0 if data["status"] == "PASS_SMOKE_ONLY" else 1


if __name__ == "__main__":
    sys.exit(main())
