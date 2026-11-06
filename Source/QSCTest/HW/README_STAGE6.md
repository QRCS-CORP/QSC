# QSC HSM Stage 6 — Software-token interoperability and physical-device acceptance

## Status

- **Executed:** NSS PKCS#11 software token P-256 key generation, sensitive/nonextractable attributes, export refusal, real ECDSA signing, token-backed CSR, session persistence, TLS signature policy, and an independent OpenSSL 3.5.5 TLS 1.3 server handshake.
- **Not executed:** a physically secured HSM or smart-card device, vendor firmware/attestation verification, token unplug/reboot, PIN lockout, device congestion, or realistic physical-signing latency.
- **G6 status:** **OPEN / physical HSM unavailable.** No FIPS, hardware-custody, physical-security, or vendor certification claims are made.
- No existing QSC production sources or build configuration are modified.

## Source and build

These are independent Linux test assets, intentionally **not** linked into the main QSC or QSCTest targets. The test app owns `main(void)` behavior via `main(argc, argv)` and must not be registered in the ordinary QSCTest executable (which already has a main).

The test app requires `QSC_HARDWARE_ENABLED` and `QSC_HARDWARE_PKCS11_ENABLED`, an external PKCS#11 development header and an NSS `libsoftokn3.so` software-token module. The runner additionally requires `certutil`, OpenSSL, Python 3, GCC or Clang, pthread and `ar`. It builds the 160-file baseline cryptographic library and the Stage 1–5 PKCS#11 adapter sources from the local QSC checkout.

From a checkout with sibling directories `QSC/` and `QSCTest/`, run:

```bash
bash QSCTest/HW/qualify_stage6_nss.sh /tmp/qsc-stage6-results
CC=clang bash QSCTest/HW/qualify_stage6_nss.sh /tmp/qsc-stage6-clang-results
```

`QSC_STAGE6_NSS_MODULE` optionally selects a trusted absolute path to NSS `libsoftokn3.so`. `QSC_STAGE6_PORT` optionally selects a free loopback port. The script creates a disposable fresh NSS database and a disposable test CA. It never writes its private CA key or NSS key database into the evidence directory. Do not use this script against a real HSM: it deliberately generates persistent keys inside a disposable software database.

`QSC_STAGE6_KEEP_NSS_MAPPED` is for sanitizer diagnostics only. Some NSS allocations appear unreachable to LeakSanitizer if the shared library is unloaded before process exit; retaining its code mapping until exit preserves vendor globals for leak accounting. The standard non-sanitized test still closes all Cryptoki and dynamic-library references.

## Acceptance procedures requiring an actual HSM

1. Record vendor, device serial (redacted in public evidence), firmware, PKCS#11 module path, module SHA-256, OS and hardware security documentation. Verify code-signing/module integrity where supported.
2. Use a designated test partition/slot and expressly authorized test key only. Never initialize, reset, clear, overwrite, or lock production tokens. Confirm whether irreversible operations are permitted before testing key generation or deletion.
3. Enumerate slots and mechanisms. Confirm real ECDSA P-256 support, distinct error mapping, and accurate capability claims. Where nonexportability is required, check manufacturer backing in addition to `CKA_SENSITIVE`/`CKA_EXTRACTABLE`; attributes alone are not remote attestation.
4. Provision a test-only key, issue certificate/CSR, complete QSC TLS 1.3 server and client authentication against an independent OpenSSL peer with TLS certificate/hostname validation enabled, and verify no software fallback.
5. Reopen the same key by persistent identifier across session teardown, token reset and process restart. Reject a replacement device with conflicting identity and test duplicate key labels/IDs.
6. Test wrong PIN, token lockout, user-presence timeout, physical removal, reconnection, session exhaustion, concurrent signing, long-running operations, and configured cancellation behavior. Never automatically repeat incorrect PIN attempts.
7. Verify key-rotation rollback, old-key availability after a failed cutover, certificate/public-key mismatch refusal, and disconnection during CertificateVerify.
8. Record at least seven trials per workload, including p50/p95 token sign latency, TLS handshake latency and concurrent-session behavior with exact device and compiler flags.
9. Run Windows/MSVC and native ARM64 qualification separately when those deployment environments are supported. The included Linux NSS results do not establish either.

**Gate G6 requires physical-device evidence, and cannot be signed off from software-token or mock results.**
