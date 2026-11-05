> Adapter reference from the integrated v12 runner. For repository setup, use the root README.

# QSC offline ACVP qualification runner

This directory contains an **offline** CAVP runner and a separate, narrowly scoped
**authenticated NIST Demo sample client**. The offline runner never submits
vectors to NIST or produces an ACVTS verdict. Only `demo_client.py`, when
launched with NIST-issued credentials, communicates with the actual Demo server.
The official ACVTS Demo server is hosted by NIST. The qualification tools
include a loopback-only simulator and a limited offline vector-response adapter.

The runner builds the unchanged QSC sources, executes the six existing CAVP
suites in their original direct-call order, checks actual printed failure
markers (the legacy harness returns no reliable process status), and produces
`cavp.log`, `results.json`, `report.md`, and `report.html`. Each unimplemented
algorithm appears under **NOT RUN**. The legacy Kyber, Dilithium, and SPHINCS+
entry points are not equivalent to qualification of the new dedicated FIPS APIs.

## Local execution

From the repository root, with CMake, a C compiler, Python 3.10+, and Ninja:

```sh
cmake -S Source/ACVP -B /var/tmp/$USER/qsc-acvp-build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DQSC_ACVP_TLS_CLASS=3
cmake --build /var/tmp/$USER/qsc-acvp-build --parallel 4
python3 Source/ACVP/run.py \
  --binary /var/tmp/$USER/qsc-acvp-build/qsc_cavp \
  --security-class 3
```

On Windows, use Visual Studio 2022's x64 CMake generator and place the build
in `%TEMP%\qsc-acvp-build`; execute the Release binary from the build tree.
Generated reports default to `%TEMP%\qsc-acvp\offline` on Windows or
`/var/tmp/$USER/qsc-acvp/offline` on Linux. Do not put runtime results in the
repository. GitHub Actions stores evidence under the runner's temporary path.

The GitHub workflow runs security classes 1, 3, and 5 separately for Ubuntu and
Windows. Inside each job, local SHA/HMAC vector tests, ECC interoperability,
parameter-specific PQ smoke tests and the six existing CAVP suites run **consecutively**.
The ECC reference implementation uses test-only `cryptography==46.0.4`, never
linked into QSC.
Any missing suite, insufficient successful aggregate markers, failure text,
process error, or timeout makes the job fail. The report explicitly records all
coverage gaps, including elliptic-curve ACVP tests.

## P-384 source synchronization

The **complete** CAVP and ECC qualification targets include `dependency/QSC/Source/QSC/ecdsap384.c`
without exception. The October 29 archive is missing the P-384 generated table
`p384_fixed_w6_table.h`; the complete targets remain **PENDING_SOURCE_UPDATE**
until it is supplied. They are never marked passed or removed from the
qualification matrix. The independent preliminary ECC target can continue to
test ECDH P-384 and eight other ECC operations in the meantime. The CI
workflow builds preliminary targets first and automatically attempts the full
CAVP/ECC targets when the header arrives. A pending or failed full build makes
the overall CI qualification fail; it does not prevent collecting partial results.
No production P-384 implementation is changed.

## NIST ACVTS Demo sample-client integration

The separately protected `.github/workflows/qsc-acvp-demo.yml` is a manual-only,
Ubuntu-based sample qualification run against the actual NIST Demo endpoint
`https://demo.acvts.nist.gov`. This workflow uses the current QSC SHA library
and the `demo_client.py` driver for mutual TLS, TOTP login, sample registration,
sequential vector fetch, response submission, bounded retry handling, and a
sanitized server verdict. It does **not** perform production CAVP validation.

The default registrations include SHA2-256/384/512, SHA3-256/512,
SHAKE-128/256 (FIPS202 revision), HMAC-SHA2-256/384/512,
ACVP-AES-ECB and ACVP-AES-GCM. The adapter
implements byte-aligned AFT, SHAKE VOT and SHA2/SHA3 MCT. It rejects LDT,
bit-oriented messages, unsupported tests, and server-directed large-submission
handling. These are honest coverage limits; no unexecuted primitive is
advertised as validated.

NIST must first approve the client TLS identity and issue TOTP credentials.
Create a protected GitHub environment named `acvts-demo`, with required manual
approval, and add three **environment secrets**:

- `ACVP_DEMO_CERT_B64`: base64 of the authorized client certificate PEM file
- `ACVP_DEMO_KEY_B64`: base64 of the matching TLS private key PEM file
- `ACVP_DEMO_TOTP_SEED`: NIST-issued TOTP shared secret, base32 encoded

No secret may be committed to the repository. Credentials are materialized
only in the runner temporary directory, removed at job completion and excluded
from artifacts. Only the sanitized `demo-results.json` is uploaded. Access
must be limited to trusted branches and authorized repository maintainers.

Run the protected GitHub workflow manually once credentials have been issued.
The SHA-only Demo workflow builds `qsc_acvp_hash` independently, so the
in-progress P-384 signer cannot block transport validation. A passing Demo
sample session is **not** a CAVP validation certificate.

Dedicated PQ and ECC response adapters are now present. Remaining gaps
include randomized ECDSA signing, non-static-unified KAS-ECC, EdDSA contexts
and prehash, full XECDH validation prerequisites, KDFs and KMAC/cSHAKE.
Offline self-consistency/interoperability results are not server verdicts.

The offline workflow runs all six OS/class jobs consecutively (`max-parallel: 1`)
and attempts a consolidated summary even when a preceding job fails. Missing
artifacts are reported as incomplete. The local consolidator supports
`--local` for partial workstation reporting.

## Local ACVP-style simulator

`local_server.py` is an intentionally restricted **loopback-only test simulator**,
not a deployment of NIST's ACVTS Demo server. It generates 40 local
byte-aligned AFT vectors for SHA2-256/384/512, SHA3-256/512, SHAKE-128/256,
and HMAC-SHA2-256/384/512, and checks their responses. Independent digest and
MAC oracles use Python's `hashlib` and `hmac`. It does not implement registration, certificate/TOTP
security, official ACVP test-group variants or a formal ACVTS server verdict.

The CI workflow starts it automatically on localhost, executes every vector set
against QSC's compiled shared library, submits results, and stores the local
verdict under `local-sha-vectors.json`. The same job writes `ecc-results.json`
and `pq-results.json`, which are required by the fail-closed consolidator. You can also start the server manually:

```sh
python3 Source/ACVP/local_server.py --port 8717
# In a separate terminal:
python3 Source/ACVP/local_client.py \
  --library /var/tmp/$USER/qsc-acvp-build/libqsc_acvp_hash.so
```

## Offline ACVP vector-response replay

The local client can read supplied ACVP JSON vector files and emit standard response
JSON for **byte-aligned AFT** SHA-2, SHA-3 and HMAC, plus **AFT/VOT** SHAKE.
It rejects unsupported test categories (including LDT and SHAKE/HMAC MCT), input bit lengths,
or absent fields rather than quietly marking them passed:

```sh
python3 Source/ACVP/local_client.py \
  --library /var/tmp/$USER/qsc-acvp-build/libqsc_acvp_hash.so \
  --vectors /var/tmp/$USER/source-vectors.json \
  --response /var/tmp/$USER/vector-response.json
```

The offline vector-response output is **not submitted to NIST**. The separate
authenticated sample client reuses the vector processor for SHA/SHAKE/HMAC.
Full ACVP coverage requires additional algorithm-specific adapters and an
actual successful NIST Demo server verdict for each registered algorithm.

## Additional direct primitive checks

```sh
python3 -m pip install cryptography==46.0.4
python3 Source/ACVP/ecc_check.py \
  --library /var/tmp/$USER/qsc-acvp-build/libqsc_acvp_ecc.so \
  --output /var/tmp/$USER/qsc-acvp/ecc
python3 Source/ACVP/pq_check.py \
  --library /var/tmp/$USER/qsc-acvp-build/libqsc_acvp_pq.so \
  --output /var/tmp/$USER/qsc-acvp/pq
```

ECC tests use independent cryptographic implementations, including invalid-peer
and tampered-signature rejection. Dedicated ML-KEM, ML-DSA and SLH-DSA tests
exercise all 12 relevant parameter sets but are **self-consistency smoke tests**, not
independent NIST known-answer tests. Each named test is invoked directly in an
isolated process, so an individual crash, error or timeout is reported without
skipping later families. Reports are written outside protected/source folders.

## Native AES-ECB / AES-CBC / AES-CTR / AES-GCM ACVP integration

The demo client now includes `ACVP-AES-ECB`, `ACVP-AES-CBC`, `ACVP-AES-CTR` and `ACVP-AES-GCM` in its **default
consecutive sample registration**, alongside the existing SHA/SHAKE/HMAC families.
AES-ECB covers 128/256-bit keys, encrypt/decrypt AFT, and the 100 x 1000 ECB
Monte Carlo test. AES-CBC covers unpadded 128/256-bit encrypt/decrypt AFT
and 100 x 1000 CBC Monte Carlo tests with mode-specific chaining.
AES-CTR covers 128/256-bit keys, external 128-bit big-endian initial counters,
byte-aligned AFT and CTR counter-sequence test types (up to 1 MiB per case).
No RFC3686 conformance or internal IV generation is advertised. AES-GCM covers 128/256-bit keys, 96-bit *externally supplied*
IVs, 128-bit tags, up to 8192-byte payloads and AAD, AFT encryption/decryption,
and expected authentication failures. Neither client supports AES-192, shortened
GCM tags, internal IV generation or arbitrary-bit payloads, and these must not
be advertised. The AES-ECB prerequisite is included in the same session.

The isolated `qsc_acvp_aes` shared library compiles current QSC AES and a
minimal `qsc_aes_bridge.c` test-only wrapper. It does not change QSC's ABI or
production code. Its binary is required only when AES algorithms are selected.
To replay AES vector sets, supply both the SHA and AES libraries:

```sh
python3 Source/ACVP/local_client.py \
  --library /var/tmp/$USER/qsc-acvp-build/libqsc_acvp_hash.so \
  --aes-library /var/tmp/$USER/qsc-acvp-build/libqsc_acvp_aes.so \
  --vectors /var/tmp/$USER/aes-vectors.json \
  --response /var/tmp/$USER/aes-response.json
```

The protected NIST Demo workflow builds both libraries, executes independent
AES reference comparisons, and submits the registered AES/SHA algorithm sets
consecutively. No NIST acceptance is claimed until a real server verdict exists.
The source-dependent P-384 qualification remains mandatory and unchanged.

## FIPS 203/204/205 ACVP vector adapters (current QSC APIs)

`demo_client.py` now has native ML-KEM, ML-DSA and SLH-DSA SHAKE vector
handlers. Pass `--pq-library` pointing to the isolated `qsc_acvp_pq` shared
library to enable them. All three families participate in the default
consecutive sample registration. Current supported capabilities:

| Family | Implemented response modes | Explicit exclusions |
|---|---|---|
| ML-KEM-512/768/1024 | FIPS203 keyGen, FIPS203-tr1 encapsulation and expanded-key decapsulation | Seed-format decapsulation and key-check modes |
| ML-DSA-44/65/87 | FIPS204 keyGen, FIPS204-tr1 deterministic external-pure sigGen with expanded keys, FIPS204 external-pure sigVer | Randomized signatures, internal mu, prehash, seed-format signing |
| SLH-DSA SHAKE 128s/f, 192s/f, 256s/f | FIPS205 keyGen, deterministic external-pure sigGen, external-pure sigVer | Randomized signatures, internal and prehash interfaces, SHA2 parameter sets |

These are deliberately restricted capability registrations, not assertions of
full FIPS implementation coverage. Unadvertised vector modes and malformed
inputs fail closed. The ACVP JSON response can contain confidential key material:
only the authenticated protocol client should transmit it. CI uploads only
sanitized status records, never downloaded or submitted vector bodies.

Offline adapter checks are independent of NIST Demo responses:

```sh
python3 Source/ACVP/mlkem_check.py \
  --library /var/tmp/$USER/qsc-acvp-build/libqsc_acvp_pq.so \
  --output /var/tmp/$USER/qsc-acvp-results
python3 Source/ACVP/pq_signature_check.py \
  --library /var/tmp/$USER/qsc-acvp-build/libqsc_acvp_pq.so \
  --output /var/tmp/$USER/qsc-acvp-results
```

The native tests exercise every advertised parameter set with deterministic
seeds, round trips and corruption rejection. They do **not** establish
independent FIPS KAT equivalence or successful ACVTS acceptance. Live NIST
Demo submission requires a registered client certificate, TOTP access, and a
GitHub `acvts-demo` protected environment. The complete ECC build continues
to require ECDSA P-384; no source exclusion is considered qualification.

## Elliptic-curve ACVP adapters and acceptance

The ECC vector adapter handles the following explicitly registered operations:

| Algorithm | Revision | Supported operations and parameter sets |
| --- | --- | --- |
| ECDSA | FIPS186-5 | keyGen (testing candidates), keyVer, sigVer; P-256/P-384/P-521 |
| DetECDSA | FIPS186-5 | deterministic sigGen; P-256/P-384/P-521, matching SHA-2 digests |
| EDDSA | 1.0 | keyGen, keyVer, pure sigGen/sigVer; ED-25519/ED-448, empty context only |
| XECDH | RFC7748 | keyGen, keyVer, SSC; Curve25519/Curve448 |
| KAS-ECC-SSC | Sp800-56Ar3 | staticUnified AFT/VAL; P-256/P-384/P-521 |

`qsc_ecc_keyver_bridge.c` calls the existing QSC Edwards point-encoding,
small-order and point-decoding primitives. ECDSA public points are checked by
QSC's corresponding ECDH validation/exchange path. XECDH key verification
exercises the QSC exchange/rejection path. Scalar-to-public generation, shared
secret computation and signature operations use QSC's implementation interfaces.
The bridge performs no new elliptic-curve arithmetic.

The vector dispatcher rejects wrong algorithm revisions, unsupported hashes,
nonempty EdDSA contexts, prehash variants, non-static KAS schemes, unsupported
ECDSA randomness modes, duplicate test-case IDs, and malformed byte strings.
The authenticated Demo workflow requires each registered ECC operation mode to
have its own matching vector set; an algorithm-level PASS cannot conceal a
missing key-generation or verification mode.

**Qualification limitations:** The offline key-generation adapter draws entropy
from the host OS. This is a development source, not a documented ACVP-validated
QSC DRBG. Live ECC registration is opt-in and blocked without a real DRBG
validation reference and independently qualified RNG integration (the
`ACVP_ECC_RNG_QUALIFIED` gate is an attestation, not proof of validation).
The ECDSA signers currently expose deterministic signing, so ordinary
randomized ECDSA sigGen is deliberately not advertised. EdDSA prehash and
nonempty Ed448 contexts, as well as KAS schemes beyond staticUnified, remain
unadvertised. No unsupported operation is silently treated as passing.

The full ECC build includes ECDSA P-384 unconditionally. The preliminary
library omits only the unavailable *signer source* while preserving all P-384
schema tests and native P-384 ECDH qualification. Two named P-384 signer tests
are explicitly pending in the preliminary run; `--complete` requires both.
No production QSC source file was modified.

Run the ECC preflight outside the repository tree:

```sh
python3 Source/ACVP/ecc_adapter_check.py \
  --library /var/tmp/$USER/qsc-acvp-build/libqsc_acvp_ecc_preliminary.so \
  --output /var/tmp/$USER/qsc-acvp/ecc-adapter
```

After the P-384 table arrives, build `qsc_acvp_ecc` and use `--complete`
with that full library. Only server-issued vectors and successful authenticated
NIST Demo verdicts establish ACVP Demo test acceptance; local checks do not.

### SP 800-185 local vector adapters (v7)

The offline vector dispatcher now handles byte-aligned AFT cases for
`cSHAKE-128`, `cSHAKE-256`, `KMAC-128`, and `KMAC-256`. Both fixed-output
KMAC and KMACXOF are callable. Published SP 800-185 cSHAKE/KMAC known-answer
vectors are tested natively. Monte Carlo, MAC verification, non-byte-aligned
inputs, hex customization, and authenticated Demo registration are **not yet
implemented** and remain explicitly rejected.

ECC adds offline `DetECDSA / sigGen / FIPS186-5` and pure `EDDSA / sigGen /
1.0` group responses, verified against the independent `cryptography` library.
Live signing registration is not enabled: a tested key-generation mechanism
and verified DRBG prerequisite are still required. ECDSA P-384 stays mandatory
for full acceptance and is pending the updated implementation.

## PBKDF / HKDF extension

The ACVP `PBKDF` / 1.0 AFT adapter covers PBKDF2-HMAC-SHA2-256/384/512
with a **112–512-bit derived key**, 128–4096-bit salt, 8–128-byte password,
and 10–1000 iterations in the advertised Demo capability. QSC's
`qsc_pbmac1_derive_key()` currently caps derived keys at 64 bytes; registering
longer outputs would be incorrect. The native offline harness also validates
RFC 5869 HKDF extract+expand for SHA-256/384/512. **HKDF is not registered as
SP 800-56C KDA**, as fixed-info processing, hybrid Z/T construction, and
full AFT/VAL behavior have not been implemented.

Run these two commands after building the `qsc_acvp_hash` target:

```shell
python Source/ACVP/kdf_check.py --library /path/to/libqsc_acvp_hash.so --output /var/tmp/$USER/qsc-acvp-kdf
python -m unittest discover -s Source/ACVP/tests -p test_kdf_vectors.py -v
```

The KDF gate is included in all offline CI jobs and the protected Demo
preflight. An offline PASS is not an authenticated NIST validation.

## Standalone SP 800-56C KDA-HKDF qualification

The KDA-HKDF adapter supports `Sp800-56Cr1` and `Sp800-56Cr2`,
with HMAC-SHA2-256/384/512, byte-aligned single expansions, concatenated
`uPartyInfo||vPartyInfo||l` fixed info, and AFT/VAL responses. It rejects
hybrid secrets, multi-expansion, unsupported encodings and unadvertised HMACs.
Both revisions are included in the offline KDF regression, which compares
native QSC output to an independently implemented HMAC-based HKDF oracle.

Live registration is **opt-in**, not automatic: select `include_kda_hkdf` in
`qsc-acvp-demo.yml` and configure `ACVP_KDA_DRBG_VALIDATION` as a protected
environment variable containing a real, applicable DRBG validation identifier.
The KDA registration includes the SHA/HMAC prerequisites from the same Demo
session. No DRBG validation is implied by local testing; missing prerequisites
fail before registration. Neither offline tests nor mock Demo tests establish
NIST KDA validation.

## NIST Demo verdict-integrity gate

The sample client fails closed if the server fails to return at least one vector
set for **every selected algorithm**, includes duplicate vector-set URLs, or
returns a vector-set `vsId` different from its requested URL. Every submitted
vector set must receive exactly one matching `passed` result in the server's
final test-session verdict. Partial results, unexpected vector-set URLs,
inconsistent verdicts, missing fields and unknown statuses **never constitute
ACVP qualification**. Incomplete server processing remains pending until the
bounded poll limit is reached, then exits unsuccessful.

The local mock transport uses intentionally incomplete registrations in a few
algorithm-specific dispatch tests; those tests check that the relevant responses
are submitted but must record `FAIL_INCOMPLETE_ALGORITHM_COVERAGE` rather than
pretend a full multi-algorithm Demo session passed. The protected live workflow
still requires issued NIST credentials and actual server-supplied verdicts.

## Final consecutive offline acceptance runner

The GitHub offline qualification workflow builds the isolated hash, AES, post-quantum,
and preliminary ECC libraries, then attempts the **complete** `qsc_cavp` and
`qsc_acvp_ecc` targets. A missing or failing P-384 signer does not stop the other
stages from running, but it prevents final qualification success. The complete
ECC and CAVP tests remain mandatory for every platform and security class.

`qualify_all.py` executes the following **eleven named stages directly and in order**:
Python regression, SHA/HMAC, AES, cSHAKE/KMAC, PBKDF/HKDF/KDA, ECC
interoperability, ECC ACVP adapter, dedicated PQ smoke tests, ML-KEM adapter,
ML-DSA/SLH-DSA adapter, and the original CAVP suites. Each stage gets a separate
log. An unsuccessful stage does not prevent the remaining available stages from
executing. The runner produces `qualify-all.json` and `qualify-all.md` in the
external evidence directory.

After configuring and building with CMake, a local diagnostic run can be started
with, for example:

```sh
python3 Source/ACVP/qualify_all.py \
  --build-dir "/var/tmp/$USER/qsc-acvp-build" \
  --output "/var/tmp/$USER/qsc-acvp-results" \
  --security-class 3 --full-build success
```

Select `--full-build success` **only after** the complete `qsc_cavp` and
`qsc_acvp_ecc` targets successfully compile. Select `pending` for a known
incomplete source update, or `failed` for any other full-build failure; neither
option can pass final acceptance. The CI workflow derives this value from the
actual complete-build result, never from an operator declaration.

The consolidation job requires exactly six runner artifacts, each containing
its complete CAVP report, per-family evidence, and a successful 11-stage
execution manifest. It checks the ECC v11 contract of 33 tests with zero skips
and P-384 actually tested, and rejects missing stage logs, changed test counts,
inconsistent security-class declarations, malformed results, or incomplete
coverage. An offline PASS is **not** a NIST Demo or CAVP validation.

## Authenticated Demo acceptance

The protected Demo workflow is configured to request ECC and KDA/HKDF by
default. A full live session requires an updated P-384 implementation, NIST
issued mutual-TLS/TOTP identity, applicable DRBG prerequisite evidence, and a
qualified random-generation path. If a prerequisite is absent, the workflow
fails without claiming certification. Manual partial selections remain useful
for transport diagnostics, but do not satisfy full project qualification.

The authenticated client currently advertises the supported AES, SHA/HMAC,
PBKDF, KDA/HKDF, FIPS post-quantum and ECC modes. The cSHAKE/KMAC response
adapter remains **offline AFT-only**: NIST's XOF specification also defines
cSHAKE Monte Carlo and KMAC MAC-verification tests, which are not yet implemented
for live registration. No unimplemented mode may be advertised or counted as
passed. The final server-side acceptance requires all selected vector sets and
algorithm modes to receive matching positive verdicts, including the server's
session status; live evidence must not be substituted with mock server results.

Neither GitHub-hosted execution nor authenticated Demo communication can be
reported as executed until their actual logs and server verdict are available.
