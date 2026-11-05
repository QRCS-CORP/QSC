# QSC ACVP Qualification

Standalone qualification project for [QRCS QSC](https://github.com/QRCS-CORP/QSC).
Includes the offline ACVP vector adapters, local test simulator, CAVP integration,
strict evidence reporting and an authenticated NIST ACVTS Demo client.
The offline simulator is not NIST; a Demo result is not a production CAVP certificate.

## Repository organization

```
Source/ACVP/                CMake, C/Python adapters, tests and CI CAVP entry point
.github/workflows/         Offline qualification and protected NIST Demo jobs
docs/adapter-guide.md      Adapter command reference
dependency/QSC/             External QSC checkout (ignored, not committed)
```

**No QSC production source is copied into this repository.** The modified CAVP entry
point is maintained here as `Source/ACVP/cavp_runner.c`, and is compiled with the
remaining upstream `Source/CAVP` sources. QSC itself is not patched.

## Initial setup

Create a new repository named `QRCS-CORP/QSC-ACVP`, on branch `main`. From its root:

```sh
git clone https://github.com/QRCS-CORP/QSC.git dependency/QSC
cmake -S Source/ACVP -B /var/tmp/qsc-acvp-build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build /var/tmp/qsc-acvp-build --target qsc_acvp_hash qsc_acvp_aes qsc_acvp_pq qsc_acvp_ecc_preliminary
python3 -m unittest discover -s Source/ACVP/tests -v
```

Use `-DQSC_ROOT=/path/to/QSC/Source` if the checkout is stored elsewhere.
The full `qsc_cavp` and `qsc_acvp_ecc` builds, including P-384, are always
mandatory for complete qualification. Missing sources produce incomplete evidence,
never PASS. All generated artifacts, logs and evidence belong outside the repository
in a temporary or platform-appropriate user data directory.

## GitHub Actions

`qsc-acvp-offline.yml` runs the Linux/Windows security-class matrix on changes,
weekly on a schedule, and manually. Its separate checkout of `QRCS-CORP/QSC`
uses `master` by default; the manual input `qsc_ref` selects a branch, tag or
commit. The QSC commit is printed in logs and recorded in the offline JSON reports
alongside the qualification repository revision.
The NIST Demo workflow is manually triggered and requires a protected `acvts-demo`
environment with the issued client certificate, key and OTP seed. ECC and KDA
registrations must not be enabled without satisfying their DRBG prerequisites.

## Qualification boundaries

- Python parser/transport tests and local interoperability are **offline evidence**.
- Complete P-384 implementation and all required operations must pass for a full verdict.
- A real ACVTS Demo PASS requires issued NIST credentials and server verdicts.
- Review source-file license notices and the repository license with QRCS before public publication.
- For individual adapter commands see `docs/adapter-guide.md`.
