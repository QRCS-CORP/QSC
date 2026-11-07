# QSC CMake Build System

**Repository-root integration guide**  
**QSC source baseline:** November 6, 2026  
**CMake project version:** 1.4.0.0  
**Status:** Engineering review candidate; not a replacement for formal QSC qualification

This guide documents the additive CMake build system for the Quantum Resistant Cryptographic Solutions Corporation (QRCS) QSC cryptographic library. It explains how to select application-specific builds, compile optional hardware providers, build static and shared libraries, install the SDK, and reproduce the available CMake integration tests.

**Important:** The CMake integration does **not** modify the existing QSC cryptographic source files, public headers, Visual Studio project files, solution files, algorithms, or protocol implementations. It creates build targets and selects which existing translation units to compile. It does not itself establish FIPS validation, RFC interoperability, hardware key custody, or constant-time qualification.

## Contents

1. [Repository layout and installation](#1-repository-layout-and-installation)
2. [Requirements and supported build environments](#2-requirements-and-supported-build-environments)
3. [Quick start](#3-quick-start)
4. [Build configurations and CMake options](#4-build-configurations-and-cmake-options)
5. [Compilation profiles](#5-compilation-profiles)
6. [Custom algorithm selections](#6-custom-algorithm-selections)
7. [Hardware-provider integration](#7-hardware-provider-integration)
8. [CPU architecture and optimization](#8-cpu-architecture-and-optimization)
9. [Static and shared libraries](#9-static-and-shared-libraries)
10. [Installable SDK and consuming applications](#10-installable-sdk-and-consuming-applications)
11. [Tests and qualification](#11-tests-and-qualification)
12. [Build artifacts and capability manifests](#12-build-artifacts-and-capability-manifests)
13. [Cross-platform build examples](#13-cross-platform-build-examples)
14. [Troubleshooting](#14-troubleshooting)
15. [Source maintenance and extension](#15-source-maintenance-and-extension)
16. [Current limitations and release gates](#16-current-limitations-and-release-gates)
17. [Licensing and integration policy](#17-licensing-and-integration-policy)

---

## 1. Repository layout and installation

Place the integration package at the **QSC repository root**, beside `QSCTest.sln`, not inside the library's existing `QSC/` folder.

```text
QSC/                              Repository root
├── CMakeLists.txt                  Root build configuration
├── CMakePresets.json               Named build presets
├── cmake/                          CMake infrastructure and documentation
│   ├── QSCSources.cmake             Source inventory and TLS dependency set
│   ├── QSCProfiles.cmake            Application/cryptography profiles
│   ├── QSCHardware.cmake            Optional hardware-provider sources
│   ├── QSCCompiler.cmake            Compiler/CPU options
│   ├── QSCInstall.cmake             SDK installation and target export
│   ├── QSCConfig.cmake.in           Installed package configuration template
│   ├── QSCFeatures.h.in             Generated capability header template
│   ├── QSCCapabilities.json.in      Generated machine-readable manifest
│   ├── QSCTests.cmake               Separate CMake smoke-test executable
│   ├── tests/
│   │   └── qsc_profile_smoke.c      Individually invoked API smoke tests
│   ├── README.md                    This document
│   └── QUALIFICATION.md            Results and unexecuted qualification work
├── QSCTest.sln                     Existing Visual Studio solution (unchanged)
├── QSC/                             Existing cryptographic library (unchanged)
│   ├── QSC.vcxproj
│   ├── qsccommon.h
│   ├── aes.c
│   └── ...
├── QSCTest/                         Existing test harness (unchanged)
├── QSCSDK/                          Existing SDK project (unchanged)
└── build/                           CMake-generated output (do not commit)
    └── qsc/
```

The root `CMakeLists.txt` expects the library in `QSC/` by default. It also accepts the alternative layout `Source/QSC/` when that directory contains `qsccommon.h`. For other layouts, provide an explicit path:

```powershell
cmake -S . -B build/qsc/full -DQSC_LIBRARY_DIR="C:/path/to/QSC/library" -DQSC_PROFILE=FULL
```

Use **forward slashes** inside CMake path values on Windows. A configured build directory caches `QSC_LIBRARY_DIR`; changing layout or moving the checkout may require a new build directory.

### Installation procedure

1. Extract the CMake integration ZIP directly into the repository root.
2. Confirm that `CMakeLists.txt` and `CMakePresets.json` are beside `QSCTest.sln`.
3. Confirm that the existing library remains under `QSC/` and that `QSC/QSC.vcxproj` is present.
4. Run the full-profile smoke build before attempting compact or hardware-specific configurations.
5. Keep generated `build/`, `out/`, and installation directories out of version control.

The CMake integration does not automatically add `QSCTest.sln`, `QSCTest/`, or `QSCSDK/` as subprojects. Their established Visual Studio build remains unchanged. The CMake test suite is a separate, much smaller integration check.

## 2. Requirements and supported build environments

| Requirement | Details |
|---|---|
| CMake | **3.21 or newer** (the package's minimum requirement) |
| C compiler | A C17-capable compiler, including supported MSVC, GCC or Clang toolchains |
| Build tool | Ninja for supplied presets, or another CMake-supported generator |
| Threading | Platform threading facilities discoverable by `find_package(Threads)` |
| Windows | Supported Visual Studio/MSVC development environment and Windows SDK |
| Linux | GCC or Clang, platform development headers and system linker |
| macOS | AppleClang/Xcode command-line tools or another supported C compiler |
| Optional HSM | Vendor PKCS#11 module, native platform SDK, TPM2-TSS, or PSA Crypto as selected |

Only the **Linux x86-64** configurations described in `cmake/QUALIFICATION.md` were actually built and smoke-tested for this review. Windows/MSVC, macOS, and ARM64 are supported **configuration targets**, not completed qualification results.

The optional source-inventory validator expects the November 6 QSC library source set. If the library sources are upgraded, review the CMake source inventory and rerun all applicable tests.

## 3. Quick start

Run commands from the repository root.

### A. Full static library (cross-platform CMake command)

```powershell
cmake -S . -B build/qsc/full -DQSC_PROFILE=FULL -DQSC_BUILD_PROFILE_TESTS=ON
cmake --build build/qsc/full --config Release
ctest --test-dir build/qsc/full -C Release --output-on-failure
```

`FULL` is the default profile, and static libraries are built by default. `--config Release` is relevant to multi-configuration generators such as Visual Studio; single-configuration generators use `CMAKE_BUILD_TYPE` selected during configuration.

### B. Use a supplied Ninja preset

```powershell
cmake --list-presets
cmake --preset pqc3
cmake --build --preset pqc3
ctest --test-dir build/qsc/pqc3 --output-on-failure
```

The preset uses the **Ninja** generator, sets a **Release** build and enables the smoke-test target. Ninja must be installed and on `PATH`. On Windows, invoke the commands from a Visual Studio Developer Command Prompt or another environment with the desired MSVC compiler configured.

### C. PQC Category 5 shared library

```powershell
cmake -S . -B build/qsc/pqc5-shared -DQSC_PROFILE=CRYPTO_PQC5 -DQSC_BUILD_SHARED=ON -DQSC_BUILD_PROFILE_TESTS=ON
cmake --build build/qsc/pqc5-shared --config Release
ctest --test-dir build/qsc/pqc5-shared -C Release --output-on-failure
```

Use **separate build directories** for static and shared configurations and for different profiles. Avoid reusing a directory after switching compilers, architectures, hardware providers or major configuration modes.

## 4. Build configurations and CMake options

The following values correspond to the supplied `CMakeLists.txt` and support modules.

| Option | Default | Purpose |
|---|---|---|
| `QSC_PROFILE` | `FULL` | Select one of the application-oriented build profiles below |
| `QSC_CUSTOM_ALGORITHMS` | Empty | Comma- or semicolon-separated algorithm IDs for `CUSTOM` |
| `QSC_BUILD_SHARED` | `OFF` | Produce a shared library rather than the default static library |
| `QSC_ENABLE_HARDWARE` | `OFF` | Compile hardware-provider infrastructure |
| `QSC_HARDWARE_PROVIDERS` | Empty | Select optional hardware adapters |
| `QSC_PSA_INCLUDE_DIR` | Empty | Include root for native PSA Crypto headers when requested |
| `QSC_PSA_LIBRARY` | Empty | Native PSA Crypto link library when requested |
| `QSC_CPU_TARGET` | `BASELINE` | Select portable baseline or explicitly targeted AVX2 build |
| `QSC_LIBRARY_DIR` | `QSC/` | Source-directory path, with a `Source/QSC/` fallback |
| `QSC_VALIDATE_INVENTORY` | `ON` | Check source-file inventory against library sources/VS project |
| `QSC_INSTALL_SDK` | `ON` | Generate SDK installation and package export rules |
| `QSC_BUILD_PROFILE_TESTS` | `OFF` | Build and register the separate CMake smoke tests |
| `CMAKE_BUILD_TYPE` | Generator-dependent | `Release`, `Debug`, etc. on single-configuration generators |
| `CMAKE_INSTALL_PREFIX` | Platform-dependent | Default installation location; override as needed |

The shipped Ninja presets set `CMAKE_BUILD_TYPE=Release` and `QSC_BUILD_PROFILE_TESTS=ON`. For multi-configuration Visual Studio builds, use `--config Release` or `--config Debug` when compiling and running CTest.

### Preset catalog

| Preset | Selected profile or options |
|---|---|
| `full` | `FULL`, static |
| `full-shared` | `FULL`, shared |
| `boot-verify` | `BOOT_VERIFY` |
| `device-identity` | `DEVICE_IDENTITY` |
| `classical` | `CRYPTO_CLASSICAL` |
| `pqc3` | `CRYPTO_PQC3` |
| `pqc5` | `CRYPTO_PQC5` |
| `hybrid` | `CRYPTO_HYBRID` |
| `cloud-hsm` | `CLOUD_HSM`, no hardware provider selected by default |
| `edge-gateway` | `EDGE_GATEWAY` |
| `tls-client` | `TLS_CLIENT` |
| `tls-server` | `TLS_SERVER` |
| `industrial-ot` | `INDUSTRIAL_OT` |
| `robot-edge` | `ROBOT_EDGE` |
| `ai-model-trust` | `AI_MODEL_TRUST` |
| `vehicle-ecu` | `VEHICLE_ECU` |
| `hsm-pkcs11` | `CLOUD_HSM` with PKCS#11 hardware support enabled |

There is no predefined `CUSTOM` preset. Specify its algorithm list explicitly when configuring. The preset names are **case-sensitive**; the corresponding `QSC_PROFILE` values use uppercase strings.

## 5. Compilation profiles

A profile is a **source-selection recipe**, not an additional copy of the cryptographic library or an end-to-end implementation of an industry protocol.

| `QSC_PROFILE` | Source-level purpose | Important boundary |
|---|---|---|
| `FULL` | All **176** QSC C source modules from the reviewed baseline | Reference build; selected hardware providers require separate configuration |
| `BOOT_VERIFY` | SHA-2/SHA-3, ECDSA P-256 and ML-DSA-65 sources | Contains complete translation units, not only verification entry points |
| `DEVICE_IDENTITY` | Classical + PQC3 primitives, hashing and AES | Does not implement a device-provisioning protocol |
| `CRYPTO_CLASSICAL` | X25519, ECDSA P-256, SHA-2 and AES | The source closure may include helper algorithms; not TLS |
| `CRYPTO_PQC3` | ML-KEM-768, ML-DSA-65, SHA-3 and AES | Not a complete key-management protocol |
| `CRYPTO_PQC5` | ML-KEM-1024, ML-DSA-87, SHA-3 and AES | Not a complete key-management protocol |
| `CRYPTO_HYBRID` | Classical + PQC3 primitives | Does not automatically implement or validate hybrid-combiner protocols |
| `CLOUD_HSM` | Selected ECC, ML-KEM, ML-DSA, hashing and AES | Does **not** enable a hardware provider unless requested |
| `EDGE_GATEWAY` | Current TLS/X.509 source dependency set | Same TLS dispatch as client/server profiles; no per-algorithm TLS pruning |
| `TLS_CLIENT` | TLS/X.509-compatible source set | **Not** a client-only TLS implementation |
| `TLS_SERVER` | TLS/X.509-compatible source set | **Not** a server-only TLS implementation |
| `INDUSTRIAL_OT` | Same source selection as the hybrid/device-identity family | Not OPC UA, IEC 62443, or SCADA protocol compliance |
| `ROBOT_EDGE` | Same source selection as the hybrid/device-identity family | Not ROS 2/DDS-Security middleware integration |
| `AI_MODEL_TRUST` | Same source selection as boot verification | Not a complete model-signing, provenance, or update framework |
| `VEHICLE_ECU` | Selected P-256/P-384, X25519, PQC3, hashing and AES | Not AUTOSAR or automotive qualification |
| `CUSTOM` | Explicitly selected independently linkable primitive modules | Unsupported custom IDs fail configuration |

`EDGE_GATEWAY`, `TLS_CLIENT`, and `TLS_SERVER` currently select the **same 88-source** TLS/X.509 dependency closure. This intentionally preserves the existing TLS group/signature/cipher dispatch and certificate-verification code. Narrowing TLS by individual groups, signature schemes, or roles would require separate protocol source work and interoperability testing.

`BOOT_VERIFY` and `AI_MODEL_TRUST` also select the same current translation units. Because the underlying ECDSA/ML-DSA files contain both signing and verification functions, **verification-only source semantics and minimized flash footprint are not guaranteed** by these names.

Several related application profiles intentionally have identical initial source selections. Their names provide deployment-specific starting configurations; they should not be marketed as having separate runtime protocol integrations until those integrations are developed and qualified.

### Profile selection rules

- The CMake resolver selects existing `.c` files and required utility sources. It does not rewrite cryptographic arithmetic.
- Source files that include implementation fragments or parameterized headers are managed as translation units rather than independently compiling every included implementation file.
- Header declarations may be broader than the compact library's actual symbols. Applications must consult compiled capabilities and link tests.
- Do not assume a particular PKI/TLS standard, cryptographic assurance level, or certification is satisfied simply from the profile name.

## 6. Custom algorithm selections

`CUSTOM` supports the identifiers explicitly enumerated below.

| Algorithm ID | Functionality selected |
|---|---|
| `SHA2` | SHA-2 source module |
| `SHA3` | SHA-3/SHAKE source module |
| `AES_GCM` | AES implementation and required shared crypto dependencies |
| `X25519` | X25519 plus supporting cryptographic modules |
| `ECDSA_P256` | ECDSA P-256 plus dependencies |
| `ECDSA_P384` | ECDSA P-384 plus dependencies |
| `MLKEM768` | ML-KEM-768 plus SHA-3 |
| `MLKEM1024` | ML-KEM-1024 plus SHA-3 |
| `MLDSA65` | ML-DSA-65 plus SHA-3 |
| `MLDSA87` | ML-DSA-87 plus SHA-3 |
| `SLHDSA_SHAKE128S` | SHAKE-128s SLH-DSA plus required SHA-2/SHA-3 |
| `SLHDSA_SHAKE256S` | SHAKE-256s SLH-DSA plus required SHA-2/SHA-3 |

Example:

```powershell
cmake -S . -B build/qsc/custom-identity -DQSC_PROFILE=CUSTOM -DQSC_CUSTOM_ALGORITHMS=SHA2,MLKEM768,MLDSA65 -DQSC_BUILD_PROFILE_TESTS=ON
cmake --build build/qsc/custom-identity --config Release
ctest --test-dir build/qsc/custom-identity -C Release --output-on-failure
```

On a shell where semicolons are interpreted specially, either use comma-separated values as above or quote the semicolon-separated value. Duplicate requested algorithm names are deduplicated by the resolver.

**Unsupported configuration example:** `-DQSC_PROFILE=CUSTOM` without an algorithm selection is intentionally rejected. Adding a new algorithm to the library does not automatically make it a supported custom ID; update `QSCProfiles.cmake`, verify its dependencies, and add the corresponding tests first.

## 7. Hardware-provider integration

Hardware support is independent of the cryptographic application profile. Enable the provider infrastructure and explicitly select the adapters required for the deployment:

```powershell
cmake -S . -B build/qsc/hsm-pkcs11 -DQSC_PROFILE=CLOUD_HSM -DQSC_ENABLE_HARDWARE=ON -DQSC_HARDWARE_PROVIDERS=PKCS11 -DQSC_BUILD_PROFILE_TESTS=ON
cmake --build build/qsc/hsm-pkcs11 --config Release
ctest --test-dir build/qsc/hsm-pkcs11 -C Release --output-on-failure
```

| Provider ID | Build behavior and dependencies |
|---|---|
| `PKCS11` | Adds QSC PKCS#11 loader, sessions, key operations, signing and key agreement; token module selected at runtime |
| `NCRYPT` | Windows only; links NCrypt/Bcrypt system APIs |
| `TPM` | Linux native TPM2-TSS configuration; requires `pkg-config` and `tss2-esys`/`tss2-tctildr` packages |
| `ATECC` | Compiles existing device-callback adapter; OEM must supply working device integration |
| `SE050` | Compiles existing SE050 adapter with PKCS#11 support; external NXP/vendor integration remains necessary |
| `PSA` | Compiles QSC PSA adapter; platform callbacks/provider implementation are application-dependent |
| `PSA_NATIVE` | Requires `QSC_PSA_INCLUDE_DIR/psa/crypto.h` and an existing `QSC_PSA_LIBRARY` |
| `PLATFORM` | Compiles platform-backed callback interface; actual provider supplied separately |

One or more providers may be named with commas or CMake semicolons. For example:

```powershell
cmake -S . -B build/qsc/hsm-multi -DQSC_PROFILE=CLOUD_HSM -DQSC_ENABLE_HARDWARE=ON -DQSC_HARDWARE_PROVIDERS=PKCS11,PSA,PLATFORM
```

### PKCS#11 and TLS signing bridges

The existing QSC source has dedicated PKCS#11 and Windows NCrypt TLS signing integration modules. The resolver includes these bridge modules when applicable to `FULL`, `EDGE_GATEWAY`, `TLS_CLIENT`, or `TLS_SERVER` and the matching provider is selected. `CLOUD_HSM` is a standalone crypto/HSM profile; it does not include the TLS/X.509 engine.

The `FULL` source list includes all repository C source files. Some hardware implementation files may be compiled as empty or feature-guarded translation units when hardware definitions are disabled; therefore a source-file count does **not** indicate active provider support.

### Hardware custody and fallback requirements

Compiled support does not imply a connected HSM, token authentication, availability of an algorithm, protected key generation, or private-key non-exportability. A hardware-bound private key must not silently be copied into software as a fallback. Runtime provider capability checks, authorized key handles, mechanism support, session management, hardware diagnostics and fail-closed behavior remain the responsibility of the existing provider APIs and consuming application.

**Hardware qualification not performed in this package:** physical PKCS#11/TPM/PSA/ATECC/SE050 operations. The available Linux tests verify configuration, linking and software smoke tests only.

## 8. CPU architecture and optimization

`QSC_CPU_TARGET` has two current values:

- `BASELINE` (default): uses the established QSC compiler/platform feature guards without selecting an additional AVX2 target in the CMake layer.
- `AVX2`: explicitly enables x86/x64 AVX2 compilation. GCC/Clang add `-mavx2 -maes -mpclmul`; MSVC uses `/arch:AVX2`.

Example for an **AVX2-capable machine**:

```powershell
cmake -S . -B build/qsc/avx2 -DQSC_PROFILE=CRYPTO_PQC3 -DQSC_CPU_TARGET=AVX2
cmake --build build/qsc/avx2 --config Release
```

The CMake project does **not** add a new runtime CPU dispatcher. A binary built specifically for AVX2 should not be deployed to a CPU without the required features. Do not infer VAES or VPCLMUL availability from AVX2 alone. Existing QSC instruction-set guards continue to control optimized paths, and any changes to target flags require cross-platform KAT, performance and side-channel qualification.

The present CMake options do not expose separate AVX-512 or Arm architecture profiles. CMake's toolchain/compiler target selection and QSC's existing platform guards govern those builds until separately integrated and tested.

## 9. Static and shared libraries

### Static library (default)

```powershell
cmake -S . -B build/qsc/static -DQSC_PROFILE=FULL -DQSC_BUILD_SHARED=OFF
cmake --build build/qsc/static --config Release
```

Expected library form: `.lib` on Windows, `.a` on Unix-like platforms (actual artifact names depend on the generator/toolchain).

### Shared library (opt-in)

```powershell
cmake -S . -B build/qsc/shared -DQSC_PROFILE=FULL -DQSC_BUILD_SHARED=ON
cmake --build build/qsc/shared --config Release
```

Expected platform forms: Windows `.dll` plus import `.lib`; Linux `.so`; macOS `.dylib`. The existing QSC DLL export annotations and CMake target-level definitions are reused without changing `qsccommon.h`. The shared-library build uses `/MD` or `/MDd` under MSVC while the static default uses `/MT` or `/MTd`. Check downstream runtime-library compatibility before shipping.

On Linux the shared target enables a linker check for unresolved external symbols. That is a link-integrity control, **not** a guarantee that every exposed API path has been executed.

The `BUILD_SHARED_LIBS` CMake variable can also influence target type in this package; using `QSC_BUILD_SHARED=ON` is the clearest explicit choice.

**Release restriction:** Windows DLL exports/imports, ABI and a separate MSVC consumer build were not validated in the available Linux test environment. macOS dylib and ARM64 validation are also outstanding.

## 10. Installable SDK and consuming applications

To install the selected QSC package into a dedicated evaluation prefix:

```powershell
cmake -S . -B build/qsc/install-test -DQSC_PROFILE=CRYPTO_PQC3 -DQSC_BUILD_SHARED=ON
cmake --build build/qsc/install-test --config Release
cmake --install build/qsc/install-test --config Release --prefix build/qsc/installed-pqc3
```

The installation includes:

```text
<prefix>/
├── include/qsc/              Unmodified public QSC headers, plus QSCFeatures.h
├── lib/                      Static or shared libraries (platform-dependent)
├── lib/cmake/QSC/            QSCConfig.cmake, package version and exported targets
└── share/qsc/                QSCCapabilities.json (platform-specific datadir)
```

On Windows, the shared DLL may be placed under `<prefix>/bin/`; import libraries and package files will follow CMake's installed directory conventions. The exact `lib`/`lib64`, `bin`, and `share` destinations are controlled by `GNUInstallDirs` and the platform.

A downstream CMake project should consume the installed target rather than manually supplying include paths or linker switches:

```cmake
cmake_minimum_required(VERSION 3.21)
project(QSCConsumer LANGUAGES C)

find_package(QSC CONFIG REQUIRED)

add_executable(qsc_consumer main.c)
target_link_libraries(qsc_consumer PRIVATE QSC::QSC)
```

Configure it with the correct installation prefix:

```powershell
cmake -S path/to/consumer -B path/to/consumer-build -DCMAKE_PREFIX_PATH="C:/path/to/installed-pqc3"
cmake --build path/to/consumer-build --config Release
```

For a non-system shared library, the runtime loader must also be able to locate the library. On Windows, place the DLL beside the executable or configure an appropriate deployment search path. On Linux/macOS, use an installation layout and runtime search-path strategy consistent with your packaging rules; avoid hard-coded developer paths in distribution artifacts.

The package exports `QSC::QSC`, and the generated capability header is installed alongside existing QSC headers. A compact library deliberately may **not** implement every function declared by those unmodified headers; use the selected profile's capabilities and consumer link tests to establish compatibility.

If `QSC_INSTALL_SDK=OFF`, the CMake package installation and target export rules are not registered. The build-tree alias target `QSC::QSC` remains available to consumers defined within the same CMake project.

## 11. Tests and qualification

Enable the independent CMake smoke suite at configure time:

```powershell
cmake -S . -B build/qsc/tests -DQSC_PROFILE=CRYPTO_HYBRID -DQSC_BUILD_PROFILE_TESTS=ON
cmake --build build/qsc/tests --config Release
ctest --test-dir build/qsc/tests -C Release --output-on-failure
```

The test executable is `qsc_profile_smoke`. Its test functions run **individually and sequentially**; it does not use a loop, registry or dispatch array to invoke tests. Tests are enabled according to the compiled feature flags. Applicable cases include:

| Test | Covered behavior |
|---|---|
| `QSC-CMAKE-001` | SHA-256 of ASCII `abc` versus known digest |
| `QSC-CMAKE-002` | SHA3-256 of ASCII `abc` versus known digest |
| `QSC-CMAKE-003` | Seeded ML-KEM-768 encapsulation/decapsulation roundtrip |
| `QSC-CMAKE-004` | Seeded ML-KEM-1024 encapsulation/decapsulation roundtrip |
| `QSC-CMAKE-005` | ML-DSA-65 seeded key generation, sign/verify |
| `QSC-CMAKE-006` | ML-DSA-87 seeded key generation, sign/verify |
| `QSC-CMAKE-007` | X25519 two-party agreement |

Deterministic seeds and the deterministic test RNG must **never** be reused for production keys or signing. KEM/signature roundtrip checks demonstrate functional integration, not independently established algorithm conformance.

The CMake smoke harness is **not** the established `QSCTest` suite. It does not replace full known-answer testing, malformed-input tests, failure propagation, sanitizer runs, constant-time analysis, ACVP, FIPS laboratory work, native hardware testing, or TLS interoperability.

For actual executed results and exclusions, consult **[QUALIFICATION.md](QUALIFICATION.md)**. Re-run tests after changing the compiler, system architecture, optimization flags, source inventory or library profile.

## 12. Build artifacts and capability manifests

Two files are generated in each build tree:

- `QSCFeatures.h`: compile-time values including `QSC_CMAKE_PROFILE`, `QSC_CMAKE_ALGORITHMS`, `QSC_CMAKE_HARDWARE_ENABLED`, provider names and selected SHA-2/SHA-3/X25519/ML-KEM/ML-DSA flags.
- `QSCCapabilities.json`: package version, profile name, algorithm summary, compiled-provider selection, CPU target, source-module count and static/shared kind.

The metadata states what was **compiled**, not what was verified, certified, connected, authorized, or proven constant-time. For example, `QSC_CMAKE_HARDWARE_ENABLED=1` does not imply that a PKCS#11 token is present or that an ML-DSA private key has hardware custody.

The manifest's algorithm list represents the profile recipe rather than an exhaustive symbol-level audit. A selected `.c` file can contain several public functions or helper primitives beyond the profile's displayed algorithms.

For a reliable distribution record, retain the generated metadata together with the compiler version, selected build flags, source commit/revision, qualification output and binary cryptographic hashes.

## 13. Cross-platform build examples

### Windows / Visual Studio 2022

Open an **x64 Native Tools Command Prompt for VS 2022** or an equivalent developer environment. From the repository root:

```powershell
cmake -S . -B build/qsc/vs2022 -G "Visual Studio 17 2022" -A x64 -DQSC_PROFILE=FULL -DQSC_BUILD_PROFILE_TESTS=ON
cmake --build build/qsc/vs2022 --config Release
ctest --test-dir build/qsc/vs2022 -C Release --output-on-failure
```

For a separate shared-library review build:

```powershell
cmake -S . -B build/qsc/vs2022-dll -G "Visual Studio 17 2022" -A x64 -DQSC_PROFILE=FULL -DQSC_BUILD_SHARED=ON -DQSC_BUILD_PROFILE_TESTS=ON
cmake --build build/qsc/vs2022-dll --config Release
ctest --test-dir build/qsc/vs2022-dll -C Release --output-on-failure
```

**These Windows commands are examples, not claims of completed MSVC tests.** Check compiler warnings, DLL exports/imports, runtime dependencies, 32-/64-bit ABI, and an external consumer before distributing binaries.

### Linux / GCC or Clang

```bash
cmake -S . -B build/qsc/linux-full -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DQSC_PROFILE=FULL -DQSC_BUILD_PROFILE_TESTS=ON
cmake --build build/qsc/linux-full --parallel 4
ctest --test-dir build/qsc/linux-full --output-on-failure
```

For Clang, use a **new** build directory and select the compiler during the first configuration:

```bash
cmake -S . -B build/qsc/clang-pqc3 -G Ninja \
  -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Release \
  -DQSC_PROFILE=CRYPTO_PQC3 -DQSC_BUILD_SHARED=ON -DQSC_BUILD_PROFILE_TESTS=ON
cmake --build build/qsc/clang-pqc3 --parallel 4
ctest --test-dir build/qsc/clang-pqc3 --output-on-failure
```

### macOS / AppleClang

```bash
cmake -S . -B build/qsc/macos-full -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DQSC_PROFILE=FULL -DQSC_BUILD_PROFILE_TESTS=ON
cmake --build build/qsc/macos-full --parallel 4
ctest --test-dir build/qsc/macos-full --output-on-failure
```

macOS and native ARM64 builds were **not** executed for this review. Cross-compilation requires a suitable CMake toolchain file and target-system SDK; merely changing `QSC_CPU_TARGET` does not provide a cross-compiler or emulate target hardware.

## 14. Troubleshooting

| Symptom | Likely cause | Corrective action |
|---|---|---|
| `Cannot locate QSC/qsccommon.h` | Root CMake files installed in wrong directory or library elsewhere | Move overlay beside `QSCTest.sln`, or set `QSC_LIBRARY_DIR` |
| `QSC_LIBRARY_DIR does not contain QSC.vcxproj` | Wrong library directory or different source snapshot | Point at the actual library project; verify `QSC.vcxproj` exists |
| `Unclassified QSC library source` | New `.c` file added after inventory was generated | Update `QSCSources.cmake` and relevant profiles; do **not** disable validation just to hide a missing module |
| `Unsupported QSC_PROFILE` | Typo or unsupported profile name | Use an exact name from Section 5 |
| `QSC_PROFILE=CUSTOM requires QSC_CUSTOM_ALGORITHMS` | Custom profile has no algorithms | Supply one or more supported IDs |
| `Unknown QSC hardware provider` | Provider name unsupported or mistyped | Use the documented provider IDs |
| `QSC_HARDWARE_PROVIDERS requires QSC_ENABLE_HARDWARE=ON` | Adapter selected without enabling hardware core | Set `-DQSC_ENABLE_HARDWARE=ON` |
| `NCRYPT is Windows-only` | Windows provider selected on Linux/macOS | Use Windows or another applicable provider |
| TPM2-TSS package discovery failure | Missing `pkg-config` or TPM2-TSS development libraries | Install/select compatible tss2-esys and tss2-tctildr SDKs |
| PSA native header/library missing | Incorrect `QSC_PSA_INCLUDE_DIR` or `QSC_PSA_LIBRARY` | Point at the correct SDK header root and link library |
| Ninja generator not found | Ninja not installed or not on `PATH` | Install Ninja or configure manually with another generator |
| MSVC compiler not detected | Not running a configured developer shell | Use Visual Studio developer tools or select an installed VS generator |
| Unresolved compact-profile symbol | API referenced but its implementation excluded | Expand the profile/custom algorithm set and validate dependencies |
| Test executable cannot load `.dll`/`.so`/`.dylib` | Runtime library search path or deployment packaging | Deploy the library with the executable or configure the loader search path |
| `find_package(QSC)` cannot locate the SDK | Installation prefix not discoverable | Set `CMAKE_PREFIX_PATH` or `QSC_DIR` to installed package location |
| CMake cache appears inconsistent after a profile or compiler change | Cached configuration from earlier build | Use a fresh build directory; don't reuse incompatible caches |
| AVX2 binary fails on older hardware | CPU lacks required instruction support | Rebuild with `QSC_CPU_TARGET=BASELINE` and qualify the target |

When diagnosing a build failure, capture the **first** compiler/linker error rather than only the final summary. Record the profile, compiler/toolchain, architecture, build kind, hardware options and generated manifest with the issue report.

## 15. Source maintenance and extension

The CMake implementation intentionally keeps the authoritative cryptographic source files and existing Visual Studio projects untouched. Changes to the build infrastructure should be reviewed independently of cryptographic implementation changes.

To add a new QSC primitive:

1. Add the implementation to `QSCSources.cmake` and maintain parity with the Visual Studio project when appropriate.
2. Determine whether it can be linked as an independent translation unit or depends on a parameterized facade, included implementation `.c`, shared `.inc`, or another primitive.
3. Add its profile and custom algorithm dependencies in `QSCProfiles.cmake`.
4. Update provider selection in `QSCHardware.cmake` only if hardware implementation support is actually present.
5. Extend the generated feature manifest and add named, directly invoked PASS/FAIL smoke cases where appropriate.
6. Build the full library and every affected compact profile on all supported platforms; rerun qualification before release.

To add a new application profile, prefer composition of already-supported primitives. Do not create duplicate cryptographic implementations or replace the existing optimized QSC paths without separate engineering authorization.

**Do not modify protected external dependencies, crypto APIs, test-suite behavior or project licenses as an incidental part of CMake maintenance.** Follow the repository's QRCS coding/documentation standard for new C/C++ source and header files.

## 16. Current limitations and release gates

The following are **not** established by this integration package:

- Native **Windows/MSVC** DLL export/import correctness, consumer ABI compatibility or full Windows tests.
- Native **macOS** or **ARM64** build/test completion.
- Real HSM, TPM, secure element, or PSA device initialization, authorization and private-key custody.
- Full QSC primitive regression suites, platform-specific KAT coverage, sanitizer results, timing parity, constant-time/side-channel assessment, or ACVP/FIPS validation.
- TLS 1.3 complete interoperability, certificate chain handling and compliance under all required algorithm combinations.
- Client-only or server-only TLS pruning, per-algorithm TLS removal, or elimination of signing routines from verification-named profiles.
- A verified flash/RAM/stack footprint for embedded devices, or actual benchmark parity on every ISA target.
- Automotive, industrial-control, robotics or AI-update protocol compliance derived from profile names.

The provided [QUALIFICATION.md](QUALIFICATION.md) identifies the tests executed on the earlier source snapshot and describes outstanding work. Treat that evidence as an **integration baseline** rather than an independent laboratory qualification or permission to deploy an untested profile.

Before adopting this overlay into the QSC main repository, verify full-library equivalence, test coverage, selected hardware mechanisms, production import/export behavior, SDK packaging, ABI and standards claims against the actual release target.

## 17. Licensing and integration policy

This CMake overlay is **build infrastructure**. It does not grant new permissions or amend the QSC license. The applicable source and product licensing terms are those supplied with the authorized QSC distribution; commercial production and redistribution require the appropriate QRCS authorization.

Keep existing QRCS copyright and license notices verbatim in all C/C++ implementation and header files. Hardware vendor SDKs and optional native libraries retain their own license and deployment requirements. Building an optional HSM adapter does not transfer rights to proprietary vendor middleware.

For engineering evidence, profile changes, and qualifying new configurations, use `cmake/QUALIFICATION.md` alongside the established QSC test and release procedures.
