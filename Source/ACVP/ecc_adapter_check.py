#!/usr/bin/env python3
# 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
# All Rights Reserved.
#  *
# NOTICE:
# This software and all accompanying materials are the exclusive property of
# Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
# and technical concepts contained herein are proprietary to QRCS and are
# protected under applicable Canadian, U.S., and international copyright,
# patent, and trade secret laws.
#  *
# CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
# - This software includes implementations of cryptographic primitives and
#   algorithms that are standardized or in the public domain, such as AES
#   and SHA-3, which are not proprietary to QRCS.
# - This software also includes cryptographic primitives, constructions, and
#   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
#   related components, which are proprietary to QRCS.
# - All source code, implementations, protocol compositions, optimizations,
#   parameter selections, and engineering work contained in this software are
#   original works of QRCS and are protected under this license.
#  *
# LICENSE AND USE RESTRICTIONS:
# - This software is licensed under the Quantum Resistant Cryptographic Solutions
#   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
# - Permission is granted solely for non-commercial evaluation, academic research,
#   cryptographic analysis, interoperability testing, and feasibility assessment.
# - Commercial use, production deployment, commercial redistribution, or
#   integration into products or services is strictly prohibited without a
#   separate written license agreement executed with QRCS.
# - Licensing and authorized distribution are solely at the discretion of QRCS.
#  *
# EXPERIMENTAL CRYPTOGRAPHY NOTICE:
# Portions of this software may include experimental, novel, or evolving
# cryptographic designs. Use of this software is entirely at the user's risk.
#  *
# DISCLAIMER:
# THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
# LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
# ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
#  *
# FULL LICENSE:
# This software is subject to the Quantum Resistant Cryptographic Solutions
# Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
# are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
#  *
# Written by: John G. Underhill
# Contact: contact@qrcscorp.ca
#

"""Execute native QSC ECC ACVP adapter tests and save sanitized offline evidence."""

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]


def main():
    """Run one named ECC suite, requiring all expected checks and explicit P-384 state."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--complete", action="store_true")
    arguments = parser.parse_args()
    if not arguments.library.is_file():
        parser.error("Native QSC ECC library is missing")
    if arguments.output.resolve().is_relative_to(ROOT):
        parser.error("Evidence must be written outside the repository")
    environment = os.environ.copy()
    environment["QSC_ACVP_ECC_LIBRARY"] = str(arguments.library.resolve())
    environment["QSC_ACVP_ECC_COMPLETE"] = "1" if arguments.complete else "0"
    process = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", str(Path(__file__).parent / "tests"),
         "-p", "test_ecc_vectors.py", "-v"],
        text=True, capture_output=True, timeout=120, check=False, env=environment)
    output = process.stdout + process.stderr
    total = re.search(r"Ran (\d+) tests? in", output)
    skips = re.search(r"skipped=(\d+)", output)
    expected_skips = 0 if arguments.complete else 2
    skipped_count = int(skips.group(1)) if skips else 0
    passed = (process.returncode == 0 and total is not None and
              int(total.group(1)) == 33 and skipped_count == expected_skips and
              re.search(r"^OK", output, re.MULTILINE) is not None)
    result = {"type": "OFFLINE_ECC_ACVP_ADAPTER_NOT_NIST",
              "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "status": "PASS_LOCAL_ADAPTER_ONLY" if passed and arguments.complete else
                        "PASS_PRELIMINARY_P384_PENDING" if passed else "FAIL",
              "total_tests": int(total.group(1)) if total else 0,
              "skipped_tests": skipped_count,
              "ecdsa_p384": "TESTED" if arguments.complete else "PENDING_SOURCE_UPDATE",
              "authenticated_nist_demo": "NOT_RUN"}
    arguments.output.mkdir(parents=True, exist_ok=True)
    (arguments.output / "ecc-acvp-adapter-results.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8")
    (arguments.output / "ecc-acvp-adapter.log").write_text(output, encoding="utf-8")
    print(f"ECC ACVP adapter: {result['status']} | tests={result['total_tests']} "
          f"| pending={result['skipped_tests']}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
