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

"""Execute native QSC cSHAKE/KMAC adapter KATs and write offline evidence."""

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
    """Run the named SP 800-185 suite; distinguish skips and absent tests."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.library.is_file():
        parser.error("Native QSC SHA3/KMAC library is missing")
    if args.output.resolve().is_relative_to(ROOT):
        parser.error("Evidence must be stored outside source checkout")
    env = os.environ.copy()
    env["QSC_ACVP_HASH_LIBRARY"] = str(args.library.resolve())
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", str(Path(__file__).parent / "tests"),
         "-p", "test_xof_vectors.py", "-v"],
        text=True, capture_output=True, timeout=120, check=False, env=env)
    output = result.stdout + result.stderr
    count = re.search(r"Ran (\d+) tests? in", output)
    passed = (result.returncode == 0 and count is not None and
              int(count.group(1)) == 9 and re.search(r"^OK$", output, re.MULTILINE) is not None)
    report = {"type": "OFFLINE_SP800_185_ACVP_ADAPTER_NOT_NIST",
              "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "status": "PASS_LOCAL_ADAPTER_ONLY" if passed else "FAIL",
              "test_functions": int(count.group(1)) if count else 0,
              "authenticated_nist_demo": "NOT_RUN",
              "full_acvp_coverage": "NOT_IMPLEMENTED"}
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "xof-acvp-adapter-results.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (args.output / "xof-acvp-adapter.log").write_text(output, encoding="utf-8")
    print(f"SP 800-185 ACVP offline adapter: {report['status']}, {report['test_functions']} tests")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
