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

"""Build and execute each QSC offline qualification stage consecutively.

Never substitutes a preliminary curve library for a complete qualification.
All stages are attempted; missing implementations and failures are recorded.
"""

import argparse
import datetime as dt
import json
import os
import re
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
TOOLS = Path(__file__).resolve().parent


class Qualification:
    """Collect a fixed-order record of isolated, fail-closed test executions."""

    def __init__(self, build: Path, output: Path, security_class: str, ready: bool):
        self.build = build.resolve()
        self.output = output.resolve()
        self.security_class = security_class
        self.ready = ready
        self.stages = []
        self.environment = dict(os.environ)
        self.environment["PYTHONDONTWRITEBYTECODE"] = "1"
        self.environment["QSC_ACVP_HASH_LIBRARY"] = str(self.library("qsc_acvp_hash"))
        self.environment["QSC_ACVP_AES_LIBRARY"] = str(self.library("qsc_acvp_aes"))
        self.environment["QSC_ACVP_PQ_LIBRARY"] = str(self.library("qsc_acvp_pq"))
        self.environment["QSC_ACVP_ECC_LIBRARY"] = str(self.library(
            "qsc_acvp_ecc" if ready else "qsc_acvp_ecc_preliminary"))
        self.environment["QSC_ACVP_ECC_COMPLETE"] = "1" if ready else "0"

    def library(self, name: str) -> Path:
        """Resolve a CMake shared-library artifact without searching source directories."""
        if os.name == "nt":
            return self.build / "Release" / (name + ".dll")
        if sys.platform == "darwin":
            return self.build / ("lib" + name + ".dylib")
        return self.build / ("lib" + name + ".so")

    def binary(self) -> Path:
        """Return the complete CAVP target's expected binary location."""
        if os.name == "nt":
            return self.build / "Release" / "qsc_cavp.exe"
        return self.build / "qsc_cavp"

    def run_stage(self, name: str, command: list[str], timeout: int = 300,
                  available: bool = True) -> None:
        """Run one named stage and preserve its exact exit status and diagnostics."""
        log_path = self.output / (name + ".log")
        if not available:
            log_path.write_text("Required complete implementation is not available.\n", encoding="utf-8")
            self.stages.append({"name": name, "status": "PENDING_SOURCE_UPDATE",
                                "returncode": None, "log": log_path.name})
            return
        status = "FAIL"
        code = None
        with log_path.open("w", encoding="utf-8") as stream:
            try:
                completed = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT,
                                           env=self.environment, cwd=ROOT, timeout=timeout,
                                           check=False, text=True)
                code = completed.returncode
                if code == 0:
                    status = "PASS"
            except subprocess.TimeoutExpired:
                stream.write("\nFAIL: qualification stage exceeded its timeout.\n")
            except OSError as error:
                stream.write("\nFAIL: process execution unavailable: " + type(error).__name__ + "\n")
        if name == "python-regression" and status == "PASS":
            output = log_path.read_text(encoding="utf-8", errors="replace")
            if re.search(r"OK \(skipped=[1-9][0-9]*\)", output):
                status = "FAIL" if self.ready else "PENDING_SOURCE_UPDATE"
        if name == "ecc-acvp" and status == "PASS" and not self.ready:
            status = "PENDING_SOURCE_UPDATE"
        self.stages.append({"name": name, "status": status,
                            "returncode": code, "log": log_path.name})
        print(f"{name}: {status}", flush=True)

    def save(self) -> bool:
        """Persist exactly the executed stages without claiming NIST validation."""
        success = len(self.stages) == 11 and all(
            item["status"] == "PASS" for item in self.stages)
        record = {"type": "OFFLINE_STAGE_EXECUTION_NOT_ACVTS",
                  "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                  "security_class": self.security_class,
                  "git_sha": os.environ.get("GITHUB_SHA", "not-recorded"),
                  "qsc_git_sha": os.environ.get("QSC_DEPENDENCY_SHA", "not-recorded"),
                  "status": "PASS" if success else "FAIL_OR_INCOMPLETE",
                  "p384_complete_source": self.ready, "nist_demo": "NOT_RUN",
                  "stages": self.stages}
        (self.output / "qualify-all.json").write_text(
            json.dumps(record, indent=2) + "\n", encoding="utf-8")
        legacy = next((item for item in self.stages
                       if item["name"] == "legacy-cavp"), None)
        if legacy is not None and legacy["status"] != "PASS" and not (
                self.output / "results.json").is_file():
            (self.output / "results.json").write_text(
                json.dumps({"type": "OFFLINE_CAVP_NOT_ACVTS", "status": "NOT_RUN",
                            "security_class": self.security_class, "suites": [],
                            "reason": "Complete CAVP target unavailable or unsuccessful"},
                           indent=2) + "\n", encoding="utf-8")
        rows = ["# QSC consecutive offline qualification", "",
                "Offline evidence only; not a NIST ACVTS verdict.", "",
                "| Stage | Status | Exit |", "|---|---|---|"]
        for stage in self.stages:
            rows.append(f"| {stage['name']} | {stage['status']} | {stage['returncode']} |")
        rows.extend(["", "Overall: **" + record["status"] + "**", ""])
        (self.output / "qualify-all.md").write_text("\n".join(rows), encoding="utf-8")
        return success


def main() -> int:
    """Execute the complete named suite in a fixed, explicit order."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--security-class", required=True, choices=("1", "3", "5"))
    parser.add_argument("--full-build", required=True, choices=("success", "failed", "pending"))
    args = parser.parse_args()
    if args.output.resolve().is_relative_to(ROOT.resolve()):
        parser.error("Runtime artifacts must remain outside the source tree")
    args.output.mkdir(parents=True, exist_ok=True)
    complete = args.full_build == "success"
    q = Qualification(args.build_dir, args.output, args.security_class, complete)
    py = sys.executable
    hash_lib = q.library("qsc_acvp_hash")
    aes_lib = q.library("qsc_acvp_aes")
    pq_lib = q.library("qsc_acvp_pq")
    ecc_lib = q.library("qsc_acvp_ecc" if complete else "qsc_acvp_ecc_preliminary")
    suite = TOOLS / "tests"

    q.run_stage("python-regression", [py, "-m", "unittest", "discover", "-s",
                                      str(suite), "-v"], timeout=420)
    q.run_stage("sha-hmac", [py, str(TOOLS / "local_check.py"),
                              "--library", str(hash_lib), "--output", str(q.output)], timeout=180)
    q.run_stage("aes", [py, str(TOOLS / "aes_check.py"),
                         "--library", str(aes_lib), "--output", str(q.output)], timeout=200)
    q.run_stage("cshake-kmac", [py, str(TOOLS / "xof_check.py"),
                                 "--library", str(hash_lib), "--output", str(q.output)], timeout=180)
    q.run_stage("pbkdf-hkdf-kda", [py, str(TOOLS / "kdf_check.py"),
                                    "--library", str(hash_lib), "--output", str(q.output)], timeout=240)
    q.run_stage("ecc-interoperability", [py, str(TOOLS / "ecc_check.py"),
                                          "--library", str(ecc_lib), "--output", str(q.output)], timeout=300)
    ecc_cmd = [py, str(TOOLS / "ecc_adapter_check.py"),
               "--library", str(ecc_lib), "--output", str(q.output)]
    if complete:
        ecc_cmd.append("--complete")
    q.run_stage("ecc-acvp", ecc_cmd, timeout=220)
    q.run_stage("pq-smoke", [py, str(TOOLS / "pq_check.py"),
                              "--library", str(pq_lib), "--output", str(q.output)], timeout=360)
    q.run_stage("mlkem-acvp", [py, str(TOOLS / "mlkem_check.py"),
                                "--library", str(pq_lib), "--output", str(q.output)], timeout=180)
    q.run_stage("mldsa-slhdsa-acvp", [py, str(TOOLS / "pq_signature_check.py"),
                                       "--library", str(pq_lib), "--output", str(q.output)], timeout=340)
    q.run_stage("legacy-cavp", [py, str(TOOLS / "run.py"),
                                 "--binary", str(q.binary()), "--security-class",
                                 args.security_class, "--output", str(q.output)],
                timeout=4000, available=complete)
    return 0 if q.save() else 1


if __name__ == "__main__":
    sys.exit(main())
