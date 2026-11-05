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

"""Fail-closed checks for QSC offline evidence consolidation."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "combine.py"
SPEC = importlib.util.spec_from_file_location("qsc_combine", SCRIPT)
combine = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(combine)


class ConsolidationIntegrityTests(unittest.TestCase):
    def test_expected_matrix_has_six_unique_jobs(self):
        self.assertEqual(len(combine.EXPECTED), 6)
        self.assertIn("qsc-offline-windows-2022-class-5", combine.EXPECTED)

    def test_untrusted_results_cannot_override_checked_fields(self):
        forged = {"status": "PASS_WITH_COVERAGE_GAPS", "job": "injected",
                  "security_class": "5", "ecc_acvp_adapter_pass": True,
                  "local_sha_simulation_pass": True}
        verified = {"job": "real", "ecc_acvp_adapter_pass": False,
                    "local_sha_simulation_pass": False}
        merged = combine.checked_record(forged, verified)
        self.assertEqual(merged["job"], "real")
        self.assertFalse(merged["ecc_acvp_adapter_pass"])
        self.assertFalse(merged["local_sha_simulation_pass"])

    def test_v11_ecc_contract_requires_all_33_unskipped_tests(self):
        good = {"type": "OFFLINE_ECC_ACVP_ADAPTER_NOT_NIST",
                "status": "PASS_LOCAL_ADAPTER_ONLY", "total_tests": 33,
                "skipped_tests": 0, "ecdsa_p384": "TESTED"}
        self.assertTrue(combine.ecc_adapter_passes(good))
        for mutation in ({"total_tests": 24}, {"skipped_tests": 2},
                         {"ecdsa_p384": "PENDING_SOURCE_UPDATE"},
                         {"status": "PASS_PRELIMINARY_P384_PENDING"}):
            with self.subTest(mutation=mutation):
                self.assertFalse(combine.ecc_adapter_passes({**good, **mutation}))

    def test_required_stage_must_have_successful_exit_and_log(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qualify-all.json"
            self.assertFalse(combine.all_stages_pass(path))
            good = {"type": "OFFLINE_STAGE_EXECUTION_NOT_ACVTS",
                    "status": "PASS", "stages": [
                        {"name": name, "status": "PASS", "returncode": 0,
                         "log": name + ".log"}
                        for name in combine.REQUIRED_STAGES]}
            for stage in good["stages"]:
                (path.parent / stage["log"]).write_text("PASS\n", encoding="utf-8")
            path.write_text(json.dumps(good), encoding="utf-8")
            self.assertTrue(combine.all_stages_pass(path))
            good["stages"][0]["status"] = "SKIPPED"
            path.write_text(json.dumps(good), encoding="utf-8")
            self.assertFalse(combine.all_stages_pass(path))


if __name__ == "__main__":
    unittest.main()
