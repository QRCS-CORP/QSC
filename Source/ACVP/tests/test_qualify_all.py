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

"""Verify fixed-order, fail-closed QSC qualification orchestration."""

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "qualify_all.py"
SPEC = importlib.util.spec_from_file_location("qsc_qualify_all", SCRIPT)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class QualificationOrchestrationTests(unittest.TestCase):
    def test_success_stage_records_real_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            qualification = runner.Qualification(root / "build", root, "3", True)
            with patch.object(runner.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)):
                qualification.run_stage("python-regression", ["echo", "pass"])
            self.assertEqual(qualification.stages[0]["status"], "PASS")
            self.assertEqual(qualification.stages[0]["returncode"], 0)
            self.assertTrue((root / "python-regression.log").is_file())

    def test_failed_stage_does_not_abort_next_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            qualification = runner.Qualification(root / "build", root, "3", True)
            with patch.object(runner.subprocess, "run", side_effect=[
                    subprocess.CompletedProcess([], 2), subprocess.CompletedProcess([], 0)]):
                qualification.run_stage("python-regression", ["false"])
                qualification.run_stage("sha-hmac", ["true"])
            self.assertEqual([stage["status"] for stage in qualification.stages],
                             ["FAIL", "PASS"])
            self.assertFalse(qualification.save())

    def test_pending_source_is_never_a_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            qualification = runner.Qualification(root / "build", root, "1", False)
            qualification.run_stage("legacy-cavp", ["should-not-run"], available=False)
            self.assertEqual(qualification.stages[0]["status"], "PENDING_SOURCE_UPDATE")
            self.assertFalse(qualification.save())

    def test_timeout_is_failure_and_subsequent_stage_can_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            qualification = runner.Qualification(root / "build", root, "5", True)
            with patch.object(runner.subprocess, "run", side_effect=[
                    subprocess.TimeoutExpired("test", 1), subprocess.CompletedProcess([], 0)]):
                qualification.run_stage("python-regression", ["timeout"])
                qualification.run_stage("sha-hmac", ["success"])
            self.assertEqual(qualification.stages[0]["status"], "FAIL")
            self.assertEqual(qualification.stages[1]["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
