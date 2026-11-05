"""Parser failure-detection tests for QSC offline qualification reports."""
import importlib.util
from pathlib import Path
import unittest

RUNNER = Path(__file__).resolve().parents[1] / "run.py"
spec = importlib.util.spec_from_file_location("qsc_acvp_runner", RUNNER)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class RunnerDetectionTests(unittest.TestCase):
    def test_missing_all_suite_headers_fail(self):
        records = runner.classify("")
        self.assertEqual(len(records), 6)
        self.assertTrue(all(row["status"] == "FAIL" for row in records))

    def test_failure_marker_overrides_success(self):
        log = "\n".join(["Running the NIST CAVP AES tests"] +
                        ["Success! Passed an AES aggregate"] * 8 +
                        ["Failure! Failed AES negative test"])
        self.assertEqual(runner.classify(log)[0]["status"], "FAIL")

    def test_insufficient_success_markers_fail(self):
        log = "Running the NIST CAVP SHA2 tests\nSuccess! Passed one group\n"
        self.assertEqual(runner.classify(log)[1]["status"], "FAIL")

    def test_detects_duplicate_suite_headers(self):
        log = ("Running the NIST CAVP AES tests\n" * 2)
        self.assertEqual(runner.classify(log)[0]["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
