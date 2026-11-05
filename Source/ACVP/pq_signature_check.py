#!/usr/bin/env python3
"""Record native FIPS204/205 ACVP adapter regression results without exposing keys."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def main() -> int:
    """Execute nine individually named signature tests and persist sanitized evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    if args.output.resolve().is_relative_to(repository.resolve()):
        parser.error("Qualification evidence must be outside the source tree")
    if not args.library.is_file():
        parser.error("QSC PQ library is missing")
    environment = dict(os.environ)
    environment["QSC_ACVP_PQ_LIBRARY"] = str(args.library.resolve())
    command = [sys.executable, "-m", "unittest", "discover", "-s",
               str(Path(__file__).parent / "tests"), "-p", "test_pq_signature_native.py", "-v"]
    result = subprocess.run(command, cwd=repository, env=environment,
                            capture_output=True, text=True, timeout=240, check=False)
    output = result.stdout + result.stderr
    match = re.search(r"Ran (\d+) tests", output)
    count = int(match.group(1)) if match else 0
    passed = result.returncode == 0 and count == 9 and output.splitlines()[-1:] == ["OK"]
    record = {"type": "OFFLINE_PQ_SIGNATURE_ACVP_ADAPTER_NOT_NIST",
              "status": "PASS_LOCAL_ADAPTER_ONLY" if passed else "FAIL",
              "native_tests": count, "mldsa_parameter_sets": 3, "slhdsa_parameter_sets": 6,
              "nist_demo_verdict": "NOT_RUN"}
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "pq-signature-results.json").write_text(
        json.dumps(record, indent=2) + "\n", encoding="utf-8")
    (args.output / "pq-signature.log").write_text(output, encoding="utf-8")
    print(f"QSC ML-DSA/SLH-DSA ACVP adapter: {record['status']}; tests={count}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
