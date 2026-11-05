#!/usr/bin/env python3
"""Execute the native ML-KEM ACVP-adapter test suite with fail-closed evidence."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def main() -> int:
    """Run exactly the three parameter-set tests and retain a sanitized result."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    if args.output.resolve().is_relative_to(root.resolve()):
        parser.error("Qualification evidence must be outside the repository")
    if not args.library.is_file():
        parser.error("Compiled QSC PQ shared library not found")
    environment = dict(os.environ)
    environment["QSC_ACVP_PQ_LIBRARY"] = str(args.library.resolve())
    command = [sys.executable, "-m", "unittest", "discover", "-s",
               str(Path(__file__).parent / "tests"), "-p", "test_mlkem_native.py", "-v"]
    result = subprocess.run(command, cwd=root, env=environment,
                            capture_output=True, text=True, timeout=90, check=False)
    log = result.stdout + result.stderr
    match = re.search(r"Ran (\d+) tests", log)
    count = int(match.group(1)) if match else 0
    passed = (result.returncode == 0 and count == 3 and
              log.splitlines()[-1:] == ["OK"] and "skipped=" not in log)
    record = {"type": "OFFLINE_MLKEM_ACVP_ADAPTER_NOT_NIST",
              "status": "PASS_LOCAL_ADAPTER_ONLY" if passed else "FAIL",
              "native_tests": count, "parameter_sets": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
              "nist_demo_verdict": "NOT_RUN"}
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "mlkem-results.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    (args.output / "mlkem.log").write_text(log, encoding="utf-8")
    print(f"ML-KEM ACVP adapter: {record['status']} ({count} parameter-set tests)")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
