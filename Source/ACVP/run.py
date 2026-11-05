#!/usr/bin/env python3
"""Execute QSC's existing CAVP harness, preserving negative results.

This is an offline evidence runner, not an ACVTS Demo client or certificate.
The CAVP application reports failures in its output but does not return a
meaningful exit status; this wrapper checks every named suite and test result.
"""

import argparse
import datetime as dt
import hashlib
import html
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SUITES = (
    ("AES", r"Running the NIST CAVP AES tests", 8),
    ("SHA-2 and HMAC", r"Running the NIST CAVP SHA2 tests", 3),
    ("SHA-3 and SHAKE", r"Running the NIST CAVP SHA3 tests", 4),
    ("ML-KEM legacy interface", r"Running the NIST ACVP ML-KEM tests", 2),
    ("ML-DSA legacy interface", r"Running the NIST (?:ACVP|CAVP) ML-DSA tests", 2),
    ("SLH-DSA legacy interface", r"Running the NIST CAVP SLH-DSA tests", 2),
)
# These are not silently promoted into ACVP passes.
UNIMPLEMENTED = (
    "Full ECC ACVP server verdicts; selected ECDSA/EDDSA/XECDH/KAS adapters are offline-tested",
    "NIST ACVP live verdicts for dedicated ML-KEM/ML-DSA/SLH-DSA APIs (offline vector adapters run separately)",
    "KMAC/cSHAKE full ACVP coverage (offline AFT only); HKDF SP800-56C KDA (RFC 5869 primitive checks only); PBKDF full NIST server verdict",
    "additional AES variable-tag and nonbyte-aligned configurations",
)
FAILURE = re.compile(r"(?:^Failure!|\bfailed\b|\berror:)", re.IGNORECASE)
SUCCESS = re.compile(r"^Success! Passed ", re.IGNORECASE)


def default_output() -> Path:
    """Choose an approved transient output directory, never the source tree."""
    root = os.environ.get("RUNNER_TEMP") or os.environ.get("TEMP")
    if not root:
        if os.name == "nt":
            root = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
        else:
            root = "/var/tmp/" + os.environ.get("USER", "qsc")
    return Path(root) / "qsc-acvp" / "offline"


def classify(log: str) -> list[dict]:
    """Fail closed when suites or required aggregate success lines are missing."""
    records = []
    lines = log.splitlines()
    matches = []
    for name, expression, minimum in SUITES:
        locations = [i for i, line in enumerate(lines) if re.search(expression, line)]
        matches.append((name, minimum, locations))
    for index, (name, minimum, locations) in enumerate(matches):
        if len(locations) != 1:
            records.append({"name": name, "status": "FAIL", "success_markers": 0,
                            "diagnostics": [f"Expected exactly one suite header; found {len(locations)}"]})
            continue
        start = locations[0]
        next_headers = [n[2][0] for n in matches[index + 1:] if n[2]]
        end = min(next_headers) if next_headers else len(lines)
        segment = lines[start:end]
        failures = [line.strip() for line in segment if FAILURE.search(line)]
        successes = sum(1 for line in segment if SUCCESS.search(line))
        if successes < minimum:
            failures.append(f"Found {successes} Success markers; expected at least {minimum}")
        records.append({"name": name, "status": "PASS" if not failures else "FAIL",
                        "success_markers": successes, "diagnostics": failures})
    return records


def render_markdown(data: dict) -> str:
    lines = ["# QSC offline CAVP qualification", "",
             "This is **offline vector evidence**, not a NIST ACVP server verdict or CAVP certificate.", "",
             f"Run UTC: {data['timestamp_utc']}",
             f"Platform: {data['platform']}",
             f"Security class: {data['security_class']}",
             f"Source SHA-256: {data['source_digest']}",
             f"Harness SHA-256: {data['harness_digest']}", "",
             "| Suite | Status | Success markers |", "|---|---|---:|"]
    for item in data["suites"]:
        lines.append(f"| {item['name']} | {item['status']} | {item['success_markers']} |")
    lines += ["", "## Unexecuted algorithm coverage", ""]
    for item in data["not_run"]:
        lines.append(f"- NOT RUN: {item}")
    lines += ["", "## Failure diagnostics", ""]
    for item in data["suites"]:
        for diagnostic in item["diagnostics"]:
            lines.append(f"- {item['name']}: {diagnostic}")
    lines += ["", f"Overall offline runner: **{data['status']}**", ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="Built qsc_cavp executable")
    parser.add_argument("--output", type=Path, default=default_output())
    parser.add_argument("--security-class", choices=("1", "3", "5"), default="3")
    parser.add_argument("--timeout", type=int, default=3600)
    args = parser.parse_args()

    if not args.binary.is_file():
        parser.error(f"Missing executable: {args.binary}")
    if not (ROOT / "dependency" / "QSC" / "Source" / "CAVP" / "KAT").is_dir():
        parser.error("CAVP/KAT is missing; expected dependency/QSC/Source/CAVP/KAT")

    if args.output.resolve().is_relative_to(ROOT.resolve()):
        parser.error("Reports must be written outside the repository")
    args.output.mkdir(parents=True, exist_ok=True)
    result = None
    error = None
    log_path = args.output / "cavp.log"
    try:
        environment = os.environ.copy()
        environment["QSC_CAVP_NONINTERACTIVE"] = "1"
        with log_path.open("wb") as stream:
            result = subprocess.run([str(args.binary.resolve())], stdin=subprocess.DEVNULL,
                                    stdout=stream, stderr=subprocess.STDOUT, env=environment,
                                    cwd=ROOT / "dependency" / "QSC" / "Source" / "CAVP", timeout=args.timeout, check=False)
    except subprocess.TimeoutExpired:
        error = f"Executable exceeded {args.timeout} seconds"
    except OSError as exc:
        error = f"Unable to execute CAVP: {exc}"
    log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.is_file() else ""
    if error and not log:
        log = error

    suites = classify(log)
    if error is not None:
        suites.append({"name": "Harness execution", "status": "FAIL", "success_markers": 0,
                       "diagnostics": [error]})
    if result is not None and result.returncode != 0:
        suites.append({"name": "Harness exit code", "status": "FAIL", "success_markers": 0,
                       "diagnostics": [f"Process exited with code {result.returncode}"]})

    qsc_header = ROOT / "dependency" / "QSC" / "Source" / "QSC" / "qsccommon.h"
    data = {
        "type": "OFFLINE_CAVP_NOT_ACVTS",
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "platform": platform.platform(),
        "security_class": args.security_class,
        "git_sha": os.environ.get("GITHUB_SHA", "not-recorded"),
        "qsc_git_sha": os.environ.get("QSC_DEPENDENCY_SHA", "not-recorded"),
        "source_digest": hashlib.sha256(qsc_header.read_bytes()).hexdigest(),
        "harness_digest": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "suites": suites,
        "not_run": list(UNIMPLEMENTED),
        "status": "PASS_WITH_COVERAGE_GAPS" if all(x["status"] == "PASS" for x in suites) else "FAIL",
    }
    if not log_path.exists():
        log_path.write_text(log, encoding="utf-8")
    (args.output / "results.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    report = render_markdown(data)
    (args.output / "report.md").write_text(report, encoding="utf-8")
    (args.output / "report.html").write_text(
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<title>QSC offline CAVP qualification</title><body><pre>" +
        html.escape(report) + "</pre></body></html>\n", encoding="utf-8")
    print(report)
    return 0 if data["status"] == "PASS_WITH_COVERAGE_GAPS" else 1


if __name__ == "__main__":
    sys.exit(main())
