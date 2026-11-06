#!/usr/bin/env python3
"""Combine offline QSC evidence, failing closed on incomplete runner matrices."""

import argparse
import json
from pathlib import Path
import re
import sys

EXPECTED = {f"qsc-offline-{os}-class-{klass}"
            for os in ("ubuntu-24.04", "windows-2022") for klass in ("1", "3", "5")}


# A complete job must execute each named suite, regardless of individual failures.
REQUIRED_STAGES = (
    "python-regression", "sha-hmac", "aes", "cshake-kmac", "pbkdf-hkdf-kda",
    "ecc-interoperability", "ecc-acvp", "pq-smoke", "mlkem-acvp",
    "mldsa-slhdsa-acvp", "legacy-cavp",
)


def checked_record(untrusted: dict, verified: dict) -> dict:
    """Keep collected data, but never let a report override a verified result."""
    return {**untrusted, **verified}


def ecc_adapter_passes(data: dict) -> bool:
    """Require every v11 ECC operation including P-384, with zero skips."""
    return (data.get("type") == "OFFLINE_ECC_ACVP_ADAPTER_NOT_NIST"
            and data.get("status") == "PASS_LOCAL_ADAPTER_ONLY"
            and data.get("total_tests") == 33
            and data.get("skipped_tests") == 0
            and data.get("ecdsa_p384") == "TESTED")


def source_revision_matches(result: dict, stage: dict, expected_sha: str | None) -> bool:
    """Reject missing, malformed, inconsistent or unexpected QSC source commits."""
    source_sha = result.get("qsc_git_sha")
    return (isinstance(source_sha, str)
            and re.fullmatch(r"[0-9a-f]{40}", source_sha) is not None
            and source_sha == stage.get("qsc_git_sha")
            and (expected_sha is None or source_sha == expected_sha))


def all_stages_pass(path: Path) -> bool:
    """Reject absent, malformed, duplicated, skipped, or failing stage records."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if data.get("type") != "OFFLINE_STAGE_EXECUTION_NOT_ACVTS" or data.get("status") != "PASS":
        return False
    stages = data.get("stages")
    if not isinstance(stages, list) or len(stages) != len(REQUIRED_STAGES):
        return False
    if [item.get("name") for item in stages] != list(REQUIRED_STAGES):
        return False
    for item in stages:
        name = item.get("name")
        if (item.get("status") != "PASS" or type(item.get("returncode")) is not int
                or item["returncode"] != 0 or item.get("log") != name + ".log"
                or not (path.parent / item["log"]).is_file()):
            return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--local", action="store_true", help="Allow partial local evidence, not CI")
    parser.add_argument("--expected-qsc-sha", help="Immutable source commit shared by all jobs")
    args = parser.parse_args()
    if args.expected_qsc_sha is None and not args.local:
        parser.error("CI consolidation requires --expected-qsc-sha")
    if args.expected_qsc_sha is not None and not re.fullmatch(r"[0-9a-f]{40}", args.expected_qsc_sha):
        parser.error("--expected-qsc-sha must be a 40-character lowercase commit SHA")
    root = Path(__file__).resolve().parents[2]
    if args.output.resolve().is_relative_to(root.resolve()):
        parser.error("Reports must be written outside the repository")
    results = []
    present = set()
    for directory in sorted(args.input.glob("qsc-offline-*")):
        record = directory / "results.json"
        if record.is_file():
            try:
                result = json.loads(record.read_text(encoding="utf-8"))
                if not isinstance(result, dict):
                    raise ValueError("Qualification result must be an object")
            except (ValueError, OSError) as exc:
                result = {"status": "FAIL", "error": str(exc)}
            present.add(directory.name)
            local_path = directory / "local-sha-vectors.json"
            ecc_path = directory / "ecc-results.json"
            ecc_adapter_path = directory / "ecc-acvp-adapter-results.json"
            pq_path = directory / "pq-results.json"
            aes_path = directory / "aes-results.json"
            mlkem_path = directory / "mlkem-results.json"
            pq_signature_path = directory / "pq-signature-results.json"
            try:
                local_data = json.loads(local_path.read_text(encoding="utf-8"))
                sha_ok = (local_data.get("status") == "LOCAL_SIMULATOR_NOT_NIST"
                          and len(local_data.get("results", [])) == 10
                          and all(case.get("passed") for case in local_data["results"]))
            except (ValueError, OSError, KeyError):
                sha_ok = False
            xof_path = directory / "xof-acvp-adapter-results.json"
            try:
                xof_data = json.loads(xof_path.read_text(encoding="utf-8"))
                xof_ok = (xof_data.get("type") == "OFFLINE_SP800_185_ACVP_ADAPTER_NOT_NIST"
                          and xof_data.get("status") == "PASS_LOCAL_ADAPTER_ONLY"
                          and xof_data.get("test_functions") == 9)
            except (ValueError, OSError, KeyError):
                xof_ok = False
            kdf_path = directory / "kdf-acvp-adapter-results.json"
            try:
                kdf_data = json.loads(kdf_path.read_text(encoding="utf-8"))
                kdf_ok = (kdf_data.get("type") == "OFFLINE_PBKDF_HKDF_KDA_ADAPTERS_NOT_NIST"
                          and kdf_data.get("status") == "PASS_LOCAL_ADAPTER_ONLY"
                          and kdf_data.get("test_functions") == 33)
            except (ValueError, OSError, KeyError):
                kdf_ok = False
            try:
                ecc_data = json.loads(ecc_path.read_text(encoding="utf-8"))
                ecc_ok = (ecc_data.get("type") == "OFFLINE_ECC_CROSS_IMPLEMENTATION_NOT_ACVTS"
                          and len(ecc_data.get("algorithms", [])) == 10
                          and all(case.get("status") == "PASS" for case in ecc_data["algorithms"]))
            except (ValueError, OSError, KeyError):
                ecc_ok = False
            try:
                ecc_adapter_data = json.loads(ecc_adapter_path.read_text(encoding="utf-8"))
                ecc_adapter_ok = ecc_adapter_passes(ecc_adapter_data)
            except (ValueError, OSError, KeyError):
                ecc_adapter_ok = False
            try:
                pq_data = json.loads(pq_path.read_text(encoding="utf-8"))
                pq_ok = (pq_data.get("type") == "OFFLINE_PQ_SELF_CONSISTENCY_NOT_ACVTS"
                         and pq_data.get("status") == "PASS_SMOKE_ONLY"
                         and len(pq_data.get("algorithms", [])) == 12
                         and all(case.get("status") == "PASS" for case in pq_data["algorithms"]))
            except (ValueError, OSError, KeyError):
                pq_ok = False
            try:
                aes_data = json.loads(aes_path.read_text(encoding="utf-8"))
                aes_ok = (aes_data.get("type") == "OFFLINE_AES_CROSS_IMPLEMENTATION_NOT_ACVTS"
                          and aes_data.get("status") == "PASS_LOCAL_INTEROPERABILITY"
                          and aes_data.get("test_functions") == 7)
            except (ValueError, OSError, KeyError):
                aes_ok = False
            try:
                mlkem_data = json.loads(mlkem_path.read_text(encoding="utf-8"))
                mlkem_ok = (mlkem_data.get("type") == "OFFLINE_MLKEM_ACVP_ADAPTER_NOT_NIST"
                            and mlkem_data.get("status") == "PASS_LOCAL_ADAPTER_ONLY"
                            and mlkem_data.get("native_tests") == 3
                            and len(mlkem_data.get("parameter_sets", [])) == 3)
            except (ValueError, OSError, KeyError):
                mlkem_ok = False
            try:
                pq_signature_data = json.loads(pq_signature_path.read_text(encoding="utf-8"))
                pq_signature_ok = (pq_signature_data.get("type") == "OFFLINE_PQ_SIGNATURE_ACVP_ADAPTER_NOT_NIST"
                                   and pq_signature_data.get("status") == "PASS_LOCAL_ADAPTER_ONLY"
                                   and pq_signature_data.get("native_tests") == 9
                                   and pq_signature_data.get("mldsa_parameter_sets") == 3
                                   and pq_signature_data.get("slhdsa_parameter_sets") == 6)
            except (ValueError, OSError, KeyError):
                pq_signature_ok = False
            stage_ok = all_stages_pass(directory / "qualify-all.json")
            try:
                stage_data = json.loads((directory / "qualify-all.json").read_text(encoding="utf-8"))
                if not isinstance(stage_data, dict):
                    stage_data = {}
            except (ValueError, OSError):
                stage_data = {}
            source_ok = source_revision_matches(result, stage_data, args.expected_qsc_sha)
            declared_class = directory.name.rsplit("-class-", 1)[-1]
            class_ok = result.get("security_class") == declared_class
            verified = {"job": directory.name, "stages_pass": stage_ok,
                        "class_match": class_ok,
                        "source_match": source_ok,
                        "ecc_acvp_adapter_pass": ecc_adapter_ok,
                            "aes_interoperability_pass": aes_ok,
                            "pq_signature_adapter_pass": pq_signature_ok,
                            "mlkem_adapter_pass": mlkem_ok,
                            "local_sha_simulation_pass": sha_ok,
                            "xof_offline_adapter_pass": xof_ok,
                            "pbkdf_hkdf_adapter_pass": kdf_ok,
                            "ecc_interoperability_pass": ecc_ok,
                            "pq_smoke_pass": pq_ok}
            results.append(checked_record(result, verified))

    observed_shas = {item.get("qsc_git_sha") for item in results}
    same_source = len(observed_shas) == 1 and all(
        item.get("source_match", False) for item in results)
    missing = [] if args.local else sorted(EXPECTED - present)
    failures = [result["job"] for result in results
                if result.get("status") != "PASS_WITH_COVERAGE_GAPS"
                or not result.get("stages_pass", False)
                or not result.get("class_match", False)
                or not result.get("source_match", False)
                or not same_source
                or not result.get("local_sha_simulation_pass", False)
                or not result.get("xof_offline_adapter_pass", False)
                or not result.get("pbkdf_hkdf_adapter_pass", False)
                or not result.get("ecc_interoperability_pass", False)
                or not result.get("ecc_acvp_adapter_pass", False)
                or not result.get("pq_smoke_pass", False)
                or not result.get("aes_interoperability_pass", False)
                or not result.get("mlkem_adapter_pass", False)
                or not result.get("pq_signature_adapter_pass", False)]
    success = bool(results) and not missing and not failures
    lines = ["# QSC consolidated offline qualification", "",
             "This report is **not an ACVTS Demo verdict or CAVP certificate**.", "",
             "| Runner | Class | Offline CAVP | SHA/HMAC | cSHAKE/KMAC AFT | PBKDF/HKDF/KDA | AES | ECC | ECC ACVP adapter | PQ smoke | ML-KEM adapter | ML-DSA/SLH-DSA adapter |", "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for result in results:
        lines.append(f"| {result['job']} | {result.get('security_class', '?')} | {result.get('status', 'FAIL')} | {'PASS' if result['local_sha_simulation_pass'] else 'FAIL'} | {'PASS' if result['xof_offline_adapter_pass'] else 'FAIL'} | {'PASS' if result['pbkdf_hkdf_adapter_pass'] else 'FAIL'} | {'PASS' if result['aes_interoperability_pass'] else 'FAIL'} | {'PASS' if result['ecc_interoperability_pass'] else 'FAIL'} | {'PASS' if result['ecc_acvp_adapter_pass'] else 'FAIL'} | {'PASS' if result['pq_smoke_pass'] else 'FAIL'} | {'PASS' if result['mlkem_adapter_pass'] else 'FAIL'} | {'PASS' if result['pq_signature_adapter_pass'] else 'FAIL'} |")
    lines += ["", f"Missing runner artifacts: {', '.join(missing) if missing else 'none'}",
              f"Failed or unreadable results: {', '.join(failures) if failures else 'none'}", "",
              "Uniform QSC source revision: " + ("YES" if same_source else "NO"),
              "Expected QSC commit: " + str(args.expected_qsc_sha or "locally inferred"), "",
              "P-384 signer must pass the complete ECC target; pending source status does not qualify.",
              "All live NIST ACVP cases remain **NOT RUN** in this offline report.", "",
              "Overall: " + ("OFFLINE PASS WITH COVERAGE GAPS" if success else "FAIL/INCOMPLETE"), ""]
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "consolidated.json").write_text(
        json.dumps({"success": success, "missing": missing, "failed": failures,
                    "source_uniform": same_source,
                    "expected_qsc_sha": args.expected_qsc_sha,
                    "results": results}, indent=2) + "\n", encoding="utf-8")
    report = "\n".join(lines)
    (args.output / "consolidated.md").write_text(report, encoding="utf-8")
    print(report)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
