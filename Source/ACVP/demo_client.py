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

"""Authenticated QSC ACVTS Demo sample client for registered QSC algorithms.

Limited scope: sample sessions, byte-oriented hashes/MACs and AES ECB/GCM, no LDT.
Requires separately provisioned NIST client TLS identity and TOTP seed.
Never stores JWTs, passwords, certificates, or unredacted protocol bodies.
"""

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
from pathlib import Path
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from local_client import QSC, build_response
from kdf_client import QscKdf, pbkdf_registration
from kda_hkdf_client import registration as kda_hkdf_registration, SELECTION as KDA_HKDF
from ecc_client import QscEcc, registration as ecc_registration
from mlkem_client import QscMlKem, registration as mlkem_registration
from mldsa_client import QscMlDsa, registration as mldsa_registration
from slhdsa_client import QscSlhDsa, registration as slhdsa_registration
from aes_client import (QscAes, ALGORITHM as AES_GCM, ECB_ALGORITHM as AES_ECB,
                        CBC_ALGORITHM as AES_CBC, CTR_ALGORITHM as AES_CTR)

DEMO_ORIGIN = "https://demo.acvts.nist.gov"
DEMO_API = "/acvp/v1"
SHA_ALGORITHMS = ("SHA2-256", "SHA2-384", "SHA2-512", "SHA3-256", "SHA3-512",
                  "SHAKE-128", "SHAKE-256", "HMAC-SHA2-256", "HMAC-SHA2-384", "HMAC-SHA2-512")
DEFAULT_ALGORITHMS = SHA_ALGORITHMS + (AES_ECB, AES_CBC, AES_CTR, AES_GCM, "ML-KEM", "ML-DSA", "SLH-DSA", "PBKDF")
ALGORITHMS = DEFAULT_ALGORITHMS + ("ECDSA", "DetECDSA", "EDDSA", "XECDH", "KAS-ECC-SSC", KDA_HKDF)


def totp(seed: str, now: float) -> str:
    """Compute RFC 6238 HMAC-SHA1 six-digit TOTP without exposing the secret."""
    normalized = "".join(seed.split()).upper()
    secret = base64.b32decode(normalized, casefold=True)
    if len(secret) < 10:
        raise ValueError("TOTP seed is unexpectedly short")
    counter = struct.pack(">Q", int(now) // 30)
    digest = hmac.new(secret, counter, hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1000000:06d}"


def registration(algorithms: tuple[str, ...] = SHA_ALGORITHMS,
                 drbg_validation: str | None = None) -> list:
    """Register only supported SHA/SHAKE/HMAC and AES byte-oriented capabilities."""
    if not algorithms or len(algorithms) != len(set(algorithms)):
        raise ValueError("Algorithm selection must be nonempty and unique")
    if any(name not in ALGORITHMS for name in algorithms):
        raise ValueError("Unsupported ACVP registration requested")
    if AES_GCM in algorithms and AES_ECB not in algorithms:
        raise ValueError('AES-GCM requires an AES-ECB prerequisite in the same session')
    if "ML-KEM" in algorithms and not {"SHA3-256", "SHA3-512", "SHAKE-128", "SHAKE-256"}.issubset(algorithms):
        raise ValueError("ML-KEM requires SHA3-256/512 and SHAKE-128/256 prerequisites")
    if "ML-DSA" in algorithms and not {"SHAKE-128", "SHAKE-256"}.issubset(algorithms):
        raise ValueError("ML-DSA requires SHAKE prerequisites")
    if "SLH-DSA" in algorithms and "SHAKE-256" not in algorithms:
        raise ValueError("SLH-DSA requires SHAKE-256 prerequisite")
    if "PBKDF" in algorithms and not {"SHA2-256", "SHA2-384", "SHA2-512"}.issubset(algorithms):
        raise ValueError("PBKDF requires all registered SHA2 prerequisites")
    if KDA_HKDF in algorithms and not {"HMAC-SHA2-256", "HMAC-SHA2-384", "HMAC-SHA2-512"}.issubset(algorithms):
        raise ValueError("KDA-HKDF requires HMAC-SHA2 prerequisites in the same session")
    if "KAS-ECC-SSC" in algorithms and "ECDSA" not in algorithms:
        raise ValueError("KAS-ECC-SSC requires ECDSA prerequisite in the same session")
    if any(name in algorithms for name in ("ECDSA", "DetECDSA")) and not {
            "SHA2-256", "SHA2-384", "SHA2-512"}.issubset(algorithms):
        raise ValueError("ECDSA requires registered SHA-2 prerequisites")
    if "EDDSA" in algorithms and not {"SHA2-512", "SHAKE-256"}.issubset(algorithms):
        raise ValueError("EDDSA requires registered SHA prerequisites")
    capabilities = []
    for name in algorithms:
        if name == KDA_HKDF:
            capabilities.extend(kda_hkdf_registration(drbg_validation))
        elif name == "PBKDF":
            capabilities.append(pbkdf_registration())
        elif name in ("ECDSA", "DetECDSA", "EDDSA", "XECDH", "KAS-ECC-SSC"):
            capabilities.extend(ecc_registration(name, drbg_validation))
        elif name == "SLH-DSA":
            capabilities.extend(slhdsa_registration())
        elif name == "ML-DSA":
            capabilities.extend(mldsa_registration())
        elif name == "ML-KEM":
            capabilities.extend(mlkem_registration())
        elif name == AES_ECB:
            capabilities.append({"algorithm": AES_ECB, "revision": "1.0",
                                 "direction": ["encrypt", "decrypt"], "keyLen": [128, 256]})
        elif name == AES_CBC:
            capabilities.append({"algorithm": AES_CBC, "revision": "1.0",
                                 "direction": ["encrypt", "decrypt"], "keyLen": [128, 256]})
        elif name == AES_CTR:
            capabilities.append({"algorithm": AES_CTR, "revision": "1.0",
                                 "direction": ["encrypt", "decrypt"], "keyLen": [128, 256],
                                 "payloadLen": [128], "incrementalCounter": True,
                                 "overflowCounter": False, "performCounterTests": True})
        elif name == AES_GCM:
            capabilities.append({"algorithm": AES_GCM, "revision": "1.0",
                                 "prereqVals": [{"algorithm": AES_ECB, "valValue": "same"}],
                                 "direction": ["encrypt", "decrypt"], "keyLen": [128, 256],
                                 "ivGen": "external", "ivGenMode": "8.2.2", "ivLen": [96],
                                 "tagLen": [128],
                                 "payloadLen": [{"min": 0, "max": 65536, "increment": 8}],
                                 "aadLen": [{"min": 0, "max": 65536, "increment": 8}]})
        elif name.startswith("HMAC-"):
            if name.removeprefix("HMAC-") not in algorithms:
                raise ValueError("HMAC prerequisite SHA algorithm must be registered in the same session")
            digest_bits = {"HMAC-SHA2-256": 256, "HMAC-SHA2-384": 384,
                           "HMAC-SHA2-512": 512}[name]
            capabilities.append({"algorithm": name, "revision": "2.0",
                                 "prereqVals": [{"algorithm": "SHA", "valValue": "same"}],
                                 "keyLen": [{"min": 8, "max": 4096, "increment": 8}],
                                 "macLen": [{"min": 128, "max": digest_bits, "increment": 8}],
                                 "msgLen": [{"min": 0, "max": 4096, "increment": 8}]})
        elif name.startswith("SHAKE-"):
            capabilities.append({"algorithm": name, "revision": "FIPS202",
                                 "outputLen": [{"min": 128, "max": 1024, "increment": 8}],
                                 "messageLength": [{"min": 0, "max": 65536, "increment": 8}]})
        else:
            capabilities.append({"algorithm": name,
                                 "revision": "2.0" if name.startswith("SHA3-") else "1.0",
                                 "messageLength": [{"min": 0, "max": 65536, "increment": 8}]})
    return [{"acvVersion": "1.0"}, {"isSample": True, "algorithms": capabilities}]

def check_path(resource: str) -> str:
    """Restrict authenticated requests to NIST Demo API resources."""
    parsed = urllib.parse.urlsplit(resource)
    if parsed.scheme or parsed.netloc or parsed.fragment or parsed.query:
        raise ValueError("ACVP resource must be a relative path without query or fragment")
    path = parsed.path
    if not path.startswith(DEMO_API + "/"):
        raise ValueError("ACVP resource is outside the Demo API")
    if any(part in (".", "..", "") for part in path.split("/")[1:]):
        raise ValueError("Invalid ACVP resource path")
    return path


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward bearer tokens across an HTTP redirect."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("ACVP redirect refused")


class DemoTransport:
    """Mutually authenticated HTTPS transport pinned to the NIST Demo origin."""

    def __init__(self, certificate: Path, private_key: Path):
        if not certificate.is_file() or not private_key.is_file():
            raise ValueError("NIST Demo certificate or private key is missing")
        context = ssl.create_default_context()
        context.load_cert_chain(str(certificate), str(private_key))
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context), NoRedirect())

    def request(self, method: str, path: str, token: str | None = None, body: list | None = None) -> list:
        """Transfer a bounded JSON envelope without logging credentials."""
        checked_path = check_path(path)
        if method not in ("GET", "POST"):
            raise ValueError("Unsupported method")
        data = json.dumps(body).encode("utf-8") if body is not None else None
        if len(data or b"") > (8 * 1024 * 1024):
            raise ValueError("ACVP response exceeds standard endpoint limit")
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(DEMO_ORIGIN + checked_path, data=data,
                                         headers=headers, method=method)
        with self._opener.open(request, timeout=45) as response:
            if response.status < 200 or response.status >= 300:
                raise ValueError(f"Unexpected HTTP status {response.status}")
            raw = response.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise ValueError("ACVP vector payload exceeds bounded in-memory client limit")
        # NIST ACVP specifies an empty success body for POST /vectorSets/{id}/results.
        if not raw and method == "POST" and checked_path.endswith("/results"):
            return [{"acvVersion": "1.0"}, {}]
        if not raw:
            raise ValueError("Unexpected empty ACVP response")
        result = json.loads(raw)
        if (not isinstance(result, list) or len(result) != 2 or
                result[0].get("acvVersion") != "1.0" or not isinstance(result[1], dict)):
            raise ValueError("Unrecognized ACVP response envelope")
        return result


def reconcile_verdict(outcome: dict, submitted: set[str]) -> str:
    """Accept a Demo PASS only for one passing verdict per submitted vector set.

    A subset, duplicate, unexpected vector set or inconsistent overall verdict
    must never be promoted to a successful qualification result.
    """
    if not isinstance(outcome, dict) or type(outcome.get("passed")) is not bool:
        return "FAIL"
    entries = outcome.get("results")
    if not isinstance(entries, list) or not submitted:
        return "FAIL"

    observed = {}
    for entry in entries:
        if not isinstance(entry, dict):
            return "FAIL"
        path = entry.get("vectorSetUrl")
        status = entry.get("status")
        if (not isinstance(path, str) or path not in submitted or path in observed or
                status not in ("passed", "failed", "fail", "error", "expired",
                               "incomplete", "missing", "unreceived", "processing", "pending")):
            return "FAIL"
        observed[path] = status

    if outcome["passed"]:
        return "PASS" if set(observed) == submitted and all(
            status == "passed" for status in observed.values()) else "FAIL"
    if any(status in ("failed", "fail", "error", "expired", "missing", "unreceived")
           for status in observed.values()):
        return "FAIL"
    return "PENDING"


def execute(transport, qsc: QSC, seed: str, selected: tuple[str, ...], poll_count: int = 8,
            poll_sleep: float = 2.0, drbg_validation: str | None = None) -> dict:
    """Perform one sample registration and process every returned vector sequentially."""
    report = {"type": "NIST_ACVTS_DEMO_SAMPLE_NOT_CAVP_CERTIFICATE",
              "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "status": "INCOMPLETE", "registration_algorithms": list(selected),
              "test_session": None, "vectors": [], "server_passed": False}
    login = transport.request("POST", DEMO_API + "/login", body=[
        {"acvVersion": "1.0"}, {"password": totp(seed, time.time())}])
    token = login[1].get("accessToken")
    if not isinstance(token, str) or not token:
        raise ValueError("Login response did not include an access token")
    large_required = login[1].get("largeEndpointRequired", False)
    standard_limit = login[1].get("sizeConstraint", -1)
    if type(large_required) is not bool or type(standard_limit) is not int:
        raise ValueError("Unexpected ACVP submission size policy")
    capability_envelope = registration(selected, drbg_validation)
    required_ecc_modes = {(item["algorithm"], item.get("mode"))
                          for item in capability_envelope[1]["algorithms"]
                          if item["algorithm"] in ("ECDSA", "DetECDSA", "EDDSA", "XECDH", "KAS-ECC-SSC")}
    session = transport.request("POST", DEMO_API + "/testSessions", token,
                                capability_envelope)[1]
    session_path = check_path(session.get("url", ""))
    if not session_path.startswith(DEMO_API + "/testSessions/"):
        raise ValueError("Invalid test-session URL")
    report["test_session"] = session_path.rsplit("/", 1)[-1]
    session_token = session.get("accessToken", token)
    if not isinstance(session_token, str) or not session_token:
        raise ValueError("Invalid session authorization token")
    urls = session.get("vectorSetUrls")
    if not isinstance(urls, list) or not urls:
        listing = transport.request("GET", session_path + "/vectorSets", session_token)[1]
        urls = listing.get("vectorSetUrls")
    if not isinstance(urls, list) or not urls:
        raise ValueError("No vector-set URLs returned by server")
    if len(urls) > 100:
        raise ValueError("Unexpectedly large ACVP vector-set list")
    expected_paths = set()
    for path in urls:
        if not isinstance(path, str):
            raise ValueError("Invalid vector-set URL type")
        validated = check_path(path)
        if (not validated.startswith(session_path + "/vectorSets/") or
                not validated.rsplit("/", 1)[-1].isdigit() or validated in expected_paths):
            raise ValueError("Invalid or duplicate vector-set URL in session")
        expected_paths.add(validated)
    for path in urls:
        vector_result = {"vector_set": None, "algorithm": "UNKNOWN", "status": "FAIL"}
        report["vectors"].append(vector_result)
        try:
            validated = check_path(path)
            if not validated.startswith(session_path + "/vectorSets/") or validated.endswith("/results"):
                raise ValueError("Vector-set URL is not part of this session")
            vector_result["vector_set"] = validated.rsplit("/", 1)[-1]
            request = transport.request("GET", validated, session_token)
            for attempt in range(8):
                retry = request[1].get("retry")
                if retry is None:
                    break
                if type(retry) not in (int, float) or retry < 0:
                    raise ValueError("Invalid ACVP retry interval")
                if attempt == 7:
                    raise ValueError("ACVP vector generation did not complete before retry limit")
                time.sleep(min(max(retry, 1), 30))
                request = transport.request("GET", validated, session_token)
            if (type(request[1].get("vsId")) is not int or
                    str(request[1]["vsId"]) != vector_result["vector_set"]):
                raise ValueError("Downloaded vector set does not match requested vsId")
            vector_result["algorithm"] = request[1].get("algorithm", "UNKNOWN")
            vector_result["mode"] = request[1].get("mode")
            if vector_result["algorithm"] == "KDA" and request[1].get("mode") == "HKDF":
                vector_result["algorithm"] = KDA_HKDF
            if vector_result["algorithm"] not in selected:
                raise ValueError("Unregistered or unsupported algorithm in vector set")
            response = build_response(request, qsc)
            if large_required and standard_limit >= 0 and len(json.dumps(response).encode("utf-8")) > standard_limit:
                raise ValueError("Vector response requires unsupported large-submission endpoint")
            transport.request("POST", validated + "/results", session_token, response)
            vector_result["status"] = "SUBMITTED"
        except (ValueError, KeyError, TypeError, urllib.error.URLError, OSError) as exc:
            vector_result["status"] = "FAIL"
            # Protocol/transport errors are deliberately not recorded verbatim: servers
            # may include URLs, bearer tokens or request bodies in their error strings.
            vector_result["reason"] = type(exc).__name__
    if any(item["status"] == "FAIL" for item in report["vectors"]):
        report["status"] = "FAIL_OR_UNSUPPORTED_VECTOR"
        return report
    executed = {item["algorithm"] for item in report["vectors"]
                if item["status"] == "SUBMITTED"}
    exercised_ecc = {(item["algorithm"], item.get("mode")) for item in report["vectors"]
                     if item["status"] == "SUBMITTED" and
                     item["algorithm"] in ("ECDSA", "DetECDSA", "EDDSA", "XECDH", "KAS-ECC-SSC")}
    missing = set(selected) - executed
    if missing or required_ecc_modes - exercised_ecc:
        report["status"] = "FAIL_INCOMPLETE_ALGORITHM_COVERAGE"
        report["missing_algorithms"] = sorted(missing)
        report["missing_ecc_modes"] = sorted(
            f"{name}/{mode if mode is not None else 'SSC'}"
            for name, mode in required_ecc_modes - exercised_ecc)
        return report
    for attempt in range(poll_count):
        outcome = transport.request("GET", session_path + "/results", session_token)[1]
        verdict = reconcile_verdict(outcome, expected_paths)
        if verdict == "PASS":
            report["server_passed"] = True
            report["status"] = "PASS_DEMO_SAMPLE"
            break
        if verdict == "FAIL":
            report["status"] = "FAIL_DEMO_VERDICT"
            break
        if attempt + 1 < poll_count:
            time.sleep(poll_sleep)
    return report


def main() -> int:
    """Run a protected Demo sample qualification, writing only sanitized results."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--aes-library", type=Path)
    parser.add_argument("--pq-library", type=Path)
    parser.add_argument("--ecc-library", type=Path)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--algorithms", nargs="+", choices=ALGORITHMS, default=list(DEFAULT_ALGORITHMS))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    if args.output.resolve().is_relative_to(root):
        parser.error("Report must be written outside the repository")
    seed = os.environ.get("ACVP_TOTP_SEED")
    if not seed:
        parser.error("ACVP_TOTP_SEED is required")
    if not args.library.is_file():
        parser.error("QSC SHA library not found")
    if any(x in args.algorithms for x in (AES_ECB, AES_CBC, AES_CTR, AES_GCM)) and (
            args.aes_library is None or not args.aes_library.is_file()):
        parser.error("AES requested but QSC AES library was not supplied")
    if any(name in args.algorithms for name in ("ML-KEM", "ML-DSA", "SLH-DSA")) and (
            args.pq_library is None or not args.pq_library.is_file()):
        parser.error("PQ algorithm requested but QSC PQ library was not supplied")
    ecc_selected = any(name in args.algorithms for name in
                       ("ECDSA", "DetECDSA", "EDDSA", "XECDH", "KAS-ECC-SSC"))
    if ecc_selected and (args.ecc_library is None or not args.ecc_library.is_file()):
        parser.error("ECC tests require the complete QSC ECC library, including P-384")
    drbg_validation = os.environ.get("ACVP_ECC_DRBG_VALIDATION")
    kda_drbg_validation = os.environ.get("ACVP_KDA_DRBG_VALIDATION")
    if KDA_HKDF in args.algorithms and not kda_drbg_validation:
        parser.error("KDA-HKDF requires ACVP_KDA_DRBG_VALIDATION (verified DRBG prerequisite)")
    if KDA_HKDF in args.algorithms and not drbg_validation:
        drbg_validation = kda_drbg_validation
    if ecc_selected and not drbg_validation:
        parser.error("ECC registration requires ACVP_ECC_DRBG_VALIDATION (verified DRBG prerequisite)")
    if ecc_selected and os.environ.get("ACVP_ECC_RNG_QUALIFIED") != "1":
        parser.error("ECC live registration requires independently qualified RNG integration")
    report = {"type": "NIST_ACVTS_DEMO_SAMPLE_NOT_CAVP_CERTIFICATE", "status": "ERROR"}
    try:
        transport = DemoTransport(args.cert, args.key)
        qsc = QSC(args.library)
        qsc.kdf = QscKdf(args.library)
        if args.aes_library is not None:
            qsc.aes = QscAes(args.aes_library)
        if args.pq_library is not None:
            qsc.kem = QscMlKem(args.pq_library)
            qsc.dsa = QscMlDsa(args.pq_library)
            qsc.slh = QscSlhDsa(args.pq_library)
        if ecc_selected:
            qsc.ecc = QscEcc(args.ecc_library)
        report = execute(transport, qsc, seed, tuple(args.algorithms),
                         drbg_validation=drbg_validation)
    except (ValueError, TypeError, urllib.error.URLError, OSError) as exc:
        report["error_category"] = type(exc).__name__
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "demo-results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"ACVTS Demo sample status: {report['status']}; "
          f"session: {report.get('test_session', 'unavailable')}")
    return 0 if report["status"] == "PASS_DEMO_SAMPLE" else 1


if __name__ == "__main__":
    sys.exit(main())
