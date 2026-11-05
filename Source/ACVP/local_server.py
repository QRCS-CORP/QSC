#!/usr/bin/env python3
"""Loopback-only SHA and HMAC ACVP-vector simulator for testing the QSC adapter.

Not a NIST server, official ACVP endpoint, or standards validation service.
"""

import argparse
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from urllib.parse import urlsplit

ALGORITHMS = (
    ("SHA2-256", "sha256", 256),
    ("SHA2-384", "sha384", 384),
    ("SHA2-512", "sha512", 512),
    ("SHA3-256", "sha3_256", 256),
    ("SHA3-512", "sha3_512", 512),
    ("SHAKE-128", "shake_128", 256),
    ("SHAKE-256", "shake_256", 512),
    ("HMAC-SHA2-256", "sha256", 256),
    ("HMAC-SHA2-384", "sha384", 384),
    ("HMAC-SHA2-512", "sha512", 512),
)
TEST_MESSAGES = (b"", b"abc", bytes(range(128)), b"QSC validation" * 17)


def calculate(algorithm: str, message: bytes, output_bits: int, key: bytes = b"") -> str:
    """Use Python's independent hashlib oracle rather than the QSC backend."""
    if key:
        return hmac.digest(key, message, algorithm).hex().upper()
    hasher = hashlib.new(algorithm, message)
    if algorithm.startswith("shake_"):
        return hasher.digest(output_bits // 8).hex().upper()
    return hasher.digest().hex().upper()


def vector(ident: int) -> list:
    """Emit the ACVP SHA test vector envelope for one test set."""
    algorithm, _, output_bits = ALGORITHMS[ident - 1]
    mac_test = algorithm.startswith("HMAC-")
    tests = []
    for case, message in enumerate(TEST_MESSAGES, 1):
        item = {"tcId": case, "msg": message.hex().upper(), "len": len(message) * 8}
        if algorithm.startswith("SHAKE"):
            item["outLen"] = output_bits
        if mac_test:
            item["key"] = (bytes(range(1, 33)) + bytes([case])).hex().upper()
        tests.append(item)
    return [{"acvVersion": "1.0"}, {
        "vsId": ident, "algorithm": algorithm, "revision": "1.0",
        "testGroups": [{"tgId": 1, "testType": "AFT", "tests": tests}]
    }]


def validate(ident: int, result: object) -> dict:
    """Validate strict group/case correspondence against independent hashes."""
    if not isinstance(result, list) or len(result) != 2:
        return {"passed": False, "error": "Invalid ACVP envelope"}
    if not isinstance(result[0], dict) or result[0].get("acvVersion") != "1.0":
        return {"passed": False, "error": "Invalid protocol version"}
    body = result[1]
    if not isinstance(body, dict) or body.get("vsId") != ident:
        return {"passed": False, "error": "Invalid vector set identifier"}
    groups = body.get("testGroups")
    if (not isinstance(groups, list) or len(groups) != 1
            or not isinstance(groups[0], dict) or groups[0].get("tgId") != 1):
        return {"passed": False, "error": "Invalid test group"}
    cases = groups[0].get("tests")
    if not isinstance(cases, list) or len(cases) != len(TEST_MESSAGES):
        return {"passed": False, "error": "Missing or extra test cases"}
    algorithm, oracle, bits = ALGORITHMS[ident - 1]
    mac_test = algorithm.startswith("HMAC-")
    failures = []
    for offset, message in enumerate(TEST_MESSAGES):
        case = cases[offset]
        if not isinstance(case, dict) or case.get("tcId") != offset + 1:
            failures.append(offset + 1)
        else:
            key = bytes.fromhex((bytes(range(1, 33)) + bytes([offset + 1])).hex()) if mac_test else b""
            expected = calculate(oracle, message, bits, key)
            field = "mac" if mac_test else "md"
            if case.get(field, "").upper() != expected:
                failures.append(offset + 1)
    return {"passed": len(failures) == 0, "tests": len(TEST_MESSAGES), "failures": failures,
            "server": "QSC_LOCAL_SIMULATOR_NOT_NIST"}


class Handler(BaseHTTPRequestHandler):
    """Serve SHA vector generation and result checking over IPv4 loopback."""

    def send_json(self, value: object, status: int = 200) -> None:
        encoded = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/health":
            self.send_json({"status": "ready", "mode": "local-only"})
            return
        prefix = "/acvp/v1/testSessions/1/vectorSets/"
        if path.startswith(prefix) and path[len(prefix):].isdigit():
            ident = int(path[len(prefix):])
            if 1 <= ident <= len(ALGORITHMS):
                self.send_json(vector(ident))
                return
        self.send_json({"error": "Not found"}, 404)

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        prefix = "/acvp/v1/testSessions/1/vectorSets/"
        if not path.startswith(prefix) or not path.endswith("/results"):
            self.send_json({"error": "Not found"}, 404)
            return
        ident_str = path[len(prefix):-len("/results")]
        if not ident_str.isdigit() or int(ident_str) not in range(1, len(ALGORITHMS) + 1):
            self.send_json({"error": "Invalid vector set"}, 404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 1048576:
            self.send_json({"error": "Invalid payload length"}, 413)
            return
        try:
            payload = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            self.send_json({"error": "Invalid JSON"}, 400)
            return
        self.send_json(validate(int(ident_str), payload))

    def log_message(self, format_string: str, *args) -> None:
        """Avoid request logging; localhost test requests contain no secrets."""
        return


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8717)
    args = parser.parse_args()
    with ThreadingHTTPServer(("127.0.0.1", args.port), Handler) as server:
        print(f"QSC LOCAL ACVP simulator, not NIST, on 127.0.0.1:{server.server_port}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
