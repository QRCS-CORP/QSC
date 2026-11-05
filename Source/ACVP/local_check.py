#!/usr/bin/env python3
"""Start the localhost SHA simulator and verify QSC responses in one CI process."""

import argparse
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from local_server import Handler
from local_client import execute, QSC


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.resolve().is_relative_to(Path(__file__).resolve().parents[2]):
        parser.error("Reports must be written outside the repository")
    if not args.library.is_file():
        parser.error("QSC shared library is missing")
    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            data = execute(f"http://127.0.0.1:{server.server_port}", QSC(args.library))
        finally:
            server.shutdown()
            thread.join(timeout=5)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "local-sha-vectors.json").write_text(
        json.dumps({"status": "LOCAL_SIMULATOR_NOT_NIST", "results": data}, indent=2) + "\n",
        encoding="utf-8")
    print("QSC localhost SHA/HMAC vector-check results:")
    for item in data:
        print(f"[{'PASS' if item['passed'] else 'FAIL'}] {item['algorithm']}, "
              f"cases={item.get('tests', 0)}")
    return 0 if all(item.get("passed") for item in data) else 1


if __name__ == "__main__":
    sys.exit(main())
