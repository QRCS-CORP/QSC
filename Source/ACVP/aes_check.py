#!/usr/bin/env python3
"""Run independent QSC AES tests and write fail-closed offline evidence."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def main() -> int:
    """Execute fixed native test suite; produce JSON evidence outside the source tree."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    if args.output.resolve().is_relative_to(repository):
        parser.error('Reports must be written outside the repository')
    if not args.library.is_file():
        parser.error('Compiled AES shared library is missing')
    environment = dict(os.environ)
    environment['QSC_ACVP_AES_LIBRARY'] = str(args.library.resolve())
    command = [sys.executable, '-m', 'unittest', 'discover', '-s',
               str(Path(__file__).parent / 'tests'), '-p', 'test_aes_native.py', '-v']
    completed = subprocess.run(command, cwd=repository, env=environment,
                               capture_output=True, text=True, timeout=180, check=False)
    log = completed.stdout + completed.stderr
    match = re.search(r'Ran (\d+) tests', log)
    count = int(match.group(1)) if match else 0
    success = (completed.returncode == 0 and count == 7 and
               'OK' in log.splitlines()[-1:] and 'skipped=' not in log)
    record = {'type': 'OFFLINE_AES_CROSS_IMPLEMENTATION_NOT_ACVTS',
              'status': 'PASS_LOCAL_INTEROPERABILITY' if success else 'FAIL',
              'test_functions': count,
              'algorithms': ['ACVP-AES-ECB', 'ACVP-AES-CBC', 'ACVP-AES-CTR', 'ACVP-AES-GCM'],
              'p384_required_separately': True}
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'aes-results.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    (args.output / 'aes.log').write_text(log, encoding='utf-8')
    print(f"QSC AES offline qualification: {record['status']}; tests={count}")
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
