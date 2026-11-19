#!/usr/bin/env python3
"""Replace only the relay binary and unit, retaining rollback copies."""
import argparse
import base64
from pathlib import Path
import stat

from relay_ops import (cli_error, connection_arguments, hash_argument,
                       remote_program, require, run_remote, sha, valid_key, validate_connection)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    connection_arguments(parser)
    parser.add_argument('--binary')
    parser.add_argument('--standing-key', required=True)
    parser.add_argument('--expect-old-binary-sha256', required=True)
    parser.add_argument('--expect-old-unit-sha256', required=True)
    parser.add_argument('--rollback', action='store_true')
    args = parser.parse_args()
    validate_connection(parser, args)
    require(valid_key(args.standing_key.lower()), 'invalid standing key')
    params = dict(standing_key=args.standing_key.lower(), rollback=args.rollback,
                  expect_old_binary_sha256=hash_argument(args.expect_old_binary_sha256),
                  expect_old_unit_sha256=hash_argument(args.expect_old_unit_sha256))
    require(args.rollback or args.binary, 'binary required for upgrade')
    if not args.rollback:
        if args.dry_run:
            params.update(binary='<local executable bytes>', unit='<repository unit bytes>',
                          new_binary_sha256='<computed from local executable>')
        else:
            path = Path(args.binary)
            require(stat.S_IMODE(path.stat().st_mode) != 0o600, 'file mode 0600 refused')
            require(path.is_file() and path.stat().st_mode & 0o111, 'binary must be executable')
            binary = path.read_bytes()
            unit_path = Path(__file__).with_name('tau-relay.service')
            require(stat.S_IMODE(unit_path.stat().st_mode) != 0o600, 'file mode 0600 refused')
            unit = unit_path.read_bytes()
            params.update(binary=base64.b64encode(binary).decode(),
                          unit=base64.b64encode(unit).decode(), new_binary_sha256=sha(binary))
    if args.dry_run:
        params['standing_key'] = '<redacted>'
        print('DRY RUN: binary + unit only; no commands executed')
    program = remote_program('upgrade_ops', params)
    payload = "set -euo pipefail\nflock -x /run/lock/tau-relay-passes.lock python3 - <<'RELAY_UPGRADE_PROGRAM'\n" + program + 'RELAY_UPGRADE_PROGRAM\n'
    if args.dry_run:
        print(payload, end='')
        return 0
    return run_remote(args, 'sudo -n /bin/bash -s', payload, 'FAIL')


if __name__ == '__main__':
    raise SystemExit(cli_error(main))
