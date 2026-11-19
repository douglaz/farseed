#!/usr/bin/env python3
"""Issue or revoke one machine pass through one pinned, locked SSH session."""
import argparse
import time

from relay_ops import (Refused, cli_error, connection_arguments, mask, remote_program,
                       run_remote, validate_connection)
from pass_ops import validate_expiry, validate_parameters


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('issue', 'revoke'))
    connection_arguments(parser)
    for name in ('key', 'address', 'standing-key', 'expect-binary-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--expiry-unix', type=int)
    parser.add_argument('--max-hours', type=int, default=24)
    parser.add_argument('--deny-cidr', action='append', default=[])
    parser.add_argument('--timeout', type=int, default=60)
    args = parser.parse_args()
    validate_connection(parser, args)
    params = {name: getattr(args, name) for name in
              ('mode', 'key', 'address', 'standing_key', 'expect_binary_sha256',
               'expiry_unix', 'max_hours', 'deny_cidr', 'timeout')}
    params['key'] = params['key'].lower()
    params['standing_key'] = params['standing_key'].lower()
    validate_parameters(params)
    if args.mode == 'issue' and args.expiry_unix is None:
        raise Refused('issue requires expiry-unix')
    if args.dry_run:
        validate_expiry(params, int(time.time()))
        # The preview is deliberately non-executable: secrets remain masked.
        preview = dict(params, key=params['key'][:8] + '<redacted>',
                       standing_key='<redacted>', address=mask(args.address),
                       deny_cidr=['<configured CIDR>' for _ in args.deny_cidr])
        print('DRY RUN: one locked session; no commands executed')
        print(f"PLAN mode={args.mode} key={params['key'][:8]} address={mask(args.address)} "
              f'expiry={args.expiry_unix} max-hours={args.max_hours} timeout={args.timeout}; '
              'N/M and ALREADY/tombstones require the locked remote snapshot')
        print('PLAN: validate running build and firewall; protect standing pass; '
              'resolve ALREADY/tombstones; publish atomically; reload once; match N/M')
        print(remote_program('pass_ops', preview), end='')
        return 0
    command = 'sudo -n flock -x /run/lock/tau-relay-passes.lock python3 -'
    return run_remote(args, command, remote_program('pass_ops', params), 'NOT CONFIRMED')


if __name__ == '__main__':
    raise SystemExit(cli_error(main, 'NOT CONFIRMED'))
