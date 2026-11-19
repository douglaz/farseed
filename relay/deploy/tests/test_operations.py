"""Offline coverage of remote operations; every external reader is fake."""
import base64
import contextlib
import importlib.util
import io
import ipaddress
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

DEPLOY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DEPLOY))
import relay_ops as ops
import pass_ops as passes
import upgrade_ops as upgrade

KEYS = [format(x, '064x') for x in range(1, 100) if ops.valid_key(format(x, '064x'))][:6]
NOW = 2_000_000_000
OLD = b'old executable'
NEW = b'new executable'
UNIT = b'[Service]\nExecStart=/usr/local/bin/tau-relay /etc/tau-relay/config.toml\nExecReload=/bin/kill -HUP $MAINPID\n'


class FakeSystem(ops.System):
    def __init__(self, root):
        super().__init__(root)
        self.calls = []
        self.ticks = 0
        self.is_active = True
        self.running = ops.sha(OLD)
        self.live_rule = True
        self.reload_lines = None
        self.start_lines = {}
        self.events = []
        self.missing_cursor = False
        self.chowns = []
        self.on_journal = None
        self.fail_new_start = False
        self.fail_rollback = False
        self.restarts = 0
        self.original_records = [dict(key=KEYS[0], hosts=['standing.example.net'],
                                      expiry=NOW + 100_000)]
        self.put(ops.BINARY, OLD, 0o755)
        self.put(ops.UNIT, UNIT)
        self.put(ops.PASSES, passes.write_toml(self.original_records), 0o640)
        self.put(ops.CONFIG, b'own_public = ["9.9.9.9"]\npass_file = "/etc/tau-relay/passes.toml"\n')
        self.put(ops.NFT, b'define relay_uid = 999\ntable inet tau_relay {\nchain output {\nmeta skuid $relay_uid tcp dport != 22 reject\n}\n}\n')
        self.put(ops.CADDY, b'preserved proxy')

    def put(self, name, data, mode=0o644):
        path = self.path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)

    def stage(self, name, data, mode, owner=None):
        self.calls.append(('stage', name))
        def chown(fd, uid, gid):
            self.chowns.append((name, uid, gid))
        with patch.object(ops.os, 'fchown', side_effect=chown):
            return super().stage(name, data, mode, owner)

    def run(self, *args):
        self.calls.append(args)
        if args == ('id', '-u', 'tau-relay'):
            return '999\n'
        if args == ('nft', '-n', 'list', 'chain', 'inet', 'tau_relay', 'output'):
            rule = '        meta skuid 999 tcp dport != 22 reject\n' if self.live_rule else ''
            return ('table inet tau_relay {\n    chain output {\n'
                    '        type filter hook output priority filter; policy accept;\n'
                    + rule + '    }\n}\n')
        if args == ('systemctl', 'is-active', ops.SERVICE):
            return 'active\n' if self.is_active else 'inactive\n'
        if args == ('journalctl', '-u', 'tau-relay', '--show-cursor', '-n', '0'):
            output = '-- No entries --\n'
            if not self.missing_cursor:
                output += f'-- cursor: s={"1" * 32};i={len(self.events):x};b={"2" * 32}\n'
            return output
        if args[:4] == ('journalctl', '-u', 'tau-relay', '--after-cursor'):
            self.assert_journal_args(args)
            if self.on_journal:
                callback, self.on_journal = self.on_journal, None
                callback()
            index = int(args[4].split(';')[1].removeprefix('i='), 16)
            return ''.join(line + '\n' for line in self.events[index:])
        if args == ('systemctl', 'reload', ops.SERVICE):
            lines = self.reload_lines
            if lines is None:
                current = passes.records(self.read(ops.PASSES))
                lines = [f'pass reload applied: {len(current)} passes, '
                         f'{sum(passes.live(record, NOW) for record in current)} in force']
            self.events.extend(lines)
            return ''
        if args == ('systemctl', 'daemon-reload'):
            return ''
        if args == ('systemctl', 'restart', ops.SERVICE):
            self.restarts += 1
            if self.fail_rollback or (self.fail_new_start and self.restarts == 1):
                raise ops.Refused('command failed: systemctl')
            self.running = self.digest(ops.BINARY)
            self.is_active = True
            self.events.extend(self.start_lines.get(self.running, ['listening 127.0.0.1:9000']))
            return ''
        if args[:2] == ('systemd-analyze', 'verify'):
            return ''
        raise AssertionError('unexpected command')

    def running_sha(self):
        return self.running

    def assert_journal_args(self, args):
        if (len(args) != 8 or args[5:] != ('-o', 'cat', '--no-pager')
                or not re.fullmatch(r's=1{32};i=[0-9a-f]+;b=2{32}', args[4])):
            raise AssertionError('unexpected journal arguments')

    def now(self):
        return NOW

    def monotonic(self):
        return self.ticks

    def sleep(self):
        self.ticks += 1


class OperationsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.addCleanup(self.temp.cleanup)
        self.system = FakeSystem(self.temp.name)
        self.params = dict(mode='issue', key=KEYS[1], address='8.8.8.8',
                           standing_key=KEYS[0], expect_binary_sha256=ops.sha(OLD),
                           expiry_unix=NOW + 3600, max_hours=24, deny_cidr=[], timeout=4)
        self.output = []

    def current(self):
        return passes.records(self.system.read(ops.PASSES))

    def append(self, **record):
        self.system.put(ops.PASSES, passes.write_toml(self.current() + [record]), 0o640)

    def issue(self):
        try:
            return passes.perform(self.system, self.params, self.output.append)
        except ops.Refused as error:
            self.output.append('NOT CONFIRMED: ' + str(error))
            return 1

    def refused(self, reason):
        before = self.system.read(ops.PASSES)
        self.assertEqual(self.issue(), 1)
        self.assertIn('NOT CONFIRMED: ' + reason, self.output)
        self.assertEqual(self.system.read(ops.PASSES), before)
        self.assertFalse(any(call[0] == 'stage' for call in self.system.calls))
        self.assertNotIn(('systemctl', 'reload', ops.SERVICE), self.system.calls)

    def test_issue_confirmed_and_preserves_metadata(self):
        before = self.system.path(ops.PASSES).stat()
        self.assertEqual(self.issue(), 0)
        self.assertTrue(self.output[-1].startswith('CONFIRMED mode=issue'))
        self.assertIn('N=2 M=2', self.output[-1])
        after = self.system.path(ops.PASSES).stat()
        self.assertEqual((before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)),
                         (after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)))
        self.assertEqual(len(self.system.chowns), 1)
        self.assertEqual(self.system.chowns[0][1:], (before.st_uid, before.st_gid))
        self.assertEqual(self.current()[0], self.system.original_records[0])
        text = '\n'.join(self.output)
        self.assertNotIn(self.params['key'], text)
        self.assertNotIn(self.params['address'], text)
        self.assertEqual(self.system.calls.count(('systemctl', 'reload', ops.SERVICE)), 1)

    def test_original_uid_gid_requested_when_different_from_operator(self):
        original_stat = Path.stat
        owner = (12345, 23456)
        def source_metadata(path, *args, **kwargs):
            metadata = original_stat(path, *args, **kwargs)
            if path == self.system.path(ops.PASSES):
                values = list(metadata)
                values[4:6] = owner
                return os.stat_result(values)
            return metadata
        with patch.object(Path, 'stat', source_metadata):
            self.assertEqual(self.issue(), 0)
        self.assertEqual(len(self.system.chowns), 1)
        self.assertEqual(self.system.chowns[0][1:], owner)

    def test_success_before_cursor_is_ignored(self):
        self.system.events.append('pass reload applied: 2 passes, 2 in force')
        self.system.reload_lines = []
        self.assertEqual(self.issue(), 1)
        self.assertEqual(self.output[-1], 'NOT CONFIRMED: reload confirmation timeout')
        self.assertEqual(self.system.calls.count(('systemctl', 'reload', ops.SERVICE)), 1)

    def test_dropped_reload_call_times_out(self):
        original_run = self.system.run
        def drop_reload(*args):
            if args == ('systemctl', 'reload', ops.SERVICE):
                return ''
            return original_run(*args)
        with patch.object(self.system, 'run', side_effect=drop_reload) as run:
            self.assertEqual(self.issue(), 1)
            self.assertEqual(run.call_args_list.count(
                unittest.mock.call('systemctl', 'reload', ops.SERVICE)), 1)
        self.assertEqual(self.output[-1], 'NOT CONFIRMED: reload confirmation timeout')
        self.assertEqual(self.system.events, [])
        self.assertEqual(len(self.current()), 2)

    def test_idempotent_already(self):
        self.assertEqual(self.issue(), 0)
        self.system.calls.clear()
        before = self.system.read(ops.PASSES)
        self.assertEqual(self.issue(), 0)
        self.assertTrue(self.output[-1].startswith('ALREADY'))
        self.assertEqual(self.system.read(ops.PASSES), before)
        self.assertNotIn(('systemctl', 'reload', ops.SERVICE), self.system.calls)
        self.assertFalse(any(call[0] == 'stage' for call in self.system.calls))

    def test_tombstone_revoked_and_expired(self):
        for revoked, expiry in ((True, NOW + 4000), (False, NOW - 100)):
            with self.subTest(revoked=revoked):
                self.system.put(ops.PASSES, passes.write_toml(self.system.original_records), 0o640)
                self.append(key=KEYS[2], hosts=['8.8.8.8'], expiry=expiry, revoked=revoked)
                self.assertEqual(self.issue(), 0)
                self.assertEqual(len(self.current()), 2)
                self.assertTrue(any(line.startswith('tombstone key=') for line in self.output))
                self.assertNotIn(KEYS[2], [r['key'] for r in self.current()])

    def test_private_address(self):
        self.params['address'] = '10.1.2.3'
        self.refused('address must be public IPv4')

    def test_relay_denied_global_addresses_refused_before_write(self):
        for address in ('224.0.0.1', '192.88.99.1', '192.0.0.100', '192.31.196.1',
                        '192.52.193.1', '192.175.48.1'):
            with self.subTest(address=address):
                self.params['address'] = address
                reason = ('address denied by relay policy' if ipaddress.IPv4Address(address).is_global
                          else 'address must be public IPv4')
                self.refused(reason)

    def test_every_relay_deny_range_copied_exactly_and_refused(self):
        policy = (DEPLOY.parent / 'src/policy.rs').read_text()
        v4 = policy.split('pub const V4_DENY:', 1)[1].split('];', 1)[0]
        ranges = tuple((int(base, 16), int(bits)) for base, bits in
                       re.findall(r'\((0x[0-9a-f]+), (\d+)\)', v4))
        self.assertEqual(len(ranges), 18)
        self.assertEqual(passes.V4_DENY, ranges)
        for base, bits in ranges:
            for value in (base, base + 1, base + (1 << (32 - bits)) - 1):
                address = ipaddress.IPv4Address(value)
                with self.subTest(address=str(address), prefix=bits):
                    self.params['address'] = str(address)
                    self.refused('address denied by relay policy' if address.is_global
                                 else 'address must be public IPv4')

    def test_own_address(self):
        self.params['address'] = '9.9.9.9'
        self.refused('address belongs to relay')

    def test_denied_cidr(self):
        self.params['deny_cidr'] = ['8.8.0.0/16']
        self.refused('address denied by CIDR')

    def test_non_ipv4(self):
        for address in ('example.net', '2606:4700:4700::1111', '8.08.8.8'):
            with self.subTest(address=address):
                self.params['address'] = address
                self.refused('address must be literal IPv4')

    def test_address_already_live(self):
        self.append(key=KEYS[2], hosts=['8.8.8.8'], expiry=NOW + 4000)
        self.refused('address already live')

    def test_standing_key(self):
        self.params['key'] = KEYS[0]
        self.refused('standing key protected')

    def test_duplicate_key(self):
        self.append(key=KEYS[1], hosts=['1.1.1.1'], expiry=NOW + 4000)
        self.refused('key already recorded')

    def test_invalid_curve_key(self):
        self.params['key'] = 'f' * 64
        self.refused('invalid x-only key')

    def test_expiry_over_max_hours(self):
        self.params['expiry_unix'] = NOW + 86401
        self.refused('expiry exceeds max-hours')

    def test_remote_max_hours_ceiling_and_smaller_limits(self):
        for hours in (0, -1, 25, 48):
            with self.subTest(hours=hours):
                self.params['max_hours'] = hours
                self.refused('max-hours must be greater than 0 and at most 24')
        for hours in (24, 1):
            with self.subTest(hours=hours):
                self.system.put(ops.PASSES, passes.write_toml(self.system.original_records), 0o640)
                self.params.update(max_hours=hours, expiry_unix=NOW + hours * 3600)
                self.assertEqual(self.issue(), 0)
                self.assertTrue(self.output[-1].startswith('CONFIRMED'))

    def test_expiry_too_soon(self):
        self.params['expiry_unix'] = NOW + 600
        self.refused('expiry must exceed now plus 600 seconds')

    def test_expiry_boundary_inside_wait_window(self):
        for expiry in (NOW - 5, NOW, NOW + 34):
            with self.subTest(expiry=expiry):
                self.system.put(ops.PASSES, passes.write_toml(self.system.original_records), 0o640)
                self.append(key=KEYS[2], hosts=['1.1.1.1'], expiry=expiry)
                self.refused('expiry inside confirmation window')

    def test_wrong_running_binary_no_write_or_reload(self):
        self.system.running = '0' * 64
        self.refused('running binary sha mismatch')

    def test_inactive_unit(self):
        self.system.is_active = False
        self.refused('unit not active')

    def test_exec_reload_missing(self):
        self.system.put(ops.UNIT, b'[Service]\n')
        self.refused('ExecReload missing')

    def test_rule_missing_live(self):
        self.system.live_rule = False
        self.refused('port-22 rule missing live')

    def test_rule_missing_file(self):
        self.system.put(ops.NFT, b'define relay_uid = 999\nchain output {\n}\n')
        self.refused('port-22 rule missing file')

    def test_rule_removed_during_issue_or_revoke_not_confirmed(self):
        for mode in ('issue', 'revoke'):
            for location in ('live', 'file'):
                with self.subTest(mode=mode, location=location):
                    self.system.put(ops.PASSES, passes.write_toml(self.system.original_records), 0o640)
                    self.system.live_rule = True
                    self.system.put(ops.NFT, b'define relay_uid = 999\nchain output {\n'
                                    b'meta skuid $relay_uid tcp dport != 22 reject\n}\n')
                    self.params['mode'] = mode
                    if mode == 'revoke':
                        self.append(key=KEYS[1], hosts=['8.8.8.8'], expiry=NOW + 3600)
                    if location == 'live':
                        self.system.on_journal = lambda: setattr(self.system, 'live_rule', False)
                    else:
                        self.system.on_journal = lambda: self.system.put(
                            ops.NFT, b'define relay_uid = 999\nchain output {\n}\n')
                    self.assertEqual(self.issue(), 1)
                    self.assertEqual(self.output[-1], 'NOT CONFIRMED: port-22 rule missing ' + location)

    def test_commented_or_wrong_chain_rule_refused(self):
        for text in ('# meta skuid $relay_uid tcp dport != 22 reject\nchain output {\n}\n',
                     'chain input {\nmeta skuid $relay_uid tcp dport != 22 reject\n}\nchain output {\n}\n'):
            self.system.put(ops.NFT, ('define relay_uid = 999\n' + text).encode())
            self.refused('port-22 rule missing file')

    def test_refusal_timeout_and_wrong_counts_do_not_restore_or_retry(self):
        for lines, reason in ((['pass reload refused'], 'relay refused reload'),
                              ([], 'reload confirmation timeout'),
                              (['pass reload applied: 2 passes, 1 in force'], 'reload counts mismatch'),
                              (['pass reload applied: 2 passes, 2 in force '], 'reload counts mismatch')):
            with self.subTest(reason=reason, lines=lines):
                self.system.put(ops.PASSES, passes.write_toml(self.system.original_records), 0o640)
                self.system.calls.clear()
                self.system.reload_lines = lines
                self.assertEqual(self.issue(), 1)
                self.assertIn('NOT CONFIRMED: ' + reason, self.output)
                self.assertEqual(len(self.current()), 2)
                self.assertEqual(self.system.calls.count(('systemctl', 'reload', ops.SERVICE)), 1)

    def test_first_outcome_wins(self):
        self.system.reload_lines = ['pass reload refused', 'pass reload applied: 2 passes, 2 in force']
        self.assertEqual(self.issue(), 1)
        self.assertEqual(self.output[-1], 'NOT CONFIRMED: relay refused reload')

    def test_changed_standing_digest_not_confirmed(self):
        def change_standing():
            records = self.current()
            records[0]['expiry'] += 100
            self.system.put(ops.PASSES, passes.write_toml(records), 0o640)
        self.system.on_journal = change_standing
        self.assertEqual(self.issue(), 1)
        self.assertEqual(self.output[-1], 'NOT CONFIRMED: standing digest changed')

    def test_changed_file_not_confirmed(self):
        self.system.on_journal = lambda: self.system.put(ops.PASSES, self.system.read(ops.PASSES) + b'# changed\n', 0o640)
        self.system.reload_lines = ['pass reload applied: 2 passes, 2 in force']
        self.assertEqual(self.issue(), 1)
        self.assertEqual(self.output[-1], 'NOT CONFIRMED: pass file sha changed')

    def test_changed_running_binary_not_confirmed(self):
        self.system.on_journal = lambda: setattr(self.system, 'running', '0' * 64)
        self.assertEqual(self.issue(), 1)
        self.assertEqual(self.output[-1], 'NOT CONFIRMED: running binary sha mismatch')

    def test_revoke_confirmed_with_m_decreasing(self):
        self.assertEqual(self.issue(), 0)
        self.params['mode'] = 'revoke'
        self.params['expiry_unix'] = None
        self.assertEqual(self.issue(), 0)
        self.assertTrue(self.current()[1]['revoked'])
        self.assertIn('N=2 M=1', self.output[-1])
        self.assertTrue(self.output[-1].startswith('CONFIRMED mode=revoke'))

    def test_revoke_requires_exact_single_host_record(self):
        self.params['mode'] = 'revoke'
        self.refused('exact pass record absent')

    def test_toml_writer_preserves_standing_values(self):
        for revoked in (None, False, True):
            record = dict(key=KEYS[0], hosts=['host.example', '8.8.4.4'], expiry=NOW + 200_000)
            if revoked is not None:
                record['revoked'] = revoked
            self.assertEqual(passes.records(passes.write_toml([record])), [record])

    def upgrade_params(self):
        return dict(standing_key=KEYS[0], rollback=False,
                    expect_old_binary_sha256=ops.sha(OLD), expect_old_unit_sha256=ops.sha(UNIT),
                    binary=base64.b64encode(NEW).decode(), unit=base64.b64encode(UNIT + b'# new\n').decode(),
                    new_binary_sha256=ops.sha(NEW))

    def test_upgrade_success_changes_only_binary_and_unit(self):
        protected = {path: self.system.read(path) for path in upgrade.PROTECTED}
        self.assertEqual(upgrade.perform(self.system, self.upgrade_params(), self.output.append), 0)
        self.assertEqual(self.system.read(ops.BINARY), NEW)
        self.assertEqual(self.system.read(ops.BINARY + '.prev'), OLD)
        self.assertEqual(self.system.read(ops.UNIT + '.prev'), UNIT)
        self.assertEqual({path: self.system.read(path) for path in upgrade.PROTECTED}, protected)
        self.assertEqual(self.output[-1], 'PASS UPGRADED')
        self.assertEqual([call for call in self.system.calls if call[0] == 'systemctl'],
                         [('systemctl', 'daemon-reload'), ('systemctl', 'restart', ops.SERVICE),
                          ('systemctl', 'is-active', ops.SERVICE)])

    def test_upgrade_rollback_on_failed_start(self):
        self.system.fail_new_start = True
        self.assertEqual(upgrade.perform(self.system, self.upgrade_params(), self.output.append), 1)
        self.assertEqual(self.system.read(ops.BINARY), OLD)
        self.assertEqual(self.system.read(ops.UNIT), UNIT)
        self.assertEqual(self.system.running_sha(), ops.sha(OLD))
        self.assertEqual(self.system.restarts, 2)
        self.assertEqual(self.output[-1], 'ROLLED BACK')

    def test_upgrade_rollback_failed_plainly(self):
        self.system.fail_rollback = True
        self.assertEqual(upgrade.perform(self.system, self.upgrade_params(), self.output.append), 1)
        self.assertEqual(self.output[-1], 'ROLLBACK FAILED')

    def test_upgrade_explicit_rollback(self):
        params = self.upgrade_params()
        self.assertEqual(upgrade.perform(self.system, params, self.output.append), 0)
        params['rollback'] = True
        self.assertEqual(upgrade.perform(self.system, params, self.output.append), 0)
        self.assertEqual(self.system.read(ops.BINARY), OLD)
        self.assertEqual(self.system.read(ops.UNIT), UNIT)
        self.assertEqual(self.output[-1], 'ROLLED BACK')

    def test_upgrade_wrong_old_hash_refused_before_mutation(self):
        params = self.upgrade_params()
        params['expect_old_binary_sha256'] = '0' * 64
        with self.assertRaisesRegex(ops.Refused, 'old binary sha mismatch'):
            upgrade.perform(self.system, params, self.output.append)
        self.assertFalse(any(call[0] == 'stage' for call in self.system.calls))

    def test_upgrade_missing_listening_line_rolls_back(self):
        self.system.start_lines[ops.sha(NEW)] = []
        self.assertEqual(upgrade.perform(self.system, self.upgrade_params(), self.output.append), 1)
        self.assertEqual(self.output[-1], 'ROLLED BACK')

    def test_rollback_without_fresh_listening_line_fails(self):
        params = self.upgrade_params()
        self.assertEqual(upgrade.perform(self.system, params, self.output.append), 0)
        self.system.start_lines[ops.sha(OLD)] = []
        params['rollback'] = True
        self.assertEqual(upgrade.perform(self.system, params, self.output.append), 1)
        self.assertTrue(self.system.active())
        self.assertEqual(self.system.running_sha(), ops.sha(OLD))
        self.assertEqual(self.output[-1], 'ROLLBACK FAILED')

    def test_rollback_cursor_failure_still_restarts_restored_relay(self):
        params = self.upgrade_params()
        self.assertEqual(upgrade.perform(self.system, params, self.output.append), 0)
        restarts = self.system.restarts
        self.system.missing_cursor = True
        params['rollback'] = True
        self.assertEqual(upgrade.perform(self.system, params, self.output.append), 1)
        self.assertEqual(self.system.restarts, restarts + 1)
        self.assertEqual(self.system.running_sha(), ops.sha(OLD))
        self.assertEqual(self.system.read(ops.BINARY), OLD)
        self.assertEqual(self.output[-1], 'ROLLBACK FAILED')

    def test_explicit_rollback_retains_interrupted_upgrade_stages(self):
        params = self.upgrade_params()
        self.system.put(ops.BINARY + '.prev', OLD, 0o755)
        self.system.put(ops.UNIT + '.prev', UNIT)
        self.system.put(ops.BINARY, NEW, 0o755)
        self.system.put(ops.BINARY + '.new', b'interrupted binary', 0o755)
        self.system.put(ops.UNIT + '.new', b'interrupted unit')
        params['rollback'] = True
        protected = {path: self.system.read(path) for path in upgrade.PROTECTED}
        for attempt in range(2):
            with self.subTest(attempt=attempt):
                self.assertEqual(upgrade.perform(self.system, params, self.output.append), 0)
                self.assertEqual(self.system.read(ops.BINARY), OLD)
                self.assertEqual(self.system.read(ops.UNIT), UNIT)
                self.assertEqual(self.system.read(ops.BINARY + '.new'), b'interrupted binary')
                self.assertEqual(self.system.read(ops.UNIT + '.new'), b'interrupted unit')
                self.assertEqual({path: self.system.read(path) for path in upgrade.PROTECTED}, protected)
                self.assertIn('PASS retained upgrade stage: binary', self.output)
                self.assertIn('PASS retained upgrade stage: unit', self.output)
                self.assertEqual(self.output[-1], 'ROLLED BACK')
        stages = [call[1] for call in self.system.calls if call[0] == 'stage']
        self.assertEqual(len(stages), 4)
        self.assertEqual(len(set(stages)), 4)
        self.assertTrue(all('.rollback-' in path and path.endswith('.new') for path in stages))

    def test_automatic_rollback_retains_unpublished_upgrade_stage(self):
        params = self.upgrade_params()
        original_replace = os.replace
        def interrupt_unit_replace(source, destination):
            if source == self.system.path(ops.UNIT + '.new'):
                raise OSError('interrupted unit replacement')
            return original_replace(source, destination)
        with patch.object(upgrade.os, 'replace', side_effect=interrupt_unit_replace):
            self.assertEqual(upgrade.perform(self.system, params, self.output.append), 1)
        self.assertEqual(self.system.read(ops.BINARY), OLD)
        self.assertEqual(self.system.read(ops.UNIT), UNIT)
        self.assertEqual(self.system.read(ops.UNIT + '.new'), base64.b64decode(params['unit']))
        self.assertIn('PASS retained upgrade stage: unit', self.output)
        self.assertEqual(self.output[-1], 'ROLLED BACK')

    def test_standing_absent_revoked_or_expired(self):
        for records, reason in (([], 'standing pass absent'),
                                ([dict(self.system.original_records[0], revoked=True)], 'standing pass not in force'),
                                ([dict(self.system.original_records[0], expiry=NOW - 100)], 'standing pass not in force')):
            with self.subTest(reason=reason):
                self.system.put(ops.PASSES, passes.write_toml(records), 0o640)
                self.refused(reason)

    def test_remote_programs_compile_and_import_without_commands(self):
        for module, params in (('pass_ops', self.params), ('upgrade_ops', self.upgrade_params())):
            source = ops.remote_program(module, params)
            compile(source, '<remote>', 'exec')
            # Execute the actual packaged module definitions, never their entry point.
            definitions = source[:source.rfind('sys.exit(')]
            with patch.dict(sys.modules):
                exec(definitions, {})
                self.assertTrue(callable(sys.modules[module].perform))

    def test_pinned_transport_matches_deploy_options(self):
        class Args:
            known_hosts = '/operator/known_hosts'
            identity = '/operator/identity with spaces'
            host = 'relay.example.net'
        self.assertEqual(ops.ssh(Args, 'command'),
                         ['ssh', '-F', '/dev/null', '-o', 'StrictHostKeyChecking=yes',
                          '-o', 'UserKnownHostsFile=/operator/known_hosts',
                          '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'UpdateHostKeys=no',
                          '-o', 'IdentitiesOnly=yes', '-i', Args.identity, 'arch@relay.example.net', 'command'])

    def load_cli(self, filename):
        spec = importlib.util.spec_from_file_location('operation_cli', DEPLOY / filename)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_issue_cli_one_locked_session(self):
        cli = self.load_cli('issue-pass.py')
        argv = ['issue-pass.py', 'issue', '--host', 'relay.example.net',
                '--known-hosts', '/operator/known_hosts', '--identity', '/operator/key',
                '--key', KEYS[1], '--address', '8.8.8.8', '--standing-key', KEYS[0],
                '--expiry-unix', str(NOW + 3600), '--expect-binary-sha256', ops.sha(OLD)]
        with patch.object(sys, 'argv', argv), patch.object(ops.subprocess, 'run') as run:
            run.return_value.returncode = 0
            run.return_value.stdout = b''
            self.assertEqual(cli.main(), 0)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0][-1],
                             'sudo -n flock -x /run/lock/tau-relay-passes.lock python3 -')
            program = run.call_args.kwargs['input'].decode()
            compile(program, '<remote>', 'exec')
            self.assertIn('sys.exit(m.remote_main(json.loads(', program)

    def test_cli_max_hours_ceiling_before_transport(self):
        cli = self.load_cli('issue-pass.py')
        for hours in (0, -1, 25, 48, 24, 1):
            with self.subTest(hours=hours):
                argv = ['issue-pass.py', 'issue', '--host', 'relay.example.net',
                        '--known-hosts', '/operator/known_hosts', '--identity', '/operator/key',
                        '--key', KEYS[1], '--address', '8.8.8.8', '--standing-key', KEYS[0],
                        '--expiry-unix', str(NOW + 3600), '--expect-binary-sha256', ops.sha(OLD),
                        '--max-hours', str(hours)]
                with patch.object(sys, 'argv', argv), patch.object(ops.subprocess, 'run') as run:
                    if 0 < hours <= 24:
                        run.return_value.returncode = 0
                        run.return_value.stdout = b''
                        self.assertEqual(cli.main(), 0)
                        self.assertEqual(run.call_count, 1)
                    else:
                        with self.assertRaisesRegex(ops.Refused,
                                                    'max-hours must be greater than 0 and at most 24'):
                            cli.main()
                        run.assert_not_called()

    def test_cli_dry_runs_execute_nothing_and_redact(self):
        for name in ('issue-pass.py', 'upgrade.py'):
            cli = self.load_cli(name)
            argv = [name, '--host', 'relay.example.net', '--known-hosts', '/operator/known_hosts',
                    '--identity', '/operator/key', '--standing-key', KEYS[0], '--dry-run']
            if name == 'issue-pass.py':
                argv.insert(1, 'issue')
                argv += ['--key', KEYS[1], '--address', '8.8.8.8', '--expiry-unix', str(NOW + 3600),
                         '--expect-binary-sha256', ops.sha(OLD)]
            else:
                argv += ['--binary', '/nonexistent/binary', '--expect-old-binary-sha256', ops.sha(OLD),
                         '--expect-old-unit-sha256', ops.sha(UNIT)]
            output = io.StringIO()
            with patch.object(sys, 'argv', argv), patch.object(ops.subprocess, 'run') as run, \
                    patch('time.time', return_value=NOW), contextlib.redirect_stdout(output):
                self.assertEqual(cli.main(), 0)
                run.assert_not_called()
            self.assertNotIn(KEYS[0], output.getvalue())
            self.assertNotIn(KEYS[1], output.getvalue())
            self.assertNotIn('8.8.8.8', output.getvalue())

    def test_upgrade_verification_failure_preserves_installed_files(self):
        original_run = self.system.run
        def fail_verify(*args):
            if args[:2] == ('systemd-analyze', 'verify'):
                raise ops.Refused('command failed: systemd-analyze')
            return original_run(*args)
        self.system.run = fail_verify
        self.assertEqual(upgrade.perform(self.system, self.upgrade_params(), self.output.append), 1)
        self.assertEqual(self.system.read(ops.BINARY), OLD)
        self.assertEqual(self.system.read(ops.UNIT), UNIT)
        self.assertEqual(self.system.restarts, 0)

    def test_upgrade_preserves_unexplained_existing_stage(self):
        self.system.put(ops.BINARY + '.new', b'other work', 0o755)
        self.assertEqual(upgrade.perform(self.system, self.upgrade_params(), self.output.append), 1)
        self.assertEqual(self.system.read(ops.BINARY + '.new'), b'other work')
        self.assertEqual(self.system.read(ops.BINARY), OLD)

    def test_numeric_firewall_rule_accepted(self):
        data = self.system.read(ops.NFT).replace(b'$relay_uid', b'999')
        self.system.put(ops.NFT, data)
        self.assertEqual(self.issue(), 0)

    def test_missing_cursor_refuses_before_rename(self):
        self.system.missing_cursor = True
        before = self.system.read(ops.PASSES)
        self.assertEqual(self.issue(), 1)
        self.assertEqual(self.output[-1], 'NOT CONFIRMED: journal cursor missing')
        self.assertEqual(self.system.read(ops.PASSES), before)
        self.assertNotIn(('systemctl', 'reload', ops.SERVICE), self.system.calls)
        self.assertFalse(any(path.name.endswith('.new') for path in
                             self.system.path('/etc/tau-relay').iterdir()))

    def test_running_executable_reader_uses_only_mainpid_exe(self):
        boundary = ops.System(self.temp.name)
        self.system.put('/proc/123/exe', OLD, 0o755)
        with patch.object(boundary, 'run', return_value='123\n') as run:
            self.assertEqual(boundary.running_sha(), ops.sha(OLD))
            run.assert_called_once_with('systemctl', 'show', ops.SERVICE,
                                        '--property=MainPID', '--value')

    def test_transport_failure_prints_not_confirmed_without_retry(self):
        class Args:
            known_hosts = '/operator/known_hosts'
            identity = '/operator/key'
            host = 'relay.example.net'
        output = io.StringIO()
        with patch.object(ops.subprocess, 'run') as run, contextlib.redirect_stdout(output):
            run.return_value.returncode = 255
            run.return_value.stdout = b''
            self.assertEqual(ops.run_remote(Args, 'command', 'program', 'NOT CONFIRMED'), 255)
            self.assertEqual(run.call_count, 1)
            self.assertIs(run.call_args.kwargs['stderr'], ops.subprocess.DEVNULL)
        self.assertEqual(output.getvalue(),
                         'NOT CONFIRMED: remote session failed; stop and establish the outcome\n')

    def test_remote_entry_points_return_safe_refusals(self):
        self.system.running = '0' * 64
        output = io.StringIO()
        with patch.object(passes, 'System', return_value=self.system), contextlib.redirect_stdout(output):
            self.assertEqual(passes.remote_main(self.params), 1)
        self.assertEqual(output.getvalue(), 'NOT CONFIRMED: running binary sha mismatch\n')


if __name__ == '__main__':
    unittest.main()
