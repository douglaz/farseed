"""Binary and unit replacement with preserved-state checks and rollback."""
import base64
import ipaddress
import os
import re
import uuid

from relay_ops import (BINARY, UNIT, CONFIG, PASSES, NFT, CADDY, SERVICE, Refused,
                       System, check_rule, require, sha)
from pass_ops import records, standing_digest

PROTECTED = (CONFIG, PASSES, CADDY, NFT)
LABELS = {BINARY: 'binary', UNIT: 'unit', CONFIG: 'config', PASSES: 'passes',
          CADDY: 'caddy', NFT: 'firewall'}


def snapshot(system, standing_key, emit):
    values = {}
    for path in (BINARY, UNIT) + PROTECTED:
        values[path] = system.digest(path)
        emit('PASS ' + LABELS[path] + ' sha256=' + values[path])
    values['standing'] = standing_digest(records(system.read(PASSES)), standing_key, system.now())
    emit('PASS standing sha256=' + values['standing'])
    check_rule(system)
    emit('PASS port-22 rules')
    return values


def preserved(system, before, key, emit):
    after = snapshot(system, key, emit)
    require(all(after[path] == before[path] for path in PROTECTED), 'protected file sha changed')
    require(after['standing'] == before['standing'], 'standing digest changed')


def listening(line):
    match = re.fullmatch(r'listening (.+):(\d+)', line)
    if not match:
        return False
    try:
        return ipaddress.ip_address(match[1].strip('[]')).is_loopback and 0 < int(match[2]) < 65536
    except ValueError:
        return False


def wait_started(system, expected, cursor):
    deadline = system.monotonic() + 30
    while system.monotonic() < deadline:
        if system.active():
            if any(listening(line) for line in system.journal(cursor)):
                require(system.running_sha() == expected, 'running binary sha mismatch')
                return
        system.sleep()
    raise Refused('start confirmation timeout')


def replace(system, path, data, mode, suffix='.new'):
    stage = path + suffix
    # Refuse an unexplained stage rather than overwrite another operator's work.
    system.stage(stage, data, mode, (0, 0))
    os.replace(system.path(stage), system.path(path))
    system.sync_dir(str(system.path(path).parent.relative_to(system.root)))


def rollback(system, params, before, emit):
    for path in (BINARY, UNIT):
        if system.path(path + '.new').exists():
            emit('PASS retained upgrade stage: ' + LABELS[path])
    old_binary = system.read(BINARY + '.prev')
    old_unit = system.read(UNIT + '.prev')
    require(sha(old_binary) == params['expect_old_binary_sha256'], 'backup binary sha mismatch')
    require(sha(old_unit) == params['expect_old_unit_sha256'], 'backup unit sha mismatch')
    suffix = '.rollback-' + uuid.uuid4().hex + '.new'
    replace(system, BINARY, old_binary, 0o755, suffix)
    replace(system, UNIT, old_unit, 0o644, suffix)
    system.run('systemctl', 'daemon-reload')
    # A journal failure must not skip the restart of the restored relay; it only leaves rollback unconfirmed.
    try:
        cursor = system.cursor()
    except Exception:
        cursor = None
    system.run('systemctl', 'restart', SERVICE)
    require(cursor is not None, 'rollback journal cursor unavailable')
    wait_started(system, params['expect_old_binary_sha256'], cursor)
    require(system.digest(BINARY) == params['expect_old_binary_sha256'], 'restored binary sha mismatch')
    require(system.digest(UNIT) == params['expect_old_unit_sha256'], 'restored unit sha mismatch')
    preserved(system, before, params['standing_key'], emit)


def perform(system, params, emit=print):
    before = snapshot(system, params['standing_key'], emit)
    if params['rollback']:
        try:
            rollback(system, params, before, emit)
        except Exception:
            emit('ROLLBACK FAILED')
            return 1
        emit('ROLLED BACK')
        return 0
    require(before[BINARY] == params['expect_old_binary_sha256'], 'old binary sha mismatch')
    require(before[UNIT] == params['expect_old_unit_sha256'], 'old unit sha mismatch')
    binary = base64.b64decode(params['binary'], validate=True)
    unit = base64.b64decode(params['unit'], validate=True)
    require(sha(binary) == params['new_binary_sha256'], 'new binary sha mismatch')
    binary_stage, unit_stage = BINARY + '.new', UNIT + '.new'
    verify_dir = '/etc/systemd/system/.tau-relay-verify-' + uuid.uuid4().hex
    system.path(verify_dir).mkdir(mode=0o755)
    backed_up = False
    staged = []
    changed = False
    try:
        system.stage(binary_stage, binary, 0o755, (0, 0))
        staged.append(binary_stage)
        system.stage(unit_stage, unit, 0o644, (0, 0))
        staged.append(unit_stage)
        require(os.access(system.path(binary_stage), os.X_OK), 'new binary not executable')
        require(system.digest(binary_stage) == params['new_binary_sha256'], 'staged binary sha mismatch')
        # Verification needs a valid .service basename, while publication uses .new.
        verify_path = verify_dir + '/tau-relay.service'
        system.stage(verify_path, unit, 0o644, (0, 0))
        system.run('systemd-analyze', 'verify', str(system.path(verify_path)))
        # Backups are durable before either installed file is replaced.
        replace(system, BINARY + '.prev', system.read(BINARY), 0o755)
        replace(system, UNIT + '.prev', system.read(UNIT), 0o644)
        backed_up = True
        changed = True
        os.replace(system.path(binary_stage), system.path(BINARY))
        os.replace(system.path(unit_stage), system.path(UNIT))
        system.sync_dir('/usr/local/bin')
        system.sync_dir('/etc/systemd/system')
        system.run('systemctl', 'daemon-reload')
        cursor = system.cursor()
        system.run('systemctl', 'restart', SERVICE)
        wait_started(system, params['new_binary_sha256'], cursor)
        require(system.digest(BINARY) == params['new_binary_sha256'], 'installed binary sha mismatch')
        require(system.digest(UNIT) == sha(unit), 'installed unit sha mismatch')
        preserved(system, before, params['standing_key'], emit)
        emit('PASS UPGRADED')
        return 0
    except Exception as error:
        emit('FAIL: ' + (str(error) if isinstance(error, Refused) else 'upgrade operation failed'))
        if backed_up and changed:
            try:
                rollback(system, params, before, emit)
                emit('ROLLED BACK')
            except Exception:
                emit('ROLLBACK FAILED')
        else:
            emit('FAIL before replacement; installed files unchanged')
        return 1
    finally:
        for path in staged:
            if not changed:
                system.path(path).unlink(missing_ok=True)
        system.path(verify_dir + '/tau-relay.service').unlink(missing_ok=True)
        system.path(verify_dir).rmdir()


def remote_main(params):
    try:
        return perform(System(), params)
    except Refused as error:
        print('FAIL: ' + str(error))
    except Exception:
        print('FAIL: operating-system or file validation failure')
    return 1
