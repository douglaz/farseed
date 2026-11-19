"""Locked pass-file planning, publication and reload confirmation."""
import copy
import ipaddress
import json
import re
import tomllib

from relay_ops import (CONFIG, PASSES, UNIT, SERVICE, Refused, System, check_rule,
                       hash_argument, mask, require, sha, valid_key)

# Copied exactly from relay/src/policy.rs:63-82 (V4_DENY).
V4_DENY = (
    (0x00000000, 8),
    (0x0a000000, 8),
    (0x64400000, 10),
    (0x7f000000, 8),
    (0xa9fe0000, 16),
    (0xac100000, 12),
    (0xc0000000, 24),
    (0xc0000200, 24),
    (0xc01fc400, 24),
    (0xc034c100, 24),
    (0xc0586300, 24),
    (0xc0a80000, 16),
    (0xc0af3000, 24),
    (0xc6120000, 15),
    (0xc6336400, 24),
    (0xcb007100, 24),
    (0xe0000000, 4),
    (0xf0000000, 4),
)


def records(data):
    file = tomllib.loads(data.decode())
    require(set(file) == {'passes'} and isinstance(file['passes'], list), 'invalid pass file')
    passes = file['passes']
    require(len(passes) <= 128, 'too many passes')
    keys, hosts = set(), set()
    for record in passes:
        require(isinstance(record, dict) and set(record) <= {'key', 'hosts', 'expiry', 'revoked'}
                and {'key', 'hosts', 'expiry'} <= set(record), 'invalid pass record')
        require(valid_key(record['key']), 'invalid pass key')
        require(type(record['expiry']) is int and 0 < record['expiry'] <= 2**64 - 1
                and type(record.get('revoked', False)) is bool, 'invalid pass values')
        require(isinstance(record['hosts'], list) and 1 <= len(record['hosts']) <= 16
                and all(isinstance(host, str) and host for host in record['hosts']),
                'invalid pass hosts')
        require(record['key'] not in keys, 'duplicate pass key')
        keys.add(record['key'])
        for host in record['hosts']:
            require(host not in hosts, 'duplicate pass host')
            hosts.add(host)
    return passes


def standing_digest(passes, key, now):
    standing = [record for record in passes if record['key'] == key]
    require(len(standing) == 1, 'standing pass absent')
    require(live(standing[0], now), 'standing pass not in force')
    return sha(json.dumps(standing[0], sort_keys=True, separators=(',', ':')).encode())


def live(record, now):
    return not record.get('revoked', False) and now < record['expiry']


def write_toml(passes):
    if not passes:
        return b'passes = []\n'
    lines = []
    for record in passes:
        lines += ['[[passes]]', 'key = ' + json.dumps(record['key']),
                  'hosts = ' + json.dumps(record['hosts']), 'expiry = ' + str(record['expiry'])]
        if 'revoked' in record:
            lines.append('revoked = ' + str(record['revoked']).lower())
        lines.append('')
    data = ('\n'.join(lines) + '\n').encode()
    require(len(data) <= 256 * 1024, 'pass file too large')
    require(records(data) == passes, 'TOML round-trip mismatch')
    return data


def validate_parameters(params):
    require(params['mode'] in ('issue', 'revoke'), 'invalid mode')
    require(valid_key(params['key']) and valid_key(params['standing_key']), 'invalid x-only key')
    require(params['key'] != params['standing_key'], 'standing key protected')
    try:
        address = ipaddress.IPv4Address(params['address'])
    except ipaddress.AddressValueError:
        raise Refused('address must be literal IPv4') from None
    require(address.is_global, 'address must be public IPv4')
    if params['mode'] == 'issue':
        require(not any(int(address) >> (32 - bits) == base >> (32 - bits)
                        for base, bits in V4_DENY), 'address denied by relay policy')
    require(params['timeout'] > 0, 'invalid time limits')
    require(0 < params['max_hours'] <= 24, 'max-hours must be greater than 0 and at most 24')
    hash_argument(params['expect_binary_sha256'])
    for cidr in params['deny_cidr']:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            raise Refused('invalid deny CIDR') from None
        require(address not in network, 'address denied by CIDR')
    return str(address)


def validate_expiry(params, now):
    if params['mode'] == 'issue':
        expiry = params['expiry_unix']
        require(type(expiry) is int and expiry > now + 600, 'expiry must exceed now plus 600 seconds')
        require(expiry <= now + params['max_hours'] * 3600, 'expiry exceeds max-hours')


def plan(params, passes, own_public, now):
    address = validate_parameters(params)
    require(address not in [str(ipaddress.ip_address(ip)) for ip in own_public],
            'address belongs to relay')
    validate_expiry(params, now)
    result = copy.deepcopy(passes)
    matches = [record for record in result if record['key'] == params['key']
               and record['hosts'] == [address]]
    if params['mode'] == 'revoke':
        require(len(matches) == 1, 'exact pass record absent')
        if matches[0].get('revoked', False):
            return result, [], True, matches[0]['expiry']
        matches[0]['revoked'] = True
        return result, [], False, matches[0]['expiry']
    if matches and live(matches[0], now):
        return result, [], True, matches[0]['expiry']
    require(not any(record['key'] == params['key'] and record not in matches for record in result),
            'key already recorded')
    tombstones = [record for record in result if address in record['hosts']]
    require(not any(live(record, now) for record in tombstones), 'address already live')
    require(not any(record['key'] == params['standing_key'] for record in tombstones),
            'standing pass protected')
    result = [record for record in result if record not in tombstones]
    result.append(dict(key=params['key'], hosts=[address], expiry=params['expiry_unix'], revoked=False))
    return result, tombstones, False, params['expiry_unix']


def check_running(system, expected):
    require(system.active(), 'unit not active')
    require(system.running_sha() == expected, 'running binary sha mismatch')


def perform(system, params, emit=print):
    validate_parameters(params)
    check_running(system, params['expect_binary_sha256'])
    unit = system.read(UNIT).decode()
    require(re.search(r'^ExecReload=/bin/kill -HUP \$MAINPID\s*$', unit, re.M),
            'ExecReload missing')
    check_rule(system)
    before_data = system.read(PASSES)
    before = records(before_data)
    now = system.now()
    standing_before = standing_digest(before, params['standing_key'], now)
    config = tomllib.loads(system.read(CONFIG).decode())
    require(config.get('pass_file') == PASSES, 'configured pass file mismatch')
    require(isinstance(config.get('own_public'), list) and config['own_public'], 'own_public missing')
    after, tombstones, already, expiry = plan(params, before, config['own_public'], now)
    n = len(after)
    m = sum(live(record, now) for record in after)
    summary = (f"mode={params['mode']} key={params['key'][:8]} address={mask(params['address'])} "
               f'expiry={expiry} N={n} M={m}')
    emit(summary)
    emit('standing before=' + standing_before)
    emit('file before=' + sha(before_data))
    if already:
        emit('standing after=' + standing_before)
        emit('file after=' + sha(before_data))
        emit('ALREADY ' + summary)
        return 0
    # Include removed records too: expiry drift cannot obscure a concurrent outcome.
    require(not any(now - 5 <= record['expiry'] <= now + params['timeout'] + 30
                    for record in before + after), 'expiry inside confirmation window')
    data = write_toml(after)
    standing_after = standing_digest(after, params['standing_key'], now)
    require(standing_after == standing_before, 'standing digest changed')
    for record in tombstones:
        emit(f"tombstone key={record['key'][:8]} address={mask(params['address'])}")
    # Refuse if another writer changed the file before publication.
    require(system.read(PASSES) == before_data, 'pass file changed before write')
    cursor = system.atomic_pass(data, system.cursor)
    emit('file after=' + sha(data))
    emit('standing after=' + standing_after)
    system.run('systemctl', 'reload', SERVICE)
    deadline = system.monotonic() + params['timeout']
    expected = f'pass reload applied: {n} passes, {m} in force'
    while system.monotonic() < deadline:
        outcome = next((line for line in system.journal(cursor)
                        if line == 'pass reload refused' or line.startswith('pass reload applied:')), None)
        if outcome is not None:
            require(outcome != 'pass reload refused', 'relay refused reload')
            require(outcome == expected, 'reload counts mismatch')
            observed_data = system.read(PASSES)
            observed = standing_digest(records(observed_data), params['standing_key'], system.now())
            emit('standing after=' + observed)
            require(observed == standing_before, 'standing digest changed')
            require(sha(observed_data) == sha(data), 'pass file sha changed')
            check_running(system, params['expect_binary_sha256'])
            check_rule(system)
            emit('CONFIRMED ' + summary)
            return 0
        system.sleep()
    raise Refused('reload confirmation timeout')


def remote_main(params):
    try:
        return perform(System(), params)
    except Refused as error:
        print('NOT CONFIRMED: ' + str(error))
    except Exception:
        # Never expose file data or command output through an exception message.
        print('NOT CONFIRMED: operating-system or file validation failure')
    return 1
