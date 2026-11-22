#!/usr/bin/env python3
"""Offline P1 regressions: execute the playbook shell against synthetic loopback HTTP only."""
import datetime
import fcntl
import http.server
import json
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parent.parent
PLAYBOOK = (ROOT / 'templates/control-center/playbook.md').read_text()
SCRIPT = PLAYBOOK.split("cat > /etc/nixos/credit-status.sh <<'FILE'\n", 1)[1].split('\nFILE\n', 1)[0] + '\n'


class CreditStatus(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / '.p1-checks')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.monitor = self.root / 'hermes/credit-monitor'
        self.workspace = self.root / 'hermes/workspace'
        self.page = self.root / 'page'
        for directory in (self.monitor, self.workspace, self.page):
            directory.mkdir(parents=True)
        self.account = self.root / 'hermes/credit-account'
        self.account.write_text(json.dumps({'credit_id': 'test-account', 'default_key': 'test-key'}))
        self.journal = self.monitor / 'state.json'
        self.balance = 5
        self.balances = []
        self.usage = 1.25
        self.status = {'invoice_id': 'invoice-1', 'status': 'New', 'amount_paid': 0}
        self.status_code = 200
        self.create_code = 201
        self.create_bad = False
        self.keys_bad = False
        self.calls = []
        self.errors = []
        fixture = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                self.reply()

            def do_POST(self):
                self.reply()

            def reply(self):
                fixture.calls.append((self.command, self.path))
                code = 200
                payload = None
                if self.path == '/credits/balance':
                    body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                    if body != {'credit_id': 'test-account'}:
                        fixture.errors.append('wrong balance body')
                    value = fixture.balances.pop(0) if fixture.balances else fixture.balance
                    payload = {'balance': value}
                elif self.path == '/keys?include_disabled=true':
                    if self.headers.get('x-credit-id') != 'test-account':
                        fixture.errors.append('wrong keys auth')
                    key = {'_id': 'hermes-key', 'reset_period': 'monthly', 'usage_limit_usd': 5,
                           'expire_at': None, 'current_period_usage_usd': fixture.usage}
                    payload = {'data': [key, key] if fixture.keys_bad else [key]}
                elif self.path == '/topup/create/btc-lightning':
                    if self.headers.get('Authorization') != 'Bearer test-key':
                        fixture.errors.append('wrong create auth')
                    state = json.loads(fixture.journal.read_text())
                    if state['invoice']['state'] != 'unknown' or state['count'] < 1 or state['last_create'] <= 0:
                        fixture.errors.append('intent not saved before create')
                    body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                    if body != {'amount': 2000, 'currency': 'SATS'}:
                        fixture.errors.append('wrong invoice request')
                    code = fixture.create_code
                    payload = {'invoice_id': 'invoice-1', 'amount': 2000, 'currency': 'SATS',
                               'expires_at': int(time.time()) + 900, 'lightning_invoice': 'lnbc2000synthetic'}
                    if code == 0:
                        self.close_connection = True
                        return
                    if fixture.create_bad:
                        payload.pop('lightning_invoice')
                elif self.path == '/topup/status/invoice-1':
                    if self.headers.get('Authorization') != 'Bearer test-key':
                        fixture.errors.append('wrong poll auth')
                    code, payload = fixture.status_code, fixture.status
                else:
                    fixture.errors.append('unexpected HTTP path')
                    code, payload = 404, {}
                encoded = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header('Content-Length', str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        script = SCRIPT.replace('/var/lib/hermes', str(self.root / 'hermes'))
        script = script.replace('/var/lib/credit-status', str(self.page))
        script = script.replace('https://api.ppq.ai', f'http://127.0.0.1:{self.server.server_port}')
        self.assertNotIn('https://', script)
        self.script = self.root / 'monitor.sh'
        self.script.write_text(script)

    def run_monitor(self):
        result = subprocess.run(['sh', str(self.script)], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(self.errors, [])
        self.assertNotIn('test-key', self.text())
        return self.text()

    def text(self):
        return (self.workspace / 'credit-status.txt').read_text()

    def state(self):
        return json.loads(self.journal.read_text())

    def update_state(self, **fields):
        state = self.state()
        state.update(fields)
        self.journal.write_text(json.dumps(state))

    def creates(self):
        return sum(path == '/topup/create/btc-lightning' for _, path in self.calls)

    def invoice(self):
        self.run_monitor()
        self.assertEqual(self.creates(), 1)
        self.assertEqual(self.state()['invoice']['state'], 'pending')

    def test_missing_account_never_calls_vendor_and_renders(self):
        self.account.unlink()
        text = self.run_monitor()
        self.assertIn('machine credit account: not set up yet', text)
        self.assertIn('ALERT: rent date unknown', text)
        self.assertEqual(self.calls, [])
        self.assertIn('content="60"', (self.page / 'index.html').read_text())

    def test_unreadable_balance_and_malformed_account_block_creation(self):
        self.balance = None
        self.assertIn('Credit balance unreadable', self.run_monitor())
        self.assertEqual(self.creates(), 0)
        self.calls.clear()
        self.account.write_text('{')
        self.assertIn('Machine credit account unreadable', self.run_monitor())
        self.assertEqual(self.calls, [])

    def test_threshold_usage_and_ambiguous_key(self):
        self.balance = 35
        self.assertIn('This period usage: 1.25', self.run_monitor())
        self.assertEqual(self.creates(), 0)
        self.keys_bad = True
        self.assertIn('usage unreadable or ambiguous', self.run_monitor())
        self.keys_bad = False
        self.usage = 5
        self.assertIn('ALERT: Hermes monthly 5 USD limit reached', self.run_monitor())
        self.balance = 34.99
        self.run_monitor()
        self.assertEqual(self.creates(), 1)

    def test_creation_saved_and_pending_reused(self):
        self.invoice()
        text = self.run_monitor()
        self.assertEqual(self.creates(), 1)
        self.assertIn('Invoice: 2000 sat', text)
        self.assertIn('Bolt11: lnbc2000synthetic', text)
        self.assertIn('Minutes left:', text)
        self.assertIn('lightning:lnbc2000synthetic', (self.page / 'index.html').read_text())

    def test_confirmed_expiry_needs_zero_paid_and_fresh_balance(self):
        self.invoice()
        self.update_state(last_create=0)
        self.status.update(status='Expired', amount_paid=1)
        self.assertIn('Invoice outcome unknown', self.run_monitor())
        self.assertEqual(self.creates(), 1)
        self.status['amount_paid'] = 0
        self.balances = [5, None]
        self.assertIn('Fresh balance unreadable', self.run_monitor())
        self.assertEqual(self.creates(), 1)
        self.balances = [5, 5]
        self.run_monitor()
        self.assertEqual(self.creates(), 2)
        self.assertEqual(self.state()['history'][-1]['state'], 'expired_unpaid')

    def test_expiry_balance_rise_records_paid_and_above_threshold_stops(self):
        self.invoice()
        self.status.update(status='Expired', amount_paid=0)
        self.balances = [5, 36]
        self.run_monitor()
        self.assertEqual(self.state()['invoice']['state'], 'paid')
        self.assertNotIn('lightning:', (self.page / 'index.html').read_text())
        self.assertEqual(self.creates(), 1)

    def test_unknown_status_and_http_failure_block_until_resolved(self):
        self.invoice()
        self.update_state(last_create=0)
        for status in ('Mystery', None, 'New'):
            with self.subTest(status=status):
                state = self.state()
                state['invoice']['expires_at'] = 1
                self.journal.write_text(json.dumps(state))
                self.status['status'] = status
                self.assertIn('Invoice outcome unknown', self.run_monitor())
                self.assertEqual(self.creates(), 1)
        self.status_code = 503
        self.run_monitor()
        self.assertEqual(self.creates(), 1)
        self.status_code = 200
        self.status['status'] = 'Settled'
        self.run_monitor()
        self.assertEqual(self.creates(), 2)

    def test_mismatched_status_identity_does_not_resolve(self):
        self.invoice()
        self.update_state(last_create=0)
        self.status.update(invoice_id='other', status='Expired')
        self.assertIn('Invoice outcome unknown', self.run_monitor())
        self.assertEqual(self.creates(), 1)

    def test_unclear_creation_never_retried(self):
        for code, bad in ((503, False), (201, True), (0, False)):
            with self.subTest(code=code, malformed=bad):
                self.journal.unlink(missing_ok=True)
                self.calls.clear()
                self.create_code, self.create_bad = code, bad
                self.assertIn('Invoice creation outcome unknown', self.run_monitor())
                self.update_state(last_create=0)
                self.run_monitor()
                self.assertEqual(self.creates(), 1)
                self.assertEqual(self.state()['invoice']['state'], 'unknown')

    def test_rate_limits_and_utc_rollover(self):
        self.invoice()
        self.status['status'] = 'Settled'
        self.assertIn('rate limit reached', self.run_monitor())
        self.assertEqual(self.creates(), 1)
        self.update_state(last_create=0, count=100)
        self.assertIn('rate limit reached', self.run_monitor())
        self.assertEqual(self.creates(), 1)
        self.update_state(day='2000-01-01')
        self.run_monitor()
        self.assertEqual(self.creates(), 2)
        self.assertEqual(self.state()['count'], 1)

    def test_corrupt_or_changed_account_state_never_recreates(self):
        self.invoice()
        self.update_state(credit_id='other')
        self.calls.clear()
        self.assertIn('Credit journal invalid or account changed', self.run_monitor())
        self.assertEqual(self.calls, [])
        self.journal.write_text('{')
        self.assertIn('Credit journal invalid', self.run_monitor())
        self.assertEqual(self.calls, [])

    def test_rent_windows_and_html_escaping(self):
        self.balance = 40
        today = datetime.datetime.now(datetime.timezone.utc).date()
        for days, message in ((20, None), (10, 'within 14 days'), (2, 'within 3 days'), (-1, 'overdue')):
            with self.subTest(days=days):
                (self.monitor / 'paid-through').write_text(str(today + datetime.timedelta(days=days)))
                text = self.run_monitor()
                if message:
                    self.assertIn(message, text)
                else:
                    self.assertNotIn('ALERT:', text)
        (self.monitor / 'paid-through').write_text('<script>alert(1)</script>')
        self.assertIn('rent date unknown', self.run_monitor())
        self.assertNotIn('<script>', (self.page / 'index.html').read_text())

    def test_parallel_invocation_cannot_dispatch(self):
        with (self.monitor / 'lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            result = subprocess.run(['sh', str(self.script)], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.calls, [])


class TemplateSyntax(unittest.TestCase):
    def test_all_shell_blocks_and_new_scripts_parse(self):
        for index, source in enumerate(re.findall(r'```sh\n(.*?)\n```', PLAYBOOK, re.S)):
            with self.subTest(block=index):
                subprocess.run(['sh', '-n'], input=source, text=True, check=True)
        subprocess.run(['sh', '-n'], input=SCRIPT, text=True, check=True)
        prestart = PLAYBOOK.split('pkgs.writeShellScript "credit-rent-snapshot" \'\'\n', 1)[1].split("\n    ''}", 1)[0]
        subprocess.run(['sh', '-n'], input=prestart, text=True, check=True)
        auth = PLAYBOOK.split('systemd.services.credit-status-auth = {', 1)[1].split("    script = ''\n", 1)[1].split("\n    '';", 1)[0]
        subprocess.run(['sh', '-n'], input=auth.replace('${pkgs.openssl}', '/openssl'), text=True, check=True)

    def test_exact_agent_rules_and_private_auth(self):
        self.assertIn('If /var/lib/hermes/workspace/credit-status.txt has a line starting with `ALERT:`, tell the user at the start of your next reply, with the status page address <http://10.88.0.1:9121/>.', PLAYBOOK)
        self.assertIn('When the user asks for a credit invoice, read it from that file; never make one yourself.', PLAYBOOK)
        self.assertIn('${pkgs.openssl}/bin/openssl passwd -6 -stdin < /var/lib/control-center/dashboard-password', PLAYBOOK)
        self.assertNotIn('--auth ', PLAYBOOK)
        self.assertIn('basicAuthFile = "/var/lib/credit-status-auth/htpasswd";', PLAYBOOK)


if __name__ == '__main__':
    (ROOT / '.p1-checks').mkdir(exist_ok=True)
    unittest.main()
