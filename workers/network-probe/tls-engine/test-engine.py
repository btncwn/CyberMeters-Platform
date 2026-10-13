#!/usr/bin/env python3
"""Loopback-only integration rigs. Never imports or probes customer targets."""
import argparse
import contextlib
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import socket
import struct
import subprocess
import tempfile
import time
import unittest

ENGINE = Path(__file__).resolve().parent
BUILD = ENGINE / '.build'


def run(command, **kwargs):
    return subprocess.run(list(map(str, command)), check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, **kwargs)


def frame(kind, payload=b''):
    return struct.pack('!BI', kind, len(payload)) + payload


def read_exact(stream, length):
    result = b''
    while len(result) < length:
        block = stream.read(length - len(result))
        if not block:
            raise AssertionError('child ended before complete frame')
        result += block
    return result


def bridge(binary, arguments, port=None, mutate=None, abort=False):
    """Test-only parent; target is always hard-coded loopback, never argv."""
    child = subprocess.Popen([str(binary), *arguments], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    sock = None
    counts = {'connections': 0, 'bytes_sent': 0, 'bytes_received': 0}
    result = None
    last_closed = False
    started = time.monotonic()
    events = selectors.DefaultSelector()
    events.register(child.stdout, selectors.EVENT_READ, 'child')
    try:
        while time.monotonic() - started < 30:
            ready = events.select(0.5)
            if not ready and child.poll() is not None:
                raise AssertionError('child exited without result: ' + str(child.returncode))
            for key, _ in ready:
                if key.data == 'network':
                    data = sock.recv(16384)
                    if not data:
                        events.unregister(sock)
                        sock.close()
                        sock = None
                        last_closed = True
                        child.stdin.write(frame(4, b'eof'))
                    else:
                        counts['bytes_received'] += len(data)
                        if mutate:
                            data = mutate(data)
                        child.stdin.write(frame(2, data))
                    continue
                header = read_exact(child.stdout, 5)
                kind, length = struct.unpack('!BI', header)
                assert length <= (262144 if kind == 3 else 16384)
                payload = read_exact(child.stdout, length)
                if kind == 1:
                    assert not payload and sock is None
                    last_closed = False
                    counts['connections'] += 1
                    if abort:
                        child.stdin.write(frame(5))
                    else:
                        assert port is not None
                        sock = socket.create_connection(('127.0.0.1', port), timeout=2)
                        events.register(sock, selectors.EVENT_READ, 'network')
                        child.stdin.write(frame(1))
                elif kind == 2:
                    assert payload and sock is not None
                    counts['bytes_sent'] += len(payload)
                    sock.sendall(payload)
                elif kind == 4:
                    assert not payload
                    if sock is None and last_closed:
                        last_closed = False
                        continue
                    assert sock is not None
                    events.unregister(sock)
                    sock.close()
                    sock = None
                    child.stdin.write(frame(4, b'eof'))
                elif kind == 3:
                    result = json.loads(payload)
                    break
                else:
                    raise AssertionError('unknown child frame')
            if result is not None:
                break
        assert result is not None, 'child deadline exceeded'
        child.stdin.close()
        child.wait(timeout=2)
        assert child.returncode == 0
        assert child.stderr.read() == b'', 'engine emitted unsanitized diagnostics'
        assert child.stdout.read() == b'', 'unexpected second result'
        for key, value in counts.items():
            assert result['telemetry'][key] == value, (key, result['telemetry'], counts)
        return result
    finally:
        if sock:
            sock.close()
        events.close()
        if child.poll() is None:
            child.kill()
            child.wait()
        for stream in (child.stdin, child.stdout, child.stderr):
            stream.close()


@contextlib.contextmanager
def server(openssl, certificate, key, protocol, extra=()):
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    family = 'modern' if 'modern' in str(openssl) else 'legacy'
    args = [BUILD / 'bin' / ('fixture-server-' + family), str(port), certificate, key, protocol]
    if extra: args.append(extra[1])
    child = subprocess.Popen(list(map(str, args)), stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            if child.poll() is not None:
                raise AssertionError('fixture failed: ' + child.stderr.read().decode())
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.05):
                    break
            except OSError:
                time.sleep(.02)
        else:
            raise AssertionError('fixture did not start')
        yield port
    finally:
        child.terminate()
        child.wait(timeout=2)
        child.stderr.close()


class BaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for family in ['legacy','modern']:
            prefix = BUILD / ('install-' + family)
            lib = prefix / ('lib64' if (prefix / 'lib64/libssl.a').exists() else 'lib')
            linker = ['-lpthread', *(['-ldl'] if platform.system() == 'Linux' else [])]
            run(['cc', '-Wno-deprecated-declarations', '-I' + str(prefix / 'include'), ENGINE / 'src/fixture-server.c', lib / 'libssl.a', lib / 'libcrypto.a', *linker, '-o', BUILD / 'bin' / ('fixture-server-' + family)])
        cls.directory = tempfile.TemporaryDirectory(prefix='tls-rig-', dir=BUILD)
        cls.fixture = Path(cls.directory.name)
        cls.legacy = BUILD / 'install-legacy/bin/openssl'
        cls.modern = BUILD / 'install-modern/bin/openssl'
        cls.cert = cls.fixture / 'cert.pem'
        cls.key = cls.fixture / 'key.pem'
        config = cls.fixture / 'openssl.cnf'
        config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n'
                          '[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\n'
                          'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,digitalSignature,keyEncipherment\n')
        run([cls.modern, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256',
             '-days', '2', '-config', config, '-out', cls.cert, '-keyout', cls.key])
        cls.expired_cert, cls.expired_key = cls.fixture / 'expired.pem', cls.fixture / 'expired.key'
        cls.future_cert, cls.future_key = cls.fixture / 'future.pem', cls.fixture / 'future.key'
        cls.unrelated_cert, cls.unrelated_key = cls.fixture / 'unrelated.pem', cls.fixture / 'unrelated.key'
        now = datetime.now(timezone.utc)
        stamp = lambda days: (now + timedelta(days=days)).strftime('%Y%m%d%H%M%SZ')
        for certificate, key, before, after in [
            (cls.expired_cert, cls.expired_key, stamp(-3), stamp(-1)),
            (cls.future_cert, cls.future_key, stamp(1), stamp(3)),
            (cls.unrelated_cert, cls.unrelated_key, stamp(-1), stamp(2)),
        ]:
            run([cls.modern, 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', key])
            run([cls.modern, 'x509', '-new', '-key', key, '-subj', '/CN=localhost',
                 '-not_before', before, '-not_after', after, '-extfile', config,
                 '-extensions', 'ext', '-out', certificate])

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def assess(self, protocol, port=None, control='handshake', family=None, extra=(),
               hostname='localhost', trust=None, **kwargs):
        family = family or ('modern' if protocol == 'tls1_3' else 'legacy')
        return bridge(BUILD / 'bin' / ('tls-baseline-' + family),
                      ['--protocol', protocol, '--control', control, '--hostname', hostname,
                       '--trust-bundle', str(trust or self.cert), '--timeout-ms', '5000', *extra], port, **kwargs)

    def test_six_protocols_finished_and_exact_trust(self):
        for protocol in ['ssl2', 'ssl3', 'tls1', 'tls1_1', 'tls1_2', 'tls1_3']:
            with self.subTest(protocol=protocol):
                openssl = self.modern if protocol == 'tls1_3' else self.legacy
                with server(openssl, self.cert, self.key, protocol) as port:
                    result = self.assess(protocol, port)
                self.assertEqual(result['state'], 'accepted', result)
                self.assertTrue(result['authenticated_finished'])
                self.assertEqual(result['negotiated']['version'], protocol)
                self.assertEqual(result['certificates']['trust'], 'valid')
                self.assertTrue(result['certificates']['hostname'])
                self.assertEqual(result['certificates']['trust_bundle_sha256'], hashlib.sha256(self.cert.read_bytes()).hexdigest())
                self.assertEqual(len(result['certificates']['offered_chain']), 1)
                self.assertEqual(len(result['certificates']['trusted_chain']), 1)
                self.assertEqual(result['ocsp']['state'], 'absent')
                self.assertNotIn('localhost', json.dumps(result))

    def test_ssl2_four_real_ciphers(self):
        catalog = self.assess('ssl2', control='catalog')['catalog']
        self.assertEqual(len(catalog), 4)
        for cipher in catalog:
            with self.subTest(cipher=cipher['name']):
                with server(self.legacy, self.cert, self.key, 'ssl2', ['-cipher', cipher['name']]) as port:
                    result = self.assess('ssl2', port, extra=['--cipher', cipher['name']])
                self.assertEqual(result['state'], 'accepted', result)
                self.assertTrue(result['authenticated_finished'])
                self.assertEqual(result['negotiated']['cipher'], cipher['name'])

    def test_weak_cipher_and_key_exchange_are_observed(self):
        for cipher, expected_pfs in [('RC4-SHA', False),
                                     ('DES-CBC3-SHA', False),
                                     ('ECDHE-RSA-AES128-GCM-SHA256', True)]:
            with self.subTest(cipher=cipher):
                with server(self.legacy, self.cert, self.key, 'tls1_2', ['-cipher', cipher]) as port:
                    result = self.assess('tls1_2', port, extra=['--cipher', cipher])
                self.assertEqual(result['state'], 'accepted', result)
                self.assertTrue(result['authenticated_finished'])
                self.assertEqual(result['negotiated']['cipher'], cipher)
                self.assertEqual(result['negotiated']['pfs'], expected_pfs)

    def test_incompatible_cipher_does_not_contact_peer(self):
        result = self.assess('ssl3', extra=['--cipher', 'AES128-GCM-SHA256'])
        self.assertEqual(result['state'], 'unexecutable')
        self.assertEqual(result['telemetry']['connections'], 0)

    def test_cipher_expressions_are_not_accepted(self):
        result = self.assess('tls1_2', extra=['--cipher', 'ALL'])
        self.assertEqual(result['state'], 'unexecutable')
        self.assertEqual(result['telemetry']['connections'], 0)

    def test_parent_abort(self):
        result = self.assess('tls1_2', abort=True)
        self.assertEqual(result['reason'], 'aborted')
        self.assertFalse(result['authenticated_finished'])
        self.assertEqual(result['telemetry']['bytes_sent'], 0)

    def test_modern_ems(self):
        with server(self.modern, self.cert, self.key, 'tls1_2') as port:
            result = self.assess('tls1_2', port, family='modern')
        self.assertEqual(result['state'], 'accepted', result)
        self.assertTrue(result['extensions']['ems'])

    def test_version_rejection_is_not_engine_unsupported(self):
        with server(self.modern, self.cert, self.key, 'tls1_3') as port:
            result = self.assess('tls1_2', port, family='modern')
        self.assertEqual(result['state'], 'rejected', result)
        self.assertEqual(result['reason'], 'peer_alert')
        self.assertFalse(result['authenticated_finished'])
        self.assertGreater(result['telemetry']['connections'], 0)

    def test_tls13_success_does_not_hide_tls12_acceptance(self):
        with server(self.modern, self.cert, self.key, 'both') as port:
            newer = self.assess('tls1_3', port, family='modern')
            older = self.assess('tls1_2', port, family='modern')
        self.assertEqual(newer['state'], 'accepted', newer)
        self.assertEqual(older['state'], 'accepted', older)
        self.assertEqual(newer['negotiated']['version'], 'tls1_3')
        self.assertEqual(older['negotiated']['version'], 'tls1_2')

    def test_certificate_hostname_and_trust_are_independent(self):
        with server(self.modern, self.cert, self.key, 'tls1_2') as port:
            wrong_name = self.assess('tls1_2', port, family='modern', control='certificate', hostname='other.example.org')
            untrusted = self.assess('tls1_2', port, family='modern', control='certificate', trust=self.unrelated_cert)
        self.assertEqual(wrong_name['state'], 'accepted')
        self.assertFalse(wrong_name['certificates']['hostname'])
        self.assertEqual(wrong_name['certificates']['trust'], 'valid')
        self.assertTrue(untrusted['certificates']['hostname'])
        self.assertEqual(untrusted['certificates']['trust'], 'invalid')

    def test_expired_and_not_yet_valid_certificates_are_distinct(self):
        for certificate, key, expected in [
            (self.expired_cert, self.expired_key, 'expired'),
            (self.future_cert, self.future_key, 'not_yet_valid'),
        ]:
            with self.subTest(expected=expected):
                with server(self.modern, certificate, key, 'tls1_2') as port:
                    result = self.assess('tls1_2', port, family='modern', control='certificate', trust=certificate)
                self.assertEqual(result['state'], 'accepted')
                self.assertEqual(result['certificates']['trust'], 'invalid')
                self.assertFalse(result['certificates']['dates'])
                self.assertEqual(result['certificates']['reason'], expected)


if __name__ == '__main__':
    unittest.main(verbosity=2)
