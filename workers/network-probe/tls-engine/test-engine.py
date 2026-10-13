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
import sys
import tempfile
import threading
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
                    # A child close frame can retire this socket earlier in the
                    # same select batch. Ignore that now-stale readiness event.
                    if sock is None or key.fileobj is not sock:
                        continue
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
def server(openssl, certificate, key, protocol, extra=(), staple=None, alternate=None):
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    family = 'modern' if 'modern' in str(openssl) else 'legacy'
    args = [BUILD / 'bin' / ('fixture-server-' + family), str(port), certificate, key, protocol]
    if extra or staple or alternate: args.append(extra[1] if extra else 'ALL:eNULL:!PSK:!SRP')
    if staple or alternate: args.append(staple or '-')
    if alternate: args.extend(alternate)
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
        cls.measurements = []
        for family in ['legacy','modern']:
            prefix = BUILD / ('install-' + family)
            lib = prefix / ('lib64' if (prefix / 'lib64/libssl.a').exists() else 'lib')
            linker = ['-lpthread', *(['-lz'] if family == 'legacy' else []),
                      *(['-ldl'] if platform.system() == 'Linux' else [])]
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
        cls.chain_leaf, cls.chain_key = cls.fixture / 'chain-leaf.pem', cls.fixture / 'chain-leaf.key'
        cls.complete_chain = cls.fixture / 'chain-complete.pem'
        intermediate = cls.fixture / 'intermediate.pem'
        intermediate_key = cls.fixture / 'intermediate.key'
        intermediate_request = cls.fixture / 'intermediate.csr'
        leaf_request = cls.fixture / 'chain-leaf.csr'
        chain_config = cls.fixture / 'chain.cnf'
        chain_config.write_text('[intermediate]\nbasicConstraints=critical,CA:TRUE,pathlen:0\n'
                                'keyUsage=critical,keyCertSign,cRLSign\n'
                                '[leaf]\nbasicConstraints=critical,CA:FALSE\n'
                                'keyUsage=critical,digitalSignature,keyEncipherment\n'
                                'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n')
        run([cls.modern, 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
             '-config', config, '-subj', '/CN=LocalIntermediate', '-keyout', intermediate_key,
             '-out', intermediate_request])
        run([cls.modern, 'x509', '-req', '-in', intermediate_request, '-CA', cls.cert,
             '-CAkey', cls.key, '-CAcreateserial', '-days', '2', '-sha256',
             '-extfile', chain_config, '-extensions', 'intermediate', '-out', intermediate])
        run([cls.modern, 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
             '-config', config, '-subj', '/CN=localhost', '-keyout', cls.chain_key, '-out', leaf_request])
        run([cls.modern, 'x509', '-req', '-in', leaf_request, '-CA', intermediate,
             '-CAkey', intermediate_key, '-CAcreateserial', '-days', '2', '-sha256',
             '-extfile', chain_config, '-extensions', 'leaf', '-out', cls.chain_leaf])
        cls.complete_chain.write_bytes(cls.chain_leaf.read_bytes() + intermediate.read_bytes())
        cls.alternate_cert = cls.fixture / 'alternate.pem'
        cls.alternate_key = cls.fixture / 'alternate.key'
        alternate_config = cls.fixture / 'alternate.cnf'
        alternate_config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n'
                                    '[dn]\nCN=other.example.org\n[ext]\n'
                                    'subjectAltName=DNS:other.example.org\n'
                                    'basicConstraints=critical,CA:TRUE\n'
                                    'keyUsage=critical,keyCertSign,digitalSignature,keyEncipherment\n')
        run([cls.modern, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256',
             '-days', '2', '-config', alternate_config,
             '-out', cls.alternate_cert, '-keyout', cls.alternate_key])
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
        serial = run([cls.modern, 'x509', '-in', cls.cert, '-serial', '-noout']).stdout.decode().strip().split('=', 1)[1]
        expiry = (now + timedelta(days=2)).strftime('%y%m%d%H%M%SZ')
        revoked_at = (now - timedelta(hours=1)).strftime('%y%m%d%H%M%SZ')
        cls.ocsp = {}
        for status, index_line in [
            ('good', f'V\t{expiry}\t\t{serial}\tunknown\t/CN=localhost\n'),
            ('revoked', f'R\t{expiry}\t{revoked_at}\t{serial}\tunknown\t/CN=localhost\n'),
        ]:
            index = cls.fixture / f'{status}.index'
            index.write_text(index_line)
            output = cls.fixture / f'{status}.der'
            run([cls.modern, 'ocsp', '-index', index, '-CA', cls.cert, '-rsigner', cls.cert,
                 '-rkey', cls.key, '-issuer', cls.cert, '-serial', '0x' + serial,
                 '-respout', output, '-ndays', '1'])
            cls.ocsp[status] = output
        bad = cls.fixture / 'bad-signature.der'
        run([cls.modern, 'ocsp', '-index', cls.fixture / 'good.index', '-CA', cls.cert,
             '-rsigner', cls.cert, '-rkey', cls.key, '-issuer', cls.cert,
             '-serial', '0x' + serial, '-respout', bad, '-ndays', '1', '-badsig'])
        cls.ocsp['bad_signature'] = bad
        stale = cls.fixture / 'stale.der'
        prefix = BUILD / 'install-modern'
        lib = prefix / ('lib64' if (prefix / 'lib64/libssl.a').exists() else 'lib')
        helper = BUILD / 'bin/ocsp-stale-fixture'
        run(['cc', '-I' + str(prefix / 'include'), ENGINE / 'src/ocsp-stale-fixture.c',
             lib / 'libcrypto.a', *(['-lpthread', '-ldl'] if platform.system() == 'Linux' else []),
             '-o', helper])
        run([helper, cls.cert, cls.key, stale])
        cls.ocsp['stale'] = stale

    @classmethod
    def tearDownClass(cls):
        samples = cls.measurements
        durations = sorted(row['telemetry']['duration_ms'] for row in samples)
        if durations:
            print('TLS loopback cost: ' + json.dumps({
                'real_checks': len(samples),
                'accepted': sum(row['state'] == 'accepted' for row in samples),
                'uncertain': sum(row['state'] == 'uncertain' for row in samples),
                'connections': sum(row['telemetry']['connections'] for row in samples),
                'bytes_sent': sum(row['telemetry']['bytes_sent'] for row in samples),
                'bytes_received': sum(row['telemetry']['bytes_received'] for row in samples),
                'duration_ms': {'min': durations[0], 'median': durations[len(durations)//2],
                                'p95': durations[(95*len(durations)-1)//100], 'max': durations[-1]},
            }, sort_keys=True), file=sys.stderr)
        cls.directory.cleanup()

    def assess(self, protocol, port=None, control='handshake', family=None, extra=(),
               hostname='localhost', trust=None, **kwargs):
        family = family or ('modern' if protocol == 'tls1_3' else 'legacy')
        result = bridge(BUILD / 'bin' / ('tls-baseline-' + family),
                        ['--protocol', protocol, '--control', control, '--hostname', hostname,
                         '--trust-bundle', str(trust or self.cert), '--timeout-ms', '5000', *extra], port, **kwargs)
        if port is not None:
            self.measurements.append(result)
        return result

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

    def test_authorized_sni_and_alpn_are_sent_and_observed(self):
        with server(self.modern, self.cert, self.key, 'tls1_2') as port:
            result = self.assess('tls1_2', port, family='modern',
                                 extra=['--alpn', 'h2-http1'])
        self.assertEqual(result['state'], 'accepted', result)
        self.assertTrue(result['negotiated']['sni_sent'])
        self.assertEqual(result['negotiated']['alpn'], 'h2')

    def test_pinned_openssl_reference_agrees_on_same_endpoint(self):
        for protocol, cipher in [('tls1_2', 'ECDHE-RSA-AES128-GCM-SHA256'),
                                 ('tls1_3', 'TLS_AES_128_GCM_SHA256')]:
            with self.subTest(protocol=protocol):
                with server(self.modern, self.cert, self.key, protocol) as port:
                    result = self.assess(protocol, port, family='modern', control='certificate',
                                         extra=['--cipher', cipher])
                    command = [self.modern, 's_client', '-brief', '-connect', f'127.0.0.1:{port}',
                               '-servername', 'localhost', '-verify_hostname', 'localhost',
                               '-CAfile', self.cert, '-' + protocol]
                    if protocol == 'tls1_2':
                        command.extend(['-cipher', cipher])
                    else:
                        command.extend(['-ciphersuites', cipher])
                    reference = run(command, input=b'', timeout=5)
                output = (reference.stdout + reference.stderr).decode()
                self.assertEqual(result['state'], 'accepted', result)
                self.assertEqual(result['negotiated']['cipher'], cipher)
                self.assertEqual(result['certificates']['trust'], 'valid')
                self.assertTrue(result['certificates']['hostname'])
                self.assertIn('Protocol version: ' + protocol.replace('tls', 'TLSv').replace('_', '.'), output)
                self.assertIn('Ciphersuite: ' + cipher, output)
                self.assertIn('Verification: OK', output)

    def test_pinned_openssl_reference_legacy_protocols_and_ciphers(self):
        cases = [
            ('ssl2', 'SSLv2', 'RC4-MD5'),
            ('ssl3', 'SSLv3', 'RC4-SHA'),
            ('tls1', 'TLSv1', 'RC4-SHA'),
            ('tls1_1', 'TLSv1.1', 'DES-CBC3-SHA'),
            ('tls1_2', 'TLSv1.2', 'ECDHE-RSA-AES128-GCM-SHA256'),
        ]
        for protocol, reference_version, cipher in cases:
            with self.subTest(protocol=protocol, cipher=cipher):
                with server(self.legacy, self.cert, self.key, protocol,
                            ['-cipher', cipher]) as port:
                    result = self.assess(protocol, port, extra=['--cipher', cipher])
                    command = [self.legacy, 's_client', '-connect', f'127.0.0.1:{port}',
                               '-CAfile', self.cert, '-' + protocol, '-cipher', cipher]
                    if protocol != 'ssl2':
                        command.extend(['-servername', 'localhost'])
                    reference = run(command, input=b'', timeout=5)
                output = (reference.stdout + reference.stderr).decode()
                self.assertEqual(result['state'], 'accepted', result)
                self.assertTrue(result['authenticated_finished'])
                self.assertEqual(result['negotiated']['cipher'], cipher)
                self.assertEqual(result['certificates']['trust'], 'valid')
                self.assertIn('Protocol  : ' + reference_version, output)
                self.assertIn('Cipher    : ' + cipher, output)
                self.assertIn('Verify return code: 0 (ok)', output)

    def test_pinned_openssl_reference_certificate_failures(self):
        cases = [
            ('wrong_hostname', self.cert, self.key, self.cert,
             'other.example.org', 'hostname mismatch'),
            ('untrusted', self.cert, self.key, self.unrelated_cert,
             'localhost', 'self-signed certificate'),
            ('expired', self.expired_cert, self.expired_key, self.expired_cert,
             'localhost', 'certificate has expired'),
            ('not_yet_valid', self.future_cert, self.future_key, self.future_cert,
             'localhost', 'certificate is not yet valid'),
            ('missing_intermediate', self.chain_leaf, self.chain_key, self.cert,
             'localhost', 'unable to get local issuer certificate'),
        ]
        for scenario, certificate, key, trust, hostname, diagnostic in cases:
            with self.subTest(scenario=scenario):
                with server(self.modern, certificate, key, 'tls1_2') as port:
                    result = self.assess('tls1_2', port, family='modern',
                                         control='certificate', hostname=hostname, trust=trust)
                    reference = subprocess.run(
                        [str(self.modern), 's_client', '-brief', '-connect', f'127.0.0.1:{port}',
                         '-servername', 'localhost', '-verify_hostname', hostname,
                         '-CAfile', str(trust), '-verify_return_error', '-tls1_2'],
                        input=b'', capture_output=True, timeout=5)
                output = (reference.stdout + reference.stderr).decode()
                self.assertEqual(result['state'], 'accepted', result)
                self.assertTrue(result['authenticated_finished'])
                self.assertNotEqual(reference.returncode, 0, output)
                self.assertIn(diagnostic, output)
                if scenario == 'wrong_hostname':
                    self.assertFalse(result['certificates']['hostname'])
                    self.assertEqual(result['certificates']['trust'], 'valid')
                else:
                    self.assertEqual(result['certificates']['trust'], 'invalid')
        with server(self.modern, self.complete_chain, self.chain_key, 'tls1_2') as port:
            complete = self.assess('tls1_2', port, family='modern', control='certificate')
            reference = run([self.modern, 's_client', '-brief', '-connect', f'127.0.0.1:{port}',
                             '-servername', 'localhost', '-verify_hostname', 'localhost',
                             '-CAfile', self.cert, '-verify_return_error', '-tls1_2'],
                            input=b'', timeout=5)
        self.assertEqual(complete['certificates']['trust'], 'valid')
        self.assertEqual(len(complete['certificates']['offered_chain']), 2)
        self.assertIn('Verification: OK', (reference.stdout + reference.stderr).decode())

    def test_same_ip_selects_different_certificates_by_sni(self):
        alternate=(self.alternate_cert,self.alternate_key,'other.example.org')
        with server(self.modern,self.cert,self.key,'tls1_2',alternate=alternate) as port:
            primary=self.assess('tls1_2',port,family='modern',control='certificate')
            other=self.assess('tls1_2',port,family='modern',control='certificate',
                              hostname='other.example.org',trust=self.alternate_cert)
        self.assertEqual(primary['state'],'accepted',primary)
        self.assertEqual(other['state'],'accepted',other)
        self.assertNotEqual(primary['certificates']['offered_chain'][0]['sha256'],
                            other['certificates']['offered_chain'][0]['sha256'])
        self.assertEqual(other['certificates']['trust'],'valid')
        self.assertTrue(other['certificates']['hostname'])

    def test_session_resumption_requires_a_second_finished_handshake(self):
        for protocol, family in [('tls1_2', 'legacy'), ('tls1_3', 'modern')]:
            with self.subTest(protocol=protocol):
                openssl = self.legacy if family == 'legacy' else self.modern
                with server(openssl, self.cert, self.key, protocol) as port:
                    result = self.assess(protocol, port, control='resumption', family=family,
                                         extra=['--max-connections', '2'])
                self.assertEqual(result['state'], 'accepted', result)
                self.assertEqual(result['reason'], 'resumption_completed')
                self.assertTrue(result['authenticated_finished'])
                self.assertTrue(result['extensions']['session_reused'])
                self.assertEqual(result['telemetry']['connections'], 2)

    def test_early_data_capacity_is_observed_without_sending_application_data(self):
        with server(self.modern, self.cert, self.key, 'tls1_3_early') as port:
            result = self.assess('tls1_3', port, control='resumption', family='modern',
                                 extra=['--max-connections', '2'])
        self.assertIn(result['state'], ['accepted', 'rejected'], result)
        self.assertEqual(result['extensions']['early_data_max'], 1024)
        self.assertEqual(result['telemetry']['connections'], 2)

    def test_fallback_scsv_protected_and_supported_paths(self):
        with server(self.modern, self.cert, self.key, 'both') as port:
            protected = self.assess('tls1_2', port, control='fallback', family='modern')
        self.assertEqual(protected['state'], 'rejected', protected)
        self.assertEqual(protected['reason'], 'fallback_rejected')
        self.assertFalse(protected['authenticated_finished'])
        self.assertEqual(protected['telemetry']['connections'], 1)
        with server(self.modern, self.cert, self.key, 'tls1_2') as port:
            supported = self.assess('tls1_2', port, control='fallback', family='modern')
        self.assertEqual(supported['state'], 'accepted', supported)
        self.assertTrue(supported['authenticated_finished'])
        self.assertEqual(supported['telemetry']['connections'], 1)

    def test_stapled_ocsp_status_and_signature_are_verified(self):
        for fixture, expected in [('good', 'good'), ('revoked', 'revoked'),
                                  ('bad_signature', 'invalid'), ('stale', 'invalid')]:
            with self.subTest(fixture=fixture):
                with server(self.modern, self.cert, self.key, 'tls1_2',
                            staple=self.ocsp[fixture]) as port:
                    result = self.assess('tls1_2', port, family='modern', control='certificate')
                self.assertEqual(result['state'], 'accepted', result)
                self.assertEqual(result['ocsp']['state'], expected, result)
                self.assertTrue(result['ocsp']['cert_id_match'])
                self.assertEqual(result['ocsp']['fresh'], fixture != 'stale')
                self.assertEqual(result['ocsp']['signature_valid'], fixture != 'bad_signature')

    def test_one_bounded_client_renegotiation(self):
        with server(self.legacy, self.cert, self.key, 'tls1_2') as port:
            result = self.assess('tls1_2', port, control='renegotiation')
        self.assertEqual(result['state'], 'accepted', result)
        self.assertEqual(result['reason'], 'renegotiation_completed')
        self.assertTrue(result['extensions']['renegotiation_completed'])
        self.assertEqual(result['telemetry']['connections'], 1)

    def test_compression_is_measured_only_by_dedicated_legacy_check(self):
        for protocol in ('ssl3', 'tls1', 'tls1_1', 'tls1_2'):
            with self.subTest(protocol=protocol):
                with server(self.legacy, self.cert, self.key, protocol) as port:
                    offered = self.assess(protocol, port, control='compression')
                    ordinary = self.assess(protocol, port)
                    offered_reference = run([self.legacy, 's_client', '-connect', f'127.0.0.1:{port}',
                                             '-servername', 'localhost', '-' + protocol], input=b'', timeout=5)
                self.assertEqual(offered['state'], 'accepted', offered)
                self.assertTrue(offered['authenticated_finished'])
                self.assertTrue(offered['extensions']['compression'])
                self.assertIsNone(ordinary['extensions']['compression'])
                self.assertIn('Compression: zlib compression',
                              (offered_reference.stdout + offered_reference.stderr).decode())
                with server(self.legacy, self.cert, self.key, protocol + '_nocomp') as port:
                    refused = self.assess(protocol, port, control='compression')
                    refused_reference = run([self.legacy, 's_client', '-connect', f'127.0.0.1:{port}',
                                             '-servername', 'localhost', '-' + protocol], input=b'', timeout=5)
                self.assertEqual(refused['state'], 'accepted', refused)
                self.assertTrue(refused['authenticated_finished'])
                self.assertFalse(refused['extensions']['compression'])
                self.assertIn('Compression: NONE',
                              (refused_reference.stdout + refused_reference.stderr).decode())

    def test_version_rejection_is_not_engine_unsupported(self):
        with server(self.modern, self.cert, self.key, 'tls1_3') as port:
            result = self.assess('tls1_2', port, family='modern')
        self.assertEqual(result['state'], 'rejected', result)
        self.assertEqual(result['reason'], 'protocol_version_rejected')
        self.assertFalse(result['authenticated_finished'])
        self.assertGreater(result['telemetry']['connections'], 0)

    def test_unrelated_fatal_alert_is_uncertain(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            def answer():
                with listener.accept()[0] as peer:
                    peer.settimeout(2)
                    peer.recv(4096)
                    peer.sendall(bytes.fromhex('15030300020250'))  # fatal internal_error
            worker = threading.Thread(target=answer, daemon=True)
            worker.start()
            result = self.assess('tls1_2', port, family='modern')
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
        self.assertEqual(result['state'], 'uncertain')
        self.assertEqual(result['reason'], 'peer_alert')
        self.assertFalse(result['authenticated_finished'])

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

    def test_offered_and_verified_chains_remain_distinct(self):
        with server(self.modern, self.chain_leaf, self.chain_key, 'tls1_2') as port:
            missing = self.assess('tls1_2', port, family='modern', control='certificate')
        with server(self.modern, self.complete_chain, self.chain_key, 'tls1_2') as port:
            complete = self.assess('tls1_2', port, family='modern', control='certificate')
        self.assertEqual(missing['state'], 'accepted')
        self.assertEqual(missing['certificates']['trust'], 'invalid')
        self.assertEqual(len(missing['certificates']['offered_chain']), 1)
        self.assertEqual(missing['certificates']['trusted_chain'], [])
        self.assertEqual(complete['state'], 'accepted')
        self.assertEqual(complete['certificates']['trust'], 'valid')
        self.assertEqual(len(complete['certificates']['offered_chain']), 2)
        self.assertEqual(len(complete['certificates']['trusted_chain']), 3)

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
