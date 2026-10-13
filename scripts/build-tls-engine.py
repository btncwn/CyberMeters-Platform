#!/usr/bin/env python3
"""Build fixed upstream TLS engines locally. Never installs system packages.

All fetched archives are verified before extraction. Build products, compiler
logs, upstream trees and local fixture keys stay in the ignored .build directory.
The build does not execute an upstream download script or use a shell.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / 'workers/network-probe/tls-engine'


def sha256(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def run(command, cwd, log, env=None):
    with log.open('ab') as output:
        output.write(('\n' + ' '.join(map(str, command)) + '\n').encode())
        try:
            subprocess.run(list(map(str, command)), cwd=cwd, env=env,
                           stdout=output, stderr=subprocess.STDOUT, check=True)
        except subprocess.CalledProcessError:
            output.flush()
            with log.open('rb') as diagnostic:
                diagnostic.seek(max(0, diagnostic.seek(0, 2) - 8192))
                print(diagnostic.read().decode('utf8', 'replace'), file=sys.stderr)
            raise


def write_catalog(build):
    entries, engines = [], {}
    for protocol in ['ssl2', 'ssl3', 'tls1', 'tls1_1', 'tls1_2', 'tls1_3']:
        family = 'modern' if protocol == 'tls1_3' else 'legacy'
        binary = build / 'bin' / ('tls-baseline-' + family)
        if not binary.exists():
            return
        wire = subprocess.check_output([str(binary), '--control', 'catalog', '--protocol', protocol], timeout=5)
        if len(wire) < 5 or wire[0] != 3 or int.from_bytes(wire[1:5], 'big') != len(wire)-5:
            raise RuntimeError('invalid catalog framing')
        result = json.loads(wire[5:])
        engines[family] = {'version': result['engine']['version'], 'source_sha256': next(
            row['sha256'] for row in json.loads((ENGINE / 'sources.json').read_text())['sources'] if row['id'] == family)}
        for cipher in result['catalog']:
            entries.append({'protocol': protocol, 'engine': family, **cipher})
    output = {'schema': 'tls-compiled-catalog-v1', 'engines': engines, 'entries': entries}
    (ENGINE / 'compiled-catalog.generated.json').write_text(json.dumps(output, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--engine', choices=['legacy', 'modern', 'all'], default='all')
    parser.add_argument('--build-dir', type=Path, default=ENGINE / '.build')
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--libraries-only', action='store_true')
    args = parser.parse_args()
    build = args.build_dir.resolve()
    if not (build.is_relative_to(ROOT) or build.is_relative_to(Path('/private/tmp'))
            or build.is_relative_to(Path('/tmp'))):
        parser.error('Build directory must be inside this worktree or /private/tmp')
    if not 1 <= args.jobs <= 16:
        parser.error('jobs must be 1..16')
    build.mkdir(parents=True, exist_ok=True)
    binary_dir = build / 'bin'
    binary_dir.mkdir(exist_ok=True)
    manifest = json.loads((ENGINE / 'sources.json').read_text())
    for source in manifest['sources']:
        identity = source['id']
        if args.engine not in ('all', identity):
            continue
        archive = build / ('openssl-' + source['version'] + '.tar.gz')
        if not archive.exists():
            partial = archive.with_suffix('.download')
            with urllib.request.urlopen(source['url'], timeout=60) as response, partial.open('wb') as out:
                shutil.copyfileobj(response, out)
            if sha256(partial) != source['sha256']:
                partial.unlink()
                raise RuntimeError('source archive hash mismatch: ' + identity)
            partial.replace(archive)
        if sha256(archive) != source['sha256']:
            raise RuntimeError('cached source archive hash mismatch: ' + identity)
        source_dir = build / ('openssl-' + source['version'])
        prefix = build / ('install-' + identity)
        log = build / ('build-' + identity + '.log')
        if not source_dir.exists():
            with tarfile.open(archive) as tar:
                for member in tar.getmembers():
                    dest = (build / member.name).resolve()
                    if not dest.is_relative_to(build) or member.isdev():
                        raise RuntimeError('unsafe archive member')
                tar.extractall(build, filter='data')
        license_copy = ENGINE / source['license_file']
        source_license = source_dir / ('LICENSE' if identity == 'legacy' else 'LICENSE.txt')
        if (sha256(license_copy) != source['license_sha256']
                or sha256(source_license) != source['license_sha256']):
            raise RuntimeError('pinned source license mismatch: ' + identity)
        system, machine = platform.system(), platform.machine()
        if identity == 'legacy':
            target = ('BSD-generic64' if system == 'Darwin' else
                      'linux-aarch64' if machine in ('aarch64', 'arm64') else 'linux-x86_64')
            options = [target, 'no-shared', 'no-dso', 'no-engine', 'no-zlib',
                       'enable-ssl2', 'enable-ssl3', 'enable-weak-ssl-ciphers']
            if system == 'Darwin':
                options.append('no-asm')
        else:
            target = ('darwin64-arm64-cc' if system == 'Darwin' and machine == 'arm64' else
                      'darwin64-x86_64-cc' if system == 'Darwin' else
                      'linux-aarch64' if machine in ('aarch64', 'arm64') else 'linux-x86_64')
            options = [target, 'no-shared', 'no-module', 'no-engine', 'no-tests',
                       'no-zlib', 'no-brotli', 'no-zstd']
        if not (prefix / 'lib/libssl.a').exists() and not (prefix / 'lib64/libssl.a').exists():
            print('Building pinned ' + identity + ' ' + source['version'], flush=True)
            run(['perl', 'Configure', *options, '--prefix=' + str(prefix),
                 '--openssldir=' + str(prefix / 'ssl')], source_dir, log)
            if identity == 'legacy':
                run(['make', 'depend'], source_dir, log)
            run(['make', '-j' + str(args.jobs)], source_dir, log)
            run(['make', 'install_sw'], source_dir, log)
        if not args.libraries_only:
            lib = prefix / ('lib64' if (prefix / 'lib64/libssl.a').exists() else 'lib')
            output = binary_dir / ('tls-baseline-' + identity)
            build_id = hashlib.sha256((source['sha256'] + sha256(ENGINE / 'src/engine.c')
                                       + sha256(ENGINE / 'src/sandbox.h')).encode()).hexdigest()
            command = [os.environ.get('CC', 'cc'), '-std=c11', '-D_GNU_SOURCE', '-O2',
                       '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations',
                       '-DCM_BUILD_ID="' + build_id + '"', '-DCM_ENGINE_FAMILY="' + identity + '"',
                       '-I' + str(prefix / 'include'), str(ENGINE / 'src/engine.c'),
                       str(lib / 'libssl.a'), str(lib / 'libcrypto.a'), '-lpthread', '-o', str(output)]
            if system == 'Linux':
                command.extend(['-ldl'])
            run(command, ROOT, log)
            record = {**source, 'build_id': build_id, 'binary_sha256': sha256(output),
                      'platform': system + '-' + machine, 'configure': options,
                      'baseline_upstream_modified': False}
            (binary_dir / (output.name + '.json')).write_text(json.dumps(record, indent=2) + '\n')
        print('Ready: ' + identity, flush=True)
    if not args.libraries_only:
        write_catalog(build)


if __name__ == '__main__':
    main()
