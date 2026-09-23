#!/usr/bin/env python3
"""Build nfqws with pinned static Netfilter libraries, outside system prefixes."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request
from linux_static_lock import load


def run(args, cwd, env):
    subprocess.run(args, cwd=cwd, env=env, check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--work', type=Path, default=Path('build/linux-static'))
    args = parser.parse_args()
    work = args.work.resolve()
    prefix = work / 'prefix'
    work.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PKG_CONFIG_PATH=str(prefix / 'lib/pkgconfig'),
               CFLAGS=f'-O2 -I{prefix}/include', LDFLAGS=f'-L{prefix}/lib')
    for name, entry in load().items():
        archive = work / f'{name}.tar.bz2'
        urllib.request.urlretrieve(entry['asset_url'], archive)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != entry['sha256']:
            raise SystemExit(f'{name}: archive checksum mismatch')
        source = work / f"{name}-{entry['version']}"
        if source.exists():
            shutil.rmtree(source)
        with tarfile.open(archive) as tar:
            tar.extractall(work, filter='data')
        run(['./configure', f'--prefix={prefix}', '--enable-static', '--disable-shared'], source, env)
        run(['make', f'-j{os.cpu_count() or 2}'], source, env)
        run(['make', 'install'], source, env)
        licenses = work / 'licenses'
        licenses.mkdir(exist_ok=True)
        shutil.copy2(source / 'COPYING', licenses / f'{name}-COPYING')
    run(['make', 'clean'], args.source, env)
    run(['make', f'CFLAGS=-static -std=gnu99 -Os -I{prefix}/include -L{prefix}/lib'], args.source, env)
    result = subprocess.run(['ldd', str(args.source.resolve() / 'nfqws')], capture_output=True, text=True)
    if result.returncode == 0 or not any(t in result.stdout + result.stderr for t in ('not a dynamic executable', 'statically linked')):
        raise SystemExit('nfqws must have no dynamic runtime dependencies')


if __name__ == '__main__':
    main()
