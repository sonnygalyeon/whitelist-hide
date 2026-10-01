#!/usr/bin/env python3
"""Verify the shipped DMG and copied .app on a native macOS runner."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import tomllib


MACHO_MAGIC = {bytes.fromhex(value) for value in (
    'feedface', 'cefaedfe', 'feedfacf', 'cffaedfe',
    'cafebabe', 'bebafeca', 'cafebabf', 'bfbafeca',
)}


def run(args, check=True):
    result = subprocess.run([str(a) for a in args], capture_output=True,
                            text=True, timeout=120)
    if check and result.returncode:
        raise RuntimeError(f'{args[0]} failed ({result.returncode}):\n'
                           f'{result.stdout}{result.stderr}')
    return result


def verify_app(app, arch, version=None):
    """Validate signatures, architecture, sealed resources and engine checksum."""
    app = app.resolve()
    info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    if info.get('CFBundleIdentifier') != 'io.whitelisthide.desktop':
        raise ValueError('unexpected application identifier')
    if info.get('CFBundlePackageType') != 'APPL':
        raise ValueError('bundle is not an application')
    if version and info.get('CFBundleShortVersionString') != version:
        raise ValueError('application version does not match the release')
    if not (app / 'Contents/_CodeSignature/CodeResources').is_file():
        raise ValueError('application resource seal is missing (unsigned .app)')
    run(['codesign', '--verify', '--deep', '--strict', '--all-architectures',
         '--verbose=2', app])

    executable = info['CFBundleExecutable']
    if Path(executable).name != executable:
        raise ValueError('invalid executable path')
    gui = app / 'Contents/MacOS' / executable
    helper = app / 'Contents/MacOS/whitelist-hide-helper'
    resources = app / 'Contents/Resources/whitelist-hide'
    engine = resources / 'runtime/utunws'
    required = {gui, helper, engine}
    binaries = set()
    for path in app.rglob('*'):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open('rb') as stream:
            magic = stream.read(4)
        if magic not in MACHO_MAGIC:
            continue
        binaries.add(path)
        if not os.access(path, os.X_OK):
            raise ValueError(f'not executable: {path.relative_to(app)}')
        actual_arch = run(['lipo', '-archs', path]).stdout.split()
        if actual_arch != [arch]:
            raise ValueError(f'wrong architecture for {path.name}: {actual_arch}')
        run(['codesign', '--verify', '--strict', '--all-architectures', path])
        # Resource-directory executables are not recursively checked by codesign.
        # Verify them explicitly and reject dependencies on the build machine.
        dependencies = run(['otool', '-L', path]).stdout.splitlines()[1:]
        for line in dependencies:
            dependency = line.strip().split(' (', 1)[0]
            if not dependency.startswith(('/usr/lib/', '/System/Library/')):
                raise ValueError(f'non-system dependency in {path.name}: {dependency}')
    if not required.issubset(binaries):
        raise ValueError('GUI, helper or utunws Mach-O binary is missing')
    manifest = tomllib.loads((resources / 'manifests/engine.toml').read_text())
    if manifest['artifact']['filename'] != 'utunws':
        raise ValueError('unexpected engine manifest filename')
    digest = hashlib.sha256(engine.read_bytes()).hexdigest()
    if manifest['artifact']['sha256'] != digest:
        raise ValueError('engine checksum mismatch: sign BEFORE staging the manifest')
    details = run(['codesign', '--display', '--verbose=4', app]).stderr
    print(f'PASS: sealed application, {len(binaries)} signed {arch} binaries, engine SHA256', flush=True)
    return {
        'version': info.get('CFBundleShortVersionString'),
        'architecture': arch,
        'signature': 'ad-hoc' if 'Signature=adhoc' in details else 'certificate',
        'binary_count': len(binaries),
        'engine_sha256': digest,
    }


def launch_check(app):
    """Detect loader/signature/startup failures, without starting a network session."""
    info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    gui = app / 'Contents/MacOS' / info['CFBundleExecutable']
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen([str(gui)], stdout=output, stderr=output, cwd=app.parent)
        try:
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                print('PASS: copied GUI stayed running for 8 seconds', flush=True)
            else:
                output.seek(0)
                raise RuntimeError(f'GUI exited during startup ({process.returncode}): '
                                   + output.read().decode(errors='replace'))
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)


def verify_dmg(dmg, arch, version, cli=None, launch=False):
    run(['hdiutil', 'verify', dmg])
    print('PASS: DMG internal checksum', flush=True)
    with tempfile.TemporaryDirectory(prefix='white hide package ') as temporary:
        root = Path(temporary)
        mount = root / 'mounted'
        mount.mkdir()
        run(['hdiutil', 'attach', '-readonly', '-nobrowse', '-mountpoint', mount, dmg])
        try:
            applications = list(mount.glob('*.app'))
            if len(applications) != 1:
                raise ValueError('expected exactly one application in DMG')
            app = root / 'Applications' / applications[0].name
            app.parent.mkdir()
            run(['ditto', applications[0], app])
        finally:
            run(['hdiutil', 'detach', mount])
        # Check the copied app, not a pre-packaging build directory.
        report = verify_app(app, arch, version)
        assessment = run(['spctl', '--assess', '--type', 'execute', '--verbose=4', app], check=False)
        report['gatekeeper_accepted'] = assessment.returncode == 0
        report['gatekeeper_assessment'] = (assessment.stdout + assessment.stderr).strip()
        if not report['gatekeeper_accepted']:
            if report['signature'] != 'ad-hoc':
                raise RuntimeError('Developer ID build rejected by Gatekeeper: '
                                   + report['gatekeeper_assessment'])
            print('LIMITATION: ad-hoc build is not Apple-notarized; Gatekeeper approval is required', flush=True)
        if cli:
            result = run([sys.executable, Path(__file__).with_name('smoke_desktop_runtime.py'),
                          '--resources', app / 'Contents/Resources/whitelist-hide',
                          '--cli', cli.resolve(),
                          '--helper', app / 'Contents/MacOS/whitelist-hide-helper'])
            print(result.stdout, end='', flush=True)
            run([app / 'Contents/MacOS/whitelist-hide-helper', 'health'])
            report['packaged_profiles_validated'] = True
        if launch:
            launch_check(app)
            report['gui_startup_seconds'] = 8
        return report


def main():
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--dmg', type=Path)
    source.add_argument('--bundle', type=Path)
    parser.add_argument('--arch', choices=('arm64', 'x64'), required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--cli', type=Path)
    parser.add_argument('--launch', action='store_true')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    if sys.platform != 'darwin':
        raise SystemExit('DMG verification requires native macOS')
    dmg = args.dmg
    if args.bundle:
        images = list((args.bundle / 'dmg').glob('*.dmg'))
        if len(images) != 1:
            raise SystemExit('expected exactly one DMG to verify')
        dmg = images[0]
    report = verify_dmg(dmg.resolve(), 'arm64' if args.arch == 'arm64' else 'x86_64',
                        args.version, args.cli, args.launch)
    report['dmg_sha256'] = hashlib.sha256(dmg.read_bytes()).hexdigest()
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
