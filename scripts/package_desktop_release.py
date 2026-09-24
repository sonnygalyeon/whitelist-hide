#!/usr/bin/env python3
"""Collect only complete, user-installable desktop packages from a native build."""
import argparse
from pathlib import Path
import shutil
import zipfile


PACKAGES = {
    ('windows', 'x64'): {
        'nsis/*.exe': 'White-Hide-Windows-Setup.exe',
        'msi/*.msi': 'White-Hide-Windows-Setup.msi',
    },
    ('macos', 'arm64'): {'dmg/*.dmg': 'White-Hide-macOS-arm64.dmg'},
    ('macos', 'x64'): {'dmg/*.dmg': 'White-Hide-macOS-intel.dmg'},
    ('linux', 'x64'): {
        'appimage/*.AppImage': 'White-Hide-Linux.AppImage',
        'deb/*.deb': 'White-Hide-Linux.deb',
        'rpm/*.rpm': 'White-Hide-Linux.rpm',
    },
}


def require_file(path):
    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError(f'missing or empty release file: {path}')
    return path


def package(platform, arch, bundle, desktop, helper, runtime, output):
    sources = []
    for pattern, name in PACKAGES[(platform, arch)].items():
        matches = list(bundle.glob(pattern))
        if len(matches) != 1:
            raise ValueError(f'expected exactly one {pattern}, found {len(matches)}')
        sources.append((require_file(matches[0]), name))
    if platform == 'windows':
        require_file(desktop)
        require_file(helper)
        for relative in ('default/config.toml', 'default/strategy.toml',
                         'manifests/engine.toml', 'runtime/winws2.exe',
                         'runtime/cygwin1.dll', 'runtime/WinDivert.dll',
                         'runtime/WinDivert64.sys', 'runtime/zapret-lib.lua',
                         'runtime/zapret-antidpi.lua'):
            require_file(runtime / relative)
    output.mkdir(parents=True, exist_ok=True)
    for source, name in sources:
        shutil.copy2(source, output / name)
    if platform == 'windows':
        with zipfile.ZipFile(output / 'White-Hide-Windows-Portable.zip', 'w',
                             compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(desktop, 'White-Hide/White Hide.exe')
            archive.write(helper, 'White-Hide/whitelist-hide-helper.exe')
            for path in sorted(runtime.rglob('*')):
                if path.is_file():
                    archive.write(path, 'White-Hide/whitelist-hide/' + path.relative_to(runtime).as_posix())
            archive.writestr('White-Hide/README.txt',
                'White Hide for Windows x64\n\n'
                'Extract the entire archive before running White Hide.exe.\n'
                'Microsoft Edge WebView2 Runtime is required.\n'
                'Confirm the UAC prompt when starting or stopping a session.\n'
                'Stop the session and close the application before moving or deleting this folder.\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--platform', choices=('windows', 'macos', 'linux'), required=True)
    parser.add_argument('--arch', choices=('x64', 'arm64'), required=True)
    parser.add_argument('--bundle', type=Path, default=Path('apps/desktop/src-tauri/target/release/bundle'))
    parser.add_argument('--desktop', type=Path, default=Path('apps/desktop/src-tauri/target/release/whitelist-hide-desktop.exe'))
    parser.add_argument('--helper', type=Path, default=Path('target/release/whitelist-hide-helper.exe'))
    parser.add_argument('--runtime', type=Path, default=Path('apps/desktop/src-tauri/resources/whitelist-hide/generated'))
    parser.add_argument('--output', type=Path, default=Path('dist/release'))
    args = parser.parse_args()
    package(args.platform, args.arch, args.bundle, args.desktop, args.helper, args.runtime, args.output)
    for path in sorted(args.output.iterdir()):
        print(f'{path.name}: {path.stat().st_size} bytes')


if __name__ == '__main__':
    main()
