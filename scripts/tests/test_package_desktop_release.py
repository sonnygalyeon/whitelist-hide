import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / 'package_desktop_release.py'
SPEC = importlib.util.spec_from_file_location('packager', SCRIPT)
packager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packager)


class ReleasePackagingTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def file(self, relative):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'fixture')
        return path

    def package(self, platform, arch):
        packager.package(platform, arch, self.root / 'bundle', self.root / 'desktop.exe',
                         self.root / 'helper.exe', self.root / 'runtime', self.root / 'out')

    def test_missing_linux_format_blocks_publication(self):
        self.file('bundle/deb/app.deb')
        self.file('bundle/rpm/app.rpm')
        with self.assertRaisesRegex(ValueError, 'AppImage'):
            self.package('linux', 'x64')
        self.assertFalse((self.root / 'out').exists())

    def test_macos_architecture_names_are_distinct(self):
        self.file('bundle/dmg/app.dmg')
        self.package('macos', 'arm64')
        self.package('macos', 'x64')
        self.assertEqual({p.name for p in (self.root / 'out').iterdir()},
                         {'White-Hide-macOS-arm64.dmg', 'White-Hide-macOS-intel.dmg'})

    def test_portable_requires_and_contains_complete_runtime(self):
        for relative in ('bundle/nsis/app.exe', 'bundle/msi/app.msi', 'desktop.exe',
                         'helper.exe', 'runtime/default/config.toml',
                         'runtime/default/strategy.toml', 'runtime/manifests/engine.toml',
                         'runtime/runtime/winws2.exe', 'runtime/runtime/cygwin1.dll',
                         'runtime/runtime/WinDivert.dll', 'runtime/runtime/WinDivert64.sys',
                         'runtime/runtime/zapret-lib.lua'):
            self.file(relative)
        with self.assertRaisesRegex(ValueError, 'zapret-antidpi.lua'):
            self.package('windows', 'x64')
        self.file('runtime/runtime/zapret-antidpi.lua')
        self.package('windows', 'x64')
        with zipfile.ZipFile(self.root / 'out/White-Hide-Windows-Portable.zip') as archive:
            self.assertIn('White-Hide/White Hide.exe', archive.namelist())
            self.assertIn('White-Hide/whitelist-hide-helper.exe', archive.namelist())
            self.assertIn('White-Hide/whitelist-hide/default/config.toml', archive.namelist())
            self.assertIn('White-Hide/whitelist-hide/runtime/WinDivert64.sys', archive.namelist())
            self.assertIsNone(archive.testzip())


if __name__ == '__main__':
    unittest.main()
