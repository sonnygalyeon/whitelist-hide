"""Native regression checks for the unsigned-bundle bug in rc.2."""
import hashlib
import importlib.util
from pathlib import Path
import platform
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    'macos_bundle', Path(__file__).resolve().parents[1] / 'verify_macos_bundle.py')
bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bundle)


@unittest.skipUnless(sys.platform == 'darwin', 'requires Apple codesign and Mach-O tools')
class MacOSBundleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='white hide signature test ')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.app = self.root / 'White Hide.app'
        self.arch = platform.machine()
        macos = self.app / 'Contents/MacOS'
        macos.mkdir(parents=True)
        resources = self.app / 'Contents/Resources/whitelist-hide'
        (resources / 'runtime').mkdir(parents=True)
        (resources / 'manifests').mkdir()
        self.resources = resources
        info = {'CFBundleIdentifier': 'io.whitelisthide.desktop',
                'CFBundleName': 'White Hide', 'CFBundleExecutable': 'White Hide',
                'CFBundlePackageType': 'APPL', 'CFBundleVersion': '1.0.0',
                'CFBundleShortVersionString': '1.0.0-rc.3'}
        (self.app / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
        source = self.root / 'fixture.c'
        source.write_text('int main(void) { return 0; }\n')
        gui = macos / 'White Hide'
        subprocess.run(['clang', str(source), '-o', str(gui)], check=True)
        self.engine = resources / 'runtime/utunws'
        for destination in (macos / 'whitelist-hide-helper', self.engine):
            shutil.copy2(gui, destination)
        for binary in (self.engine, macos / 'whitelist-hide-helper'):
            self.sign(binary)
        self.write_manifest()

    def sign(self, path):
        bundle.run(['codesign', '--force', '--sign', '-', '--timestamp=none', path])

    def write_manifest(self):
        digest = hashlib.sha256(self.engine.read_bytes()).hexdigest()
        (self.resources / 'manifests/engine.toml').write_text(
            f'[artifact]\nfilename = "utunws"\nsha256 = "{digest}"\n')

    def verify(self):
        return bundle.verify_app(self.app, self.arch, '1.0.0-rc.3')

    def test_unsigned_app_with_linker_signed_binary_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'resource seal is missing'):
            self.verify()

    def test_inside_out_signed_bundle_passes(self):
        self.sign(self.app)
        result = self.verify()
        self.assertEqual(result['signature'], 'ad-hoc')
        self.assertEqual(result['binary_count'], 3)

    def test_resource_modified_after_signing_is_rejected(self):
        self.sign(self.app)
        (self.resources / 'manifests/engine.toml').write_text('tampered')
        with self.assertRaisesRegex(RuntimeError, 'codesign failed'):
            self.verify()

    def test_stale_engine_hash_is_rejected_even_with_valid_app_seal(self):
        (self.resources / 'manifests/engine.toml').write_text(
            '[artifact]\nfilename = "utunws"\nsha256 = "' + '0' * 64 + '"\n')
        self.sign(self.app)
        with self.assertRaisesRegex(ValueError, 'engine checksum mismatch'):
            self.verify()

    def test_wrong_architecture_is_rejected(self):
        self.sign(self.app)
        other = 'x86_64' if self.arch == 'arm64' else 'arm64'
        with self.assertRaisesRegex(ValueError, 'wrong architecture'):
            bundle.verify_app(self.app, other)


if __name__ == '__main__':
    unittest.main()
