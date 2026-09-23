import hashlib
import pathlib
import subprocess
import sys
import tempfile
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/stage_desktop_runtime.py'


class StagingTests(unittest.TestCase):
    def stage(self, platform, missing=None):
        tmp = tempfile.TemporaryDirectory(prefix='whitelist runtime ')
        self.addCleanup(tmp.cleanup)
        root = pathlib.Path(tmp.name)
        source, output = root / 'input', root / 'generated'
        source.mkdir()
        files = {'linux': ['nfqws'], 'macos': ['utunws'], 'windows': ['winws2.exe', 'cygwin1.dll', 'WinDivert.dll', 'WinDivert64.sys', 'zapret-lib.lua', 'zapret-antidpi.lua']}[platform]
        for name in files:
            if name != missing:
                (source / name).write_bytes(('fixture ' + name).encode())
        triple = {'linux': 'x86_64-unknown-linux-gnu', 'macos': 'aarch64-apple-darwin', 'windows': 'x86_64-pc-windows-msvc'}[platform]
        result = subprocess.run([sys.executable, str(SCRIPT), '--platform', platform, '--target', triple, '--input', str(source), '--output', str(output)], capture_output=True, text=True)
        return output, result

    def test_all_platform_profiles_resolve_verified_bundles(self):
        for platform in ['linux', 'macos', 'windows']:
            with self.subTest(platform=platform):
                output, result = self.stage(platform)
                self.assertEqual(result.returncode, 0, result.stderr)
                for config_name, strategy_name in [('config.toml', 'strategy.toml'), ('config-split.toml', 'split.toml'), ('config-disorder.toml', 'disorder.toml')]:
                    base = output / 'default'
                    config = tomllib.loads((base / config_name).read_text())
                    strategy = tomllib.loads((base / strategy_name).read_text())
                    self.assertEqual(config['strategy']['name'], strategy['id'])
                    for binding in [config['engine'], *config['engine'].get('dependencies', [])]:
                        manifest = tomllib.loads((base / binding['manifest']).read_text())
                        binary = base / binding['binary']
                        self.assertEqual(manifest['artifact']['sha256'], hashlib.sha256(binary.read_bytes()).hexdigest())
                    if platform == 'windows':
                        self.assertEqual(len(config['engine']['dependencies']), 5)

    def test_windows_cannot_ship_without_lua(self):
        _, result = self.stage('windows', missing='zapret-antidpi.lua')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('zapret-antidpi.lua', result.stderr)


if __name__ == '__main__':
    unittest.main()
