import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'smoke', Path(__file__).resolve().parents[1] / 'smoke_desktop_runtime.py')
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class DriverCleanupTests(unittest.TestCase):
    def test_service_removed_by_stop_is_successful_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            driver = root / 'runtime/WinDivert64.sys'
            driver.parent.mkdir()
            driver.write_bytes(b'fixture')
            results = [subprocess.CompletedProcess([], code, '', '') for code in (0, 1060)]
            with patch.object(smoke, 'windows_driver_path', return_value=str(driver)), \
                    patch.object(smoke, 'run', side_effect=results):
                smoke.cleanup_windows_fixture(root)
            self.assertFalse(driver.exists())

    def test_another_driver_is_never_stopped(self):
        with patch.object(smoke, 'windows_driver_path', return_value='another/WinDivert64.sys'), \
                patch.object(smoke, 'run') as command:
            with self.assertRaisesRegex(RuntimeError, 'another WinDivert driver'):
                smoke.cleanup_windows_fixture(Path('fixture'))
            command.assert_not_called()

    def test_access_denied_is_not_ignored(self):
        root = Path('fixture')
        denied = subprocess.CompletedProcess([], 5, 'access denied', '')
        with patch.object(smoke, 'windows_driver_path',
                          return_value=str(root / 'runtime/WinDivert64.sys')), \
                patch.object(smoke, 'run', return_value=denied):
            with self.assertRaisesRegex(RuntimeError, 'cannot stop fixture driver'):
                smoke.cleanup_windows_fixture(root)
