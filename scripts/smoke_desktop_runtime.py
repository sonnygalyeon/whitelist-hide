#!/usr/bin/env python3
"""Check real bundled engine arguments; optionally exercise an isolated CI host."""
import argparse
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib


def run(args, check=True):
    result = subprocess.run([str(a) for a in args], text=True, capture_output=True, timeout=90)
    if check and result.returncode:
        raise RuntimeError(f'{args[0]} failed ({result.returncode})\n{result.stdout}\n{result.stderr}')
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--resources', type=Path, required=True)
    parser.add_argument('--cli', type=Path, required=True)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--live', action='store_true')
    args = parser.parse_args()
    root, cli, helper = args.resources.resolve(), args.cli.resolve(), args.helper.resolve()
    # Exercise paths with spaces on every OS, as in Program Files on Windows.
    with tempfile.TemporaryDirectory(prefix='white hide smoke ',
                                     dir='/tmp' if os.name != 'nt' else None) as tmp:
        fixture = Path(tmp)
        root = shutil.copytree(root, fixture / 'bundle')
        if os.name != 'nt':
            # Engines drop root privileges. Keep the runner's home private.
            fixture.chmod(0o755)
            for path in [root, *root.rglob('*')]:
                path.chmod(path.stat().st_mode | (0o555 if path.is_dir() else 0o444))
        exercise(root, cli, helper, args.live)


def exercise(root, cli, helper, live):
    platform = {'darwin': 'utunws', 'win32': 'winws'}.get(sys.platform, 'nfqws')
    profiles = [('config.toml', 'strategy.toml'), ('config-split.toml', 'split.toml'), ('config-disorder.toml', 'disorder.toml')]
    for config_name, strategy_name in profiles:
        config_path, strategy = root / 'default' / config_name, root / 'default' / strategy_name
        config = tomllib.loads(config_path.read_text())
        binary = (config_path.parent / config['engine']['binary']).resolve()
        run([cli, 'config', 'verify', config_path])
        compiled = run([cli, 'strategy', 'compile', strategy, platform]).stdout.splitlines()[1:]
        command = [str(binary), '--dry-run', *(['--qnum=200'] if platform == 'nfqws' else []), *compiled]
        result = subprocess.run(command, cwd=binary.parent, text=True, capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError(f'{strategy_name}: engine rejected compiled strategy\n{result.stdout}\n{result.stderr}')
        print(f'{strategy_name}: real engine accepts compiled parameters', flush=True)
    if not live:
        return
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('--live is restricted to disposable GitHub Actions runners')
    state = Path(run([cli, 'runtime', 'state-path']).stdout.strip())
    if state.exists():
        raise SystemExit('runner already has a session; refusing to interfere')
    def stopped():
        report = run([helper, 'health']).stdout
        assert 'session_present=false' in report, report
        if sys.platform.startswith('linux'):
            assert run(['nft', 'list', 'table', 'inet', 'whitelist_hide'], check=False).returncode != 0
        if sys.platform == 'darwin':
            result = run(['/sbin/pfctl', '-a', 'com.apple/whitelist-hide', '-sr'])
            assert not result.stdout.strip(), result.stdout
    try:
        for config, strategy in profiles:
            run([helper, 'start', root / 'default' / config, root / 'default' / strategy])
            report = run([helper, 'health']).stdout
            assert 'running=true' in report and 'network_resource=true' in report, report
            # Duplicate start is rejected and must leave the first session intact.
            assert run([helper, 'start', root / 'default' / config, root / 'default' / strategy], check=False).returncode != 0
            assert 'running=true' in run([helper, 'health']).stdout
            run([helper, 'stop'])
            stopped()
            print(f'{strategy}: native start / duplicate rejection / stop OK', flush=True)
        run([helper, 'start', root / 'default/config.toml', root / 'default/strategy.toml'])
        pid = json.loads(state.read_text())['engine_pid']
        if sys.platform == 'win32':
            run(['taskkill', '/PID', str(pid), '/F'])
        else:
            os.kill(pid, signal.SIGKILL)
        deadline = time.monotonic() + 30
        while state.exists() and time.monotonic() < deadline:
            time.sleep(1)
        stopped()
        print('Unexpected engine termination: watchdog rollback OK', flush=True)
    finally:
        run([helper, 'stop'], check=False)
        logs = run([helper, 'logs'], check=False)
        print(logs.stdout[-8000:])


if __name__ == '__main__':
    main()
