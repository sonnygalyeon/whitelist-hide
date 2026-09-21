#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
FORBIDDEN_SUFFIXES = {
    ".exe", ".dll", ".sys", ".dylib", ".so", ".bin",
}
ALLOWED_BINARY_PATH_PREFIXES = set()


def tracked_files() -> list[pathlib.Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    )
    return [
        ROOT / item.decode("utf-8")
        for item in result.stdout.split(b"\0")
        if item
    ]


def check_no_opaque_binaries() -> list[str]:
    failures: list[str] = []
    for path in tracked_files():
        relative = path.relative_to(ROOT)
        if any(str(relative).startswith(prefix) for prefix in ALLOWED_BINARY_PATH_PREFIXES):
            continue
        if relative.suffix.lower() in FORBIDDEN_SUFFIXES:
            failures.append(f"tracked opaque binary is forbidden: {relative}")
    return failures


def check_upstream_lock() -> list[str]:
    lock_path = ROOT / "third_party" / "upstream.lock.toml"
    with lock_path.open("rb") as stream:
        data = tomllib.load(stream)

    failures: list[str] = []
    for platform in ("macos", "linux", "windows"):
        entry = data.get(platform)
        if not isinstance(entry, dict):
            failures.append(f"missing upstream lock section: {platform}")
            continue
        if entry.get("status") != "source-build-enabled":
            failures.append(
                f"{platform} source build is not enabled: {entry.get('status')!r}"
            )
        commit = entry.get("commit", "")
        if not isinstance(commit, str) or len(commit) != 40:
            failures.append(f"{platform} commit must be an exact 40-char SHA")
        if not entry.get("license"):
            failures.append(f"{platform} license metadata is missing")
        if not entry.get("repository"):
            failures.append(f"{platform} repository metadata is missing")
    driver = data.get("windows_driver")
    if not isinstance(driver, dict):
        failures.append("missing upstream lock section: windows_driver")
    else:
        if driver.get("status") != "pinned-release-verified":
            failures.append(
                f"Windows driver release is not verified: {driver.get('status')!r}"
            )
        digest = driver.get("sha256", "")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            failures.append("windows_driver.sha256 must be 64 lowercase hex characters")
        commit = driver.get("commit", "")
        if not isinstance(commit, str) or len(commit) != 40:
            failures.append("windows_driver.commit must be an exact 40-char SHA")
        for key in ("repository", "version", "license", "asset_url"):
            if not driver.get(key):
                failures.append(f"windows_driver.{key} metadata is missing")

    linux_static = data.get("linux_static")
    if not isinstance(linux_static, dict):
        failures.append("missing upstream lock section: linux_static")
    else:
        for name in ("libmnl", "libnfnetlink", "libnetfilter_queue"):
            entry = linux_static.get(name)
            if not isinstance(entry, dict):
                failures.append(f"missing linux_static dependency: {name}")
                continue
            if entry.get("status") != "pinned-tarball-verified":
                failures.append(f"linux_static.{name} is not pinned and verified")
            digest = entry.get("sha256", "")
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(char not in "0123456789abcdef" for char in digest)
            ):
                failures.append(f"linux_static.{name}.sha256 is invalid")
            url = entry.get("asset_url", "")
            if not isinstance(url, str) or not url.startswith("https://www.netfilter.org/pub/"):
                failures.append(f"linux_static.{name}.asset_url must use netfilter.org HTTPS")

    return failures


def main() -> int:
    failures = check_no_opaque_binaries() + check_upstream_lock()
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1

    print("release metadata gate: OK")
    print("tracked opaque binaries: none")
    print("source-build metadata: macOS/Linux/Windows enabled")
    print("WinDivert release metadata and SHA-256: pinned")
    print("Linux static Netfilter dependency tarballs: pinned and SHA-256 verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
