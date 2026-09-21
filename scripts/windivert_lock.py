#!/usr/bin/env python3
import argparse
import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOCK = ROOT / "third_party" / "upstream.lock.toml"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--github-output")
    args = parser.parse_args()

    with LOCK.open("rb") as handle:
        data = tomllib.load(handle)

    target = data.get("windows_driver")
    if not isinstance(target, dict):
        raise SystemExit("windows_driver section is missing")

    required = ("repository", "commit", "version", "license", "asset_url", "sha256", "status")
    for key in required:
        value = target.get(key)
        if not isinstance(value, str) or not value:
            raise SystemExit(f"windows_driver.{key} is missing or invalid")

    if not SHA40.fullmatch(str(target["commit"])):
        raise SystemExit("windows_driver.commit must be an exact 40-char SHA")
    if not SHA256.fullmatch(str(target["sha256"])):
        raise SystemExit("windows_driver.sha256 must be lowercase SHA-256")
    if target["status"] != "pinned-release-verified":
        raise SystemExit("windows_driver release is not verified")

    lines = [
        f"repository={target['repository']}",
        f"commit={target['commit']}",
        f"version={target['version']}",
        f"license={target['license']}",
        f"asset_url={target['asset_url']}",
        f"sha256={target['sha256']}",
    ]
    output = "\n".join(lines) + "\n"
    if args.github_output:
        pathlib.Path(args.github_output).write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
