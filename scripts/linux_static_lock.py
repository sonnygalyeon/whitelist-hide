#!/usr/bin/env python3
from __future__ import annotations

import argparse
import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOCK = ROOT / "third_party" / "upstream.lock.toml"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
NAMES = ("libmnl", "libnfnetlink", "libnetfilter_queue")


def load() -> dict[str, dict[str, str]]:
    with LOCK.open("rb") as stream:
        data = tomllib.load(stream)
    section = data.get("linux_static")
    if not isinstance(section, dict):
        raise SystemExit("missing linux_static metadata")

    result: dict[str, dict[str, str]] = {}
    for name in NAMES:
        entry = section.get(name)
        if not isinstance(entry, dict):
            raise SystemExit(f"missing linux_static.{name}")
        for key in ("version", "asset_url", "sha256", "status"):
            value = entry.get(key)
            if not isinstance(value, str) or not value:
                raise SystemExit(f"linux_static.{name}.{key} is missing")
        if entry["status"] != "pinned-tarball-verified":
            raise SystemExit(f"linux_static.{name} is not verified")
        if not entry["asset_url"].startswith("https://www.netfilter.org/pub/"):
            raise SystemExit(f"linux_static.{name}.asset_url must use netfilter.org HTTPS")
        if not SHA256.fullmatch(entry["sha256"]):
            raise SystemExit(f"linux_static.{name}.sha256 is invalid")
        result[name] = {key: str(value) for key, value in entry.items()}
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--github-output")
    args = parser.parse_args()
    data = load()

    lines: list[str] = []
    for name in NAMES:
        prefix = name.upper()
        entry = data[name]
        lines.extend(
            [
                f"{prefix}_VERSION={entry['version']}",
                f"{prefix}_URL={entry['asset_url']}",
                f"{prefix}_SHA256={entry['sha256']}",
            ]
        )
    output = "\n".join(lines) + "\n"
    if args.github_output:
        pathlib.Path(args.github_output).write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
