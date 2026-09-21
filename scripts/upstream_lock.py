#!/usr/bin/env python3
import argparse
import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOCK = ROOT / "third_party" / "upstream.lock.toml"
SHA40 = re.compile(r"^[0-9a-f]{40}$")


def load_target(name: str) -> dict[str, object]:
    with LOCK.open("rb") as handle:
        data = tomllib.load(handle)

    if data.get("schema") != 1:
        raise SystemExit("unsupported upstream lock schema")

    target = data.get(name)
    if not isinstance(target, dict):
        raise SystemExit(f"unknown target: {name}")

    required = (
        "repository",
        "commit",
        "subdir",
        "artifact",
        "build_target",
        "license",
        "license_path",
        "status",
    )
    for key in required:
        value = target.get(key)
        if not isinstance(value, str) or not value:
            raise SystemExit(f"{name}.{key} is missing or invalid")

    commit = str(target["commit"])
    if not SHA40.fullmatch(commit):
        raise SystemExit(f"{name}.commit must be an exact 40-character git SHA")

    repository = str(target["repository"])
    if not repository.startswith("https://github.com/") or not repository.endswith(".git"):
        raise SystemExit(f"{name}.repository must be an HTTPS GitHub clone URL")

    for key in ("subdir", "artifact", "license_path"):
        value = pathlib.PurePosixPath(str(target[key]))
        if value.is_absolute() or ".." in value.parts:
            raise SystemExit(f"{name}.{key} must stay inside the upstream checkout")

    return target


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", choices=("macos", "linux", "windows"))
    parser.add_argument("--github-output")
    args = parser.parse_args()

    target = load_target(args.target)

    lines = [
        f"repository={target['repository']}",
        f"commit={target['commit']}",
        f"subdir={target['subdir']}",
        f"artifact={target['artifact']}",
        f"build_target={target['build_target']}",
        f"license={target['license']}",
        f"license_path={target['license_path']}",
        f"status={target['status']}",
    ]

    if args.target == "windows":
        for key in (
            "windivert_version",
            "windivert_url",
            "windivert_archive_sha256",
            "windivert_dll_sha256",
            "windivert_sys_sha256",
        ):
            value = target.get(key)
            if not isinstance(value, str) or not value:
                raise SystemExit(f"windows.{key} is missing or invalid")
            lines.append(f"{key}={value}")

    if args.github_output:
        pathlib.Path(args.github_output).write_text("\n".join(lines) + "\n", encoding="utf-8")
    else:
        print("\n".join(lines))

    return 0


if __name__ == "__main__":
    sys.exit(main())
