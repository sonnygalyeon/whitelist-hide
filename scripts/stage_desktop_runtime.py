#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import shutil
import stat
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOCK = ROOT / "third_party" / "upstream.lock.toml"
DEFAULTS = ROOT / "apps" / "desktop" / "resources" / "default"


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def target_name(platform: str, triple: str) -> str:
    if "x86_64" in triple:
        arch = "x86_64"
    elif "aarch64" in triple or "arm64" in triple:
        arch = "aarch64"
    else:
        raise SystemExit(f"unsupported desktop architecture: {triple}")
    return f"{platform}-{arch}"


def q(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_manifest(
    path: pathlib.Path,
    *,
    name: str,
    version: str,
    source: str,
    license_name: str,
    platform: str,
    filename: str,
    digest: str,
) -> None:
    path.write_text(
        "\n".join(
            [
                "schema = 1",
                f"name = {q(name)}",
                f"version = {q(version)}",
                f"source = {q(source)}",
                f"license = {q(license_name)}",
                "",
                "[artifact]",
                f"platform = {q(platform)}",
                f"filename = {q(filename)}",
                f"sha256 = {q(digest)}",
                "",
            ]
        ),
        encoding="utf-8",
    )


def copy_runtime(src: pathlib.Path, dst: pathlib.Path, executable: bool = False) -> pathlib.Path:
    if not src.is_file():
        raise SystemExit(f"required runtime artifact is missing: {src}")
    shutil.copy2(src, dst)
    if executable and os.name != "nt":
        mode = dst.stat().st_mode
        dst.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return dst


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", choices=("windows", "macos", "linux"), required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--input", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()

    with LOCK.open("rb") as stream:
        lock = tomllib.load(stream)

    platform_target = target_name(args.platform, args.target)
    upstream = lock[args.platform]

    if args.output.exists():
        shutil.rmtree(args.output)
    (args.output / "runtime").mkdir(parents=True)
    (args.output / "manifests").mkdir()
    (args.output / "default").mkdir()
    shutil.copytree(DEFAULTS / "lists", args.output / "default" / "lists")

    strategy_src = DEFAULTS / "strategy.toml"
    shutil.copy2(strategy_src, args.output / "default" / "strategy.toml")

    engine_name = str(upstream["artifact"])
    engine_src = args.input / engine_name
    engine_dst = copy_runtime(
        engine_src,
        args.output / "runtime" / engine_name,
        executable=True,
    )
    source = f"{upstream['repository']}@{upstream['commit']}"
    write_manifest(
        args.output / "manifests" / "engine.toml",
        name=engine_name,
        version=str(upstream["commit"]),
        source=source,
        license_name=str(upstream["license"]),
        platform=platform_target,
        filename=engine_name,
        digest=sha256(engine_dst),
    )

    dependency_blocks: list[tuple[str, str]] = []

    if args.platform == "windows":
        driver = lock["windows_driver"]
        dependencies = [
            (
                "cygwin1.dll",
                "cygwin-runtime.toml",
                "https://cygwin.com/",
                "Cygwin runtime distribution license",
            ),
            (
                "WinDivert.dll",
                "windivert-dll.toml",
                f"{driver['repository']}@{driver['commit']}",
                str(driver["license"]),
            ),
            (
                "WinDivert64.sys",
                "windivert-driver.toml",
                f"{driver['repository']}@{driver['commit']}",
                str(driver["license"]),
            ),
        ]
        for filename, manifest_name, dep_source, dep_license in dependencies:
            dst = copy_runtime(
                args.input / filename,
                args.output / "runtime" / filename,
            )
            write_manifest(
                args.output / "manifests" / manifest_name,
                name=filename,
                version=str(driver["version"]) if filename.startswith("WinDivert") else "bundled",
                source=dep_source,
                license_name=dep_license,
                platform=platform_target,
                filename=filename,
                digest=sha256(dst),
            )
            dependency_blocks.append((manifest_name, filename))

    config_lines = [
        "schema = 1",
        "",
        "[engine]",
        'manifest = "../manifests/engine.toml"',
        f'binary = "../runtime/{engine_name}"',
        "",
        "[strategy]",
        'name = "standard"',
    ]
    for manifest_name, filename in dependency_blocks:
        config_lines.extend(
            [
                "",
                "[[engine.dependencies]]",
                f'manifest = "../manifests/{manifest_name}"',
                f'binary = "../runtime/{filename}"',
            ]
        )
    config_lines.append("")
    (args.output / "default" / "config.toml").write_text(
        "\n".join(config_lines),
        encoding="utf-8",
    )

    provenance = args.input / "PROVENANCE.txt"
    if provenance.is_file():
        shutil.copy2(provenance, args.output / "PROVENANCE.txt")

    print(f"staged desktop runtime: {args.output}")
    print(f"target: {platform_target}")
    print(f"engine: {engine_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
