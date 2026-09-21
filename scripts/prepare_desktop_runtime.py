#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import pathlib
import shutil
import stat


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def q(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def safe_name(value: str) -> str:
    return "".join(ch.lower() if ch.isalnum() else "-" for ch in value).strip("-")


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


def parse_dependency(spec: str) -> tuple[pathlib.Path, str, str, str, str]:
    parts = spec.split("::", 4)
    if len(parts) != 5:
        raise SystemExit(
            "dependency must be PATH::NAME::SOURCE::LICENSE::VERSION"
        )
    path, name, source, license_name, version = parts
    return pathlib.Path(path), name, source, license_name, version


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", required=True)
    parser.add_argument("--resource-root", required=True, type=pathlib.Path)
    parser.add_argument("--engine", required=True, type=pathlib.Path)
    parser.add_argument("--engine-name", required=True)
    parser.add_argument("--engine-version", required=True)
    parser.add_argument("--engine-source", required=True)
    parser.add_argument("--engine-license", required=True)
    parser.add_argument("--dependency", action="append", default=[])
    args = parser.parse_args()

    root = args.resource_root
    runtime = root / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)

    for old in runtime.iterdir():
        if old.is_file() or old.is_symlink():
            old.unlink()
        elif old.is_dir():
            shutil.rmtree(old)
    for old in root.glob("artifact-*.toml"):
        old.unlink()
    for old in (root / "config.toml", root / "engine.toml"):
        if old.exists():
            old.unlink()

    engine_dst = runtime / args.engine.name
    shutil.copy2(args.engine, engine_dst)
    if not args.platform.startswith("windows-"):
        mode = engine_dst.stat().st_mode
        engine_dst.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    write_manifest(
        root / "engine.toml",
        name=args.engine_name,
        version=args.engine_version,
        source=args.engine_source,
        license_name=args.engine_license,
        platform=args.platform,
        filename=engine_dst.name,
        digest=sha256(engine_dst),
    )

    dependencies: list[tuple[str, str]] = []
    for raw in args.dependency:
        dep_path, dep_name, source, license_name, version = parse_dependency(raw)
        dep_dst = runtime / dep_path.name
        shutil.copy2(dep_path, dep_dst)
        manifest_name = f"artifact-{safe_name(dep_name)}.toml"
        write_manifest(
            root / manifest_name,
            name=dep_name,
            version=version,
            source=source,
            license_name=license_name,
            platform=args.platform,
            filename=dep_dst.name,
            digest=sha256(dep_dst),
        )
        dependencies.append((manifest_name, dep_dst.name))

    lines = [
        "schema = 1",
        "",
        "[engine]",
        'manifest = "engine.toml"',
        f'binary = "runtime/{engine_dst.name}"',
    ]
    for manifest_name, filename in dependencies:
        lines.extend(
            [
                "",
                "[[engine.dependencies]]",
                f'manifest = "{manifest_name}"',
                f'binary = "runtime/{filename}"',
            ]
        )
    lines.extend(["", "[strategy]", 'name = "balanced-default"', ""])
    (root / "config.toml").write_text("\n".join(lines), encoding="utf-8")

    print(f"prepared desktop runtime: {root}")
    print(f"engine sha256: {sha256(engine_dst)}")
    print(f"dependencies: {len(dependencies)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
