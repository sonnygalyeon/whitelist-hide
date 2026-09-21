#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import pathlib
import shutil
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "third_party" / "upstream.lock.toml"
DEFAULT_PROFILE = ROOT / "apps" / "desktop" / "profile" / "balanced"


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def quote(value: str) -> str:
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
                f"name = {quote(name)}",
                f"version = {quote(version)}",
                f"source = {quote(source)}",
                f"license = {quote(license_name)}",
                "",
                "[artifact]",
                f"platform = {quote(platform)}",
                f"filename = {quote(filename)}",
                f"sha256 = {quote(digest)}",
                "",
            ]
        ),
        encoding="utf-8",
    )


def copy_artifact(
    source: pathlib.Path,
    destination: pathlib.Path,
    manifest_dir: pathlib.Path,
    *,
    manifest_name: str,
    artifact_name: str,
    version: str,
    provenance: str,
    license_name: str,
    platform: str,
) -> tuple[pathlib.Path, pathlib.Path]:
    if not source.is_file():
        raise SystemExit(f"required artifact is missing: {source}")

    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)

    manifest = manifest_dir / f"{manifest_name}.toml"
    write_manifest(
        manifest,
        name=artifact_name,
        version=version,
        source=provenance,
        license_name=license_name,
        platform=platform,
        filename=destination.name,
        digest=sha256(destination),
    )
    return destination, manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", choices=("macos", "linux", "windows"))
    parser.add_argument("--platform", required=True)
    parser.add_argument("--engine", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--profile", type=pathlib.Path, default=DEFAULT_PROFILE)
    parser.add_argument("--windivert-dll", type=pathlib.Path)
    parser.add_argument("--windivert-driver", type=pathlib.Path)
    parser.add_argument("--cygwin-dll", type=pathlib.Path)
    parser.add_argument("--lua-dir", type=pathlib.Path)
    args = parser.parse_args()

    with LOCK_PATH.open("rb") as stream:
        lock = tomllib.load(stream)

    upstream = lock[args.target]
    output = args.output.resolve()
    if output.exists():
        shutil.rmtree(output)

    runtime_dir = output / "runtime"
    manifest_dir = runtime_dir / "manifests"
    profile_dir = output / "profile"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    shutil.copytree(args.profile, profile_dir)

    strategy = tomllib.loads((profile_dir / "strategy.toml").read_text(encoding="utf-8"))
    strategy_id = str(strategy["id"])

    engine_dest, engine_manifest = copy_artifact(
        args.engine.resolve(),
        runtime_dir / args.engine.name,
        manifest_dir,
        manifest_name="engine",
        artifact_name=str(upstream["artifact"]),
        version=str(upstream["commit"]),
        provenance=f"{upstream['repository']}@{upstream['commit']}",
        license_name=str(upstream["license"]),
        platform=args.platform,
    )

    dependencies: list[tuple[pathlib.Path, pathlib.Path]] = []

    if args.target == "windows":
        required = {
            "--windivert-dll": args.windivert_dll,
            "--windivert-driver": args.windivert_driver,
            "--cygwin-dll": args.cygwin_dll,
            "--lua-dir": args.lua_dir,
        }
        missing = [name for name, value in required.items() if value is None]
        if missing:
            raise SystemExit("Windows staging requires " + ", ".join(missing))

        driver = lock["windows_driver"]
        for source, manifest_name, artifact_name in [
            (args.windivert_dll, "windivert-dll", "WinDivert.dll"),
            (args.windivert_driver, "windivert-driver", "WinDivert64.sys"),
        ]:
            assert source is not None
            dest, manifest = copy_artifact(
                source.resolve(),
                runtime_dir / source.name,
                manifest_dir,
                manifest_name=manifest_name,
                artifact_name=artifact_name,
                version=str(driver["version"]),
                provenance=str(driver["asset_url"]),
                license_name=str(driver["license"]),
                platform=args.platform,
            )
            dependencies.append((dest, manifest))

        cygwin = lock["windows_cygwin"]
        assert args.cygwin_dll is not None
        dest, manifest = copy_artifact(
            args.cygwin_dll.resolve(),
            runtime_dir / args.cygwin_dll.name,
            manifest_dir,
            manifest_name="cygwin-runtime",
            artifact_name="cygwin1.dll",
            version=str(cygwin["version"]),
            provenance=str(cygwin["source"]),
            license_name=str(cygwin["license"]),
            platform=args.platform,
        )
        dependencies.append((dest, manifest))

        assert args.lua_dir is not None
        lua_dir = args.lua_dir.resolve()
        for filename in ("zapret-lib.lua", "zapret-antidpi.lua"):
            source = lua_dir / filename
            dest, manifest = copy_artifact(
                source,
                runtime_dir / "lua" / filename,
                manifest_dir,
                manifest_name=filename.removesuffix(".lua"),
                artifact_name=filename,
                version=str(upstream["commit"]),
                provenance=f"{upstream['repository']}@{upstream['commit']}",
                license_name=str(upstream["license"]),
                platform=args.platform,
            )
            dependencies.append((dest, manifest))

    def rel_from_profile(path: pathlib.Path) -> str:
        relative_to_root = path.relative_to(output)
        return pathlib.Path("..", *relative_to_root.parts).as_posix()

    lines = [
        "schema = 1",
        "",
        "[engine]",
        f"manifest = {quote(rel_from_profile(engine_manifest))}",
        f"binary = {quote(rel_from_profile(engine_dest))}",
        "",
    ]

    for dependency, manifest in dependencies:
        lines.extend(
            [
                "[[engine.dependencies]]",
                f"manifest = {quote(rel_from_profile(manifest))}",
                f"binary = {quote(rel_from_profile(dependency))}",
                "",
            ]
        )

    lines.extend(["[strategy]", f"name = {quote(strategy_id)}", ""])
    (profile_dir / "config.toml").write_text("\n".join(lines), encoding="utf-8")

    print(f"staged desktop runtime: {output}")
    print(f"engine_sha256={sha256(engine_dest)}")
    print(f"dependencies={len(dependencies)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
