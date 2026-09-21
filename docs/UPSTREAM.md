# Pinned upstream engine sources

whitelist-hide does not treat a binary as trusted merely because it came from a known repository.

The source inputs used for engine builds are pinned in `third_party/upstream.lock.toml` by exact 40-character Git commit SHA.

## Current pins

### macOS

- repository: Flowseal/zapret-mac-discord-youtube
- commit: `94c3b5125b4904ce2f6aec0e2197fe17f2fadf14`
- source directory: `nfq`
- output: `utunws`
- license: MIT, verified from the repository `LICENSE`

The macOS fork contains the `utun` transport required by the current backend design.

### Linux

- repository: bol-van/zapret
- commit: `d437963452674faadfd45adcd62466272b5a2fcd`
- source directory: `nfq`
- output: `nfqws`
- license: MIT, verified from `docs/LICENSE.txt`

### Windows

- repository: bol-van/zapret2
- commit: `00f5aaa36de500971faf6db440dd7d8b25672281`
- source directory: `nfq2`
- output: `winws2.exe`
- license: MIT, verified from `docs/LICENSE.txt`
- WinDivert runtime: 2.2.2

The Windows build follows the current upstream model: Cygwin x86_64, static LuaJIT, `make cygwin64`, then a separately checksummed WinDivert 2.2.2 runtime bundle.

## Source-build workflow

`.github/workflows/engine-source-build.yml` builds macOS, Linux and Windows engines from exact pinned source commits.

The workflow:

1. validates the lock file;
2. initializes an empty upstream Git repository;
3. fetches only the exact locked commit;
4. confirms `HEAD` equals that commit;
5. confirms the expected license file exists;
6. builds from source;
7. generates SHA-256 sums and provenance metadata;
8. uploads the result as a CI artifact.

The CI artifact is still not automatically installed or executed. A release process must feed its digest into the normal artifact manifest and verification path.
