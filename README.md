This repository contains reverse engineering notes and guides for educational purposes, using open source tools such as ghidra to pry into binaries for the Nintendo Switch. It also contains basic methodology on how to operate ghidra with the intent to inspect "ARM" binaries that run on the Nintendo Switch.

This repository does not host, nor contain guides that assist with circumventing security measures that safeguard digital assets.

All material exist purely for research reference.

The Python toolkit under [scripts/](scripts/) works independently of hactool, libhac, hactoolnet, or other third-party binaries.

---

## Requirements

- Python 3
- `pycryptodome` **or** `pycryptodomex`
  - Debian/Ubuntu (apt): `python3-pycryptodome` (imports as `pycryptodomex`)
  - Arch (pacman): `python-pycryptodome` (imports as `pycryptodome`)
- `capstone` — ARM64 disassembly (pattern finding, emummc offsets)
- `lz4` — firmware decompression
- `cryptography` — NPDM signature handling

```
python3 -m pip install pycryptodome capstone lz4 cryptography
```

---

## Ghidra / patch-making tutorial

- Part 1A — set up Ghidra and the switch loader on Windows: [(link)](guides/Part1A-WindowsSetup.MD)
- Part 1B — set up Ghidra and the switch loader on Linux: [(link)](guides/Part1B-LinuxSetup.MD)
  - or use [scripts/setup_ghidra.sh](scripts/setup_ghidra.sh) to install OpenJDK 21, Ghidra and the Switch loader automatically on Linux.
- Part 2 — a basic introduction to Ghidra, demonstrating how to force-enable network connectivity in the "NIFM" module: [(link)](guides/Part2.MD)
  - the resulting "patches" for what this guide produces are at https://github.com/misson20000/exefs_patches/tree/master/atmosphere/exefs_patches/nfim_ctest

---

## Quick start

```
# 1. Derive a keyset (prod.keys). Optionally fill mariko_kek / mariko_bek in scripts/keys.py first.
python scripts/crypto.py

# 2. Process firmware: decrypt, extract and decompress modules of interest.
#    Put .nca files in firmware/ (single) or firmwares/<version>/ subfolders (--batch).
python scripts/process_firmware.py
python scripts/process_firmware.py --batch

# 3. Inspect a single file ad-hoc with the unified hactool-style CLI.
python scripts/hac.py -t nca file.nca --romfsdir out

# 4. Build sigpatches: find patterns -> align diffs -> emit .ips / FS patches.
python scripts/find_patterns.py --ams
python scripts/generate_pattern_diffs.py
python scripts/make_patches.py
```

> **Note:** the `mariko_kek` / `mariko_bek` values used in step 1 can be obtained with tools such as `lockpick_rcm`. Filling them into [scripts/keys.py](scripts/keys.py) lets `crypto.py` derive `mariko_master_kek_source`.

> **Optional Atmosphère patches:** if a clone of [Atmosphère](https://github.com/Atmosphere-NX/Atmosphere) exists at `./atmosphere`, `process_firmware.py` also writes Atmosphère source patches into `output/<version>/` when a new key revision or firmware target is detected. This is optional and is **not** a git submodule; if the folder is absent the step is skipped.

**Full reference for every script (entry points, libraries, inputs/outputs): [docs/SCRIPTS.md](docs/SCRIPTS.md).**

---

## Credits

- [switchbrew](https://switchbrew.org) — for all the information on formats and cryptography.
- [@SciresM](https://github.com/SciresM) — hactool, for references on formats — [scripts/aes_128.py](scripts/aes_128.py) — [tsec_keygen.bin](https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/tsec_keygen/tsec_keygen.bin)
- [@reswitched](https://github.com/reswitched) — [scripts/nxo64.py](scripts/nxo64.py)
- [@blawar](https://github.com/blawar) — for references to various things in [nut](https://github.com/blawar/nut)
- everything else: [@borntohonk](https://github.com/borntohonk)
