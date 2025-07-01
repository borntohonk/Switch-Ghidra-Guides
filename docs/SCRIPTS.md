# `scripts/` reference

Detailed reference for the Python toolkit in [scripts/](../scripts/). For a quick start and install
instructions, see the [README](../README.md). This document covers `scripts/` only — the
[ipcserver/](../ipcserver/) helpers are documented separately.

These scripts work independently of hactool, libhac, hactoolnet, or other third-party binaries.

---

## Contents

- [Concepts & workflow](#concepts--workflow)
- [Folder conventions](#folder-conventions)
- [Entry-point scripts](#entry-point-scripts)
- [Library modules](#library-modules)
- [Data & supporting directories](#data--supporting-directories)

---

## Concepts & workflow

The toolkit decrypts and inspects Nintendo Switch file formats and derives the patterns used to
build sigpatches. A typical end-to-end run looks like:

1. **Keys** — derive a keyset (`prod.keys`) with [crypto.py](../scripts/crypto.py). Optionally fill
   in `mariko_kek` / `mariko_bek` in [keys.py](../scripts/keys.py) first (see below).
2. **Firmware extraction** — run [process_firmware.py](../scripts/process_firmware.py) over a
   `firmware/` folder (or `firmwares/` subfolders with `--batch`) to decrypt, extract and decompress
   the modules of interest into `output/<version>/`.
3. **Pattern finding** — [find_patterns.py](../scripts/find_patterns.py) scans the extracted
   binaries for the instruction patterns that need patching and records string diffs in
   `patch_database/`. [generate_pattern_diffs.py](../scripts/generate_pattern_diffs.py) aligns those
   diffs into regex-friendly form ([known_patterns.py](../scripts/known_patterns.py)).
4. **Patch generation** — [make_patches.py](../scripts/make_patches.py) emits the final `.ips` exefs
   patches and Hekate-style FS patches, packaged as a `.zip`.

Format-specific inspection (dumping a single NCA/XCI/NSP, listing a RomFS, decompressing a KIP1,
etc.) is handled ad-hoc by the unified [hac.py](../scripts/hac.py) CLI.

### Optional Atmosphère integration

[process_firmware.py](../scripts/process_firmware.py) can additionally emit Atmosphère source
patches when a new key revision or firmware target is detected. This is **optional**: if a clone of
[Atmosphère](https://github.com/Atmosphere-NX/Atmosphere) exists at `./atmosphere`, the script writes
`output/<version>/<version>_atmosphere.patch` and `<version>_atmosphere_keygen.patch` (apply with
`cd atmosphere && git apply ../<patch>`). If `./atmosphere` is absent or empty the script prints a
`[WARN] ... skipping` line and continues normally
([process_firmware.py:472-477](../scripts/process_firmware.py), [:667-673](../scripts/process_firmware.py)).
The `atmosphere/` directory is a plain optional clone — **not** a git submodule.

---

## Folder conventions

| Folder | Role |
|---|---|
| `firmware/` | Input: a single firmware's `.nca` files (default for `process_firmware.py`). |
| `firmwares/` | Input: one subfolder per firmware version (used by `process_firmware.py --batch`). |
| `output/<version>/` | Output: extracted/decompressed modules, hashes, strings, patches, keygen state. |
| `nsp/` | Input: `.nsp` files for `process_nsp.py`. |
| `external_binaries/` | Holds `tsec_keygen.bin` (input for `decrypt_atmosphere_tsec_keygen.py`). |
| `patch_database/` | Pattern/patch databases produced by `find_patterns.py` and consumed by `make_patches.py`. |
| `out/` | Default output for `organize_firmware_files.py` / `search_every_nca.py`. |
| `ipc_json_dumps/` | IPC JSON exports produced via Ghidra headless analysis (see `process_swipc.py`). |

---

## Entry-point scripts

Scripts meant to be run directly (`python scripts/<name>.py`).

### hac.py — unified format inspection / extraction CLI

The flagship tool: a single hactool-style CLI for inspecting and extracting every supported format.

```
python scripts/hac.py -t <type> [file] [options]
```

- **`-t/--intype`** (required): `nca`, `xci`, `nsp`, `pfs0`, `romfs`, `npdm`, `ini1`, `kip1`,
  `pk21`, `package2`, `keygen`.
- **`file`**: positional input file (omit only for `-t keygen`).
- Common options: `--outdir DIR`, `--out/-o FILE`, `--titlekey HEX`, `--listromfs`, `--json FILE`
  (NPDM export), `--uncompressed FILE` (decompress KIP1/NSO), `-i/--info` (CNMT metadata),
  `-d/--dev` (dev keyset for `keygen`).
- Section / filesystem extraction: `--section{0..3}[dir]`, `--exefs[dir]`, `--romfs[dir]`,
  `--pfs0dir`, `--header`, `--plaintext`.

Examples (from the tool's own help):

```
python scripts/hac.py -t nca file.nca --romfsdir romfs_out
python scripts/hac.py -t nca file.nca --titlekey 9A9A1E33B9E7308BF569FCCB40387CA2 --exefsdir exefs
python scripts/hac.py -t romfs romfs.bin --listromfs
python scripts/hac.py -t keygen prod.keys
```

### crypto.py — keyset generation (and core crypto library)

Run directly to derive a full keyset. Dual-purpose: also the central crypto library imported across
the toolkit (see [Library modules](#library-modules)).

```
python scripts/crypto.py
```

- `do_keygen()` writes `prod.keys`; `do_dev_keygen()` writes `dev.keys`.
- Optionally fill `mariko_kek` / `mariko_bek` in [keys.py](../scripts/keys.py) first to derive
  `mariko_master_kek_source`. Those values can be sourced from tools such as `lockpick_rcm`.

### process_firmware.py — main firmware pipeline

Decrypts, extracts, decompresses and reports on firmware, and (optionally) emits Atmosphère patches.

```
python scripts/process_firmware.py            # single firmware in firmware/
python scripts/process_firmware.py --batch    # every subfolder in firmwares/
```

- **Input:** `.nca` files in `firmware/` (single) or `firmwares/<version>/` (batch).
- **Output:** `output/<version>/` containing hashes, dAuth firmware strings, `.kip1` and `.nso0`
  modules, `keygen_state_*.json`, and (if `./atmosphere` is present) Atmosphère patches.

### find_patterns.py — pattern discovery

Scans extracted firmware binaries for known patch patterns and collects string diffs for building
regex patterns.

```
python scripts/find_patterns.py [--ams]
```

- Run `process_firmware.py` first so the binaries exist in `output/`.
- `--ams` additionally checks the Atmosphère loader patch.
- Having multiple firmware versions extracted greatly improves the diffs collected.
- Writes pattern data into `patch_database/`.

### generate_pattern_diffs.py — align diffs into regex form

```
python scripts/generate_pattern_diffs.py
```

No arguments. Run after `find_patterns.py`; combines the collected outputs into aligned form to ease
manual pattern creation, regenerating [pattern_diffs.py](../scripts/pattern_diffs.py) and populating
[known_patterns.py](../scripts/known_patterns.py).

### make_patches.py — build final patch artifacts

```
python scripts/make_patches.py
```

No arguments. Consumes the `patch_database/*.txt` databases and produces `.ips` exefs patches plus
Hekate-style FS patches, packaged as a `.zip` (mirrors the layout in `patch_database/`).

### process_nsp.py — extract & analyze NSP packages

```
python scripts/process_nsp.py [-v|--verbose]
```

- **Input:** `.nsp` files in `nsp/`.
- **Output:** extracted package contents and exefs (section 0), with CNMT metadata.

### process_swipc.py — prepare modules for Ghidra IPC export

Outputs firmware `.nso0` / `.kip1` files in the naming scheme expected by the Ghidra headless IPC
JSON exporter.

```
python scripts/process_swipc.py
```

The result can be batch-imported and analyzed with Ghidra's `analyzeHeadless`, producing IPC `.json`
exports like those under [ipc_json_dumps/](../ipc_json_dumps/), e.g.:

```
analyzeHeadless.bat <proj_dir> <proj_name> -postScript EnableSwitchIpcJsonExport.java \
  <ipc_json_dumps/programs> -import <out/programs> -overwrite -log <program.log>
```

### decrypt_atmosphere_tsec_keygen.py — decrypt the TSEC keygen blob

```
python scripts/decrypt_atmosphere_tsec_keygen.py
```

No arguments. Decrypts `external_binaries/tsec_keygen.bin` to `decrypted_tsec_keygen.bin`, which can
be viewed with [envydis](https://github.com/envytools/envytools) or in Ghidra via
[ghidra_falcon](https://github.com/marysaka/ghidra_falcon).

### search_every_nca.py — bulk NCA content search

```
python scripts/search_every_nca.py [input_folder] [output_folder]
```

Positional `argv` (defaults `firmware` / `out`). Searches every NCA section for a pattern and prints
matches (title ID, NCA path, section index, offset).

### organize_firmware_files.py — sort NCAs by content type

```
python scripts/organize_firmware_files.py [input_folder] [output_folder]
```

Positional `argv` (defaults `firmware` / `out`). Sorts NCAs into `programs/` and `applets/` and
writes per-module SHA256 hashes. Also imported as a helper by `process_firmware.py`.

### emummc_h.py — extract FS offsets for emummc headers

```
python scripts/emummc_h.py
```

Disassembles FS KIP1 with Capstone (ARM64) to extract the offsets used in Atmosphère emummc header
files. Also imported by `process_firmware.py`.

### package3_and_stratosphere.py — fetch/extract Atmosphère package3

Dual library + CLI.

```
python scripts/package3_and_stratosphere.py <package3_path> <out_dir>   # extract KIPs from a package3
python scripts/package3_and_stratosphere.py                              # download & extract package3 + stratosphere romfs
```

### disable_ca_verification_patch.py / disable_browser_ca_verification_patch.py

> **Unmaintained since firmware 19.0.0** (kept for reference).

```
python scripts/disable_ca_verification_patch.py            # expects ssl.nso0 in CWD
python scripts/disable_browser_ca_verification_patch.py    # expects foss_browser_ssl.nro in CWD
```

Each emits a `<module_id>.ips` patch. Background:
[disable-ca-verification](https://github.com/misson20000/exefs_patches#disable-ca-verification),
[disable-browser-ca-verification](https://github.com/misson20000/exefs_patches#disable-browser-ca-verification).

---

## Library modules

Imported by the scripts above; not normally run directly. A few expose a small convenience CLI
(noted), but their primary role is as importable modules. The most widely imported — and therefore
the ones to understand first — are **crypto.py**, **util.py**, **nca.py** and **pfs0.py**.

### Crypto & keys

| Module | Role |
|---|---|
| [crypto.py](../scripts/crypto.py) | Core crypto: AES (XTS/CTR/ECB/CBC), master-key derivation, titlekey handling. Also a keygen entry point (above). |
| [keys.py](../scripts/keys.py) | Root key container (e.g. Mariko KEK/BEK); user-fillable. |
| [key_sources.py](../scripts/key_sources.py) | Master-key sources, TSEC/keyblob sources, BIS / header key constants. |
| [aes_128.py](../scripts/aes_128.py) | Pure-Python AES-128 (ECB/CBC/CTR/XTS, incl. Nintendo variants). *(SciresM)* |

### Format parsers

| Module | Format |
|---|---|
| [nca.py](../scripts/nca.py) | NCA (Nintendo Content Archive) header/section decrypt & extract. |
| [pfs0.py](../scripts/pfs0.py) | PFS0 container (NCA sections, NSP). *Has a convenience CLI: `python scripts/pfs0.py <in.pfs0> <out_dir>`.* |
| [hfs0.py](../scripts/hfs0.py) | HFS0 container (XCI partitions). |
| [romfs.py](../scripts/romfs.py) | RomFS read-only filesystem. |
| [ivfc.py](../scripts/ivfc.py) | IVFC hash-tree validation for RomFS. |
| [bktr.py](../scripts/bktr.py) | BKTR relocation tables (update/patch NCAs). |
| [npdm.py](../scripts/npdm.py) | NPDM program manifest (ACL/KAC/SAC). *(switchbrew)* |
| [nacp.py](../scripts/nacp.py) | NACP application control properties. *(switchbrew)* |
| [cnmt.py](../scripts/cnmt.py) | CNMT content-meta parsing. *(switchbrew)* |
| [nxo64.py](../scripts/nxo64.py) | NSO0 / KIP1 decompression (BLZ/LZ4). *(reswitched)* |
| [xci.py](../scripts/xci.py) | XCI cartridge parsing (HFS0 partitions, NCA/CNMT/NACP). |
| [nsp.py](../scripts/nsp.py) | NSP submission package (PFS0, `.tik` titlekeys, CNMT). |

### Helpers & generated data

| Module | Role |
|---|---|
| [util.py](../scripts/util.py) | Shared helpers: hex printing, dir creation, file patching, LZ4/NRO decompression, version parsing. |
| [extract_packages.py](../scripts/extract_packages.py) | Package1/2/3 + INI1 extraction helpers (imported by `process_firmware.py` / `find_patterns.py`; not runnable on its own). |
| [pattern_diffs.py](../scripts/pattern_diffs.py) | **Auto-generated** by `generate_pattern_diffs.py`. |
| [known_patterns.py](../scripts/known_patterns.py) | **Auto-generated** regex/wildcard patterns. |

---

## Data & supporting directories

| Path | Contents |
|---|---|
| [guides/](../guides/) | Ghidra setup & patching tutorials: [Part1A (Windows)](../guides/Part1A-WindowsSetup.MD), [Part1B (Linux)](../guides/Part1B-LinuxSetup.MD), [Part2](../guides/Part2.MD). |
| [scripts/setup_ghidra.sh](../scripts/setup_ghidra.sh) | Automated Linux installer for OpenJDK 21, Ghidra, and the Ghidra Switch loader. |
| `patch_database/` | Pattern/patch databases (`.txt`) shared between `find_patterns.py` and `make_patches.py`. |
| `external_binaries/` | `tsec_keygen.bin` and its license. |
| [ipc_json_dumps/](../ipc_json_dumps/) | Example IPC JSON exports from Ghidra analysis. |
| `img/` | Screenshots referenced by the guides. |
