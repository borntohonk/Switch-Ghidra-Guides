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

### Optional eShop API access

[simba.py](../scripts/simba.py) queries the Nintendo eShop GraphQL API and needs a client certificate
in PEM form. That certificate is produced by [p12_to_pem.py](../scripts/p12_to_pem.py) from the
`ClientCertData` romfs of title `0100000000000859` (firmware 20.0.0 and above). Beyond raw queries,
simba.py can build and maintain a titledb (`titledb.json`) of base games, DLC, demos and bundles. [recon.py](../scripts/recon.py) (JS chunks, GraphQL fields).

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
| `recon_out/` | Output of `recon_savanna.py`: beautified eShop web client scripts, `manifest.js`, `persisted_queries.json`. |

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

### p12_to_pem.py — convert the eShop client certificate to PEM

Converts the `.p12` client certificate shipped in firmware into a single PEM (private key, certificate,
chain) usable by [simba.py](../scripts/simba.py).

```
python scripts/p12_to_pem.py <input_folder> [-o OUTPUT_DIR] [--raw]
```

- **Requirements:** `pip install cryptography` (the script raises an `ImportError` naming it if missing).
- **Input folder:** the `romfs` of title `0100000000000859` — `ClientCertData` — which exists on
  firmware **20.0.0 and above**. It must contain `meta.json`, the `.p12` named in it
  (`eshop_hac_prod.p12`) and the URLs file it references (`eshop_hac_urls.txt`). The romfs can be
  extracted with `hac.py -t nca <nca> --romfsdir <dir>`.
- **Password:** read from `meta.json`; nothing is hardcoded.
- **Output:** `<name>.pem` (e.g. `eshop_hac_prod.pem`) in the current directory, or in `-o OUTPUT_DIR`.
- **stdout:** the target URL patterns from the URLs file, in readable form (optional prefixes expanded,
  `*` for wildcard parts), e.g. `https://hac.*.savanna.srv.nintendo.net/`. `--raw` prints the patterns
  as written (regex).
- Exits with an error if the folder, `meta.json`, `.p12` or URLs file is missing, or the password is
  wrong.

### simba.py — Nintendo eShop GraphQL client and titledb builder

Command-line client for the eShop GraphQL API (`hac.lp1.savanna.srv.nintendo.net`), replacing the
legacy REST endpoints (search, titles/aocs, item detail, title IDs). It can also build and maintain a
[titledb](#titledb-record-format) `titledb.json` (base games, DLC, demos and bundles). Each command prints
one compact JSON object or item per line (NDJSON) unless noted.

```
python scripts/simba.py <command> [args]
```

- **Requirements:** `pip install requests` (the script raises an `ImportError` naming it if missing).
- **Client certificate:** a PEM at `eshop_hac_prod.pem` in the current directory (from
  [p12_to_pem.py](../scripts/p12_to_pem.py)); override with `CERT=/path/to/file.pem`. The script exits
  if the file does not exist, except for the commands that work offline (`regions`, `process-titledb`,
  `reorder-titledb`, `update-titledb-file` and the usage text).
- **Settings are environment variables**, set before the command:

  ```
  ALL=1 PLATFORM=BEE SHOP=3 python scripts/simba.py search
  ```

#### Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `SHOP` | `4` | eShop `shopId` (`@inContext`). |
| `COUNTRY` / `LANG_CODE` / `REGION` | `US` / `en` / `USA` | Store country, language and search region. |
| `PLATFORM` | `HAC` | Search platform: `HAC` or `BEE`. |
| `SALES` | `ONSALE_OR_PRE_ORDER` | `ONSALE`, `COMING_SOON`, or `ALL` (on sale/pre-order plus coming soon, deduped; the default for `search-all` only). |
| `SORT` | `RELEASE_DATE_DESC` | Also `RELEASE_DATE_ASC`, `SALES_AMOUNT_DESC`, `DL_COUNT_DESC`, `PRICE_ASC`, `PRICE_DESC`, `PRICE_END_AT_ASC`, `RELEVANCE`; `BOTH` = newest + oldest passes, deduped. |
| `FREEWORD` / `LIMIT` | empty / `60` | Search term; page size (`dlc` uses `25`). |
| `ALL` | unset | `1` = fetch every page (a single search stops at offset 999). |
| `MAX_PAGES` | `1000` | Page safety cap. |
| `SLEEP` | `0` | Delay between requests: seconds (`3`, `0.5`) or a random range (`1-2`). |
| `BATCH` | `25` | nsUids per request for `scan-range` and `reprocess-titledb`. |
| `BUNDLE` | `1` | Bundle rows are kept (as full-data rows). `BUNDLE=0` drops them. |
| `QUIET` | unset | `1` silences progress lines (`scan-range`, `scrape-all`, `reprocess-titledb`) and the search summary. |
| `PROGRESS_EVERY` | `20` / `10` | Progress interval when stderr is not a terminal: batches (`scan-range`) / titles (`scrape-all`). On a terminal the line is redrawn every step. |
| `PRETTY` | unset | `1` = indented multi-line JSON instead of one compact line (all commands). |
| `RAW` | unset | `1` on `dlc` = print the raw GraphQL rows instead of titledb records. |
| `CLEAN_TEXT` | `1` | `0` = do not clean text when building records (see [Text clean-up](#text-clean-up)). |
| `TEXT_ASCII` / `TEXT_REPLACE` | `2` / unset | Character substitutions in the same clean-up: `TEXT_ASCII` 0 (off), 1 (punctuation, fullwidth forms), 2 (default, + accents) / your own `src=dst;src=dst` pairs. |
| `TITLEDB_SORT` | `1` | `0` = `update-titledb` / `update-titledb-file` append new entries instead of sorting the file by nsUid. |
| `UPDATE_COUNT` | `150` | How many of the newest titles `update-titledb` checks (`ALL=1` = up to 1000). |
| `SCOPE` / `UPDATE` | `all` / unset | `reprocess-titledb`: which entry types to refresh; `UPDATE=1` runs `update-titledb` afterwards. |
| `DEBUG` | unset | `1` prints the equivalent `curl` command of every request to stderr. |
| `GQL` / `CERT` / `TIMEOUT` | eShop endpoint / `eshop_hac_prod.pem` / `60` | Endpoint, certificate path, request timeout (seconds). |

Advanced, for probing the API: `PARENT` (for `fields`), `DLC_RECORD_FIELDS`, `DLC_ROM_SIZES=off`,
`ROM_SIZES`, `BUNDLE_FIELDS`, `DEMO_FIELDS`, `PUBLIC_STATUSES`, `SALES_STATUSES`,
`SCRAPE_SALES_STATUSES`, `INCLUDE_BUNDLES`.

#### Commands

**Shop information**

| Command | Purpose |
|---|---|
| `country`, `regions`, `language [CC]`, `languages [CC]` | Shop/country info and language codes. |
| `save-languages [file]`, `save-regions [file]` | Write `{country: [languages]}` / `{region: [countries]}` JSON for all regions. |

**Lookup and search**

| Command | Purpose |
|---|---|
| `item <nsUid> [lang]`, `title <titleId>...` | Application by nsUid / by title ID. `item` prints a titledb record. Applications only (7001…); not demos, DLC or bundles. |
| `dlc <nsUid> [offset]` | DLC of an **application** (needs the base title's nsUid) as titledb records, one per line (`ALL=1` for every page, `RAW=1` for raw rows). |
| `dlc-titles <titleId>...` | DLC items by DLC title ID. |
| `search [offset]`, `dlc-search [offset]`, `search-count` | Search applications / DLC; result count for the current filters. Bundle rows come back as full-data rows. |
| `get-latest` | Newest page only. Ignores `ALL`, `FREEWORD`, `SORT`, `SALES`, `LIMIT`, `BUNDLE`, `MAX_PAGES`; respects `PLATFORM`, `SHOP`, `COUNTRY`, `LANG_CODE`, `REGION`. |
| `search-all` | Every item, by walking `FREEWORD` prefix shards (one query cannot page past offset 999). |
| `scan-range <from> <to>` | Exact nsUid scan, no search depth limit, `BATCH` nsUids per request, progress and ETA on stderr. The lookup depends on the nsUid prefix, and `<from>` and `<to>` must share it: `7001` applications (search-shaped rows), `7003` demos, `7005` DLC, `7007` bundles (the last three give full-data rows). |

**Building a titledb**

| Command | Purpose |
|---|---|
| `scrape-title <nsUid>` | Application, its DLC (including DLC inside bundles) and its demos as titledb entries, one `{"<nsUid>": record}` per line. |
| `scrape-all [file]` | Titledb entries for every row of NDJSON `scan-range` / `search` output (file or stdin). Applications are scraped (title + DLC + demos); demo, DLC and bundle rows are converted directly. Progress and ETA on stderr (no percentage when reading a stream). |
| `scrape-latest`, `scrape-all-latest` | `scrape-all` of the newest page / of the newest 1000 titles (one search, all pages). |
| `process-titledb [in] [out]` | Merge `{"<nsUid>": record}` lines (from the commands above, file or stdin) into one JSON object. Later duplicates win; one entry per line, or indented with `PRETTY=1`. Offline. |
| `update-titledb [titledb.json]` | Scrape the newest `UPDATE_COUNT` (150) titles and **add** only entries not already in the file; prints how many were added. `ALL=1` checks up to 1000. Never changes existing entries. Result sorted by nsUid. |
| `update-titledb-file <titledb.json> <other>` | Add the entries of another titledb file (NDJSON also accepted) that are not already in the first; a repeated nsUid is added once. Never changes existing entries. Offline. Result sorted by nsUid. |
| `reorder-titledb [file] [out]` | Sort a titledb file by nsUid, ascending (in place by default; `-` = stdout). Offline. |
| `clean-titledb [file] [out]` | Normalise the text fields (`name`, `description`, `intro`, `publisher`, `developer`) of every entry; see [Text clean-up](#text-clean-up). In place by default (only rewritten if something changed). Offline. |
| `reprocess-titledb <in> [out] [nsUid...]` | Re-fetch existing entries and rewrite them in the current format (see below). |

**Probing the API** (the schema has no introspection)

| Command | Purpose |
|---|---|
| `fields <nsUid> [name...]` | Which field names exist on `applicationItem` (`PARENT=relatedItems fields ...` probes inside a field). |
| `dlc-fields <titleId> [name...]`, `bundle-fields [name...]` | The same for `DlcItem` and `BundleItem`. |
| `lookup-probe [nsUid\|name...]` | Which `item { <field>(nsUid: N) }` root fields exist. |
| `raw <nsUid> '<selection>'` | Run an arbitrary `applicationItem` selection and print the response. |
| `extra <nsUid\|country> [field...]` | The extra fields (below) of an item (root follows the nsUid prefix) or of the store; all, or the named ones. |
| `extra-fields [kind]` | List the extra fields (`application demo dlc bundle country`). Offline. |

An `X` from a probe means the type rejects that field; `OK` means the schema accepts it (no data
needed, so the nsUid / title ID may be one that does not exist).

#### titledb record format

Every entry is `{"<nsUid>": record}`. Keys are in titledb (alphabetical) order and unknown data is `null`:

```
bannerUrl category description developer frontBoxArt iconUrl id [ids] intro isDemo key languages name
nsuId numberOfPlayers [parentId] publisher rating ratingContent region releaseDate rightsId screenshots
size version
```

| Type | nsUid prefix | Notes |
|---|---|---|
| Base game | `7001…` | `id` = title ID; `rightsId` = title ID + 16 zeros; `category` from the genre; `intro` from `catchCopy`; `size` from the ROM size. |
| Demo | `7003…` | `isDemo: true`; `id` and `rightsId` are `null`; `parentId` = base title ID (set when scraped through its base title or reprocessed; `null` from a bare demo scan); rating, `ratingContent` and `size` filled. |
| DLC | `7005…` | `ids` = `[id]`; `rightsId` is `null` (it ends in the ticket's master key revision, which the API does not expose); `category`, `languages` and `numberOfPlayers` are `null`. |
| Bundle | `7007…` | `id`, `rightsId`, `languages`, `category` are `null`; `ratingContent` is `[]` when empty. |

Empty `category`, `languages` and `screenshots` are `null`, not `[]`. Fields the API does not provide
(`developer`, `frontBoxArt`, `iconUrl`, `key`, `region`, `version`) are always `null` in new entries.

#### Text clean-up

Text from the eShop can carry oddities that break line-based tools or look wrong. Every record built by
`item`, `dlc`, `scrape-*`, `scan-range` + `scrape-all`, `update-titledb` and `reprocess-titledb` is cleaned
automatically (`CLEAN_TEXT=0` turns this off). `process-titledb` cleans every entry it writes (data scraped
before the clean-up existed is fixed by re-running it), `update-titledb-file` cleans only the entries it adds,
and `clean-titledb` cleans an existing file. What it does to `name`, `description`, `intro`, `publisher` and
`developer`:

- literal `\uXXXX` escapes (including surrogate pairs) and HTML entities (`&amp;`, `&#8482;`) are decoded;
- Unicode NFC normalisation (compatibility forms such as full-width letters are left alone);
- every line terminator becomes `\n`: CRLF, CR, VT, FF, NEL (U+0085), line separator (U+2028) and paragraph
  separator (U+2029). In the single-line fields (`name`, `publisher`, `developer`) a line break becomes a space;
- control characters and invisible characters (zero-width space, word joiner, BOM, soft hyphen) are removed;
  zero-width joiners are kept, since emoji and some scripts need them;
- no-break and other unusual spaces (U+00A0, U+2000–200A, U+202F, U+205F) become a plain space;
- trailing spaces on each line and whitespace at both ends are dropped; text that ends up empty becomes `null`.

`clean-titledb` prints how many entries and which kinds of fix it applied. Visible characters (quotes,
dashes, `™`/`®`, `•`, accented letters) are folded to ASCII at `TEXT_ASCII=2` (default); `TEXT_ASCII=0` disables
this. `™`/`®`/`•`, kana and kanji are kept unless you substitute them:

- `TEXT_REPLACE='src=dst;src=dst'` applies your own substitutions first (an empty `dst` deletes the
  character), e.g. `TEXT_REPLACE='™=;•=-'` drops `™` and turns `•` into `-`.
- `TEXT_ASCII=1` converts typographic punctuation to ASCII: `‘ ’ ‚ ′ ‛ ´` to `'`, `“ ” „ ″ ‟` to `"`,
  `‐ ‑ ‒ – — ― −` to `-`, `…` to `...`; the ideographic space to a plain space; fullwidth forms
  (`！ＡＢＣ：～`) to their ASCII equivalents; Roman-numeral characters (`Ⅱ`) to `II`. Letters, kana, kanji and
  symbols such as `™ ® × ★` stay.
- `TEXT_ASCII=2` additionally drops accents from Latin letters (`Pokémon` becomes `Pokemon`, `Yōdanji`
  becomes `Yodanji`). Kana, kanji and symbols stay.
- Anything else (kana, kanji, `™ ® •`) is left to `TEXT_REPLACE`, e.g. `TEXT_REPLACE='™=;®='`.

For example, `TEXT_ASCII=1` turns `Pokémon™: Let’s Go, Pikachu!` into `Pokémon™: Let's Go, Pikachu!`, and `2`
turns it into `Pokemon™: Let's Go, Pikachu!`. The options also apply while records are being built; accented
letters are only touched at levels 2 and 3.

#### Generating a titledb

Scan each nsUid range, convert the scans to titledb entries, then merge. Do the base games first, so DLC
and demos found through their base title (with `parentId`) win over the bare scans. Use `SLEEP` to
throttle (it applies per request: `SLEEP=3` with the default `BATCH=25` is one request every ~3 s).

```
# generate a new titledb with everything possible for the US / en store
python scripts/simba.py scan-range 70010000000000 70010000140000 > basegames.ndjson
python scripts/simba.py scan-range 70030000000000 70030000026000 > demos.ndjson
python scripts/simba.py scan-range 70050000000000 70050000090000 > dlc.ndjson
python scripts/simba.py scan-range 70070000000000 70070000050000 > bundles.ndjson
python scripts/simba.py scrape-all basegames.ndjson > base_titledb.ndjson
python scripts/simba.py process-titledb base_titledb.ndjson titledb.json
python scripts/simba.py scrape-all dlc.ndjson > dlc_titledb.ndjson
python scripts/simba.py scrape-all bundles.ndjson > bundles_titledb.ndjson
python scripts/simba.py scrape-all demos.ndjson > demos_titledb.ndjson
python scripts/simba.py update-titledb-file titledb.json dlc_titledb.ndjson
python scripts/simba.py update-titledb-file titledb.json bundles_titledb.ndjson
python scripts/simba.py update-titledb-file titledb.json demos_titledb.ndjson
ALL=1 python scripts/simba.py update-titledb titledb.json
```

The ranges above are the upper bounds seen so far; widen them if newer nsUids appear. Scans are not
resumable (rerun the command), and `scrape-all` of the base games is the slow step.

For maintenance of the titledb, weekly-ish:

```
python scripts/simba.py update-titledb titledb.json
```

Other regions: set `SHOP`, `COUNTRY`, `LANG_CODE` and `REGION` (see `regions`, `country`, `languages`);
the older `PLATFORM=BEE SHOP=3 python scripts/simba.py scrape-latest` form still works.

#### Reprocessing an existing titledb

`reprocess-titledb` re-fetches existing entries by nsUid and rewrites them with the current format
(`ids`, nulls, sizes, ratings ...). Unlike `update-titledb`, it **does** overwrite the entries it refreshes.

```
python scripts/simba.py reprocess-titledb titledb.json                       # everything, in place
SCOPE=dlc,demo python scripts/simba.py reprocess-titledb titledb.json         # only some types
python scripts/simba.py reprocess-titledb titledb.json - 70010000000025 70070000040226   # targeted nsUids
UPDATE=1 python scripts/simba.py reprocess-titledb titledb.json               # then add new titles
python scripts/simba.py reprocess-titledb hac_titles.ndjson titledb.json      # from an old scrape-all dump
```

- `SCOPE` is `all` or a comma list of `base`, `demo`, `dlc`, `bundle`. Extra nsUids after the output
  refresh only those (`-` as the output means in place).
- Lookups go by nsUid with the type's own root field, batched (`BATCH`), with `SLEEP` defaulting to `1-2`.
  A rejected batch is split to isolate the bad nsUid and the batch size lowered.
- A refresh never loses data: where the API returns `null` and the old entry had a value (for example a
  DLC `rightsId`, `version`, a demo's `parentId`), the old value stays. Entries the API does not return stay
  as they were.
- An old dump (one base title per line with nested `dlc` / `demos`) is accepted as input; it needs an
  explicit output file.
- Progress is saved next to the output (`<out>.reprocess.ndjson`) and picked up on rerun after an
  interruption; it is removed when the run finishes.

#### Extra fields (library, unused)

`EXTRA_FIELDS` holds every field found on application,demo, DLC, bundle and `country` that no other query in simba.py requests (prices, tags, play styles, features,
movies, notices, upgrade info, dominant colors, disclaimers, tax and payment flags ...), each with its sub-selection.
Nothing in the titledb or Simba code uses them. Validation-only evidence: the server accepts them; a title may have
no data.

| Function | Returns |
|---|---|
| `extra_fields(kind=None)` | Names per kind, or the list of one kind. |
| `item_extra(nsuid, fields=None, region=None, language=None)` | `{field: value}` for all or the named fields; the root follows the nsUid prefix. A field the server errors on is `None`; a failing request is split until the field is alone. |
| `country_extra(fields=None, region=None, language=None)` | The same for the store (`country`). `caTaxLocations` needs parameters at run time and comes back `None`. |
| `get_<kind>_<field_in_snake_case>(...)` | One function per field, made on demand: `get_application_play_styles(nsuid)`, `get_dlc_price_v2(nsuid)`, `get_country_currency()`. |

#### Simba compatibility (library)

simba.py can stand in for a client of the dead bugyo/shogun REST API. These functions keep the shogun client's names,
arguments and return shapes as Simba JSON (the legacy shogun format that nut's `Title.parseSimbaJson` reads), built
from GraphQL data. They are library code: simba.py never imports nut, so the file works on its own and can be shared
unchanged with projects that embed it (nut keeps its `Titles`-filling scrape functions in its own module).

| Function | Returns |
|---|---|
| `getTitleByNsuid(nsuId, region, language)` | Simba JSON of any item. The lookup follows the nsUid prefix (7001/7003/7005/7007). |
| `getDlcByNsuid(nsuId, ...)` | Simba JSON of a DLC. |
| `getAocs(baseNsuid, ..., first_page=None)` | `{"contents": [Simba JSON with "id"], "total"}`. Same DLC set as `scrape-title`. `first_page`: DLC rows already fetched (`fetch_apps`). |
| `getLatest(language, region, cont)`, `searchPage(language, region, page, per_page=LIMIT)` | wg search page: `{"contents": [... "ns_uid"], "total", "total_pages"}`. Pages are 1-based and stop at the newest 1000 items. |
| `ids(titleIds, type, region, language)` | `{"id_pairs": [{"title_id", "id"}]}`. `titleIds` is a list or comma string (25 per request works); `type` is `title` (applications) or `aoc` (DLC). |
| `country(region)`, `countryLanguage(s)`, `saveLanguages`, `saveRegions` | Same as the `country` / `language(s)` / `save-*` commands. |
| `latestNsuids(language, region)` | The newest `LATEST_COUNT` (default and maximum 1000) nsUids of a store, as `scrape-all-latest` lists them (one search over every page, deduped). |
| `fetch_apps(nsuids, region, language)` | Generator of `(nsUid, applicationItem or None, ok)` for many applications, `SCRAPE_BATCH` (15) per request, each with its first 25 DLC rows (`row["dlcItems"]["items"]`, the `first_page` of `getAocs`) and its demo nsUids. |
| `simba_json(item)`, `simba_context(region, language)` | The converter, and the per-thread store/language override the functions above use. |

- `region` / `language` are the legacy values (`US`, `en`). Each request goes to that store. The language is mapped
  to the store's own code (`en` -> `en_US` if that is what `availableLanguages` lists) for lookups. The search uses
  the store's `regionCode` and the short language code (searchV4 returns nothing for `en_US`). The override is per
  thread, so threaded callers work.
- `shop_id` and `force` are accepted and ignored: `SHOP` applies, and there is no disk cache.
- `simba_json(item)` produces the format. Keys with no data are left out, and text is cleaned as for titledb.
  `parseSimbaJson` then fills the same values as `titledb_record` (except `size`, which is `0` rather than `null`
  when unknown). `target_titles` is never produced.
- Demos carry only name, rating, `ratingContent`, size and publisher: `DemoItem` rejects banner, screenshots, release
  date, description and catch copy. `publisher` is checked against the schema once; `DEMO_LOOKUP_FIELDS` replaces it
  (`off` = none).
- `fetch_apps`: above ~18 applications per request (with their 25-row DLC page) the API answers error 1806 with
  `extensions.title` `QUERY_COST_LIMIT_EXCEEDED`; a rejected batch is split and the size lowered. Scraping titles this
  way gives the same data as one lookup per title in far fewer requests (verified live: 47 titles, 119 requests
  became 46).
- DLC paging (`dlc`, `scrape-title`, `getAocs`) stops at the first short page instead of requesting an empty one
  (every page but the last holds exactly `LIMIT` rows, confirmed live).

`simba <what>` prints this Simba JSON without nut, for the store `COUNTRY` in `LANG_CODE`:

```
python scripts/simba.py simba title 70010000000025      # any nsUid type
python scripts/simba.py simba dlc 70050000000010
python scripts/simba.py simba aocs 70010000000025
python scripts/simba.py simba latest 2                  # LIMIT per page
TYPE=aoc python scripts/simba.py simba ids 01007EF00011F001
python scripts/simba.py simba country GB
```

#### Examples

```
python scripts/simba.py search-count
SORT=BOTH ALL=1 python scripts/simba.py search > titles.ndjson
python scripts/simba.py scan-range 70010000000001 70010000001000 | python scripts/simba.py scrape-all
PLATFORM=BEE SHOP=3 python scripts/simba.py scrape-latest
PRETTY=1 python scripts/simba.py item 70010000000025
python scripts/simba.py reorder-titledb titledb.json
```

### [recon_savanna.py](../scripts/recon_savanna.py) — fetch and beautify the eShop web client's JS chunks

Downloads `_buildManifest.js` of a Next.js build and every script it lists, plus every script the entry page itself
loads (main, framework, webpack, `pages/_app`, `app-*`), from the Savanna host with the same client certificate as
simba.py (`CERT`, default `eshop_hac_prod.pem`; no curl). One `requests.Session` first GETs the entry page
(`ENTRY_PATH`, default `/`) to receive the server's "user-bucket" cookie and the `buildId` (default; or give it as
argument). Without the cookie, manifest and static files can come from different builds (404).
Files are saved beautified (`pip install jsbeautifier`, otherwise as downloaded) in `recon_out/` named after their
path (`static/chunks/x.js` -> `static_chunks_x.js`), with `manifest.js` and `persisted_queries.json`.
Non-200 responses are never written; the only deletion is the `pretty_<name>` copy of a file just re-saved. Existing
`.js` files that contain an HTML error page (from older runs) are listed at the end.
Requirements: `pip install requests`; optional `jsbeautifier`; `node` (evaluates the build manifest).
Usage: `python scripts/recon_savanna.py [buildId]`.

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
