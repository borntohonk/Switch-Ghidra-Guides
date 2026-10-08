# Copyright (c) 2026 borntohonk
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


"""
Process NSP files: extract and analyze them.

Supports sparse NCA sections via BKTR layered storage, and optional
base + update pairing so sparse holes are filled from a matching update.

Usage:
    python process_nsp.py
    python process_nsp.py -v

    # Explicit pair
    python process_nsp.py --base game.nsp --update game_update.nsp -v

    # Auto-match sparse bases with updates found in ./nsp
    python process_nsp.py --pair-sparse -v
"""

import argparse
import traceback
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import nca
import nsp
import pfs0
import util
from cnmt import ContentMetaType, ContentType

NSP_INPUT_DIR = Path("nsp/")
NSP_EXTRACT_DIR = Path("nsp/extracted/")
EXEFS_OUTPUT_DIR = Path("nsp/extracted_exefs/")
ROMFS_OUTPUT_DIR = Path("nsp/extracted_romfs/")


# ---------------------------------------------------------------------------
# Helpers: title identity and Program NCA lookup
# ---------------------------------------------------------------------------

def process_sdk_object_only(nsp_file: Path):
    nsp.process_nsp_info_in_memory_for_sdk_object(nsp_file)

def application_id_from_cnmt(cnmt_obj) -> int:
    """
    Resolve the base application title ID from a CNMT.

    Application  -> title_id
    Patch        -> patch_extended_header.application_id (fallback: title_id & ~0x800)
    """
    if cnmt_obj.content_meta_type == ContentMetaType.APPLICATION:
        return cnmt_obj.title_id
    if cnmt_obj.content_meta_type == ContentMetaType.PATCH:
        if getattr(cnmt_obj, "patch_extended_header", None) is not None:
            return cnmt_obj.patch_extended_header.application_id
        # Conventional patch TID ends with 0x800
        return cnmt_obj.title_id & ~0x800
    if cnmt_obj.content_meta_type == ContentMetaType.ADD_ON_CONTENT:
        if getattr(cnmt_obj, "addon_extended_header", None) is not None:
            return cnmt_obj.addon_extended_header.application_id
        return cnmt_obj.title_id
    return cnmt_obj.title_id


def find_program_nca(metadata: nsp.NspMetadata, titlekey=None):
    """
    Locate the Program NCA inside an extracted NSP.

    Prefers content_type == Program; falls back to primary (largest non-CNMT).
    Returns (NcaFileInfo, titlekey_bytes).
    """
    tk = titlekey if titlekey is not None else metadata.primary_titlekey

    # Prefer explicit Program content type
    for nca_info in metadata.nca_files:
        if nca_info.filename.endswith(".cnmt.nca"):
            continue
        try:
            hdr = nca.NcaHeaderOnly(util.InitializeFile(nca_info.filepath))
            if hdr.content_type == "Program":
                return nca_info, tk
        except Exception:
            continue

    # Fallback: primary (largest non-CNMT)
    if metadata.primary_nca is not None:
        return metadata.primary_nca, tk

    raise FileNotFoundError(f"No Program NCA found in {metadata.nsp_filename}")


def load_nsp_bundle(nsp_path: Path, verbose: bool = False):
    """
    Extract an NSP and return (metadata, cnmt_obj, app_id, meta_type, version).
    """
    extract_path = NSP_EXTRACT_DIR / nsp_path.stem
    metadata = nsp.extract_nsp(nsp_path, extract_path, print_progress=verbose)
    if verbose:
        nsp.print_nsp_metadata(metadata, verbose=True)

    cnmt_obj = nsp.extract_cnmt_and_parse(metadata, print_progress=verbose)
    if verbose:
        cnmt_obj.print_info(verbose=True)

    app_id = application_id_from_cnmt(cnmt_obj)
    return metadata, cnmt_obj, app_id, cnmt_obj.content_meta_type, cnmt_obj.version


def open_program_nca(metadata: nsp.NspMetadata) -> nca.Nca:
    """Open the Program NCA for an extracted NSP metadata bundle."""
    nca_info, titlekey = find_program_nca(metadata)
    return nca.Nca(
        util.InitializeFile(nca_info.filepath),
        master_kek_source=None,
        titlekey=titlekey,
    )


# ---------------------------------------------------------------------------
# Single-NSP processing (no pairing)
# ---------------------------------------------------------------------------

def process_single_nsp(nsp_file: Path, verbose: bool = False):
    """Process one NSP: extract CNMT + ExeFS from its Program NCA."""
    print(f"\n{'=' * 70}")
    print(f"Processing: {nsp_file.name}")
    print(f"{'=' * 70}")

    nca_data = None
    try:
        metadata, cnmt_obj, app_id, meta_type, version = load_nsp_bundle(
            nsp_file, verbose=verbose
        )

        if verbose:
            print(f"\n[EXEFS] Extracting section 0 (exefs)...")

        nca_data = open_program_nca(metadata)

        # debug print nca info:
        #nca.NcaInfo(nca_data)

        exefs_data = nca.save_section(nca_data, 0)

        title_id = f"{cnmt_obj.title_id:016X}"
        exefs_output = EXEFS_OUTPUT_DIR / title_id
        pfs0.extract_pfs0(exefs_data, exefs_output, print_progress=verbose)

        if getattr(nca_data, "IsSparse", False):
            print(
                f"\n✓ Processed {nsp_file.name} "
                f"(sparse sections via BKTR layer — use --base/--update or "
                f"--pair-sparse to complete from an update)"
            )
        else:
            print(f"\n✓ Successfully processed {nsp_file.name}")

    except Exception as e:
        sparse_note = ""
        try:
            if nca_data is not None and nca_data.IsSparse:
                sparse_note = " (sparse NCA — try --base/--update pairing)"
        except Exception:
            pass
        print(f"\n✗ Failed to process {nsp_file.name}{sparse_note}: {e}")
        if verbose:
            traceback.print_exc()


# ---------------------------------------------------------------------------
# Base + update pairing
# ---------------------------------------------------------------------------

def process_paired_nsps(
    base_path: Path,
    update_path: Path,
    verbose: bool = False,
):
    """
    Process a designated base + update pair.

    Opens both Program NCAs, runs apply_update_pairing so sparse holes on
    the base are filled from the update's Indirect layers, then extracts
    ExeFS from the resolved base section 0.
    """
    print(f"\n{'=' * 70}")
    print(f"Pairing base + update")
    print(f"  base:   {base_path.name}")
    print(f"  update: {update_path.name}")
    print(f"{'=' * 70}")

    try:
        base_meta, base_cnmt, base_app_id, base_type, base_ver = load_nsp_bundle(
            base_path, verbose=verbose
        )
        upd_meta, upd_cnmt, upd_app_id, upd_type, upd_ver = load_nsp_bundle(
            update_path, verbose=verbose
        )

        if base_app_id != upd_app_id:
            print(
                f"\n✗ Title mismatch: base app_id=0x{base_app_id:016X} "
                f"vs update app_id=0x{upd_app_id:016X}"
            )
            return

        if verbose:
            print(
                f"\n[PAIR] app_id=0x{base_app_id:016X}  "
                f"base_type={base_type.name} v{base_ver}  "
                f"update_type={upd_type.name} v{upd_ver}"
            )

        base_nca = open_program_nca(base_meta)
        update_nca = open_program_nca(upd_meta)

        if verbose:
            sparse_secs = [
                i for i in range(4) if base_nca.fsheaders[i].IsSparse
            ]
            patch_secs = [
                i for i in range(4) if update_nca.fsheaders[i].has_patch_indirect
            ]
            print(f"[PAIR] base sparse sections: {sparse_secs}")
            print(f"[PAIR] update Indirect sections: {patch_secs}")

        if verbose:
            b0 = base_nca.fsheaders[0]
            u0 = update_nca.fsheaders[0]
            print(
                f"[PAIR] base sec0: sparse={b0.IsSparse} "
                f"table_size=0x{b0.sparseTableSize:X} "
                f"entry_count={b0.sparseTableHeaderEntryCount} "
                f"phys=0x{b0.sparsePhysicalOffset:X} "
                f"section_bytes={len(base_nca.sections[0])} "
                f"content={b0.content_start:X}-{b0.content_end:X} "
                f"has_content={b0.section_has_content}"
            )
            print(
                f"[PAIR] update sec0: sparse={u0.IsSparse} "
                f"indirect={u0.has_patch_indirect} "
                f"section_bytes={len(update_nca.sections[0])} "
                f"content={u0.content_start:X}-{u0.content_end:X} "
                f"has_content={u0.section_has_content}"
            )

        # Pair RomFS (section 1) via update Indirect + base sparse.
        base_nca.apply_update_pairing(update_nca, section_indices=[1])

        # ExeFS (section 0) source priority:
        #  1. Base sparse BKTR layer (if table exists)
        #  2. Update full section 0 (common when base ExeFS is sparse-stub)
        #  3. Base degraded physical decrypt
        #  4. Update section 0 regardless
        exefs_source = None
        exefs_nca = None

        if base_nca.sparse_storages[0] is not None:
            exefs_source = "base-sparse-layer"
            exefs_nca = base_nca
        elif (
            not update_nca.fsheaders[0].IsSparse
            and (
                update_nca.fsheaders[0].section_has_content
                or len(update_nca.sections[0]) > 0
            )
        ):
            exefs_source = "update-full-section"
            exefs_nca = update_nca
        else:
            if base_nca.fsheaders[0].IsSparse and base_nca.sparse_storages[0] is None:
                try:
                    base_nca._init_sparse_storage(0)
                except Exception as e:
                    if verbose:
                        print(f"[PAIR] base sparse init: {e}")
                if base_nca.sparse_storages[0] is None:
                    base_nca._init_sparse_degraded(0)
            if base_nca.sparse_storages[0] is not None or (
                base_nca.decrypted_sections[0]
                and len(base_nca.decrypted_sections[0]) > 0
            ):
                exefs_source = "base-degraded"
                exefs_nca = base_nca
            else:
                exefs_source = "update-fallback"
                exefs_nca = update_nca

        if verbose:
            print(f"[EXEFS] source={exefs_source}")
            print("[EXEFS] Extracting section 0 (exefs)...")

        exefs_data = nca.save_section(exefs_nca, 0)
        if not exefs_data:
            raise ValueError(
                f"ExeFS extraction returned empty "
                f"(source={exefs_source}, "
                f"base_sparse={base_nca.fsheaders[0].IsSparse}, "
                f"update_has_content={update_nca.fsheaders[0].section_has_content})"
            )

        title_id = f"{base_app_id:016X}"
        exefs_output = EXEFS_OUTPUT_DIR / title_id
        pfs0.extract_pfs0(exefs_data, exefs_output, print_progress=verbose)

        # Free ExeFS buffers before the multi-GiB RomFS stream
        del exefs_data
        for obj in (base_nca, update_nca):
            try:
                if obj.sections:
                    obj.sections[0] = b""
                if obj.decrypted_sections:
                    obj.decrypted_sections[0] = b""
            except Exception:
                pass
        import gc
        gc.collect()

        # ----------------------------------------------------------------
        # RomFS (section 1): base sparse + update Indirect layered storage
        # ----------------------------------------------------------------
        if verbose:
            b1 = base_nca.fsheaders[1]
            u1 = update_nca.fsheaders[1]
            print(
                f"[ROMFS] base sec1: sparse={b1.IsSparse} "
                f"table_size=0x{b1.sparseTableSize:X} "
                f"layer={base_nca.sparse_storages[1] is not None} "
                f"content={b1.content_start:X}-{b1.content_end:X}"
            )
            print(
                f"[ROMFS] update sec1: indirect={u1.has_patch_indirect} "
                f"layer={update_nca.indirect_storages[1] is not None} "
                f"content={u1.content_start:X}-{u1.content_end:X}"
            )
            print(
                f"[ROMFS] paired base indirect={base_nca.indirect_storages[1] is not None} "
                f"sparse={base_nca.sparse_storages[1] is not None}"
            )

        romfs_output = ROMFS_OUTPUT_DIR / title_id
        util.mkdirp(romfs_output)

        # Prefer the NCA that holds the resolved section-1 layer
        romfs_nca = base_nca
        if (
            base_nca.indirect_storages[1] is None
            and update_nca.indirect_storages[1] is not None
        ):
            romfs_nca = update_nca

        if verbose:
            print(f"[ROMFS] Extracting layered section 1 → {romfs_output}")

        ok = nca.SectionExtractor.extract_section_romfs(
            romfs_nca, romfs_output, section_idx=1, verbose=verbose
        )
        if not ok:
            raise ValueError(
                "RomFS extraction failed — sparse+Indirect layer may be "
                "incomplete or content extents missing"
            )

        # Quick proof: count extracted files
        file_count = sum(1 for p in romfs_output.rglob("*") if p.is_file())
        if verbose:
            print(f"[ROMFS] Extracted {file_count} file(s) under {romfs_output}")

        print(
            f"\n✓ Paired {base_path.name} + {update_path.name} "
            f"(app 0x{base_app_id:016X})\n"
            f"  ExeFS → {exefs_output}\n"
            f"  RomFS → {romfs_output} ({file_count} files)"
        )

    except Exception as e:
        print(f"\n✗ Pairing failed: {e}")
        if verbose:
            traceback.print_exc()


def auto_pair_sparse(nsp_files: List[Path], verbose: bool = False):
    """
    Scan all NSPs in the list, group by application ID, and for every
    sparse base that has at least one update of the same title, run
    process_paired_nsps with the highest-version update.

    NSPs that are not part of a sparse pair are processed individually.
    """
    # catalogue: app_id -> list of (path, meta_type, version, is_sparse_program)
    catalog: Dict[int, List[Tuple[Path, ContentMetaType, int, bool]]] = {}

    print(f"\n{'=' * 70}")
    print(f"Scanning {len(nsp_files)} NSP(s) for sparse pairing...")
    print(f"{'=' * 70}")

    for nsp_file in nsp_files:
        try:
            metadata, cnmt_obj, app_id, meta_type, version = load_nsp_bundle(
                nsp_file, verbose=False
            )
            # Header-only sparse probe (first 0xC00 only — no full NCA load).
            is_sparse = False
            try:
                nca_info, _tk = find_program_nca(metadata)
                with open(nca_info.filepath, "rb") as f:
                    header_blob = f.read(0xC00)
                hdr_only = nca.NcaHeaderOnly(header_blob)
                dec = hdr_only.decrypted_nca_header
                for si in range(4):
                    fs = nca.FsHeader(
                        dec[0x400 + si * 0x200 : 0x400 + (si + 1) * 0x200]
                    )
                    if fs.IsSparse:
                        is_sparse = True
                        break
            except Exception:
                pass

            catalog.setdefault(app_id, []).append(
                (nsp_file, meta_type, version, is_sparse)
            )
            if verbose:
                print(
                    f"  {nsp_file.name}: app=0x{app_id:016X} "
                    f"type={meta_type.name} v{version} sparse={is_sparse}"
                )
        except Exception as e:
            print(f"  ✗ scan failed for {nsp_file.name}: {e}")
            if verbose:
                traceback.print_exc()

    paired_paths = set()

    for app_id, entries in catalog.items():
        bases = [
            e for e in entries
            if e[1] == ContentMetaType.APPLICATION or (
                e[1] != ContentMetaType.PATCH and e[3]
            )
        ]
        # Prefer explicit APPLICATION entries; also treat sparse non-patch as base
        app_bases = [e for e in entries if e[1] == ContentMetaType.APPLICATION]
        if not app_bases:
            app_bases = [e for e in entries if e[3] and e[1] != ContentMetaType.PATCH]

        updates = [e for e in entries if e[1] == ContentMetaType.PATCH]
        # Sort updates by version descending — pick newest
        updates.sort(key=lambda e: e[2], reverse=True)

        sparse_bases = [e for e in app_bases if e[3]]

        if sparse_bases and updates:
            # Pair each sparse base with the newest update
            newest_upd = updates[0]
            for base_entry in sparse_bases:
                process_paired_nsps(base_entry[0], newest_upd[0], verbose=verbose)
                paired_paths.add(base_entry[0])
                paired_paths.add(newest_upd[0])
        elif sparse_bases and not updates:
            for base_entry in sparse_bases:
                print(
                    f"\n⚠ Sparse base {base_entry[0].name} "
                    f"(app 0x{app_id:016X}) has no update in ./nsp — "
                    f"processing alone (zeros for holes)"
                )
                process_single_nsp(base_entry[0], verbose=verbose)
                paired_paths.add(base_entry[0])

    # Process remaining NSPs that were not part of a pair
    for nsp_file in nsp_files:
        if nsp_file not in paired_paths:
            process_single_nsp(nsp_file, verbose=verbose)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Process NSP files: extract CNMT/ExeFS, with optional sparse "
            "base+update pairing."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
      Process every .nsp in ./nsp (sparse sections get a virtual image
      with zero-fill for holes).

  %(prog)s -v
      Same, with verbose progress.

  %(prog)s --base game.nsp --update game_update.nsp -v
      Explicitly pair a base NSP with an update of the same title.
      Sparse holes on the base are filled from the update's Indirect layers.

  %(prog)s --pair-sparse -v
      Auto-detect sparse bases and matching updates inside ./nsp, pair
      them (newest update wins), then process remaining NSPs alone.
        """,
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print verbose progress information",
    )
    parser.add_argument(
        "--base",
        type=Path,
        default=None,
        help="Path to a base application .nsp (requires --update)",
    )
    parser.add_argument(
        "--update",
        type=Path,
        default=None,
        help="Path to an update/patch .nsp (requires --base)",
    )
    parser.add_argument(
        "--pair-sparse",
        action="store_true",
        help=(
            "Auto-match sparse base NSPs with updates of the same title "
            "found in ./nsp"
        ),
    )

    args = parser.parse_args()

    # --- Explicit pair mode ---
    if args.base is not None or args.update is not None:
        if args.base is None or args.update is None:
            parser.error("--base and --update must be used together")
        if not args.base.is_file():
            parser.error(f"Base NSP not found: {args.base}")
        if not args.update.is_file():
            parser.error(f"Update NSP not found: {args.update}")
        process_paired_nsps(args.base, args.update, verbose=args.verbose)
        print(f"\n{'=' * 70}")
        print("Processing complete!")
        print(f"{'=' * 70}")
        return

    # --- Directory scan modes ---
    nsp_files = sorted(NSP_INPUT_DIR.glob("*.nsp"))
    if not nsp_files:
        print(f"No .nsp files found in {NSP_INPUT_DIR}/")
        return

    print(f"Found {len(nsp_files)} NSP file(s)")

    if args.pair_sparse:
        auto_pair_sparse(nsp_files, verbose=args.verbose)
    else:
        for nsp_file in nsp_files:
            try:
                process_single_nsp(nsp_file, verbose=args.verbose)
                #process_sdk_object_only(nsp_file)
            except KeyboardInterrupt:
                print("\nInterrupted by user")
                break
            except Exception as e:
                print(f"\nUnexpected error processing {nsp_file.name}: {e}")
                if args.verbose:
                    traceback.print_exc()
                continue

    print(f"\n{'=' * 70}")
    print("Processing complete!")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
