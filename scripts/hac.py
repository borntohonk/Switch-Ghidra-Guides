#!/usr/bin/env python3

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
hac.py - Nintendo Switch file format tool (inspired by hactool)

Supported types: nca, xci, nsp, pfs0, romfs, npdm, ini1, kip1, pk21/package2, keygen
"""

import argparse
import sys
from pathlib import Path

from nca import Nca, SectionExtractor, NcaInfo

import pfs0
import xci
import npdm
import util
import romfs
import extract_packages
import crypto
import nsp


def main():
    parser = argparse.ArgumentParser(
        description="Nintendo Switch file format inspection / extraction tool",
        epilog="Examples:\n"
               "  hac.py -t nca file.nca --romfsdir romfs_out\n"
               "  hac.py -t nca file.nca --titlekey 9A9A1E33B9E7308BF569FCCB40387CA2 --exefsdir exefs\n"
               "  hac.py -t romfs romfs.bin --listromfs\n"
               "  hac.py -t keygen prod.keys\n",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "-t", "--intype", required=True,
        choices=["nca", "xci", "nsp", "pfs0", "romfs", "npdm", "ini1", "kip1", "pk21", "package2", "keygen"],
        help="input file format/type"
    )
    parser.add_argument(
        "file", nargs="?", help="input file (not needed for keygen)"
    )

    parser.add_argument("--out", "-o", help="output file (for single-file results)")
    parser.add_argument("--outdir", help="output directory (for extractions)")

    # ── Other shared / format specific ──────────────────────────────────────
    extract_g = parser.add_argument_group("PFS0 / RomFS / XCI / NSP options")
    extract_g.add_argument("--pfs0dir", metavar="DIR", help="extract PFS0 contents (alias of --outdir)")
    extract_g.add_argument("--xci_key", help="XCI header key (optional)")

    npdm_g = parser.add_argument_group("NPDM options")
    npdm_g.add_argument("--json", metavar="FILE", help="export NPDM as JSON")

    pkg_g = parser.add_argument_group("Package2 / INI1 / KIP options")
    pkg_g.add_argument("--uncompressed", metavar="FILE", help="decompress KIP1/NSO")

    nca_g = parser.add_argument_group("NCA options")
    nca_g.add_argument("--titlekey", help="Titlekey (32 hex chars) for titlekey-encrypted NCAs")
    nca_g.add_argument("--plaintext", metavar="FILE", help="Save plaintext NCA (encrypted header + decrypted sections)")
    nca_g.add_argument("--header", metavar="FILE", help="Save decrypted NCA header")
    nca_g.add_argument("--section0", metavar="FILE", help="Save raw decrypted section 0")
    nca_g.add_argument("--section1", metavar="FILE", help="Save raw decrypted section 1")
    nca_g.add_argument("--section2", metavar="FILE", help="Save raw decrypted section 2")
    nca_g.add_argument("--section3", metavar="FILE", help="Save raw decrypted section 3")
    nca_g.add_argument("--section0dir", metavar="DIR", help="Extract section 0 (if RomFS or PFS0)")
    nca_g.add_argument("--section1dir", metavar="DIR", help="Extract section 1")
    nca_g.add_argument("--section2dir", metavar="DIR", help="Extract section 2")
    nca_g.add_argument("--section3dir", metavar="DIR", help="Extract section 3")
    nca_g.add_argument("--exefs", metavar="FILE", help="Save decrypted ExeFS section as .pfs0")
    nca_g.add_argument("--exefsdir", metavar="DIR", help="Extract ExeFS section contents")
    nca_g.add_argument("--romfs", metavar="FILE", help="Save decrypted RomFS section as .romfs")
    nca_g.add_argument("--romfsdir", metavar="DIR", help="Extract RomFS section contents")
    nca_g.add_argument("--listromfs", action="store_true", help="List files in RomFS section (no extraction)")

    key_g = parser.add_argument_group("Keygen options")
    key_g.add_argument("-d", "--dev", action="store_true", help="generate dev keys instead of prod")

    args = parser.parse_args()

    # ── Keygen ──────────────────────────────────────────────────────────────
    if args.intype == "keygen":
        out_path = args.out or args.file or ("dev.keys" if args.dev else "prod.keys")
        generator = crypto.do_dev_keygen if args.dev else crypto.do_keygen
        generator(out_path)
        print(f"Keys written to: {out_path}")
        return 0

    # Input file required for all other modes
    if not args.file:
        parser.error(f"input file required for --intype {args.intype}")

    input_path = Path(args.file)
    if not input_path.is_file():
        parser.error(f"file not found: {input_path}")

    # Unified output dir logic (handles aliases)
    outdir = args.outdir
    for alias in (args.pfs0dir, args.exefsdir, args.romfsdir):
        if alias and not outdir:
            outdir = alias

    if outdir:
        Path(outdir).mkdir(parents=True, exist_ok=True)

    # ── Format handlers ─────────────────────────────────────────────────────

    if args.intype == "npdm":
        if not args.json:
            parser.error("--json FILE required for npdm")
        obj = util.InitializeFile(str(input_path))
        npdm.export_npdm_json(obj, args.json)
        print(f"NPDM exported to: {args.json}")
        return 0

    if args.intype == "pfs0":
        if not outdir:
            parser.error("extraction requires --outdir or --pfs0dir")
        obj = util.InitializeFile(str(input_path))
        pfs0.extract_pfs0(obj, outdir)
        print(f"PFS0 extracted to: {outdir}")
        return 0

    if args.intype == "romfs":
        obj = util.InitializeFile(str(input_path))
        if args.listromfs:
            romfs.romfs_process(obj, output_path=None, list_only=True, print_info=False)
        elif outdir:
            romfs.romfs_process(obj, output_path=outdir, list_only=False, print_info=False)
            print(f"RomFS extracted to: {outdir}")
        else:
            parser.error("use --romfsdir / --outdir or --listromfs")
        return 0

    if args.intype == "xci":
        obj = util.InitializeFile(str(input_path))
        if outdir:
            xci.xci_process(obj, output_path=outdir, xci_key=args.xci_key,
                            auto_load_keys=True, verify_hashes=False,
                            list_only=False, print_info=False)
            print(f"XCI extracted to: {outdir}")
        else:
            xci.xci_process(obj, output_path=None, xci_key=args.xci_key,
                            auto_load_keys=True, verify_hashes=False,
                            list_only=True, print_info=True)
        return 0

    if args.intype in ("pk21", "package2"):
        if not outdir:
            parser.error("--outdir required for package2 extraction")
        f = util.InitializeFile(str(input_path))
        key = extract_packages.try_decrypt_package2(f)
        if not key:
            print("Failed to decrypt Package2", file=sys.stderr)
            return 1
        ctx = extract_packages.decrypt_and_extract_package2(f, key)
        if not ctx.ini1_bin:
            print("No INI1 section found", file=sys.stderr)
            return 1
        extract_packages.extract_kips_from_ini1(ctx.ini1_bin, outdir)
        print(f"KIPs extracted to: {outdir}")
        return 0

    if args.intype == "ini1":
        if not outdir:
            parser.error("--outdir required for ini1")
        f = util.InitializeFile(str(input_path))
        extract_packages.extract_kips_from_ini1(f, outdir)
        print(f"KIPs extracted to: {outdir}")
        return 0

    if args.intype == "kip1":
        if not args.uncompressed:
            parser.error("--uncompressed FILE required")
        util.decompress_kip(str(input_path), args.uncompressed)
        print(f"Decompressed to: {args.uncompressed}")
        return 0
    
    # nsp can also be extracted just calling for type pfs0
    # what makes type nsp different, is that it automatically extracts the titlekey;
    # it then uses the titlekey to extract the exefs and romfs of the primary nca; (sometimes the romfs dir is empty)
    if args.intype == "nsp":
        if not outdir:
            parser.error("--outdir required for nsp")
        nsp.extract_exefs_from_nsp(input_path, outdir, print_progress=True)
        print(f'NSP extracted to: {outdir}')
        return 0

    if args.intype == "nca":
        if not args.file:
            parser.error("input file required for --intype nca")

        input_path = Path(args.file)
        if not input_path.is_file():
            parser.error(f"file not found: {input_path}")

        # Prepare titlekey if provided
        titlekey = None
        if args.titlekey:
            titlekey_str = args.titlekey.replace(" ", "").strip().lower()
            if len(titlekey_str) != 32 or not all(c in "0123456789abcdef" for c in titlekey_str):
                parser.error("--titlekey must be exactly 32 hexadecimal characters")
            titlekey = bytes.fromhex(titlekey_str)

        # Load NCA
        try:
            file_obj = util.InitializeFile(str(input_path))
            nca = Nca(file_obj, titlekey=titlekey)
        except Exception as e:
            print(f"Failed to load/decrypt NCA: {e}", file=sys.stderr)
            return 1

        # Always show info (like hactool does by default)
        try:
            NcaInfo(nca)
        except Exception as e:
            print(f"Warning: Could not print full NCA info: {e}", file=sys.stderr)

        # ── Output handling ─────────────────────────────────────────────────────

        any_output = False

        # Single-file outputs (mutually exclusive in most cases, but we allow multiple)
        if args.plaintext:
            if SectionExtractor.save_plaintext_nca(nca, args.plaintext):
                print(f"Plaintext NCA saved to: {args.plaintext}")
                any_output = True
            else:
                print(f"Failed to save plaintext NCA", file=sys.stderr)

        if args.header:
            if SectionExtractor.save_header(nca, args.header, encrypted=False):
                print(f"Decrypted header saved to: {args.header}")
                any_output = True
            else:
                print(f"Failed to save header", file=sys.stderr)

        # Raw section dumps
        for sec, path in enumerate([args.section0, args.section1, args.section2, args.section3], 0):
            if path:
                if SectionExtractor.save_section_raw(nca, sec, path):
                    print(f"Section {sec} saved to: {path}")
                    any_output = True
                else:
                    print(f"Failed to save section {sec}", file=sys.stderr)

        # Section extractions (directory outputs)
        for sec, dirpath in enumerate([args.section0dir, args.section1dir, args.section2dir, args.section3dir], 0):
            if dirpath:
                Path(dirpath).mkdir(parents=True, exist_ok=True)
                if SectionExtractor.extract_section(nca, sec, dirpath):
                    print(f"Section {sec} extracted to: {dirpath}")
                    any_output = True
                else:
                    print(f"Failed to extract section {sec}", file=sys.stderr)

        # ExeFS (usually PFS0)
        if args.exefs:
            if SectionExtractor.save_section_as_pfs0(nca, args.exefs):
                print(f"ExeFS (PFS0) saved to: {args.exefs}")
                any_output = True
            else:
                print("No valid ExeFS/PFS0 section found", file=sys.stderr)

        if args.exefsdir:
            Path(args.exefsdir).mkdir(parents=True, exist_ok=True)
            if SectionExtractor.extract_section_pfs0(nca, args.exefsdir):
                print(f"ExeFS extracted to: {args.exefsdir}")
                any_output = True
            else:
                print("No valid ExeFS/PFS0 section found or extraction failed", file=sys.stderr)

        # RomFS
        if args.romfs:
            if SectionExtractor.save_section_as_romfs(nca, args.romfs):
                print(f"RomFS saved to: {args.romfs}")
                any_output = True
            else:
                print("No valid RomFS section found", file=sys.stderr)

        if args.romfsdir:
            Path(args.romfsdir).mkdir(parents=True, exist_ok=True)
            if SectionExtractor.extract_section_romfs(nca, args.romfsdir):
                print(f"RomFS extracted to: {args.romfsdir}")
                any_output = True
            else:
                print("No valid RomFS section found or extraction failed", file=sys.stderr)

        if args.listromfs:
            contents = SectionExtractor.list_romfs_contents(nca)
            if contents:
                print("\nRomFS file list:")
                for entry in contents:
                    print(f"  {entry}")
                any_output = True
            else:
                print("No RomFS section found or failed to list contents", file=sys.stderr)

        # If nothing was requested → just show info (already done above)
        if not any_output:
            print("\nNo extraction/output option specified. NCA info shown above.")
            print("Use --romfs, --romfsdir, --exefs, --exefsdir, --sectionX, etc. to extract content.")

        return 0

    parser.error(f"unsupported intype: {args.intype}")

if __name__ == "__main__":
    sys.exit(main() or 0)