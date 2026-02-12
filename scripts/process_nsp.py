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

This script:
1. Finds all NSP files in the nsp/ directory
2. Extracts each NSP
3. Analyzes CNMT metadata
4. Extracts primary NCA's section 0 (exefs)

Usage:
    python process_nsp.py              # Quiet mode
    python process_nsp.py -v           # Verbose mode
    python process_nsp.py --verbose    # Verbose mode
"""

import argparse
import nca
import nsp
import cnmt
import pfs0
import util
from pathlib import Path

NSP_INPUT_DIR = Path('nsp/')
NSP_EXTRACT_DIR = Path('nsp/extracted/')
EXEFS_OUTPUT_DIR = Path('nsp/extracted_exefs/')


def process_single_nsp(nsp_file: Path, verbose: bool = False):
    """
    Process a single NSP file.

    Args:
        nsp_file: Path to .nsp file
        verbose:  Whether to print progress information
    """
    filename_without_ext = nsp_file.stem
    extract_path = NSP_EXTRACT_DIR / filename_without_ext

    print(f"\n{'='*70}")
    print(f"Processing: {nsp_file.name}")
    print(f"{'='*70}")

    try:
        # Extract NSP and gather metadata
        metadata = nsp.extract_nsp(
            nsp_file,
            extract_path,
            print_progress=verbose
        )

        # Print metadata
        nsp.print_nsp_metadata(metadata, verbose=verbose)

        # Extract and parse CNMT from primary NCA
        if verbose:
            print(f"\n[CNMT] Extracting CNMT from primary NCA...")
        try:
            cnmt_obj = nsp.extract_cnmt_and_parse(
                metadata,
                print_progress=verbose
            )

            # Print CNMT info
            cnmt_obj.print_info(verbose=verbose)

            # Extract exefs (section 0)
            if verbose:
                print(f"\n[EXEFS] Extracting section 0 (exefs)...")
            nca_data = nca.Nca(util.InitializeFile(metadata.primary_nca.filepath), master_kek_source=None, titlekey=metadata.primary_titlekey)
            exefs_data = nca.save_section(nca_data, 0)

            # Extract PFS0 from exefs
            title_id = f"{cnmt_obj.title_id:016X}"
            exefs_output = EXEFS_OUTPUT_DIR / title_id
            pfs0.extract_pfs0(exefs_data, exefs_output, print_progress=verbose)

            print(f"\n✓ Successfully processed {nsp_file.name}")

        except Exception as e:
            print(f"\n✗ Failed to extract CNMT: {e}")
            if verbose:
                import traceback
                traceback.print_exc()

    except Exception as e:
        print(f"\n✗ Failed to process NSP: {e}")
        if verbose:
            import traceback
            traceback.print_exc()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Process NSP files: extract and analyze them.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s              # Process NSP files in quiet mode
  %(prog)s -v           # Process NSP files with verbose output
  %(prog)s --verbose    # Process NSP files with verbose output
        """
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print verbose progress information"
    )

    args = parser.parse_args()

    util.mkdirp(NSP_EXTRACT_DIR)
    util.mkdirp(EXEFS_OUTPUT_DIR)

    nsp_files = list(NSP_INPUT_DIR.glob("*.nsp"))

    if not nsp_files:
        print(f"No .nsp files found in {NSP_INPUT_DIR}/")
        return

    print(f"Found {len(nsp_files)} NSP file(s)")

    for nsp_file in nsp_files:
        try:
            process_single_nsp(nsp_file, verbose=args.verbose)
        except KeyboardInterrupt:
            print("\nInterrupted by user")
            break
        except Exception as e:
            print(f"\nUnexpected error processing {nsp_file.name}: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            continue

    print(f"\n{'='*70}")
    print("Processing complete!")
    print(f"{'='*70}")

if __name__ == "__main__":
    main()