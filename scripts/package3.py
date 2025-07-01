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


"""Extract the KIPs from a local Atmosphere package3 file"""

import argparse
import re
import sys
from pathlib import Path

import nxo64


def extract_all_compressed_kips(package3_path: Path, out_dir: Path = Path("package3_extracted")):
    """
    Extracts the compressed KIPs from an Atmosphere package3.
    Writes the exact raw blobs — no trimming, no modifications.
    Produces files that pass hactool -t kip1 validation.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    
    with open(package3_path, "rb") as f:
        data = f.read()
    
    print("Extracting compressed KIPs (exact raw blobs, no trimming)...")
    
    # Marker -> filename mapping
    kips = [
        #(b'emummc', "emummc.bin"),
        (b'Loader', "loader.kip1"),
        (b'NCM', "ncm.kip1"),
        (b'ProcessManager', "pm.kip1"),
        (b'sm', "sm.kip1"),
        #(b'boot', "boot.bin"),
        (b'spl', "spl.kip1"),
        (b'ams_mitm', "ams_mitm.kip1"),
    ]
    
    extracted = 0
    for marker, filename in kips:
        result = re.search(marker, data)
        if result is None:
            print(f"Warning: Marker {marker!r} not found – skipping {filename}")
            continue
        
        name_pos = result.start()
        header_data = data[name_pos - 0x10 : name_pos]
        
        offset = int.from_bytes(header_data[0x0:0x4], 'little')
        size = int.from_bytes(header_data[0x4:0x8], 'little')
        end = offset + size
        
        kip_raw = data[offset:end]
        
        out_path = out_dir / filename
        
        with open(out_path, "wb") as f:
            f.write(kip_raw)  # Exact raw blob — no changes
        f.close()

        print(f"Extracted {filename} ({size} bytes raw) @ {offset:#x}")
        extracted += 1
    
    print(f"\nExtracted {extracted}/{len(kips)} valid compressed KIPs (hactool-compatible).")
    print(f"Output directory: {out_dir.resolve()}")


def decompress_all_kips(kip_dir: Path):
    """
    Decompresses all .kip1 files in a directory and writes decompressed versions with 'u_' prefix.
    Skips files that already start with 'u_' (already decompressed).
    """
    kip_dir = Path(kip_dir)
    if not kip_dir.exists():
        print(f"Error: Directory {kip_dir} does not exist.")
        return
    
    kip_files = sorted([f for f in kip_dir.glob("*.kip1") if not f.name.startswith("u_")])
    
    if not kip_files:
        print(f"No .kip1 files found in {kip_dir} (or all already decompressed)")
        return
    
    print(f"\nDecompressing {len(kip_files)} KIP files...")
    
    for kip_path in kip_files:
        decompressed_filename = "u_" + kip_path.name
        decompressed_path = kip_dir / decompressed_filename
        
        # Skip if already decompressed
        if decompressed_path.exists():
            print(f"Skipping {kip_path.name} (already decompressed)")
            continue
        
        try:
            with open(kip_path, "rb") as compressed_kip:
                decompressed_data = nxo64.decompress_kip(compressed_kip)
                nxo64.write_file(str(decompressed_path), decompressed_data)
            print(f"Decompressed {kip_path.name} -> {decompressed_filename}")
        except Exception as e:
            print(f"Error decompressing {kip_path.name}: {e}")
    
    print(f"Decompression complete.")


def main():
    parser = argparse.ArgumentParser(description="Extract the compressed KIPs from an Atmosphere package3.")
    parser.add_argument("package3", type=Path, help="path to a package3 file")
    parser.add_argument("out_dir", type=Path, nargs="?", default=Path("package3_extracted"),
                        help="output directory (default: package3_extracted)")
    parser.add_argument("--decompress", action="store_true",
                        help="also write decompressed u_<name>.kip1 copies")
    args = parser.parse_args()

    if not args.package3.is_file():
        print(f"Error: {args.package3} does not exist.")
        sys.exit(1)

    extract_all_compressed_kips(args.package3, args.out_dir)
    if args.decompress:
        decompress_all_kips(args.out_dir)


if __name__ == "__main__":
    main()
