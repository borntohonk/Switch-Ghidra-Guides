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


import json
import re
import sys
import shutil
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from zipfile import ZipFile

import nxo64
import romfs
import pfs0

REPO = "Atmosphere-NX/Atmosphere"
API_URL = f"https://api.github.com/repos/{REPO}/releases?per_page=50"  # Enough for most repos

def decompress_exefs(main_path, nso_name):
    main_path = main_path
    nso_name = nso_name
    with open(main_path, 'rb') as compressed_exefs_file:
        decompressed_nso = nxo64.decompress_nso(compressed_exefs_file)
        with open(nso_name, 'wb') as decompressed_exefs_file:
            decompressed_exefs_file.write(decompressed_nso)
            decompressed_exefs_file.close()
            compressed_exefs_file.close()

def extract_all_compressed_kips(package3_path: Path, out_dir: Path = Path("package3_and_stratosphere_extracted")):
    """
    Extracts all 8 compressed KIPs from Atmosphere package3 using your 100% working method.
    Writes the exact raw blobs — no trimming, no modifications.
    Produces files that pass hactool -t kip1 validation.
    """
    out_dir.mkdir(exist_ok=True)
    
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
    
    print(f"\nExtracted {extracted}/6 valid compressed KIPs (hactool-compatible).")
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


def fetch_url(url, headers=None):
    """Helper to fetch and decode a URL with headers."""
    if headers is None:
        headers = {}
    # GitHub requires a User-Agent
    headers.setdefault("User-Agent", "python-stdlib-downloader/1.0")
    headers.setdefault("Accept", "application/vnd.github+json")
    
    req = Request(url, headers=headers)
    try:
        with urlopen(req, timeout=30) as response:
            return response.read().decode("utf-8")
    except HTTPError as e:
        print(f"HTTP Error {e.code}: {e.reason} for {url}")
        sys.exit(1)
    except URLError as e:
        print(f"URL Error: {e.reason} for {url}")
        sys.exit(1)


def get_newest_release():
    """Fetch all releases and return the newest by published_at (includes pre-releases)."""
    data = fetch_url(API_URL)
    try:
        releases = json.loads(data)
    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON: {e}")
        sys.exit(1)

    if not releases:
        print("No releases found.")
        sys.exit(1)

    # Filter out drafts, sort by published_at descending
    valid_releases = [r for r in releases if not r.get("draft")]
    if not valid_releases:
        print("No published releases found.")
        sys.exit(1)

    newest = max(valid_releases, key=lambda r: r["published_at"])
    return newest


def download_asset(release, asset_name_contains="atmosphere"):
    """Download the Atmosphere zip asset."""
    for asset in release["assets"]:
        name = asset["name"]
        if asset_name_contains in name and name.endswith(".zip"):
            download_url = asset["browser_download_url"]
            filename = Path(name)
            
            print(f"Downloading {filename} from {release['tag_name']} "
                  f"({'pre-release' if release['prerelease'] else 'stable'})...")
            
            # Stream download with progress
            try:
                req = Request(download_url, headers={"User-Agent": "python-stdlib-downloader/1.0"})
                with urlopen(req, timeout=60) as response, open(filename, "wb") as out_file:
                    total = int(response.headers.get("content-length", 0))
                    downloaded = 0
                    chunk_size = 8192
                    while True:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break
                        out_file.write(chunk)
                        downloaded += len(chunk)
                        if total:
                            print(f"\rProgress: {downloaded / total:.1%}", end="", flush=True)
                print("\nDownload complete.")
                return filename
            except Exception as e:
                print(f"Failed to download {download_url}: {e}")
                sys.exit(1)

    print(f"No matching zip asset found in release {release['tag_name']}")
    sys.exit(1)


def download_and_extract_package3_and_stratosphere_romfs():
    release = get_newest_release()
    
    print(f"Selected: {release['tag_name']} "
          f"({'pre-release' if release['prerelease'] else 'stable'}) "
          f"published {release['published_at'][:10]}")

    zip_path = download_asset(release, asset_name_contains="atmosphere-")

    match = re.search(r"atmosphere-([\d.]+).*?([0-9A-Fa-f]{9,})", zip_path.name)
    if not match:
        print("Could not parse version/hash from filename.")
        sys.exit(1)

    atmosphere_version = re.search(r"[\d.]+", zip_path.name).group()
    atmosphere_hash = match.group(2)[:9]

    print(f"Version: {atmosphere_version}")
    print(f"Hash: {atmosphere_hash}")
    if release['prerelease']:
        ams_string = f"Atmosphere-{atmosphere_version}-prerelease-{atmosphere_hash}"
    else:
        ams_string = f"Atmosphere-{atmosphere_version}-master-{atmosphere_hash}"

    try:
        with ZipFile(zip_path) as amszip:
            with amszip.open("atmosphere/package3") as package3_file:
                with open("package3", "wb") as package3:
                    shutil.copyfileobj(package3_file, package3)
                package3.close()
                package3_path = Path("package3")
                if package3_path.exists():
                    extract_all_compressed_kips(package3_path)
                    decompress_all_kips(Path("package3_and_stratosphere_extracted"))
            package3_file.close()
        amszip.close()
    except KeyError:
        print("Warning: 'atmosphere/package3' not found in zip.")
    except Exception as e:
        print(f"Error reading zip: {e}")


    try:
        with ZipFile(zip_path) as amszip:
            with amszip.open("atmosphere/stratosphere.romfs") as stratosphere_file:
                with open("stratosphere.romfs", "wb") as stratosphere_romfs:
                    shutil.copyfileobj(stratosphere_file, stratosphere_romfs)
                    stratosphere_romfs.close()
                stratosphere_path = Path("stratosphere.romfs")
                if stratosphere_path.exists():
                    with open("stratosphere.romfs", "rb") as stratosphere_file:
                        stratosphere_data = stratosphere_file.read()
                        romfs.romfs_process(stratosphere_data, output_path=Path(f"package3_and_stratosphere_extracted"), list_only=False, print_info=False)
            stratosphere_file.close()
        amszip.close()

    except KeyError:
        print("Warning: 'atmosphere/stratosphere.romfs' not found in zip.")
    except Exception as e:
        print(f"Error reading zip: {e}")

    try:
        erpt_path = Path("package3_and_stratosphere_extracted/atmosphere/contents/010000000000002b/exefs.nsp")
        if erpt_path.exists():
            with open(erpt_path, "rb") as erpt_file:
                erpt_data = erpt_file.read()
                exefs = pfs0.extract_pfs0(erpt_data, f"package3_and_stratosphere_extracted/")
                exefs

    except KeyError:
        print("Warning: error with ERPT.")
    except Exception as e:
        print(f"Error reading zip: {e}")
    os.rename('package3_and_stratosphere_extracted/main', 'package3_and_stratosphere_extracted/compressed_erpt.nso0')
    decompress_exefs('package3_and_stratosphere_extracted/compressed_erpt.nso0', 'package3_and_stratosphere_extracted/uncompressed_erpt.nso0')


    if Path(zip_path).exists():
        os.remove(zip_path)
    if Path("package3").exists():
        os.remove("package3")
    if Path("stratosphere.romfs").exists():
        os.remove("stratosphere.romfs")

    return ams_string

def main():
    download_and_extract_package3_and_stratosphere_romfs()

if __name__ == "__main__":
    main()