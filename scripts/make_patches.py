#!/usr/bin/env python3
# make_patches.py
# Generates Atmosphere .ips patches AND Hekate bootloader/patches.ini

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

import os
import ast
import shutil
import glob
import sys
import re

# --- Atmosphere IPS patches ---
REQUIRED_DIRS = [
    "patches/atmosphere/exefs_patches/es_patches/",
    "patches/atmosphere/exefs_patches/nfim_ctest/",
    "patches/atmosphere/exefs_patches/nim_ctest/",
    "patches/atmosphere/exefs_patches/olsc_patches/",
    "patches/atmosphere/exefs_patches/erpt_patches/",
    "patches/atmosphere/kip_patches/fs_patches/",
    "patches/atmosphere/kip_patches/loader_patches/",
]

IPS_PATCHES_FILE = "patch_database/ips_patches.txt"

# --- Hekate patches.ini ---
BOOTLOADER_DIR = "patches/bootloader"
PATCHES_INI = os.path.join(BOOTLOADER_DIR, "patches.ini")

FS_KIP_FILE = "patch_database/fs_kip_patches.txt"
LDR_KIP_FILE = "patch_database/ldr_kip_patches.txt"

HEADER = '''# UTF-8
# A KIP section is [kip1_name:sha256_hex_8bytes]
# A patchset is .patch_name=kip_section_dec:offset_hex_0x:length_hex_0x:src_data_hex,dst_data_hex
# _dec: 1 char decimal | _hex_0x: max u32 prefixed with 0x | _hex: hex array.
# Kip1 section decimals: TEXT: 0, RODATA: 1, DATA: 2.
#
# Care when editing this, otherwise it will fail to be parsed.
# The order matters and must match up to the patches in pkg2.c of Hekate. (See _kip_ids variable.)

'''

def _parse_patch_file(filepath: str) -> list:
    """Parse a patch database file, returning list of entries."""
    entries = []
    if not os.path.exists(filepath):
        return entries
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f.readlines(), 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if line.endswith(','):
                    line = line[:-1]
                
                try:
                    entry = ast.literal_eval(line)
                    entries.append((line_num, entry))
                except Exception as e:
                    print(f"Warning: Line {line_num}: {e}")
                    continue
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
    
    return entries


def _create_directory_tree():
    """Delete and recreate all output directories for a clean build."""
    print("Ensuring clean output directories...")
    
    # Clean Atmosphere patches
    atmosphere_parent = "patches/atmosphere"
    if os.path.exists(atmosphere_parent):
        shutil.rmtree(atmosphere_parent)
        print(f"   [DEL] Removed {atmosphere_parent}/")
    os.makedirs(atmosphere_parent, exist_ok=True)
    print(f"   [NEW] Created {atmosphere_parent}/")
    
    for directory in REQUIRED_DIRS:
        os.makedirs(directory, exist_ok=True)
        print(f"      [OK] {directory}")
    
    # Clean Hekate bootloader
    if os.path.exists(BOOTLOADER_DIR):
        shutil.rmtree(BOOTLOADER_DIR)
        print(f"   [DEL] Removed {BOOTLOADER_DIR}/")
    os.makedirs(BOOTLOADER_DIR, exist_ok=True)
    print(f"   [NEW] Created {BOOTLOADER_DIR}/")


def _write_atmosphere_ips_patches(entries: list) -> int:
    """Write .ips files for Atmosphere from parsed entries."""
    created_count = 0
    
    for line_num, entry in entries:
        if len(entry) != 4:
            print(f"Warning: Line {line_num}: Expected 4 items, got {len(entry)}. Skipping.")
            continue
        
        version, moduleid, ipspath, patch_hex = entry
        moduleid = moduleid.strip()
        ipspath = ipspath.strip()
        
        if not ipspath.endswith('/'):
            print(f"Warning: Line {line_num}: Invalid path '{ipspath}'. Skipping.")
            continue
        
        try:
            os.makedirs(ipspath, exist_ok=True)
            filename = os.path.join(ipspath, f"{moduleid}.ips")
            patch_bytes = bytes.fromhex(patch_hex)
            
            with open(filename, 'wb') as ips_file:
                ips_file.write(patch_bytes)
            
            created_count += 1
            print(f"   Created: {filename} ({len(patch_bytes)} bytes)")
        except Exception as e:
            print(f"Error: Line {line_num}: {e}")
    
    return created_count


def _write_hekate_fs_patches(out_file, entries: list) -> int:
    """Write FS KIP patches to hekate patches.ini."""
    count = 0
    
    for line_num, entry in entries:
        if len(entry) != 4:
            print(f"Warning: FS line {line_num}: Expected 4-tuple, got {len(entry)}. Skipping.")
            continue
        
        try:
            fw_version, patch_string, fs_type, sdk_version = entry
            patch_string = patch_string.strip()
            
            out_file.write(f'#FS {fw_version}-{fs_type} - SDKVersion: {sdk_version}\n')
            out_file.write(f"{patch_string}\n\n")
            count += 1
        except Exception as e:
            print(f"Error: FS line {line_num}: {e}")
    
    return count


def _write_hekate_loader_patches(out_file, entries: list) -> int:
    """Write Loader KIP patches to hekate patches.ini."""
    count = 0
    
    for line_num, entry in entries:
        if len(entry) not in (3, 4):
            print(f"Warning: Loader line {line_num}: Expected 3 or 4-tuple, got {len(entry)}. Skipping.")
            continue
        
        try:
            fw_version = entry[0]
            patch_block = entry[1].strip()
            ams_version = entry[3] if len(entry) == 4 else "unknown"
            
            out_file.write(f'#loader {ams_version} (fw: {fw_version})\n')
            out_file.write(f"{patch_block}\n\n")
            count += 1
        except Exception as e:
            print(f"Error: Loader line {line_num}: {e}")
    
    return count


def _get_latest_version(filepath: str, version_index: int) -> str:
    """Extract the latest version from the last entry in a patch file."""
    entries = _parse_patch_file(filepath)
    if not entries:
        return "unknown"
    
    try:
        _, last_entry = entries[-1]
        return str(last_entry[version_index])
    except (IndexError, TypeError):
        return "unknown"

def process_atmosphere_ips():
    """Generate .ips files from ips_patches.txt."""
    if not os.path.exists(IPS_PATCHES_FILE):
        print(f"Warning: '{IPS_PATCHES_FILE}' not found — skipping Atmosphere IPS generation.")
        return 0

    print(f"\nGenerating Atmosphere .ips patches from {IPS_PATCHES_FILE}...")
    entries = _parse_patch_file(IPS_PATCHES_FILE)
    created_count = _write_atmosphere_ips_patches(entries)
    print(f"   → Created {created_count} Atmosphere .ips patches")
    return created_count


def generate_hekate_patches_ini():
    """Generate patches/bootloader/patches.ini from KIP patch files."""
    if not os.path.exists(FS_KIP_FILE) and not os.path.exists(LDR_KIP_FILE):
        print("Warning: Neither fs_kip_patches.txt nor ldr_kip_patches.txt found — skipping patches.ini.")
        return

    print(f"\nGenerating Hekate {PATCHES_INI}...")
    total_sections = 0

    with open(PATCHES_INI, 'w', encoding='utf-8') as out_file:
        out_file.write(HEADER)
        
        # Write FS patches
        if os.path.exists(FS_KIP_FILE):
            print(f"   Processing {FS_KIP_FILE}...")
            entries = _parse_patch_file(FS_KIP_FILE)
            fs_count = _write_hekate_fs_patches(out_file, entries)
            total_sections += fs_count
            print(f"      Added {fs_count} FS sections")
        
        # Write Loader patches
        if os.path.exists(LDR_KIP_FILE):
            print(f"   Processing {LDR_KIP_FILE}...")
            entries = _parse_patch_file(LDR_KIP_FILE)
            ldr_count = _write_hekate_loader_patches(out_file, entries)
            total_sections += ldr_count
            print(f"      Added {ldr_count} Loader sections")

    print(f"\nGenerated {PATCHES_INI} with {total_sections} patch sections.")

def _cleanup_old_archives():
    """Remove old patch archive files."""
    old_zips = glob.glob("Hekate+AMS-package3-sigpatches-*.zip")
    if not old_zips:
        print("No old sigpatch archives found.")
        return
    
    print(f"Removing {len(old_zips)} old archive(s)...")
    for old_zip in old_zips:
        try:
            os.remove(old_zip)
            print(f"   [DEL] {old_zip}")
        except Exception as e:
            print(f"   [ERR] Failed to delete {old_zip}: {e}")


def _create_archive(atmosphere_version: str, firmware_version: str):
    """Create final patch archive with version information."""
    archive_name = f"Hekate+AMS-package3-sigpatches-{atmosphere_version}-cfw-{firmware_version}"
    
    try:
        shutil.make_archive(archive_name, 'zip', 'patches')
        print(f"\nCreated archive: {archive_name}.zip")
    except Exception as e:
        print(f"\nError creating archive: {e}")


def main():
    """Main entry point for patch generation."""
    _create_directory_tree()
    _cleanup_old_archives()
    
    # Generate patches
    ips_count = process_atmosphere_ips()
    generate_hekate_patches_ini()
    
    # Extract version information from patch files
    atmosphere_version = _get_latest_version(LDR_KIP_FILE, 3)  # Index 3 is ams_version
    firmware_version = _get_latest_version(LDR_KIP_FILE, 0)    # Index 0 is fw_version
    
    print(f"\nDetected Atmosphere version: {atmosphere_version}")
    print(f"Detected highest firmware version: {firmware_version}")
    
    # Create archive
    _create_archive(atmosphere_version, firmware_version)
    
    print("\nAll tasks completed successfully!")

if __name__ == "__main__":
    main()