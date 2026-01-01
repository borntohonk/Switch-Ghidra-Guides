#!/usr/bin/env python3
# make_patches.py
# Generates Atmosphere .ips patches AND Hekate bootloader/patches.ini

# Copyright (c) 2025 borntohonk
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

def create_directories():
    """Delete and recreate the parent output directories for a clean build."""
    print("Ensuring clean output directories...")

    # --- Atmosphere patches parent ---
    atmosphere_parent = "patches/atmosphere"
    if os.path.exists(atmosphere_parent):
        shutil.rmtree(atmosphere_parent)
        print(f"   [DEL] Removed existing {atmosphere_parent}/")
    os.makedirs(atmosphere_parent, exist_ok=True)  # exist_ok safe since we just deleted
    print(f"   [NEW] Created {atmosphere_parent}/")

    # Create the required exefs_patches subdirectories
    for directory in REQUIRED_DIRS:
        os.makedirs(directory, exist_ok=True)
        print(f"      [OK] {directory}")

    # --- Hekate bootloader parent ---
    if os.path.exists(BOOTLOADER_DIR):
        shutil.rmtree(BOOTLOADER_DIR)
        print(f"   [DEL] Removed existing {BOOTLOADER_DIR}/")
    os.makedirs(BOOTLOADER_DIR, exist_ok=True)
    print(f"   [NEW] Created {BOOTLOADER_DIR}/")

def process_atmosphere_ips():
    """Original logic: generate .ips files from ips_patches.txt."""
    if not os.path.exists(IPS_PATCHES_FILE):
        print(f"Warning: '{IPS_PATCHES_FILE}' not found — skipping Atmosphere IPS generation.")
        return 0

    print(f"\nGenerating Atmosphere .ips patches from {IPS_PATCHES_FILE}...")

    with open(IPS_PATCHES_FILE, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    created_count = 0

    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        if line.endswith(','):
            line = line[:-1]

        try:
            entry = ast.literal_eval(line)
            if len(entry) != 4:
                print(f"Warning: NSO line {line_num}: Expected 4 items, got {len(entry)}. Skipping.")
                continue

            moduleid = entry[1].strip()
            ipspath = entry[2].strip()
            patch_hex = entry[3].strip()

            if not ipspath.endswith('/') or ipspath not in REQUIRED_DIRS:
                print(f"Warning: NSO line {line_num}: Invalid path '{ipspath}'. Skipping.")
                continue

            filename = os.path.join(ipspath, f"{moduleid}.ips")
            patch_bytes = bytes.fromhex(patch_hex)

            with open(filename, 'wb') as ips_file:
                ips_file.write(patch_bytes)

            created_count += 1
            print(f"   Created: {filename} ({len(patch_bytes)} bytes)")

        except Exception as e:
            print(f"Error: NSO line {line_num}: {e}")
            continue

    print(f"   → Created {created_count} Atmosphere .ips patches")
    return created_count

def generate_hekate_patches_ini():
    """Generate patches/bootloader/patches.ini from fs_kip_patches.txt and ldr_kip_patches.txt."""
    if not os.path.exists(FS_KIP_FILE) and not os.path.exists(LDR_KIP_FILE):
        print("Warning: Neither fs_kip_patches.txt nor ldr_kip_patches.txt found — skipping patches.ini generation.")
        return

    print(f"\nGenerating Hekate {PATCHES_INI}...")

    with open(PATCHES_INI, 'w', encoding='utf-8') as out_file:
        out_file.write(HEADER)

        total_sections = 0

        # --- FS KIP patches ---
        if os.path.exists(FS_KIP_FILE):
            print(f"   Processing {FS_KIP_FILE}...")
            with open(FS_KIP_FILE, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            fs_count = 0
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line:
                    continue
                if line.endswith(','):
                    line = line[:-1]

                try:
                    entry = ast.literal_eval(line)
                    if len(entry) != 5:
                        print(f"Warning: FS line {line_num}: Expected 5-tuple, got {len(entry)}. Skipping.")
                        continue

                    fw_version = entry[0]
                    title_block = entry[1].strip()
                    patch_block = entry[2].strip()
                    fs_type = entry[3]
                    sdk_version = entry[4]

                    out_file.write(f'#FS {fw_version}-{fs_type} - SDKVersion:{sdk_version}\n')
                    out_file.write(f"{title_block}\n")
                    out_file.write(f"{patch_block}\n")
                    out_file.write('\n')  # ← This adds the blank line between sections
                    fs_count += 1

                except Exception as e:
                    print(f"Error: FS line {line_num}: {e}")
                    continue

            total_sections += fs_count
            print(f"      Added {fs_count} FS sections")

        # --- Loader KIP patches ---
        if os.path.exists(LDR_KIP_FILE):
            print(f"   Processing {LDR_KIP_FILE}...")
            with open(LDR_KIP_FILE, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            ldr_count = 0
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line:
                    continue
                if line.endswith(','):
                    line = line[:-1]

                try:
                    entry = ast.literal_eval(line)
                    if len(entry) < 4:
                        print(f"Warning: Loader line {line_num}: Too few elements. Skipping.")
                        continue

                    patch_block = entry[1].strip()
                    ams_version = entry[-1]

                    out_file.write(f'#loader {ams_version}\n')
                    out_file.write(f"{patch_block}\n")
                    out_file.write('\n')  # ← This adds the blank line between loader sections too
                    ldr_count += 1

                except Exception as e:
                    print(f"Error: Loader line {line_num}: {e}")
                    continue

            total_sections += ldr_count
            print(f"      Added {ldr_count} Loader sections")

    print(f"\nDone! Generated {PATCHES_INI} with {total_sections} patch sections and blank lines between entries.")

def main():
    create_directories()
    old_zips = glob.glob("Hekate+AMS-package3-sigpatches-*.zip")
    if old_zips:
        print(f"Removing {len(old_zips)} old archive(s)...")
        for old_zip in old_zips:
            try:
                os.remove(old_zip)
                print(f"   [DEL] {old_zip}")
            except Exception as e:
                print(f"   [ERR] Failed to delete {old_zip}: {e}")
    else:
        print("No old sigpatch archives found.")

    ips_count = process_atmosphere_ips()
    generate_hekate_patches_ini()

    current_atmosphere_version = "unknown"
    if os.path.exists(LDR_KIP_FILE):
        try:
            with open(LDR_KIP_FILE, 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f.readlines() if line.strip() and line.strip().endswith(',')]
                if lines:
                    last_line = lines[-1]
                    if last_line.endswith(','):
                        last_line = last_line[:-1]
                    last_entry = ast.literal_eval(last_line)
                    ams_string = last_entry[-1]  # Last element is the full Atmosphere string

                    import re
                    match = re.match(r'Atmosphere-(\d+\.\d+\.\d+)(-prerelease|-master)?', ams_string)
                    if match:
                        version = match.group(1)
                        tag = match.group(2) or ''
                        current_atmosphere_version = version + ('p' if '-prerelease' in tag else '')
                    else:
                        print(f"Warning: Could not parse Atmosphere version from: {ams_string}")
                else:
                    print("Warning: ldr_kip_patches.txt is empty — using fallback Atmosphere version.")
        except Exception as e:
            print(f"Error reading/parsing ldr_kip_patches.txt for Atmosphere version: {e}")
    else:
        print("Warning: ldr_kip_patches.txt not found — using fallback Atmosphere version.")

    highest_firmware_version = "unknown"
    if os.path.exists(LDR_KIP_FILE):
        try:
            with open(LDR_KIP_FILE, 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f.readlines() if line.strip() and line.strip().endswith(',')]
                if lines:
                    last_line = lines[-1]
                    if last_line.endswith(','):
                        last_line = last_line[:-1]
                    last_entry = ast.literal_eval(last_line)
                    highest_firmware_version = last_entry[0]
                    print(f"Detected highest supported firmware: {highest_firmware_version} (from latest Loader patch)")
                else:
                    print("Warning: ldr_kip_patches.txt is empty — using fallback firmware version.")
        except Exception as e:
            print(f"Error reading/parsing ldr_kip_patches.txt for firmware version: {e}")
    else:
        print("Warning: ldr_kip_patches.txt not found — using fallback firmware version.")

    # --- Create final zip archive ---
    archive_string = f"Hekate+AMS-package3-sigpatches-{current_atmosphere_version}-cfw-{highest_firmware_version}"
    try:
        shutil.make_archive(archive_string, 'zip', 'patches')
        print(f"\nCreated archive: {archive_string}.zip")
    except Exception as e:
        print(f"\nError creating archive: {e}")

    print("\nAll tasks completed successfully!")

if __name__ == "__main__":
    main()