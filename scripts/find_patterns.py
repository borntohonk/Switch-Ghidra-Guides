#!/usr/bin/env python

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

import re
import hashlib
import os
import ast
import binascii
import sys
import shutil
import errno
from urllib.request import Request, urlopen
import argparse
from typing import Tuple, List, Dict, Optional
from dataclasses import dataclass

import package3_and_stratosphere

try:
    from capstone import *
    from capstone.arm64 import *

except ModuleNotFoundError:
    print('Please install capstone first!')
    sys.exit(1)

parser = argparse.ArgumentParser()

parser.add_argument(
    '--ams',
    action='store_true',
)

args = parser.parse_args()


def convert_sys_patch_nibble_string(input_string):
    if not isinstance(input_string, str):
        raise TypeError("Input must be a string")

    modified_string = input_string.replace('?', '.')
    return modified_string

# Pattern dataclass for struct-like organization
@dataclass
class Pattern:
    name: str
    pattern_string: str
    offset: int
    headoffset: int
    module_name: str
    conditions: Tuple[str, ...]
    patch_bytes: str
    min_version: str
    max_version: str
    patch_type: Optional[str] = None
    patch_size: Optional[str] = None

def mkdirp(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def remove_duplicates_by_index(list_of_tuples, index_to_check):
    seen_values = set()
    unique_list = []
    for current_tuple in list_of_tuples:
        value_to_check = current_tuple[index_to_check]

        if value_to_check not in seen_values:
            unique_list.append(current_tuple)
            seen_values.add(value_to_check)
            
    return unique_list


def load_existing_pattern_diffs(filepath: str) -> Dict[str, Dict[str, str]]:
    """
    Loads pattern_diffs.py and converts lists of tuples back to dicts for merging.
    Returns the same internal structure as before (dict of dicts).
    """
    existing = {
        'es_pattern_diffs': {},
        'blankcal0crashfix_pattern_diffs': {},
        'blockfirmwareupdates_pattern_diffs': {},
        'nifm_pattern_diffs': {},
        'olsc_pattern_diffs': {},
        'fat32_noncasigchk_pattern_diffs': {},
        'exfat_noncasigchk_pattern_diffs': {},
        'fat32_noacidsigchk1_pattern_diffs': {},
        'exfat_noacidsigchk1_pattern_diffs': {},
        'fat32_noacidsigchk2_pattern_diffs': {},
        'exfat_noacidsigchk2_pattern_diffs': {},
        'fat32_nocntchk_pattern_diffs': {},
        'exfat_nocntchk_pattern_diffs': {},
        'loader_pattern_diffs': {},
        'erpt_pattern_diffs': {},
    }

    if not os.path.exists(filepath):
        return existing

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        local_ns = {}
        exec(content, {"__builtins__": {}}, local_ns)  # safe-ish exec

        for key in existing:
            value = local_ns.get(key)
            if isinstance(value, dict):
                # old format → keep as is
                existing[key] = value
            elif isinstance(value, list):
                # new format → convert list[tuple] → dict
                existing[key] = {ver: bytes_val for ver, bytes_val in value}
            # else: ignore silently or log

    except Exception as e:
        print(f"Warning: Could not parse {filepath}: {e}")
        print("   → Starting with empty diffs.")

    return existing

# Helper to load existing patch txt files
def load_existing_patches(filepath: str) -> List[Tuple]:
    patches = []
    if not os.path.exists(filepath):
        return patches
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.endswith(','):
                    line = line[:-1]
                if line:
                    patches.append(ast.literal_eval(line))
    except Exception as e:
        print(f"Warning: Could not parse existing {filepath}: {e}")
        patches = []
    return patches


def update_patch_file(filepath: str, current_db: List[Tuple], unique_index: int = 1):
    existing = load_existing_patches(filepath)
    seen = {item[unique_index] for item in existing}
    new_entries = [item for item in current_db if item[unique_index] not in seen]
    
    if not new_entries:
        print(f"No new entries for {filepath} — unchanged.")
        return False

    combined = existing + new_entries
    # Remove duplicates again just in case
    combined = remove_duplicates_by_index(combined, unique_index)
    # Sort by version (index 0)
    combined.sort(key=lambda x: version_to_tuple(x[0]))

    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            for entry in combined:
                f.write(f"{entry},\n")
        print(f"Appended {len(new_entries)} new entries to {filepath}")
        return True
    except Exception as e:
        print(f"Error writing {filepath}: {e}")
        return False

def version_to_tuple(version_string):
    parts = version_string.split('-')[0].split('.')
    return tuple(int(p) for p in parts)

def MAKEHOSVERSION(lowest_firmware, highest_firmware, current_firmware):
    target_low_version_tuple = version_to_tuple(lowest_firmware)
    target_high_version_tuple = version_to_tuple(highest_firmware)
    current_version_tuple = version_to_tuple(current_firmware)

    if current_version_tuple >= target_low_version_tuple and current_version_tuple <= target_high_version_tuple:
        return True
    else:
        return False

def print_patch_summary(patch_summary_file_path):
    try:
        with open(patch_summary_file_path, 'r') as file:
            file_content = file.read()
            print(file_content)
    except FileNotFoundError:
        print(f"Error: The file '{patch_summary_file_path}' was not found.")
    except Exception as e:
        print(f"An error occurred in loading the patch_summary: {e}")


# sys-patch logic explanation:
# "(49, 0,) +49" (nifm/ctest) from start from the start the string found in it's entirity, as sys-patch tests things stupid, then it reads from 0x0 of the end in decimals where the "head" was placed (49),
# and the 4th byte from there is what is tested (for most cond checks), the next number determines where from the tested byte is being patched. (should be 0, otherwise its not testing the bytes being patched!)
# should be noted ams loader patch being (6,2) is different from this general rule of not testing for what is being patched.
# as it finds searches for "009401C0BE12(6)1F00(2)", testing 4 bytes from from offset (6) for cmp_cond byte of "6B",
# and then applies the patch of "00", two bytes offset after the testing point (0)1F00(2), turning (6)1F00(2)->01<-6B - cmp w0, w1 -  into (6)1F00(2)->00<-6B - cmp w0, w0

patch_magic = "5041544348" # "PATCH"
ips32_magic = "4950533332" # "IPS32"
eof_magic = "454F46" # "EOF"
eeof_magic = "45454F46" # "EEOF"

cmp_patch = b"\x00"
nop_patch = b"\x1F\x20\x03\xD5" # FS (nop)
ret0_patch = b"\xE0\x03\x1F\x2A" # FS (mov w0, wzr)
mov0_patch = b"\xE0\x03\x1F\xAA" # ES
mov2_patch = b"\xE2\x03\x1F\xAA" # NIM
ret1_patch = b"\x20\x00\x80\xD2" # OLSC
mov0_ret_patch = b"\xE0\x03\x1F\x2A\xC0\x03\x5F\xD6" # NIM
ctest_patch = b"\x00\x30\x9A\xD2\x00\x1E\xA1\xF2\x61\x01\x00\xD4\xE0\x03\x1F\xAA\xC0\x03\x5F\xD6" # NIFM (mov x0, #0xd180 - movk x0, #0x8f0, lsl #16 - svc #0xb - mov x0, xzr - ret)

patch_size_1 = '0001'
patch_size_4 = '0004'
patch_size_8 = '0008'
patch_size_20 = '0014'

es_cond = ('D1', 'A9', 'AA', '2A', '92')
block_fw_updates_cond = ('A8', 'A9', 'F8', 'F9', 'D6')
ctest_cond = ('F8', 'F9', 'A9')
adr_cond = ('10',)
bl_cond = ('25', '94', '97')
tbz_cond = ('36',)
cmp_cond = ('6B', 'F1',)
sub_cond = ('D1',)

# FW_VER_ANY constant for version ranges
FW_VER_ANY = '99.99.99'


# Define pattern arrays for each module type
ES_PATTERNS = [
    Pattern('es_1.0.0-8.1.1',               '0091....0094..7E4092', 10, 0, 'ES', es_cond, mov0_patch, '1.0.0', '8.1.1'),
    Pattern('es_9.0.0-11.0.1',              '00..........A0....D1....FF97', 14, 0, 'ES', es_cond, mov0_patch, '9.0.0', '11.0.1'),
    Pattern('es_12.0.0-18.1.0',             '02........D2..52....0091', 32, 0, 'ES', es_cond, mov0_patch, '12.0.0', '18.1.0'),
    Pattern('es_19.0.0+',                   'A1........031F2A....0091', 32, 0, 'ES', es_cond, mov0_patch, '19.0.0', FW_VER_ANY),
]


NIFM_PATTERNS = [
    Pattern('nifm_1.0.0-19.0.1',            '03..AAE003..AA......39....04F8........E0', -29, 0, 'NIFM', ctest_cond, ctest_patch, '1.0.0', '19.0.1'),
    Pattern('nifm_20.0.0+',                 '03..AA......AA..................0314AA....14AA', -17, 0, 'NIFM', ctest_cond, ctest_patch, '20.0.0', FW_VER_ANY),
]


OLSC_PATTERNS = [
    Pattern('olsc_6.0.0-14.1.2',            '00..73....F9....4039', 42, 0, 'OLSC', bl_cond, ret1_patch, '6.0.0', '14.1.2'),
    Pattern('olsc_15.0.0-18.1.0',           '00..73....F9....4039', 38, 0, 'OLSC', bl_cond, ret1_patch, '15.0.0', '18.1.0'),
    Pattern('olsc_19.0.0+',                 '00..73....F9....4039', 42, 0, 'OLSC', bl_cond, ret1_patch, '19.0.0', FW_VER_ANY),
]

NIM_PATTERNS = [
    Pattern('nim_blankcal0_17.0.0+',        '03D5..............................97....0094....00..........61', 2, 0, 'NIM', adr_cond, mov2_patch, '17.0.0', FW_VER_ANY),
    Pattern('nim_blockfw_1.0.0-5.1.0',      '1139F3', -30, 0, 'NIM', block_fw_updates_cond, mov0_ret_patch, '1.0.0', '5.1.0'),
    Pattern('nim_blockfw_6.0.0-6.2.0',      'F30301AA..4E', -40, 0, 'NIM', block_fw_updates_cond, mov0_ret_patch, '6.0.0', '6.2.0'),
    Pattern('nim_blockfw_7.0.0-10.2.0',     'F30301AA014C', -36, 0, 'NIM', block_fw_updates_cond, mov0_ret_patch, '7.0.0', '10.2.0'),
    Pattern('nim_blockfw_11.0.0-11.0.1',    '9AF0....................C0035FD6', 16, 0, 'NIM', block_fw_updates_cond, mov0_ret_patch, '11.0.0', '11.0.1'),
    Pattern('nim_blockfw_12.0.0+',          '41....4C............C0035FD6', 14, 0, 'NIM', block_fw_updates_cond, mov0_ret_patch, '12.0.0', FW_VER_ANY),
    
]

FS_PATTERNS = [
    Pattern('fs_noacidsigchk1_1.0.0-9.2.0', 'C8FE4739', -24, 0, 'FS', bl_cond, ret0_patch, '1.0.0', '9.2.0'),
    Pattern('fs_noacidsigchk2_1.0.0-9.2.0', '0210911F000072', -5, 0, 'FS', bl_cond, ret0_patch, '1.0.0', '9.2.0'),
    Pattern('fs_noncasigchk_1.0.0-3.0.2',   '88..42..58', -4, 0, 'FS', tbz_cond, nop_patch, '1.0.0', '3.0.2'),
    Pattern('fs_noncasigchk_4.0.0-16.1.0',  '1E4839....00......0054', -17, 0, 'FS', tbz_cond, nop_patch, '4.0.0', '16.1.0'),
    Pattern('fs_noncasigchk_17.0.0+',       '0694....00..42..0091', -18, 0, 'FS', tbz_cond, nop_patch, '17.0.0', FW_VER_ANY),
    Pattern('fs_nocntchk_1.0.0-18.1.0',     '40F9........081C00121F05', 2, 0, 'FS', bl_cond, ret0_patch, '1.0.0', '18.1.0'),
    Pattern('fs_nocntchk_19.0.0+',          '40F9............40B9091C', 2, 0, 'FS', bl_cond, ret0_patch, '19.0.0', FW_VER_ANY),
]


LOADER_PATTERNS = [
    Pattern('noacidsigchk_10.0.0+',         '009401C0BE121F00', 6, 2, 'LOADER', cmp_cond, cmp_patch, '10.0.0', FW_VER_ANY), 
]


ERPT_PATTERNS = [
    Pattern('no_erpt',                      'FD7B02A9FD830091F76305A9', -4, 0, 'ERPT', sub_cond, mov0_ret_patch, '10.0.0', FW_VER_ANY), 
]


def get_module_id(nso0):
    with open(nso0, 'rb') as f:
        f.seek(0x40)
        return binascii.hexlify(f.read(0x14)).decode('utf-8').upper()


def is_valid_version_format(version_str: str) -> bool:
    """Check if version string matches semantic versioning pattern X.Y.Z"""
    try:
        parts = version_str.split('.')
        if len(parts) < 2 or len(parts) > 3:
            return False
        for part in parts:
            if not part.isdigit():
                return False
        return True
    except Exception:
        return False


def get_valid_version_folders(output_dir: str = 'output') -> List[str]:
    """Get all valid version folders from output directory"""
    valid_versions = []

    if not os.path.isdir(output_dir):
        print(f"Error: Output directory '{output_dir}' not found.")
        sys.exit(1)

    try:
        entries = os.listdir(output_dir)
    except Exception as e:
        print(f"Error: Failed to read directory '{output_dir}': {e}")
        sys.exit(1)

    for entry in entries:
        folder_path = os.path.join(output_dir, entry)
        if os.path.isdir(folder_path) and is_valid_version_format(entry):
            valid_versions.append(entry)

    if not valid_versions:
        print(f"Error: No folders matching version format (X.Y.Z) found in '{output_dir}'.")

    valid_versions.sort(key=version_to_tuple)
    return valid_versions


def hex_string_to_python_bytes(hex_str: str) -> str:
    """Convert hex string to Python byte string representation"""
    hex_str = hex_str.strip()
    byte_list = [f"\\x{hex_str[i:i+2].lower()}" for i in range(0, len(hex_str), 2)]
    return "b'" + "".join(byte_list) + "'"


def patch_check_module(path, pattern, pattern_offset, pattern_head_offset, ghidra_pattern, patch_type, patch_size, conds, module_name, changelog, diffs, patch_offsets, fw_patch, ips_db):
    with open(path, 'rb') as decompressed_module:
        find_patterns = changelog
        read_data = decompressed_module.read()
        hex_data = read_data.hex().upper()
        result = re.search(pattern, hex_data)
        patch_type_hex = patch_type.hex().upper()
        module_id = get_module_id(path)
        all_matches = [*re.finditer(pattern, hex_data)]
        match_count = len(all_matches)
        if match_count > 1:
            print(f'DEBUG - ({module_name}) - {version} - ELIMINATE DUPLICATES BY DIFFING AGAINST THE PATTERN')
            for match in all_matches:
                offset = '%06X' % (match.start() + pattern_offset)
                print(f'DEBUG - ({module_name}) - {version} - found - {match.group()}')
                print(f'DEBUG - ({module_name}) - {version} - offset found at {offset}')
        elif match_count == 0:
            print(f'DEBUG - ({module_name}) - NO RESULTS FOUND AT ALL - {version}')
        if not result:
            find_patterns.write(f'({module_name}) {version} {module_name} offset not found\n')
            find_patterns.write(f'({module_name}) Sys-patch for {module_name} string is invalid for: {version}\n\n')
        else:
            module_offset = int(result.start() / 2) + pattern_offset
            offset = '%06X' % (module_offset)
            patch_bytes_start = module_offset
            patch_bytes_end = patch_bytes_start + 0x4
            patch_bytes = read_data[patch_bytes_start:patch_bytes_end]
            patch_bytes_hex = patch_bytes.hex().upper()
            patch_byte = patch_bytes_hex[-2:]
            pattern_diff_string_start = module_offset - 0x20
            pattern_diff_string_end = pattern_diff_string_start + 0x60
            ARM_CODE = read_data[pattern_diff_string_start:pattern_diff_string_end]
            pattern_diff_string = ARM_CODE.hex().upper()
            diffs[version] = pattern_diff_string
            if module_name == "NIM-FW":
                patch_fw = '%06X%s%s' % ((module_offset + pattern_head_offset), patch_size, patch_type_hex)
            if module_name == "NIM" and version_to_tuple(version) >= version_to_tuple("17.0.0"):
                patch_blank = '%06X%s%s' % ((module_offset + pattern_head_offset), patch_size, patch_type_hex)
                patch = fw_patch + patch_blank
            else:
                patch = '%06X%s%s' % ((module_offset + pattern_head_offset), patch_size, patch_type_hex)
            patch_offset_string = (module_name, patch_bytes_hex, offset, module_id)
            patch_offsets[version] = patch_offset_string
            if patch_byte in conds:
                find_patterns.write(f'({module_name}) an arm instruction with ending of 0x{patch_byte} was found at the designated offset.\n')
                find_patterns.write(f'({module_name}) Sys-patch for {module_name} string still valid for: {version}\n')
                find_patterns.write(f'({module_name}) Sys-patch {module_name} pattern found at: {offset}\n')
                find_patterns.write(f'({module_name}) The ghidra-equivalent pattern used was: {ghidra_pattern}\n')
                find_patterns.write(f'({module_name}) The existing bytes at the offset are: {patch_bytes_hex}\n\n')
                md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
                for i in md.disasm(patch_bytes, module_offset):
                    find_patterns.write('from: 0x%X: (%s) %s %s\n' %(i.address, i.bytes.hex().upper(), i.mnemonic, i.op_str))
                for i in md.disasm(patch_type, module_offset):
                    find_patterns.write('to:   0x%X: (%s) %s %s\n' %(i.address, i.bytes.hex().upper(), i.mnemonic, i.op_str))
                if module_name == "NIM-FW" and version_to_tuple(version) >= version_to_tuple("17.0.0"):
                    find_patterns.write(f'\n\n({module_name}) See NIM for the correct .ips file combining both patches for NIM:\n\n')
                else:
                    find_patterns.write(f'\n\n({module_name}) {version} {module_name} moduleid (and what .ips filename should be): {module_id}\n\n')
                    find_patterns.write(f'({module_name}) IPS patch bytes would be:\n')
                    find_patterns.write(f'({module_name}) {patch_magic}{patch}{eof_magic}\n\n')
                    find_patterns.write(f'({module_name}) pattern string for diff: \n \n{pattern_diff_string}\n\n')

                if module_name == "NIM-FW":
                    return patch_fw

                if module_name == "NIM-FW":
                    module_name = "NIM_CTEST"
                if module_name == "NIM":
                    module_name = "NIM_CTEST"
                if module_name == "NIFM":
                    module_name = "NFIM_CTEST"
                if module_name == "ES":
                    module_name = "ES_PATCHES"
                if module_name == "OLSC":
                    module_name = "OLSC_PATCHES"
                if module_name == "ERPT":
                    module_name = "ERPT_PATCHES"
                patch_path = "patches/atmosphere/exefs_patches/" + module_name.lower() + "/"
                patch_string_with_magic = (patch_magic + patch + eof_magic)
                ips_db_string = (version, module_id, patch_path, patch_string_with_magic)
                ips_db.append(ips_db_string)

                find_patterns.write(f'\n\n{module_name} arm instructions in order from pattern diff string above (offset: 0x{offset} is what is being patched):\n\n')
                md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
                instruction_order = []
                for i in md.disasm(ARM_CODE, module_offset - 0x20):
                    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
                    instruction_order.append(i.mnemonic)
                    if i.address == module_offset:
                        find_patterns.write(f"\n0x{i.address:X}:\t{i.mnemonic}\t{i.op_str}\n\n")
                    else:
                        find_patterns.write(f"0x{i.address:X}:\t{i.mnemonic}\t{i.op_str}\n")
                find_patterns.write(f'\ninstruction order:\n')
                find_patterns.write(" ".join(instruction_order))
                find_patterns.write(f'\n\n')

            else:
                find_patterns.write(f'({module_name}) the arm instruction was either not found after the pattern, or is ends differently. Must be checked. Assume it is broken.\n\n')
                print(f'DEBUG - ({module_name}) {version} - PBS: {patch_bytes_hex} - PB: {patch_byte} - OFS: {offset}')

def patch_check_loader(path, pattern, pattern_offset, pattern_head_offset, ghidra_pattern, conds, module_name, changelog, diffs, patch_offsets, hash, patch_db, loader_ams_string, ips_db):
    with open(path, 'rb') as decompressed_module:
        cmp_patch_hex = cmp_patch.hex().upper()
        find_patterns = changelog
        read_data = decompressed_module.read()
        hex_data = read_data.hex().upper()
        result = re.search(pattern, hex_data)
        all_matches = [*re.finditer(pattern, hex_data)]
        match_count = len(all_matches)
        if match_count > 1:
            print(f'DEBUG - ({module_name}) - {version} - ELIMINATE DUPLICATES BY DIFFING AGAINST THE PATTERN')
            for match in all_matches:
                offset = '%06X' % (match.start() + pattern_offset)
                print(f'DEBUG - ({module_name}) - {version} - found - {match.group()}')
                print(f'DEBUG - ({module_name}) - {version} - offset found at {offset}')
        elif match_count == 0:
            print(f'DEBUG - ({module_name}) - NO RESULTS FOUND AT ALL - {version}')
        if not result:
            find_patterns.write(f'({module_name}) {version} {module_name} offset not found\n')
            find_patterns.write(f'({module_name}) Sys-patch for {module_name} string is invalid for: {version}\n\n')
        else:
            module_offset = int(result.start() / 2) + pattern_offset
            offset = '%06X' % (module_offset)
            patch_bytes_start = module_offset
            patch_bytes_end = patch_bytes_start + 0x4
            patch_bytes = read_data[patch_bytes_start:patch_bytes_end]
            patch_bytes_hex = patch_bytes.hex().upper()
            patch_byte = patch_bytes[-2:]
            pattern_diff_string_start = module_offset - 0x20
            pattern_diff_string_end = pattern_diff_string_start + 0x60
            ARM_CODE = read_data[pattern_diff_string_start:pattern_diff_string_end]
            pattern_diff_string = ARM_CODE.hex().upper()
            diffs[version] = pattern_diff_string
            head_offset = '%06X' % (module_offset + pattern_head_offset - 0x100)
            if patch_byte in conds:
                find_patterns.write(f'({module_name}) an arm instruction with ending of 0x{patch_byte} was found at the designated offset.\n')
                find_patterns.write(f'({module_name}) Sys-patch for {module_name} string still valid for: {version}\n')
                find_patterns.write(f'({module_name}) Sys-patch {module_name} pattern found at: {offset}\n')
                find_patterns.write(f'({module_name}) The ghidra-equivalent pattern used was: {ghidra_pattern}\n')
                find_patterns.write(f'({module_name}) The existing bytes at the offset are: {patch_bytes_hex}\n\n')
                
                md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
                for i in md.disasm(patch_bytes, module_offset):
                    find_patterns.write('from: 0x%X: (%s) %s %s\n' %(i.address, i.bytes.hex().upper(), i.mnemonic, i.op_str))
                for i in md.disasm(cmp_patch, module_offset):
                    find_patterns.write('to:   0x%X: (%s) %s %s\n' %(i.address, i.bytes.hex().upper(), i.mnemonic, i.op_str))

                find_patterns.write(f'\n\nLOADER FULL HASH: {hash}\n\n')
                find_patterns.write(f'[Loader:{hash[:16]}]\n')
                find_patterns.write(f'.nosigchk=0:0x{head_offset}:0x1:01,00\n')

                instruction_order = []
                md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
                instruction_order = []
                find_patterns.write(f'{module_name} arm instructions in order from pattern diff string (offset: 0x{offset} is what is being patched):\n\n')
                for i in md.disasm(ARM_CODE, module_offset - 0x20):
                    instruction_order.append(i.mnemonic)
                    if i.address == module_offset:
                        find_patterns.write(f"\n0x{i.address:X}:\t{i.mnemonic}\t{i.op_str}\n\n")
                    else:
                        find_patterns.write(f"0x{i.address:X}:\t{i.mnemonic}\t{i.op_str}\n")
                find_patterns.write(f'\ninstruction order:\n')
                find_patterns.write(" ".join(instruction_order))
                find_patterns.write(f'\n\n')

                patch_db_string = (version, f'[Loader:{hash[:16]}]\n.nosigchk=0:0x{head_offset}:0x1:01,00\n\n', "LOADER", loader_ams_string)
                patch_db.append(patch_db_string)
                patch_path = "patches/atmosphere/kip_patches/loader_patches/"
                patch = '%06X%s%s' % ((module_offset + pattern_head_offset), patch_size_1, cmp_patch_hex)
                patch_string_with_magic = (patch_magic + patch + eof_magic)
                ips_db_string = (version, hash, patch_path, patch_string_with_magic)
                ips_db.append(ips_db_string)
            else:
                find_patterns.write(f'({module_name}) the arm instruction was either not found after the pattern, or is ends differently. Must be checked. Assume it is broken.\n\n')
                print(f'DEBUG - ({module_name}) {version} - PBS: {patch_bytes_hex} - PB: {patch_byte} - OFS: {offset}')


def patch_check_fs(path, hash, noncasigchk_pattern, nocntchk_pattern, noacidsigchk1_pattern, noacidsigchk2_pattern, noncasigchk_offset, nocntchk_offset, noacidsigchk1_offset, noacidsigchk2_offset,  noncasigchk_ghidra_pattern, nocntchk_ghidra_pattern, noacidsigchk1_ghidra_pattern, noacidsigchk2_ghidra_pattern, noncasigchk_patch, nocntchk_patch, noacidsigchk1_patch, noacidsigchk2_patch, noncasigchk_cond, nocntchk_cond, noacidsigchk1_cond, noacidsigchk2_cond, noncasigchk_diffs, nocntchk_diffs, noacidsigchk1_diffs, noacidsigchk2_diffs, nonsigchk_offsets, nocntchk_offsets, noacidsigchk1_offsets, noacidsigchk2_offsets, kip_patch_db, ips_db, module_name, changelog):
    with open(path, 'rb') as decompressed_module:
        find_patterns = changelog
        read_data = decompressed_module.read()
        hex_data = read_data.hex().upper()
        result_1 = re.search(noncasigchk_pattern, hex_data)
        result_2 = re.search(nocntchk_pattern, hex_data)
        all_matches_1 =[*re.finditer(noncasigchk_pattern, hex_data)]
        all_matches_2 =[*re.finditer(nocntchk_pattern, hex_data)]
        nocntchk_patch_hex = nocntchk_patch.hex().upper()
        noncasigchk_patch_hex = noncasigchk_patch.hex().upper()
        noacidsigchk1_patch_hex = noacidsigchk1_patch.hex().upper()
        noacidsigchk2_patch_hex = noacidsigchk2_patch.hex().upper()
        match_count_1 = len(all_matches_1)
        match_count_2 = len(all_matches_2)
        if match_count_1 > 1:
            print(f'DEBUG - ({module_name}) - NONCASIGCHK - {version} - ELIMINATE DUPLICATES BY DIFFING AGAINST THE PATTERN')
            for match in all_matches_1:
                offset_1 = '%06X' % (match.start() + noncasigchk_offset)
                print(f'DEBUG - (FS-{module_name}) - NONCASIGCHK - {version} - found - {match.group()}')
                print(f'DEBUG - (FS-{module_name}) - NONCASIGCHK - {version} - offset found at {offset_1}')
        elif match_count_1 == 0:
            print(f'DEBUG - (FS-{module_name}) - NO RESULTS FOUND AT ALL - NONCASIGCHK - {version}')

        if match_count_2 > 1:
            print(f'DEBUG - (FS-{module_name}) - NOCNTCHK - {version} - ELIMINATE DUPLICATES BY DIFFING AGAINST THE PATTERN')
            for match in all_matches_2:
                offset_2 = '%06X' % (match.start() + nocntchk_offset)
                print(f'DEBUG - (FS-{module_name}) - NOCNTCHK - {version} - found - {match.group()}')
                print(f'DEBUG - (FS-{module_name}) - NOCNTCHK - {version} - offset found at {offset_2}')
        elif match_count_2 == 0:
            print(f'DEBUG - (FS-{module_name}) - NO RESULTS FOUND AT ALL - NOCNTCHK - {version}')
        if not result_1:
            find_patterns.write(f'(FS-{module_name}) {version} First FS-{module_name} offset not found\n')
            find_patterns.write(f'(FS-{module_name}) Sys-patch for FS-{module_name} NONCASIGCHK string is invalid for: {version}\n\n')
        elif not result_2:
            find_patterns.write(f'(FS-{module_name}) {version} Second FS-{module_name} offset not found\n')
            find_patterns.write(f'(FS-{module_name}) Sys-patch for FS-{module_name} NOCNTCHK string is invalid for: {version}\n\n')
        else:
            module_offset_1 = int(result_1.start() / 2) + noncasigchk_offset
            module_offset_2 = int(result_2.start() / 2) + nocntchk_offset
            hekate_offset_1 = module_offset_1 - 0x100
            hekate_offset_2 = module_offset_2 - 0x100
            offset_1 = '%06X' % (module_offset_1)
            offset_2 = '%06X' % (module_offset_2)
            hekate_adjusted_offset_1 = '%06X' % (hekate_offset_1)
            hekate_adjusted_offset_2 = '%06X' % (hekate_offset_2)
            patch_bytes_start_1 = module_offset_1
            patch_bytes_end_1 = patch_bytes_start_1 + 0x4
            patch_bytes_1 = read_data[patch_bytes_start_1:patch_bytes_end_1]
            patch_bytes_start_2 = module_offset_2
            patch_bytes_end_2 = patch_bytes_start_2 + 0x4
            patch_bytes_2 = read_data[patch_bytes_start_2:patch_bytes_end_2]
            patch_1_byte = patch_bytes_1[-1:].hex().upper()
            patch_2_byte = patch_bytes_2[-1:].hex().upper()
            patch_1_bytes = patch_bytes_1.hex().upper()
            patch_2_bytes = patch_bytes_2.hex().upper()
            pattern_diff_string_start_1 = module_offset_1 - 0x20
            pattern_diff_string_end_1 = pattern_diff_string_start_1 + 0x60
            ARM_CODE_1 = read_data[pattern_diff_string_start_1:pattern_diff_string_end_1]
            pattern_diff_string_1 = ARM_CODE_1.hex().upper()
            pattern_diff_string_start_2 = module_offset_2 - 0x20
            pattern_diff_string_end_2 = pattern_diff_string_start_2 + 0x60
            ARM_CODE_2 = read_data[pattern_diff_string_start_2:pattern_diff_string_end_2]
            pattern_diff_string_2 = ARM_CODE_2.hex().upper()
            noncasigchk_diffs[version] = pattern_diff_string_1
            nocntchk_diffs[version] = pattern_diff_string_2
            nonsigchk_offset_string = [module_name, patch_1_bytes, offset_1, hash]
            nocntchk_offset_string = [module_name, patch_2_bytes, offset_2, hash]
            nonsigchk_offsets[version] = nonsigchk_offset_string
            nocntchk_offsets[version] = nocntchk_offset_string

            if version_to_tuple(version) <= version_to_tuple("9.99.9"):
                result_3 = re.search(noacidsigchk1_pattern, hex_data) # these don't need validation
                result_4 = re.search(noacidsigchk2_pattern, hex_data) # these don't need validation
                module_offset_3 = int(result_3.start() / 2) + noacidsigchk1_offset
                module_offset_4 = int(result_4.start() / 2) + noacidsigchk2_offset
                hekate_offset_3 = module_offset_3 - 0x100
                hekate_offset_4 = module_offset_4 - 0x100
                offset_3 = '%06X' % (module_offset_3)
                offset_4 = '%06X' % (module_offset_4)
                hekate_adjusted_offset_3 = '%06X' % (hekate_offset_3)
                hekate_adjusted_offset_4 = '%06X' % (hekate_offset_4)
                patch_bytes_start_3 = module_offset_3
                patch_bytes_start_4 = module_offset_4
                patch_bytes_end_3 = patch_bytes_start_3 + 0x4
                patch_bytes_end_4 = patch_bytes_start_4 + 0x4
                patch_3_bytes = read_data[patch_bytes_start_3:patch_bytes_end_3]
                patch_4_bytes = read_data[patch_bytes_start_4:patch_bytes_end_4]
                patch_3_bytes = patch_3_bytes.hex().upper()
                patch_4_bytes = patch_4_bytes.hex().upper()

                pattern_diff_string_start_3 = module_offset_3 - 0x20
                pattern_diff_string_end_3 = pattern_diff_string_start_3 + 0x60
                pattern_diff_string_3 = read_data[pattern_diff_string_start_3:pattern_diff_string_end_3].hex().upper()
                pattern_diff_string_start_4 = module_offset_4 - 0x20
                pattern_diff_string_end_4 = pattern_diff_string_start_4 + 0x60
                pattern_diff_string_4 = read_data[pattern_diff_string_start_4:pattern_diff_string_end_4].hex().upper()

                noacidsigchk1_diffs[version] = pattern_diff_string_3
                noacidsigchk2_diffs[version] = pattern_diff_string_4
                noacidsigchk1_offset_string = [module_name, patch_3_bytes, offset_3, hash]
                noacidsigchk2_offset_string = [module_name, patch_4_bytes, offset_4, hash]
                noacidsigchk1_offsets[version] = noacidsigchk1_offset_string
                noacidsigchk2_offsets[version] = noacidsigchk2_offset_string

            if patch_1_byte in noncasigchk_cond:
                find_patterns.write(f'(FS-{module_name}) a "TBZ" arm instruction with ending of 0x{patch_1_byte} was found\n')
                if patch_2_byte in nocntchk_cond:
                    find_patterns.write(f'(FS-{module_name}) a "BL" arm instruction with ending of 0x{patch_2_byte} was found.\n\n')
                    find_patterns.write(f'(FS-{module_name}) both sys-patch strings are valid for FS-{module_name} for: {version}\n')
                    find_patterns.write(f'(FS-{module_name}) {version} NOCASIGCHK Sys-patch FS-{module_name} pattern found at: {offset_1}\n')
                    find_patterns.write(f'(FS-{module_name}) The ghidra-equivalent pattern used was : {noncasigchk_ghidra_pattern}\n')
                    find_patterns.write(f'(FS-{module_name}) The existing bytes at the first offset are: {patch_1_bytes}\n\n')

                    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
                    for i in md.disasm(patch_bytes_1, module_offset_1):
                        find_patterns.write('from: 0x%X: (%s) %s %s\n' %(i.address, i.bytes.hex().upper(), i.mnemonic, i.op_str))
                    for i in md.disasm(noncasigchk_patch, module_offset_1):
                        find_patterns.write('to:   0x%X: (%s) %s %s\n' %(i.address, i.bytes.hex().upper(), i.mnemonic, i.op_str))

                    find_patterns.write(f'\n\n(FS-{module_name}) An arm "TBZ" condition is what is supposed to be patched\n')
                    find_patterns.write(f'(FS-{module_name}) {version} Second Sys-patch FS-FAT32 pattern found at: {offset_2}\n')
                    find_patterns.write(f'(FS-{module_name}) The ghidra-equivalent pattern used was : {nocntchk_ghidra_pattern}\n')
                    find_patterns.write(f'(FS-{module_name}) The existing bytes at the second offset are: {patch_2_bytes}\n\n')

                    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
                    for i in md.disasm(patch_bytes_2, module_offset_2):
                        find_patterns.write('from: 0x%X: (%s) %s %s\n' %(i.address, i.bytes.hex().upper(), i.mnemonic, i.op_str))
                    for i in md.disasm(nocntchk_patch, module_offset_2):
                        find_patterns.write('to:   0x%X: (%s) %s %s\n' %(i.address, i.bytes.hex().upper(), i.mnemonic, i.op_str))


                    find_patterns.write(f'\n\n(FS-{module_name}) An arm "BL" condition is what is supposed to be patched, it is found within the pattern.\n')
                    find_patterns.write(f'(FS-{module_name}) {version} FS-{module_name} SHA256 hash: {hash}\n\n')
                    find_patterns.write(f'(FS-{module_name}) a hekate string for this would be:\n\n')
                    find_patterns.write(f'#FS {version}-{module_name}\n')
                    find_patterns.write(f'[FS:{hash[:16]}]\n')
                    if version_to_tuple(version) <= version_to_tuple("9.99.9"):
                        find_patterns.write(f'.nosigchk=0:0x{hekate_adjusted_offset_3}:0x4:{patch_3_bytes},{noacidsigchk1_patch}\n')
                        find_patterns.write(f'.nosigchk=0:0x{hekate_adjusted_offset_4}:0x4:{patch_4_bytes},{noacidsigchk2_patch}\n')
                    find_patterns.write(f'.nosigchk=0:0x{hekate_adjusted_offset_1}:0x4:{patch_1_bytes},{noncasigchk_patch_hex}\n')
                    find_patterns.write(f'.nosigchk=0:0x{hekate_adjusted_offset_2}:0x4:{patch_2_bytes},{nocntchk_patch_hex}\n\n')


                    if version_to_tuple(version) <= version_to_tuple("9.99.9"):
                        patch_db_string = (version,
                                          f'[FS:{hash[:16]}]\n',
                                          f'.nosigchk=0:0x{hekate_adjusted_offset_3}:0x4:{patch_3_bytes},{noacidsigchk1_patch_hex}\n.nosigchk=0:0x{hekate_adjusted_offset_4}:0x4:{patch_4_bytes},{noacidsigchk2_patch_hex}\n.nosigchk=0:0x{hekate_adjusted_offset_1}:0x4:{patch_1_bytes},{noncasigchk_patch_hex}\n.nosigchk=0:0x{hekate_adjusted_offset_2}:0x4:{patch_2_bytes},{nocntchk_patch_hex}\n\n',
                        module_name)
                        kip_patch_db.append(patch_db_string)

                    else:
                        patch_db_string = (version,
                                        f'[FS:{hash[:16]}]\n',
                                        f'.nosigchk=0:0x{hekate_adjusted_offset_1}:0x4:{patch_1_bytes},{noncasigchk_patch_hex}\n.nosigchk=0:0x{hekate_adjusted_offset_2}:0x4:{patch_2_bytes},{nocntchk_patch_hex}\n\n',
                                        module_name)
                        kip_patch_db.append(patch_db_string)

                    patch_path = "patches/atmosphere/kip_patches/fs_patches/"

                    patch_1 = '%06X%s%s' % ((module_offset_1), patch_size_4, noncasigchk_patch_hex)
                    patch_2 = '%06X%s%s' % ((module_offset_2), patch_size_4, nocntchk_patch_hex)
                    if version_to_tuple(version) <= version_to_tuple("9.99.9"):
                        patch_3 = '%06X%s%s' % ((module_offset_3), patch_size_4, noacidsigchk1_patch_hex)
                        patch_4 = '%06X%s%s' % ((module_offset_4), patch_size_4, noacidsigchk2_patch_hex)
                        patch_string_with_magic = (patch_magic + patch_3 + patch_4 + patch_1 + patch_2 + eof_magic)     
                    else:
                        patch_string_with_magic = (patch_magic + patch_1 + patch_2 + eof_magic)
                    ips_db_string = (version, hash, patch_path, patch_string_with_magic)
                    ips_db.append(ips_db_string)

                    find_patterns.write(f'(FS-{module_name}) NONCASIGCHK string for diff: \n \n{pattern_diff_string_1}\n\n')

                    instruction_order = []
                    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
                    instruction_order = []
                    find_patterns.write(f'{module_name} arm instructions in order from pattern diff string above (NONCASIGCHK) (offset: 0x{offset_1} is what is being patched):\n\n')
                    for i in md.disasm(ARM_CODE_1, module_offset_1 - 0x20):
                        instruction_order.append(i.mnemonic)
                        if i.address == module_offset_1:
                            find_patterns.write(f"\n0x{i.address:X}:\t{i.mnemonic}\t{i.op_str}\n\n")
                        else:
                            find_patterns.write(f"0x{i.address:X}:\t{i.mnemonic}\t{i.op_str}\n")
                    find_patterns.write(f'\ninstruction order:\n')
                    find_patterns.write(" ".join(instruction_order))
                    find_patterns.write(f'\n\n')

                    find_patterns.write(f'(FS-{module_name}) NOCNTCHK string for diff: \n \n{pattern_diff_string_2}\n\n')

                    instruction_order = []
                    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
                    instruction_order = []
                    find_patterns.write(f'{module_name} arm instructions in order from pattern diff string above (NOCNTCHK) (offset: 0x{offset_2} is what is being patched):\n\n')
                    for i in md.disasm(ARM_CODE_2, module_offset_2 - 0x20):
                        instruction_order.append(i.mnemonic)
                        if i.address == module_offset_2:
                            find_patterns.write(f"\n0x{i.address:X}:\t{i.mnemonic}\t{i.op_str}\n\n")
                        else:
                            find_patterns.write(f"0x{i.address:X}:\t{i.mnemonic}\t{i.op_str}\n")
                    find_patterns.write(f'\ninstruction order:\n')
                    find_patterns.write(" ".join(instruction_order))
                    find_patterns.write(f'\n\n')

                else:
                    find_patterns.write(f'(FS-{module_name}) The second pattern doesnt match what it should match.\n\n\n')
                    print(f'DEBUG - (FS-{module_name}) {version} - PBS: {patch_2_bytes} - PB: {patch_2_byte} - OFS: {offset_2}')
            else:
                find_patterns.write(f'(FS-{module_name}) The first pattern doesnt match what it should match.\n\n\n')
                print(f'DEBUG - (FS-{module_name}) {version} - PBS: {patch_1_bytes} - PB: {patch_1_byte} - OFS: {offset_1}')
    decompressed_module.close()


fs_kip_patch_database = []
ldr_kip_patch_database = []
ips_patch_database = []

es_pattern_diffs = {}
blockfirmwareupdates_pattern_diffs = {}
blankcal0crashfix_pattern_diffs = {}
nifm_pattern_diffs = {}
olsc_pattern_diffs = {}

fat32_nocntchk_pattern_diffs = {}
exfat_nocntchk_pattern_diffs = {}
fat32_noncasigchk_pattern_diffs = {}
exfat_noncasigchk_pattern_diffs = {}

fat32_noacidsigchk1_pattern_diffs = {}
exfat_noacidsigchk1_pattern_diffs = {}
fat32_noacidsigchk2_pattern_diffs = {}
exfat_noacidsigchk2_pattern_diffs = {}

es_pattern_offsets = {}
blockfirmwareupdates_pattern_offsets = {}
blankcal0crashfix_pattern_offsets = {}
nifm_pattern_offsets = {}
olsc_pattern_offsets = {}
fat32_noncasigchk_pattern_offsets = {}
exfat_noncasigchk_pattern_offsets = {}
fat32_nocntchk_pattern_offsets = {}
exfat_nocntchk_pattern_offsets = {}

fat32_nosigchk1_pattern_offsets = {}
fat32_nosigchk2_pattern_offsets = {}

exfat_nosigchk1_pattern_offsets = {}
exfat_nosigchk2_pattern_offsets = {}

fat32_noacidsigchk1_pattern_offsets = {}
exfat_noacidsigchk1_pattern_offsets = {}
fat32_noacidsigchk2_pattern_offsets = {}
exfat_noacidsigchk2_pattern_offsets = {}

def get_pattern_for_version(patterns: List[Pattern], version: str) -> Optional[Pattern]:
    """Get the matching pattern for a given firmware version"""
    for pattern in patterns:
        if MAKEHOSVERSION(pattern.min_version, pattern.max_version, version):
            return pattern
    return None


mkdirp("output")

valid_versions = get_valid_version_folders('output')

if not valid_versions:
    print("No valid version folders found in 'output/'.")
    print("Skipping all per-version processing (pattern searching, summaries, debug logs, diffs).\n")
else:
    print(f"Found {len(valid_versions)} valid version folders: {', '.join(valid_versions)}\n")

    for version in valid_versions:
        current_firmware_version = version

        es_path = f'output/{version}/{version}_uncompressed_es.nso0'
        nim_path = f'output/{version}/{version}_uncompressed_nim.nso0'
        nifm_path = f'output/{version}/{version}_uncompressed_nifm.nso0'
        olsc_path = f'output/{version}/{version}_uncompressed_olsc.nso0'
        ssl_path = f'output/{version}/{version}_uncompressed_ssl.nso0'
        compressed_fat32_path = f'output/{version}/{version}_fat32_FS.kip1'
        decompressed_fat32_path = f'output/{version}/{version}_fat32_uFS.kip1'
        compressed_exfat_path = f'output/{version}/{version}_exfat_FS.kip1'
        decompressed_exfat_path = f'output/{version}/{version}_exfat_uFS.kip1'

        if os.path.exists(compressed_fat32_path):
            fat32hash = hashlib.sha256(open(compressed_fat32_path, 'rb').read()).hexdigest().upper()
        if os.path.exists(compressed_exfat_path):
            exfathash = hashlib.sha256(open(compressed_exfat_path, 'rb').read()).hexdigest().upper()

        # Get patterns for this version
        es_pattern_obj = get_pattern_for_version(ES_PATTERNS, current_firmware_version)
        nifm_pattern_obj = get_pattern_for_version(NIFM_PATTERNS, current_firmware_version)
        olsc_pattern_obj = get_pattern_for_version(OLSC_PATTERNS, current_firmware_version)

        # For NIM patterns, we need to handle both blankcal0 and blockfw separately
        nim_blankcal0_obj = next((p for p in NIM_PATTERNS if 'blankcal0' in p.name and MAKEHOSVERSION(p.min_version, p.max_version, current_firmware_version)), None)
        nim_blockfw_obj = next((p for p in NIM_PATTERNS if 'blockfw' in p.name and MAKEHOSVERSION(p.min_version, p.max_version, current_firmware_version)), None)
    
        # For FS patterns
        fs_noacidsigchk1_obj = next((p for p in FS_PATTERNS if 'fs_noacidsigchk1' in p.name and MAKEHOSVERSION(p.min_version, p.max_version, current_firmware_version)), None)
        fs_noacidsigchk2_obj = next((p for p in FS_PATTERNS if 'fs_noacidsigchk2' in p.name and MAKEHOSVERSION(p.min_version, p.max_version, current_firmware_version)), None)

        fs_noncasigchk_obj = next((p for p in FS_PATTERNS if 'noncasigchk' in p.name and MAKEHOSVERSION(p.min_version, p.max_version, current_firmware_version)), None)
        fs_nocntchk_obj = next((p for p in FS_PATTERNS if 'nocntchk' in p.name and MAKEHOSVERSION(p.min_version, p.max_version, current_firmware_version)), None)

        # Compile patterns
        es_pattern = convert_sys_patch_nibble_string(es_pattern_obj.pattern_string) if es_pattern_obj else None
        nifm_pattern = convert_sys_patch_nibble_string(nifm_pattern_obj.pattern_string) if nifm_pattern_obj else None
        olsc_pattern = convert_sys_patch_nibble_string(olsc_pattern_obj.pattern_string) if olsc_pattern_obj else None
        blankcal0crashfix_pattern = convert_sys_patch_nibble_string(nim_blankcal0_obj.pattern_string) if nim_blankcal0_obj else None
        blockfirmwareupdates_pattern = convert_sys_patch_nibble_string(nim_blockfw_obj.pattern_string) if nim_blockfw_obj else None

        fs_noacidsigchk1_pattern = convert_sys_patch_nibble_string(fs_noacidsigchk1_obj.pattern_string) if fs_noacidsigchk1_obj else None
        fs_noacidsigchk2_pattern = convert_sys_patch_nibble_string(fs_noacidsigchk2_obj.pattern_string) if fs_noacidsigchk2_obj else None
        fs_noncasigchk_pattern = convert_sys_patch_nibble_string(fs_noncasigchk_obj.pattern_string) if fs_noncasigchk_obj else None
        fs_nocntchk_pattern = convert_sys_patch_nibble_string(fs_nocntchk_obj.pattern_string) if fs_nocntchk_obj else None

        # Get offsets and other metadata
        es_offset = es_pattern_obj.offset if es_pattern_obj else None
        es_headoffset = es_pattern_obj.headoffset if es_pattern_obj else None
        gh_string = es_pattern_obj.pattern_string if es_pattern_obj else None
        es_ghidra_pattern = ' '.join(gh_string[i:i+2] for i in range(0, len(gh_string), 2))

        nifm_offset = nifm_pattern_obj.offset if nifm_pattern_obj else None
        nifm_headoffset = nifm_pattern_obj.headoffset if nifm_pattern_obj else None
        gh_string = nifm_pattern_obj.pattern_string if nifm_pattern_obj else None
        nifm_ghidra_pattern = ' '.join(gh_string[i:i+2] for i in range(0, len(gh_string), 2))


        if version_to_tuple(version) >= version_to_tuple("6.0.0"):
            olsc_offset = olsc_pattern_obj.offset if olsc_pattern_obj else None
            olsc_headoffset = olsc_pattern_obj.headoffset if olsc_pattern_obj else None
            gh_string = olsc_pattern_obj.pattern_string if olsc_pattern_obj else None
            olsc_ghidra_pattern = ' '.join(gh_string[i:i+2] for i in range(0, len(gh_string), 2))


        if version_to_tuple(version) >= version_to_tuple("17.0.0"):
            blankcal0crashfix_offset = nim_blankcal0_obj.offset if nim_blankcal0_obj else None
            blankcal0crashfix_headoffset = nim_blankcal0_obj.headoffset if nim_blankcal0_obj else None
            gh_string = nim_blankcal0_obj.pattern_string if nim_blankcal0_obj else None
            blankcal0crashfix_ghidra_pattern = ' '.join(gh_string[i:i+2] for i in range(0, len(gh_string), 2))

        blockfirmwareupdates_offset = nim_blockfw_obj.offset if nim_blockfw_obj else None
        blockfirmwareupdates_headoffset = nim_blockfw_obj.headoffset if nim_blockfw_obj else None
        gh_string = nim_blockfw_obj.pattern_string if nim_blockfw_obj else None
        blockfirmwareupdates_ghidra_pattern = ' '.join(gh_string[i:i+2] for i in range(0, len(gh_string), 2))


        fs_nocntchk_offset = fs_nocntchk_obj.offset if fs_nocntchk_obj else None
        fs_nocntchk_headoffset = fs_nocntchk_obj.headoffset if fs_nocntchk_obj else None
        gh_string = fs_nocntchk_obj.pattern_string if fs_nocntchk_obj else None
        fs_nocntchk_ghidra_pattern = ' '.join(gh_string[i:i+2] for i in range(0, len(gh_string), 2))

        if version_to_tuple(version) <= version_to_tuple("9.99.9"):
            fs_noacidsigchk1_offset = fs_noacidsigchk1_obj.offset if fs_noacidsigchk1_obj else None
            fs_noacidsigchk1_headoffset = fs_noacidsigchk1_obj.headoffset if fs_noacidsigchk1_obj else None
            gh_string = fs_noacidsigchk1_obj.pattern_string if fs_noacidsigchk1_obj else None
            fs_noacidsigchk1_ghidra_pattern = ' '.join(gh_string[i:i+2] for i in range(0, len(gh_string), 2))

            fs_noacidsigchk2_offset = fs_noacidsigchk2_obj.offset if fs_noacidsigchk2_obj else None
            fs_noacidsigchk2_headoffset = fs_noacidsigchk2_obj.headoffset if fs_noacidsigchk2_obj else None
            gh_string = fs_noacidsigchk2_obj.pattern_string if fs_noacidsigchk2_obj else None
            fs_noacidsigchk2_ghidra_pattern = ' '.join(gh_string[i:i+2] for i in range(0, len(gh_string), 2))

        fs_noncasigchk_offset = fs_noncasigchk_obj.offset if fs_noncasigchk_obj else None
        fs_noncasigchk_headoffset = fs_noncasigchk_obj.headoffset if fs_noncasigchk_obj else None
        gh_string = fs_noncasigchk_obj.pattern_string if fs_noncasigchk_obj else None
        fs_noncasigchk_ghidra_pattern = ' '.join(gh_string[i:i+2] for i in range(0, len(gh_string), 2)) 

        fs_nocntchk_offset = fs_nocntchk_obj.offset if fs_nocntchk_obj else None
        fs_nocntchk_headoffset = fs_nocntchk_obj.headoffset if fs_nocntchk_obj else None
        gh_string = fs_nocntchk_obj.pattern_string if fs_nocntchk_obj else None
        fs_nocntchk_ghidra_pattern = ' '.join(gh_string[i:i+2] for i in range(0, len(gh_string), 2))


        with open(f'output/{version}/{version}_patch_summary_with_diff_strings.txt', 'w') as find_patterns:

            patch_check_module(es_path, es_pattern, es_offset, es_headoffset, es_ghidra_pattern, mov0_patch, patch_size_4, es_cond, 'ES', find_patterns, es_pattern_diffs, es_pattern_offsets, None, ips_patch_database)

            patch_check_module(nifm_path, nifm_pattern, nifm_offset, nifm_headoffset, nifm_ghidra_pattern, ctest_patch, patch_size_20, ctest_cond, 'NIFM', find_patterns, nifm_pattern_diffs, nifm_pattern_offsets, None, ips_patch_database)

            if version_to_tuple(version) >= version_to_tuple("6.0.0"):
                patch_check_module(olsc_path, olsc_pattern, olsc_offset, olsc_headoffset, olsc_ghidra_pattern, ret1_patch, patch_size_4, bl_cond, 'OLSC', find_patterns, olsc_pattern_diffs, olsc_pattern_offsets, None, ips_patch_database)

            if version_to_tuple(version) >= version_to_tuple("17.0.0"):
                block_fw_patch = patch_check_module(nim_path, blockfirmwareupdates_pattern, blockfirmwareupdates_offset, blockfirmwareupdates_headoffset, blockfirmwareupdates_ghidra_pattern, mov0_ret_patch, patch_size_8, block_fw_updates_cond, 'NIM-FW', find_patterns, blockfirmwareupdates_pattern_diffs, blockfirmwareupdates_pattern_offsets, None, ips_patch_database)
            else:
                patch_check_module(nim_path, blockfirmwareupdates_pattern, blockfirmwareupdates_offset, blockfirmwareupdates_headoffset, blockfirmwareupdates_ghidra_pattern, mov0_ret_patch, patch_size_8, block_fw_updates_cond, 'NIM-FW', find_patterns, blockfirmwareupdates_pattern_diffs, blockfirmwareupdates_pattern_offsets, None, ips_patch_database)

            if version_to_tuple(version) >= version_to_tuple("17.0.0"):
                patch_check_module(nim_path, blankcal0crashfix_pattern, blankcal0crashfix_offset, blankcal0crashfix_headoffset, blankcal0crashfix_ghidra_pattern, mov2_patch, patch_size_4, adr_cond, 'NIM', find_patterns, blankcal0crashfix_pattern_diffs, blankcal0crashfix_pattern_offsets, block_fw_patch, ips_patch_database)

            patch_check_fs(decompressed_fat32_path, fat32hash, fs_noncasigchk_pattern, fs_nocntchk_pattern, fs_noacidsigchk1_pattern, fs_noacidsigchk2_pattern, fs_noncasigchk_offset, fs_nocntchk_offset, fs_noacidsigchk1_offset, fs_noacidsigchk2_offset, fs_noncasigchk_ghidra_pattern, fs_nocntchk_ghidra_pattern, fs_noacidsigchk1_ghidra_pattern, fs_noacidsigchk2_ghidra_pattern, nop_patch, ret0_patch, ret0_patch, ret0_patch, tbz_cond, bl_cond, bl_cond, bl_cond, fat32_noncasigchk_pattern_diffs, fat32_nocntchk_pattern_diffs, fat32_noacidsigchk1_pattern_diffs, fat32_noacidsigchk2_pattern_diffs, fat32_noncasigchk_pattern_offsets, fat32_nocntchk_pattern_offsets, fat32_noacidsigchk1_pattern_offsets, fat32_noacidsigchk2_pattern_offsets, fs_kip_patch_database, ips_patch_database, 'FAT32', find_patterns)
            if os.path.exists(decompressed_exfat_path):
                patch_check_fs(decompressed_exfat_path, exfathash, fs_noncasigchk_pattern, fs_nocntchk_pattern, fs_noacidsigchk1_pattern, fs_noacidsigchk2_pattern, fs_noncasigchk_offset, fs_nocntchk_offset, fs_noacidsigchk1_offset, fs_noacidsigchk2_offset, fs_noncasigchk_ghidra_pattern, fs_nocntchk_ghidra_pattern, fs_noacidsigchk1_ghidra_pattern, fs_noacidsigchk2_ghidra_pattern, nop_patch, ret0_patch, ret0_patch, ret0_patch, tbz_cond, bl_cond, bl_cond, bl_cond, exfat_noncasigchk_pattern_diffs, exfat_nocntchk_pattern_diffs, exfat_noacidsigchk1_pattern_diffs, exfat_noacidsigchk2_pattern_diffs, exfat_noncasigchk_pattern_offsets, exfat_nocntchk_pattern_offsets, exfat_noacidsigchk1_pattern_offsets, exfat_noacidsigchk2_pattern_offsets, fs_kip_patch_database, ips_patch_database, 'EXFAT', find_patterns)

            ## ssl more quirky and .nso0, leave as old format since it's not used by sys-patch anymore, and only for automatically forwarding the ssl patches

            patchvalue5 = "08" # SSL
            patchvalue6 = "1300" # SSL
            patchvalue7 = "14" # SSL
            patchvalue8 = "08008052" # SSL

            ssl_pattern1 = rb'\x08\x00\x80\x12\x69\x12\x05\x91\x7f\x1e\x00\xf9\x68\x42\x00\xb9'
            ssl_pattern2 = rb'\x24\x09\x43\x7a\xa0\x00\x00\x54'
            ssl_pattern3 = rb'\x88\x16\x00\x12'
            ssl_offset1 = 16 # # ssl_pattern1
            ssl_offset2 = 4 # ssl_pattern2
            ssl_offset3 = 7 # ssl_pattern2
            ssl_offset4 = 8 # ssl_pattern3


            if version_to_tuple(version) >= version_to_tuple("21.0.0"):
                with open(f'{ssl_path}', 'rb') as decompressed_ssl_nso:
                    read_data = decompressed_ssl_nso.read()
                    result1 = re.search(ssl_pattern1, read_data)
                    result2 = re.search(ssl_pattern2, read_data)
                    result3 = re.search(ssl_pattern3, read_data)
                    if not result1:
                        find_patterns.write(f'(SSL) {version} SSL pattern 1 no match found\n')
                        find_patterns.write(f'(SSL) SSL pattern 1 is invalid for: {version}\n\n')
                    if not result2:
                        find_patterns.write(f'(SSL) {version} SSL pattern 2 no match found\n')
                        find_patterns.write(f'(SSL) SSL pattern 2 is invalid for: {version}\n\n')
                    if not result3:
                        find_patterns.write(f'(SSL) {version} SSL pattern 3 no match found\n')
                        find_patterns.write(f'(SSL) SSL pattern 3 is invalid for: {version}\n\n')
                    if (result1 and result2 and result3):
                        offset1 = '%06X' % (result1.start() + ssl_offset1)
                        offset2 = '%06X' % (result2.start() + ssl_offset2)
                        offset3 = '%06X' % (result2.start() + ssl_offset3)
                        offset4 = '%06X' % (result3.start() + ssl_offset4)
                        decompressed_ssl_nso.seek(result1.start() + ssl_offset1)
                        ssl_patch1_bytes = decompressed_ssl_nso.read(0x4).hex().upper()
                        decompressed_ssl_nso.seek(result2.start() + ssl_offset2)
                        ssl_patch2_bytes = decompressed_ssl_nso.read(0x4).hex().upper()
                        decompressed_ssl_nso.seek(result3.start() + ssl_offset4)
                        ssl_patch3_bytes = decompressed_ssl_nso.read(0x4).hex().upper()
                        patch1 = '%08X%s%s' % (result1.start() + ssl_offset1, '0001', f'{patchvalue5}')
                        patch2 = '%08X%s%s' % (result2.start() + ssl_offset2, '0002', f'{patchvalue6}')
                        patch3 = '%08X%s%s' % (result2.start() + ssl_offset3, '0001', f'{patchvalue7}')
                        patch4 = '%08X%s%s' % (result3.start() + ssl_offset4, '0004', f'{patchvalue8}')
                        find_patterns.write(f'(SSL) patterns found results for: {version}\n')
                        find_patterns.write(f'(SSL) pattern 1 found at: {offset1} ## 21.0.0+ 0x119B60\n') 
                        find_patterns.write(f'(SSL) The ghidra-equivalent pattern used was: 08 00 80 12 69 12 05 91 7f 1e 00 f9 68 42 00 b9\n')
                        find_patterns.write(f'(SSL) The existing bytes at the offset are: {ssl_patch1_bytes}\n') # 21.0.0+ // 680080D2 // mov x8, #3
                        find_patterns.write(f'(SSL) this is patched out to become {patchvalue5}0080D2 (mov x8, #0), to make make register x8 (x10 20.5.0 and below) zero, so that the movk turns the value used into 0x100000000 instead of 0x100000003 - seen in the ghidra decompiled view\n')
                        find_patterns.write(f'(SSL) pattern 2 found at: {offset2} ## 21.0.0+ 0x11A914\n') 
                        find_patterns.write(f'(SSL) pattern 3 found at: {offset3} ## 21.0.0+ 0x11A917\n') 
                        find_patterns.write(f'(SSL) The ghidra-equivalent pattern used was: 24 09 43 7a a0 00 00 54\n')
                        find_patterns.write(f'(SSL) The existing bytes at the two offsets combined are: {ssl_patch2_bytes}\n') # 21.0.0+ // A0000054 // b.eq #0x14
                        find_patterns.write(f'(SSL) this is patched out to become  {patchvalue6}00{patchvalue7} (b #0x4c) to target the second branch instead of comparing values (b.eq #0x14) and going to the first one\n')
                        find_patterns.write(f'(SSL) pattern 4 found at: {offset4} ## 21.0.0+ 0x11A968\n') 
                        find_patterns.write(f'(SSL) The ghidra-equivalent pattern used was: 88 16 00 12\n')
                        find_patterns.write(f'(SSL) The existing bytes at the offset are: {ssl_patch3_bytes}\n') # 21.0.0+ // 684601B9 // str w8, [x19, #0x144]
                        find_patterns.write(f'(SSL) this is patched out to become {patchvalue8} (mov w8, #0), to prepare register w8 with a zero, for the purpose of making the function return 0 (success) later on.\n')
                        find_patterns.write(f'(SSL) {version} SSL moduleid (and what .ips filename should be): {get_module_id(ssl_path)}\n\n')
                        find_patterns.write(f'(SSL) IPS patch bytes would be:\n')
                        find_patterns.write(f'(SSL) {ips32_magic}{patch1}{patch2}{patch3}{patch4}{eeof_magic}\n\n')
                    else:
                        find_patterns.write(f'(SSL) one or more SSL patterns were not found\n\n')
            else:
                find_patterns.write(f'\n(SSL) only the very latest pattern is supported (21.0.0+), current version is: {version}\n\n')
        patch_summary_file = f'output/{version}/{version}_patch_summary_with_diff_strings.txt'  
        find_patterns.close()

if args.ams:
    if os.path.exists('package3_and_stratosphere_extracted'):
        shutil.rmtree('package3_and_stratosphere_extracted')
    ams_string = package3_and_stratosphere.download_and_extract_package3_and_stratosphere_romfs()

    loader_path = f'package3_and_stratosphere_extracted/u_loader.kip1'
    compressed_loader_path = f'package3_and_stratosphere_extracted/loader.kip1' 

    if os.path.exists(compressed_loader_path):
        loader_pattern_obj = get_pattern_for_version(LOADER_PATTERNS, '10.0.0')
        loader_pattern = convert_sys_patch_nibble_string(loader_pattern_obj.pattern_string) if loader_pattern_obj else None
        loader_offset = loader_pattern_obj.offset if loader_pattern_obj else None
        loader_headoffset = loader_pattern_obj.headoffset if loader_pattern_obj else None
        gh_string = loader_pattern_obj.pattern_string if loader_pattern_obj else None
        loader_ghidra_pattern = ' '.join(gh_string[i:i+2] for i in range(0, len(gh_string), 2))
        loader_pattern_diffs = {}
        loader_pattern_offsets = {}
        loaderhash = hashlib.sha256(open(compressed_loader_path, 'rb').read()).hexdigest().upper()

        try:
            if not version:
                pass

        except NameError:
            version = "latest"
            try:
                url = "https://raw.githubusercontent.com/Atmosphere-NX/Atmosphere/master/libraries/libvapours/include/vapours/ams/ams_api_version.h"
                req = Request(url)
                req.add_header('User-Agent', 'Mozilla/5.0 (compatible; find_patterns.py)')  # GitHub recommends a User-Agent

                with urlopen(req) as response:
                    content = response.read().decode('utf-8')

                major_match = re.search(r'#define ATMOSPHERE_SUPPORTED_HOS_VERSION_MAJOR\s+(\d+)', content)
                minor_match = re.search(r'#define ATMOSPHERE_SUPPORTED_HOS_VERSION_MINOR\s+(\d+)', content)
                micro_match = re.search(r'#define ATMOSPHERE_SUPPORTED_HOS_VERSION_MICRO\s+(\d+)', content)

                if major_match and minor_match and micro_match:
                    version = f"{major_match.group(1)}.{minor_match.group(1)}.{micro_match.group(1)}"
                    print(f"Fetched latest supported HOS version from Atmosphere: {version}")
                else:
                    print("Warning: Could not parse version macros — using 'latest'.")
            except Exception as e:
                print(f"Warning: Failed to fetch latest HOS version: {e}. Using 'latest'.")

        with open(f'output/loader_patch_summary.txt', 'w') as find_patterns:
            patch_check_loader(loader_path, loader_pattern, loader_offset, loader_headoffset, loader_ghidra_pattern, cmp_cond, 'LOADER', find_patterns, loader_pattern_diffs, loader_pattern_offsets, loaderhash, ldr_kip_patch_database, ams_string, ips_patch_database)
        find_patterns.close()

    uncompressed_erpt_path = f'package3_and_stratosphere_extracted/uncompressed_erpt.nso0'
    if os.path.exists(uncompressed_erpt_path):
        erpt_pattern_diffs = {}
        erpt_pattern_offsets = {}
        erpt_pattern_obj = get_pattern_for_version(ERPT_PATTERNS, '10.0.0')
        erpt_pattern = convert_sys_patch_nibble_string(erpt_pattern_obj.pattern_string) if erpt_pattern_obj else None
        erpt_offset = erpt_pattern_obj.offset if erpt_pattern_obj else None
        erpt_headoffset = erpt_pattern_obj.headoffset if erpt_pattern_obj else None
        gh_string = erpt_pattern_obj.pattern_string if erpt_pattern_obj else None
        erpt_ghidra_pattern = ' '.join(gh_string[i:i+2] for i in range(0, len(gh_string), 2))

        with open(f'output/erpt_patch_summary.txt', 'w') as find_patterns:
            patch_check_module(uncompressed_erpt_path, erpt_pattern, erpt_offset, erpt_headoffset, erpt_ghidra_pattern, mov0_ret_patch, patch_size_8, sub_cond, 'ERPT', find_patterns, erpt_pattern_diffs, erpt_pattern_offsets, None, ips_patch_database)
        find_patterns.close()

print("\n" + "="*80)
print("Updating scripts/pattern_diffs.py and patch databases incrementally...")
print("="*80 + "\n")

try:
    with open('output/es_debug_logs.txt', 'w', encoding='utf-8') as logs:
        for version, debug_logs in sorted(es_pattern_offsets.items(), key=lambda x: version_to_tuple(x[0])):
            logs.write(f"    '{version}': {debug_logs},\n")
    logs.close()

    with open('output/nifm_debug_logs.txt', 'w', encoding='utf-8') as logs:
        for version, debug_logs in sorted(nifm_pattern_offsets.items(), key=lambda x: version_to_tuple(x[0])):
            logs.write(f"    '{version}': {debug_logs},\n")
    logs.close()

    with open('output/olsc_debug_logs.txt', 'w', encoding='utf-8') as logs:
        for version, debug_logs in sorted(olsc_pattern_offsets.items(), key=lambda x: version_to_tuple(x[0])):
            logs.write(f"    '{version}': {debug_logs},\n")
    logs.close()

    with open('output/nim_blankcal0crashfix_debug_logs.txt', 'w', encoding='utf-8') as logs:
        for version, debug_logs in sorted(blankcal0crashfix_pattern_offsets.items(), key=lambda x: version_to_tuple(x[0])):
            logs.write(f"    '{version}': {debug_logs},\n")
    logs.close()

    with open('output/nim_blockfirmwareupdates_debug_logs.txt', 'w', encoding='utf-8') as logs:
        for version, debug_logs in sorted(blockfirmwareupdates_pattern_offsets.items(), key=lambda x: version_to_tuple(x[0])):
            logs.write(f"    '{version}': {debug_logs},\n")
    logs.close()

    with open('output/fat32_noncasigchk_debug_logs.txt', 'w', encoding='utf-8') as logs:
        for version, debug_logs in sorted(fat32_noncasigchk_pattern_offsets.items(), key=lambda x: version_to_tuple(x[0])):
            logs.write(f"    '{version}': {debug_logs},\n")
    logs.close()

    with open('output/exfat_noncasigchk_debug_logs.txt', 'w', encoding='utf-8') as logs:
        for version, debug_logs in sorted(exfat_noncasigchk_pattern_offsets.items(), key=lambda x: version_to_tuple(x[0])):
            logs.write(f"    '{version}': {debug_logs},\n")
    logs.close()

    with open('output/fat32_nocntchk_debug_logs.txt', 'w', encoding='utf-8') as logs:
        for version, debug_logs in sorted(fat32_nocntchk_pattern_offsets.items(), key=lambda x: version_to_tuple(x[0])):
            logs.write(f"    '{version}': {debug_logs},\n")
    logs.close()

    with open('output/exfat_nocntchk_debug_logs.txt', 'w', encoding='utf-8') as logs:
        for version, debug_logs in sorted(exfat_nocntchk_pattern_offsets.items(), key=lambda x: version_to_tuple(x[0])):
            logs.write(f"    '{version}': {debug_logs},\n")
    logs.close()

    with open('output/fat32_noacidsigchk1_debug_logs.txt', 'w', encoding='utf-8') as logs:
        for version, debug_logs in sorted(fat32_noacidsigchk1_pattern_offsets.items(), key=lambda x: version_to_tuple(x[0])):
            logs.write(f"    '{version}': {debug_logs},\n")
    logs.close()

    with open('output/exfat_noacidsigchk1_debug_logs.txt', 'w', encoding='utf-8') as logs:
        for version, debug_logs in sorted(exfat_noacidsigchk1_pattern_offsets.items(), key=lambda x: version_to_tuple(x[0])):
            logs.write(f"    '{version}': {debug_logs},\n")
    logs.close()   

    with open('output/fat32_noacidsigchk2_debug_logs.txt', 'w', encoding='utf-8') as logs:
        for version, debug_logs in sorted(fat32_noacidsigchk2_pattern_offsets.items(), key=lambda x: version_to_tuple(x[0])):
            logs.write(f"    '{version}': {debug_logs},\n")
    logs.close()

    with open('output/exfat_noacidsigchk2_debug_logs.txt', 'w', encoding='utf-8') as logs:
        for version, debug_logs in sorted(exfat_noacidsigchk2_pattern_offsets.items(), key=lambda x: version_to_tuple(x[0])):
            logs.write(f"    '{version}': {debug_logs},\n")
    logs.close()  

    if args.ams:
        with open('output/loader_debug_logs.txt', 'w', encoding='utf-8') as logs:
            for version, debug_logs in sorted(loader_pattern_offsets.items(), key=lambda x: version_to_tuple(x[0])):
                logs.write(f"    '{version}': {debug_logs},\n")
        logs.close()

except Exception as e:
        print(f"Error writing debug logs: {e}")

pattern_diffs_path = 'scripts/pattern_diffs.py'
existing_diffs = load_existing_pattern_diffs(pattern_diffs_path)

diff_categories = [
    ('es_pattern_diffs', es_pattern_diffs),
    ('blankcal0crashfix_pattern_diffs', blankcal0crashfix_pattern_diffs),
    ('blockfirmwareupdates_pattern_diffs', blockfirmwareupdates_pattern_diffs),
    ('nifm_pattern_diffs', nifm_pattern_diffs),
    ('olsc_pattern_diffs', olsc_pattern_diffs),
    ('fat32_noacidsigchk1_pattern_diffs', fat32_noacidsigchk1_pattern_diffs),
    ('exfat_noacidsigchk1_pattern_diffs', exfat_noacidsigchk1_pattern_diffs),
    ('fat32_noacidsigchk2_pattern_diffs', fat32_noacidsigchk2_pattern_diffs),
    ('exfat_noacidsigchk2_pattern_diffs', exfat_noacidsigchk2_pattern_diffs),
    ('fat32_noncasigchk_pattern_diffs', fat32_noncasigchk_pattern_diffs),
    ('exfat_noncasigchk_pattern_diffs', exfat_noncasigchk_pattern_diffs),
    ('fat32_nocntchk_pattern_diffs', fat32_nocntchk_pattern_diffs),
    ('exfat_nocntchk_pattern_diffs', exfat_nocntchk_pattern_diffs),
]

if args.ams:
    diff_categories += [
        ('loader_pattern_diffs', loader_pattern_diffs),
        ('erpt_pattern_diffs', erpt_pattern_diffs),
    ]

updated = False
for category_name, new_dict in diff_categories:
    old_dict = existing_diffs[category_name]
    for version, diff_str in new_dict.items():
        py_bytes = hex_string_to_python_bytes(diff_str)
        if version not in old_dict or old_dict[version] != py_bytes:
            old_dict[version] = py_bytes
            updated = True

if updated or not os.path.exists(pattern_diffs_path):
    try:
        with open(pattern_diffs_path, 'w', encoding='utf-8') as f:
            f.write("# Auto-generated pattern diff strings\n")
            f.write("# Generated from find_patterns.py\n")
            f.write("# Do not edit manually unless you know what you're doing — new runs will preserve entries.\n\n")

            for category_name, _ in diff_categories:
                data = existing_diffs[category_name]
                
                # Convert dict → sorted list of tuples
                entries = sorted(
                    data.items(),
                    key=lambda x: version_to_tuple(x[0])
                )
                
                if not entries:
                    f.write(f"{category_name} = []\n\n")
                    continue
                    
                f.write(f"{category_name} = [\n")
                for version, py_bytes in entries:
                    f.write(f"    ('{version}', {py_bytes}),\n")
                f.write("]\n\n")

        print(f"Updated {pattern_diffs_path} with new/missing versions.")
        total_entries = sum(len(d) for d in existing_diffs.values())
        print(f"  Total diff entries preserved/added: {total_entries}")
    except Exception as e:
        print(f"Error writing {pattern_diffs_path}: {e}")
else:
    print(f"No new pattern diffs to add — {pattern_diffs_path} unchanged.")


fs_kip_patch_database = remove_duplicates_by_index(fs_kip_patch_database, 1)
ldr_kip_patch_database = remove_duplicates_by_index(ldr_kip_patch_database, 1)
ips_patch_database = remove_duplicates_by_index(ips_patch_database, 1)

fs_kip_updated = update_patch_file('patch_database/fs_kip_patches.txt', fs_kip_patch_database)
ldr_kip_updated = update_patch_file('patch_database/ldr_kip_patches.txt', ldr_kip_patch_database)
ips_updated = update_patch_file('patch_database/ips_patches.txt', ips_patch_database)

if not fs_kip_updated and not ips_updated and not ldr_kip_updated:
    print("All patch databases already up to date.")

print("\nMerging SDK versions into fs_kip_patches.txt (adding missing SDK versions only)...")

fs_kip_file = 'patch_database/fs_kip_patches.txt'
fs_sdk_file = 'patch_database/fs_sdk_versions.txt'

if not os.path.exists(fs_sdk_file):
    print(f"{fs_sdk_file} not found — skipping SDK version merge.")
else:
    sdk_entries = load_existing_patches(fs_sdk_file)
    print(f"Loaded {len(sdk_entries)} entries from fs_sdk_versions.txt")

    # Build map: (fw_version, short_16_char_string_upper) -> sdk_version
    sdk_map = {}
    for entry in sdk_entries:
        if len(entry) >= 3:
            fw_version = entry[0]
            short_16 = entry[1]
            full_hash = entry[2].upper()
            sdk_version = entry[3]
            sdk_map[(fw_version, short_16)] = sdk_version

    print(f"Built SDK map with {len(sdk_map)} unique (fw_version, 16-char short) entries")

    kip_entries = load_existing_patches(fs_kip_file)
    print(f"Loaded {len(kip_entries)} entries from fs_kip_patches.txt")

    added_count = 0
    new_kip_entries = []

    for entry in kip_entries:
        if len(entry) == 5:
            # Already has SDK version — keep unchanged
            new_kip_entries.append(entry)
            continue
        if len(entry) != 4:
            # Unusual length — keep as-is
            new_kip_entries.append(entry)
            continue

        fw_version = entry[0]
        title_block = entry[1]
        patch_str = entry[2]
        fs_type = entry[3]

        match = re.search(r'\[FS:([0-9A-F]{16})\]', title_block)
        if not match:
            print(f"Warning: Could not parse 16-char TitleID from: {title_block.strip()}")
            new_kip_entries.append(entry)
            continue

        short_16 = match.group(1).upper()  # the exact 16-char string

        key = (fw_version, short_16)
        sdk_version = sdk_map.get(key)

        if sdk_version:
            # Append the SDK version as the 5th element — no changes to title_block
            new_entry = (fw_version, title_block, patch_str, fs_type, sdk_version)
            new_kip_entries.append(new_entry)
            added_count += 1
            print(f"Added SDK {sdk_version} to {fw_version} {fs_type} ({short_16})")
        else:
            print(f"No exact 16-char match for {fw_version} {fs_type} ({short_16})")
            new_kip_entries.append(entry)

    if added_count > 0:
        try:
            with open(fs_kip_file, 'w', encoding='utf-8') as f:
                for entry in new_kip_entries:
                    f.write(f"{entry},\n")
            print(f"\nSuccessfully appended SDK version to {added_count} entries in fs_kip_patches.txt!")
        except Exception as e:
            print(f"Error writing {fs_kip_file}: {e}")
    else:
        print("\nNo SDK versions appended — all entries either already have SDK or no exact 16-char match found.")

print("="*80)

# Cleanup AMS temp files if used
if os.path.exists('package3_and_stratosphere_extracted'):
    shutil.rmtree('package3_and_stratosphere_extracted')

print("\nIncremental update complete!")