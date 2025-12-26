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
import binascii
import sys
import shutil
import argparse
from typing import Tuple, List, Dict, Optional
from dataclasses import dataclass

import package3_and_stratosphere

parser = argparse.ArgumentParser()

parser.add_argument(
    '--ams',
    action='store_true',
)

args = parser.parse_args()

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

# vibecoded ai-slop function courtesy of grok4.1
def pattern_to_regex_bytestring(pattern: str) -> re.Pattern:
    pattern = pattern.strip()
    
    # Remove 0x prefix if present
    if pattern.startswith(('0x', '0X')):
        pattern = pattern[2:]
    
    regex_parts = []

    pattern = pattern.upper()
    i = 0
    while i < len(pattern):
        if pattern[i] == '.':
            regex_parts.append(b'.')
            i += 1
        else:
            if i + 1 >= len(pattern):
                raise ValueError(f"Incomplete hex byte at position {i}")
            token = pattern[i:i+2]
            if all(c in '0123456789ABCDEF' for c in token):
                byte_val = int(token, 16)
                regex_parts.append(re.escape(bytes([byte_val])))
                i += 2
            else:
                raise ValueError(f"Invalid hex characters at position {i}: '{pattern[i:i+2]}'")

    compiled_regex = re.compile(b''.join(regex_parts))

    return compiled_regex

# vibecoded ai-slop function courtesy of grok4.1
def format_sys_patch_string_to_ghidra_string(s: str) -> str:
    s = s.strip()
    
    # Remove 0x prefix if present
    if s.startswith(('0x', '0X')):
        s = s[2:]
    
    result = []
    i = 0
    n = len(s)
    
    while i < n:
        if s[i] == '.':
            result.append("..")
            i += 1
        else:
            byte = s[i:i+2].upper()
            if len(byte) != 2 or not all(c in "0123456789ABCDEF" for c in byte):
                raise ValueError(f"Invalid hex byte at position {i}: '{s[i:i+2]}'")
            result.append(byte)
            i += 2
    
    return " ".join(result)

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

def get_latest_firmware_version_from_provided_files():
    with open('sorted_firmware/by-type/Data/0100000000000809/romfs/file', 'rb') as file:
        data_read = file.read()
        firmware_version = data_read[0x68:0x6E].decode('utf-8', errors='replace').replace(chr(0), "")
        file.close()
        return firmware_version
    
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

cmp_patch = "00"
nop_patch = "1F2003D5" # FS (nop)
ret0_patch = "E0031F2A" # FS (mov w0, wzr)
mov0_patch = "E0031FAA" # ES
mov2_patch = "E2031FAA" # NIM
ret1_patch = "200080D2" # OLSC
mov0_ret_patch = "E0031F2AC0035FD6" # NIM
ctest_patch = "00309AD2001EA1F2610100D4E0031FAAC0035FD6" # NIFM (mov x0, #0xd180 - movk x0, #0x8f0, lsl #16 - svc #0xb - mov x0, xzr - ret)

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
    Pattern('es_1.0.0-8.1.1', '0xE8.00...FF97.0300AA..00.....E0.0091..0094.7E4092.......A9', 32, 0, 'ES', es_cond, mov0_patch, '1.0.0', '8.1.1'),
    Pattern('es_9.0.0-11.0.1', '0x00...............00.....A0..D1...97.......A9', 30, 0, 'ES', es_cond, mov0_patch, '9.0.0', '11.0.1'),
    Pattern('es_12.0.0-18.1.0', '0x02.00...........00...00.....A0..D1...97.......A9', 32, 0, 'ES', es_cond, mov0_patch, '12.0.0', '18.1.0'),
    Pattern('es_19.0.0+', '0xA1.00...........00...00.....A0..D1...97.......A9', 32, 0, 'ES', es_cond, mov0_patch, '19.0.0', FW_VER_ANY),
]

NIFM_PATTERNS = [
    Pattern('nifm_1.0.0-19.0.1', '0x03.AAE003.AA...39..04F8....E0', -29, 0, 'NIFM', ctest_cond, ctest_patch, '1.0.0', '19.0.1'),
    Pattern('nifm_20.0.0+', '0x03.AA...AA.........0314AA..14AA', -17, 0, 'NIFM', ctest_cond, ctest_patch, '20.0.0', FW_VER_ANY),
]

OLSC_PATTERNS = [
    Pattern('olsc_6.0.0-14.1.2', '0x00.73..F968024039..00...00', 42, 0, 'OLSC', bl_cond, ret1_patch, '6.0.0', '14.1.2'),
    Pattern('olsc_15.0.0-18.1.0', '0x00.73..F968024039..00...00', 38, 0, 'OLSC', bl_cond, ret1_patch, '15.0.0', '18.1.0'),
    Pattern('olsc_19.0.0+', '0x00.73..F968024039..00...00', 42, 0, 'OLSC', bl_cond, ret1_patch, '19.0.0', FW_VER_ANY),
]

NIM_PATTERNS = [
    Pattern('nim_blankcal0_17.0.0+', '0x00351F2003D5...............97..0094..00.....61', 6, 0, 'NIM', adr_cond, mov2_patch, '17.0.0', FW_VER_ANY),
    Pattern('nim_blockfw_1.0.0-5.1.0', '0x1139F30301AA81.40F9E0.1191', -30, 0, 'NIM', block_fw_updates_cond, mov0_ret_patch, '1.0.0', '5.1.0'),
    Pattern('nim_blockfw_6.0.0-6.2.0', '0xF30301AA.4E40F9E0..91', -40, 0, 'NIM', block_fw_updates_cond, mov0_ret_patch, '6.0.0', '6.2.0'),
    Pattern('nim_blockfw_7.0.0-11.0.1', '0xF30301AA014C40F9F40300AAE0..91', -36, 0, 'NIM', block_fw_updates_cond, mov0_ret_patch, '7.0.0', '11.0.1'),
    Pattern('nim_blockfw_12.0.0+', '0x280841F9084C00F9E0031F.C0035FD6', 16, 0, 'NIM', block_fw_updates_cond, mov0_ret_patch, '12.0.0', FW_VER_ANY),
]

FS_PATTERNS = [
    #Pattern('fs_noacidsigchk_1.0.0-9.2.0', '0xC8FE4739', -24, 'FS', bl_cond, ret0_patch, '1.0.0', '9.2.0'),
    #Pattern('fs_noacidsigchk_1.0.0-9.2.0', '0x1E48391F.0071..0054', -5, 'FS', bl_cond, ret0_patch, '1.0.0', '9.2.0'),
    Pattern('fs_noncasigchk_10.0.0-16.1.0', '0x1E48391F.0071..0054', -17, 0, 'FS', tbz_cond, nop_patch, '10.0.0', '16.1.0'),
    Pattern('fs_noncasigchk_17.0.0+', '0x0694..00.42.0091', -18, 0, 'FS', tbz_cond, nop_patch, '17.0.0', FW_VER_ANY),
    Pattern('fs_nocntchk_10.0.0-18.1.0', '0x00..0240F9....08.....00...00...0037', 6, 0, 'FS', bl_cond, ret0_patch, '10.0.0', '18.1.0'),
    Pattern('fs_nocntchk_19.0.0-20.5.0', '0x00..0240F9....08.....00...00...0054', 6, 0, 'FS', bl_cond, ret0_patch, '19.0.0', '20.5.0'),
    Pattern('fs_nocntchk_21.0.0+', '0x00..0240F9....E8.....00...00...0054', 6, 0, 'FS', bl_cond, ret0_patch, '21.0.0', FW_VER_ANY),
]

LOADER_PATTERNS = [
    Pattern('noacidsigchk_10.0.0+', '0x009401C0BE121F00', 6, 2, 'LOADER', cmp_cond, cmp_patch, '10.0.0', FW_VER_ANY), 
]

ERPT_PATTERNS = [
    Pattern('no_erpt', '0x...D1FD7B02A9FD830091F76305A9', 0, 0, 'ERPT', sub_cond, mov0_ret_patch, '10.0.0', FW_VER_ANY), 
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
        sys.exit(1)
    
    valid_versions.sort(key=version_to_tuple)
    return valid_versions

def hex_string_to_python_bytes(hex_str: str) -> str:
    """Convert hex string to Python byte string representation"""
    hex_str = hex_str.strip()
    byte_list = [f"\\x{hex_str[i:i+2].lower()}" for i in range(0, len(hex_str), 2)]
    return "b'" + "".join(byte_list) + "'"

def patch_check_module(path, pattern, pattern_offset, pattern_head_offset, ghidra_pattern, patch_type, patch_size, conds, module_name, changelog, diffs, patch_offsets, hash):
    with open(path, 'rb') as decompressed_module:
        find_patterns = changelog
        read_data = decompressed_module.read()
        result = re.search(pattern, read_data)
        module_id = get_module_id(path)
        all_matches = [*re.finditer(pattern, read_data)]
        match_count = len(all_matches)
        if match_count > 1:
            print(f'DEBUG - ({module_name}) - {version} - ELIMINATE DUPLICATES BY DIFFING AGAINST THE PATTERN')
            for match in all_matches:
                offset = '%06X' % (match.start() + pattern_offset)
                print(f'DEBUG - ({module_name}) - {version} - found - {match.group().hex().upper()}')
                print(f'DEBUG - ({module_name}) - {version} - offset found at {offset}')
        elif match_count == 0:
            print(f'DEBUG - ({module_name}) - NO RESULTS FOUND AT ALL - {version}')
        if not result:
            find_patterns.write(f'({module_name}) {version} {module_name} offset not found\n')
            find_patterns.write(f'({module_name}) Sys-patch for {module_name} string is invalid for: {version}\n\n')
        else:
            module_offset = result.start() + pattern_offset
            offset = '%06X' % (module_offset)
            patch_bytes_start = module_offset
            patch_bytes_end = patch_bytes_start + 0x4
            patch_bytes = read_data[patch_bytes_start:patch_bytes_end].hex().upper()
            patch_byte = patch_bytes[-2:]
            pattern_diff_string_start = module_offset - 0x20
            pattern_diff_string_end = pattern_diff_string_start + 0x60
            pattern_diff_string = read_data[pattern_diff_string_start:pattern_diff_string_end].hex().upper()
            diffs[version] = pattern_diff_string
            patch = '%06X%s%s' % ((module_offset + pattern_head_offset), patch_size, patch_type)
            head_offset = '%06X' % (module_offset + pattern_head_offset)
            patch_offset_string = (module_name, patch_bytes, offset, module_id)
            patch_offsets[version] = patch_offset_string
            if patch_byte in conds:
                find_patterns.write(f'({module_name}) an arm instruction with ending of 0x{patch_byte} was found at the designated offset.\n')
                find_patterns.write(f'({module_name}) Sys-patch for {module_name} string still valid for: {version}\n')
                find_patterns.write(f'({module_name}) Sys-patch {module_name} pattern found at: {offset}\n')
                find_patterns.write(f'({module_name}) The ghidra-equivalent pattern used was: {ghidra_pattern}\n')
                find_patterns.write(f'({module_name}) The existing bytes at the offset are: {patch_bytes}\n')
                if module_name != 'LOADER':
                    find_patterns.write(f'({module_name}) {version} {module_name} buildid (and what .ips filename should be): {module_id}\n\n')
                    find_patterns.write(f'({module_name}) IPS patch bytes would be:\n')
                    find_patterns.write(f'({module_name}) {patch_magic}{patch}{eof_magic}\n\n')
                    find_patterns.write(f'({module_name}) pattern string for diff: \n \n{pattern_diff_string}\n\n')
                if module_name == 'LOADER':
                    find_patterns.write(f'LOADER FULL HASH: {hash}\n\n')
                    find_patterns.write(f'[LOADER:{hash[:16]}]\n')
                    find_patterns.write(f'.nosigchk=0:0x{head_offset}:0x1:01,00\n')
            else:
                find_patterns.write(f'({module_name}) the arm instruction was either not found after the pattern, or is ends differently. Must be checked. Assume it is broken.\n\n')
                print(f'DEBUG - ({module_name}) {version} - PBS: {patch_bytes} - PB: {patch_byte} - OFS: {offset}')

def patch_check_fs(path, hash, noncasigchk_pattern, nocntchk_pattern, noncasigchk_offset, nocntchk_offset, noncasigchk_ghidra_pattern, nocntchk_ghidra_pattern, noncasigchk_patch, nocntchk_patch, noncasigchk_cond, nocntchk_cond, module_name, changelog, noncasigchk_diffs, nocntchk_diffs, nonsigchk_offsets, nocntchk_offsets):
    with open(path, 'rb') as decompressed_module:
        find_patterns = changelog
        read_data = decompressed_module.read()
        result_1 = re.search(noncasigchk_pattern, read_data)
        result_2 = re.search(nocntchk_pattern, read_data)
        all_matches_1 =[*re.finditer(noncasigchk_pattern, read_data)]
        all_matches_2 =[*re.finditer(nocntchk_pattern, read_data)]
        match_count_1 = len(all_matches_1)
        match_count_2 = len(all_matches_2)
        if match_count_1 > 1:
            print(f'DEBUG - ({module_name}) - NONCASIGCHK - {version} - ELIMINATE DUPLICATES BY DIFFING AGAINST THE PATTERN')
            for match in all_matches_1:
                offset_1 = '%06X' % (match.start() + noncasigchk_offset)
                print(f'DEBUG - (FS-{module_name}) - NONCASIGCHK - {version} - found - {match.group().hex().upper()}')
                print(f'DEBUG - (FS-{module_name}) - NONCASIGCHK - {version} - offset found at {offset_1}')
        elif match_count_1 == 0:
            if version != '11.0.0' and version != '11.0.1':
                # this pattern is valid for 11.0.0/11.0.1, but for reasons unknown it says there isn't a match
                print(f'DEBUG - (FS-{module_name}) - NO RESULTS FOUND AT ALL - NONCASIGCHK - {version}')

        if match_count_2 > 1:
            print(f'DEBUG - (FS-{module_name}) - NOCNTCHK - {version} - ELIMINATE DUPLICATES BY DIFFING AGAINST THE PATTERN')
            for match in all_matches_2:
                offset_2 = '%06X' % (match.start() + nocntchk_offset)
                print(f'DEBUG - (FS-{module_name}) - NOCNTCHK - {version} - found - {match.group().hex().upper()}')
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
            module_offset_1 = result_1.start() + noncasigchk_offset
            module_offset_2 = result_2.start() + nocntchk_offset
            offset_1 = '%06X' % (module_offset_1)
            offset_2 = '%06X' % (module_offset_2)
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
            pattern_diff_string_1 = read_data[pattern_diff_string_start_1:pattern_diff_string_end_1].hex().upper()
            pattern_diff_string_start_2 = module_offset_2 - 0x20
            pattern_diff_string_end_2 = pattern_diff_string_start_2 + 0x60
            pattern_diff_string_2 = read_data[pattern_diff_string_start_2:pattern_diff_string_end_2].hex().upper()
            noncasigchk_diffs[version] = pattern_diff_string_1
            nocntchk_diffs[version] = pattern_diff_string_2
            nonsigchk_offset_string = [module_name, patch_1_bytes, offset_1, hash]
            nocntchk_offset_string = [module_name, patch_2_bytes, offset_2, hash]
            nonsigchk_offsets[version] = nonsigchk_offset_string
            nocntchk_offsets[version] = nocntchk_offset_string
            if patch_1_byte in noncasigchk_cond:
                find_patterns.write(f'(FS-{module_name}) a "TBZ" arm instruction with ending of 0x{patch_1_byte} was found\n')
                if patch_2_byte in nocntchk_cond:
                    find_patterns.write(f'(FS-{module_name}) a "BL" arm instruction with ending of 0x{patch_2_byte} was found.\n\n')
                    find_patterns.write(f'(FS-{module_name}) both sys-patch strings are valid for FS-{module_name} for: {version}\n')
                    find_patterns.write(f'(FS-{module_name}) {version} NOCASIGCHK Sys-patch FS-{module_name} pattern found at: {offset_1}\n')
                    find_patterns.write(f'(FS-{module_name}) The ghidra-equivalent pattern used was : {noncasigchk_ghidra_pattern}\n')
                    find_patterns.write(f'(FS-{module_name}) The existing bytes at the first offset are: {patch_1_bytes}\n')
                    find_patterns.write(f'(FS-{module_name}) An arm "TBZ" condition is what is supposed to be patched\n')
                    find_patterns.write(f'(FS-{module_name}) {version} Second Sys-patch FS-FAT32 pattern found at: {offset_2}\n')
                    find_patterns.write(f'(FS-{module_name}) The ghidra-equivalent pattern used was : {nocntchk_ghidra_pattern}\n')
                    find_patterns.write(f'(FS-{module_name}) The existing bytes at the second offset are: {patch_2_bytes}')
                    find_patterns.write(f'(FS-{module_name}) An arm "BL" condition is what is supposed to be patched, it is found within the pattern.\n')
                    find_patterns.write(f'(FS-{module_name}) {version} FS-{module_name} SHA256 hash: {hash}\n\n')
                    find_patterns.write(f'(FS-{module_name}) a hekate string for this would be:\n\n')
                    find_patterns.write(f'#FS {version}-{module_name}\n')
                    find_patterns.write(f'[FS:{hash[:16]}]\n')
                    find_patterns.write(f'.nosigchk=0:0x{offset_2}:0x4:{patch_2_bytes},{nocntchk_patch}\n')
                    find_patterns.write(f'.nosigchk=0:0x{offset_1}:0x4:{patch_1_bytes},{noncasigchk_patch}\n\n')
                    find_patterns.write(f'(FS-{module_name}) NONCASIGCHK string for diff: \n \n{pattern_diff_string_1}\n\n')
                    find_patterns.write(f'(FS-{module_name}) NOCNTCHK string for diff: \n \n{pattern_diff_string_2}\n\n')
                else:
                    find_patterns.write(f'(FS-{module_name}) The second pattern doesnt match what it should match.\n\n\n')
                    print(f'DEBUG - (FS-{module_name}) {version} - PBS: {patch_2_bytes} - PB: {patch_2_byte} - OFS: {offset_2}')
            else:
                find_patterns.write(f'(FS-{module_name}) The first pattern doesnt match what it should match.\n\n\n')
                print(f'DEBUG - (FS-{module_name}) {version} - PBS: {patch_1_bytes} - PB: {patch_1_byte} - OFS: {offset_1}')
    decompressed_module.close()

es_pattern_diffs = {}
blockfirmwareupdates_pattern_diffs = {}
blankcal0crashfix_pattern_diffs = {}
nifm_pattern_diffs = {}
olsc_pattern_diffs = {}
fat32_noncasigchk_pattern_diffs = {}
exfat_noncasigchk_pattern_diffs = {}
fat32_nocntchk_pattern_diffs = {}
exfat_nocntchk_pattern_diffs = {}

es_pattern_offsets = {}
blockfirmwareupdates_pattern_offsets = {}
blankcal0crashfix_pattern_offsets = {}
nifm_pattern_offsets = {}
olsc_pattern_offsets = {}
fat32_noncasigchk_pattern_offsets = {}
exfat_noncasigchk_pattern_offsets = {}
fat32_nocntchk_pattern_offsets = {}
exfat_nocntchk_pattern_offsets = {}

def get_pattern_for_version(patterns: List[Pattern], version: str) -> Optional[Pattern]:
    """Get the matching pattern for a given firmware version"""
    for pattern in patterns:
        if MAKEHOSVERSION(pattern.min_version, pattern.max_version, version):
            return pattern
    return None

valid_versions = get_valid_version_folders('output')
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
    fs_noncasigchk_obj = next((p for p in FS_PATTERNS if 'noncasigchk' in p.name and MAKEHOSVERSION(p.min_version, p.max_version, current_firmware_version)), None)
    fs_nocntchk_obj = next((p for p in FS_PATTERNS if 'nocntchk' in p.name and MAKEHOSVERSION(p.min_version, p.max_version, current_firmware_version)), None)
    
    # Compile patterns
    es_pattern = pattern_to_regex_bytestring(es_pattern_obj.pattern_string) if es_pattern_obj else None
    nifm_pattern = pattern_to_regex_bytestring(nifm_pattern_obj.pattern_string) if nifm_pattern_obj else None
    olsc_pattern = pattern_to_regex_bytestring(olsc_pattern_obj.pattern_string) if olsc_pattern_obj else None
    blankcal0crashfix_pattern = pattern_to_regex_bytestring(nim_blankcal0_obj.pattern_string) if nim_blankcal0_obj else None
    blockfirmwareupdates_pattern = pattern_to_regex_bytestring(nim_blockfw_obj.pattern_string) if nim_blockfw_obj else None
    fs_noncasigchk_pattern = pattern_to_regex_bytestring(fs_noncasigchk_obj.pattern_string) if fs_noncasigchk_obj else None
    fs_nocntchk_pattern = pattern_to_regex_bytestring(fs_nocntchk_obj.pattern_string) if fs_nocntchk_obj else None

    # Get offsets and other metadata
    es_offset = es_pattern_obj.offset if es_pattern_obj else None
    es_headoffset = es_pattern_obj.headoffset if es_pattern_obj else None
    es_ghidra_pattern = format_sys_patch_string_to_ghidra_string(es_pattern_obj.pattern_string) if es_pattern_obj else None
    
    nifm_offset = nifm_pattern_obj.offset if nifm_pattern_obj else None
    nifm_headoffset = nifm_pattern_obj.headoffset if nifm_pattern_obj else None
    nifm_ghidra_pattern = format_sys_patch_string_to_ghidra_string(nifm_pattern_obj.pattern_string) if nifm_pattern_obj else None
    
    olsc_offset = olsc_pattern_obj.offset if olsc_pattern_obj else None
    olsc_headoffset = olsc_pattern_obj.headoffset if olsc_pattern_obj else None
    olsc_ghidra_pattern = format_sys_patch_string_to_ghidra_string(olsc_pattern_obj.pattern_string) if olsc_pattern_obj else None
    
    blankcal0crashfix_offset = nim_blankcal0_obj.offset if nim_blankcal0_obj else None
    blankcal0crashfix_headoffset = nim_blankcal0_obj.headoffset if nim_blankcal0_obj else None
    blankcal0crashfix_ghidra_pattern = format_sys_patch_string_to_ghidra_string(nim_blankcal0_obj.pattern_string) if nim_blankcal0_obj else None
    
    blockfirmwareupdates_offset = nim_blockfw_obj.offset if nim_blockfw_obj else None
    blockfirmwareupdates_headoffset = nim_blockfw_obj.headoffset if nim_blockfw_obj else None
    blockfirmwareupdates_ghidra_pattern = format_sys_patch_string_to_ghidra_string(nim_blockfw_obj.pattern_string) if nim_blockfw_obj else None
    
    fs_noncasigchk_offset = fs_noncasigchk_obj.offset if fs_noncasigchk_obj else None
    fs_noncasigchk_headoffset = fs_noncasigchk_obj.headoffset if fs_noncasigchk_obj else None
    fs_noncasigchk_ghidra_pattern = format_sys_patch_string_to_ghidra_string(fs_noncasigchk_obj.pattern_string) if fs_noncasigchk_obj else None
    
    fs_nocntchk_offset = fs_nocntchk_obj.offset if fs_nocntchk_obj else None
    fs_nocntchk_headoffset = fs_nocntchk_obj.headoffset if fs_nocntchk_obj else None
    fs_nocntchk_ghidra_pattern = format_sys_patch_string_to_ghidra_string(fs_nocntchk_obj.pattern_string) if fs_nocntchk_obj else None

    with open(f'output/{version}/{version}_patch_summary_with_diff_strings.txt', 'w') as find_patterns:
        patch_check_module(es_path, es_pattern, es_offset, es_headoffset, es_ghidra_pattern, mov0_patch, patch_size_4, es_cond, 'ES', find_patterns, es_pattern_diffs, es_pattern_offsets, None)

        patch_check_module(nifm_path, nifm_pattern, nifm_offset, nifm_headoffset, nifm_ghidra_pattern, ctest_patch, patch_size_20, ctest_cond, 'NIFM', find_patterns, nifm_pattern_diffs, nifm_pattern_offsets, None)

        if version_to_tuple(version) >= version_to_tuple("6.0.0"):
            patch_check_module(olsc_path, olsc_pattern, olsc_offset, olsc_headoffset, olsc_ghidra_pattern, ret1_patch, patch_size_4, bl_cond, 'OLSC', find_patterns, olsc_pattern_diffs, olsc_pattern_offsets, None)

        if version_to_tuple(version) >= version_to_tuple("17.0.0"):
            patch_check_module(nim_path, blankcal0crashfix_pattern, blankcal0crashfix_offset, blankcal0crashfix_headoffset, blankcal0crashfix_ghidra_pattern, mov2_patch, patch_size_4, adr_cond, 'NIM', find_patterns, blankcal0crashfix_pattern_diffs, blankcal0crashfix_pattern_offsets, None)

        patch_check_module(nim_path, blockfirmwareupdates_pattern, blockfirmwareupdates_offset, blockfirmwareupdates_headoffset, blockfirmwareupdates_ghidra_pattern, mov0_ret_patch, patch_size_8, block_fw_updates_cond, 'NIM', find_patterns, blockfirmwareupdates_pattern_diffs, blockfirmwareupdates_pattern_offsets, None)

        if version_to_tuple(version) >= version_to_tuple("10.0.0"):
            patch_check_fs(decompressed_fat32_path, fat32hash, fs_noncasigchk_pattern, fs_nocntchk_pattern, fs_noncasigchk_offset, fs_nocntchk_offset, fs_noncasigchk_ghidra_pattern, fs_nocntchk_ghidra_pattern, nop_patch, ret0_patch, tbz_cond, bl_cond, 'FAT32', find_patterns, fat32_noncasigchk_pattern_diffs, fat32_nocntchk_pattern_diffs, fat32_noncasigchk_pattern_offsets, fat32_nocntchk_pattern_offsets)
            if os.path.exists(decompressed_exfat_path):
                patch_check_fs(decompressed_exfat_path, exfathash, fs_noncasigchk_pattern, fs_nocntchk_pattern, fs_noncasigchk_offset, fs_nocntchk_offset, fs_noncasigchk_ghidra_pattern, fs_nocntchk_ghidra_pattern, nop_patch, ret0_patch, tbz_cond, bl_cond, 'EXFAT', find_patterns, exfat_noncasigchk_pattern_diffs, exfat_nocntchk_pattern_diffs, exfat_noncasigchk_pattern_offsets, exfat_nocntchk_pattern_offsets)

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
                    find_patterns.write(f'(SSL) {version} SSL buildid (and what .ips filename should be): {get_module_id(ssl_path)}\n\n')
                    find_patterns.write(f'(SSL) IPS patch bytes would be:\n')
                    find_patterns.write(f'(SSL) {ips32_magic}{patch1}{patch2}{patch3}{patch4}{eeof_magic}\n\n')
                else:
                    find_patterns.write(f'(SSL) one or more SSL patterns were not found\n\n')
        else:
            find_patterns.write(f'\n(SSL) only the very latest pattern is supported (21.0.0+), current version is: {version}\n\n')
    patch_summary_file = f'output/{version}/{version}_patch_summary_with_diff_strings.txt'  
    find_patterns.close()
        

if args.ams:
    package3_and_stratosphere.download_and_extract_package3_and_stratosphere_romfs()

    loader_path = f'package3_and_stratosphere_extracted/u_loader.kip1'
    compressed_loader_path = f'package3_and_stratosphere_extracted/loader.kip1' 

    if os.path.exists(compressed_loader_path):
        loader_pattern_obj = get_pattern_for_version(LOADER_PATTERNS, '10.0.0')
        loader_pattern = pattern_to_regex_bytestring(loader_pattern_obj.pattern_string) if loader_pattern_obj else None
        loader_offset = loader_pattern_obj.offset if loader_pattern_obj else None
        loader_headoffset = loader_pattern_obj.headoffset if loader_pattern_obj else None
        loader_ghidra_pattern = format_sys_patch_string_to_ghidra_string(loader_pattern_obj.pattern_string) if loader_pattern_obj else None
        loader_pattern_diffs = {}
        loader_pattern_offsets = {}
        loaderhash =  hashlib.sha256(open(compressed_loader_path, 'rb').read()).hexdigest().upper()
        with open(f'output/loader_patch_summary.txt', 'w') as find_patterns:
            patch_check_module(loader_path, loader_pattern, loader_offset, loader_headoffset, loader_ghidra_pattern, cmp_patch, patch_size_1, cmp_cond, 'LOADER', find_patterns, loader_pattern_diffs, loader_pattern_offsets, loaderhash)
        find_patterns.close()

    uncompressed_erpt_path = f'package3_and_stratosphere_extracted/uncompressed_erpt.nso0'
    if os.path.exists(uncompressed_erpt_path):
        erpt_pattern_diffs = {}
        erpt_pattern_offsets = {}
        erpt_pattern_obj = get_pattern_for_version(ERPT_PATTERNS, '10.0.0')
        erpt_pattern = pattern_to_regex_bytestring(erpt_pattern_obj.pattern_string) if erpt_pattern_obj else None
        erpt_offset = erpt_pattern_obj.offset if erpt_pattern_obj else None
        erpt_headoffset = erpt_pattern_obj.headoffset if erpt_pattern_obj else None
        erpt_ghidra_pattern = format_sys_patch_string_to_ghidra_string(erpt_pattern_obj.pattern_string) if erpt_pattern_obj else None

        with open(f'output/erpt_patch_summary.txt', 'w') as find_patterns:
            patch_check_module(uncompressed_erpt_path, erpt_pattern, erpt_offset, erpt_headoffset, erpt_ghidra_pattern, mov0_ret_patch, patch_size_8, sub_cond, 'ERPT', find_patterns, erpt_pattern_diffs, erpt_pattern_offsets, None)
        find_patterns.close()

print("\n" + "="*80)
print("Writing pattern diffs to scripts/pattern_diffs.py...")
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

    if args.ams:
        with open('output/loader_debug_logs.txt', 'w', encoding='utf-8') as logs:
            for version, debug_logs in sorted(loader_pattern_offsets.items(), key=lambda x: version_to_tuple(x[0])):
                logs.write(f"    '{version}': {debug_logs},\n")
        logs.close()

except Exception as e:
    print(f"Error writing pattern_diffs.py: {e}")
    sys.exit(1)

try:
    with open('scripts/pattern_diffs.py', 'w', encoding='utf-8') as patterns_file:
        patterns_file.write("# Auto-generated pattern diff strings\n")
        patterns_file.write("# Generated from find_patterns.py\n\n")
        
        # Write ES patterns
        patterns_file.write("es_pattern_diffs = {\n")
        for version, diff_str in sorted(es_pattern_diffs.items(), key=lambda x: version_to_tuple(x[0])):
            py_bytes = hex_string_to_python_bytes(diff_str)
            patterns_file.write(f"    '{version}': {py_bytes},\n")
        patterns_file.write("}\n\n")

        # Write NIM blankcal0crashfix patterns
        patterns_file.write("blankcal0crashfix_pattern_diffs = {\n")
        for version, diff_str in sorted(blankcal0crashfix_pattern_diffs.items(), key=lambda x: version_to_tuple(x[0])):
            py_bytes = hex_string_to_python_bytes(diff_str)
            patterns_file.write(f"    '{version}': {py_bytes},\n")
        patterns_file.write("}\n\n")

        # Write NIM blockfirmwareupdate patterns
        patterns_file.write("blockfirmwareupdates_pattern_diffs = {\n")
        for version, diff_str in sorted(blockfirmwareupdates_pattern_diffs.items(), key=lambda x: version_to_tuple(x[0])):
            py_bytes = hex_string_to_python_bytes(diff_str)
            patterns_file.write(f"    '{version}': {py_bytes},\n")
        patterns_file.write("}\n\n")
        
        # Write NIFM patterns
        patterns_file.write("nifm_pattern_diffs = {\n")
        for version, diff_str in sorted(nifm_pattern_diffs.items(), key=lambda x: version_to_tuple(x[0])):
            py_bytes = hex_string_to_python_bytes(diff_str)
            patterns_file.write(f"    '{version}': {py_bytes},\n")
        patterns_file.write("}\n\n")

        # Write OLSC patterns
        patterns_file.write("olsc_pattern_diffs = {\n")
        for version, diff_str in sorted(olsc_pattern_diffs.items(), key=lambda x: version_to_tuple(x[0])):
            py_bytes = hex_string_to_python_bytes(diff_str)
            patterns_file.write(f"    '{version}': {py_bytes},\n")
        patterns_file.write("}\n\n")
        
        # Write FAT32 noncasigchk patterns 
        patterns_file.write("fat32_noncasigchk_pattern_diffs = {\n")
        for version, diff_str in sorted(fat32_noncasigchk_pattern_diffs.items(), key=lambda x: version_to_tuple(x[0])):
            py_bytes = hex_string_to_python_bytes(diff_str)
            patterns_file.write(f"    '{version}': {py_bytes},\n")
        patterns_file.write("}\n\n")

        # Write EXFAT noncasigchk patterns
        patterns_file.write("exfat_noncasigchk_pattern_diffs = {\n")
        for version, diff_str in sorted(exfat_noncasigchk_pattern_diffs.items(), key=lambda x: version_to_tuple(x[0])):
            py_bytes = hex_string_to_python_bytes(diff_str)
            patterns_file.write(f"    '{version}': {py_bytes},\n")
        patterns_file.write("}\n\n")
        
        # Write FAT32 nocntchk patterns
        patterns_file.write("fat32_nocntchk_pattern_diffs = {\n")
        for version, diff_str in sorted(fat32_nocntchk_pattern_diffs.items(), key=lambda x: version_to_tuple(x[0])):
            py_bytes = hex_string_to_python_bytes(diff_str)
            patterns_file.write(f"    '{version}': {py_bytes},\n")
        patterns_file.write("}\n\n")
        
        # Write EXFAT nocntchk patterns
        patterns_file.write("exfat_nocntchk_pattern_diffs = {\n")
        for version, diff_str in sorted(exfat_nocntchk_pattern_diffs.items(), key=lambda x: version_to_tuple(x[0])):
            py_bytes = hex_string_to_python_bytes(diff_str)
            patterns_file.write(f"    '{version}': {py_bytes},\n")
        patterns_file.write("}\n")

        if args.ams:
            # Write LOADER patterns
            patterns_file.write("loader_pattern_diffs = {\n")
            for version, diff_str in sorted(loader_pattern_diffs.items(), key=lambda x: version_to_tuple(x[0])):
                py_bytes = hex_string_to_python_bytes(diff_str)
                patterns_file.write(f"    '{version}': {py_bytes},\n")
            patterns_file.write("}\n\n")

            # Write ERPT patterns
            patterns_file.write("erpt_pattern_diffs = {\n")
            for version, diff_str in sorted(erpt_pattern_diffs.items(), key=lambda x: version_to_tuple(x[0])):
                py_bytes = hex_string_to_python_bytes(diff_str)
                patterns_file.write(f"    '{version}': {py_bytes},\n")
            patterns_file.write("}\n\n")

    
    print(f"Successfully wrote pattern diffs to scripts/pattern_diffs.py")
    print(f"  - ES patterns: {len(es_pattern_diffs)} entries")
    print(f"  - NIM blankcal0crashfix patterns: {len(blankcal0crashfix_pattern_diffs)} entries")
    print(f"  - NIM blockfirmwareupdates patterns: {len(blockfirmwareupdates_pattern_diffs)} entries")
    print(f"  - NIFM patterns: {len(nifm_pattern_diffs)} entries")
    print(f"  - OLSC patterns: {len(olsc_pattern_diffs)} entries")
    print(f"  - FAT32 noncasigchk patterns: {len(fat32_noncasigchk_pattern_diffs)} entries")
    print(f"  - EXFAT noncasigchk patterns: {len(exfat_noncasigchk_pattern_diffs)} entries")
    print(f"  - FAT32 nocntchk patterns: {len(fat32_nocntchk_pattern_diffs)} entries")
    print(f"  - EXFAT nocntchk patterns: {len(exfat_nocntchk_pattern_diffs)} entries")
    if args.ams:
        print(f"  - LOADER patterns: {len(erpt_pattern_diffs)} entries")
        print(f"  - ERPT patterns: {len(loader_pattern_diffs)} entries")
    
except Exception as e:
    print(f"Error writing pattern_diffs.py: {e}")
    sys.exit(1)

if os.path.exists('package3_and_stratosphere_extracted'):
    shutil.rmtree('package3_and_stratosphere_extracted')