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

import re
import sys
from typing import Tuple
import binascii

# vibecoded ai-slop function courtesy of grok4.1
def pattern_to_regex_bytestring(pattern: str) -> Tuple[bytes, re.Pattern, str]:
    pattern = pattern.strip()
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

latest_version = get_latest_firmware_version_from_provided_files()
version = latest_version
current_firmware_version = version

es_path = f'output/{version}/{version}_uncompressed_es.nso0'
nim_path = f'output/{version}/{version}_uncompressed_nim.nso0'
nifm_path = f'output/{version}/{version}_uncompressed_nifm.nso0'
ssl_path = f'output/{version}/{version}_uncompressed_ssl.nso0'
compressed_fat32_path = f'output/{version}/{version}_fat32_FS.kip1'
decompressed_fat32_path = f'output/{version}/{version}_fat32_uFS.kip1'
compressed_exfat_path = f'output/{version}/{version}_exfat_FS.kip1'
decompressed_exfat_path = f'output/{version}/{version}_exfat_uFS.kip1'

fat32hash = hashlib.sha256(open(compressed_fat32_path, 'rb').read()).hexdigest().upper()
if os.path.exists(compressed_exfat_path):
    exfathash = hashlib.sha256(open(compressed_exfat_path, 'rb').read()).hexdigest().upper()

# sys-patch logic explanation:
# "(49, 0,) +49" (nifm/ctest) from start from the start the string found in it's entirity, as sys-patch tests things stupid, then it reads from 0x0 of the end in decimals where the "head" was placed (49),
# and the 4th byte from there is what is tested (for most cond checks), the next number determines where from the tested byte is being patched. (should be 0, otherwise its not testing the bytes being patched!)
# should be noted ams loader patch being (6,2) is different from this general rule of not testing for what is being patched.
# as it finds searches for "009401C0BE12(6)1F00(2)", testing 4 bytes from from offset (6) for cmp_cond byte of "6B",
# and then applies the patch of "00", two bytes offset after the testing point (0)1F00(2), turning (6)1F00(2)->01<-6B - cmp w0, w1 -  into (6)1F00(2)->00<-6B - cmp w0, w0

ssl_pattern1 = rb'\x08\x00\x80\x12\x69\x12\x05\x91\x7f\x1e\x00\xf9\x68\x42\x00\xb9'
ssl_pattern2 = rb'\x24\x09\x43\x7a\xa0\x00\x00\x54'
ssl_pattern3 = rb'\x88\x16\x00\x12'
ssl_offset1 = 16 # # ssl_pattern1
ssl_offset2 = 4 # ssl_pattern2
ssl_offset3 = 7 # ssl_pattern2
ssl_offset4 = 8 # ssl_pattern3
patch_magic = "5041544348" # "PATCH"
ips32_magic = "4950533332" # "IPS32"
eof_magic = "454F46" # "EOF"
eeof_magic = "45454F46" # "EEOF"
patchvalue1 = "1F2003D5" # FS (nop)
patchvalue2 = "E0031F2A" # FS (mov w0, wzr)
patchvalue3 = "E0031FAA" # ES, NIM (mov x0, xzr)
patchvalue4 = "00309AD2001EA1F2610100D4E0031FAAC0035FD6" # NIFM (mov x0, #0xd180 - movk x0, #0x8f0, lsl #16 - svc #0xb - mov x0, xzr - ret)
patchvalue5 = "08" # SSL
patchvalue6 = "1300" # SSL
patchvalue7 = "14" # SSL
patchvalue8 = "08008052" # SSL


def get_build_id(nso0):
    with open(nso0, 'rb') as f:
        f.seek(0x40)
        return binascii.hexlify(f.read(0x14)).decode('utf-8').upper()
    
FW_VER_ANY = '99.99.99'

if (MAKEHOSVERSION(f'1.0.0', '1.0.0', current_firmware_version)) == True:
    es_sys_patch_pattern = ('..00.....e0.0091..0094..4092...d1')
    es_pattern = pattern_to_regex_bytestring(es_sys_patch_pattern)
    es_offset = 16
    es_ghidra_pattern = format_sys_patch_string_to_ghidra_string(es_sys_patch_pattern)
    # { "es_1.0.0", "0x..00.....e0.0091..0094..4092...d1", 16, 0, and_cond, mov0_patch, mov0_applied, true, FW_VER_ANY, MAKEHOSVERSION(1,0,0) },
if (MAKEHOSVERSION(f'2.0.0', '8.1.1', current_firmware_version)) == True:
    es_sys_patch_pattern = ('..00.....e0.0091..0094..4092...a9')
    es_pattern = pattern_to_regex_bytestring(es_sys_patch_pattern)
    es_offset = 16
    es_ghidra_pattern = format_sys_patch_string_to_ghidra_string(es_sys_patch_pattern)
    # { "es_2.0.0-8.1.1", "0x..00.....e0.0091..0094..4092...a9", 16, 0, and_cond, mov0_patch, mov0_applied, true, MAKEHOSVERSION(2,0,0), MAKEHOSVERSION(8,1,1) },
if (MAKEHOSVERSION(f'9.0.0', '20.5.0', current_firmware_version)) == True:
    es_sys_patch_pattern = ('..00...0094a0..d1..ff97.......a9')
    es_pattern = pattern_to_regex_bytestring(es_sys_patch_pattern)
    es_offset = 16
    es_ghidra_pattern = format_sys_patch_string_to_ghidra_string(es_sys_patch_pattern)
    # { "es_9.0.0-20.5.0", "0x..00...0094a0..d1..ff97.......a9", 16, 0, mov2_cond, mov0_patch, mov0_applied, true, MAKEHOSVERSION(9,0,0), MAKEHOSVERSION(20,5,0) },
if (MAKEHOSVERSION(f'21.0.0', FW_VER_ANY, current_firmware_version)) == True:
    es_sys_patch_pattern = '..00....97a0..d1...97e003132a...a9'
    es_pattern = pattern_to_regex_bytestring(es_sys_patch_pattern)
    es_offset = 16
    es_ghidra_pattern = format_sys_patch_string_to_ghidra_string(es_sys_patch_pattern)
    # { "es_21.0.0+", "0x..00....97a0..d1...97e003132a...a9", 16, 0, mov2_cond, mov0_patch, mov0_applied, true, MAKEHOSVERSION(21,0,0), FW_VER_ANY }


if (MAKEHOSVERSION(f'1.0.0', '18.1.0', current_firmware_version)) == True:
    nifm_sys_patch_pattern = '....................F40300AA....F30314AAE00314AA9F0201397F8E04F8'
    nifm_pattern = pattern_to_regex_bytestring(nifm_sys_patch_pattern)
    nifm_offset = 0
    nifm_ghidra_pattern = format_sys_patch_string_to_ghidra_string(nifm_sys_patch_pattern)
    # { "ctest_1.0.0-18.1.0", "....................F40300AA....F30314AAE00314AA9F0201397F8E04F8", 16, -16, ctest_cond, ctest_patch, ctest_applied, true, FW_VER_ANY, MAKEHOSVERSION(18,1,0) },
if (MAKEHOSVERSION(f'19.0.0', '20.5.0', current_firmware_version)) == True:
    nifm_sys_patch_pattern = '14...........91...........97...............14'
    nifm_pattern = pattern_to_regex_bytestring(nifm_sys_patch_pattern)
    nifm_offset = 41
    nifm_ghidra_pattern = format_sys_patch_string_to_ghidra_string(nifm_sys_patch_pattern)
    # { "ctest_1.9.0-20.5.0", "14...........91...........97...............14", 41, 0, stp_cond, ctest_patch, ctest_applied, true, MAKEHOSVERSION(19,0,0), MAKEHOSVERSION(20,5,0) }
if (MAKEHOSVERSION(f'21.0.0', FW_VER_ANY, current_firmware_version)) == True:
    nifm_sys_patch_pattern = '14...........91...........97...............14'
    nifm_pattern = pattern_to_regex_bytestring(nifm_sys_patch_pattern)
    nifm_offset = 49
    nifm_ghidra_pattern = format_sys_patch_string_to_ghidra_string(nifm_sys_patch_pattern)
    # { "ctest_21.0.0+", "14...........91...........97...............14", 49, 0, stp_cond, ctest_patch, ctest_applied, true, MAKEHOSVERSION(21,0,0), FW_VER_ANY }


if (MAKEHOSVERSION(f'17.0.0', '20.5.0', current_firmware_version)) == True:
    nim_sys_patch_pattern = '.0F00351F2003D5'
    nim_pattern = pattern_to_regex_bytestring(nim_sys_patch_pattern)
    nim_offset = 8
    nim_ghidra_pattern = format_sys_patch_string_to_ghidra_string(nim_sys_patch_pattern)
    # { "nim_17.0.0-20.5.0", "0x.0F00351F2003D5", 8, 0, adr_cond, mov2_patch, mov2_applied, true, MAKEHOSVERSION(17,0,0), MAKEHOSVERSION(20,5,0) }
if (MAKEHOSVERSION(f'21.0.0', FW_VER_ANY, current_firmware_version)) == True:
    nim_sys_patch_pattern = '.0700351F2003D5'
    nim_pattern = pattern_to_regex_bytestring(nim_sys_patch_pattern)
    nim_offset = 8
    nim_ghidra_pattern = format_sys_patch_string_to_ghidra_string(nim_sys_patch_pattern)
    # { "nim_21.0.0+", "0x.0700351F2003D5", 8, 0, adr_cond, mov2_patch, mov2_applied, true, MAKEHOSVERSION(21,0,0), FW_VER_ANY },


if (MAKEHOSVERSION(f'10.0.0', '16.1.0', current_firmware_version)) == True:
    fs_sys_patch_pattern_1 = '0036.......71..0054..4839'
    fs_pattern1 = pattern_to_regex_bytestring(fs_sys_patch_pattern_1)
    fs_offset1 = -2
    fs_ghidra_pattern1 = format_sys_patch_string_to_ghidra_string(fs_sys_patch_pattern_1)
    # { "noncasigchk_10.0.0-16.1.0", "0x0036.......71..0054..4839", -2, 0, tbz_cond, nop_patch, nop_applied, true, MAKEHOSVERSION(10,0,0), MAKEHOSVERSION(16,1,0) },
if (MAKEHOSVERSION(f'17.0.0', '20.5.0', current_firmware_version)) == True:
    fs_sys_patch_pattern_1 = '.94..0036.258052'
    fs_pattern1 = pattern_to_regex_bytestring(fs_sys_patch_pattern_1)
    fs_offset1 = 2
    fs_ghidra_pattern1 = format_sys_patch_string_to_ghidra_string(fs_sys_patch_pattern_1)
    # { "noncasigchk_17.0.0_20.5.0", "0x.94..0036.258052", 2, 0, tbz_cond, nop_patch, nop_applied, true, MAKEHOSVERSION(17,0,0), MAKEHOSVERSION(20,5,0) },
if (MAKEHOSVERSION(f'21.0.0', FW_VER_ANY, current_firmware_version)) == True:
    fs_sys_patch_pattern_1 = '.94..0036.........258052'
    fs_pattern1 = pattern_to_regex_bytestring(fs_sys_patch_pattern_1)
    fs_offset1 = 2
    fs_ghidra_pattern1 = format_sys_patch_string_to_ghidra_string(fs_sys_patch_pattern_1)
    # { "noncasigchk_21.0.0+", "0x.94..0036.........258052", 2, 0, tbz_cond, nop_patch, nop_applied, true, MAKEHOSVERSION(21,0,0), FW_VER_ANY }, // 21.0.0+


if (MAKEHOSVERSION(f'10.0.0', '18.1.0', current_firmware_version)) == True:
    fs_sys_patch_pattern_2 = '40f9...9408.0012.050071'
    fs_pattern2 = pattern_to_regex_bytestring(fs_sys_patch_pattern_2)
    fs_offset2 = 2
    fs_ghidra_pattern1 = format_sys_patch_string_to_ghidra_string(fs_sys_patch_pattern_1)
    # { "nocntchk_10.0.0-18.1.0", "0x40f9...9408.0012.050071", 2, 0, bl_cond, ret0_patch, ret0_applied, true, MAKEHOSVERSION(10,0,0), MAKEHOSVERSION(18,1,0) },
if (MAKEHOSVERSION(f'19.0.0', FW_VER_ANY, current_firmware_version)) == True:
    fs_sys_patch_pattern_2 = '40f9...94..40b9..0012'
    fs_pattern2 = pattern_to_regex_bytestring(fs_sys_patch_pattern_2)
    fs_offset2 = 2
    fs_ghidra_pattern2 = format_sys_patch_string_to_ghidra_string(fs_sys_patch_pattern_2)
    # { "nocntchk_19.0.0+", "0x40f9...94..40b9..0012", 2, 0, bl_cond, ret0_patch, ret0_applied, true, MAKEHOSVERSION(19,0,0), FW_VER_ANY },


with open(f'output/{version}/{version}_patch_summary.txt', 'w') as check_patches:
    with open(f'{es_path}', 'rb') as decompressed_es_nso:
        read_data = decompressed_es_nso.read()
        result = re.search(es_pattern, read_data)
        if not result:
            check_patches.write(f'(ES) {version} ES offset not found\n')
            check_patches.write(f'(ES) Sys-patch for ES string is invalid for: {version}\n\n')
        else:
            offset = '%06X' % (result.start() + es_offset)
            decompressed_es_nso.seek(result.start() + es_offset)
            es_patch_bytes = decompressed_es_nso.read(0x4).hex().upper()
            es_patch_byte = es_patch_bytes[-2:]
            patch = '%06X%s%s' % (result.start() + es_offset, '0004', f'{patchvalue3}')
            if es_patch_byte in ('2A', '92'):
                check_patches.write(f'(ES) a "MOV" arm instruction with ending of 0x{es_patch_byte} was found within the pattern\n')
                check_patches.write(f'(ES) Sys-patch for ES string still valid for: {version}\n')
                check_patches.write(f'(ES) Sys-patch ES pattern found at: {offset}\n') # 0x0736B0 for 21.0.0
                check_patches.write(f'(ES) The ghidra-equivalent pattern used was: {es_ghidra_pattern}\n')
                check_patches.write(f'(ES) The existing bytes at the offset are: {es_patch_bytes}\n') # mov w0, w19 / (E003132A) 21.0.0
                check_patches.write(f'(ES) An arm "MOV" condition is what is supposed to be patched at this offset\n')
                check_patches.write(f'(ES) {version} ES buildid (and what .ips filename should be): {get_build_id(es_path)}\n\n')
                check_patches.write(f'(ES) IPS patch bytes would be:\n')
                check_patches.write(f'(ES) {patch_magic}{patch}{eof_magic}\n\n')
            else:
                check_patches.write(f'(ES) a "MOV" arm instruction was either not found after the pattern, or is ends differently. Must be checked. Assume it is broken.\n\n')

    with open(f'{nifm_path}', 'rb') as decompressed_nifm_nso:
        read_data = decompressed_nifm_nso.read()
        result = re.search(nifm_pattern, read_data)
        if not result:
            check_patches.write(f'(NIFM) {version} NIFM offset not found\n')
            check_patches.write(f'(NIFM) Sys-patch for NIFM string is invalid for: {version}\n\n')
        else:
            offset = '%06X' % (result.start() + nifm_offset)
            decompressed_nifm_nso.seek(result.start() + nifm_offset)
            nifm_patch_bytes = decompressed_nifm_nso.read(0x4).hex().upper() # example for 21.0.0 FD7BBDA9 / stp x29, x30, [sp, #-0x30]!
            nifm_patch_byte = nifm_patch_bytes[-2:]
            patch = '%06X%s%s' % (result.start() + nifm_offset, '0014', f'{patchvalue4}')
            if nifm_patch_byte in ('A9'):
                check_patches.write(f'(NIFM) an "STP" arm instruction with ending of 0x{nifm_patch_byte} was found proceding the pattern\n')
                check_patches.write(f'(NIFM) Sys-patch for NIFM string still valid for: {version}\n')
                check_patches.write(f'(NIFM) Sys-patch NIFM pattern found at: {offset}\n') # 0x0890D0 for 21.0.0
                check_patches.write(f'(NIFM) The ghidra-equivalent pattern used was: {nifm_ghidra_pattern}\n')
                check_patches.write(f'(NIFM) The existing bytes at the offset are: {nifm_patch_bytes}\n') # stp x29, x30, [sp, #-0x30]! / (FD7BBDA9) 21.0.0
                check_patches.write(f'(NIFM) An arm "STP" condition is what is supposed to be patched at the offset right after the branch arm condition tested ("B")\n')
                check_patches.write(f'(NIFM) {version} NIFM buildid (and what .ips filename should be): {get_build_id(nifm_path)}\n\n')
                check_patches.write(f'(NIFM) IPS patch bytes would be:\n')
                check_patches.write(f'(NIFM) {patch_magic}{patch}{eof_magic}\n\n')
            else:
                if version_to_tuple(version) <= version_to_tuple("19.0.0"):
                    check_patches.write(f'(NIFM) Sys-patch for NIFM string still valid for: {version}\n')
                    check_patches.write(f'(NIFM) The existing bytes at the offset are: {nifm_patch_bytes}\n')
                    check_patches.write(f'(NIFM) {version} NIFM buildid (and what .ips filename should be): {get_build_id(nifm_path)}\n\n')
                    check_patches.write(f'(NIFM) {patch_magic}{patch}{eof_magic}\n\n')
                    check_patches.write(f'(NIFM) IPS patch bytes would be:\n')
                else:
                    check_patches.write(f'(NIFM) an STP arm instruction was either not found after the pattern, or is ends differently. Must be checked. Assume it is broken.\n\n')

    if version_to_tuple(version) >= version_to_tuple("17.0.0"):
        with open(f'{nim_path}', 'rb') as decompressed_nim_nso:
            read_data = decompressed_nim_nso.read()
            result = re.search(nim_pattern, read_data)
            if not result:
                check_patches.write(f'(NIM) {version} NIM offset not found\n')
                check_patches.write(f'(NIM) Sys-patch for NIM string is invalid for: {version}\n\n')
            else:
                offset = '%06X' % (result.start() + nim_offset)
                decompressed_nim_nso.seek(result.start() + nim_offset)
                nim_patch_bytes = decompressed_nim_nso.read(0x4).hex().upper()
                nim_patch_byte = nim_patch_bytes[-2:]
                patch = '%06X%s%s' % (result.start() + nim_offset, '0004', f'{patchvalue3}')
                if nim_patch_byte in ('10'):
                    check_patches.write(f'(NIM) a "ADR" arm instruction with ending of 0x{nim_patch_byte} was found within the pattern\n')
                    check_patches.write(f'(NIM) Sys-patch for NIM string still valid for: {version}\n')
                    check_patches.write(f'(NIM) Sys-patch NIM pattern found at: {offset}\n') # 0x18CCD4 for 21.0.0
                    check_patches.write(f'(NIM) The ghidra-equivalent pattern used was: {nim_ghidra_pattern}\n')
                    check_patches.write(f'(NIM) The existing bytes at the offset are: {nim_patch_bytes}\n') # adr x2, #0x29c / (E2140010) 21.0.0
                    check_patches.write(f'(NIM) An arm "ADR" condition is what is supposed to be patched at the offset right after the "CBNZ and "NOP" conditions the pattern finds\n')
                    check_patches.write(f'(NIM) {version} NIM buildid (and what .ips filename should be): {get_build_id(nim_path)}\n\n')
                    check_patches.write(f'(NIM) IPS patch bytes would be:\n')
                    check_patches.write(f'(NIM) {patch_magic}{patch}{eof_magic}\n\n')
                else:
                    check_patches.write(f'(NIM) an "ADR" arm instruction was either not found after the pattern, or is ends differently. Must be checked. Assume it is broken.\n')
    else:
        check_patches.write(f'\n(NIM) no patches needed or exist for prodinfo blanker crashfix, starts at version 17.0.0+ and current version is: {version}\n\n')

    if version_to_tuple(version) >= version_to_tuple("10.0.0"):
        with open(decompressed_fat32_path, 'rb') as fat32f:
            read_data = fat32f.read()
            result1 = re.search(fs_pattern1, read_data)
            result2 = re.search(fs_pattern2, read_data)
            if not result1:
                check_patches.write(f'(FS-FAT32) {version} First FS-FAT32 offset not found\n')
                check_patches.write(f'(FS-FAT32) Sys-patch for FS-FAT32 noncasigchk_new string is invalid for: {version}\n\n')
            elif not result2:
                check_patches.write(f'(FS-FAT32) {version} Second FS-FAT32 offset not found\n')
                check_patches.write(f'(FS-FAT32) Sys-patch for FS-FAT32 nocntchk2 string is invalid for: {version}\n\n')
            else:
                offset1 = '%06X' % (result1.start() + fs_offset1)
                offset2 = '%06X' % (result2.start() + fs_offset2)
                fat32f.seek(result1.start() + fs_offset1)
                fat32_patch1_bytes = fat32f.read(0x4).hex().upper()
                fat32_patch1_byte = fat32_patch1_bytes[-2:]
                fat32f.seek(result2.start() + fs_offset2)
                fat32_patch2_bytes = fat32f.read(0x4).hex().upper()
                fat32_patch2_byte = fat32_patch2_bytes[-2:]
                if fat32_patch1_byte in ('36'):
                    check_patches.write(f'(FS-FAT32) a "TBZ" arm instruction with ending of 0x{fat32_patch1_byte} was found within the pattern, first pattern verified\n')
                    if fat32_patch2_byte in ('94'):
                        check_patches.write(f'(FS-FAT32) a "BL" arm instruction with ending of 0x{fat32_patch2_byte} was found within the pattern, second pattern verified\n\n')
                        check_patches.write(f'(FS-FAT32) both sys-patch strings are valid for FS-FAT32 for: {version}\n')
                        check_patches.write(f'(FS-FAT32) {version} First Sys-patch FS-FAT32 pattern found at: {offset1}\n') # 0x026A60 for 21.0.0
                        check_patches.write(f'(FS-FAT32) The ghidra-equivalent pattern used was (21.0.0+) : {fs_ghidra_pattern1}\n') # changed in 21.0.0
                        check_patches.write(f'(FS-FAT32) The existing bytes at the first offset are: {fat32_patch1_bytes}\n') # tbz w0, #0, #0x120 / (00090036) 21.0.0
                        check_patches.write(f'(FS-FAT32) An arm "TBZ" condition is what is supposed to be patched, it is found within the pattern.\n')
                        check_patches.write(f'(FS-FAT32) {version} Second Sys-patch FS-FAT32 pattern found at: {offset2}\n') # 0x07FB88 for 21.0.0
                        check_patches.write(f'(FS-FAT32) The ghidra-equivalent pattern used was (19.0.0+) : {fs_ghidra_pattern2}\n')
                        check_patches.write(f'(FS-FAT32) The existing bytes at the second offset are: {fat32_patch2_bytes}') # bl #0xe3048 / (128C0394) 21.0.0
                        check_patches.write(f'(FS-FAT32) An arm "BL" condition is what is supposed to be patched, it is found within the pattern.\n')
                        check_patches.write(f'(FS-FAT32) {version} FS-FAT32 SHA256 hash: {fat32hash}\n\n')
                        check_patches.write(f'(FS-FAT32) a hekate string for this would be:\n\n')
                        check_patches.write(f'#FS {version}-Fat32\n')
                        check_patches.write(f'[FS:{fat32hash[:16]}]\n')
                        check_patches.write(f'.nosigchk=0:0x{offset2}:0x4:{fat32_patch2_bytes},{patchvalue2}\n')
                        check_patches.write(f'.nosigchk=0:0x{offset1}:0x4:{fat32_patch1_bytes},{patchvalue1}\n\n')
                    else:
                        check_patches.write(f'(FS-FAT32) The second pattern doesnt match what it should match.\n\n\n')
                else:
                    check_patches.write(f'(FS-FAT32) The first pattern doesnt match what it should match.\n\n\n')
        fat32f.close()
    else:
        check_patches.write(f'\n(FS-FAT32) both patches for FS start at 10.0.0+, this is version {version}\n\n')

    if version_to_tuple(version) >= version_to_tuple("10.0.0"):
        if os.path.exists(decompressed_exfat_path):
            with open(decompressed_exfat_path, 'rb') as exfatf:
                read_data = exfatf.read()
                result1 = re.search(fs_pattern1, read_data)
                result2 = re.search(fs_pattern2, read_data)
                if not result1:
                    check_patches.write(f'(FS-EXFAT) {version} First FS-ExFAT offset not found\n')
                    check_patches.write(f'(FS-EXFAT) Sys-patch for FS-ExFAT noncasigchk_new string is invalid for: {version}\n\n')
                elif not result2:
                    check_patches.write(f'(FS-EXFAT) {version} Second FS-ExFAT offset not found\n')
                    check_patches.write(f'(FS-EXFAT) Sys-patch for FS-ExFAT nocntchk2 string is invalid for: {version}\n\n')
                else:
                    offset1 = '%06X' % (result1.start() + fs_offset1)
                    offset2 = '%06X' % (result2.start() + fs_offset2)
                    exfatf.seek(result1.start() + fs_offset1)
                    exfat_patch1_bytes = exfatf.read(0x4).hex().upper()
                    exfat_patch1_byte = exfat_patch1_bytes[-2:]
                    exfatf.seek(result2.start() + fs_offset2)
                    exfat_patch2_bytes = exfatf.read(0x4).hex().upper()
                    exfat_patch2_byte = exfat_patch2_bytes[-2:]
                    if exfat_patch1_byte in ('36'):
                        check_patches.write(f'(FS-EXFAT) a "TBZ" arm instruction with ending of 0x{exfat_patch1_byte} was found within the pattern, first pattern verified\n')
                        if exfat_patch2_byte in ('94'):
                            check_patches.write(f'(FS-EXFAT) a "BL" arm instruction with ending of 0x{exfat_patch2_byte} was found within the pattern, second pattern verified\n\n')
                            check_patches.write(f'(FS-EXFAT) both sys-patch strings are valid for FS-exFAT for: {version}\n')
                            check_patches.write(f'(FS-EXFAT) {version} First Sys-patch FS-ExFAT pattern found at: {offset1}\n') # 0x026A60 for 21.0.0
                            check_patches.write(f'(FS-EXFAT) The ghidra-equivalent pattern used was (21.0.0+) : {fs_ghidra_pattern1}\n') # changed in 21.0.0
                            check_patches.write(f'(FS-EXFAT) The existing bytes at the first offset are: {exfat_patch1_bytes}\n') # tbz w0, #0, #0x120 / (00090036) 21.0.0
                            check_patches.write(f'(FS-EXFAT) An arm "TBZ" condition is what is supposed to be patched, it is found within the pattern.\n')
                            check_patches.write(f'(FS-EXFAT) {version} Second Sys-patch FS-ExFAT pattern found at: {offset2}\n') # 0x07FB88 for 21.0.0
                            check_patches.write(f'(FS-EXFAT) The ghidra-equivalent pattern used was (19.0.0+) : {fs_ghidra_pattern2}2\n')
                            check_patches.write(f'(FS-EXFAT) The existing bytes at the second offset are: {exfat_patch2_bytes}\n') # bl #0xee1a8 / (6AB80394) 21.0.0
                            check_patches.write(f'(FS-EXFAT) An arm "BL" condition is what is supposed to be patched, it is found within the pattern.\n')
                            check_patches.write(f'(FS-EXFAT) {version} FS-ExFAT SHA256 hash: {exfathash}\n\n')
                            check_patches.write(f'(FS-EXFAT) a hekate string for this would be:\n\n')
                            check_patches.write(f'#FS {version}-ExFAT\n')
                            check_patches.write(f'[FS:{exfathash[:16]}]\n')
                            check_patches.write(f'.nosigchk=0:0x{offset2}:0x4:{exfat_patch2_bytes},{patchvalue2}\n')
                            check_patches.write(f'.nosigchk=0:0x{offset1}:0x4:{exfat_patch1_bytes},{patchvalue1}\n\n')
                        else:
                            check_patches.write(f'(FS-EXFAT) The second pattern doesnt match what it should match.\n\n\n')    
                    else:
                        check_patches.write(f'(FS-EXFAT) The first pattern doesnt match what it should match.\n\n\n')
            exfatf.close()
        else:
            check_patches.write(f'(FS-EXFAT) FS-exFAT was skipped for: {version}, due to missing NCA file for exfat in the provided firmware files.\n\n\n')
    else:
        check_patches.write(f'\n(FS-EXFAT) both patches for FS start at 10.0.0+, this is version {version}\n\n')



    if version_to_tuple(version) >= version_to_tuple("21.0.0"):
        with open(f'{ssl_path}', 'rb') as decompressed_ssl_nso:
            read_data = decompressed_ssl_nso.read()
            result1 = re.search(ssl_pattern1, read_data)
            result2 = re.search(ssl_pattern2, read_data)
            result3 = re.search(ssl_pattern3, read_data)
            if not result:
                check_patches.write(f'(SSL) {version} SSL pattern 1 no match found\n')
                check_patches.write(f'(SSL) SSL pattern 1 is invalid for: {version}\n\n')
            if not result2:
                check_patches.write(f'(SSL) {version} SSL pattern 2 no match found\n')
                check_patches.write(f'(SSL) SSL pattern 2 is invalid for: {version}\n\n')
            if not result3:
                check_patches.write(f'(SSL) {version} SSL pattern 3 no match found\n')
                check_patches.write(f'(SSL) SSL pattern 3 is invalid for: {version}\n\n')
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
                check_patches.write(f'(SSL) patterns found results for: {version}\n')
                check_patches.write(f'(SSL) pattern 1 found at: {offset1} ## 21.0.0+ 0x119B60\n') 
                check_patches.write(f'(SSL) The ghidra-equivalent pattern used was: 08 00 80 12 69 12 05 91 7f 1e 00 f9 68 42 00 b9\n')
                check_patches.write(f'(SSL) The existing bytes at the offset are: {ssl_patch1_bytes}\n') # 21.0.0+ // 680080D2 // mov x8, #3
                check_patches.write(f'(SSL) this is patched out to become {patchvalue5}0080D2 (mov x8, #0), to make make register x8 (x10 20.5.0 and below) zero, so that the movk turns the value used into 0x100000000 instead of 0x100000003 - seen in the ghidra decompiled view\n')
                check_patches.write(f'(SSL) pattern 2 found at: {offset2} ## 21.0.0+ 0x11A914\n') 
                check_patches.write(f'(SSL) pattern 3 found at: {offset3} ## 21.0.0+ 0x11A917\n') 
                check_patches.write(f'(SSL) The ghidra-equivalent pattern used was: 24 09 43 7a a0 00 00 54\n')
                check_patches.write(f'(SSL) The existing bytes at the two offsets combined are: {ssl_patch2_bytes}\n') # 21.0.0+ // A0000054 // b.eq #0x14
                check_patches.write(f'(SSL) this is patched out to become  {patchvalue6}00{patchvalue7} (b #0x4c) to target the second branch instead of comparing values (b.eq #0x14) and going to the first one\n')
                check_patches.write(f'(SSL) pattern 4 found at: {offset4} ## 21.0.0+ 0x11A968\n') 
                check_patches.write(f'(SSL) The ghidra-equivalent pattern used was: 88 16 00 12\n')
                check_patches.write(f'(SSL) The existing bytes at the offset are: {ssl_patch3_bytes}\n') # 21.0.0+ // 684601B9 // str w8, [x19, #0x144]
                check_patches.write(f'(SSL) this is patched out to become {patchvalue8} (mov w8, #0), to prepare register w8 with a zero, for the purpose of making the function return 0 (success) later on.\n')
                check_patches.write(f'(SSL) {version} SSL buildid (and what .ips filename should be): {get_build_id(ssl_path)}\n\n')
                check_patches.write(f'(SSL) IPS patch bytes would be:\n')
                check_patches.write(f'(SSL) {ips32_magic}{patch1}{patch2}{patch3}{patch4}{eeof_magic}\n\n')
            else:
                check_patches.write(f'(SSL) one or more SSL patterns were not found\n\n')
    else:
        check_patches.write(f'\n(SSL) only the very latest pattern is supported (21.0.0+), current version is: {version}\n\n')
check_patches.close()



patch_summary_file = f'output/{version}/{version}_patch_summary.txt'
print_patch_summary(patch_summary_file)