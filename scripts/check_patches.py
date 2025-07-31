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
import sys
import hashlib
import os
import process_firmware
from keys import RootKeys
from key_sources import KeySources
from pathlib import Path

es_path = "es.nso0"
nim_path = "nim.nso0"
nifm_path = "nifm.nso0"
compressed_fat32_path = "FS.kip1"
decompressed_fat32_path = "uFS.kip1"
compressed_exfat_path = "NONE"
decompressed_exfat_path = "NONE"

fat32hash = hashlib.sha256(open(compressed_fat32_path, 'rb').read()).hexdigest().upper()
if os.path.exists(compressed_exfat_path):
    exfathash = hashlib.sha256(open(compressed_exfat_path, 'rb').read()).hexdigest().upper()

root_keys = RootKeys()
key_sources = KeySources()
mariko_master_kek_source = key_sources.mariko_master_kek_sources[-1]

with open('sorted_firmware/by-type/Data/0100000000000809/romfs/file', 'rb') as file:
    data_read = file.read()
    firmware_version = data_read[0x68:0x6E].decode('utf-8')
    file.close()

version = firmware_version

def get_build_id(nso0):
    with open(nso0, 'rb') as f:
        f.seek(0x40)
        return f.read(0x14).hex().upper()

with open(f'{es_path}', 'rb') as decompressed_es_nso:
    read_data = decompressed_es_nso.read()
    result = re.search(rb'.{2}\x00.{3}\x00\x94\xa0.{2}\xd1.{2}\xff\x97.{7}\xa9', read_data)
    # { "es3", "0x..00...0094a0..d1..ff97.......a9", 16, 0, mov2_cond, mov0_patch, mov0_applied, true, MAKEHOSVERSION(9,0,0), FW_VER_ANY }, //9.0.0 - 19.0.0+
    if not result:
        print(f'{version} ES offset not found\n')
        print(f'Sys-patch for ES string is invalid for: {version}\n\n')
    else:
        if result.group(0)[19:20] == bytes([0x2A]) or bytes([0x92]): # mov2_cond check
            offset = '%06X' % (result.start() + 0x10)
            decompressed_es_nso.seek(result.start() + 0x10 + 0x3)
            es_patch_byte = decompressed_es_nso.read(0x1).hex().upper()
            if es_patch_byte in ('2A', '92'):
                print(f'a "MOV" arm instruction with ending of 0x{es_patch_byte} was found within the pattern\n')
                print(f'Sys-patch for ES string still valid for: {version}\n')
                print(f'Sys-patch ES pattern found at: {offset}\n')
                print(f'The ghidra-equivalent pattern used was: .. .. 00 .. .. .. 00 94 a0 .. .. d1 .. .. ff 97 .. .. .. .. .. .. .. a9\n')
                print(f'An arm "MOV" condition is what is supposed to be patched at this offset\n')
                print(f'{version} ES buildid: {get_build_id(es_path)}\n')
            else:
                print('a "MOV" arm instruction was either not found after the pattern, or is ends differently. Must be checked. Assume it is broken.\n\n')
        else:
            print(f'ARM instruction does not match expected result, sys-patch for ES wont work.\n\n')

with open(f'{nifm_path}', 'rb') as decompressed_nifm_nso:
    read_data = decompressed_nifm_nso.read()
    result = re.search(rb'\x14.{11}\x91.{11}\x97.{15}\x14', read_data)
    # { "ctest", "....................20F40300AA....F30314AAE00314AA9F0201397F8E04F8", 16, -16, ctest_cond, ctest_patch, ctest_applied, true, FW_VER_ANY },
    # { "ctest2", "14...........91...........97...............14", 37, 4, b_cond, ctest_patch, ctest_applied, true, MAKEHOSVERSION(19,0,0), FW_VER_ANY }, //19.1.0 - 20.0.1+
    if not result:
        print(f'{version} NIFM offset not found\n')
        print(f'Sys-patch for NIFM string is invalid for: {version}\n\n')
    else:
        if result.group(0)[40:41] == bytes([0x14]): # b_cond check (what is being patched is STP)
            offset = '%06X' % (result.start() + 0x29) # "+41" from start should match ctest2 sys-patch logic, but it should be +37 as sys-patch tests things stupid, then + 0x4
            decompressed_nifm_nso.seek(result.start() + 0x2c)
            nifm_patch_byte = decompressed_nifm_nso.read(0x1).hex().upper()
            if nifm_patch_byte in ('A9'):
                print(f'an "STP" arm instruction with ending of 0x{nifm_patch_byte} was found proceding the pattern\n')
                print(f'Sys-patch for NIFM string still valid for: {version}\n')
                print(f'Sys-patch NIFM pattern found at: {offset}\n')
                print(f'The ghidra-equivalent pattern used was: 14 .. .. .. .. .. .. .. .. .. .. .. 91 .. .. .. .. .. .. .. .. .. .. .. 97 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. 14\n')
                print(f'An arm "STP" condition is what is supposed to be patched at the offset right after the branch arm condition tested ("B")\n')
                print(f'{version} NIFM buildid: {get_build_id(nifm_path)}\n')
            else:
                print('an STP arm instruction was either not found after the pattern, or is ends differently. Must be checked. Assume it is broken. - If this happens, add (new) and change the ctest2 cond check to a stp_cond ("0xA9") check ("41, 0, stp_cond, ctest_patch, ctest_applied"") (\n\n')
        else:
            print('ARM instruction does not match expected result, sys-patch for NIFM wont work.\n\n')

with open(f'{nim_path}', 'rb') as decompressed_nim_nso:
    read_data = decompressed_nim_nso.read()
    result = re.search(rb'.\x0F\x00\x35\x1F\x20\x03\xD5....', read_data)
    # { "nim", "0x.0F00351F2003D5", 8, 0, adr_cond, mov2_patch, mov2_applied, true, MAKEHOSVERSION(17,0,0), FW_VER_ANY },
    if not result:
        print(f'{version} NIM offset not found\n')
        print(f'Sys-patch for NIM string is invalid for: {version}\n\n')
    else:
        if result.group(0)[11:12] == bytes([0x10]): # adr_cond check
            offset = '%06X' % (result.start() + 0x8)
            decompressed_nim_nso.seek(result.start() + 0x8 + 0x3)
            nim_patch_byte = decompressed_nim_nso.read(0x1).hex().upper()
            if nim_patch_byte in ('10'):
                print(f'a "ADR" arm instruction with ending of 0x{nim_patch_byte} was found within the pattern\n')
                print(f'Sys-patch for NIM string still valid for: {version}\n')
                print(f'Sys-patch NIM pattern found at: {offset}\n')
                print(f'The ghidra-equivalent pattern used was: .. 0F 00 35 1F 20 03 D5 .. .. .. ..\n')
                print(f'An arm "ADR" condition is what is supposed to be patched at the offset right after the "CBNZ and "NOP" conditions the pattern finds\n')
                print(f'{version} NIM buildid: {get_build_id(nim_path)}\n')
            else:
                print('an "ADR" arm instruction was either not found after the pattern, or is ends differently. Must be checked. Assume it is broken.\n\n')
        else:
            print('ARM instruction does not match expected result, sys-patch for NIM wont work.\n\n')


fspattern1 = rb'.\x94.{2}\x00\x36.\x25\x80\x52'
# { "noncasigchk_new", "0x.94..0036.258052", 2, 0, tbz_cond, nop_patch, nop_applied, true, MAKEHOSVERSION(17,0,0), FW_VER_ANY }, // 17.0.0 - 19.0.0+
fsoffset1 = 0x2

fspattern2 = rb'\x40\xf9.{3}\x94.{2}\x40\xb9.{2}\x00\x12'
# { "nocntchk2", "0x40f9...94..40b9..0012", 2, 0, bl_cond, ret0_patch, ret0_applied, true, MAKEHOSVERSION(19,0,0), FW_VER_ANY },
fsoffset2 = 0x2
patchvalue = "E0031F2A"

with open(decompressed_fat32_path, 'rb') as fat32f:
    read_data = fat32f.read()
    result1 = re.search(fspattern1, read_data)
    result2 = re.search(fspattern2, read_data)
    if not result1:
        print(f'{version} First FS-FAT32 offset not found\n')
        print(f'Sys-patch for FS-FAT32 noncasigchk_new string is invalid for: {version}\n')
    elif not result2:
        print(f'{version} Second FS-FAT32 offset not found\n')
        print(f'Sys-patch for FS-FAT32 nocntchk2 string is invalid for: {version}\n')
    else:
        if result1.group(0)[5:6] == bytes([0x36]) and result2.group(0)[5:6] == bytes([0x94]): # tbz_cond and bl_cond check
            offset1 = '%06X' % (result1.start() + fsoffset1)
            offset2 = '%06X' % (result2.start() + fsoffset2)
            fat32f.seek(result1.start() + fsoffset1 + 0x3)
            fat32_patch1_byte = fat32f.read(0x1).hex().upper()
            fat32f.seek(result2.start() + fsoffset2 + 0x3)
            fat32_patch2_byte = fat32f.read(0x1).hex().upper()
            if fat32_patch1_byte in ('36'):
                print(f'a "TBZ" arm instruction with ending of 0x{fat32_patch1_byte} was found within the pattern, first pattern verified\n')
                if fat32_patch2_byte in ('94'):
                    print(f'a "BL" arm instruction with ending of 0x{fat32_patch2_byte} was found within the pattern, second pattern verified\n')
                    print(f'both sys-patch strings are valid for FS-FAT32 for: {version}\n')
                    print(f'{version} First Sys-patch FS-FAT32 pattern found at: {offset1}\n')
                    print(f'The ghidra-equivalent pattern used was (11.0.0+) : .. 94 .. .. 00 36 .. 25 80 52\n')
                    print(f'An arm "TBZ" condition is what is supposed to be patched, it is found within the pattern.\n')
                    print(f'{version} Second Sys-patch FS-FAT32 pattern found at: {offset2}\n')
                    print(f'The ghidra-equivalent pattern used was (19.0.0+) : 40 f9 .. .. .. 94 .. .. 40 b9 .. .. 00 12\n')
                    print(f'An arm "BL" condition is what is supposed to be patched, it is found within the pattern.\n')
                    print(f'{version} FS-FAT32 SHA256 hash: {fat32hash}\n\n')
            else:
                print('The first pattern doesnt match what it should match.\n\n')
        else:
            print('sys-patch wont be able to patch FS properly\n\n')
fat32f.close()

if os.path.exists(decompressed_exfat_path):
    with open(decompressed_exfat_path, 'rb') as exfatf:
        read_data = exfatf.read()
        result1 = re.search(fspattern1, read_data)
        result2 = re.search(fspattern2, read_data)
        if not result1:
            print(f'{version} First FS-ExFAT offset not found\n')
            print(f'Sys-patch for FS-ExFAT noncasigchk_new string is invalid for: {version}\n')
        elif not result2:
            print(f'{version} Second FS-ExFAT offset not found\n')
            print(f'Sys-patch for FS-ExFAT nocntchk2 string is invalid for: {version}\n')
        else:
            if result1.group(0)[5:6] == bytes([0x36]) and result2.group(0)[5:6] == bytes([0x94]): # tbz_cond and bl_cond check
                offset1 = '%06X' % (result1.start() + fsoffset1)
                offset2 = '%06X' % (result2.start() + fsoffset2)
                exfatf.seek(result1.start() + fsoffset1 + 0x3)
                exfat_patch1_byte = exfatf.read(0x1).hex().upper()
                exfatf.seek(result2.start() + fsoffset2 + 0x3)
                exfat_patch2_byte = exfatf.read(0x1).hex().upper()
                if exfat_patch1_byte in ('36'):
                    print(f'a "TBZ" arm instruction with ending of 0x{exfat_patch1_byte} was found within the pattern, first pattern verified\n')
                    if exfat_patch2_byte in ('94'):
                        print(f'a "BL" arm instruction with ending of 0x{exfat_patch2_byte} was found within the pattern, second pattern verified\n')
                        print(f'both sys-patch strings are valid for FS-exFAT for: {version}\n')
                        print(f'{version} First Sys-patch FS-ExFAT pattern found at: {offset1}\n')
                        print(f'The ghidra-equivalent pattern used was (11.0.0+) : .. 94 .. .. 00 36 .. 25 80 52\n')
                        print(f'An arm "TBZ" condition is what is supposed to be patched, it is found within the pattern.\n')
                        print(f'{version} Second Sys-patch FS-ExFAT pattern found at: {offset2}\n')
                        print(f'The ghidra-equivalent pattern used was (19.0.0+) : 40 f9 .. .. .. 94 .. .. 40 b9 .. .. 00 12\n')
                        print(f'An arm "BL" condition is what is supposed to be patched, it is found within the pattern.\n')
                        print(f'{version} FS-ExFAT SHA256 hash: {exfathash}\n\n')
                    else:
                        print('sys-patch wont be able to patch FS properly\n\n')
    exfatf.close()

else:
    print(f'FS-exFAT was skipped for: {version}, due to missing NCA file for exfat in the provided firmware files.\n\n')