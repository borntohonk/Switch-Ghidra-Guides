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

es_path = "es.nso0"
nim_path = "nim.nso0"
nifm_path = "nifm.nso0"
compressed_fat32_path = "fat32FS.kip1"
decompressed_fat32_path = "fat32uFS.kip1"
compressed_exfat_path = "exfatFS.kip1"
decompressed_exfat_path = "exfatuFS.kip1"

fat32hash = hashlib.sha256(open(compressed_fat32_path, 'rb').read()).hexdigest().upper()
if os.path.exists(compressed_exfat_path):
    exfathash = hashlib.sha256(open(compressed_exfat_path, 'rb').read()).hexdigest().upper()
with open('sorted_firmware/by-type/Data/0100000000000809/romfs/file', 'rb') as file:
    data_read = file.read()
    firmware_version = data_read[0x68:0x6E].decode('utf-8', errors='replace')
    file.close()

version = firmware_version

fspattern1 = rb'.\x94.{2}\x00\x36.{9}\x25\x80\x52' # here
# { "noncasigchk_old2", "0x.94..0036.258052", 2, 0, tbz_cond, nop_patch, nop_applied, true, MAKEHOSVERSION(17,0,0), MAKEHOSVERSION(20,5,0) }, // 17.0.0 - 20.5.0
# { "noncasigchk_new", "0x.94..0036.........258052", 2, 0, tbz_cond, nop_patch, nop_applied, true, MAKEHOSVERSION(21,0,0), FW_VER_ANY }, // 21.0.0+
fsoffset1 = 2
fspattern2 = rb'\x40\xf9.{3}\x94.{2}\x40\xb9.{2}\x00\x12'
# { "nocntchk2", "0x40f9...94..40b9..0012", 2, 0, bl_cond, ret0_patch, ret0_applied, true, MAKEHOSVERSION(19,0,0), FW_VER_ANY },
fsoffset2 = 2
patch_magic = "5041544348" # "PATCH"
eof_magic = "454F46" # "EOF"
patchvalue1 = "1F2003D5" # FS (nop)
patchvalue2 = "E0031F2A" # FS (mov w0, wzr)
patchvalue3 = "E0031FAA" # ES, NIM (mov x0, xzr)
patchvalue4 = "00309AD2001EA1F2610100D4E0031FAAC0035FD6" # NIFM (mov x0, #0xd180 - movk x0, #0x8f0, lsl #16 - svc #0xb - mov x0, xzr - ret)

def get_build_id(nso0):
    with open(nso0, 'rb') as f:
        f.seek(0x40)
        return binascii.hexlify(f.read(0x14)).decode('utf-8').upper()

with open(f'{es_path}', 'rb') as decompressed_es_nso:
    read_data = decompressed_es_nso.read()
    result = re.search(rb'..\x00....\x97\xa0..\xd1...\x97\xe0\x03\x13\x2a...\xa9', read_data)
    # { "es4", "0x..00....97a0..d1...97e003132a...a9", 16, 0, mov2_cond, mov0_patch, mov0_applied, true, MAKEHOSVERSION(21,0,0), FW_VER_ANY }, //21.0.0+
    if not result:
        print(f'(ES) {version} ES offset not found')
        print(f'(ES) Sys-patch for ES string is invalid for: {version}\n')
    else:
        if result.group(0)[19:20] in (bytes([0x2A]), bytes([0x92])): # mov2_cond check
            offset = '%06X' % (result.start() + 16)
            decompressed_es_nso.seek(result.start() + 16)
            es_patch_bytes = decompressed_es_nso.read(0x4).hex().upper()
            es_patch_byte = es_patch_bytes[-2:]
            patch = '%06X%s%s' % (result.start() + 16, '0004', f'{patchvalue3}')
            if es_patch_byte in ('2A', '92'):
                print(f'(ES) a "MOV" arm instruction with ending of 0x{es_patch_byte} was found within the pattern')
                print(f'(ES) Sys-patch for ES string still valid for: {version}')
                print(f'(ES) Sys-patch ES pattern found at: {offset}') # 0x0736B0 for 21.0.0
                print(f'(ES) The ghidra-equivalent pattern used was: .. .. 00 .. .. .. .. 97 a0 .. .. d1 .. .. .. 97 e0 03 13 2a .. .. .. a9')
                print(f'(ES) The existing bytes at the offset are: {es_patch_bytes}') # mov w0, w19 / (E003132A) 21.0.0
                print(f'(ES) An arm "MOV" condition is what is supposed to be patched at this offset')
                print(f'(ES) {version} ES buildid (and what .ips filename should be): {get_build_id(es_path)}\n')
                print(f'(ES) IPS patch bytes would be:')
                print(f'(ES) {patch_magic}{patch}{eof_magic}\n')
            else:
                print(f'(ES) a "MOV" arm instruction was either not found after the pattern, or is ends differently. Must be checked. Assume it is broken.\n')
        else:
            print(f'(ES) ARM instruction does not match expected result, sys-patch for ES wont work.\n')

with open(f'{nifm_path}', 'rb') as decompressed_nifm_nso:
    read_data = decompressed_nifm_nso.read()
    result = re.search(rb'\x14.{11}\x91.{11}\x97.{15}\x14', read_data)
    # { "ctest2", "14...........91...........97...............14", 41, 0, stp_cond, ctest_patch, ctest_applied, true, MAKEHOSVERSION(19,0,0), MAKEHOSVERSION(20,5,0) }, //19.0.0 - 20.5.0
    # { "ctest3", "14...........91...........97...............14", 49, 0, stp_cond, ctest_patch, ctest_applied, true, MAKEHOSVERSION(21,0,0), FW_VER_ANY }, //21.0.0
    # "(49, 0,) +49" from start from the start the string found in it's entirity, as sys-patch tests things stupid, then it reads from 0x0 of the end in decimals where the "head" was placed (49), and the 4th byte from there is what is tested (for most cond checks), the next number determines where from the tested byte is being patched. (should be 0, otherwise its not testing the bytes being patched!)
    # should be noted ams loader patch being (6,2) is different from this general rule of not testing for what is being patched.
    # as it finds searches for "009401C0BE12(6)1F00(2)", testing 4 bytes from from offset (6) for cmp_cond byte of "6B" and then applies the patch of "00", two bytes offset after the testing point (0)1F00(2), turning (6)1F00(2)->01<-6B - cmp w0, w1 -  into (6)1F00(2)->00<-6B - cmp w0, w0
    if not result:
        print(f'(NIFM) {version} NIFM offset not found')
        print(f'(NIFM) Sys-patch for NIFM string is invalid for: {version}\n')
    else:
        offset = '%06X' % (result.start() + 49)
        decompressed_nifm_nso.seek(result.start() + 49)
        nifm_patch_bytes = decompressed_nifm_nso.read(0x4).hex().upper() # example for 21.0.0 FD7BBDA9 / stp x29, x30, [sp, #-0x30]!
        nifm_patch_byte = nifm_patch_bytes[-2:]
        patch = '%06X%s%s' % (result.start() + 49, '0014', f'{patchvalue4}')
        if nifm_patch_byte in ('A9'):
            print(f'(NIFM) an "STP" arm instruction with ending of 0x{nifm_patch_byte} was found proceding the pattern')
            print(f'(NIFM) Sys-patch for NIFM string still valid for: {version}')
            print(f'(NIFM) Sys-patch NIFM pattern found at: {offset}') # 0x0890D0 for 21.0.0
            print(f'(NIFM) The ghidra-equivalent pattern used was: 14 .. .. .. .. .. .. .. .. .. .. .. 91 .. .. .. .. .. .. .. .. .. .. .. 97 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. 14')
            print(f'(NIFM) The existing bytes at the offset are: {nifm_patch_bytes}') # stp x29, x30, [sp, #-0x30]! / (FD7BBDA9) 21.0.0
            print(f'(NIFM) An arm "STP" condition is what is supposed to be patched at the offset right after the branch arm condition tested ("B")')
            print(f'(NIFM) {version} NIFM buildid (and what .ips filename should be): {get_build_id(nifm_path)}\n')
            print(f'(NIFM) IPS patch bytes would be:')
            print(f'(NIFM) {patch_magic}{patch}{eof_magic}\n')
        else:
            print(f'(NIFM) an STP arm instruction was either not found after the pattern, or is ends differently. Must be checked. Assume it is broken.\n')

with open(f'{nim_path}', 'rb') as decompressed_nim_nso:
    read_data = decompressed_nim_nso.read()
    result = re.search(rb'.\x07\x00\x35\x1F\x20\x03\xD5....', read_data) 
	# { "nim_old", "0x.0F00351F2003D5", 8, 0, adr_cond, mov2_patch, mov2_applied, true, MAKEHOSVERSION(17,0,0), MAKEHOSVERSION(20,5,0) },
    # { "nim_new", "0x.0700351F2003D5", 8, 0, adr_cond, mov2_patch, mov2_applied, true, MAKEHOSVERSION(21,0,0), FW_VER_ANY },
    if not result:
        print(f'(NIM) {version} NIM offset not found')
        print(f'(NIM) Sys-patch for NIM string is invalid for: {version}\n')
    else:
        if result.group(0)[11:12] == bytes([0x10]): # adr_cond check
            offset = '%06X' % (result.start() + 8)
            decompressed_nim_nso.seek(result.start() + 8)
            nim_patch_bytes = decompressed_nim_nso.read(0x4).hex().upper()
            nim_patch_byte = nim_patch_bytes[-2:]
            patch = '%06X%s%s' % (result.start() + 8, '0004', f'{patchvalue3}')
            if nim_patch_byte in ('10'):
                print(f'(NIM) a "ADR" arm instruction with ending of 0x{nim_patch_byte} was found within the pattern')
                print(f'(NIM) Sys-patch for NIM string still valid for: {version}')
                print(f'(NIM) Sys-patch NIM pattern found at: {offset}') # 0x18CCD4 for 21.0.0
                print(f'(NIM) The ghidra-equivalent pattern used was: .. 07 00 35 1F 20 03 D5 .. .. .. ..')
                print(f'(NIM) The existing bytes at the offset are: {nim_patch_bytes}') # adr x2, #0x29c / (E2140010) 21.0.0
                print(f'(NIM) An arm "ADR" condition is what is supposed to be patched at the offset right after the "CBNZ and "NOP" conditions the pattern finds')
                print(f'(NIM) {version} NIM buildid (and what .ips filename should be): {get_build_id(nim_path)}\n')
                print(f'(NIM) IPS patch bytes would be:')
                print(f'(NIM) {patch_magic}{patch}{eof_magic}\n')
            else:
                print(f'(NIM) an "ADR" arm instruction was either not found after the pattern, or is ends differently. Must be checked. Assume it is broken.\n')
        else:
            print(f'(NIM) ARM instruction does not match expected result, sys-patch for NIM wont work.\n')

with open(decompressed_fat32_path, 'rb') as fat32f:
    read_data = fat32f.read()
    result1 = re.search(fspattern1, read_data)
    result2 = re.search(fspattern2, read_data)
    if not result1:
        print(f'(FS-FAT32) {version} First FS-FAT32 offset not found')
        print(f'(FS-FAT32) Sys-patch for FS-FAT32 noncasigchk_new string is invalid for: {version}\n')
    elif not result2:
        print(f'(FS-FAT32) {version} Second FS-FAT32 offset not found')
        print(f'(FS-FAT32) Sys-patch for FS-FAT32 nocntchk2 string is invalid for: {version}\n')
    else:
        if result1.group(0)[5:6] == bytes([0x36]) and result2.group(0)[5:6] == bytes([0x94]): # tbz_cond and bl_cond check
            offset1 = '%06X' % (result1.start() + fsoffset1)
            offset2 = '%06X' % (result2.start() + fsoffset2)
            fat32f.seek(result1.start() + fsoffset1)
            fat32_patch1_bytes = fat32f.read(0x4).hex().upper()
            fat32_patch1_byte = fat32_patch1_bytes[-2:]
            fat32f.seek(result2.start() + fsoffset2)
            fat32_patch2_bytes = fat32f.read(0x4).hex().upper()
            fat32_patch2_byte = fat32_patch2_bytes[-2:]
            if fat32_patch1_byte in ('36'):
                print(f'(FS-FAT32) a "TBZ" arm instruction with ending of 0x{fat32_patch1_byte} was found within the pattern, first pattern verified')
                if fat32_patch2_byte in ('94'):
                    print(f'(FS-FAT32) a "BL" arm instruction with ending of 0x{fat32_patch2_byte} was found within the pattern, second pattern verified\n')
                    print(f'(FS-FAT32) both sys-patch strings are valid for FS-FAT32 for: {version}')
                    print(f'(FS-FAT32) {version} First Sys-patch FS-FAT32 pattern found at: {offset1}') # 0x026A60 for 21.0.0
                    print(f'(FS-FAT32) The ghidra-equivalent pattern used was (21.0.0+) : .. 94 .. .. 00 36 .. .. .. .. .. .. .. .. .. 25 80 52') # changed in 21.0.0
                    print(f'(FS-FAT32) The existing bytes at the first offset are: {fat32_patch1_bytes}') # tbz w0, #0, #0x120 / (00090036) 21.0.0
                    print(f'(FS-FAT32) An arm "TBZ" condition is what is supposed to be patched, it is found within the pattern.')
                    print(f'(FS-FAT32) {version} Second Sys-patch FS-FAT32 pattern found at: {offset2}') # 0x07FB88 for 21.0.0
                    print(f'(FS-FAT32) The ghidra-equivalent pattern used was (19.0.0+) : 40 f9 .. .. .. 94 .. .. 40 b9 .. .. 00 12')
                    print(f'(FS-FAT32) The existing bytes at the second offset are: {fat32_patch2_bytes}') # bl #0xe3048 / (128C0394) 21.0.0
                    print(f'(FS-FAT32) An arm "BL" condition is what is supposed to be patched, it is found within the pattern.')
                    print(f'(FS-FAT32) {version} FS-FAT32 SHA256 hash: {fat32hash}\n')
                    print(f'(FS-FAT32) a hekate string for this would be:\n')
                    print(f'#FS {version}-Fat32')
                    print(f'[FS:{fat32hash[:16]}]')
                    print(f'.nosigchk=0:0x{offset2}:0x4:{fat32_patch2_bytes},{patchvalue2}')
                    print(f'.nosigchk=0:0x{offset1}:0x4:{fat32_patch1_bytes},{patchvalue1}\n')
                else:
                    print(f'(FS-FAT32) The second pattern doesnt match what it should match.\n\n')
            else:
                print(f'(FS-FAT32) The first pattern doesnt match what it should match.\n\n')
        else:
            print(f'(FS-FAT32) sys-patch wont be able to patch FS properly\n\n')
fat32f.close()

if os.path.exists(decompressed_exfat_path):
    with open(decompressed_exfat_path, 'rb') as exfatf:
        read_data = exfatf.read()
        result1 = re.search(fspattern1, read_data)
        result2 = re.search(fspattern2, read_data)
        if not result1:
            print(f'(FS-EXFAT) {version} First FS-ExFAT offset not found')
            print(f'(FS-EXFAT) Sys-patch for FS-ExFAT noncasigchk_new string is invalid for: {version}\n')
        elif not result2:
            print(f'(FS-EXFAT) {version} Second FS-ExFAT offset not found')
            print(f'(FS-EXFAT) Sys-patch for FS-ExFAT nocntchk2 string is invalid for: {version}\n')
        else:
            if result1.group(0)[5:6] == bytes([0x36]) and result2.group(0)[5:6] == bytes([0x94]): # tbz_cond and bl_cond check
                offset1 = '%06X' % (result1.start() + fsoffset1)
                offset2 = '%06X' % (result2.start() + fsoffset2)
                exfatf.seek(result1.start() + fsoffset1)
                exfat_patch1_bytes = exfatf.read(0x4).hex().upper()
                exfat_patch1_byte = exfat_patch1_bytes[-2:]
                exfatf.seek(result2.start() + fsoffset2)
                exfat_patch2_bytes = exfatf.read(0x4).hex().upper()
                exfat_patch2_byte = exfat_patch2_bytes[-2:]
                if exfat_patch1_byte in ('36'):
                    print(f'(FS-EXFAT) a "TBZ" arm instruction with ending of 0x{exfat_patch1_byte} was found within the pattern, first pattern verified')
                    if exfat_patch2_byte in ('94'):
                        print(f'(FS-EXFAT) a "BL" arm instruction with ending of 0x{exfat_patch2_byte} was found within the pattern, second pattern verified\n')
                        print(f'(FS-EXFAT) both sys-patch strings are valid for FS-exFAT for: {version}')
                        print(f'(FS-EXFAT) {version} First Sys-patch FS-ExFAT pattern found at: {offset1}') # 0x026A60 for 21.0.0
                        print(f'(FS-EXFAT) The ghidra-equivalent pattern used was (21.0.0+) : .. 94 .. .. 00 36 .. .. .. .. .. .. .. .. .. 25 80 52') # changed in 21.0.0
                        print(f'(FS-EXFAT) The existing bytes at the first offset are: {exfat_patch1_bytes}') # tbz w0, #0, #0x120 / (00090036) 21.0.0
                        print(f'(FS-EXFAT) An arm "TBZ" condition is what is supposed to be patched, it is found within the pattern.')
                        print(f'(FS-EXFAT) {version} Second Sys-patch FS-ExFAT pattern found at: {offset2}') # 0x07FB88 for 21.0.0
                        print(f'(FS-EXFAT) The ghidra-equivalent pattern used was (19.0.0+) : 40 f9 .. .. .. 94 .. .. 40 b9 .. .. 00 12')
                        print(f'(FS-EXFAT) The existing bytes at the second offset are: {exfat_patch2_bytes}') # bl #0xee1a8 / (6AB80394) 21.0.0
                        print(f'(FS-EXFAT) An arm "BL" condition is what is supposed to be patched, it is found within the pattern.')
                        print(f'(FS-EXFAT) {version} FS-ExFAT SHA256 hash: {exfathash}\n')
                        print(f'(FS-EXFAT) a hekate string for this would be:\n')
                        print(f'#FS {version}-ExFAT')
                        print(f'[FS:{exfathash[:16]}]')
                        print(f'.nosigchk=0:0x{offset2}:0x4:{exfat_patch2_bytes},{patchvalue2}')
                        print(f'.nosigchk=0:0x{offset1}:0x4:{exfat_patch1_bytes},{patchvalue1}')
                    else:
                        print(f'(FS-EXFAT) The second pattern doesnt match what it should match.\n\n')    
                else:
                    print(f'(FS-EXFAT) The first pattern doesnt match what it should match.\n\n')
            else:
                print(f'(FS-EXFAT) sys-patch wont be able to patch FS properly\n\n')
    exfatf.close()

else:
    print(f'(FS-EXFAT) FS-exFAT was skipped for: {version}, due to missing NCA file for exfat in the provided firmware files.\n\n')