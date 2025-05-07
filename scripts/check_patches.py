#!/usr/bin/env python

import re
import subprocess
import shutil
import sys
import hashlib
import os
import argparse
import platform
import key_sources
import nxo64
import aes_sample

try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Hash import SHA256
except ModuleNotFoundError:
    try:
        from Crypto.Cipher import AES
        from Crypto.Hash import SHA256
    except ModuleNotFoundError:
        print('Please install pycryptodome(ex) first!')
        sys.exit(1)

argParser = argparse.ArgumentParser()
argParser.add_argument("-l", "--location", help="firmware folder location.")
argParser.add_argument("-k", "--keys", help="keyfile to use.")
args = argParser.parse_args()
location = "%s" % args.location
prod_keys = "%s" % args.keys

def decompress_main(main):
    with open(f'{main}', 'rb') as decompressed_main:
        return nxo64.decompress_nso(decompressed_main)
    
def decompress_kip(kip):
    with open(f'{kip}', 'rb') as decompressed_kip:
        return nxo64.decompress_kip(decompressed_kip)
    
def decrypt(input, key):
    cipher = AES.new(key, AES.MODE_ECB)
    output = cipher.decrypt(input)
    return output

if location == "None":
    location = "firmware"

user_folder = os.path.expanduser('~/.switch')
user_keys = os.path.expanduser('~/.switch/prod.keys')

if prod_keys == "None" and os.path.exists(user_keys):
    prod_keys = user_keys
    shutil.copy(user_keys, "prod.keys")
elif prod_keys == "None":
    prod_keys = "prod.keys"

if platform.system() == "Windows":
    hactoolnet = "tools/hactoolnet-windows.exe"
    hactool = "tools/hactool-windows.exe"
    hshell = False
elif platform.system() == "Linux":
    hactoolnet = "tools/hactoolnet-linux"
    hactool = "tools/hactool-linux"
    hshell = True
elif platform.system() == "Darwin":
    hactoolnet = "tools/hactoolnet-macos"
    hactool = "tools/hactool-macos"
else:
    hactool = "hactool"
    hactoolnet = "hactoolnet"
    print("Unknown Platform: {platform.system()}, proide your own hactool and hactoolnet")

aes_sample.do_keygen()
subprocess.run(f'{hactoolnet} --keyset prod.keys -t switchfs {location} --title 0100000000000819 --romfsdir {location}/titleid/0100000000000819/romfs/', shell = hshell, stdout = subprocess.DEVNULL)
subprocess.run(f'{hactoolnet} --keyset prod.keys -t pk11 {location}/titleid/0100000000000819/romfs/a/package1 --outdir {location}/titleid/0100000000000819/romfs/a/pkg1', shell = hshell , stdout = subprocess.DEVNULL)
with open(f'{location}/titleid/0100000000000819/romfs/a/pkg1/Decrypted.bin', 'rb') as decrypted_bin:
    secmon_data = decrypted_bin.read()
    result = re.search(b'\x4F\x59\x41\x53\x55\x4D\x49', secmon_data)
    byte_alignment = decrypted_bin.seek(result.end() + 0x22)
    mariko_master_kek_source_dev_key = decrypted_bin.read(0x10).hex().upper()
    byte_alignment = decrypted_bin.seek(result.end() + 0x32)
    mariko_master_kek_source_key = decrypted_bin.read(0x10).hex().upper()
    byte_alignment = decrypted_bin.seek(0x150)
    revision = decrypted_bin.read(0x01)
    incremented_revision = int.from_bytes(revision, byteorder='little') - 0x1
    incremented_hex_revision = (hex(incremented_revision)[2:])
    mariko_master_kek_source = f'mariko_master_kek_source_{incremented_hex_revision}       = {mariko_master_kek_source_key}'
    mariko_master_kek_source_dev = f'mariko_master_kek_source_{incremented_hex_revision}       = {mariko_master_kek_source_dev_key}'
    decrypted_bin.close()
    with open('prod.keys', 'a') as keygen:
        keygen.write(f'\n')
        keygen.write(f'{mariko_master_kek_source}')
        keygen.close()

    with open(prod_keys, 'w') as new_prod_keys:
        subprocess.run(f'{hactoolnet} --keyset prod.keys -t keygen', shell = hshell, stdout=new_prod_keys)
        new_prod_keys.close()
        os.remove('prod.keys')

    subprocess.run(f'{hactoolnet} --keyset {prod_keys} -t switchfs {location} --title 0100000000000809 --romfsdir {location}/titleid/0100000000000809/romfs/', shell = hshell, stdout = subprocess.DEVNULL)
    with open(f'{location}/titleid/0100000000000809/romfs/file', 'rb') as get_version:
            byte_alignment = get_version.seek(0x68)
            read_version_number = get_version.read(0x6).hex().upper()
            version = (bytes.fromhex(read_version_number).decode('utf-8'))
            version_ = version.replace('.', '_')

print(f'Patch changelog for {version}:\n\n')
print(f'# Firmware version number generated keys for is: {version}\n')
print(f'# key revision generated keys for ends with _{incremented_hex_revision}\n')
print(f'# {mariko_master_kek_source}\n')
print(f'# Keygen completed and output to {prod_keys}\n\n')

escompressed = f'{location}/titleid/0100000000000033/exefs/main'
nifmcompressed = f'{location}/titleid/010000000000000f/exefs/main'
nimcompressed = f'{location}/titleid/0100000000000025/exefs/main'
esuncompressed = f'{location}/titleid/0100000000000033/exefs/u_main'
nifmuncompressed = f'{location}/titleid/010000000000000f/exefs/u_main'
nimuncompressed = f'{location}/titleid/0100000000000025/exefs/u_main'
fat32compressed = f'{location}/titleid/0100000000000819/romfs/nx/ini1/FS.kip1'
exfatcompressed = f'{location}/titleid/010000000000081b/romfs/nx/ini1/FS.kip1'
fat32uncompressed = f'{location}/titleid/0100000000000819/romfs/nx/ini1/u_FS.kip1'
exfatuncompressed = f'{location}/titleid/010000000000081b/romfs/nx/ini1/u_FS.kip1'

subprocess.run(f'{hactoolnet} -k {prod_keys} -t switchfs {location} --title 0100000000000033 --exefsdir {location}/titleid/0100000000000033/exefs/', shell = hshell, stdout = subprocess.DEVNULL)
nxo64.write_file(f'{esuncompressed}', decompress_main(f'{escompressed}'))
subprocess.run(f'{hactoolnet} -k {prod_keys} -t switchfs {location} --title 010000000000000f --exefsdir {location}/titleid/010000000000000f/exefs/', shell = hshell, stdout = subprocess.DEVNULL)
nxo64.write_file(f'{nifmuncompressed}', decompress_main(f'{nifmcompressed}'))
subprocess.run(f'{hactoolnet} -k {prod_keys} -t switchfs {location} --title 0100000000000025 --exefsdir {location}/titleid/0100000000000025/exefs/', shell = hshell, stdout = subprocess.DEVNULL)
nxo64.write_file(f'{nimuncompressed}', decompress_main(f'{nimcompressed}'))
subprocess.run(f'{hactoolnet} -k {prod_keys} -t switchfs {location} --title 0100000000000819 --romfsdir {location}/titleid/0100000000000819/romfs/', shell = hshell, stdout = subprocess.DEVNULL)
subprocess.run(f'{hactoolnet} -k {prod_keys} -t pk21 {location}/titleid/0100000000000819/romfs/nx/package2 --ini1dir {location}/titleid/0100000000000819/romfs/nx/ini1', shell = hshell, stdout = subprocess.DEVNULL)
nxo64.write_file(f'{fat32uncompressed}', decompress_kip(f'{fat32compressed}'))
subprocess.run(f'{hactoolnet} -k {prod_keys} -t switchfs {location} --title 010000000000081b --romfsdir {location}/titleid/010000000000081b/romfs/', shell = hshell, stdout = subprocess.DEVNULL)
subprocess.run(f'{hactoolnet} -k {prod_keys} -t pk21 {location}/titleid/010000000000081b/romfs/nx/package2 --ini1dir {location}/titleid/010000000000081b/romfs/nx/ini1', shell = hshell, stdout = subprocess.DEVNULL)
if os.path.exists(exfatuncompressed):
    nxo64.write_file(f'{exfatuncompressed}', decompress_kip(f'{exfatcompressed}'))

def get_es_build_id():
    with open(escompressed, 'rb') as f:
        f.seek(0x40)
        return f.read(0x14).hex().upper()

def get_nifm_build_id():
    with open(nifmcompressed, 'rb') as f:
        f.seek(0x40)
        return f.read(0x14).hex().upper()

def get_nim_build_id():
    with open(nimcompressed, 'rb') as f:
        f.seek(0x40)
        return f.read(0x14).hex().upper()

esbuildid = get_es_build_id()
nifmbuildid = get_nifm_build_id()
nimbuildid = get_nim_build_id()
fat32hash = hashlib.sha256(open(fat32compressed, 'rb').read()).hexdigest().upper()
if os.path.exists(exfatcompressed):
    exfathash = hashlib.sha256(open(exfatcompressed, 'rb').read()).hexdigest().upper()

with open(f'{esuncompressed}', 'rb') as decompressed_es_nso:
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
                print(f'{version} ES build-id: {esbuildid}\n\n')
            else:
                print('a "MOV" arm instruction was either not found after the pattern, or is ends differently. Must be checked. Assume it is broken.\n\n')
        else:
            print(f'ARM instruction does not match expected result, sys-patch for ES wont work.\n\n')

with open(f'{nifmuncompressed}', 'rb') as decompressed_nifm_nso:
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
                print(f'{version} NIFM build-id: {nifmbuildid}\n\n')
            else:
                print('an STP arm instruction was either not found after the pattern, or is ends differently. Must be checked. Assume it is broken. - If this happens, add (new) and change the ctest2 cond check to a stp_cond ("0xA9") check ("41, 0, stp_cond, ctest_patch, ctest_applied"") (\n\n')
        else:
            print('ARM instruction does not match expected result, sys-patch for NIFM wont work.\n\n')

with open(f'{nimuncompressed}', 'rb') as decompressed_nim_nso:
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
                print(f'{version} NIM build-id: {nimbuildid}\n\n')
            else:
                print('an "ADR" arm instruction was either not found after the pattern, or is ends differently. Must be checked. Assume it is broken.\n\n')
        else:
            print('ARM instruction does not match expected result, sys-patch for NIM wont work.\n\n')

if incremented_revision < 11:
    # below 11.0.0 == 10.0.0
    fspattern1 = rb'.{2}\x00\x36.{7}\x71.{2}\x00\x54.{2}\x48\x39'
    # { "noncasigchk_old", "0x..0036.......71..0054..4839", 0, 0, tbz_cond, nop_patch, nop_applied, true, MAKEHOSVERSION(10,0,0), MAKEHOSVERSION(16,1,0) },
    fsoffset1 = 0x0
else:
    # above == 11.0.0+
    # noncasigchk_
    fspattern1 = rb'.\x94.{2}\x00\x36.\x25\x80\x52'
    # { "noncasigchk_new", "0x.94..0036.258052", 2, 0, tbz_cond, nop_patch, nop_applied, true, MAKEHOSVERSION(17,0,0), FW_VER_ANY }, // 17.0.0 - 19.0.0+
    fsoffset1 = 0x2

if incremented_revision < 17:
    #below 17.0.0
    fspattern2 = rb'\x40\xf9.{3}\x94\x08.\x00\x12.\x05\x00\x71'
    # { "nocntchk", "0x40f9...9408.0012.050071", 2, 0, bl_cond, ret0_patch, ret0_applied, true, MAKEHOSVERSION(10,0,0), MAKEHOSVERSION(18,1,0) },
    fsoffset2 = 0x2
    patchvalue = "E0031F2A"
else:
    # above 19.0.0
    # nocntchk2
    fspattern2 = rb'\x40\xf9.{3}\x94.{2}\x40\xb9.{2}\x00\x12'
    # { "nocntchk2", "0x40f9...94..40b9..0012", 2, 0, bl_cond, ret0_patch, ret0_applied, true, MAKEHOSVERSION(19,0,0), FW_VER_ANY },
    fsoffset2 = 0x2
    patchvalue = "E0031F2A"

with open(fat32uncompressed, 'rb') as fat32f:
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
                    print(f'{version} Second Sys-patch FS-FAT32 pattern found at: {offset2}\n')
                    print(f'{version} FS-FAT32 SHA256 hash: {fat32hash}\n\n')
            else:
                print('The first pattern doesnt match what it should match.\n\n')
        else:
            print('sys-patch wont be able to patch FS properly\n\n')
fat32f.close()

if os.path.exists(exfatuncompressed):
    with open(exfatuncompressed, 'rb') as exfatf:
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
