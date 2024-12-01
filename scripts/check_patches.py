#!/usr/bin/env python

import re
import subprocess
import shutil
import hashlib
import os
import argparse
import platform
import key_sources
import nxo64
try:
    from Cryptodome.Cipher import AES
except ModuleNotFoundError:
    pass

try:
    from Crypto.Cipher import AES
except ModuleNotFoundError:
    pass

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
    shutil.copy(user_keys, "temp.keys")
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
elif platform.system() == "MacOS":
    hactoolnet = "tools/hactoolnet-macos"
    hactool = "tools/hactool-macos"
else:
    hactool = "hactool"
    hactoolnet = "hactoolnet"
    print("Unknown Platform: {platform.system()}, proide your own hactool and hactoolnet")

master_keks = [decrypt(i, key_sources.mariko_kek) for i in key_sources.mariko_master_kek_sources]

# generate master_key_%% from all provided master_kek_%% using master_key_source
current_master_key = decrypt(key_sources.master_key_source, master_keks[-1])

current_master_key_revision = len(key_sources.Master_Key_Sources)
master_keys = []
first = True
for i in reversed(key_sources.Master_Key_Sources):
    if first:
        first = False
        previous_key = i
        next_master_key = decrypt(previous_key, current_master_key)
        current_master_key_revision = current_master_key_revision -1
        master_keys.append(current_master_key)
        master_keys.append(next_master_key)
    else:
        key = previous_key
        previous_key = i
        next_master_key = decrypt(previous_key, next_master_key)
        current_master_key_revision = current_master_key_revision -1
        master_keys.append(next_master_key)


with open('temp.keys', 'w') as temp_keys:
    temp_keys.write(f'master_key_00 = ' + f'{master_keys[-1].hex().upper()}\n')
    temp_keys.write(f'header_key = ' + f'{key_sources.header_key.hex().upper()}\n')
    temp_keys.write(f'mariko_bek = ' + f'{key_sources.mariko_bek.hex().upper()}\n')
    temp_keys.write(f'mariko_kek = ' + f'{key_sources.mariko_kek.hex().upper()}\n\n')
    temp_keys.close()
    subprocess.run(f'{hactoolnet} --keyset temp.keys -t switchfs {location} --title 0100000000000819 --romfsdir {location}/titleid/0100000000000819/romfs/', shell = hshell, stdout = subprocess.DEVNULL)
    subprocess.run(f'{hactoolnet} --keyset temp.keys -t pk11 {location}/titleid/0100000000000819/romfs/a/package1 --outdir {location}/titleid/0100000000000819/romfs/a/pkg1', shell = hshell , stdout = subprocess.DEVNULL)
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
        with open('temp.keys', 'a') as keygen:
            keygen.write(f'\n')
            keygen.write(f'{mariko_master_kek_source}')
            keygen.close()

        with open(prod_keys, 'w') as new_prod_keys:
            subprocess.run(f'{hactoolnet} --keyset temp.keys -t keygen', shell = hshell, stdout=new_prod_keys)
            new_prod_keys.close()
            os.remove('temp.keys')

        if not os.path.exists(user_folder):
            os.makedirs(user_folder)
        if not os.path.exists(user_keys):
            shutil.copy(prod_keys, user_keys)

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
            print(f'Sys-patch for ES string still valid for: {version}\n')
            print(f'Sys-patch ES pattern found at: {offset}\n')
            print(f'{version} ES build-id: {esbuildid}\n\n')
        else:
            print(f'ARM instruction does not match expected result, sys-patch for ES wont work.')

with open(f'{nifmuncompressed}', 'rb') as decompressed_nifm_nso:
    read_data = decompressed_nifm_nso.read()
    result = re.search(rb'.{20}\xf4\x03\x00\xaa.{4}\xf3\x03\x14\xaa\xe0\x03\x14\xaa\x9f\x02\x01\x39\x7f\x8e\x04\xf8', read_data)
    # { "ctest", "....................F40300AA....F30314AAE00314AA9F0201397F8E04F8", 16, -16, ctest_cond, ctest_patch, ctest_applied, true, FW_VER_ANY },
    if not result:
        print(f'{version} NIFM offset not found\n')
        print(f'Sys-patch for NIFM string is invalid for: {version}\n\n')
    else:
        if result.group(0)[16:20] == bytes([0xF5, 0x03, 0x01, 0xAA]): # ctest_cond check
            offset = '%06X' % (result.start())
            print(f'Sys-patch for NIFM string still valid for: {version}\n')
            print(f'Sys-patch NIFM pattern found at: {offset}\n')
            print(f'{version} NIFM build-id: {nifmbuildid}\n\n')
        else:
            print("ARM instruction does not match expected result, sys-patch for NIFM won't work.")

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
            print(f'Sys-patch for NIM string still valid for: {version}\n')
            print(f'Sys-patch NIM pattern found at: {offset}\n')
            print(f'{version} NIM build-id: {nimbuildid}\n\n')
        else:
            print("ARM instruction does not match expected result, sys-patch for NIM won't work.")

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
            print(f'both sys-patch strings are valid for FS-FAT32 for: {version}\n')
            print(f'{version} First Sys-patch FS-FAT32 pattern found at: {offset1}\n')
            print(f'{version} Second Sys-patch FS-FAT32 pattern found at: {offset2}\n')
            print(f'{version} FS-FAT32 SHA256 hash: {fat32hash}\n\n')
        else:
            print("sys-patch won't be able to patch FS properly")
fat32f.close()

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
        if result1.group(0)[5:6] == bytes([0x36]) and result2.group(0)[5:6] == bytes([0x94]): # bl_cond and bl_cond check
            offset1 = '%06X' % (result1.start() + fsoffset1)
            offset2 = '%06X' % (result2.start() + fsoffset2)
            print(f'both sys-patch strings are valid for FS-exFAT for: {version}\n')
            print(f'{version} First Sys-patch FS-ExFAT pattern found at: {offset1}\n')
            print(f'{version} Second Sys-patch FS-ExFAT pattern found at: {offset2}\n')
            print(f'{version} FS-ExFAT SHA256 hash: {exfathash}\n\n')
        else:
            print("sys-patch won't be able to patch FS properly")
exfatf.close()