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
import aes128
from base64 import b64decode

argParser = argparse.ArgumentParser()
argParser.add_argument("-l", "--location", help="firmware folder location.")
argParser.add_argument("-k", "--keys", help="keyfile to use.")
argParser.add_argument("-v", "--verbose", action="store_true")
args = argParser.parse_args()
location = "%s" % args.location
prod_keys = "%s" % args.keys
verbose = "%s" % args.verbose

def decompress_main(main):
    with open(f'{main}', 'rb') as decompressed_main:
        return nxo64.decompress_nso(decompressed_main)
    
def decompress_kip(kip):
    with open(f'{kip}', 'rb') as decompressed_kip:
        return nxo64.decompress_kip(decompressed_kip)
    
def decrypt(key, decryption_key):
	crypto = aes128.AESECB(decryption_key)
	return crypto.decrypt(key)

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
    if verbose == "True":
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

changelog = open(f'./{version_}_patch_changelog.txt', 'w')
changelog.write(f'Patch changelog for {version}:\n\n')
changelog.write(f'# Firmware version number generated keys for is: {version}\n')
changelog.write(f'# key revision generated keys for ends with _{incremented_hex_revision}\n')
changelog.write(f'# {mariko_master_kek_source}\n')
changelog.write(f'# Keygen completed and output to {prod_keys}\n')

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

changelog.write(f'\n===== Relevant hashes and buildids for {version}  =====\n')
changelog.write(f'\nes build-id:, {esbuildid}')
changelog.write(f'\nnifm build-id, {nifmbuildid}')
changelog.write(f'\nnim build-id:, {nimbuildid}')
changelog.write(f'\nfat32 sha256:, {fat32hash}')
changelog.write(f'\nexfat sha256:, {exfathash}')

esbuildid = get_es_build_id()
es_patch = f'{esbuildid}.ips'
if es_patch in os.listdir('patches/atmosphere/exefs_patches/es_patches'):
    changelog.write(f'\n\nES related patch changelog for {version}:\n')
    changelog.write(f'ES patch for version {version} already exists as an .ips patch, and the build id is: {esbuildid}\n\n')
else:
    with open(f'{esuncompressed}', 'rb') as decompressed_es_nso:
        read_data = decompressed_es_nso.read()
        result = re.search(rb'.{2}\x00.{3}\x00\x94\xa0.{2}\xd1.{2}\xff\x97.{7}\xa9', read_data)
        if not result:
            changelog.write(f'ES related patch changelog for {version}:\n')
            changelog.write(f'{version} ES offset not found\n\n')
        else:
            patch = '%06X%s%s' % (result.start() + 0x10, '0004', 'E0031FAA')
            offset = '%06X' % (result.start() + 0x10 - 0x100)
            text_file = open('./patches/atmosphere/exefs_patches/es_patches/%s.ips' % esbuildid, 'wb')
            text_file.write(bytes.fromhex(str(f'5041544348{patch}454F46')))
            text_file.close()
            changelog.write(f'ES related patch changelog for {version}:\n')
            changelog.write(f'{version} ES build-id: {esbuildid}\n')
            changelog.write(f'{version} ES offset and patch at: {patch}\n\n')
            changelog.write(f'{version} ES related patch for atmosphere fork\n')
            changelog.write(f'constexpr inline const EmbeddedPatchEntry DisableTicketVerificationPatches_{version_}[] = {{\n')
            changelog.write(f'    {{ 0x{offset}, "\\xE0\\x03\\x1F\\xAA", 4 }},\n')
            changelog.write(f'}};\n')
            changelog.write(f'\n')
            changelog.write(f'    {{ ParseModuleId("{get_es_build_id()}"), util::size(DisableTicketVerificationPatches_{version_}), DisableTicketVerificationPatches_{version_} }}, /* {version} */\n')
            changelog.write(f'\n')

nifmbuildid = get_nifm_build_id()
nifm_patch = f'{nifmbuildid}.ips'

if nifm_patch in os.listdir('patches/atmosphere/exefs_patches/nifm_ctest'):
    changelog.write(f'NIFM CTEST related patch changelog for {version}:\n')
    changelog.write(f'NIFM CTEST patch for version {version} already exists as an .ips patch, and the build id is: {nifmbuildid}\n\n')
else:
    with open(f'{nifmuncompressed}', 'rb') as decompressed_nifm_nso:
        read_data = decompressed_nifm_nso.read()
        result = re.search(rb'.{20}\xf4\x03\x00\xaa.{4}\xf3\x03\x14\xaa\xe0\x03\x14\xaa\x9f\x02\x01\x39\x7f\x8e\x04\xf8', read_data)
        if not result:
            changelog.write(f'NIFM related patch changelog for {version}:\n')
            changelog.write(f'{version} NIFM offset not found\n\n')
        else:
            patch = '%06X%s%s' % (result.start(), '0014', '00309AD2001EA1F2610100D4E0031FAAC0035FD6')
            offset = '%06X' % (result.start() - 0x100)
            text_file = open('./patches/atmosphere/exefs_patches/nifm_ctest/%s.ips' % nifmbuildid, 'wb')
            text_file.write(bytes.fromhex(str(f'5041544348{patch}454F46')))
            text_file.close()
            changelog.write(f'NIFM related patch changelog for {version}:\n')
            changelog.write(f'{version} NIFM CTEST build-id: {nifmbuildid}\n')
            changelog.write(f'{version} NIFM CTEST offset and patch at: {patch}\n\n')
            changelog.write(f'{version} NIFM related patch for atmosphere fork\n')
            changelog.write(f'constexpr inline const EmbeddedPatchEntry ForceCommunicationEnabledPatches_{version_}[] = {{\n')
            changelog.write(f'    {{ 0x{offset}, "\\x00\\x30\\x9A\\xD2\\x00\\x1E\\xA1\\xF2\\x61\\x01\\x00\\xD4\\xE0\\x03\\x1F\\xAA\\xC0\\x03\\x5F\\xD6", 20 }},\n')
            changelog.write(f'}};\n')
            changelog.write(f'\n')
            changelog.write(f'    {{ ParseModuleId("{get_nifm_build_id()}"), util::size(ForceCommunicationEnabledPatches_{version_}), ForceCommunicationEnabledPatches_{version_} }}, /* {version} */\n')
            changelog.write(f'\n')


nimbuildid = get_nim_build_id()
nim_patch = f'{nimbuildid}.ips'

if incremented_revision > 17:
    if nim_patch in os.listdir('patches/atmosphere/exefs_patches/ams_blanker_fix'):
        changelog.write(f'NIM related patch changelog for {version}:\n')
        changelog.write(f'NIM patch for version {version} already exists as an .ips patch, and the build id is: {nimbuildid}\n\n')
    else:
        with open(f'{nimuncompressed}', 'rb') as decompressed_nim_nso:
            read_data = decompressed_nim_nso.read()
            result = re.search(rb'.\x0F\x00\x35\x1F\x20\x03\xD5', read_data)
            if not result:
                changelog.write(f'nim related patch changelog for {version}:\n')
                changelog.write(f'{version} nim offset not found\n\n')
            else:
                patch = '%06X%s%s' % (result.start() + 0x8, '0004', 'E2031FAA')
                offset = '%06X' % (result.start() + 0x8 - 0x100)
                text_file = open('./patches/atmosphere/exefs_patches/ams_blanker_fix/%s.ips' % nimbuildid, 'wb')
                text_file.write(bytes.fromhex(str(f'5041544348{patch}454F46')))
                text_file.close()
                changelog.write(f'nim related patch changelog for {version}:\n')
                changelog.write(f'{version} nim build-id: {nimbuildid}\n')
                changelog.write(f'{version} nim offset and patch at: {patch}\n\n')
                changelog.write(f'{version} nim related patch for atmosphere fork\n')
                changelog.write(f'constexpr inline const EmbeddedPatchEntry AmsProdinfoBlankerFix_{version_}[] = {{\n')
                changelog.write(f'    {{ 0x{offset}, "\\xE2\\x03\\x1F\\xAA", 4 }},\n')
                changelog.write(f'}};\n')
                changelog.write(f'\n')
                changelog.write(f'    {{ ParseModuleId("{get_nim_build_id()}"), util::size(AmsProdinfoBlankerFix_{version_}), AmsProdinfoBlankerFix_{version_} }}, /* {version} */\n')
                changelog.write(f'\n')

if incremented_revision < 11:
    #below 11.0.0 == 10.0.0
    fspattern1 = rb'.{2}\x00\x36.{7}\x71.{2}\x00\x54.{2}\x48\x39'
    fsoffset1 = 0x0
elif incremented_revision > 12:
    #above == 11.0.0+
    fspattern1 = rb'.\x94.{2}\x00\x36.\x25\x80\x52'
    fsoffset1= 0x2

if incremented_revision < 18:
    #below 19.0.0
    fspattern2 = rb'\x40\xf9.{3}\x94\x08.\x00\x12.\x05\x00\x71' 
    fsoffset2 = 0x2
else:
    #above 19.0.0
    fspattern2 = rb'\x40\xf9.{3}\x94.{2}\x40\xb9.{2}\x00\x12'
    fsoffset2= 0x2

with open('./hekate_patches/fs_patches.ini') as fs_patches:
    if fat32hash[:16] in fs_patches.read():
        changelog.write(f'FS-FAT32 patch related changelog for {version}:\n')
        changelog.write(f'FS-FAT32 patch for version {version} already exists in fs_patches.ini with the short hash of: {fat32hash[:16]}\n\n')
    else:
        with open(fat32uncompressed, 'rb') as fat32f:
            read_data = fat32f.read()
            result1 = re.search(fspattern1, read_data)
            result2 = re.search(fspattern2, read_data)
            if not result1:
                changelog.write(f'FS-FAT32 patch related changelog for {version}:\n')
                changelog.write(f'{version} First FS-FAT32 offset not found\n')
            elif not result2:
                changelog.write(f'FS-FAT32 patch related changelog for {version}:\n')
                changelog.write(f'{version} Second FS-FAT32 offset not found\n')
            else:
                patch1 = '%06X%s%s' % (result1.start() + 0x2, '0004', '1F2003D5')
                patch2 = '%06X%s%s' % (result2.start() + fsoffset2, '0004', 'E0031F2A')
                changelog.write(f'FS-FAT32 patch related changelog for {version}:\n')
                changelog.write(f'{version} First FS-FAT32 offset and patch at: {patch1}\n')
                changelog.write(f'{version} Second FS-FAT32 offset and patch at: {patch2}\n')
                changelog.write(f'{version} FS-FAT32 SHA256 hash: {fat32hash}\n\n')
                fat32_hekate = open('./hekate_patches/fs_patches.ini', 'a')
                fat32_hekate.write(f'\n#FS {version}-fat32\n')
                fat32_hekate.write(f'[FS:{fat32hash[:16]}]\n')
                byte_alignment = fat32f.seek(result1.start() + fsoffset1)
                fat32_hekate.write('.nosigchk=0:0x' + '%06X' % (result1.start() + fsoffset1 - 0x100) + f':0x4:{fat32f.read(0x4).hex().upper()},1F2003D5\n')
                byte_alignment = fat32f.seek(result2.start() + fsoffset2)
                fat32_hekate.write('.nosigchk=0:0x' + '%06X' % (result2.start() + fsoffset2 - 0x100) + f':0x4:{fat32f.read(0x4).hex().upper()},E0031F2A\n')
                fat32_hekate.close()
                changelog.write(f'{version} FS-FAT32 related patch for atmosphere fork\n')
                changelog.write(f'AddPatch(fs_meta, 0x' + '%06X' % (result1.start() + fsoffset1) + f', NoNcaHeaderSignatureCheckPatch0, sizeof(NoNcaHeaderSignatureCheckPatch0));\n')
                changelog.write(f'AddPatch(fs_meta, 0x' + '%06X' % (result2.start() + fsoffset2) + f', NoNcaHeaderSignatureCheckPatch1, sizeof(NoNcaHeaderSignatureCheckPatch1));\n\n')
        fat32f.close()
fs_patches.close()

with open('./hekate_patches/fs_patches.ini') as fs_patches:
    if exfathash[:16] in fs_patches.read():
        changelog.write(f'FS-ExFAT patch related changelog for {version}:\n')
        changelog.write(f'FS-ExFAT patch for version {version} already exists in fs_patches.ini with the short hash of: {exfathash[:16]}\n')
    else:
        with open(exfatuncompressed, 'rb') as exfatf:
            read_data = exfatf.read()
            result1 = re.search(fspattern1, read_data)
            result2 = re.search(fspattern2, read_data)
            if not result1:
                changelog.write(f'FS-ExFAT patch related changelog for {version}:\n')
                changelog.write(f'{version} First FS-ExFAT offset not found\n')
            elif not result2:
                changelog.write(f'FS-ExFAT patch related changelog for {version}:\n')
                changelog.write(f'{version} Second FS-ExFAT offset not found\n')
            else:
                patch1 = '%06X%s%s' % (result1.start() + fsoffset1, '0004', '1F2003D5')
                patch2 = '%06X%s%s' % (result2.start() + fsoffset2, '0004', 'E0031F2A')
                changelog.write(f'FS-ExFAT patch related changelog for {version}:\n')
                changelog.write(f'{version} First FS-ExFAT offset and patch at: {patch1}\n')
                changelog.write(f'{version} Second FS-exFAT offset and patch at: {patch2}\n')
                changelog.write(f'{version} FS-ExFAT SHA256 hash: {exfathash}\n\n')
                exfat_hekate = open('./hekate_patches/fs_patches.ini', 'a')
                exfat_hekate.write(f'\n#FS {version}-exfat\n')
                exfat_hekate.write(f'[FS:{exfathash[:16]}]\n')
                byte_alignment = exfatf.seek(result1.start() + fsoffset1)
                exfat_hekate.write('.nosigchk=0:0x' + '%06X' % (result1.start() + fsoffset1 - 0x100) + f':0x4:{exfatf.read(0x4).hex().upper()},1F2003D5\n')
                byte_alignment = exfatf.seek(result2.start() + fsoffset2)
                exfat_hekate.write('.nosigchk=0:0x' + '%06X' % (result2.start() + fsoffset2 - 0x100) + f':0x4:{exfatf.read(0x4).hex().upper()},E0031F2A\n')
                exfat_hekate.close()
                changelog.write(f'{version} FS-ExFAT related patch for atmosphere fork\n')
                changelog.write(f'AddPatch(fs_meta, 0x' + '%06X' % (result1.start() + fsoffset1) + f', NoNcaHeaderSignatureCheckPatch0, sizeof(NoNcaHeaderSignatureCheckPatch0));\n')
                changelog.write(f'AddPatch(fs_meta, 0x' + '%06X' % (result2.start() + fsoffset2) + f', NoNcaHeaderSignatureCheckPatch1, sizeof(NoNcaHeaderSignatureCheckPatch1));\n\n')
        exfatf.close()
fs_patches.close()
changelog.close()

with open('./patches/bootloader/patches.ini', 'wb') as outfile:
    for filename in ['./hekate_patches/header.ini', './hekate_patches/fs_patches.ini', './hekate_patches/loader_patches.ini']:
        with open(filename, 'rb') as readfile:
            shutil.copyfileobj(readfile, outfile)
shutil.make_archive('patches', 'zip', 'patches')

if verbose == "True":
    with open(f'./{version_}_patch_changelog.txt') as print_changelog:
        print(print_changelog.read())
    print_changelog.close()
