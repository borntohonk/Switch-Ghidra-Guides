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
import sys
import shutil
import errno
import ast
from pathlib import Path
import nca
from key_sources import KeySources
import extract_packages
import nxo64
from typing import Tuple, List, Dict, Optional
from hashlib import sha256

import lz4


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


def remove_duplicates_by_index(list_of_tuples, index_to_check):
    seen_values = set()
    unique_list = []
    for current_tuple in list_of_tuples:
        value_to_check = current_tuple[index_to_check]

        if value_to_check not in seen_values:
            unique_list.append(current_tuple)
            seen_values.add(value_to_check)
            
    return unique_list


def update_patch_file(filepath: str, current_db: List[Tuple], unique_index: int = 1):
    existing = load_existing_patches(filepath)
    seen = {item[unique_index] for item in existing}
    new_entries = [item for item in current_db if item[unique_index] not in seen]
   
    if not new_entries:
        print(f"No new entries for {filepath} — unchanged.")
        return False

    combined = existing + new_entries
    combined = remove_duplicates_by_index(combined, unique_index)
    combined.sort(key=lambda x: version_to_tuple(x[0]))

    written_count = 0
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            for entry in combined:
                if version_to_tuple(entry[0]) >= version_to_tuple("10.0.0"):
                    f.write(f"{entry},\n")
                    written_count += 1
        if written_count > 0:
            print(f"Appended {written_count} new entries (version ≥10.0.0) to {filepath}")
        else:
            print(f"No new entries written to {filepath} (all below version 10.0.0)")
        return written_count > 0
    except Exception as e:
        print(f"Error writing {filepath}: {e}")
        return False


def version_to_tuple(version_string):
    parts = version_string.split('-')[0].split('.')
    return tuple(int(p) for p in parts)


def print_hash_summary(hash_summary_file_path):
    try:
        with open(hash_summary_file_path, 'r') as file:
            file_content = file.read()
            print(file_content)
    except FileNotFoundError:
        print(f"Error: The file '{hash_summary_file_path}' was not found.")
    except Exception as e:
        print(f"An error occurred in loading the hash_summary: {e}")


def mkdirp(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def sort_nca(location):
    firmware_location = location
    for nca_file in os.listdir(firmware_location):
        ncaFull = f'{firmware_location}/{nca_file}'
        nca_file = nca.Nca(ncaFull)
        titleId = nca_file.titleId
        content_type = nca_file.content_type
        try:
            mkdirp("sorted_firmware" + "/by-type/" + content_type + "/" + titleId)
            shutil.copy(ncaFull, "sorted_firmware/" + "/by-type/" + content_type + "/" + titleId + "/" + "data.nca")
        except:
            pass


def check_master_key_revision(nca_path):
    ncaFull = nca_path
    nca_header = nca.Nca(ncaFull)
    titleId = nca_header.titleId
    if titleId == '0100000000000809':
        master_key_rev = nca_header.master_key_revision
        return master_key_rev


def get_system_version(nca_path):
    nca_file = nca.Nca(nca_path)
    decrypted_section_00 = nca_file.decrypted_sections[0]
    romfs = nca.Romfs(decrypted_section_00[nca_file.fsheaders[0].romfs_start:nca_file.fsheaders[0].romfs_end], f"sorted_firmware/by-type/Data/0100000000000809/romfs/")
    romfs
    with open('sorted_firmware/by-type/Data/0100000000000809/romfs/file', 'rb') as file:
        data_read = file.read()
        firmware_version = data_read[0x68:0x6E].decode('utf-8').replace(chr(0), "")
        return firmware_version
    file.close()

def extract_exefs(nca_path):
    nca_file = nca.Nca(nca_path)
    decrypted_section_00 = nca_file.decrypted_sections[0]
    titleId = nca_file.titleId
    exefs = nca.Pfs0(decrypted_section_00[nca_file.fsheaders[0].pfs0_start:nca_file.fsheaders[0].pfs0_end], f"sorted_firmware/by-type/Program/{titleId}/exefs/")
    moduleid = exefs.moduleid
    return moduleid

def decompress_exefs(main_path, nso_name):
    main_path = main_path
    nso_name = nso_name
    with open(main_path, 'rb') as compressed_exefs_file:
        decompressed_nso = nxo64.decompress_nso(compressed_exefs_file)
        with open(nso_name, 'wb') as decompressed_exefs_file:
            decompressed_exefs_file.write(decompressed_nso)
            decompressed_exefs_file.close()
            compressed_exefs_file.close()

def get_nro_module_id(input):
    with open(input, 'rb') as f:
        f.seek(0x40)
        return(f.read(0x10).hex().upper())

keygen_revisions = [
    (0x00, '1.0.0'), # KeyGenerationOld 0x00
    (0x01, '2.0.0'), # KeyGenerationOld 0x01 (Unused)
    (0x02, '3.0.0'), # KeyGenerationOld 0x02
    (0x03, '3.0.1'),
    (0x04, '4.0.0'),
    (0x05, '5.0.0'),
    (0x06, '6.0.0'),
    (0x07, '6.2.0'),
    (0x08, '7.0.0'),
    (0x09, '8.1.0'),
    (0x0A, '9.0.0'),
    (0x0B, '9.1.0'),
    (0x0C, '12.1.0'),
    (0x0D, '13.0.0'),
    (0x0E, '14.0.0'),
    (0x0F, '15.0.0'),
    (0x10, '16.0.0'),
    (0x11, '17.0.0'),
    (0x12, '18.0.0'),
    (0x13, '19.0.0'),
    (0x14, '20.0.0'),
    (0x15, '21.0.0'),
]

def sort_and_process():
    key_sources = KeySources()
    sort_nca("firmware")
    sdk_versions = []
    fat32_path = Path('sorted_firmware/by-type/Data/0100000000000819/data.nca')
    exfat_path = Path('sorted_firmware/by-type/Data/010000000000081B/data.nca')
    system_version_path = Path('sorted_firmware/by-type/Data/0100000000000809/data.nca')
    master_key_revision = check_master_key_revision(system_version_path)
    master_key_revision_index = master_key_revision
    master_key_keygen_list = [revision[0] for revision in keygen_revisions]
    if master_key_revision not in master_key_keygen_list or master_key_revision == master_key_keygen_list[-1]:
        if os.path.exists(fat32_path):
            master_kek_source, fat32_sdkversion = extract_packages.process_package12(Path(fat32_path))
        if os.path.exists(exfat_path):
            exfat_sdkversion = extract_packages.process_package12(Path(exfat_path), master_kek_source)[1]
        if master_kek_source not in key_sources.master_kek_sources:
            print("A new master_kek_source was detected, add it to key_sources.py to properly process the rest of the firmware files. Terminating script")
            sys.exit(1)
    elif master_key_revision in master_key_keygen_list:
        if master_key_revision_index == -1:
            master_key_revision_index = 0
        system_version = get_system_version(system_version_path)
        master_kek_source = key_sources.master_kek_sources[master_key_revision_index]
        if os.path.exists(fat32_path):
            fat32_sdkversion = extract_packages.process_package2(Path(fat32_path), master_kek_source)
        if os.path.exists(exfat_path):
            exfat_sdkversion = extract_packages.process_package2(Path(exfat_path), master_kek_source)
    system_version = get_system_version(system_version_path)
    mkdirp(f'output/{system_version}')
    es_path = Path('sorted_firmware/by-type/Program/0100000000000033/data.nca')
    nifm_path = Path('sorted_firmware/by-type/Program/010000000000000F/data.nca')
    olsc_path =  Path('sorted_firmware/by-type/Program/010000000000003E/data.nca')
    nim_path = Path('sorted_firmware/by-type/Program/0100000000000025/data.nca')
    ssl_path = Path('sorted_firmware/by-type/Program/0100000000000024/data.nca')
    usb_path = Path('sorted_firmware/by-type/Program/0100000000000006/data.nca')
    es_buildid = extract_exefs(es_path)
    nifm_buildid = extract_exefs(nifm_path)
    if version_to_tuple(system_version) >= version_to_tuple("6.0.0"):
        olsc_buildid = extract_exefs(olsc_path)
    nim_buildid = extract_exefs(nim_path)
    ssl_buildid = extract_exefs(ssl_path)
    usb_buildid = extract_exefs(usb_path)
    if os.path.exists(fat32_path):
        fat32hash = sha256(open('sorted_firmware/by-type/Data/0100000000000819/romfs/nx/fat32_FS.kip1', 'rb').read()).hexdigest().upper()
        fat32sdkstring = (system_version, fat32hash[:16], fat32hash, fat32_sdkversion)
        sdk_versions.append(fat32sdkstring)
    if os.path.exists(exfat_path):
        exfathash = sha256(open('sorted_firmware/by-type/Data/010000000000081B/romfs/nx/exfat_FS.kip1', 'rb').read()).hexdigest().upper()
        exfatsdkstring = (system_version, exfathash[:16], exfathash, exfat_sdkversion)
        sdk_versions.append(exfatsdkstring)
    print(f'\nfirmware version of files provided is: {system_version}\n')
    with open(f'output/{system_version}/{system_version}_hashes.txt', 'w') as hash_file:
        if os.path.exists(fat32_path):
            hash_file.write(f'{system_version} fat32 sha256 = {fat32hash}\n')
        else:
            hash_file.write(f'{system_version} No fat32 present in this firmware version in the provided firmware files.\n')
        if os.path.exists(exfat_path):
            hash_file.write(f'{system_version} exfat sha256 = {exfathash}\n')
        else:
            hash_file.write(f'{system_version} No exFAT present in this firmware version in the provided firmware files.\n')
        hash_file.write(f'{system_version} es_buildID: {es_buildid}\n')
        hash_file.write(f'{system_version} nifm_buildID: {nifm_buildid}\n')
        if version_to_tuple(system_version) >= version_to_tuple("6.0.0"):
            hash_file.write(f'{system_version} olsc_buildID: {olsc_buildid}\n')
        hash_file.write(f'{system_version} nim_buildID: {nim_buildid}\n')
        hash_file.write(f'{system_version} ssl_buildID: {ssl_buildid}\n')
        hash_file.write(f'{system_version} usb_buildID: {usb_buildid}\n')
    hash_file.close()
    if os.path.exists(fat32_path):
        shutil.copy('sorted_firmware/by-type/Data/0100000000000819/romfs/nx/fat32_FS.kip1', f'output/{system_version}/{system_version}_fat32_FS.kip1')
        shutil.copy('sorted_firmware/by-type/Data/0100000000000819/romfs/nx/fat32_uFS.kip1', f'output/{system_version}/{system_version}_fat32_uFS.kip1')
    if os.path.exists(exfat_path):
        shutil.copy('sorted_firmware/by-type/Data/010000000000081B/romfs/nx/exfat_FS.kip1', f'output/{system_version}/{system_version}_exfat_FS.kip1')
        shutil.copy('sorted_firmware/by-type/Data/010000000000081B/romfs/nx/exfat_uFS.kip1', f'output/{system_version}/{system_version}_exfat_uFS.kip1')
    shutil.copy('sorted_firmware/by-type/Program/0100000000000033/exefs/main', f'output/{system_version}/{system_version}_compressed_es.nso0')
    shutil.copy('sorted_firmware/by-type/Program/010000000000000F/exefs/main', f'output/{system_version}/{system_version}_compressed_nifm.nso0')
    if version_to_tuple(system_version) >= version_to_tuple("6.0.0"):
        shutil.copy('sorted_firmware/by-type/Program/010000000000003E/exefs/main', f'output/{system_version}/{system_version}_compressed_olsc.nso0')
    shutil.copy('sorted_firmware/by-type/Program/0100000000000025/exefs/main', f'output/{system_version}/{system_version}_compressed_nim.nso0')
    shutil.copy('sorted_firmware/by-type/Program/0100000000000024/exefs/main', f'output/{system_version}/{system_version}_compressed_ssl.nso0')
    shutil.copy('sorted_firmware/by-type/Program/0100000000000006/exefs/main', f'output/{system_version}/{system_version}_compressed_usb.nso0')
    decompress_exefs('sorted_firmware/by-type/Program/0100000000000033/exefs/main', f'output/{system_version}/{system_version}_uncompressed_es.nso0')
    decompress_exefs('sorted_firmware/by-type/Program/010000000000000F/exefs/main', f'output/{system_version}/{system_version}_uncompressed_nifm.nso0')
    if version_to_tuple(system_version) >= version_to_tuple("6.0.0"):
        decompress_exefs('sorted_firmware/by-type/Program/010000000000003E/exefs/main', f'output/{system_version}/{system_version}_uncompressed_olsc.nso0')
    decompress_exefs('sorted_firmware/by-type/Program/0100000000000025/exefs/main', f'output/{system_version}/{system_version}_uncompressed_nim.nso0')
    decompress_exefs('sorted_firmware/by-type/Program/0100000000000024/exefs/main', f'output/{system_version}/{system_version}_uncompressed_ssl.nso0')
    decompress_exefs('sorted_firmware/by-type/Program/0100000000000006/exefs/main', f'output/{system_version}/{system_version}_uncompressed_usb.nso0')

    hash_summary_file = f'output/{system_version}/{system_version}_hashes.txt'
    print_hash_summary(hash_summary_file)

    sdk_versions_updated = update_patch_file('patch_database/fs_sdk_versions.txt', sdk_versions)
    if not sdk_versions_updated:
        print("SDK version strings up to date")


if __name__ == "__main__":
    sort_and_process()