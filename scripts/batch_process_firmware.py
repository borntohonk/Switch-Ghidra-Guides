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
from pathlib import Path
import nca
from key_sources import KeySources
import extract_packages
import nxo64
import aes_sample
from hashlib import sha256

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

def get_valid_firmware_folders(firmwares_dir: str = 'firmwares') -> dict:
    """
    Discover all valid firmware folders under firmwares/ directory.
    Validates that each folder contains at least one .nca file.
    Returns dict of {folder_name: nca_count}
    """
    valid_folders = {}
    
    if not os.path.isdir(firmwares_dir):
        print(f"Error: Firmwares directory '{firmwares_dir}' not found.")
        sys.exit(1)
    
    try:
        entries = os.listdir(firmwares_dir)
    except Exception as e:
        print(f"Error: Failed to read directory '{firmwares_dir}': {e}")
        sys.exit(1)
    
    for entry in entries:
        folder_path = os.path.join(firmwares_dir, entry)
        if os.path.isdir(folder_path):
            # Count .nca files in this folder
            nca_files = [f for f in os.listdir(folder_path) if f.lower().endswith('.nca')]
            
            if len(nca_files) == 0:
                print(f"Warning: Folder '{entry}' contains no .nca files, skipping.")
                continue
            
            valid_folders[entry] = len(nca_files)
    
    if not valid_folders:
        print(f"Error: No folders with .nca files found in '{firmwares_dir}'.")
        sys.exit(1)
    
    return valid_folders

def clear_sorted_firmware():
    """Clear the sorted_firmware directory"""
    if os.path.exists('sorted_firmware'):
        try:
            shutil.rmtree('sorted_firmware')
            os.makedirs('sorted_firmware')
        except Exception as e:
            print(f"Warning: Could not clear sorted_firmware: {e}")
    else:
        os.makedirs('sorted_firmware')

def sort_nca(location):
    firmware_location = location
    for nca_file in os.listdir(firmware_location):
        ncaFull = f'{firmware_location}/{nca_file}'
        with open(ncaFull, 'rb') as f:
            key_sources = KeySources()
            tsec_keys = aes_sample.TsecKeygen(key_sources.tsec_secret_26)
            header_key = aes_sample.Keygen(tsec_keys.tsec_root_key_02).header_key
            nca_data = nca.decrypt_header(f.read(0xC00), header_key)
            nca_header = nca.NcaHeader(nca_data)
            titleId = nca_header.titleId
            content_type = nca_header.contentType
            try:
                mkdirp("sorted_firmware" + "/by-type/" + content_type + "/" + titleId)
                shutil.copy(ncaFull, "sorted_firmware/" + "/by-type/" + content_type + "/" + titleId + "/" + "data.nca")
            except:
                pass

def check_master_key_revision(nca_path):
    ncaFull = nca_path
    with open(ncaFull, 'rb') as f:
        key_sources = KeySources()
        tsec_keys = aes_sample.TsecKeygen(key_sources.tsec_secret_26)
        header_key = aes_sample.Keygen(tsec_keys.tsec_root_key_02).header_key
        nca_data = nca.decrypt_header(f.read(0xC00), header_key)
        nca_header = nca.NcaHeader(nca_data)
        titleId = nca_header.titleId
        if titleId == '0100000000000809':
            master_key_rev = nca_header.sdkVersion
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
    buildid = exefs.buildid
    return buildid

def decompress_exefs(main_path, nso_name):
    main_path = main_path
    nso_name = nso_name
    with open(main_path, 'rb') as compressed_exefs_file:
        decompressed_nso = nxo64.decompress_nso(compressed_exefs_file)
        with open(nso_name, 'wb') as decompressed_exefs_file:
            decompressed_exefs_file.write(decompressed_nso)
            decompressed_exefs_file.close()
            compressed_exefs_file.close()

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
    
    # Get all valid firmware folders
    firmware_folders = get_valid_firmware_folders('firmwares')
    print(f"\nFound {len(firmware_folders)} valid firmware folder(s):")
    for folder_name, nca_count in firmware_folders.items():
        print(f"  - {folder_name}: {nca_count} .nca files")
    print()
    
    # Process each firmware folder
    for firmware_folder_name in sorted(firmware_folders.keys()):
        firmware_location = f'firmwares/{firmware_folder_name}'
        
        print(f"\n{'='*80}")
        print(f"Processing firmware from: {firmware_location}")
        print(f"{'='*80}\n")
        
        # Clear and setup sorted_firmware for this iteration
        clear_sorted_firmware()
        
        # Sort NCAs from this firmware folder
        sort_nca(firmware_location)
        
        fat32_path = Path('sorted_firmware/by-type/Data/0100000000000819/data.nca')
        exfat_path = Path('sorted_firmware/by-type/Data/010000000000081B/data.nca')
        system_version_path = Path('sorted_firmware/by-type/Data/0100000000000809/data.nca')
        master_key_revision = check_master_key_revision(system_version_path)
        master_key_revision_index = master_key_revision -1
        master_key_keygen_list = [revision[0] for revision in keygen_revisions]
        if master_key_revision not in master_key_keygen_list or master_key_revision == master_key_keygen_list[-1]:
            if os.path.exists(fat32_path):
                master_kek_source = extract_packages.process_package12(Path(fat32_path))
            if os.path.exists(exfat_path):
                process_exfat = extract_packages.process_package12(Path(exfat_path), master_kek_source)
                process_exfat
            if master_kek_source not in key_sources.master_kek_sources:
                print("A new master_kek_source was detected, add it to key_sources.py to properly process the rest of the firmware files. Terminating script")
                sys.exit(1)
        elif master_key_revision in master_key_keygen_list:
            if master_key_revision_index == -1:
                master_key_revision_index = 0
            master_kek_source = key_sources.master_kek_sources[master_key_revision_index]
            if os.path.exists(fat32_path):
                process_fat32 = extract_packages.process_package2(Path(fat32_path), master_kek_source)
                process_fat32
            if os.path.exists(exfat_path):
                process_exfat = extract_packages.process_package2(Path(exfat_path), master_kek_source)
                process_exfat
        system_version = get_system_version(system_version_path)
        mkdirp(f'output/{system_version}')
        es_path = Path('sorted_firmware/by-type/Program/0100000000000033/data.nca')
        nifm_path = Path('sorted_firmware/by-type/Program/010000000000000F/data.nca')
        olsc_path =  Path('sorted_firmware/by-type/Program/010000000000003E/data.nca')
        nim_path = Path('sorted_firmware/by-type/Program/0100000000000025/data.nca')
        ssl_path = Path('sorted_firmware/by-type/Program/0100000000000024/data.nca')
        es_buildid = extract_exefs(es_path)
        nifm_buildid = extract_exefs(nifm_path)
        if version_to_tuple(system_version) >= version_to_tuple("6.0.0"):
            olsc_buildid = extract_exefs(olsc_path)
        nim_buildid = extract_exefs(nim_path)
        ssl_buildid = extract_exefs(ssl_path)
        if os.path.exists(fat32_path):
            fat32hash = sha256(open('sorted_firmware/by-type/Data/0100000000000819/romfs/nx/fat32_FS.kip1', 'rb').read()).hexdigest().upper()
        if os.path.exists(exfat_path):
            exfathash = sha256(open('sorted_firmware/by-type/Data/010000000000081B/romfs/nx/exfat_FS.kip1', 'rb').read()).hexdigest().upper()
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
        decompress_exefs('sorted_firmware/by-type/Program/0100000000000033/exefs/main', f'output/{system_version}/{system_version}_uncompressed_es.nso0')
        decompress_exefs('sorted_firmware/by-type/Program/010000000000000F/exefs/main', f'output/{system_version}/{system_version}_uncompressed_nifm.nso0')
        if version_to_tuple(system_version) >= version_to_tuple("6.0.0"):
            decompress_exefs('sorted_firmware/by-type/Program/010000000000003E/exefs/main', f'output/{system_version}/{system_version}_uncompressed_olsc.nso0')
        decompress_exefs('sorted_firmware/by-type/Program/0100000000000025/exefs/main', f'output/{system_version}/{system_version}_uncompressed_nim.nso0')
        decompress_exefs('sorted_firmware/by-type/Program/0100000000000024/exefs/main', f'output/{system_version}/{system_version}_uncompressed_ssl.nso0')

        hash_summary_file = f'output/{system_version}/{system_version}_hashes.txt'
        print_hash_summary(hash_summary_file)
    
    print(f"\n{'='*80}")
    print(f"Batch processing completed successfully!")
    print(f"{'='*80}\n")

if __name__ == "__main__":
    sort_and_process()