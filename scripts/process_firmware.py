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
from keys import RootKeys
from key_sources import KeySources
import extract_packages
import nxo64
import aes_sample
from hashlib import sha256

import lz4

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

def get_system_version(nca_path, keys):
    keys = keys
    nca_file = nca.Nca(nca_path, keys)
    decrypted_section_00 = nca_file.decrypted_sections[0]
    romfs = nca.Romfs(decrypted_section_00[nca_file.fsheaders[0].romfs_start:nca_file.fsheaders[0].romfs_end], f"sorted_firmware/by-type/Data/0100000000000809/romfs/")
    romfs
    with open('sorted_firmware/by-type/Data/0100000000000809/romfs/file', 'rb') as file:
        data_read = file.read()
        firmware_version = data_read[0x68:0x6E].decode('utf-8')
        return firmware_version
    file.close()

def extract_browser_dll_romfs(nca_path, keys):
    keys = keys
    nca_file = nca.Nca(nca_path, keys)
    decrypted_section_00 = nca_file.decrypted_sections[0]
    romfs = nca.Romfs(decrypted_section_00[nca_file.fsheaders[0].romfs_start:nca_file.fsheaders[0].romfs_end], f"sorted_firmware/by-type/Data/0100000000000803/romfs/")
    romfs

def extract_exefs(nca_path, keys):
    keys = keys
    nca_file = nca.Nca(nca_path, keys)
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

def decompress_foss_nro(nro_path, nro_name):
    nro_path = nro_path
    nro_name = nro_name
    with open(nro_path, 'rb') as file:
        input_data = file.read()
        decompressed = lz4.block.decompress(input_data)
        decompressed_browser_file = open(nro_name, 'wb')
        decompressed_browser_file.write(decompressed)
        decompressed_browser_file.close()

def get_nro_build_id(input):
    with open(input, 'rb') as f:
        f.seek(0x40)
        return(f.read(0x10).hex().upper())

potential_foss_browser_paths = [
    'sorted_firmware/by-type/Data/0100000000000803/romfs/dll/webkit_wkc.nro.lz4',
    'sorted_firmware/by-type/Data/0100000000000803/romfs/dll_0/webkit_wkc.nro.lz4',
    'sorted_firmware/by-type/Data/0100000000000803/romfs/dll_1/webkit_wkc.nro.lz4',
    'sorted_firmware/by-type/Data/0100000000000803/romfs/nro/netfront/core_1/default/cfi_enabled/webkit_wkc.nro.lz4', # 14.0.0
    'sorted_firmware/by-type/Data/0100000000000803/romfs/nro/netfront/core_2/default/cfi_enabled/webkit_wkc.nro.lz4', # 18.0.0
    'sorted_firmware/by-type/Data/0100000000000803/romfs/nro/netfront/core_3/default/cfi_enabled/webkit_wkc.nro.lz4', # 20.0.0
    'sorted_firmware/by-type/Data/0100000000000803/romfs/nro/netfront/core_3/Default/cfi_nncfi/webkit_wkc.nro.lz4' # 21.0.0
]

def try_foss_browser_paths():
    for browser_ssl_path in potential_foss_browser_paths:
        if os.path.exists(browser_ssl_path):
            browser_ssl_path = browser_ssl_path
            return browser_ssl_path

def sort_and_process():
    key_sources = KeySources()
    sort_nca("firmware")
    fat32_path = Path('sorted_firmware/by-type/Data/0100000000000819/data.nca')
    exfat_path = Path('sorted_firmware/by-type/Data/010000000000081B/data.nca')
    system_version_path = Path('sorted_firmware/by-type/Data/0100000000000809/data.nca')
    browserdll_path = Path('sorted_firmware/by-type/Data/0100000000000803/data.nca')
    master_kek_source = extract_packages.process_package12(Path(fat32_path))
    if os.path.exists(exfat_path):
        process_exfat = extract_packages.process_package12(Path(exfat_path), master_kek_source)
        process_exfat
    if master_kek_source not in key_sources.master_kek_sources:
        print("A new master_kek_source was detected, add it to key_sources.py to properly process the rest of the firmware files. Terminating script")
        sys.exit(1)
    keys = aes_sample.single_keygen(master_kek_source)
    system_version = get_system_version(system_version_path, keys).replace(chr(0), "")
    mkdirp(f'output/{system_version}')
    extract_browser_dll_romfs(browserdll_path, keys)
    current_browser_ssl_path = try_foss_browser_paths()
    decompress_foss_nro(f'{current_browser_ssl_path}', f'output/{system_version}/{system_version}_foss_browser_ssl.nro') # path last updated 21.0.0
    es_path = Path('sorted_firmware/by-type/Program/0100000000000033/data.nca')
    nifm_path = Path('sorted_firmware/by-type/Program/010000000000000F/data.nca')
    nim_path = Path('sorted_firmware/by-type/Program/0100000000000025/data.nca')
    ssl_path = Path('sorted_firmware/by-type/Program/0100000000000024/data.nca')
    usb_path = Path('sorted_firmware/by-type/Program/0100000000000006/data.nca')
    es_buildid = extract_exefs(es_path, keys)
    nifm_buildid = extract_exefs(nifm_path, keys)
    nim_buildid = extract_exefs(nim_path, keys)
    ssl_buildid = extract_exefs(ssl_path, keys)
    usb_buildid = extract_exefs(usb_path, keys)
    fat32hash = sha256(open('sorted_firmware/by-type/Data/0100000000000819/romfs/nx/fat32_FS.kip1', 'rb').read()).hexdigest().upper()
    if os.path.exists(exfat_path):
        exfathash = sha256(open('sorted_firmware/by-type/Data/010000000000081B/romfs/nx/exfat_FS.kip1', 'rb').read()).hexdigest().upper()
    foss_browser_buildid = get_nro_build_id(f'output/{system_version}/{system_version}_foss_browser_ssl.nro')
    print(f'\nfirmware version of files provided is: {system_version}\n')
    with open(f'output/{system_version}/{system_version}_hashes.txt', 'w') as hash_file:
        hash_file.write(f'{system_version} fat32 sha256 = {fat32hash}\n')
        if os.path.exists(exfat_path):
            hash_file.write(f'{system_version} exfat sha256 = {exfathash}\n')
        else:
            hash_file.write(f'{system_version} No exFAT present in this firmware version in the provided firmware files.\n')
        hash_file.write(f'{system_version} es_buildID: {es_buildid}\n')
        hash_file.write(f'{system_version} nifm_buildID: {nifm_buildid}\n')
        hash_file.write(f'{system_version} nim_buildID: {nim_buildid}\n')
        hash_file.write(f'{system_version} ssl_buildID: {ssl_buildid}\n')
        hash_file.write(f'{system_version} usb_buildID: {usb_buildid}\n')
        hash_file.write(f'{system_version} foss_ssl_browser_buildID: {foss_browser_buildid}\n')
    hash_file.close()
    shutil.copy('sorted_firmware/by-type/Data/0100000000000819/romfs/nx/fat32_FS.kip1', f'output/{system_version}/{system_version}_fat32_FS.kip1')
    shutil.copy('sorted_firmware/by-type/Data/0100000000000819/romfs/nx/fat32_uFS.kip1', f'output/{system_version}/{system_version}_fat32_uFS.kip1')
    if os.path.exists(exfat_path):
        shutil.copy('sorted_firmware/by-type/Data/010000000000081B/romfs/nx/exfat_FS.kip1', f'output/{system_version}/{system_version}_exfat_FS.kip1')
        shutil.copy('sorted_firmware/by-type/Data/010000000000081B/romfs/nx/exfat_uFS.kip1', f'output/{system_version}/{system_version}_exfat_uFS.kip1')
    shutil.copy('sorted_firmware/by-type/Program/0100000000000033/exefs/main', f'output/{system_version}/{system_version}_compressed_es.nso0')
    shutil.copy('sorted_firmware/by-type/Program/010000000000000F/exefs/main', f'output/{system_version}/{system_version}_compressed_nifm.nso0')
    shutil.copy('sorted_firmware/by-type/Program/0100000000000025/exefs/main', f'output/{system_version}/{system_version}_compressed_nim.nso0')
    shutil.copy('sorted_firmware/by-type/Program/0100000000000024/exefs/main', f'output/{system_version}/{system_version}_compressed_ssl.nso0')
    shutil.copy('sorted_firmware/by-type/Program/0100000000000006/exefs/main', f'output/{system_version}/{system_version}_compressed_usb.nso0')
    decompress_exefs('sorted_firmware/by-type/Program/0100000000000033/exefs/main', f'output/{system_version}/{system_version}_uncompressed_es.nso0')
    decompress_exefs('sorted_firmware/by-type/Program/010000000000000F/exefs/main', f'output/{system_version}/{system_version}_uncompressed_nifm.nso0')
    decompress_exefs('sorted_firmware/by-type/Program/0100000000000025/exefs/main', f'output/{system_version}/{system_version}_uncompressed_nim.nso0')
    decompress_exefs('sorted_firmware/by-type/Program/0100000000000024/exefs/main', f'output/{system_version}/{system_version}_uncompressed_ssl.nso0')
    decompress_exefs('sorted_firmware/by-type/Program/0100000000000006/exefs/main', f'output/{system_version}/{system_version}_uncompressed_usb.nso0')

    hash_summary_file = f'output/{system_version}/{system_version}_hashes.txt'
    print_hash_summary(hash_summary_file)

if __name__ == "__main__":
    sort_and_process()