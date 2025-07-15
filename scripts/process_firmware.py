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
from io import BytesIO
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
            root_keys = RootKeys()
            key_sources = KeySources()
            if sha256(root_keys.mariko_kek).hexdigest().upper() != "ACEA0798A729E8E0B3EF6D83CF7F345537E41ACCCCCAD8686D35E3F5454D5132":
                print("mariko_kek is incorrectly filled in, the key filled into keys.py is incorrect, terminating script.")
                sys.exit(1)
            else:
                header_key = aes_sample.Keygen(root_keys.mariko_kek).header_key
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
    romfs = nca.Romfs(decrypted_section_00[nca_file.fsheaders[0].romfs_start:nca_file.fsheaders[0].romfs_end], "./sorted_firmware/by-type/Data/0100000000000809/romfs/")
    with open('sorted_firmware/by-type/Data/0100000000000809/romfs/file', 'rb') as file:
        data_read = file.read()
        firmware_version = data_read[0x68:0x6E].decode('utf-8')
        return firmware_version
        file.close()
        return key_area_application

def extract_exefs(nca_path, keys):
    keys = keys
    nca_file = nca.Nca(nca_path, keys)
    decrypted_section_00 = nca_file.decrypted_sections[0]
    titleId = nca_file.titleId
    exefs = nca.Pfs0(decrypted_section_00[nca_file.fsheaders[0].pfs0_start:nca_file.fsheaders[0].pfs0_end], f"./sorted_firmware/by-type/Program/{titleId}/exefs/")
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

def sort_and_process():
    key_sources = KeySources()
    sort_nca("firmware")
    fat32_path = Path('sorted_firmware/by-type/Data/0100000000000819/data.nca')
    system_version_path = Path('sorted_firmware/by-type/Data/0100000000000809/data.nca')
    mariko_master_kek_source = extract_packages.process_package12(Path(fat32_path))
    if mariko_master_kek_source not in key_sources.mariko_master_kek_sources:
        print("A new mariko_master_kek_source was detected, add it to key_sources.py to properly process the rest of the firmware files. Terminating script")
        sys.exit(1)
    keys = aes_sample.single_keygen(mariko_master_kek_source)
    system_version = get_system_version(system_version_path, keys)
    print(f'\nfirmware version of files provided is: {system_version}\n')
    fat32hash = sha256(open('FS.kip1', 'rb').read()).hexdigest().upper()
    print(f'{system_version} fat32 sha256 = {fat32hash}')
    es_path = Path('sorted_firmware/by-type/Program/0100000000000033/data.nca')
    nifm_path = Path('sorted_firmware/by-type/Program/010000000000000F/data.nca')
    nim_path = Path('sorted_firmware/by-type/Program/0100000000000025/data.nca')
    ssl_path = Path('sorted_firmware/by-type/Program/0100000000000024/data.nca')
    print(f'{system_version} es_buildID: {extract_exefs(es_path, keys)}')
    print(f'{system_version} nifm_buildID: {extract_exefs(nifm_path, keys)}')
    print(f'{system_version} nim_buildID: {extract_exefs(nim_path, keys)}')
    print(f'{system_version} ssl_buildID: {extract_exefs(ssl_path, keys)}')
    decompress_exefs('sorted_firmware/by-type/Program/0100000000000033/exefs/main', 'es.nso0')
    decompress_exefs('sorted_firmware/by-type/Program/010000000000000F/exefs/main', 'nifm.nso0')
    decompress_exefs('sorted_firmware/by-type/Program/0100000000000025/exefs/main', 'nim.nso0')
    decompress_exefs('sorted_firmware/by-type/Program/0100000000000024/exefs/main', 'ssl.nso0')

if __name__ == "__main__":
    sort_and_process()