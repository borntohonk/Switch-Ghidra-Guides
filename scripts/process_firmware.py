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
import shutil
import errno
from pathlib import Path
import nca
import key_sources as key_sources
import extract_packages
import extract_exefs
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
        decrypted_header, key_area_encryption_type, program_id, content_type, aes_ctr = nca.decrypt_header(ncaFull, key_sources.header_key)
        if content_type == "ROMFS":
            mkdirp("sorted_firmware" + "/by-type/" + "romfs/" + program_id)
            try:
                if ncaFull.endswith(".cnmt.nca"):
                    pass
                else:
                    shutil.copy(ncaFull, "sorted_firmware/" + "/by-type/" + "romfs/" + program_id + "/" + "data.nca")
            except:
                pass
        elif content_type == "PFS0":
            mkdirp("sorted_firmware" + "/by-type/" + "exefs/" + program_id)
            try:
                if ncaFull.endswith(".cnmt.nca"):
                    pass
                else:
                    shutil.copy(ncaFull, "sorted_firmware/" + "/by-type/" + "exefs/" + program_id + "/" + "program.nca")
            except:
                pass

def get_system_version(nca_path, mariko_master_kek_source_key):
    nca_file = nca_path
    decrypted_header, key_area_encryption_type, program_id, content_type, aes_ctr = nca.decrypt_header(nca_file, key_sources.header_key)
    mariko_master_kek_source = mariko_master_kek_source_key
    master_kek, master_key, package2_key, titlekek, key_area_key_system, key_area_key_ocean, key_area_key_application = aes_sample.single_keygen(mariko_master_kek_source)
    decrypted_section_0 = nca.decrypt_section_0(nca_file, key_area_key_application, decrypted_header, content_type, aes_ctr)
    extracted_romfs = nca.extract_romfs(decrypted_header, decrypted_section_0)
    result = re.search(b'\x66\x69\x6C\x65', extracted_romfs)
    system_version_file_size_location = result.start() - 0x10
    system_version_file_size_length = system_version_file_size_location + 0x4
    system_version_file_size = int.from_bytes(extracted_romfs[system_version_file_size_location:system_version_file_size_length], "little", signed=False) + 0x200
    system_version_file_offset_location = result.start() - 0x18
    system_version_file_offset_length = system_version_file_offset_location + 0x4
    system_version_file_offset = int.from_bytes(extracted_romfs[system_version_file_offset_location:system_version_file_offset_length], "little", signed=False) + 0x200
    system_version_file_length = system_version_file_size + system_version_file_offset
    extracted_system_version_file = extracted_romfs[system_version_file_offset:system_version_file_length]
    firmware_version = extracted_system_version_file[0x68:0x6E].decode('utf-8')
    return firmware_version

if __name__ == "__main__":
    sort_nca("firmware")
    fat32_path = Path('sorted_firmware/by-type/romfs/0100000000000819/data.nca')
    system_version_path = Path('sorted_firmware/by-type/romfs/0100000000000809/data.nca')
    mariko_master_kek_source = extract_packages.process_package12(Path(fat32_path))
    system_version = get_system_version(system_version_path, mariko_master_kek_source)
    print(f'\nfirmware version of files provided is: {system_version}\n')
    fat32hash = sha256(open('FS.kip1', 'rb').read()).hexdigest().upper()
    print(f'{system_version} fat32 sha256 = {fat32hash}')
    es_path = Path('sorted_firmware/by-type/exefs/0100000000000033/program.nca')
    nifm_path = Path('sorted_firmware/by-type/exefs/010000000000000F/program.nca')
    nim_path = Path('sorted_firmware/by-type/exefs/0100000000000025/program.nca')
    ssl_path = Path('sorted_firmware/by-type/exefs/0100000000000024/program.nca')
    print(f'{system_version} es_buildID: {extract_exefs.prepare_exefs(es_path, "es.nso0")}') # prints buildid and outputs 
    print(f'{system_version} nifm_buildID: {extract_exefs.prepare_exefs(nifm_path, "nifm.nso0")}')
    print(f'{system_version} nim_buildID: {extract_exefs.prepare_exefs(nim_path, "nim.nso0")}')
    print(f'{system_version} ssl_buildID: {extract_exefs.prepare_exefs(ssl_path, "ssl.nso0")}')