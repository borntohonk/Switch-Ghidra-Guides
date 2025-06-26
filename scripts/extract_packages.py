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
import re
import nca
from pathlib import Path

try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util import Counter
except ModuleNotFoundError:
    try:
        from Crypto.Cipher import AES
        from Crypto.Util import Counter
    except ModuleNotFoundError:
        print('Please install pycryptodome(ex) first!')
        sys.exit(1)

import key_sources as key_sources
import aes_sample
import nxo64

def decrypt_cbc(input, key, IV):
    cipher = AES.new(key, AES.MODE_CBC, iv=IV)
    output = cipher.decrypt(input)
    return output

def decrypt_ecb(input, key):
    cipher = AES.new(key, AES.MODE_ECB)
    output = cipher.decrypt(input)
    return output

def encrypt_ecb(input, key):
    cipher = AES.new(key, AES.MODE_ECB)
    output = cipher.encrypt(input)
    return output

def decrypt_ctr(input, key, CTR):
    ctr = Counter.new(128, initial_value=int.from_bytes(CTR, byteorder='big'))
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    output = cipher.decrypt(input)
    return output

def extract_package2(extracted_romfs):
    extracted_romfs = extracted_romfs
    result = re.search(b'\x70\x61\x63\x6B\x61\x67\x65\x32', extracted_romfs)
    package2_size_location = result.start() - 0x10
    package2_size_length = package2_size_location + 0x4
    package2_size = int.from_bytes(extracted_romfs[package2_size_location:package2_size_length], "little", signed=False) + 0x200
    package2_offset_location = result.start() - 0x18
    package2_offset_length = package2_offset_location + 0x4
    package2_offset = int.from_bytes(extracted_romfs[package2_offset_location:package2_offset_length], "little", signed=False) + 0x200
    package2_length = package2_size + package2_offset
    with open('package2', 'wb') as nca_romfs:
        nca_romfs.write(extracted_romfs[package2_offset:package2_length])
        nca_romfs.close()

def decrypt_package2_and_extract_fs_from_ini1(package2, pkg2_key):
    with open(package2, 'rb') as f:
        data = f.read()
        package2_key = pkg2_key
        package2_header_offset = 0x100
        f.seek(package2_header_offset)
        encrypted_package2_header = f.read(0x100)
        package2_header_ctr_offset = 0x100
        f.seek(package2_header_ctr_offset)
        package2_header_ctr = f.read(0x10)
        decrypted_package2_header = decrypt_ctr(encrypted_package2_header, package2_key, package2_header_ctr)
        package2_header_ctr = decrypted_package2_header[0x0:0x10]
        package2_section_0_ctr = decrypted_package2_header[0x10:0x20]
        package2_section_0_size = int.from_bytes(decrypted_package2_header[0x60:0x64], "little", signed=False)
        f.seek(0x200)
        package2_section_0 = f.read(package2_section_0_size)
        decrypted_package2_section_0 = decrypt_ctr(package2_section_0, package2_key, package2_section_0_ctr)
        fs_result = re.search(bytes([0x4B, 0x49, 0x50, 0x31, 0x46, 0x53]), decrypted_package2_section_0)
        fs_kip1_start = fs_result.start()
        loader_result = re.search(bytes([0x4B, 0x49, 0x50, 0x31, 0x4C, 0x6F, 0x61, 0x64, 0x65, 0x72]), decrypted_package2_section_0)
        loader_kip1_start = loader_result.start()
        fs_kip1 = decrypted_package2_section_0[fs_kip1_start:loader_kip1_start]
        with open('FS.kip1', 'wb') as fs_kip1_file:
            fs_kip1_file.write(fs_kip1)
            fs_kip1_file.close()
        with open('FS.kip1', 'rb') as compressed_fs_kip:
            nxo64.write_file(f'uFS.kip1', nxo64.decompress_kip(compressed_fs_kip))
            compressed_fs_kip.close()

def extract_package1(extracted_romfs):
    extracted_romfs = extracted_romfs
    result = re.search(b'\x70\x61\x63\x6B\x61\x67\x65\x31\x34', extracted_romfs)
    package1_size_location = result.start() - 0x10
    package1_size_length = package1_size_location + 0x4
    package1_size = int.from_bytes(extracted_romfs[package1_size_location:package1_size_length], "little", signed=False) + 0x200
    package1_offset_location = result.start() - 0x18
    package1_offset_length = package1_offset_location + 0x4
    package1_offset = int.from_bytes(extracted_romfs[package1_offset_location:package1_offset_length], "little", signed=False) + 0x200
    package1_length = package1_size + package1_offset
    package1_enc = extracted_romfs[package1_offset:package1_length]
    return package1_enc

def decrypt_mariko_package1(encrypted_package1):
    package1 = encrypted_package1
    header = package1[0x0:0x190]
    bl_size = package1[0x154:0x158]
    bl_size = int.from_bytes(bl_size, "little", signed=False)
    enc_size = bl_size
    if enc_size > 0:
        aes_iv = package1[0x170:0x180]
        encrypted_package1_offset = 0x180
        encrypted_package1 = package1[0x180:enc_size]
        decrypted_package1 = decrypt_cbc(encrypted_package1, key_sources.mariko_bek, aes_iv)
        package1_dec = header + decrypted_package1[0x10:]
        return package1_dec

def get_mariko_key_sources(decrypted_package1):
    result1 = re.search(b'\x4F\x59\x41\x53\x55\x4D\x49', decrypted_package1)
    mariko_master_kek_source_dev_start = result1.end() + 0x22
    mariko_master_kek_source_dev_end = mariko_master_kek_source_dev_start + 0x10
    mariko_master_kek_source_dev = decrypted_package1[mariko_master_kek_source_dev_start:mariko_master_kek_source_dev_end]
    mariko_master_kek_source_prod_start = result1.end() + 0x32
    mariko_master_kek_source_prod_end = mariko_master_kek_source_prod_start + 0x10
    mariko_master_kek_source_prod = decrypted_package1[mariko_master_kek_source_prod_start:mariko_master_kek_source_prod_end]
    revision = decrypted_package1[0x150:0x151].hex().upper()
    incremented_revision = int(revision) - 0x1
    return mariko_master_kek_source_prod, mariko_master_kek_source_dev, incremented_revision

def process_package12(nca_path):
    master_key_00 = aes_sample.master_keys(key_sources.mariko_master_kek_sources[-1])[0]
    key_area_key_application_00 = aes_sample.generateKek(key_sources.key_area_key_application_source, master_key_00, key_sources.aes_kek_generation_source, key_sources.aes_key_generation_source)
    nca_file = nca.Nca(nca_path, key_area_key_application_00)
    decrypted_nca_header = nca_file.decrypted_nca_header
    decrypted_section_00 = nca_file.decrypted_sections[0]
    titleId = nca_file.titleId
    if titleId == "0100000000000819" or "010000000000081B":
        extracted_romfs = nca.extract_romfs(decrypted_nca_header, decrypted_section_00)
        encrypted_package1 = extract_package1(extracted_romfs)
        extract_package2(extracted_romfs)
        decrypted_package1 = decrypt_mariko_package1(encrypted_package1)
        mariko_master_kek_source, mariko_master_kek_source_dev, revision = get_mariko_key_sources(decrypted_package1)
        master_kek, master_key, package2_key, titlekek, key_area_key_system, key_area_key_ocean, key_area_key_application = aes_sample.single_keygen(mariko_master_kek_source) # directly from provided FS nca, requires mariko_bek
        decrypt_package2_and_extract_fs_from_ini1('package2', package2_key)
        if titleId == "0100000000000819":
            if mariko_master_kek_source in key_sources.mariko_master_kek_sources:
                print(f'mariko_master_kek_source_{revision} = {mariko_master_kek_source.hex().upper()}')
                print(f'master_kek_{revision} = {master_kek.hex().upper()}')
                print(f'master_key_{revision} = {master_key.hex().upper()}')
                print(f'package2_key_{revision} = {package2_key.hex().upper()}')
                print(f'key_area_key_system_{revision} = {key_area_key_system.hex().upper()}')
                print(f'key_area_key_ocean_{revision} = {key_area_key_ocean.hex().upper()}')
                print(f'key_area_key_application_{revision} = {key_area_key_application.hex().upper()}')
            else:
                new_master_kek = decrypt_ecb(mariko_master_kek_source, key_sources.mariko_kek)
                new_master_key = decrypt_ecb(key_sources.Master_Key_Source, new_master_kek)
                new_master_kek_source = encrypt_ecb(new_master_kek, key_sources.tsec_root_key_02)
                new_master_kek_dev =  decrypt_ecb(new_master_kek_source, key_sources.tsec_root_key_02_dev)
                new_master_key_dev =  decrypt_ecb(key_sources.Master_Key_Source, new_master_kek_dev)
                previous_mariko_master_kek_source = key_sources.mariko_master_kek_sources[-1]
                previous_master_kek = decrypt_ecb(previous_mariko_master_kek_source, key_sources.mariko_kek)
                previous_master_key = decrypt_ecb(key_sources.Master_Key_Source, previous_master_kek)
                previous_master_kek_source = encrypt_ecb(previous_master_kek, key_sources.tsec_root_key_02)
                previous_master_kek_dev =  decrypt_ecb(previous_master_kek_source, key_sources.tsec_root_key_02_dev)
                previous_master_key_dev =  decrypt_ecb(key_sources.Master_Key_Source, previous_master_kek_dev)
                new_master_key_source_vector = encrypt_ecb(previous_master_key, new_master_key).hex().upper()
                new_master_key_source_vector_dev = encrypt_ecb(previous_master_key_dev, new_master_key_dev).hex().upper()
                formatted_mariko_master_kek_source = '0x' + ', 0x'.join(mariko_master_kek_source.hex().upper()[i:i+2] for i in range(0, len(mariko_master_kek_source.hex().upper()), 2))
                formatted_mariko_master_kek_source_dev = '0x' + ', 0x'.join(mariko_master_kek_source_dev.hex().upper()[i:i+2] for i in range(0, len(mariko_master_kek_source_dev.hex().upper()), 2))
                formatted_vector = '0x' + ', 0x'.join(new_master_key_source_vector[i:i+2] for i in range(0, len(new_master_key_source_vector), 2))
                formatted_vector_dev = '0x' + ', 0x'.join(new_master_key_source_vector_dev[i:i+2] for i in range(0, len(new_master_key_source_vector_dev), 2))
                formatted_master_kek_source = '0x' + ', 0x'.join(new_master_kek_source.hex().upper()[i:i+2] for i in range(0, len(new_master_kek_source.hex().upper()), 2))
                print(f'mariko_master_kek_source_{revision} = {mariko_master_kek_source.hex().upper()}')
                print(f'master_kek_source_{revision} = {new_master_kek_source.hex().upper()}')
                print(f'master_kek_{revision} = ' + new_master_kek.hex().upper())
                print(f'master_key_{revision} = '  +   new_master_key.hex().upper())
                print()
                print(f'bytes([{formatted_vector}]),') # "MasterKeySources" https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L116-L136
                print(f'^ add this string to Production_Master_Key_Vectors array ^')
                print(f'bytes([{formatted_master_kek_source}]),') # "EristaMasterKekSource" https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L34-L37
                print(f'^ add this string to master_kek_sources array ^')
                print(f'bytes([{formatted_mariko_master_kek_source}]),') # "MarikoMasterKekSource" https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L24-L27
                print(f'^ add this string to mariko_master_kek_sources array ^')
                print()
                print(f'mariko_master_kek_source_dev_{revision} = {mariko_master_kek_source_dev.hex().upper()}')
                print(f'master_kek_dev_{revision} = ' + new_master_kek_dev.hex().upper())
                print(f'master_key_dev_{revision} = '  +   new_master_key_dev.hex().upper())
                print()
                print(f'bytes([{formatted_vector_dev}]),')
                print(f'^ add this string to Development_Master_Key_Vectors array ^') # "MasterKeySourcesDev" https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L138-L158
                print(f'bytes([{formatted_mariko_master_kek_source_dev}]),')
                print(f'^ unused, but output for consistency ^') # "MarikoMasterKekSourceDev" https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L29-L32
        return mariko_master_kek_source
        #else:
            # implement proper romfs extraction to make this necessary
            #decrypted_section_0 = nca.decrypt_section_0(nca, header_key, key_area_key_application_13, decrypted_nca_header, ctr) # todo, key_area_key make dynamic
            #extracted_romfs = extract_romfs(decrypted_nca_header, decrypted_section_0)