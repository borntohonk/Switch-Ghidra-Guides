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
import sys
import nca
from hashlib import sha256

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

from keys import RootKeys
from key_sources import KeySources
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

def decrypt_package2_and_extract_fs_from_ini1(package2, pkg2_key):
    with open(package2, 'rb') as f:
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

def decrypt_package1(encrypted_package1):
    key_sources = KeySources()
    tsec_keys = aes_sample.TsecKeygen(key_sources.tsec_secret_26)
    package1 = encrypted_package1
    header = package1[0x0:0x190]
    bl_size = package1[0x154:0x158]
    bl_size = int.from_bytes(bl_size, "little", signed=False)
    enc_size = bl_size
    if enc_size > 0:
        aes_iv = package1[0x170:0x180]
        encrypted_package1 = package1[0x180:enc_size]
        decrypted_package1 = decrypt_cbc(encrypted_package1, tsec_keys.package1_key_08, aes_iv)
        package1_dec = header + decrypted_package1[0x10:]
        return package1_dec

def get_key_sources(decrypted_package1):
    result1 = re.search(b'\x4F\x59\x41\x53\x55\x4D\x49', decrypted_package1)
    master_kek_source_prod_start = result1.end() + 0x42
    master_kek_source_prod_end = master_kek_source_prod_start + 0x10
    master_kek_source_prod = decrypted_package1[master_kek_source_prod_start:master_kek_source_prod_end]
    return master_kek_source_prod

def process_package12(nca_path):
    root_keys = RootKeys()
    key_sources = KeySources()
    tsec_keys = aes_sample.TsecKeygen(key_sources.tsec_secret_26)
    master_kek_source_for_keygen = key_sources.master_kek_sources[0]
    keys = aes_sample.single_keygen(master_kek_source_for_keygen)
    nca_file = nca.Nca(nca_path, keys)
    decrypted_section_00 = nca_file.decrypted_sections[0]
    titleId = nca_file.titleId
    if titleId == "0100000000000819" or "010000000000081B":
        romfs = nca.Romfs(decrypted_section_00[nca_file.fsheaders[0].romfs_start:nca_file.fsheaders[0].romfs_end], f"./sorted_firmware/by-type/Data/{titleId}/romfs/")
        romfs
        with open(f'sorted_firmware/by-type/Data/{titleId}/romfs/nx/package1', 'rb') as file:
            encrypted_package1 = file.read()
            decrypted_package1 = decrypt_package1(encrypted_package1)
            file.close()
        master_kek_source = get_key_sources(decrypted_package1)
        master_kek, master_key, package2_key, titlekek, key_area_key_system, key_area_key_ocean, key_area_key_application = aes_sample.single_keygen(master_kek_source)
        decrypt_package2_and_extract_fs_from_ini1(f'sorted_firmware/by-type/Data/{titleId}/romfs/nx/package2', package2_key)
        incremented_revision = f'{(len(key_sources.master_kek_sources)):x}'
        current_revision = f'{(len(key_sources.master_kek_sources) - 1):x}'
        if titleId == "0100000000000819":
            if master_kek_source in key_sources.master_kek_sources:
                print(f'master_kek_source_{current_revision} = {master_kek_source.hex().upper()}')
                print(f'master_kek_{current_revision} = {master_kek.hex().upper()}')
                print(f'master_key_{current_revision} = {master_key.hex().upper()}')
                print(f'package2_key_{current_revision} = {package2_key.hex().upper()}')
                print(f'titlekek_{current_revision} = {titlekek.hex().upper()}')
                print(f'key_area_key_system_{current_revision} = {key_area_key_system.hex().upper()}')
                print(f'key_area_key_ocean_{current_revision} = {key_area_key_ocean.hex().upper()}')
                print(f'key_area_key_application_{current_revision} = {key_area_key_application.hex().upper()}')
                if sha256(root_keys.mariko_kek).hexdigest().upper() != "ACEA0798A729E8E0B3EF6D83CF7F345537E41ACCCCCAD8686D35E3F5454D5132":
                    print("mariko_kek is incorrectly filled in, the key filled into keys.py is incorrect or blank, mariko_master_kek_source wont be generated")
                else:
                    mariko_master_kek_source = encrypt_ecb(master_kek, root_keys.mariko_kek)
                    print(f'mariko_master_kek_source_{current_revision} = {mariko_master_kek_source.hex().upper()}')
            else:
                new_master_kek = decrypt_ecb(master_kek_source, tsec_keys.tsec_root_key_02)
                new_master_key = decrypt_ecb(key_sources.master_key_source, new_master_kek)
                previous_master_kek_source = key_sources.master_kek_sources[-1]
                previous_master_kek = decrypt_ecb(previous_master_kek_source, tsec_keys.tsec_root_key_02)
                previous_master_key = decrypt_ecb(key_sources.master_key_source, previous_master_kek)
                new_master_key_source_vector = encrypt_ecb(previous_master_key, new_master_key).hex().upper()
                formatted_master_kek_source = '0x' + ', 0x'.join(master_kek_source.hex().upper()[i:i+2] for i in range(0, len(master_kek_source.hex().upper()), 2))
                formatted_vector = '0x' + ', 0x'.join(new_master_key_source_vector[i:i+2] for i in range(0, len(new_master_key_source_vector), 2))
                print(f'master_kek_source_{incremented_revision} = {master_kek_source.hex().upper()}')
                print(f'master_kek_{incremented_revision} = ' + new_master_kek.hex().upper())
                print(f'master_key_{incremented_revision} = '  +   new_master_key.hex().upper())
                print()
                print(f'bytes([{formatted_vector}]),') # "MasterKeySources" https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L116-L136
                print(f'^ add this string to master_key_vectors array ^')
                print(f'bytes([{formatted_master_kek_source}]),') # # "EristaMasterKekSource" https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L34-L37
                print(f'^ add this string to master_kek_sources array ^')
                print()
                new_master_kek_dev =  decrypt_ecb(master_kek_source, tsec_keys.tsec_root_key_02_dev)
                new_master_key_dev =  decrypt_ecb(key_sources.master_key_source, new_master_kek_dev)
                previous_master_kek_dev =  decrypt_ecb(previous_master_kek_source, tsec_keys.tsec_root_key_02_dev)
                previous_master_key_dev =  decrypt_ecb(key_sources.master_key_source, previous_master_kek_dev)
                new_master_key_source_vector_dev = encrypt_ecb(previous_master_key_dev, new_master_key_dev).hex().upper()
                formatted_vector_dev = '0x' + ', 0x'.join(new_master_key_source_vector_dev[i:i+2] for i in range(0, len(new_master_key_source_vector_dev), 2))
                print(f'master_kek_dev_{incremented_revision} = ' + new_master_kek_dev.hex().upper())
                print(f'master_key_dev_{incremented_revision} = '  +   new_master_key_dev.hex().upper())
                print()
                print(f'bytes([{formatted_vector_dev}]),')
                print(f'^ add this string to master_key_vectors_dev array ^') # "MasterKeySourcesDev" https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L138-L158
                if sha256(root_keys.mariko_kek).hexdigest().upper() != "ACEA0798A729E8E0B3EF6D83CF7F345537E41ACCCCCAD8686D35E3F5454D5132":
                    print("mariko_kek is incorrectly filled in, the key filled into keys.py is incorrect or blank, mariko_master_kek_source wont be generated")
                else:
                    new_mariko_master_kek_source = encrypt_ecb(new_master_kek, root_keys.mariko_kek)
                    print(f'mariko_master_kek_source_{incremented_revision} = {new_mariko_master_kek_source.hex().upper()}')
                    formatted_mariko_master_kek_source = '0x' + ', 0x'.join(new_mariko_master_kek_source.hex().upper()[i:i+2] for i in range(0, len(new_mariko_master_kek_source.hex().upper()), 2))
                    print(f'bytes([{formatted_mariko_master_kek_source}]),') # "MarikoMasterKekSource" https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L24-L27
                    print(f'^ add this string to mariko_master_kek_sources array ^')
        return master_kek_source