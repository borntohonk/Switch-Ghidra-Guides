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

import sys
from hashlib import sha256
from keys import RootKeys
from key_sources import KeySources

try:
    from Cryptodome.Cipher import AES
except ModuleNotFoundError:
    try:
        from Crypto.Cipher import AES
    except ModuleNotFoundError:
        print('Please install pycryptodome(ex) first!')
        sys.exit(1)

def decrypt(input, key):
    cipher = AES.new(key, AES.MODE_ECB)
    output = cipher.decrypt(input)
    return output

def encrypt(input, key):
    cipher = AES.new(key, AES.MODE_ECB)
    output = cipher.encrypt(input)
    return output

def generateKek(src, masterKey, kek_seed, key_seed):
    kek = []
    src_kek = []

    kek = decrypt(kek_seed ,masterKey)
    src_kek = decrypt(src ,kek)
    if key_seed is not None:
        return decrypt(key_seed ,src_kek)
    else:
        return src_kek

def single_keygen(master_kek_source):
    key_sources = KeySources()
    tsec_keys = TsecKeygen(key_sources.tsec_secret_26)
    master_kek = decrypt(master_kek_source, tsec_keys.tsec_root_key_02)
    master_key = decrypt(key_sources.master_key_source, master_kek)
    package2_key = decrypt(key_sources.package2_key_source, master_key)
    titlekek = decrypt(key_sources.titlekek_source, master_key)
    key_area_key_system = generateKek(key_sources.key_area_key_system_source, master_key , key_sources.aes_kek_generation_source, key_sources.aes_key_generation_source)
    key_area_key_ocean = generateKek(key_sources.key_area_key_ocean_source, master_key , key_sources.aes_kek_generation_source, key_sources.aes_key_generation_source)
    key_area_key_application = generateKek(key_sources.key_area_key_application_source, master_key , key_sources.aes_kek_generation_source, key_sources.aes_key_generation_source)
    return master_kek, master_key, package2_key, titlekek, key_area_key_system, key_area_key_ocean, key_area_key_application

class Keygen():
    def __init__(self, tsec_root_key_02):
        self.key_sources = KeySources()
        self.tsec_root_key_02 = tsec_root_key_02
        self.mariko_master_kek_sources = self.key_sources.mariko_master_kek_sources
        self.master_kek_sources = self.key_sources.master_kek_sources
        self.master_key_vectors = self.key_sources.master_key_vectors
        self.master_kek = [decrypt(i, self.tsec_root_key_02) for i in self.master_kek_sources]
        self.master_key = [decrypt(self.key_sources.master_key_source, i) for i in self.master_kek]
        self.current_master_key = self.master_key[-1]
        self.header_kek = generateKek(self.key_sources.header_kek_source, self.master_key[0], self.key_sources.aes_kek_generation_source, self.key_sources.aes_key_generation_source)
        self.header_key = decrypt(self.key_sources.header_key_source, self.header_kek)
        self.package2_key = [decrypt(self.key_sources.package2_key_source, i) for i in self.master_key]
        self.titlekek = [decrypt(self.key_sources.titlekek_source, i) for i in self.master_key]
        self.key_area_key_application = [generateKek(self.key_sources.key_area_key_application_source, i, self.key_sources.aes_kek_generation_source, self.key_sources.aes_key_generation_source) for i in self.master_key]
        self.key_area_key_ocean = [generateKek(self.key_sources.key_area_key_ocean_source, i, self.key_sources.aes_kek_generation_source, self.key_sources.aes_key_generation_source) for i in self.master_key]
        self.key_area_key_system = [generateKek(self.key_sources.key_area_key_system_source, i, self.key_sources.aes_kek_generation_source, self.key_sources.aes_key_generation_source) for i in self.master_key]

class KeygenDev():
    def __init__(self, tsec_root_key_02):
        self.key_sources = KeySources()
        self.tsec_root_key_02 = tsec_root_key_02
        self.mariko_master_kek_sources = self.key_sources.mariko_master_kek_sources
        self.master_kek_sources = self.key_sources.master_kek_sources
        self.master_key_vectors = self.key_sources.master_key_vectors
        self.master_kek = [decrypt(i, self.tsec_root_key_02) for i in self.master_kek_sources]
        self.master_key = master_keys_dev()
        self.current_master_key = self.master_key[-1]
        self.header_kek = generateKek(self.key_sources.header_kek_source, self.master_key[0], self.key_sources.aes_kek_generation_source, self.key_sources.aes_key_generation_source)
        self.header_key = decrypt(self.key_sources.header_key_source, self.header_kek)
        self.package2_key = [decrypt(self.key_sources.package2_key_source, i) for i in self.master_key]
        self.titlekek = [decrypt(self.key_sources.titlekek_source, i) for i in self.master_key]
        self.key_area_key_application = [generateKek(self.key_sources.key_area_key_application_source, i, self.key_sources.aes_kek_generation_source, self.key_sources.aes_key_generation_source) for i in self.master_key]
        self.key_area_key_ocean = [generateKek(self.key_sources.key_area_key_ocean_source, i, self.key_sources.aes_kek_generation_source, self.key_sources.aes_key_generation_source) for i in self.master_key]
        self.key_area_key_system = [generateKek(self.key_sources.key_area_key_system_source, i, self.key_sources.aes_kek_generation_source, self.key_sources.aes_key_generation_source) for i in self.master_key]

class TsecKeygen():
    def __init__(self, hovi_kek):
        if sha256(hovi_kek).hexdigest().upper() == "CEFE01C9E3EEEF1A73B8C10D742AE386279B7DFF30A2FBC0AABD058C1F135833":
            self.hovi_kek = hovi_kek
            # nvidia falcon crypto:

            # (encrypted if _00 and _01 / decrypted if _02 by tsec_secret_26, then the result is then used as key to encrypt tsec_auth_signatures_%%, essentially this falcon instruction chain:)
            # buffer = address to stored seed combination hovi + _sig/_kek/_enc + _key + _prd/_dev/_iv1
            # csecret $c1, 0x26 (loads csecret 0x26 into $c1)
            # ckeyreg $c1 (uses $c1 as key for encryption/decryption)
            # cenc/cdec $c0, buffer (result is tsec_root_kek_%% // package1_kek_%% // package1_mac_kek_%%)
            # csigenc $c0, $c0 (resulting key is Package1_Key_06/_07/_08 // Package1_Mac_Key_06/_07/_08 // Tsec_Root_Key_00/_01/_02 // hovi_iv_00/_01/_02)
            # output by secureboot tsec firmware stage within package1

            # The following sources are made out of seed parts of the hex representations of the words:
            # [0]"HOVI", [1]"_SIG"/"_ENC"/"_KEK", [2]"_KEY", [3]"_IV1"/"_PRD"/"_DEV"

            self.package1_mac_kek_source                = bytes([0x48, 0x4F, 0x56, 0x49, 0x5F, 0x53, 0x49, 0x47, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x50, 0x52, 0x44]) # HOVI_SIG_KEY_PRD
            self.package1_kek_source                    = bytes([0x48, 0x4F, 0x56, 0x49, 0x5F, 0x45, 0x4E, 0x43, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x50, 0x52, 0x44]) # HOVI_ENC_KEY_PRD 
            self.tsec_root_kek_source                   = bytes([0x48, 0x4F, 0x56, 0x49, 0x5F, 0x4B, 0x45, 0x4B, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x50, 0x52, 0x44]) # HOVI_KEK_KEY_PRD
            self.tsec_hovi_iv_key                       = bytes([0x48, 0x4F, 0x56, 0x49, 0x5F, 0x45, 0x4E, 0x43, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x49, 0x56, 0x31]) # HOVI_ENC_KEY_IV1
            self.package1_mac_kek_source_dev            = bytes([0x48, 0x4F, 0x56, 0x49, 0x5F, 0x53, 0x49, 0x47, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x44, 0x45, 0x56]) # HOVI_SIG_KEY_DEV
            self.package1_kek_source_dev                = bytes([0x48, 0x4F, 0x56, 0x49, 0x5F, 0x45, 0x4E, 0x43, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x44, 0x45, 0x56]) # HOVI_ENC_KEY_DEV
            self.tsec_root_kek_source_dev               = bytes([0x48, 0x4F, 0x56, 0x49, 0x5F, 0x4B, 0x45, 0x4B, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x44, 0x45, 0x56]) # HOVI_KEK_KEY_DEV

            # tsec auth hash/signature can be found by searching for "1D E3 64 58 FA 9E C2 98 D5 B4 57 74 B5 82 E7 11", selecting the last result +0x1, or +0x30 from start of result found (zeroes encrypted by tsec_secret_06)
            self.tsec_auth_signature_00                 = bytes([0xA7, 0x7B, 0x86, 0x58, 0x6A, 0xE1, 0xB0, 0x3D, 0x4F, 0xFB, 0xA3, 0xAD, 0xA8, 0xF8, 0xDE, 0x32]) # source 0x3300 encrypted package1 6.2.0 
            self.tsec_auth_signature_01                 = bytes([0xA3, 0xFF, 0xB0, 0xF6, 0xBC, 0x49, 0xA0, 0x6D, 0xF2, 0xFC, 0x79, 0x16, 0x97, 0xD8, 0x1D, 0x32]) # source 0x3B00 encrypted package1 7.0.0
            self.tsec_auth_signature_02                 = bytes([0x0B, 0x55, 0xCC, 0x08, 0x20, 0xE6, 0x30, 0x7F, 0xD0, 0x87, 0x47, 0x9E, 0xAA, 0x2E, 0x7F, 0x98]) # source 0x3D00 encrypted package1 8.1.0+

            self.tsec_root_kek_00 = encrypt(self.tsec_root_kek_source, self.hovi_kek)
            self.tsec_root_kek_01 = self.tsec_root_kek_00 
            self.tsec_root_kek_02 = decrypt(self.tsec_root_kek_source, self.hovi_kek)

            self.package1_kek_00 = encrypt(self.package1_kek_source, self.hovi_kek)
            self.package1_kek_01 = self.package1_kek_00
            self.package1_kek_02 = decrypt(self.package1_kek_source, self.hovi_kek)

            self.package1_mac_kek_00 = encrypt(self.package1_mac_kek_source, self.hovi_kek)
            self.package1_mac_kek_01 = self.package1_mac_kek_00
            self.package1_mac_kek_02 = decrypt(self.package1_mac_kek_source, self.hovi_kek)

            self.tsec_root_key_00 = encrypt(self.tsec_auth_signature_00, self.tsec_root_kek_00)
            self.tsec_root_key_01 = encrypt(self.tsec_auth_signature_01, self.tsec_root_kek_01)
            self.tsec_root_key_02 = encrypt(self.tsec_auth_signature_02, self.tsec_root_kek_02)

            self.package1_key_06 = encrypt(self.tsec_auth_signature_00, self.package1_kek_00)
            self.package1_key_07 = encrypt(self.tsec_auth_signature_01, self.package1_kek_01)
            self.package1_key_08 = encrypt(self.tsec_auth_signature_02, self.package1_kek_02)

            self.package1_mac_key_06 = encrypt(self.tsec_auth_signature_00, self.package1_mac_kek_00)
            self.package1_mac_key_07 = encrypt(self.tsec_auth_signature_01, self.package1_mac_kek_01)
            self.package1_mac_key_08 = encrypt(self.tsec_auth_signature_02, self.package1_mac_kek_02)

            self.tsec_root_kek_00_dev = encrypt(self.tsec_root_kek_source_dev, self.hovi_kek)
            self.tsec_root_kek_01_dev = self.tsec_root_kek_00_dev 
            self.tsec_root_kek_02_dev = decrypt(self.tsec_root_kek_source_dev, self.hovi_kek)

            self.package1_kek_00_dev = encrypt(self.package1_kek_source_dev, self.hovi_kek)
            self.package1_kek_01_dev = self.package1_kek_00_dev
            self.package1_kek_02_dev = decrypt(self.package1_kek_source_dev, self.hovi_kek)

            self.package1_mac_kek_00_dev = encrypt(self.package1_mac_kek_source_dev, self.hovi_kek)
            self.package1_mac_kek_01_dev = self.package1_mac_kek_00_dev
            self.package1_mac_kek_02_dev = decrypt(self.package1_mac_kek_source_dev, self.hovi_kek)

            self.tsec_root_key_00_dev = encrypt(self.tsec_auth_signature_00, self.tsec_root_kek_00_dev)
            self.tsec_root_key_01_dev = encrypt(self.tsec_auth_signature_01, self.tsec_root_kek_01_dev)
            self.tsec_root_key_02_dev = encrypt(self.tsec_auth_signature_02, self.tsec_root_kek_02_dev)

            self.package1_key_06_dev = encrypt(self.tsec_auth_signature_00, self.package1_kek_00_dev)
            self.package1_key_07_dev = encrypt(self.tsec_auth_signature_01, self.package1_kek_01_dev)
            self.package1_key_08_dev = encrypt(self.tsec_auth_signature_02, self.package1_kek_02_dev)

            self.package1_mac_key_06_dev = encrypt(self.tsec_auth_signature_00, self.package1_mac_kek_00_dev)
            self.package1_mac_key_07_dev = encrypt(self.tsec_auth_signature_01, self.package1_mac_kek_01_dev)
            self.package1_mac_key_08_dev = encrypt(self.tsec_auth_signature_02, self.package1_mac_kek_02_dev)

def get_latest_master_key():
    key_sources = KeySources()
    hovi_kek = key_sources.tsec_secret_26
    tsec_keygen = TsecKeygen(hovi_kek)
    tsec_root_key_02 = tsec_keygen.tsec_root_key_02
    tsec_root_key_02_dev = tsec_keygen.tsec_root_key_02_dev
    latest_master_kek_source = key_sources.master_kek_sources[-1]
    master_kek = decrypt(latest_master_kek_source, tsec_root_key_02)
    master_kek_dev = decrypt(latest_master_kek_source, tsec_root_key_02_dev)
    master_key = decrypt(key_sources.master_key_source, master_kek)
    master_key_dev = decrypt(key_sources.master_key_source, master_kek_dev)
    return master_key, master_key_dev

def master_keys():
    latest_master_key = get_latest_master_key()[0]
    key_sources = KeySources()
    master_key_vectors = key_sources.master_key_vectors
    current_master_key = latest_master_key
    master_key = []
    first = True
    for i in reversed(master_key_vectors):
        if first:
            first = False
            previous_key = i
            next_master_key = decrypt(previous_key, current_master_key)
            master_key.append(current_master_key)
            master_key.append(next_master_key)
        else:
            key = previous_key
            previous_key = i
            next_master_key = decrypt(previous_key, next_master_key)
            master_key.append(next_master_key)
    master_key.reverse()
    return master_key

def master_keys_dev():
    latest_master_key = get_latest_master_key()[1]
    key_sources = KeySources()
    master_key_vectors = key_sources.master_key_vectors_dev
    current_master_key = latest_master_key
    master_key = []
    first = True
    for i in reversed(master_key_vectors):
        if first:
            first = False
            previous_key = i
            next_master_key = decrypt(previous_key, current_master_key)
            master_key.append(current_master_key)
            master_key.append(next_master_key)
        else:
            key = previous_key
            previous_key = i
            next_master_key = decrypt(previous_key, next_master_key)
            master_key.append(next_master_key)
    master_key.reverse()
    return master_key

def do_keygen():
    keys = "prod.keys"
    root_keys = RootKeys()
    key_sources = KeySources()
    hovi_kek = key_sources.tsec_secret_26
    tsec_keygen = TsecKeygen(hovi_kek)
    keygen = Keygen(tsec_keygen.tsec_root_key_02)

    with open(keys, 'w') as manual_crypto:
        manual_crypto.write(f'tsec_secret_26 = ' + f'{hovi_kek.hex().upper()}\n\n')
        manual_crypto.write(f'tsec_root_kek_00 = ' + f'{tsec_keygen.tsec_root_kek_00.hex().upper()}\n')
        manual_crypto.write(f'tsec_root_kek_01 = ' + f'{tsec_keygen.tsec_root_kek_01.hex().upper()}\n')
        manual_crypto.write(f'tsec_root_kek_02 = ' + f'{tsec_keygen.tsec_root_kek_02.hex().upper()}\n\n')

        manual_crypto.write(f'package1_mac_kek_00 = ' + f'{tsec_keygen.package1_mac_kek_00.hex().upper()}\n')
        manual_crypto.write(f'package1_mac_kek_01 = ' + f'{tsec_keygen.package1_mac_kek_01.hex().upper()}\n')
        manual_crypto.write(f'package1_mac_kek_02 = ' + f'{tsec_keygen.package1_mac_kek_02.hex().upper()}\n\n')

        manual_crypto.write(f'package1_kek_00 = ' + f'{tsec_keygen.package1_kek_00.hex().upper()}\n')
        manual_crypto.write(f'package1_kek_01 = ' + f'{tsec_keygen.package1_kek_01.hex().upper()}\n')
        manual_crypto.write(f'package1_kek_02 = ' + f'{tsec_keygen.package1_kek_02.hex().upper()}\n\n')

        manual_crypto.write(f'tsec_auth_signature_00 = ' + f'{tsec_keygen.tsec_auth_signature_00.hex().upper()}\n')
        manual_crypto.write(f'tsec_auth_signature_01 = ' + f'{tsec_keygen.tsec_auth_signature_01.hex().upper()}\n')
        manual_crypto.write(f'tsec_auth_signature_02 = ' + f'{tsec_keygen.tsec_auth_signature_02.hex().upper()}\n\n')

        manual_crypto.write(f'tsec_root_key_00 = ' + f'{tsec_keygen.tsec_root_key_00.hex().upper()}\n')
        manual_crypto.write(f'tsec_root_key_01 = ' + f'{tsec_keygen.tsec_root_key_01.hex().upper()}\n')
        manual_crypto.write(f'tsec_root_key_02 = ' + f'{tsec_keygen.tsec_root_key_02.hex().upper()}\n\n')

        manual_crypto.write(f'keyblob_mac_key_source = ' + f'{key_sources.keyblob_mac_key_source.hex().upper()}\n')
        # Write keyblob_key_source_%%
        count = -0x1
        for i in key_sources.keyblob_key_sources:
            count = count + 0x1
            keys = f'keyblob_key_source_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
            manual_crypto.write(f'{keys}\n')

        manual_crypto.write(f'\n')
        # Write master_kek_sources
        count = -0x1
        for i in key_sources.master_kek_sources:
            count = count + 0x1
            keys = f'master_kek_source_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
            manual_crypto.write(f'{keys}\n')

        manual_crypto.write(f'\n')
        if sha256(root_keys.mariko_bek).hexdigest().upper() == "491A836813E0733A0697B2FA27D0922D3D6325CE3C6BBEA982CF4691FAF6451A":
            manual_crypto.write(f'mariko_bek = ' + f'{root_keys.mariko_bek.hex().upper()}\n')
        if sha256(root_keys.mariko_kek).hexdigest().upper() == "ACEA0798A729E8E0B3EF6D83CF7F345537E41ACCCCCAD8686D35E3F5454D5132":
            manual_crypto.write(f'mariko_kek = ' + f'{root_keys.mariko_kek.hex().upper()}\n\n')

        # Write mariko_master_kek_sources
        count = -0x1
        for i in key_sources.mariko_master_kek_sources:
            count = count + 0x1
            keys = f'mariko_master_kek_source_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
            manual_crypto.write(f'{keys}\n')

        manual_crypto.write(f'\n')
        # generate master_kek_%% from all provided master_kek_sources
        master_keks = keygen.master_kek
        count = -0x1
        for i in master_keks:
            count = count + 0x1
            keys = f'master_kek_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
            manual_crypto.write(f'{keys}\n')
        
        manual_crypto.write(f'\n')
        manual_crypto.write(f'master_key_source = ' + f'{key_sources.master_key_source.hex().upper()}\n\n')

        # generate master_key_%% from all provided master_kek_%% using Master_Key_Source
        master_keys = keygen.master_key
        # Write master_key_%%
        count = -0x1
        for i in master_keys:
            count = count + 0x1
            keys = f'master_key_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
            manual_crypto.write(f'{keys}\n')

        manual_crypto.write(f'\npackage1_key_06 = ' + f'{tsec_keygen.package1_key_06.hex().upper()}\n')
        manual_crypto.write(f'package1_key_07 = ' + f'{tsec_keygen.package1_key_07.hex().upper()}\n')
        manual_crypto.write(f'package1_key_08 = ' + f'{tsec_keygen.package1_key_08.hex().upper()}\n\n')
        manual_crypto.write(f'package1_mac_key_06 = ' + f'{tsec_keygen.package1_mac_key_06.hex().upper()}\n')
        manual_crypto.write(f'package1_mac_key_07 = ' + f'{tsec_keygen.package1_mac_key_07.hex().upper()}\n')
        manual_crypto.write(f'package1_mac_key_08 = ' + f'{tsec_keygen.package1_mac_key_08.hex().upper()}\n')

        manual_crypto.write(f'\n')
        manual_crypto.write(f'package2_key_source = ' + f'{key_sources.package2_key_source.hex().upper()}\n\n')

        # generate package2_key_%% from all provided master_key_%% using package2_key_source
        package2_key = keygen.package2_key
        count = -0x1
        for i in package2_key:
            count = count + 0x1
            keys = f'package2_key_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
            manual_crypto.write(f'{keys}\n')

        manual_crypto.write(f'\n')
        manual_crypto.write(f'bis_kek_source = ' + f'{key_sources.bis_kek_source.hex().upper()}\n')

        # Write bis_key_source_%%
        count = -1
        for i in key_sources.bis_key_sources:
            count = count + 0x1
            keys = f'bis_key_source_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
            manual_crypto.write(f'{keys}\n')

        manual_crypto.write(f'\n')
        manual_crypto.write(f'per_console_key_source = ' + f'{key_sources.per_console_key_source.hex().upper()}\n')
        manual_crypto.write(f'retail_specific_aes_key_source = ' + f'{key_sources.retail_specific_aes_key_source.hex().upper()}\n')
        manual_crypto.write(f'aes_kek_generation_source = ' + f'{key_sources.aes_kek_generation_source.hex().upper()}\n')
        manual_crypto.write(f'aes_key_generation_source = ' + f'{key_sources.aes_key_generation_source.hex().upper()}\n')
        manual_crypto.write(f'titlekek_source = ' + f'{key_sources.titlekek_source.hex().upper()}\n\n')

        # generate title_kek_%% from all provided master_key_%% using titlekek_source
        titlekek = keygen.titlekek
        count = -0x1
        for i in titlekek:
            count = count + 0x1
            keys = f'titlekek_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
            manual_crypto.write(f'{keys}\n')

        manual_crypto.write(f'\n')

        manual_crypto.write(f'header_kek_source = ' + f'{key_sources.header_kek_source.hex().upper()}\n')
        manual_crypto.write(f'header_key_source = ' + f'{key_sources.header_key_source.hex().upper()}\n')
        manual_crypto.write(f'header_kek = ' + f'{keygen.header_kek.hex().upper()}\n')
        manual_crypto.write(f'header_key = ' + f'{keygen.header_key.hex().upper()}\n\n')

        manual_crypto.write(f'key_area_key_system_source = ' + f'{key_sources.key_area_key_system_source.hex().upper()}\n')
        manual_crypto.write(f'key_area_key_application_source = ' + f'{key_sources.key_area_key_application_source.hex().upper()}\n')
        manual_crypto.write(f'key_area_key_ocean_source = ' + f'{key_sources.key_area_key_ocean_source.hex().upper()}\n\n')

        manual_crypto.write(f'save_mac_kek_source = ' + f'{key_sources.save_mac_kek_source.hex().upper()}\n')
        manual_crypto.write(f'save_mac_key_source_00 = ' + f'{key_sources.save_mac_key_source_00.hex().upper()}\n')
        manual_crypto.write(f'save_mac_key_source_01 = ' + f'{key_sources.save_mac_key_source_01.hex().upper()}\n')
        manual_crypto.write(f'save_mac_sd_card_kek_source = ' + f'{key_sources.save_mac_sd_card_kek_source.hex().upper()}\n')
        manual_crypto.write(f'save_mac_sd_card_key_source = ' + f'{key_sources.save_mac_sd_card_key_source.hex().upper()}\n')
        manual_crypto.write(f'sd_card_kek_source = ' + f'{key_sources.sd_card_kek_source.hex().upper()}\n\n')

        manual_crypto.write(f'xci_header_key = ' + f'{key_sources.xci_header_key.hex().upper()}\n\n')

        # generate key_area_key_application_%% from all provided master_key_%% using key_area_key_application_source
        key_area_key_application = keygen.key_area_key_application
        count = -0x1
        for i in key_area_key_application:
            count = count +0x1
            keys = f'key_area_key_application_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
            manual_crypto.write(f'{keys}\n')

        manual_crypto.write(f'\n')

        # generate key_area_key_ocean_%% from all provided master_key_%% using key_area_key_ocean_source
        key_area_key_ocean = keygen.key_area_key_ocean
        count = -0x1
        for i in key_area_key_ocean:
            count = count +0x1
            keys = f'key_area_key_ocean_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
            manual_crypto.write(f'{keys}\n')

        manual_crypto.write(f'\n')

        # generate key_area_key_system_%% from all provided master_key_%% using key_area_key_system_source
        key_area_key_system = keygen.key_area_key_system
        count = -0x1
        for i in key_area_key_system:
            count = count +0x1
            keys = f'key_area_key_system_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
            manual_crypto.write(f'{keys}\n')


def do_dev_keygen():
    keys = "dev.keys"
    key_sources = KeySources()
    hovi_kek = key_sources.tsec_secret_26
    tsec_keygen = TsecKeygen(hovi_kek)
    keygen = KeygenDev(tsec_keygen.tsec_root_key_02_dev)

    with open(keys, 'w') as manual_crypto:
        manual_crypto.write(f'tsec_secret_26 = ' + f'{hovi_kek.hex().upper()}\n\n')
        manual_crypto.write(f'tsec_root_kek_00 = ' + f'{tsec_keygen.tsec_root_kek_00_dev.hex().upper()}\n')
        manual_crypto.write(f'tsec_root_kek_01 = ' + f'{tsec_keygen.tsec_root_kek_01_dev.hex().upper()}\n')
        manual_crypto.write(f'tsec_root_kek_02 = ' + f'{tsec_keygen.tsec_root_kek_02_dev.hex().upper()}\n\n')

        manual_crypto.write(f'package1_mac_kek_00 = ' + f'{tsec_keygen.package1_mac_kek_00_dev.hex().upper()}\n')
        manual_crypto.write(f'package1_mac_kek_01 = ' + f'{tsec_keygen.package1_mac_kek_01_dev.hex().upper()}\n')
        manual_crypto.write(f'package1_mac_kek_02 = ' + f'{tsec_keygen.package1_mac_kek_02_dev.hex().upper()}\n\n')

        manual_crypto.write(f'package1_kek_00 = ' + f'{tsec_keygen.package1_kek_00_dev.hex().upper()}\n')
        manual_crypto.write(f'package1_kek_01 = ' + f'{tsec_keygen.package1_kek_01_dev.hex().upper()}\n')
        manual_crypto.write(f'package1_kek_02 = ' + f'{tsec_keygen.package1_kek_02_dev.hex().upper()}\n\n')

        manual_crypto.write(f'tsec_auth_signature_00 = ' + f'{tsec_keygen.tsec_auth_signature_00.hex().upper()}\n')
        manual_crypto.write(f'tsec_auth_signature_01 = ' + f'{tsec_keygen.tsec_auth_signature_01.hex().upper()}\n')
        manual_crypto.write(f'tsec_auth_signature_02 = ' + f'{tsec_keygen.tsec_auth_signature_02.hex().upper()}\n\n')

        manual_crypto.write(f'tsec_root_key_00 = ' + f'{tsec_keygen.tsec_root_key_00_dev.hex().upper()}\n')
        manual_crypto.write(f'tsec_root_key_01 = ' + f'{tsec_keygen.tsec_root_key_01_dev.hex().upper()}\n')
        manual_crypto.write(f'tsec_root_key_02 = ' + f'{tsec_keygen.tsec_root_key_02_dev.hex().upper()}\n\n')

        manual_crypto.write(f'keyblob_mac_key_source = ' + f'{key_sources.keyblob_mac_key_source.hex().upper()}\n')
        # Write keyblob_key_source_%%
        count = -0x1
        for i in key_sources.keyblob_key_sources:
            count = count + 0x1
            keys = f'keyblob_key_source_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
            manual_crypto.write(f'{keys}\n')

        manual_crypto.write(f'\n')
        # Write master_kek_sources
        count = -0x1
        for i in key_sources.master_kek_sources:
            count = count + 0x1
            keys = f'master_kek_source_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
            manual_crypto.write(f'{keys}\n')

        manual_crypto.write(f'\n')
        # generate master_kek_%% from all provided mariko_master_kek_sources
        master_keks = keygen.master_kek
        count = -0x1
        for i in master_keks:
            count = count + 0x1
            keys = f'master_kek_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
            manual_crypto.write(f'{keys}\n')
        
        manual_crypto.write(f'\n')
        manual_crypto.write(f'master_key_source = ' + f'{key_sources.master_key_source.hex().upper()}\n\n')

        # generate master_key_%% from all provided master_kek_%% using Master_Key_Source
        master_keys = master_keys_dev()
        # Write master_key_%%
        count = -0x1
        for i in master_keys:
            count = count + 0x1
            keys = f'master_key_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
            manual_crypto.write(f'{keys}\n')

        manual_crypto.write(f'\npackage1_key_06 = ' + f'{tsec_keygen.package1_key_06_dev.hex().upper()}\n')
        manual_crypto.write(f'package1_key_07 = ' + f'{tsec_keygen.package1_key_07_dev.hex().upper()}\n')
        manual_crypto.write(f'package1_key_08 = ' + f'{tsec_keygen.package1_key_08_dev.hex().upper()}\n\n')
        manual_crypto.write(f'package1_mac_key_06 = ' + f'{tsec_keygen.package1_mac_key_06_dev.hex().upper()}\n')
        manual_crypto.write(f'package1_mac_key_07 = ' + f'{tsec_keygen.package1_mac_key_07_dev.hex().upper()}\n')
        manual_crypto.write(f'package1_mac_key_08 = ' + f'{tsec_keygen.package1_mac_key_08_dev.hex().upper()}\n')

        manual_crypto.write(f'\n')
        manual_crypto.write(f'package2_key_source = ' + f'{key_sources.package2_key_source.hex().upper()}\n\n')

        # generate package2_key_%% from all provided master_key_%% using package2_key_source
        package2_key = keygen.package2_key
        count = -0x1
        for i in package2_key:
            count = count + 0x1
            keys = f'package2_key_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
            manual_crypto.write(f'{keys}\n')

        manual_crypto.write(f'\n')
        manual_crypto.write(f'bis_kek_source = ' + f'{key_sources.bis_kek_source.hex().upper()}\n')

        # Write bis_key_source_%%
        count = -1
        for i in key_sources.bis_key_sources:
            count = count + 0x1
            keys = f'bis_key_source_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
            manual_crypto.write(f'{keys}\n')

        manual_crypto.write(f'\n')
        manual_crypto.write(f'per_console_key_source = ' + f'{key_sources.per_console_key_source.hex().upper()}\n')
        manual_crypto.write(f'retail_specific_aes_key_source = ' + f'{key_sources.retail_specific_aes_key_source.hex().upper()}\n')
        manual_crypto.write(f'aes_kek_generation_source = ' + f'{key_sources.aes_kek_generation_source.hex().upper()}\n')
        manual_crypto.write(f'aes_key_generation_source = ' + f'{key_sources.aes_key_generation_source.hex().upper()}\n')
        manual_crypto.write(f'titlekek_source = ' + f'{key_sources.titlekek_source.hex().upper()}\n\n')

        # generate title_kek_%% from all provided master_key_%% using titlekek_source
        titlekek = keygen.titlekek
        count = -0x1
        for i in titlekek:
            count = count + 0x1
            keys = f'titlekek_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
            manual_crypto.write(f'{keys}\n')

        manual_crypto.write(f'\n')

        manual_crypto.write(f'header_kek_source = ' + f'{key_sources.header_kek_source.hex().upper()}\n')
        manual_crypto.write(f'header_key_source = ' + f'{key_sources.header_key_source.hex().upper()}\n')
        manual_crypto.write(f'header_kek = ' + f'{keygen.header_kek.hex().upper()}\n')
        manual_crypto.write(f'header_key = ' + f'{keygen.header_key.hex().upper()}\n\n')

        manual_crypto.write(f'key_area_key_system_source = ' + f'{key_sources.key_area_key_system_source.hex().upper()}\n')
        manual_crypto.write(f'key_area_key_application_source = ' + f'{key_sources.key_area_key_application_source.hex().upper()}\n')
        manual_crypto.write(f'key_area_key_ocean_source = ' + f'{key_sources.key_area_key_ocean_source.hex().upper()}\n\n')

        manual_crypto.write(f'save_mac_kek_source = ' + f'{key_sources.save_mac_kek_source.hex().upper()}\n')
        manual_crypto.write(f'save_mac_key_source_00 = ' + f'{key_sources.save_mac_key_source_00.hex().upper()}\n')
        manual_crypto.write(f'save_mac_key_source_01 = ' + f'{key_sources.save_mac_key_source_01.hex().upper()}\n')
        manual_crypto.write(f'save_mac_sd_card_kek_source = ' + f'{key_sources.save_mac_sd_card_kek_source.hex().upper()}\n')
        manual_crypto.write(f'save_mac_sd_card_key_source = ' + f'{key_sources.save_mac_sd_card_key_source.hex().upper()}\n')
        manual_crypto.write(f'sd_card_kek_source = ' + f'{key_sources.sd_card_kek_source.hex().upper()}\n\n')

        manual_crypto.write(f'xci_header_key = ' + f'{key_sources.xci_header_key.hex().upper()}\n\n')

        # generate key_area_key_application_%% from all provided master_key_%% using key_area_key_application_source
        key_area_key_application = keygen.key_area_key_application
        count = -0x1
        for i in key_area_key_application:
            count = count +0x1
            keys = f'key_area_key_application_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
            manual_crypto.write(f'{keys}\n')

        manual_crypto.write(f'\n')

        # generate key_area_key_ocean_%% from all provided master_key_%% using key_area_key_ocean_source
        key_area_key_ocean = keygen.key_area_key_ocean
        count = -0x1
        for i in key_area_key_ocean:
            count = count +0x1
            keys = f'key_area_key_ocean_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
            manual_crypto.write(f'{keys}\n')

        manual_crypto.write(f'\n')

        # generate key_area_key_system_%% from all provided master_key_%% using key_area_key_system_source
        key_area_key_system = keygen.key_area_key_system
        count = -0x1
        for i in key_area_key_system:
            count = count +0x1
            keys = f'key_area_key_system_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
            manual_crypto.write(f'{keys}\n')
if __name__ == "__main__":
    do_keygen()
    do_dev_keygen()