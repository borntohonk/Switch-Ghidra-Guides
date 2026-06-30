# Copyright (c) 2026 borntohonk
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
from struct import pack

from keys import RootKeys
import aes_128
from key_sources import KeySources

try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util import Counter
    from Cryptodome.Hash import CMAC
except ModuleNotFoundError:
    try:
        from Crypto.Cipher import AES
        from Crypto.Util import Counter
        from Crypto.Hash import CMAC
    except ModuleNotFoundError:
        print('Please install pycryptodome(ex) first!')
        sys.exit(1)

def decrypt_xts(input, key):
    """Decrypt using XTS mode (for headers)."""
    crypto = aes_128.AESXTS(key)
    return crypto.decrypt(input)

def encrypt_xts(input, key):
    """Encrypt using XTS mode."""
    crypto = aes_128.AESXTS(key)
    return crypto.encrypt(input)

def decrypt_ctr(input, key, CTR, ctr_offset=None):
    """Decrypt using CTR mode. Supports both standard and offset modes."""
    if ctr_offset is None:
        ctr = Counter.new(128, initial_value=int.from_bytes(CTR, byteorder='big'))
        crypto = AES.new(key, AES.MODE_CTR, counter=ctr)
    else:
        crypto = aes_128.AESCTR(key, CTR, offset=ctr_offset)
    return crypto.decrypt(input)

def encrypt_ctr(input, key, ctr, ctr_offset=None):
    """Encrypt using CTR mode. Supports both standard and offset modes."""
    if ctr_offset is None:
        ctr_obj = Counter.new(128, initial_value=int.from_bytes(ctr, byteorder='big'))
        crypto = AES.new(key, AES.MODE_CTR, counter=ctr_obj)
    else:
        crypto = aes_128.AESCTR(key, ctr, offset=ctr_offset)
    return crypto.encrypt(input)

def decrypt_ecb(input, key):
    """Decrypt using ECB mode."""
    crypto = aes_128.AESECB(key)
    return crypto.decrypt(input)

def encrypt_ecb(input, key):
    """Encrypt using ECB mode."""
    crypto = aes_128.AESECB(key)
    return crypto.encrypt(input)

def calculate_falcon_hs_auth_hash(raw_imem_page_bytes, imem_start_addr, tsec_secret_1):
    """Compute the TSEC Falcon HS auth hash that the cauth hardware verifies on NS→HS transition.

    The hardware checks: AES_ECB(c3, DM_MAC(page_bytes, imem_start_addr))
    where c3 = AES_ECB(tsec_secret_1, zeros) and DM_MAC is the Davies-Meyer MAC
    defined by the TSEC cauth security model.

    Parameters:
        raw_imem_page_bytes (bytes): raw IMEM bytes for the cauth-covered region,
            taken directly from the firmware image (may span both unencrypted and
            layer-1-encrypted content — the hardware hashes what is in IMEM, not
            what is in the decrypted view).
        imem_start_addr (int): IMEM byte address of the first covered page
            (= start_page field from cauth register × 0x100).
        tsec_secret_1 (bytes): 16-byte hardware signing key (csecret slot 0x01,
            KeySources.tsec_secret_01).

    Returns:
        bytes: 16-byte auth hash.

    Usage:
        key_sources = KeySources()
        fw = open('tsec_keygen.bin', 'rb').read()

        # cauth register at NS→HS transition: 0x01030044
        #   page_count   = 0x01  →  1 page (0x100 bytes)
        #   flags        = 0x03  →  bit17 set (encrypted), bit16 set
        #   start_page   = 0x44  →  IMEM byte address 0x4400
        #
        # tsec_keygen IMEM base = 0x4000, so file_offset = IMEM_addr − 0x4000:
        #   file[0x400:0x500]  →  IMEM[0x4400:0x4500]

        h = calculate_falcon_hs_auth_hash(
            fw[0x400:0x500],          # 1 raw page from firmware file
            0x4400,                   # IMEM start address from cauth
            key_sources.tsec_secret_01,
        )
        # h == b'\\x86:\\x8c\\x95...' == bytes.fromhex('863a8c95ad4df7f1180b51bf1003db14')
        # This matches the $c6 cadd-embedded value in the tsec_keygen NS code.
    """
    def _davies_meyer_mac(data, address):
        ciphertext = bytearray(16)
        for i in range(0, len(data), 0x100):
            blocks = data[i:i + 0x100] + pack("<IIII", address, 0, 0, 0)
            for k in range(0, len(blocks), 16):
                aes = AES.new(bytes(blocks[k:k+16]), AES.MODE_ECB)
                ciphertext = bytearray(bytes(x ^ y for x, y in zip(aes.encrypt(bytes(ciphertext)), bytes(ciphertext))))
            address += 0x100
        return bytes(ciphertext)

    c3 = encrypt_ecb(bytes(16), tsec_secret_1)
    mac = _davies_meyer_mac(raw_imem_page_bytes, imem_start_addr)
    return encrypt_ecb(mac, c3)

def compute_cmac(data, key):
    """Compute AES-128-CMAC tag over data."""
    c = CMAC.new(key, ciphermod=AES)
    c.update(data)
    return c.digest()

def decrypt_cbc(input, key, IV):
    """Decrypt using CBC mode."""
    crypto = aes_128.AESCBC(key, IV)
    return crypto.decrypt(input)

def encrypt_cbc(input, key, IV):
    """Encrypt using CBC mode."""
    crypto = aes_128.AESCBC(key, IV)
    return crypto.encrypt(input)

def generateKek(src, masterKey, kek_seed, key_seed):
    kek = []
    src_kek = []

    kek = decrypt_ecb(kek_seed ,masterKey)
    src_kek = decrypt_ecb(src ,kek)
    if key_seed is not None:
        return decrypt_ecb(key_seed ,src_kek)
    else:
        return src_kek

def single_keygen_master_kek(master_kek_source, tsec_root_revision=2):
    key_sources = KeySources()
    tsec_keys = TsecKeygen(key_sources.tsec_secret_26)
    if tsec_root_revision == 0:
        tsec_root_key = tsec_keys.tsec_root_key_00
    if tsec_root_revision == 1:
        tsec_root_key = tsec_keys.tsec_root_key_01
    if tsec_root_revision == 2:
        tsec_root_key = tsec_keys.tsec_root_key_02
    master_kek = decrypt_ecb(master_kek_source, tsec_root_key)
    master_key = decrypt_ecb(key_sources.master_key_source, master_kek)
    package2_key = decrypt_ecb(key_sources.package2_key_source, master_key)
    titlekek = decrypt_ecb(key_sources.titlekek_source, master_key)
    key_area_key_system = generateKek(key_sources.key_area_key_system_source, master_key , key_sources.aes_kek_generation_source, key_sources.aes_key_generation_source)
    key_area_key_ocean = generateKek(key_sources.key_area_key_ocean_source, master_key , key_sources.aes_kek_generation_source, key_sources.aes_key_generation_source)
    key_area_key_application = generateKek(key_sources.key_area_key_application_source, master_key , key_sources.aes_kek_generation_source, key_sources.aes_key_generation_source)
    return master_kek, master_key, package2_key, titlekek, key_area_key_system, key_area_key_ocean, key_area_key_application

def single_keygen_master_key(master_key):
    key_sources = KeySources()
    package2_key = decrypt_ecb(key_sources.package2_key_source, master_key)
    titlekek = decrypt_ecb(key_sources.titlekek_source, master_key)
    key_area_key_system = generateKek(key_sources.key_area_key_system_source, master_key , key_sources.aes_kek_generation_source, key_sources.aes_key_generation_source)
    key_area_key_ocean = generateKek(key_sources.key_area_key_ocean_source, master_key , key_sources.aes_kek_generation_source, key_sources.aes_key_generation_source)
    key_area_key_application = generateKek(key_sources.key_area_key_application_source, master_key , key_sources.aes_kek_generation_source, key_sources.aes_key_generation_source)
    return master_key, package2_key, titlekek, key_area_key_system, key_area_key_ocean, key_area_key_application

def single_keygen_dev(master_kek_source, tsec_root_revision=2):
    key_sources = KeySources()
    tsec_keys = TsecKeygen(key_sources.tsec_secret_26)
    if tsec_root_revision == 0:
        tsec_root_key = tsec_keys.tsec_root_key_00_dev
    if tsec_root_revision == 1:
        tsec_root_key = tsec_keys.tsec_root_key_01_Dev
    if tsec_root_revision == 2:
        tsec_root_key = tsec_keys.tsec_root_key_02_dev
    master_kek = decrypt_ecb(master_kek_source, tsec_root_key)
    master_key = decrypt_ecb(key_sources.master_key_source, master_kek)
    package2_key = decrypt_ecb(key_sources.package2_key_source, master_key)
    titlekek = decrypt_ecb(key_sources.titlekek_source, master_key)
    key_area_key_system = generateKek(key_sources.key_area_key_system_source, master_key , key_sources.aes_kek_generation_source, key_sources.aes_key_generation_source)
    key_area_key_ocean = generateKek(key_sources.key_area_key_ocean_source, master_key , key_sources.aes_kek_generation_source, key_sources.aes_key_generation_source)
    key_area_key_application = generateKek(key_sources.key_area_key_application_source, master_key , key_sources.aes_kek_generation_source, key_sources.aes_key_generation_source)
    return master_kek, master_key, package2_key, titlekek, key_area_key_system, key_area_key_ocean, key_area_key_application

def tsec_keygen():
    key_sources = KeySources()
    tsec_keys = TsecKeygen(key_sources.tsec_secret_26)
    return tsec_keys.tsec_root_key_02, tsec_keys.tsec_root_key_02_dev

def derive_keyblob_keys():
    key_sources = KeySources()
    tsec_keys = TsecKeygen(key_sources.tsec_secret_26)
    secure_boot_key = key_sources.secure_boot_key
    tsec_key = tsec_keys.tsec_key
    keyblob_key_sources = key_sources.keyblob_key_sources
    keyblob_mac_key_source = key_sources.keyblob_mac_key_source
    keyblob_keys = []
    keyblob_mac_keys = []
    for i in keyblob_key_sources:
        keyblob_kek = decrypt_ecb(i, tsec_key)
        keyblob_key = decrypt_ecb(keyblob_kek, secure_boot_key)
        keyblob_keys.append(keyblob_key)
        keyblob_mac_key = decrypt_ecb(keyblob_mac_key_source, keyblob_key)
        keyblob_mac_keys.append(keyblob_mac_key)
    return keyblob_keys, keyblob_mac_keys

def decrypt_keyblobs(encrypted_keyblobs, keyblob_keys, keyblob_mac_keys, warn=True):
    """Decrypt encrypted keyblobs.

    Each encrypted keyblob is 0xB0 bytes with layout:
        [0x00:0x10] CMAC tag
        [0x10:0x20] CTR counter
        [0x20:0xB0] AES-128-CTR encrypted payload (0x90 bytes)

    The CMAC covers bytes [0x10:0xB0] (counter + encrypted payload).

    Args:
        encrypted_keyblobs: list of 0xB0-byte blobs (one per slot up to USED_KEYBLOB_COUNT)
        keyblob_keys: list of 16-byte decryption keys
        keyblob_mac_keys: list of 16-byte CMAC keys
        warn: if True, print a warning when the CMAC does not match

    Returns:
        list of decrypted payloads (bytes, 0x90 bytes each), or None for skipped slots
    """
    USED_KEYBLOB_COUNT = 6
    keyblobs = []
    
    for i in range(USED_KEYBLOB_COUNT):
        enc_kb = encrypted_keyblobs[i]
        if isinstance(enc_kb, list):
            enc_kb = b''.join(enc_kb)
        key = keyblob_keys[i]
        mac_key = keyblob_mac_keys[i]

        if all(b == 0 for b in key) or all(b == 0 for b in mac_key) or all(b == 0 for b in enc_kb):
            keyblobs.append(None)
            continue

        cmac_stored = enc_kb[0x00:0x10]
        counter = enc_kb[0x10:0x20]
        encrypted_payload = enc_kb[0x20:]

        cmac_computed = compute_cmac(enc_kb[0x10:0x10 + 0xA0], mac_key)
        if cmac_computed != cmac_stored and warn:
            print(f"Warning: Keyblob MAC {i:02x} is invalid. Are SBK/TSEC key correct?")

        decrypted = decrypt_ctr(encrypted_payload, key, counter)
        keyblobs.append([decrypted[j:j+16] for j in range(0, len(decrypted), 16)])

    return keyblobs

def encrypt_keyblobs(keyblobs, keyblob_keys, keyblob_mac_keys, counters=None):
    """Encrypt plaintext keyblobs to produce encrypted keyblob structures.

    Inverse of decrypt_keyblobs. Each output is 0xB0 bytes:
        [0x00:0x10] CMAC over [0x10:0xB0]
        [0x10:0x20] CTR counter
        [0x20:0xB0] AES-128-CTR encrypted payload

    Args:
        keyblobs: list of 0x90-byte plaintext payloads, or None to skip a slot
        keyblob_keys: list of 16-byte encryption keys
        keyblob_mac_keys: list of 16-byte CMAC keys
        counters: optional list of 16-byte counters; defaults to all-zeros per slot

    Returns:
        list of encrypted keyblob bytes (0xB0 each), or None for skipped slots
    """
    encrypted_keyblobs = []
    for i in range(USED_KEYBLOB_COUNT):
        kb = keyblobs[i]
        key = keyblob_keys[i]
        mac_key = keyblob_mac_keys[i]

        if kb is None or all(b == 0 for b in key) or all(b == 0 for b in mac_key):
            encrypted_keyblobs.append(None)
            continue

        counter = (counters[i] if counters else None) or bytes(16)
        encrypted_payload = encrypt_ctr(kb, key, counter)
        cmac = compute_cmac(counter + encrypted_payload, mac_key)
        encrypted_keyblobs.append(cmac + counter + encrypted_payload)

    return encrypted_keyblobs

class BaseKeygen:
    """Base class for key generation with shared initialization logic."""
    
    def __init__(self, tsec_keys, isdev):
        self.key_sources = KeySources()
        self.tsec_keys = tsec_keys

        if isdev == True:
            self.tsec_root_key_00 = self.tsec_keys.tsec_root_key_00_dev
            self.tsec_root_key_01 = self.tsec_keys.tsec_root_key_01_dev
            self.tsec_root_key_02 = self.tsec_keys.tsec_root_key_02_dev
        elif isdev == False:
            self.tsec_root_key_00 = self.tsec_keys.tsec_root_key_00
            self.tsec_root_key_01 = self.tsec_keys.tsec_root_key_01
            self.tsec_root_key_02 = self.tsec_keys.tsec_root_key_02

        self.mariko_master_kek_sources = self.key_sources.mariko_master_kek_sources
        self.master_kek_sources = self.key_sources.master_kek_sources
        self.master_key_vectors = self.key_sources.master_key_vectors
        
        self.encrypted_keyblobs = self.key_sources.encrypted_keyblobs
        keyblob_keys, keyblob_mac_keys = derive_keyblob_keys()
        self.keyblobs = decrypt_keyblobs(self.encrypted_keyblobs, keyblob_keys, keyblob_mac_keys)

        master_keks_0_5 = []
        self.package1_keys = []
        for i in self.keyblobs:
            master_keks_0_5.append(i[0])
            self.package1_keys.append(i[8])

        # Decrypt master keys
        self.master_kek_source_06 = self.key_sources.master_kek_source_06
        self.master_kek_06 = decrypt_ecb(self.master_kek_source_06, self.tsec_root_key_00)
        self.master_kek_source_07 = self.key_sources.master_kek_source_07
        self.master_kek_07 = decrypt_ecb(self.master_kek_source_07, self.tsec_root_key_01)
        self.master_kek_root_key_02 = [decrypt_ecb(i, self.tsec_root_key_02) for i in self.master_kek_sources]
        self.master_kek = []
        for i in master_keks_0_5:
            self.master_kek.append(i)
        self.master_kek.append(self.master_kek_06)
        self.master_kek.append(self.master_kek_07)
        for i in self.master_kek_root_key_02:
            self.master_kek.append(i)
        self.master_key = self._derive_master_keys()
        self.current_master_key = self.master_key[-1]
        
        # Generate derived keys
        self._generate_derived_keys()
    
    def _derive_master_keys(self):
        """To be overridden by subclasses."""
        raise NotImplementedError
    
    def _generate_derived_keys(self):
        """Generate all derived keys from master keys."""
        self.header_kek = generateKek(
            self.key_sources.header_kek_source,
            self.master_key[0],
            self.key_sources.aes_kek_generation_source,
            self.key_sources.aes_key_generation_source
        )
        self.header_key = decrypt_ecb(self.key_sources.header_key_source, self.header_kek)
        self.package2_key = [decrypt_ecb(self.key_sources.package2_key_source, i) for i in self.master_key]
        self.titlekek = [decrypt_ecb(self.key_sources.titlekek_source, i) for i in self.master_key]
        
        # Generate key area keys
        self.key_area_key_application = [
            generateKek(self.key_sources.key_area_key_application_source, i,
                       self.key_sources.aes_kek_generation_source,
                       self.key_sources.aes_key_generation_source)
            for i in self.master_key
        ]
        self.key_area_key_ocean = [
            generateKek(self.key_sources.key_area_key_ocean_source, i,
                       self.key_sources.aes_kek_generation_source,
                       self.key_sources.aes_key_generation_source)
            for i in self.master_key
        ]
        self.key_area_key_system = [
            generateKek(self.key_sources.key_area_key_system_source, i,
                       self.key_sources.aes_kek_generation_source,
                       self.key_sources.aes_key_generation_source)
            for i in self.master_key
        ]

class Keygen(BaseKeygen):
    """Production keygen using production master keys."""
    
    def _derive_master_keys(self):
        """Derive production master keys."""
        old_master_keys_prod = master_keys_prod()
        new_master_keys_prod = ([decrypt_ecb(self.key_sources.master_key_source, i) for i in self.master_kek_root_key_02])[1:]
        combined_master_keys_prod = old_master_keys_prod + new_master_keys_prod
        return combined_master_keys_prod

class KeygenDev(BaseKeygen):
    """Development keygen using development master keys."""
    
    def _derive_master_keys(self):
        """Derive development master keys."""
        old_master_keys_dev = master_keys_dev()
        new_master_keys_dev = ([decrypt_ecb(self.key_sources.master_key_source, i) for i in self.master_kek_root_key_02])[1:]
        combined_master_keys_dev = old_master_keys_dev + new_master_keys_dev
        return combined_master_keys_dev

class TsecKeygen():
    def __init__(self, hovi_kek):
        if sha256(hovi_kek).hexdigest().upper() == "CEFE01C9E3EEEF1A73B8C10D742AE386279B7DFF30A2FBC0AABD058C1F135833":
            self.hovi_kek = hovi_kek
            self.tsec_secret_26 = self.hovi_kek

            # This is atmosphere's tsec_keygen.bin (T210 Erista, file size 0x1F00):
            #
            # Encryption layers:
            #   file[0x000:0x410]  - unencrypted NS Falcon code (IMEM base 0x4000)
            #   file[0x410:0x1A00] - layer-1: AES-128-ECB with tsec_secret_06
            #   file[0x1A00:0x1F00]- layer-2: AES-128-CBC with atmosphere_key_output_c2 (IV = zeros)
            #
            # Layer-2 key derivation (performed by the second HS block at IMEM[0x4519]):
            #   1. auth_hash = calculate_falcon_hs_auth_hash(fw[0x400:0x500], imem_addr=0x4400, tsec_secret_01)
            #                = 863A8C95AD4DF7F1180B51BF1003DB14
            #      (Davies-Meyer MAC of the cauth-covered HS page, wrapped by AES(tsec_secret_01, zeros);
            #       embedded as cadd nibbles in NS code IMEM[0x4065:0x4165])
            #   2. csigenc   = AES_ECB(KEY=hovi_kek, PT=auth_hash) = 41FCD9969516BEF3D52043BFCD87F429
            #      (Falcon csigenc semantics: KEY is the register ($c2=hovi_kek), PT is the live auth sig)
            #   3. For each cN: output_key = AES_ECB(KEY=csigenc, PT=cN_nibbles_combined)
            #      (Falcon cenc with ckeyreg=csigenc; each cN_nibbles_combined is the 32-nibble cadd
            #       sequence from the second HS block reconstructed as a 16-byte value)
            self.atmosphere_tsec_keygen_auth_signature = b'\x86\x3a\x8c\x95\xad\x4d\xf7\xf1\x18\x0b\x51\xbf\x10\x03\xdb\x14'
            # csigenc = AES_ECB(KEY=hovi_kek, PT=auth_hash) = 41FCD9969516BEF3D52043BFCD87F429
            self.atmosphere_tsec_keygen_key = encrypt_ecb(self.atmosphere_tsec_keygen_auth_signature, self.hovi_kek)


            self.C2_NIBBLES_COMBINED = b'\xBC\xBF\xC1\x0B\x81\xD2\x47\x66\x97\x93\x98\x25\x6D\x83\x23\xE4'
            self.C3_NIBBLES_COMBINED = b'\x42\x84\xFD\x6D\x6D\x2F\xFC\xB7\x8D\x87\x46\x14\x71\x88\x53\x9C'
            self.C4_NIBBLES_COMBINED = b'\xF5\xD8\x6D\x71\x01\x36\x56\x66\xCD\x83\x95\x2E\x76\x9E\x95\x81'
            self.C5_NIBBLES_COMBINED = b'\x4F\x3C\x17\x84\x8A\xA5\xCD\xBE\xB0\x9C\x55\x1F\x75\x16\x98\xCA'
            self.C6_NIBBLES_COMBINED = b'\x69\x1D\xB4\xB8\x9F\x19\xF4\xF8\xF4\x7B\xAB\xB4\xA0\xB5\x98\x66'

            # $c2 → 1DBC7263E0274F22E737A5988EA4EE90
            # AES-128-CBC key for layer-2 (file[0x1A00:0x1F00], IV = zeros).
            # Used by the second HS block to decrypt the inner Falcon stage before lcall 0x900.
            self.atmosphere_key_output_c2 = encrypt_ecb(self.C2_NIBBLES_COMBINED, self.atmosphere_tsec_keygen_key)

            # $c3 → 4B4F00000000000000000000000048EC  (= tsec_root_key_02)
            # TsecRoot (production): written to SE keyslot 13 (AesKeySlot_TsecRoot).
            # fusee derives MasterKek on production hardware:
            #   SetEncryptedAesKey128(MasterKek, TsecRoot, EristaMasterKekSource)  [fusee_key_derivation.cpp:288]
            self.atmosphere_key_output_c3 = encrypt_ecb(self.C3_NIBBLES_COMBINED, self.atmosphere_tsec_keygen_key)

            # $c4 → CA990000000000000000000000001DF2  (= tsec_root_key_02_dev)
            # TsecRootDev (development): written to SE keyslot 11 (AesKeySlot_TsecRootDev).
            # fusee uses this instead of TsecRoot when HardwareState != Production:
            #   SetEncryptedAesKey128(MasterKek, TsecRootDev, EristaMasterKekSource)  [fusee_key_derivation.cpp:288]
            self.atmosphere_key_output_c4 = encrypt_ecb(self.C4_NIBBLES_COMBINED, self.atmosphere_tsec_keygen_key)

            # $c5 → 484F56495F454B535F30310000000000  ("HOVI_EKS_01\x00\x00\x00\x00\x00")
            # Input seed passed to the inner Falcon stage at IMEM[0x900] for hovi_EKS key derivation.
            # Zeroed by the inner code after use — not written to a keyslot.
            self.atmosphere_key_output_c5 = encrypt_ecb(self.C5_NIBBLES_COMBINED, self.atmosphere_tsec_keygen_key)

            # $c6 → 892A36228D49E0484D480CB0ACDA0234  (= keygen_auth_signature)
            # Auth signature produced by the inner Falcon stage's own cauth verification.
            # Passed into the inner code's csigenc chain to derive the console-unique tsec_key
            # (HOVI_EKS_01 path) and hovi_common_key. Not written to a keyslot directly.
            self.atmosphere_key_output_c6 = encrypt_ecb(self.C6_NIBBLES_COMBINED, self.atmosphere_tsec_keygen_key)

            # This is "gen_usr_key", of keygen_ldr:

            # buffer = address to stored seed combination CODE + _SIG/_ENC + zero padding
            # store buffer in register $c0
            # csecret $c1, 0x26 (loads csecret 0x26 into $c1)
            # ckeyreg $c1 (uses $c1 as key for encryption/decryption)
            # cenc $c0, buffer (result is code_sig_kek // code_enc_kek)
            # csigenc $c0, $c0 (resulting key is code_sig_key  // code_enc_key )
            # the following logic is for the keygenldr to decrypt the encrypted keygen binary, using code_enc_key in cbc mode with IV as zeroes

            # The following sources are made out of seed parts of the hex representations of the words:
            # [0]"CODE, [1]"_SIG"/"_ENC", [2] "ZERO PADDING TO 0x10 size"
            self.code_sig_source = b'\x43\x4F\x44\x45\x5F\x53\x49\x47\x5F\x30\x31\x00\x00\x00\x00\x00' # CODE_SIG_01
            self.code_enc_source = b'\x43\x4F\x44\x45\x5F\x45\x4E\x43\x5F\x30\x31\x00\x00\x00\x00\x00' # CODE_ENC_01

            #self.boot_auth_signature = b'\x6E\xB7\x59\x84\x2B\xAB\x4B\x9B\x13\x26\x07\x7D\xB2\x7B\xC3\x6E' # boot ( this auth signature doesn't matter as much )
            self.keygen_ldr_auth_signature = b'\x9C\x8B\x75\xD3\xDF\x0B\xF0\x6C\x95\xFC\x91\xC0\x76\x1E\xF0\x62' # keygen_ldr auth signature

            self.code_sig_kek = encrypt_ecb(self.code_sig_source, self.hovi_kek)
            self.code_enc_kek = encrypt_ecb(self.code_enc_source, self.hovi_kek)

            self.code_sig_key = encrypt_ecb(self.keygen_ldr_auth_signature, self.code_sig_kek) # csigenc
            self.code_enc_key = encrypt_ecb(self.keygen_ldr_auth_signature, self.code_enc_kek) # csigenc


            # This is "gen_tsec_key", of "keygen":
            
            # This is HOVI_EKS_01:
            # buffer = address to stored seed combination HOVI + _EKS_01/_COMMON_01 + zero padding
            # store buffer in register $c0
            # csecret $c1, 0x3F (loads csecret 0x3F into $c1 - console unique)
            # csigenc $c1, $c1 (overwrites register $c1 with csigenc output of tsec_secret_0x3F & keygen_auth_signature)
            # csecret $c2, 0x00 (load csecret 0x00 into $c2)
            # ckeyreg $c2 (use csecret 0x00 as key)
            # cenc $c2, $c0 (encrypt the buffer with csecret 0x00 and then overwrite register $c2 with cenc outut of tsec_secret_00 & buffer)
            # ckeyreg $c2 ( use the new key as key)
            # csigenc $c2, $c2 (overwrites register $c2 with csigenc output of the key generated above & keygen_auth_signature)
            # ckeyreg $c2 (use the csigenc key above as key)
            # cenc $c2 $c1 (encrypt the csigenc + 0x3F key into $c2, using the key above.)

            # This is "HOVI_COMMON_01:"
            # csecret $c2, 0x00 (loads csecret 0x00 into $c2)
            # cenc $c2, $c0 (encrypt the buffer with csecret 0x00 and then overwrite register $c2 with cenc outut of tsec_secret_00 & buffer)
            # ckeyreg $c2 (use $c2 as key)
            # csigenc $c2, $c2 (overwrites register $c2 with csigenc output of the key generated above & keygen_auth_signature)

            # The following sources are made out of seed parts of the hex representations of the words:
            # [0]"HOVI, [1]"_EKS_01"/"_COMMON_01", [2] "ZERO PADDING TO 0x10 size"
            self.hovi_eks_source = b'\x48\x4F\x56\x49\x5F\x45\x4B\x53\x5F\x30\x31\x00\x00\x00\x00\x00' # HOVI_EKS_01
            self.hovi_common_source = b'\x48\x4F\x56\x49\x5F\x43\x4F\x4D\x4D\x4F\x4E\x5F\x30\x31\x00\x00' # HOVI_COMMON_01

            # the following is the output of the encrypted keygen stage.
            self.keygen_auth_signature = b'\x89\x2A\x36\x22\x8D\x49\xE0\x48\x4D\x48\x0C\xB0\xAC\xDA\x02\x34' # keygen auth signature
            self.key_sources = KeySources()
            self.unknown_tsec_secret_3F = self.key_sources.zeroes
            self.tsec_secret_00 = self.key_sources.tsec_secret_00

            # HOVI_EKS_01 ( output is the normal tsec_key - console unique)
            self.csigenc_3F = encrypt_ecb(self.keygen_auth_signature, self.unknown_tsec_secret_3F) # console unique key, replaced with zeroes purpose of demonstration
            self.hovi_eks_kek_source = encrypt_ecb(self.hovi_eks_source, self.tsec_secret_00)
            self.hovi_eks_kek = encrypt_ecb(self.keygen_auth_signature, self.hovi_eks_kek_source) # csigenc
            self.hovi_eks_key = encrypt_ecb(self.csigenc_3F, self.hovi_eks_kek)
            self.tsec_key = self.hovi_eks_key # console unique, using an all zero substitute for tsec_secret_0x3F key, this should yield "D7BE6D23D43BF185476290B792C7AE39" - a fake tsec_key

            # HOVI_COMMON_01 ( unused key? no proof of it being used anywhere )
            self.hovi_common_kek = encrypt_ecb(self.hovi_common_source, self.tsec_secret_00)
            self.hovi_common_key = encrypt_ecb(self.keygen_auth_signature, self.hovi_common_kek) # csigenc

            # this is "SecureBoot":

            # (encrypted if _00 and _01 / decrypted if _02 by tsec_secret_26, then the result is then used as key to encrypt tsec_auth_signatures_%%, essentially this falcon instruction chain:)
            # buffer = address to stored seed combination hovi + _sig/_kek/_enc + _key + _prd/_dev/_iv1
            # the buffer is stored in $c2
            # csecret $c3, 0x26 (loads csecret 0x26 into $c3)
            # ckeyreg $c3 (uses $c3 as key for encryption/decryption)
            # cenc/cdec $c4, $c2 (encrypt/decrypt buffer into $c4 using hovi_kek/tsec_secret_26 as key ( encrypt if _00 & _01, decrypt if _02 ) 
            # result is tsec_root_kek_%% // package1_kek_%% // package1_mac_kek_%%)
            # ckeyreg $c4 (use the output as key)
            # csigenc $c4, $c4 (resulting key is Package1_Key_06/_07/_08 // Package1_Mac_Key_06/_07/_08 // Tsec_Root_Key_00/_01/_02 // hovi_iv_00/_01/_02)

            # this is an extra step for only 1 of the 3 keys - package1_mac (_SIG)
            # ckeyreg $c4 (use $c4 as key)
            # cxor $c2 $c2 (clears $c2 ?)
            # cenc $c3 $c2 (encrypts now empty $c2 into $c3 using the above key)

            # The following sources are made out of seed parts of the hex representations of the words:
            # [0]"HOVI", [1]"_SIG"/"_ENC"/"_KEK", [2]"_KEY", [3]"_IV1"/"_PRD"/"_DEV"
            self.package1_mac_kek_source                = bytes([0x48, 0x4F, 0x56, 0x49, 0x5F, 0x53, 0x49, 0x47, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x50, 0x52, 0x44]) # HOVI_SIG_KEY_PRD
            self.package1_kek_source                    = bytes([0x48, 0x4F, 0x56, 0x49, 0x5F, 0x45, 0x4E, 0x43, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x50, 0x52, 0x44]) # HOVI_ENC_KEY_PRD 
            self.tsec_root_kek_source                   = bytes([0x48, 0x4F, 0x56, 0x49, 0x5F, 0x4B, 0x45, 0x4B, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x50, 0x52, 0x44]) # HOVI_KEK_KEY_PRD
            self.tsec_hovi_iv_key                       = bytes([0x48, 0x4F, 0x56, 0x49, 0x5F, 0x45, 0x4E, 0x43, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x49, 0x56, 0x31]) # HOVI_ENC_KEY_IV1
            self.package1_mac_kek_source_dev            = bytes([0x48, 0x4F, 0x56, 0x49, 0x5F, 0x53, 0x49, 0x47, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x44, 0x45, 0x56]) # HOVI_SIG_KEY_DEV
            self.package1_kek_source_dev                = bytes([0x48, 0x4F, 0x56, 0x49, 0x5F, 0x45, 0x4E, 0x43, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x44, 0x45, 0x56]) # HOVI_ENC_KEY_DEV
            self.tsec_root_kek_source_dev               = bytes([0x48, 0x4F, 0x56, 0x49, 0x5F, 0x4B, 0x45, 0x4B, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x44, 0x45, 0x56]) # HOVI_KEK_KEY_DEV

            # tsec auth hash/signature can be found by searching for "1D E3 64 58 FA 9E C2 98 D5 B4 57 74 B5 82 E7 11" in the encrypted package1 erista binary,
            # selecting the last result +0x1, or +0x30 from start of result found (zeroes encrypted by tsec_secret_06)
            self.tsec_auth_signature_00                 = bytes([0xA7, 0x7B, 0x86, 0x58, 0x6A, 0xE1, 0xB0, 0x3D, 0x4F, 0xFB, 0xA3, 0xAD, 0xA8, 0xF8, 0xDE, 0x32]) # source 0x3300 encrypted package1 6.2.0
            self.tsec_auth_signature_01                 = bytes([0xA3, 0xFF, 0xB0, 0xF6, 0xBC, 0x49, 0xA0, 0x6D, 0xF2, 0xFC, 0x79, 0x16, 0x97, 0xD8, 0x1D, 0x32]) # source 0x3B00 encrypted package1 7.0.0
            self.tsec_auth_signature_02                 = bytes([0x0B, 0x55, 0xCC, 0x08, 0x20, 0xE6, 0x30, 0x7F, 0xD0, 0x87, 0x47, 0x9E, 0xAA, 0x2E, 0x7F, 0x98]) # source 0x3D00 encrypted package1 8.1.0+

            # Encrypt/decrypt keys for production (rev 0/1/2)
            self.tsec_root_kek_00 = encrypt_ecb(self.tsec_root_kek_source, self.hovi_kek)
            self.tsec_root_kek_01 = self.tsec_root_kek_00 
            self.tsec_root_kek_02 = decrypt_ecb(self.tsec_root_kek_source, self.hovi_kek)

            self.package1_kek_00 = encrypt_ecb(self.package1_kek_source, self.hovi_kek)
            self.package1_kek_01 = self.package1_kek_00
            self.package1_kek_02 = decrypt_ecb(self.package1_kek_source, self.hovi_kek)

            self.package1_mac_kek_00 = encrypt_ecb(self.package1_mac_kek_source, self.hovi_kek)
            self.package1_mac_kek_01 = self.package1_mac_kek_00
            self.package1_mac_kek_02 = decrypt_ecb(self.package1_mac_kek_source, self.hovi_kek)

            # Generate root, package1, and mac keys from signatures
            self._derive_keys_from_signatures(
                [self.tsec_root_kek_00, self.tsec_root_kek_01, self.tsec_root_kek_02],
                [self.package1_kek_00, self.package1_kek_01, self.package1_kek_02],
                [self.package1_mac_kek_00, self.package1_mac_kek_01, self.package1_mac_kek_02],
                is_dev=False
            )

            # Encrypt/decrypt keys for development (rev 0/1/2)
            self.tsec_root_kek_00_dev = encrypt_ecb(self.tsec_root_kek_source_dev, self.hovi_kek)
            self.tsec_root_kek_01_dev = self.tsec_root_kek_00_dev 
            self.tsec_root_kek_02_dev = decrypt_ecb(self.tsec_root_kek_source_dev, self.hovi_kek)

            self.package1_kek_00_dev = encrypt_ecb(self.package1_kek_source_dev, self.hovi_kek)
            self.package1_kek_01_dev = self.package1_kek_00_dev
            self.package1_kek_02_dev = decrypt_ecb(self.package1_kek_source_dev, self.hovi_kek)

            self.package1_mac_kek_00_dev = encrypt_ecb(self.package1_mac_kek_source_dev, self.hovi_kek)
            self.package1_mac_kek_01_dev = self.package1_mac_kek_00_dev
            self.package1_mac_kek_02_dev = decrypt_ecb(self.package1_mac_kek_source_dev, self.hovi_kek)

            # Generate dev keys from signatures ( csigenc )
            self._derive_keys_from_signatures(
                [self.tsec_root_kek_00_dev, self.tsec_root_kek_01_dev, self.tsec_root_kek_02_dev],
                [self.package1_kek_00_dev, self.package1_kek_01_dev, self.package1_kek_02_dev],
                [self.package1_mac_kek_00_dev, self.package1_mac_kek_01_dev, self.package1_mac_kek_02_dev],
                is_dev=True
            )      

    def _derive_keys_from_signatures(self, tsec_keklist, pk1_keklist, pk1_mac_keklist, is_dev=False):
        """Derive all keys from auth signatures for the given keklist."""
        suffix = "_dev" if is_dev else ""
        sigs = [self.tsec_auth_signature_00, self.tsec_auth_signature_01, self.tsec_auth_signature_02]
        
        for i, (tsec_kek, pk1_kek, mac_kek, sig) in enumerate(
            zip(tsec_keklist, pk1_keklist, pk1_mac_keklist, sigs)
        ):
            rev = f"0{i}"
            pk1_rev = f"0{6+i}"
            
            # Derive TSEC root keys
            setattr(self, f'tsec_root_key_{rev}{suffix}', encrypt_ecb(sig, tsec_kek))
            
            # Derive Package1 keys
            setattr(self, f'package1_key_{pk1_rev}{suffix}', encrypt_ecb(sig, pk1_kek))
            
            # Derive Package1 MAC keys
            mac_key = encrypt_ecb(sig, mac_kek)
            setattr(self, f'package1_mac_key_{pk1_rev}{suffix}', mac_key)

            # cenc(zeros, package1_mac_key) — L from the CMAC subkey derivation in secure_boot (NIST SP 800-38B)
            setattr(self, f'package1_mac_cmac_key_{pk1_rev}{suffix}', encrypt_ecb(self.key_sources.zeroes, mac_key))

def master_key_0a():
    key_sources = KeySources()
    hovi_kek = key_sources.tsec_secret_26
    tsec_keygen = TsecKeygen(hovi_kek)
    tsec_root_key_02 = tsec_keygen.tsec_root_key_02
    tsec_root_key_02_dev = tsec_keygen.tsec_root_key_02_dev
    master_kek_0a_source = key_sources.master_kek_sources[0]
    master_kek = decrypt_ecb(master_kek_0a_source, tsec_root_key_02)
    master_kek_dev = decrypt_ecb(master_kek_0a_source, tsec_root_key_02_dev)
    master_key = decrypt_ecb(key_sources.master_key_source, master_kek)
    master_key_dev = decrypt_ecb(key_sources.master_key_source, master_kek_dev)
    return master_key, master_key_dev

def master_keys_prod():
    master_key_0a_prod, master_key_0a_dev = master_key_0a()
    key_sources = KeySources()
    master_key_vectors = key_sources.master_key_vectors[0:8]
    current_master_key = master_key_0a_prod
    master_key = []
    first = True
    for i in reversed(master_key_vectors):
        if first:
            first = False
            previous_key = i
            next_master_key = decrypt_ecb(previous_key, current_master_key)
            master_key.append(current_master_key)
            master_key.append(next_master_key)
        else:
            key = previous_key
            previous_key = i
            next_master_key = decrypt_ecb(previous_key, next_master_key)
            master_key.append(next_master_key)
    master_key.reverse()
    return master_key

def master_keys_dev():
    master_key_0a_prod, master_key_0a_dev = master_key_0a()
    key_sources = KeySources()
    master_key_vectors = key_sources.master_key_vectors_dev[0:8]
    current_master_key = master_key_0a_dev
    master_key = []
    first = True
    for i in reversed(master_key_vectors):
        if first:
            first = False
            previous_key = i
            next_master_key = decrypt_ecb(previous_key, current_master_key)
            master_key.append(current_master_key)
            master_key.append(next_master_key)
        else:
            key = previous_key
            previous_key = i
            next_master_key = decrypt_ecb(previous_key, next_master_key)
            master_key.append(next_master_key)
    master_key.reverse()
    return master_key

def do_keygen(keys = "prod.keys"):
    #keys = "prod.keys"
    root_keys = RootKeys()
    key_sources = KeySources()
    hovi_kek = key_sources.tsec_secret_26
    tsec_keygen = TsecKeygen(hovi_kek)
    keygen = Keygen(tsec_keygen, isdev=False)

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
        count = 0x7
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
        # generate master_kek_%% from all provided master_kek_sources and keyblobs
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
        manual_crypto.write(f'\n')
        package1_keys = keygen.package1_keys
        count = -0x1
        for i in package1_keys:
            count = count + 0x1
            keys = f'package1_key_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
            manual_crypto.write(f'{keys}\n')

        manual_crypto.write(f'package1_key_06 = ' + f'{tsec_keygen.package1_key_06.hex().upper()}\n')
        manual_crypto.write(f'package1_key_07 = ' + f'{tsec_keygen.package1_key_07.hex().upper()}\n')
        manual_crypto.write(f'package1_key_08 = ' + f'{tsec_keygen.package1_key_08.hex().upper()}\n\n')
        manual_crypto.write(f'package1_mac_key_06 = ' + f'{tsec_keygen.package1_mac_key_06.hex().upper()}\n')
        manual_crypto.write(f'package1_mac_key_07 = ' + f'{tsec_keygen.package1_mac_key_07.hex().upper()}\n')
        manual_crypto.write(f'package1_mac_key_08 = ' + f'{tsec_keygen.package1_mac_key_08.hex().upper()}\n')
        manual_crypto.write(f'\npackage1_mac_cmac_key_06 = ' + f'{tsec_keygen.package1_mac_cmac_key_06.hex().upper()}\n')
        manual_crypto.write(f'package1_mac_cmac_key_07 = ' + f'{tsec_keygen.package1_mac_cmac_key_07.hex().upper()}\n')
        manual_crypto.write(f'package1_mac_cmac_key_08 = ' + f'{tsec_keygen.package1_mac_cmac_key_08.hex().upper()}\n')

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


def do_dev_keygen(keys = "dev.keys"):
    #keys = "dev.keys"
    key_sources = KeySources()
    hovi_kek = key_sources.tsec_secret_26
    tsec_keygen = TsecKeygen(hovi_kek)
    keygen = KeygenDev(tsec_keygen, isdev=True)

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
        count = 0x7
        for i in key_sources.master_kek_sources:
            count = count + 0x1
            keys = f'master_kek_source_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
            manual_crypto.write(f'{keys}\n')

        manual_crypto.write(f'\n')
        # generate master_kek_%% from all provided mariko_master_kek_sources
        master_keks = keygen.master_kek_root_key_02
        count = 0x7
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

        manual_crypto.write(f'\npackage1_key_06 = ' + f'{tsec_keygen.package1_key_06_dev.hex().upper()}\n')
        manual_crypto.write(f'package1_key_07 = ' + f'{tsec_keygen.package1_key_07_dev.hex().upper()}\n')
        manual_crypto.write(f'package1_key_08 = ' + f'{tsec_keygen.package1_key_08_dev.hex().upper()}\n\n')
        manual_crypto.write(f'package1_mac_key_06 = ' + f'{tsec_keygen.package1_mac_key_06_dev.hex().upper()}\n')
        manual_crypto.write(f'package1_mac_key_07 = ' + f'{tsec_keygen.package1_mac_key_07_dev.hex().upper()}\n')
        manual_crypto.write(f'package1_mac_key_08 = ' + f'{tsec_keygen.package1_mac_key_08_dev.hex().upper()}\n')
        manual_crypto.write(f'\npackage1_mac_cmac_key_06 = ' + f'{tsec_keygen.package1_mac_cmac_key_06_dev.hex().upper()}\n')
        manual_crypto.write(f'package1_mac_cmac_key_07 = ' + f'{tsec_keygen.package1_mac_cmac_key_07_dev.hex().upper()}\n')
        manual_crypto.write(f'package1_mac_cmac_key_08 = ' + f'{tsec_keygen.package1_mac_cmac_key_08_dev.hex().upper()}\n')

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

def get_package2_keys():
    """Get all production package2 keys.
    
    Returns:
        list: List of 21 package2_key values (bytes) for revisions 0x00-0x14
    """
    key_sources = KeySources()
    tsec_keys = TsecKeygen(key_sources.tsec_secret_26)
    keygen = Keygen(tsec_keys, isdev=False)
    return keygen.package2_key


def get_package2_keys_dev():
    """Get all development package2 keys.
    
    Returns:
        list: List of 21 package2_key values (bytes) for revisions 0x00-0x14
    """
    key_sources = KeySources()
    tsec_keys = TsecKeygen(key_sources.tsec_secret_26)
    keygen = KeygenDev(tsec_keys, isdev=True)
    return keygen.package2_key


if __name__ == "__main__":
    do_keygen()
    do_dev_keygen()