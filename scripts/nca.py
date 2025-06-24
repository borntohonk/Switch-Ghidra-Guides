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

import os
import re
import aes_128

def decrypt_xts(input, key):
    crypto = aes_128.AESXTS(key)
    decrypted = crypto.decrypt(input)
    return decrypted

def decrypt_ctr(input, key, CTR):
    ctr = Counter.new(128, initial_value=int.from_bytes(CTR, byteorder='big'))
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    output = cipher.decrypt(input)
    return output

def decrypt_ecb(input, key):
    cipher = AES.new(key, AES.MODE_ECB)
    output = cipher.decrypt(input)
    return output

def decrypt_header(nca, key):
    with open(nca, 'rb') as f:
        data = f.read()
        f.seek(0)
        encrypted_header = f.read(0xC00)
        decrypted_header = decrypt_xts(encrypted_header, key)
        key_area_encryption_type = decrypted_header[0x207:0x208]
        if key_area_encryption_type == b'\x00':
            key_area_encryption_type = "Application"
        elif key_area_encryption_type == b'\x01':
            key_area_encryption_type = "Ocean"
        elif key_area_encryption_type == b'\x02':
            key_area_encryption_type = "System"
        program_id = decrypted_header[0x210:0x218][::-1].hex().upper()
        section_0_storage_type = decrypted_header[0x402:0x403]
        if section_0_storage_type == b'\x00':
            content_type = "ROMFS"
        elif section_0_storage_type == b'\x01':
            content_type = "PFS0"
        return decrypted_header, key_area_encryption_type, program_id, content_type

def decrypt_section_0(nca, key_area_key, decrypted_header, content_type):
    section_0 = decrypted_header[0x240:0x250]
    section_0_start = int.from_bytes(section_0[0x0:0x4], "little", signed=False) * 0x200
    section_0_end = int.from_bytes(section_0[0x4:0x8], "little", signed=False) * 0x200
    section_0_size = section_0_end - section_0_start
    encrypted_key_area = decrypted_header[0x300:0x340]
    decrypted_key_area = decrypt_ecb(encrypted_key_area, key_area_key)
    decrypted_key_area_key_2 = decrypted_key_area[0x20:0x30]
    if content_type == "ROMFS":
        ctr = bytes.fromhex("000000000000000000000000000000C0")
    elif content_type == "PFS0":
        ctr = bytes.fromhex("000000010000000000000000000000C0")
    with open(nca, 'rb') as f:
        data = f.read()
        f.seek(section_0_start)
        #fsHeader_0 = decrypted_header[0x400:0x600]
        #fsHeader_0_ctr = fsHeader_0[0x5A:0x62] # the c0 byte is found at 0x62
        encrypted_section_0 = f.read(section_0_size)
        decrypted_section_0 = decrypt_ctr(encrypted_section_0, decrypted_key_area_key_2, ctr)
        return decrypted_section_0

def extract_romfs(decrypted_header, decrypted_section_0):
    romfs_start = int.from_bytes(decrypted_header[0x490:0x493], "little", signed=False)
    romfs_size = int.from_bytes(decrypted_header[0x498:0x49B], "little", signed=False)
    romfs_end = romfs_start + romfs_size
    romfs = decrypted_section_0[romfs_start:romfs_end]
    return romfs