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

def decrypt_ctr(input, key, ctr, ctr_offset):
    crypto = aes_128.AESCTR(key, ctr, offset=ctr_offset)
    decrypted = crypto.decrypt(input)
    return decrypted

def decrypt_ecb(input, key):
    crypto = aes_128.AESECB(key)
    decrypted = crypto.decrypt(input)
    return decrypted

def decrypt_header(nca, key):
    with open(nca, 'rb') as f:
        data = f.read()
        f.seek(0)
        encrypted_header = f.read(0xC00)
        decrypted_header = decrypt_xts(encrypted_header, key)
        return decrypted_header

def get_program_id(decrypted_header):
    program_id = decrypted_header[0x210:0x218][::-1].hex().upper()
    return program_id

def get_section_amount(decrypted_header):
    fs_section_00_first_byte = decrypted_header[0x400:0x401]
    fs_section_01_first_byte = decrypted_header[0x600:0x601]
    fs_section_02_first_byte = decrypted_header[0x800:0x801]
    fs_section_03_first_byte = decrypted_header[0xA00:0xA01]
    num_sections = 0
    if fs_section_00_first_byte != b'\x00':
        num_sections = num_sections + 1
    if fs_section_01_first_byte != b'\x00':
        num_sections = num_sections + 1
    if fs_section_02_first_byte != b'\x00':
        num_sections = num_sections + 1
    if fs_section_03_first_byte != b'\x00':
        num_sections = num_sections + 1
    return num_sections

def get_nca_types(decrypted_header):
    nca_content_type = decrypted_header[0x205:0x206]
    if nca_content_type == b'\x00':
        content_type = "Program"
    elif nca_content_type == b'\x01':
        content_type = "Meta"
    elif nca_content_type == b'\x02':
        content_type = "Control"
    elif nca_content_type == b'\x03':
        content_type = "Manual"
    elif nca_content_type == b'\x04':
        content_type = "Data"
    elif nca_content_type == b'\x05':
        content_type = "PublicData"
    return content_type

def get_fs_section_content_types(decrypted_header):
    section_00_storage_type = decrypted_header[0x402:0x403]
    section_01_storage_type = decrypted_header[0x602:0x603]
    section_02_storage_type = decrypted_header[0x802:0x803]
    section_03_storage_type = decrypted_header[0xA02:0xA03]
    if section_00_storage_type == b'\x00':
        fs_section_00_content_type = "ROMFS"
    elif section_00_storage_type == b'\x01':
        fs_section_00_content_type = "PFS0"
    if section_01_storage_type == b'\x00':
        fs_section_01_content_type = "ROMFS"
    elif section_01_storage_type == b'\x01':
        fs_section_01_content_type = "PFS0"
    if section_02_storage_type == b'\x00':
        fs_section_02_content_type = "ROMFS"
    elif section_02_storage_type == b'\x01':
        fs_section_02_content_type = "PFS0"
    if section_03_storage_type == b'\x00':
        fs_section_03_content_type = "ROMFS"
    elif section_03_storage_type == b'\x01':
        fs_section_03_content_type = "PFS0"
    return fs_section_00_content_type, fs_section_01_content_type, fs_section_02_content_type, fs_section_03_content_type

def get_section_offsets(decrypted_header):
    section_00_offset_start = int.from_bytes(decrypted_header[0x240:0x244], "little", signed=False) * 0x200
    section_01_offset_start = int.from_bytes(decrypted_header[0x250:0x254], "little", signed=False) * 0x200
    section_02_offset_start = int.from_bytes(decrypted_header[0x260:0x264], "little", signed=False) * 0x200
    section_03_offset_start = int.from_bytes(decrypted_header[0x270:0x274], "little", signed=False) * 0x200
    section_00_offset_end = int.from_bytes(decrypted_header[0x244:0x248], "little", signed=False) * 0x200
    section_01_offset_end = int.from_bytes(decrypted_header[0x254:0x258], "little", signed=False) * 0x200
    section_02_offset_end = int.from_bytes(decrypted_header[0x264:0x268], "little", signed=False) * 0x200
    section_03_offset_end = int.from_bytes(decrypted_header[0x274:0x278], "little", signed=False) * 0x200
    return section_00_offset_start, section_01_offset_start, section_02_offset_start, section_03_offset_start, section_00_offset_end, section_01_offset_end, section_02_offset_end, section_03_offset_end

def get_crypto_counters(decrypted_header):
    fs_section_00_crypto_counter = bytearray((b"\x00"*8) + decrypted_header[0x540:0x548])[::-1]
    fs_section_01_crypto_counter = bytearray((b"\x00"*8) + decrypted_header[0x740:0x748])[::-1]
    fs_section_02_crypto_counter = bytearray((b"\x00"*8) + decrypted_header[0x940:0x948])[::-1]
    fs_section_03_crypto_counter = bytearray((b"\x00"*8) + decrypted_header[0xB40:0xB48])[::-1]
    return fs_section_00_crypto_counter, fs_section_01_crypto_counter, fs_section_02_crypto_counter, fs_section_03_crypto_counter   

def decrypt_sections(nca, decrypted_header, key_area_key):
    program_id = get_program_id(decrypted_header)
    section_amount = get_section_amount(decrypted_header)
    crypto_counter_00, crypto_counter_01, crypto_counter_02, crypto_counter_03 = get_crypto_counters(decrypted_header)
    section_00_offset_start, section_01_offset_start, section_02_offset_start, section_03_offset_start, section_00_offset_end, section_01_offset_end, section_02_offset_end, section_03_offset_end = get_section_offsets(decrypted_header)
    section_00_content_type, section_01_content_type, section_02_content_type, section_03_content_type = get_fs_section_content_types(decrypted_header)
    section_00_size = section_00_offset_end - section_00_offset_start
    section_01_size = section_01_offset_end - section_01_offset_start
    section_02_size = section_02_offset_end - section_02_offset_start
    section_03_size = section_03_offset_end - section_03_offset_start
    encrypted_key_area = decrypted_header[0x300:0x340]
    decrypted_key_area = decrypt_ecb(encrypted_key_area, key_area_key)
    decrypted_key_area_key_2 = decrypted_key_area[0x20:0x30]
    with open(nca, 'rb') as f:
        data = f.read()
        if section_amount <= 4:
            f.seek(section_03_offset_start)
            encrypted_section_03 = f.read(section_03_size)
            decrypted_section_03 = decrypt_ctr(encrypted_section_03, decrypted_key_area_key_2, crypto_counter_03, section_03_offset_start)
        if section_amount <= 3:
            f.seek(section_02_offset_start)
            encrypted_section_02 = f.read(section_02_size)
            decrypted_section_02 = decrypt_ctr(encrypted_section_02, decrypted_key_area_key_2, crypto_counter_02, section_02_offset_start)
        if section_amount <= 2:
            f.seek(section_01_offset_start)
            encrypted_section_01 = f.read(section_01_size)
            decrypted_section_01 = decrypt_ctr(encrypted_section_01, decrypted_key_area_key_2, crypto_counter_01, section_01_offset_start)
        if section_amount <= 1:
            f.seek(section_00_offset_start)
            encrypted_section_00 = f.read(section_00_size)
            decrypted_section_00 = decrypt_ctr(encrypted_section_00, decrypted_key_area_key_2, crypto_counter_00, section_00_offset_start)
    return decrypted_section_00, decrypted_section_01, decrypted_section_02, decrypted_section_03

def extract_romfs(decrypted_header, decrypted_section_00):
    romfs_start = int.from_bytes(decrypted_header[0x490:0x493], "little", signed=False)
    romfs_size = int.from_bytes(decrypted_header[0x498:0x49B], "little", signed=False)
    romfs_end = romfs_start + romfs_size
    romfs = decrypted_section_00[romfs_start:romfs_end]
    return romfs

def extract_pfs0(decrypted_header, decrypted_section_00):
    pfs0_start = int.from_bytes(decrypted_header[0x440:0x444], "little", signed=False)
    pfs0_size = int.from_bytes(decrypted_header[0x448:0x44C], "little", signed=False)
    pfs0_end = pfs0_start + pfs0_size
    pfs0 = decrypted_section_00[pfs0_start:pfs0_end]
    return pfs0