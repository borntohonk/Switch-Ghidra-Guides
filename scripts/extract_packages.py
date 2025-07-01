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

import re
from nca import Nca, SectionExtractor, NcaInfo
import os
import struct
from pathlib import Path
from hashlib import sha256
import romfs

from keys import RootKeys
from key_sources import KeySources
import util
import crypto
import nxo64


# ============================================================================
# Package1 (PK11) - Bootloader Processing
# ============================================================================

class Package1Context:
    """Package1 (PK11) processing context (mirrors hactools pk11_ctx_t)."""
    def __init__(self, data):
        self.data = data
        self.is_decrypted = False
        self.key_revision = 0


def decrypt_erista_package1(encrypted_package1):
    """Decrypt Package1 (PK11) bootloader.
    
    Package1 contains the first bootloader stage and is encrypted with
    a fixed key. This extracts and decrypts it.
    """
    key_sources = KeySources()
    tsec_keys = crypto.TsecKeygen(key_sources.tsec_secret_26)
    
    # Parse Package1 header
    header = encrypted_package1[0x0:0x190]
    bl_size = int.from_bytes(encrypted_package1[0x154:0x158], 'little')
    
    if bl_size > 0:
        aes_iv = encrypted_package1[0x170:0x180]
        encrypted_data = encrypted_package1[0x180:0x180 + bl_size]
        decrypted_data = crypto.decrypt_cbc(encrypted_data, tsec_keys.package1_key_08, aes_iv)
        package1_dec = header + decrypted_data[0x10:]
        return package1_dec
    
    return encrypted_package1

def decrypt_mariko_package1(encrypted_package1):
    """Decrypt Package1 (PK11) bootloader.
    
    Package1 contains the first bootloader stage and is encrypted with
    a fixed key. This extracts and decrypts it.
    """
    root_keys = RootKeys()
    
    # Parse Package1 header
    header = encrypted_package1[0x0:0x190]
    bl_size = int.from_bytes(encrypted_package1[0x154:0x158], 'little')
    
    if bl_size > 0:
        aes_iv = encrypted_package1[0x170:0x180]
        encrypted_data = encrypted_package1[0x180:0x180 + bl_size]
        decrypted_data = crypto.decrypt_cbc(encrypted_package1, root_keys.mariko_bek, aes_iv)
        package1_dec = header + decrypted_data[0x10:]
        return package1_dec
    
    return encrypted_package1

def try_decrypt_package2(package2_data):    
    package2_keys = crypto.get_package2_keys()
    for package2_key in package2_keys:
        ctr = package2_data[0x100:0x110]
        header_encrypted = package2_data[0x100:0x200]
        header_decrypted = crypto.decrypt_ctr(header_encrypted, package2_key, ctr)

        magic = header_decrypted[0x50:0x54]
        if magic == b'PK21':

            return package2_key
    
    raise ValueError("No valid key found")


def erista_extract_key_sources_from_package1(decrypted_package1):
    """Extract master_kek_source from decrypted Package1.
    
    The master_kek_source is embedded in Package1 and used to derive
    all other master keys.
    """
    # Search for OYASUMI magic which precedes key sources
    result_oyasumi = re.search(bytes([0x4F, 0x59, 0x41, 0x53, 0x55, 0x4D, 0x49]), decrypted_package1)
    # this is in "Secure Monitor"
    if not result_oyasumi:
        raise ValueError("Failed to find key source magic in Package1 - for oyasumi string")

    result_package2 = re.search(bytes([0x70, 0x61, 0x63, 0x6B, 0x61, 0x67, 0x65, 0x32]), decrypted_package1)
    # this is in "Secure Monitor - every version has every other device master key source source directly above the last one in 0x10 sizes, 21.0.0 = 0x120 size keyblock, 20.0.0 0x110 size keyblock, and so on"
    if not result_package2:
        raise ValueError("Failed to find key source magic in Package1 - for package2 string")
    
    # master_kek_source is at a fixed offset after the magic
    master_kek_source_start = result_oyasumi.end() + 0x42
    master_kek_source_end = master_kek_source_start + 0x10
    master_kek_source = decrypted_package1[master_kek_source_start:master_kek_source_end]

    device_master_key_source_source_start = result_package2.start() - 0x14
    device_master_key_source_source_end = device_master_key_source_source_start + 0x10
    device_master_key_source_source = decrypted_package1[device_master_key_source_source_start:device_master_key_source_source_end]

    return master_kek_source, device_master_key_source_source

def mariko_extract_key_sources_from_package1(decrypted_package1):
    """Extract master_kek_source from decrypted Package1.
    
    The master_kek_source is embedded in Package1 and used to derive
    all other master keys.
    """
    # Search for OYASUMI magic which precedes key sources
    result = re.search(bytes([0x4F, 0x59, 0x41, 0x53, 0x55, 0x4D, 0x49]), decrypted_package1)
    if not result:
        raise ValueError("Failed to find key source magic in Package1")
    
    # master_kek_source is at a fixed offset after the magic
    mariko_master_kek_source_dev_start = result.start() + 0x29
    mariko_master_kek_source_dev_end = mariko_master_kek_source_dev_start + 0x10
    mariko_master_kek_source_dev = decrypted_package1[mariko_master_kek_source_dev_start:mariko_master_kek_source_dev_end]
    mariko_master_kek_source_start = mariko_master_kek_source_dev_start + 0x10
    mariko_master_kek_source_end = mariko_master_kek_source_dev_end + 0x10   
    mariko_master_kek_source = decrypted_package1[mariko_master_kek_source_start:mariko_master_kek_source_end]
    
    return mariko_master_kek_source, mariko_master_kek_source_dev


# ============================================================================
# Package2 (PK21) - Kernel Processing
# ============================================================================

class Package2Context:
    """Package2 (PK21) processing context (mirrors hactools pk21_ctx_t)."""
    def __init__(self, data):
        self.data = data
        self.is_decrypted = False
        self.key_revision = 0
        self.header = None
        self.kernel_bin = None
        self.ini1_bin = None


def parse_package2_header(package2_data):
    """Parse Package2 header."""
    header = {}
    header['magic'] = package2_data[0x100:0x104]
    header['section_sizes'] = [
        int.from_bytes(package2_data[0x140:0x144], 'little'),
        int.from_bytes(package2_data[0x144:0x148], 'little'),
        int.from_bytes(package2_data[0x148:0x14C], 'little'),
    ]
    return header


def decrypt_and_extract_package2(package2_data, package2_key):
    ctx = Package2Context(package2_data)
    
    header_enc = package2_data[0x100:0x200]
    ctr_header = package2_data[0x100:0x110]          # initial CTR for header only
    
    # Decrypt header using header CTR
    header_dec = crypto.decrypt_ctr(header_enc, package2_key, ctr_header)
    
    magic = header_dec[0x50:0x54]
    if magic != b'PK21':
        ctx.is_decrypted = False
        return ctx
    
    ctx.is_decrypted = True
    bootloader_version = '0x' + header_dec[0x5d:0x5e].hex().upper()

    ctx.data = package2_data[0:0x100] + header_dec   # for now; body added later
    
    # Parse sizes (little-endian) from decrypted header
    section_sizes = [
        int.from_bytes(header_dec[0x60:0x64], 'little'),
        int.from_bytes(header_dec[0x64:0x68], 'little'),
        int.from_bytes(header_dec[0x68:0x6c], 'little'),
        int.from_bytes(header_dec[0x6c:0x70], 'little'),  # usually 0
    ]
    ctx.header = {'section_sizes': section_sizes[:3]}   # keep your original 3 for compatibility
    
    #print(f"Section sizes from header: {[hex(s) for s in section_sizes]}")
    
    # Extract per-section CTRs from decrypted header
    section_ctrs = [
        header_dec[0x10:0x20],   # sec 0
        header_dec[0x20:0x30],   # sec 1
        header_dec[0x30:0x40],   # sec 2
        header_dec[0x40:0x50],   # sec 3
    ]
    
    # Decrypt sections sequentially from 0x200
    body_offset = 0x200
    decrypted_body = bytearray()
    
    for i, size in enumerate(section_sizes):
        if size == 0:
            continue
        sec_data_enc = package2_data[body_offset : body_offset + size]
        sec_ctr = section_ctrs[i]
        sec_dec = crypto.decrypt_ctr(sec_data_enc, package2_key, sec_ctr)
        decrypted_body += sec_dec
        body_offset += size
    
    ctx.data += decrypted_body   # or keep separate if preferred
    
    # Now extract kernel (sec 0) and ini1 (sec 1 or embedded)
    offset = 0x200   # but since we decrypted sequentially, use cumulative
    ctx.kernel_bin = decrypted_body[0 : section_sizes[0]]   # first section
    
    if section_sizes[1] > 0:
        ini1_start = section_sizes[0]
        ctx.ini1_bin = decrypted_body[ini1_start : ini1_start + section_sizes[1]]
        print(f"INI1 from section 1, size: 0x{section_sizes[1]:x}")
    else:
        # 8.0.0+ → search kernel
        #print("Searching for INI1 embedded in kernel...")
        ctx.ini1_bin = extract_ini1_from_kernel(ctx.kernel_bin)
    
    return ctx, bootloader_version

def extract_ini1_from_kernel(kernel_data):
    """Extract INI1 from kernel section.
    
    In firmware 8.0.0 and later, INI1 is embedded within the kernel
    section. This function locates and extracts it.
    """
    # Search for INI1 magic
    ini1_pos = kernel_data.find(b'INI1')
    if ini1_pos < 0:
        return None
    
    # Read INI1 header to get size
    # INI1 header: magic (4 bytes), size (4 bytes), num_processes (4 bytes), reserved (4 bytes)
    if ini1_pos + 8 > len(kernel_data):
        return None
    
    ini1_size = int.from_bytes(kernel_data[ini1_pos + 4:ini1_pos + 8], 'little')
    if ini1_pos + ini1_size > len(kernel_data):
        return None
    
    return kernel_data[ini1_pos:ini1_pos + ini1_size]

def extract_kips_from_ini1_as_objects(ini1_data, exfat_or_fat32):
    if len(ini1_data) < 0x10 or ini1_data[:4] != b'INI1':
        print("Invalid INI1 data (wrong magic or too small)")
        return

    num_kips = struct.unpack_from('<I', ini1_data, 8)[0]
    #print(f"Extracting {num_kips} raw KIPs from INI1 (size 0x{len(ini1_data):x})")

    pos = 0x10  # Start after INI1 header

    kip_hashes = []
    kip_objects = []

    for idx in range(num_kips):
        if pos + 0x100 > len(ini1_data):
            print(f"Truncated before KIP {idx} header at 0x{pos:x}")
            break

        header = ini1_data[pos : pos + 0x100]

        if header[:4] != b'KIP1':
            print(f"KIP {idx} invalid magic at 0x{pos:x}")
            break

        # hactool layout: section_headers[3] at 0x20, each 16 bytes, compressed_size at +0x08
        text_comp   = struct.unpack_from('<I', header, 0x28)[0]  # 0x20 + 0x08
        ro_comp     = struct.unpack_from('<I', header, 0x38)[0]  # 0x20 + 0x10 + 0x08
        data_comp   = struct.unpack_from('<I', header, 0x48)[0]  # 0x20 + 0x20 + 0x08

        kip_size = 0x100 + text_comp + ro_comp + data_comp

        remaining = len(ini1_data) - pos
        if kip_size > remaining or kip_size < 0x200:
            print(f"KIP {idx} invalid size 0x{kip_size:x} (remaining 0x{remaining:x})")
            print(f"  Sizes: text_comp=0x{text_comp:x} (bytes: {header[0x28:0x2c].hex()}), "
                  f"ro_comp=0x{ro_comp:x} (bytes: {header[0x38:0x3c].hex()}), "
                  f"data_comp=0x{data_comp:x} (bytes: {header[0x48:0x4c].hex()})")
            break

        kip_raw = ini1_data[pos : pos + kip_size]

        # Name from 0x04 (12 bytes, null-terminated in hactool)
        name_bytes = header[0x04:0x10]  # 12 bytes for name
        name_end = name_bytes.find(b'\0')
        name = name_bytes[:name_end].decode('ascii', errors='ignore').strip() if name_end != -1 else f"kip{idx}"
        if not name:
            name = f"kip{idx}"

        kip_hash = sha256(kip_raw).hexdigest().upper()
        kip_hashes.append(kip_hash)
        if name == "FS":
            if exfat_or_fat32 != None:
                name = exfat_or_fat32 + "_" + name
        
        decompressed_kip = util.decompress_kip_object(kip_raw)
        kip_objects.append((name, decompressed_kip))

        #print(f"Saved KIP {idx}: {name}.kip1 (raw size 0x{kip_size:x}) "
        #      f"[text:0x{text_comp:x}, ro:0x{ro_comp:x}, data:0x{data_comp:x}]")

        pos += kip_size
    return kip_hashes, kip_objects


# ============================================================================
# Filesystem Package Processing
# ============================================================================


def process_filesystem_package_object(package2_object, exfat_or_fat32=None):
    # Bruteforce try Package2 keys until success
    package2_key = try_decrypt_package2(package2_object) 
    
    # Decrypt Package2
    package2_ctx, bootloader_version = decrypt_and_extract_package2(package2_object, package2_key)
    
    # Extract filesystem KIPs from INI1
    if package2_ctx.ini1_bin:
        kip_hashes, kip_objects = extract_kips_from_ini1_as_objects(package2_ctx.ini1_bin, exfat_or_fat32)
        return kip_hashes, bootloader_version, kip_objects

# ============================================================================
# High-level Workflows
# ============================================================================

def erista_process_package_object_with_key_derivation(package1):
    decrypted_package1 = decrypt_erista_package1(package1)
    package1_version = decrypted_package1[0x10:0x18].decode('utf-8')
    master_kek_source, device_master_key_source_source = erista_extract_key_sources_from_package1(decrypted_package1)
    
    return master_kek_source, device_master_key_source_source, package1_version

def mariko_process_package_object_with_key_derivation(package1):
    decrypted_package1 = decrypt_mariko_package1(package1)
    mariko_master_kek_source, mariko_master_kek_source_dev = mariko_extract_key_sources_from_package1(decrypted_package1)

    return mariko_master_kek_source, mariko_master_kek_source_dev

if __name__ == "__main__":
    pass