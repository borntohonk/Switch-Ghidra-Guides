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
import errno
from hashlib import sha256
import re
from keys import RootKeys
from key_sources import KeySources
import aes_128
import aes_sample

def mkdirp(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

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

def decrypt_header(header, key):
    decrypted_header = decrypt_xts(header, key)
    return decrypted_header

ROMFS_ENTRY_EMPTY = b'\xff\xff\xff\xff'

class SectionTableEntry:
    def __init__(self, d):
        self.mediaOffset = int.from_bytes(d[0x0:0x4], byteorder='little', signed=False)
        self.mediaEndOffset = int.from_bytes(d[0x4:0x8], byteorder='little', signed=False)

        self.offset = self.mediaOffset * 0x200
        self.endOffset = self.mediaEndOffset * 0x200

        self.unknown1 = int.from_bytes(d[0x8:0xc], byteorder='little', signed=False)
        self.unknown2 = int.from_bytes(d[0xc:0x10], byteorder='little', signed=False)
        self.sha1 = None

class FsHeader():
    def __init__(self, fsheader):
        self.fsheader = fsheader
        self.version =  int.from_bytes(self.fsheader[0x0:0x2], byteorder='little', signed=False)
        self.fsType = int.from_bytes(self.fsheader[0x2:0x3], byteorder='little', signed=False)
        self.hashType = int.from_bytes(self.fsheader[0x3:0x4], byteorder='little', signed=False)
        self.encryptionType = int.from_bytes(self.fsheader[0x4:0x5], byteorder='little', signed=False)
        self.padding = self.fsheader[0x5:0x8]
        self.hashOffset = 0x8
        self.hashInfo = self.fsheader[0x8:0x100]
        self.patchInfo = self.fsheader[0x100:0x140]
        self.generation = self.fsheader[0x140:0x144]
        self.secureValue = self.fsheader[0x144:0x148]
        self.sparseInfo = self.fsheader[0x148:0x1A0]
        self.reserved = self.fsheader[0x1A0:0x200]
        self.CryptoCounterCtr = bytearray((b"\x00"*8) + self.generation + self.secureValue)[::-1]
        fs_content_type = self.fsType
        if fs_content_type == 0:
            self.fsType = "ROMFS"
            self.romfs_start = int.from_bytes(self.fsheader[0x90:0x93], "little", signed=False)
            self.romfs_size = int.from_bytes(self.fsheader[0x98:0x9B], "little", signed=False)
            self.romfs_end = self.romfs_start + self.romfs_size
        elif fs_content_type == 1:
            self.fsType = "PFS0"
            self.pfs0_start = int.from_bytes(self.fsheader[0x40:0x44], "little", signed=False)
            self.pfs0_size = int.from_bytes(self.fsheader[0x48:0x4C], "little", signed=False)
            self.pfs0_end = self.pfs0_start + self.pfs0_size

class NsoHeader():
    def __init__(self, nsoheader):
        self.nsoheader = nsoheader
        self.magic = nsoheader[0x0:0x04]
        self.version = int.from_bytes(self.nsoheader[0x04:0x08], byteorder='little', signed=False)
        self.reserved_0x8 = self.nsoheader[0x04:0x08]
        self.flags = self.nsoheader[0x08:0x0C]
        self.TextFileOffset = int.from_bytes(self.nsoheader[0x10:0x14], byteorder='little', signed=False)
        self.TextMemoryOffset = int.from_bytes(self.nsoheader[0x14:0x18], byteorder='little', signed=False)
        self.TextSize = int.from_bytes(self.nsoheader[0x18:0x1C], byteorder='little', signed=False)
        self.ModuleNameOffset = int.from_bytes(self.nsoheader[0x1C:0x20], byteorder='little', signed=False)
        self.RoFileOffset = int.from_bytes(self.nsoheader[0x20:0x24], byteorder='little', signed=False)
        self.RoMemoryOffset = int.from_bytes(self.nsoheader[0x24:0x28], byteorder='little', signed=False)
        self.RoSize = int.from_bytes(self.nsoheader[0x28:0x2C], byteorder='little', signed=False)
        self.ModuleNameSize = int.from_bytes(self.nsoheader[0x2C:0x30], byteorder='little', signed=False)
        self.DataFileOffset = int.from_bytes(self.nsoheader[0x30:0x34], byteorder='little', signed=False)
        self.DataMemoryOffset = int.from_bytes(self.nsoheader[0x34:0x38], byteorder='little', signed=False)
        self.DataSize = int.from_bytes(self.nsoheader[0x38:0x1C], byteorder='little', signed=False)
        self.BssSize = int.from_bytes(self.nsoheader[0x38:0x3C], byteorder='little', signed=False)
        self.ModuleId = self.nsoheader[0x40:0x50].hex().upper()
        self.TextFileSize = int.from_bytes(self.nsoheader[0x60:0x64], byteorder='little', signed=False)
        self.RoFileSize = int.from_bytes(self.nsoheader[0x64:0x68], byteorder='little', signed=False)
        self.DataFileSize = int.from_bytes(self.nsoheader[0x68:0x6C], byteorder='little', signed=False)
        self.reserved_0x6C = self.nsoheader[0x6C:0x88]
        self.EmbeddedOffset = int.from_bytes(self.nsoheader[0x88:0x8C], byteorder='little', signed=False)
        self.EmbeddedSize = int.from_bytes(self.nsoheader[0x8C:0x90], byteorder='little', signed=False)
        self.DynStrOffset= int.from_bytes(self.nsoheader[0x90:0x94], byteorder='little', signed=False)
        self.DynStrSize = int.from_bytes(self.nsoheader[0x94:0x98], byteorder='little', signed=False)
        self.DynSymOffset = int.from_bytes(self.nsoheader[0x98:0x9C], byteorder='little', signed=False)
        self.DynSymSize = int.from_bytes(self.nsoheader[0x9C:0xA0], byteorder='little', signed=False)
        self.TextHash = self.nsoheader[0xA0:0xC0]
        self.RoHash = self.nsoheader[0xC0:0xE0]
        self.DatatHash = self.nsoheader[0xE0:0x100]

class NcaHeader():
    def __init__(self, ncaheader):
        self.ncaheader = ncaheader
        self.signature1 = self.ncaheader[0x0:0x100]
        self.signature2 = self.ncaheader[0x100:0x200]
        self.magic = self.ncaheader[0x200:0x204]
        self.isGameCard = int.from_bytes(self.ncaheader[0x204:0x205], byteorder='little', signed=False)
        self.contentType = int.from_bytes(self.ncaheader[0x205:0x206], byteorder='little', signed=False)
        self.cryptoType = int.from_bytes(self.ncaheader[0x205:0x206], byteorder='little', signed=False)
        self.keyIndex =int.from_bytes(self.ncaheader[0x207:0x208], byteorder='little', signed=False)
        self.size = int.from_bytes(self.ncaheader[0x208:0x210], byteorder='little', signed=False)
        self.titleId = self.ncaheader[0x210:0x218][::-1].hex().upper()
        self.contentIndex =int.from_bytes(self.ncaheader[0x218:0x21C], byteorder='little', signed=False)
        self.sdkVersion = int.from_bytes(self.ncaheader[0x220:0x221], byteorder='little', signed=False)
        self.cryptoType2 = int.from_bytes(self.ncaheader[0x220:0x221], byteorder='little', signed=False)
        self.rightsId = self.ncaheader[0x210:0x218].hex().upper()
        self.sectionTables = []
        self.sectionTables.append(SectionTableEntry(self.ncaheader[0x240:0x250]))
        self.sectionTables.append(SectionTableEntry(self.ncaheader[0x250:0x260]))
        self.sectionTables.append(SectionTableEntry(self.ncaheader[0x260:0x270]))
        self.sectionTables.append(SectionTableEntry(self.ncaheader[0x270:0x280]))
        self.EncryptedKeyArea = []
        self.EncryptedKeyArea.append(self.ncaheader[0x300:0x310])
        self.EncryptedKeyArea.append(self.ncaheader[0x310:0x320])
        self.EncryptedKeyArea.append(self.ncaheader[0x320:0x330])
        self.EncryptedKeyArea.append(self.ncaheader[0x330:0x340])
        nca_content_type = self.contentType
        if nca_content_type == 0:
            self.contentType = "Program"
        elif nca_content_type == 1:
            self.contentType = "Meta"
        elif nca_content_type == 2:
            self.contentType = "Control"
        elif nca_content_type == 3:
            self.contentType = "Manual"
        elif nca_content_type == 4:
            self.contentType = "Data"
        elif nca_content_type == 5:
            self.contentType = "PublicData"

class Nca():
    def __init__(self, nca, keyset_for_firmware):
        self.nca = nca
        self.master_kek, self.master_key, self.package2_key, self.titlekek, self.key_area_key_system, self.key_area_key_ocean, self.key_area_key_application = keyset_for_firmware
        self.sections = []
        with open(self.nca, 'rb') as f:
            nca_data = f.read()
            self.encrypted_header = nca_data[0x0:0xC00]
            self.root_keys = RootKeys()
            self.key_sources = KeySources()
            if sha256(self.root_keys.mariko_kek).hexdigest().upper() != "ACEA0798A729E8E0B3EF6D83CF7F345537E41ACCCCCAD8686D35E3F5454D5132":
                print("mariko_kek is incorrectly filled in, the key filled into keys.py is incorrect, terminating script.")
                f.close()
                sys.exit(1)
            else:
                self.header_key = aes_sample.Keygen(self.root_keys.mariko_kek).header_key
                self.decrypted_nca_header = decrypt_header(self.encrypted_header, self.header_key)
                self.header = NcaHeader(self.decrypted_nca_header)
                section_00 = nca_data[self.header.sectionTables[0].offset:self.header.sectionTables[0].endOffset]
                section_01 = nca_data[self.header.sectionTables[1].offset:self.header.sectionTables[1].endOffset]
                section_02 = nca_data[self.header.sectionTables[2].offset:self.header.sectionTables[2].endOffset]
                section_03 = nca_data[self.header.sectionTables[3].offset:self.header.sectionTables[3].endOffset]
                self.sections.append(section_00)
                self.sections.append(section_01)
                self.sections.append(section_02)
                self.sections.append(section_03)
                f.close()
        if self.header.keyIndex == 0:
            self.key_area_key = self.key_area_key_application
        elif self.header.keyIndex == 1:
            self.key_area_key = self.key_area_key_ocean
        elif self.header.keyIndex == 2:
            self.key_area_key = self.key_area_key_system
        self.titleId = self.header.titleId
        self.sectionFilesystems = []
        self.fsheader_00 = FsHeader(self.decrypted_nca_header[0x400:0x600])
        self.fsheader_01 = FsHeader(self.decrypted_nca_header[0x600:0x800])
        self.fsheader_02 = FsHeader(self.decrypted_nca_header[0x800:0xA00])
        self.fsheader_03 = FsHeader(self.decrypted_nca_header[0xA00:0xC00])
        self.sectionFilesystems.append(self.fsheader_00.fsType)
        self.sectionFilesystems.append(self.fsheader_01.fsType)
        self.sectionFilesystems.append(self.fsheader_02.fsType)
        self.sectionFilesystems.append(self.fsheader_03.fsType)
        self.CryptoCounterCtrs = []
        self.CryptoCounterCtrs.append(self.fsheader_00.CryptoCounterCtr)
        self.CryptoCounterCtrs.append(self.fsheader_01.CryptoCounterCtr)
        self.CryptoCounterCtrs.append(self.fsheader_02.CryptoCounterCtr)
        self.CryptoCounterCtrs.append(self.fsheader_03.CryptoCounterCtr)
        self.CryptoCounterOffsets = []
        self.CryptoCounterOffsets.append(self.header.sectionTables[0].offset)
        self.CryptoCounterOffsets.append(self.header.sectionTables[1].offset)
        self.CryptoCounterOffsets.append(self.header.sectionTables[2].offset)
        self.CryptoCounterOffsets.append(self.header.sectionTables[3].offset)
        self.DecryptedKeyArea = []
        self.DecryptedKeyArea.append(decrypt_ecb(self.header.EncryptedKeyArea[0], self.key_area_key))
        self.DecryptedKeyArea.append(decrypt_ecb(self.header.EncryptedKeyArea[1], self.key_area_key))
        self.DecryptedKeyArea.append(decrypt_ecb(self.header.EncryptedKeyArea[2], self.key_area_key))
        self.DecryptedKeyArea.append(decrypt_ecb(self.header.EncryptedKeyArea[3], self.key_area_key))
        self.DecryptedKeyAreaKey2 = self.DecryptedKeyArea[2]
        self.decrypted_sections = []
        self.decrypted_sections.append(decrypt_ctr(self.sections[0], self.DecryptedKeyAreaKey2, self.CryptoCounterCtrs[0], self.CryptoCounterOffsets[0]))
        self.decrypted_sections.append(decrypt_ctr(self.sections[1], self.DecryptedKeyAreaKey2, self.CryptoCounterCtrs[1], self.CryptoCounterOffsets[1]))
        self.decrypted_sections.append(decrypt_ctr(self.sections[2], self.DecryptedKeyAreaKey2, self.CryptoCounterCtrs[2], self.CryptoCounterOffsets[2]))
        self.decrypted_sections.append(decrypt_ctr(self.sections[3], self.DecryptedKeyAreaKey2, self.CryptoCounterCtrs[3], self.CryptoCounterOffsets[3]))

class Romfs():
    def __init__(self, romfs, romfs_path):
        self.romfs = romfs
        self.romfs_path = romfs_path
        self.romfs_header = RomfsHeader(romfs[0x0:0x50])
        self.data_offset = self.romfs_header.data_offset
        self.file_meta_table_size = self.romfs_header.file_meta_table_size
        self.dir_meta_table_size = self.romfs_header.dir_meta_table_size
        self.dir_entry_table = self.romfs[self.romfs_header.dir_meta_table_offset:self.romfs_header.dir_meta_table_length]
        self.file_entry_table = self.romfs[self.romfs_header.file_meta_table_offset:self.romfs_header.file_meta_table_length]
        self.root_dir_entry_offset_start = 0x0
        self.root_dir_entry = RomfsDirEntry(self.dir_entry_table[self.root_dir_entry_offset_start:self.romfs_header.dir_meta_table_size])
        self.root_file_entry_offset_start = 0x0
        self.root_file_entry = RomfsFileEntry(self.file_entry_table[self.root_file_entry_offset_start:self.romfs_header.file_meta_table_size])
        self.start_path = romfs_path
        self.process_romfs = self.romfs_visit_dir(self.dir_entry_table, self.file_entry_table, self.data_offset, self.romfs, self.root_dir_entry_offset_start, self.dir_meta_table_size, self.file_meta_table_size, self.start_path)

    def romfs_visit_file(self, file_entry_table, data_offset, romfs, file_offset_raw, file_meta_table_size, dir_path):
        self.file_entry_table = file_entry_table
        self.romfs = romfs
        self.data_offset = data_offset
        self.file_offset_raw = file_offset_raw
        self.file_meta_table_size = file_meta_table_size
        self.dir_path = dir_path
        while self.file_offset_raw != ROMFS_ENTRY_EMPTY:
            self.file_offset = int.from_bytes(self.file_offset_raw, byteorder='little', signed=False)
            self.file_offset_size = self.file_offset + self.file_meta_table_size
            self.file_entry = RomfsFileEntry(self.file_entry_table[self.file_offset:self.file_offset_size])
            self.current_path = self.dir_path
            if self.file_entry.file_name_size != 0:
                self.file_name = self.file_entry.file_name.decode("UTF-8")
                if self.file_name not in self.current_path:
                    str_path = ''.join(self.current_path)
                    self.current_path = str_path + self.file_name

            self.file_start = self.data_offset + self.file_entry.file_offset
            self.file_end = self.file_start + self.file_entry.file_size

            with open(self.current_path, 'wb') as file:
                file.write(self.romfs[self.file_start:self.file_end])
                file.close()

            self.file_offset = self.file_entry.file_sibling_offset
            self.file_offset_raw = self.file_entry.file_sibling_offset_raw

    def romfs_visit_dir(self, dir_entry_table, file_entry_table, data_offset, romfs, dir_offset, dir_meta_table_size, file_meta_table_size, parent_path):
        self.dir_entry_table = dir_entry_table
        self.file_entry_table = file_entry_table
        self.data_offset = data_offset
        self.romfs = romfs
        self.dir_offset = dir_offset
        self.dir_meta_table_size = dir_meta_table_size
        self.file_meta_table_size = file_meta_table_size
        self.parent_path = parent_path
        self.dir_offset_size = self.dir_offset + self.dir_meta_table_size
        self.dir_entry = RomfsDirEntry(self.dir_entry_table[self.dir_offset:self.dir_offset_size])

        self.current_path = self.parent_path
        if self.dir_entry.dir_name_size != 0:
            self.dir_name = self.dir_entry.dir_name.decode("UTF-8") + "/"
            str_path = ''.join(self.current_path)
            self.current_path = str_path + self.dir_name

        mkdirp(self.current_path)
        if self.dir_entry.dir_file_offset_raw != ROMFS_ENTRY_EMPTY:
            self.romfs_visit_file(self.file_entry_table, self.data_offset, self.romfs, self.dir_entry.dir_file_offset_raw, self.file_meta_table_size, self.current_path)

        if self.dir_entry.dir_child_offset_raw != ROMFS_ENTRY_EMPTY:
            self.romfs_visit_dir(self.dir_entry_table, self.file_entry_table, self.data_offset, self.romfs, self.dir_entry.dir_child_offset, self.dir_meta_table_size, self.file_meta_table_size, self.current_path)
        
        if self.dir_entry.dir_sibling_offset_raw != ROMFS_ENTRY_EMPTY:
            self.romfs_visit_dir(self.dir_entry_table, self.file_entry_table, self.data_offset, self.romfs, self.dir_entry.dir_sibling_offset, self.dir_meta_table_size, self.file_meta_table_size, self.parent_path)

class RomfsHeader():
    def __init__(self, romfs):
        self.romfs = romfs
        self.header_size = int.from_bytes(self.romfs[0x0:0x8], byteorder='little', signed=False)
        self.dir_hash_table_offset = int.from_bytes(self.romfs[0x8:0x10], byteorder='little', signed=False)
        self.dir_hash_table_size = int.from_bytes(self.romfs[0x10:0x18], byteorder='little', signed=False)
        self.dir_hash_table_length = self.dir_hash_table_offset + self.dir_hash_table_size
        self.dir_meta_table_offset = int.from_bytes(self.romfs[0x18:0x20], byteorder='little', signed=False)
        self.dir_meta_table_size = int.from_bytes(self.romfs[0x20:0x28], byteorder='little', signed=False)
        self.dir_meta_table_length = self.dir_meta_table_offset + self.dir_meta_table_size
        self.file_hash_table_offset = int.from_bytes(self.romfs[0x28:0x30], byteorder='little', signed=False)
        self.file_hash_table_size = int.from_bytes(self.romfs[0x30:0x38], byteorder='little', signed=False)
        self.file_hash_table_length = self.file_hash_table_offset + self.file_hash_table_size
        self.file_meta_table_offset = int.from_bytes(self.romfs[0x38:0x40], byteorder='little', signed=False)
        self.file_meta_table_size = int.from_bytes(self.romfs[0x40:0x48], byteorder='little', signed=False)
        self.file_meta_table_length = self.file_meta_table_offset + self.file_meta_table_size
        self.data_offset = int.from_bytes(self.romfs[0x48:0x50], byteorder='little', signed=False)

class RomfsDirEntry():
    def __init__(self, romfs_direntry):
        self.direntry = romfs_direntry
        self.dir_parent_offset_raw = self.direntry[0x0:0x4]
        self.dir_parent_offset = int.from_bytes(self.dir_parent_offset_raw, byteorder='little', signed=False)
        self.dir_sibling_offset_raw = self.direntry[0x4:0x8]
        self.dir_sibling_offset = int.from_bytes(self.dir_sibling_offset_raw, byteorder='little', signed=False)
        self.dir_child_offset_raw = self.direntry[0x8:0xC]
        self.dir_child_offset = int.from_bytes(self.dir_child_offset_raw, byteorder='little', signed=False)
        self.dir_file_offset_raw = self.direntry[0xC:0x10]
        self.dir_file_offset = int.from_bytes(self.dir_file_offset_raw, byteorder='little', signed=False)
        self.dir_hash = self.direntry[0x10:0x14:]
        self.dir_name_size_raw = self.direntry[0x14:0x18]
        self.dir_name_size = int.from_bytes(self.dir_name_size_raw, byteorder='little', signed=False)
        self.dir_name_length = 0x18 + self.dir_name_size
        self.dir_name = self.direntry[0x18:self.dir_name_length]

class RomfsFileEntry():
    def __init__(self, romfs_fileentry):
        self.fileentry = romfs_fileentry
        self.file_parent_offset_raw = self.fileentry[0x0:0x4]
        self.file_parent_offset = int.from_bytes(self.file_parent_offset_raw, byteorder='little', signed=False)
        self.file_sibling_offset_raw = self.fileentry[0x4:0x8]
        self.file_sibling_offset = int.from_bytes(self.file_sibling_offset_raw, byteorder='little', signed=False)
        self.file_offset_raw = self.fileentry[0x8:0x10]
        self.file_offset = int.from_bytes(self.file_offset_raw, byteorder='little', signed=False)
        self.file_size_raw = self.fileentry[0x10:0x18]
        self.file_size = int.from_bytes(self.file_size_raw, byteorder='little', signed=False)
        self.file_hash = self.fileentry[0x18:0x1C]
        self.file_name_size_raw = self.fileentry[0x1C:0x20]
        self.file_name_size = int.from_bytes(self.file_name_size_raw, byteorder='little', signed=False)
        self.file_name_length = 0x20 + self.file_name_size
        self.file_name = self.fileentry[0x20:self.file_name_length]


class Pfs0():
    def __init__(self, pfs0, pfs0_path):
        self.pfs0 = pfs0
        self.pfs0_path = pfs0_path
        self.magic = self.pfs0[0x0:0x4]
        self.EntryCount_raw = self.pfs0[0x4:0x8]
        self.EntryCount = int.from_bytes(self.EntryCount_raw, byteorder='little', signed=False)
        self.StringTableSize_raw = self.pfs0[0x8:0xC]
        self.StringTableSize = int.from_bytes(self.StringTableSize_raw, byteorder='little', signed=False)
        self.reserved_0xC = self.pfs0[0xC:0x10]
        self.PartitionEntryTable = self.pfs0[0x10:0x28]
        self.partition_entry = Pfs0FileEntry(self.PartitionEntryTable)
        self.number_of_files = self.EntryCount
        self.header_size = 0x10 + self.number_of_files * 0x18 + self.StringTableSize
        self.pfs0_header = pfs0[0x0:self.header_size]
        self.pfs0_data = pfs0[self.header_size:]
        mkdirp(self.pfs0_path)

        current_offset = 0x10
        for i in range(self.number_of_files):
            current_offset = current_offset
            current_offset_end = current_offset + 0x18
            pfs0_file_entry = Pfs0FileEntry(self.pfs0_header[current_offset:current_offset_end])
            current_file_offset = pfs0_file_entry.PartitionEntryOffset
            current_file_size = pfs0_file_entry.PartitionEntrySize
            if current_file_offset == 0:
                self.pfs0_main = self.pfs0_data[current_file_offset:current_file_size]
                main_path = pfs0_path + "main"
                with open(main_path, 'wb') as f:
                    f.write(self.pfs0_main)
                    f.close()
                self.buildid = self.pfs0_main[0x40:0x54].hex().upper()
            current_offset = current_offset + 0x18

class Pfs0FileEntry():
    def __init__(self, pfs0_partitionentry):
        self.partitonentry = pfs0_partitionentry
        self.PartitionEntryOffset_raw = self.partitonentry[0x0:0x8]
        self.PartitionEntryOffset = int.from_bytes(self.PartitionEntryOffset_raw, byteorder='little', signed=False)
        self.PartitionEntrySize_raw = self.partitonentry[0x8:0x10]
        self.PartitionEntrySize = int.from_bytes(self.PartitionEntrySize_raw, byteorder='little', signed=False)
        self.PartitionEntryStringOffset_raw = self.partitonentry[0x10:0x14]
        self.PartitionEntryStringOffset = int.from_bytes(self.PartitionEntryStringOffset_raw, byteorder='little', signed=False)
        self.PartitionEntryReserved_0x14 = self.partitonentry[0x14:0x18]