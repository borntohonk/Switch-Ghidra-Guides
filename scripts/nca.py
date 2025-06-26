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
import key_sources as key_sources
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

def decrypt_header(header, key):
    decrypted_header = decrypt_xts(header, key)
    return decrypted_header

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
        elif fs_content_type == 1:
            self.fsType = "PFS0"

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
    def __init__(self, nca, key_area_key):
        self.nca = nca
        self.key_area_key = key_area_key
        self.sections = []
        with open(self.nca, 'rb') as f:
            nca_data = f.read()
            self.encrypted_header = nca_data[0x0:0xC00]
            self.decrypted_nca_header = decrypt_header(self.encrypted_header, key_sources.header_key)
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

def extract_romfs(decrypted_nca_header, decrypted_section_00):
    romfs_start = int.from_bytes(decrypted_nca_header[0x490:0x493], "little", signed=False)
    romfs_size = int.from_bytes(decrypted_nca_header[0x498:0x49B], "little", signed=False)
    romfs_end = romfs_start + romfs_size
    romfs = decrypted_section_00[romfs_start:romfs_end]
    return romfs

def extract_pfs0(decrypted_nca_header, decrypted_section_00):
    pfs0_start = int.from_bytes(decrypted_nca_header[0x440:0x444], "little", signed=False)
    pfs0_size = int.from_bytes(decrypted_nca_header[0x448:0x44C], "little", signed=False)
    pfs0_end = pfs0_start + pfs0_size
    pfs0 = decrypted_section_00[pfs0_start:pfs0_end]
    return pfs0