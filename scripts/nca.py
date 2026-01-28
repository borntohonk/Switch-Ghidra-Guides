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
import re
from pathlib import Path
from keys import RootKeys
from key_sources import KeySources
import romfs
import ivfc
import pfs0
import npdm
import util
import crypto

# ============================================================================
# Constants
# ============================================================================

# NCA structure offsets and sizes
NCA_HEADER_SIZE = 0xC00
NCA_SIGNATURE1_OFFSET = 0x0
NCA_SIGNATURE1_SIZE = 0x100
NCA_SIGNATURE2_OFFSET = 0x100
NCA_SIGNATURE2_SIZE = 0x100
NCA_MAGIC_OFFSET = 0x200
NCA_MAGIC_SIZE = 4
NCA_DISTRIBUTION_OFFSET = 0x204
NCA_CONTENT_TYPE_OFFSET = 0x205
NCA_CRYPTO_TYPE_OFFSET = 0x206
NCA_KEY_INDEX_OFFSET = 0x207
NCA_SIZE_OFFSET = 0x208
NCA_SIZE_SIZE = 8
NCA_TITLE_ID_OFFSET = 0x210
NCA_TITLE_ID_SIZE = 8
NCA_CONTENT_INDEX_OFFSET = 0x218
NCA_SDK_VERSION_OFFSET = 0x21C
NCA_SDK_VERSION_SIZE = 4
NCA_KEY_GENERATION_OFFSET = 0x220
NCA_CRYPTO_TYPE2_OFFSET = 0x221
NCA_RIGHTS_ID_OFFSET = 0x230
NCA_RIGHTS_ID_SIZE = 16
NCA_SECTION_TABLE_OFFSET = 0x240
NCA_SECTION_ENTRY_SIZE = 0x10
NCA_ENCRYPTED_KEY_AREA_OFFSET = 0x300
NCA_KEY_AREA_KEY_SIZE = 0x10

# FsHeader offsets
FS_HEADER_VERSION_OFFSET = 0x0
FS_HEADER_FS_TYPE_OFFSET = 0x2
FS_HEADER_HASH_TYPE_OFFSET = 0x3
FS_HEADER_ENCRYPTION_TYPE_OFFSET = 0x4
FS_HEADER_PADDING_OFFSET = 0x5
FS_HEADER_HASH_INFO_OFFSET = 0x8
FS_HEADER_PATCH_INFO_OFFSET = 0x100
FS_HEADER_GENERATION_OFFSET = 0x140
FS_HEADER_SECURE_VALUE_OFFSET = 0x144
FS_HEADER_SPARSE_INFO_OFFSET = 0x148
FS_HEADER_RESERVED_OFFSET = 0x1A0
FS_HEADER_SIZE = 0x200

# SectionTableEntry offsets
SECTION_TABLE_MEDIA_OFFSET = 0x0
SECTION_TABLE_MEDIA_END_OFFSET = 0x4
MEDIA_BLOCK_SIZE = 0x200

# Content type mappings
CONTENT_TYPES = ["Program", "Meta", "Control", "Manual", "Data", "PublicData"]
KEY_AREA_KEY_TYPES = ["Application", "Ocean", "System"]
DISTRIBUTION_TYPES = {0: "Download", 1: "GameCard"}
FS_TYPES = {0: "RomFS", 1: "PFS0"}

# Encryption type strings
ENCRYPTION_TYPE_STANDARD = "Standard crypto"
ENCRYPTION_TYPE_TITLEKEY = "Titlekey crypto"

# Magic values
IVFC_MAGIC = b'IVFC'
PFS0_MAGIC = b'PFS0'
RIGHTS_ID_NULL = "00000000000000000000000000000000"
ZERO_HASH = bytearray(b"\x00" * 16)

def save_section(nca_object, i, output_path=None):
    """
    Extract a decrypted section from an NCA file.
    
    Args:
        nca_object: NCA object with decrypted sections
        i: Section index (0-3)
        output_path: (deprecated) Unused parameter kept for compatibility
    
    Returns:
        bytes: Decrypted section data (RomFS or PFS0)
    """
    decrypted_section = nca_object.decrypted_sections[i]
    fs_header = nca_object.fsheaders[i]
    return decrypted_section[fs_header.content_start:fs_header.content_end]

class SectionTableEntry:
    """
    Parses a section table entry from NCA header.
    
    A section table entry describes where a section's data is located
    on disk (in media blocks) and its size.
    """
    def __init__(self, data):
        """
        Args:
            data: 16-byte section table entry from NCA header
        """
        self.mediaOffset = int.from_bytes(data[0x0:0x4], byteorder='little', signed=False)
        self.mediaEndOffset = int.from_bytes(data[0x4:0x8], byteorder='little', signed=False)
        
        # Convert media offsets to byte offsets (media blocks are 0x200 bytes)
        self.offset = self.mediaOffset * MEDIA_BLOCK_SIZE
        self.endOffset = self.mediaEndOffset * MEDIA_BLOCK_SIZE
        
        self.unknown1 = int.from_bytes(data[0x8:0xc], byteorder='little', signed=False)
        self.unknown2 = int.from_bytes(data[0xc:0x10], byteorder='little', signed=False)
        self.sha1 = None

class FsHeader:
    """
    Parses and represents a filesystem header from an NCA section.
    
    Filesystem headers describe the structure and encryption of sections,
    whether they're RomFS (read-only) or PFS0 (plain filesystem) format.
    """
    def __init__(self, fsheader):
        """
        Args:
            fsheader: 512-byte filesystem header from NCA header
        """
        self.fsheader = fsheader
        self.version = int.from_bytes(self.fsheader[FS_HEADER_VERSION_OFFSET:FS_HEADER_VERSION_OFFSET + 2], 
                                     byteorder='little', signed=False)
        self.fsType = int.from_bytes(self.fsheader[FS_HEADER_FS_TYPE_OFFSET:FS_HEADER_FS_TYPE_OFFSET + 1], 
                                    byteorder='little', signed=False)
        self.hashType = int.from_bytes(self.fsheader[FS_HEADER_HASH_TYPE_OFFSET:FS_HEADER_HASH_TYPE_OFFSET + 1], 
                                      byteorder='little', signed=False)
        self.encryptionType = int.from_bytes(self.fsheader[FS_HEADER_ENCRYPTION_TYPE_OFFSET:FS_HEADER_ENCRYPTION_TYPE_OFFSET + 1], 
                                           byteorder='little', signed=False)
        self.padding = self.fsheader[FS_HEADER_PADDING_OFFSET:FS_HEADER_PADDING_OFFSET + 3]
        self.hashInfo = self.fsheader[FS_HEADER_HASH_INFO_OFFSET:FS_HEADER_HASH_INFO_OFFSET + 0xF8]
        
        self.section_has_content = False
        self.content_start = 0
        self.content_end = 0
        self.content_extension = ""
        
        self._parse_fs_type()
        
        self.patchInfo = self.fsheader[FS_HEADER_PATCH_INFO_OFFSET:FS_HEADER_PATCH_INFO_OFFSET + 0x40]
        self.generation = self.fsheader[FS_HEADER_GENERATION_OFFSET:FS_HEADER_GENERATION_OFFSET + 4]
        self.secureValue = self.fsheader[FS_HEADER_SECURE_VALUE_OFFSET:FS_HEADER_SECURE_VALUE_OFFSET + 4]
        self.sparseInfo = self.fsheader[FS_HEADER_SPARSE_INFO_OFFSET:FS_HEADER_SPARSE_INFO_OFFSET + 0x58]
        self.reserved = self.fsheader[FS_HEADER_RESERVED_OFFSET:FS_HEADER_RESERVED_OFFSET + 0x60]
        self.CryptoCounterCtr = bytearray((b"\x00" * 8) + self.generation + self.secureValue)[::-1]
    
    def _parse_fs_type(self):
        """Parse filesystem type (RomFS or PFS0)."""
        if self.fsType == 0:
            self._parse_romfs()
        elif self.fsType == 1:
            self._parse_pfs0()
    
    def _parse_romfs(self):
        """Parse RomFS (Read-Only Filesystem) header."""
        self.hashData = ivfc.Ivfc(self.hashInfo)
        if self.hashData.magic == IVFC_MAGIC:
            self.magic = "IVFC"
            self.section_has_content = True
            self.max_layer = self.hashData.max_layers - 1
            self.fsType = "RomFS"
            self.ivfc_levels = self.hashData.levels
            self.superblockHash = self.hashData.master_hash
            self.id = int.from_bytes(self.hashData.version, byteorder='little', signed=False)
            
            content_start = self.hashData.levels[self.max_layer].data_offset
            content_size = self.hashData.levels[self.max_layer].data_size
            
            self.content_start = content_start
            self.content_end = content_start + content_size
            self.content_extension = ".romfs"
    
    def _parse_pfs0(self):
        """Parse PFS0 (Plain Filesystem) header."""
        self.hashData = pfs0.Pfs0HashData(self.hashInfo)
        if self.hashType == 2:
            if self.hashData.master_hash == ZERO_HASH:
                self.section_has_content = False
            else:
                self.section_has_content = True
                self.fsType = "PFS0"
                self.superblockHash = self.hashData.master_hash
                self.magic = "PFS0"
                
                self.content_start = self.hashData.region_1_offset
                self.content_end = self.content_start + self.hashData.region_1_size
                self.content_extension = ".pfs0"

class NcaHeader:
    """
    Parses and represents the main NCA header.
    
    The NCA header contains metadata about the content, including signatures,
    title ID, encryption information, and section table entries.
    """
    def __init__(self, ncaheader):
        """
        Args:
            ncaheader: 3072-byte decrypted NCA header
        """
        self.ncaheader = ncaheader
        self.signature1 = self.ncaheader[NCA_SIGNATURE1_OFFSET:NCA_SIGNATURE1_OFFSET + NCA_SIGNATURE1_SIZE].hex().upper()
        self.signature2 = self.ncaheader[NCA_SIGNATURE2_OFFSET:NCA_SIGNATURE2_OFFSET + NCA_SIGNATURE2_SIZE].hex().upper()
        self.magic = self.ncaheader[NCA_MAGIC_OFFSET:NCA_MAGIC_OFFSET + NCA_MAGIC_SIZE].decode("utf-8")
        
        is_game_card = int.from_bytes(self.ncaheader[NCA_DISTRIBUTION_OFFSET:NCA_DISTRIBUTION_OFFSET + 1], 
                                      byteorder='little', signed=False)
        self.isGameCard = is_game_card
        self.distribution_type = DISTRIBUTION_TYPES.get(is_game_card, "Unknown")
        
        content_type_idx = int.from_bytes(self.ncaheader[NCA_CONTENT_TYPE_OFFSET:NCA_CONTENT_TYPE_OFFSET + 1], 
                                         byteorder='little', signed=False)
        self.contentType = content_type_idx
        
        self.cryptoType = int.from_bytes(self.ncaheader[NCA_CRYPTO_TYPE_OFFSET:NCA_CRYPTO_TYPE_OFFSET + 1], 
                                        byteorder='little', signed=False)
        self.keyIndex = int.from_bytes(self.ncaheader[NCA_KEY_INDEX_OFFSET:NCA_KEY_INDEX_OFFSET + 1], 
                                      byteorder='little', signed=False)
        self.size = int.from_bytes(self.ncaheader[NCA_SIZE_OFFSET:NCA_SIZE_OFFSET + NCA_SIZE_SIZE], 
                                  byteorder='little', signed=False)
        
        # Title ID is in reverse byte order
        self.titleId = self.ncaheader[NCA_TITLE_ID_OFFSET:NCA_TITLE_ID_OFFSET + NCA_TITLE_ID_SIZE][::-1].hex().upper()
        
        self.contentIndex = int.from_bytes(self.ncaheader[NCA_CONTENT_INDEX_OFFSET:NCA_CONTENT_INDEX_OFFSET + 4], 
                                          byteorder='little', signed=False)
        
        self.sdkVersion = self._parse_sdk_version()
        
        self.KeyGeneration = int.from_bytes(self.ncaheader[NCA_KEY_GENERATION_OFFSET:NCA_KEY_GENERATION_OFFSET + 1], 
                                           byteorder='little', signed=False)
        self.cryptoType2 = int.from_bytes(self.ncaheader[NCA_CRYPTO_TYPE2_OFFSET:NCA_CRYPTO_TYPE2_OFFSET + 1], 
                                         byteorder='little', signed=False)
        self.rightsId = self.ncaheader[NCA_RIGHTS_ID_OFFSET:NCA_RIGHTS_ID_OFFSET + NCA_RIGHTS_ID_SIZE].hex().upper()
        
        # Map content type index to name
        self.contentType = CONTENT_TYPES[content_type_idx] if content_type_idx < len(CONTENT_TYPES) else "Unknown"
        
        # Parse section tables and encrypted key area
        self.sectionTables = [
            SectionTableEntry(self.ncaheader[NCA_SECTION_TABLE_OFFSET + i * NCA_SECTION_ENTRY_SIZE:
                                            NCA_SECTION_TABLE_OFFSET + (i + 1) * NCA_SECTION_ENTRY_SIZE])
            for i in range(4)
        ]
        self.EncryptedKeyArea = [
            self.ncaheader[NCA_ENCRYPTED_KEY_AREA_OFFSET + i * NCA_KEY_AREA_KEY_SIZE:
                          NCA_ENCRYPTED_KEY_AREA_OFFSET + (i + 1) * NCA_KEY_AREA_KEY_SIZE]
            for i in range(4)
        ]
    
    def _parse_sdk_version(self):
        """Parse SDK version from 4-byte field."""
        sdk_bytes = self.ncaheader[NCA_SDK_VERSION_OFFSET:NCA_SDK_VERSION_OFFSET + NCA_SDK_VERSION_SIZE]
        sdk_parts = [
            str(int.from_bytes(sdk_bytes[3:4], byteorder='little')),
            str(int.from_bytes(sdk_bytes[2:3], byteorder='little')),
            str(int.from_bytes(sdk_bytes[1:2], byteorder='little')),
            '0'
        ]
        return '.'.join(sdk_parts)

class NcaHeaderOnly:
    """
    Lightweight NCA parser that only decrypts and parses the header.
    
    Used when you only need metadata about an NCA file without
    decrypting the full content sections.
    """
    def __init__(self, nca_data):
        """
        Args:
            nca_data: Complete NCA file data (at least first 0xC00 bytes)
        """
        self.nca_data = nca_data
        self.sections = []
        
        # Decrypt the NCA header
        self.encrypted_header = nca_data[0x0:NCA_HEADER_SIZE]
        self.root_keys = RootKeys()
        key_sources = KeySources()
        self.tsec_keys = crypto.TsecKeygen(key_sources.tsec_secret_26)
        self.header_key = crypto.Keygen(self.tsec_keys.tsec_root_key_02).header_key
        self.decrypted_nca_header = crypto.decrypt_xts(self.encrypted_header, self.header_key)
        
        # Parse the header
        self.header = NcaHeader(self.decrypted_nca_header)
        
        # Extract key properties
        self._extract_properties()
    
    def _extract_properties(self):
        """Extract commonly used properties from header."""
        self.distribution_type = DISTRIBUTION_TYPES.get(self.header.isGameCard, "Unknown")
        self.rightsid = self.header.rightsId
        self.encryption_type = ENCRYPTION_TYPE_TITLEKEY if self.rightsid != RIGHTS_ID_NULL else ENCRYPTION_TYPE_STANDARD
        self.content_type = self.header.contentType
        self.titleId = self.header.titleId
        self.sdkversion = self.header.sdkVersion
        self.cryptoType = self.header.cryptoType
        self.cryptoType2 = self.header.cryptoType2
        self.KeyGeneration = self.header.KeyGeneration
        self.master_key_revision = self._calculate_master_key_revision()
    
    def _calculate_master_key_revision(self):
        """Calculate the master key revision from crypto type and key generation."""
        if self.KeyGeneration != 0:
            return self.KeyGeneration - 1
        elif self.cryptoType == 0 and self.KeyGeneration == 0:
            return 0
        elif self.cryptoType == 2 and self.KeyGeneration == 0:
            return 1
        return 0

class Nca:
    """
    Full NCA parser that decrypts and parses header, sections, and content.
    
    Handles both Standard crypto (fixed keys) and Titlekey crypto (encrypted keys)
    encryption types. Decrypts all 4 sections and prepares them for extraction.
    """
    def __init__(self, nca_data, master_kek_source=None, titlekey=None):
        """
        Args:
            nca_data: Complete NCA file data
            titlekey: Optional titlekey for titlekey-encrypted content
        """
        self.nca_data = nca_data
        self.sections = []
        
        # Decrypt the NCA header
        self.encrypted_header = nca_data[0x0:NCA_HEADER_SIZE]
        self.root_keys = RootKeys()
        key_sources = KeySources()
        self.tsec_keys = crypto.TsecKeygen(key_sources.tsec_secret_26)
        self.header_key = crypto.Keygen(self.tsec_keys.tsec_root_key_02).header_key
        self.decrypted_nca_header = crypto.decrypt_xts(self.encrypted_header, self.header_key)
        
        # Parse the header
        self.header = NcaHeader(self.decrypted_nca_header)
        
        # Extract key properties
        self._extract_properties()
        
        # Extract raw section data
        for i in range(4):
            self.sections.append(nca_data[self.header.sectionTables[i].offset:self.header.sectionTables[i].endOffset])
        
        # Setup key area
        self._setup_key_area()
        
        # Parse filesystem headers
        self.fsheaders = [
            FsHeader(self.decrypted_nca_header[0x400 + i * FS_HEADER_SIZE:0x400 + (i + 1) * FS_HEADER_SIZE])
            for i in range(4)
        ]
        
        # Decrypt sections based on encryption type
        self._decrypt_sections(titlekey)
    
    def _extract_properties(self):
        """Extract commonly used properties from header."""
        self.distribution_type = DISTRIBUTION_TYPES.get(self.header.isGameCard, "Unknown")
        self.rightsid = self.header.rightsId
        self.encryption_type = ENCRYPTION_TYPE_TITLEKEY if self.rightsid != RIGHTS_ID_NULL else ENCRYPTION_TYPE_STANDARD
        self.content_type = self.header.contentType
        self.titleId = self.header.titleId
        self.sdkversion = self.header.sdkVersion
        self.cryptoType = self.header.cryptoType
        self.cryptoType2 = self.header.cryptoType2
        self.KeyGeneration = self.header.KeyGeneration
        self.master_key_revision = self._calculate_master_key_revision()
    
    def _calculate_master_key_revision(self):
        """Calculate the master key revision from crypto type and key generation."""
        if self.KeyGeneration != 0:
            return self.KeyGeneration - 1
        elif self.cryptoType == 0 and self.KeyGeneration == 0:
            return 0
        elif self.cryptoType == 2 and self.KeyGeneration == 0:
            return 1
        return 0
    
    def _setup_key_area(self):
        """Setup key area and derive decryption keys."""
        self.tsec_root_key_prod, self.tsec_root_key_dev = crypto.tsec_keygen()
        self.keygen = crypto.Keygen(self.tsec_root_key_prod)
        self.master_keys = self.keygen.master_key
        master_key = self.master_keys[self.master_key_revision]
        self.keys = crypto.single_keygen_master_key(master_key)
        self.master_key, self.package2_key, self.titlekek, \
            self.key_area_key_system, self.key_area_key_ocean, self.key_area_key_application = self.keys
        
        # Setup key area key types
        self.key_area_key_types = [self.key_area_key_application, self.key_area_key_ocean, self.key_area_key_system]
        self.key_area_key_type = KEY_AREA_KEY_TYPES[self.header.keyIndex] if self.header.keyIndex < len(KEY_AREA_KEY_TYPES) else "Unknown"
        self.key_area_key = self.key_area_key_types[self.header.keyIndex]
    
    def _decrypt_sections(self, titlekey):
        """Decrypt sections based on encryption type."""
        if self.encryption_type == ENCRYPTION_TYPE_TITLEKEY:
            self._decrypt_sections_titlekey(titlekey)
        else:
            self._decrypt_sections_standard()
    
    def _decrypt_sections_titlekey(self, titlekey):
        """Decrypt sections using titlekey encryption."""
        self.encrypted_titlekey = titlekey
        self.decrypted_titlekey = crypto.decrypt_ecb(self.encrypted_titlekey, self.titlekek)
        self.decrypted_sections = []
        for i in range(4):
            self.decrypted_sections.append(
                crypto.decrypt_ctr(self.sections[i], self.decrypted_titlekey, 
                                  self.fsheaders[i].CryptoCounterCtr, self.header.sectionTables[i].offset)
            )
    
    def _decrypt_sections_standard(self):
        """Decrypt sections using standard (fixed key) encryption."""
        self.DecryptedKeyArea = []
        for i in range(4):
            self.DecryptedKeyArea.append(crypto.decrypt_ecb(self.header.EncryptedKeyArea[i], self.key_area_key))
        
        self.decrypted_sections = []
        for i in range(4):
            self.decrypted_sections.append(
                crypto.decrypt_ctr(self.sections[i], self.DecryptedKeyArea[2], 
                                  self.fsheaders[i].CryptoCounterCtr, self.header.sectionTables[i].offset)
            )
    
    # ========================================================================
    # Utility methods for hac.py and other tools
    # ========================================================================
    
    def get_header_bytes(self):
        """
        Get the decrypted NCA header as bytes.
        
        Returns:
            bytes: Decrypted 0xC00-byte NCA header
        """
        return self.decrypted_nca_header
    
    def get_encrypted_header_bytes(self):
        """
        Get the encrypted NCA header as bytes.
        
        Returns:
            bytes: Encrypted 0xC00-byte NCA header
        """
        return self.encrypted_header
    
    def get_section_bytes(self, section_idx):
        """
        Get raw encrypted section data.
        
        Args:
            section_idx: Section index (0-3)
        
        Returns:
            bytes: Raw encrypted section data
        """
        if section_idx < 0 or section_idx > 3:
            raise ValueError(f"Invalid section index: {section_idx}")
        return self.sections[section_idx]
    
    def get_decrypted_section_bytes(self, section_idx):
        """
        Get decrypted section data.
        
        Args:
            section_idx: Section index (0-3)
        
        Returns:
            bytes: Decrypted section data
        """
        if section_idx < 0 or section_idx > 3:
            raise ValueError(f"Invalid section index: {section_idx}")
        return self.decrypted_sections[section_idx]
    
    def has_section(self, section_idx):
        """
        Check if a section has content.
        
        Args:
            section_idx: Section index (0-3)
        
        Returns:
            bool: True if section contains data
        """
        if section_idx < 0 or section_idx > 3:
            return False
        return self.fsheaders[section_idx].section_has_content
    
    def get_section_type(self, section_idx):
        """
        Get the type of a section (RomFS or PFS0).
        
        Args:
            section_idx: Section index (0-3)
        
        Returns:
            str: Section type ("RomFS" or "PFS0") or None if no content
        """
        if section_idx < 0 or section_idx > 3:
            return None
        fsheader = self.fsheaders[section_idx]
        if fsheader.section_has_content:
            return fsheader.fsType
        return None
    
    def is_titlekey_encrypted(self):
        """
        Check if NCA uses titlekey encryption.
        
        Returns:
            bool: True if titlekey-encrypted, False if standard crypto
        """
        return self.encryption_type == ENCRYPTION_TYPE_TITLEKEY
    
    def get_titlekey(self):
        """
        Get the decrypted titlekey if this is a titlekey-encrypted NCA.
        
        Returns:
            bytes: Decrypted titlekey, or None if standard crypto
        """
        if self.encryption_type == ENCRYPTION_TYPE_TITLEKEY:
            return self.decrypted_titlekey
        return None
    
    def get_titlekey_encrypted(self):
        """
        Get the encrypted titlekey if this is a titlekey-encrypted NCA.
        
        Returns:
            bytes: Encrypted titlekey, or None if standard crypto
        """
        if self.encryption_type == ENCRYPTION_TYPE_TITLEKEY:
            return self.encrypted_titlekey
        return None
    
    def get_keys_info(self):
        """
        Get encryption keys information.
        
        Returns:
            dict: Dictionary with key information
        """
        info = {
            'encryption_type': self.encryption_type,
            'master_key_revision': self.master_key_revision,
            'key_area_key_type': self.key_area_key_type,
        }
        
        if self.encryption_type == ENCRYPTION_TYPE_TITLEKEY:
            info['encrypted_titlekey'] = self.encrypted_titlekey.hex().upper() if hasattr(self.encrypted_titlekey, 'hex') else self.encrypted_titlekey.hex().upper()
            info['decrypted_titlekey'] = self.decrypted_titlekey.hex().upper() if hasattr(self.decrypted_titlekey, 'hex') else self.decrypted_titlekey.hex().upper()
        else:
            info['key_area_key'] = self.key_area_key.hex().upper() if hasattr(self.key_area_key, 'hex') else self.key_area_key.hex().upper()
            info['key_area_key_encrypted'] = [k.hex().upper() for k in self.header.EncryptedKeyArea]
            info['key_area_key_decrypted'] = [k.hex().upper() for k in self.DecryptedKeyArea]
        
        return info

class NcaInfo:
    """
    Generates and prints detailed information about an NCA file.
    
    Displays encryption keys, section details, RomFS/PFS0 structure,
    and NPDM (process metadata) information.
    """
    
    # NPDM pattern for extracting process metadata
    NPDM_PATTERN = rb'\x4D\x45\x54\x41\x00\x00\x00\x00'
    NPDM_ACI_OFFSET_OFFSET = 0x70
    NPDM_ACI_OFFSET_SIZE = 4
    NPDM_ACI_SIZE_OFFSET = 0x74
    NPDM_ACI_SIZE_SIZE = 4
    
    def __init__(self, nca):
        """
        Args:
            nca: Nca object with decrypted sections
        """
        self.nca = nca
        self.ncaheader = self.nca.header
        
        # Collect output lines for different sections
        nca_info_lines = []
        section_info_lines = []
        npdm_info_lines = []
        kac_info_lines = []
        sac_info_lines = []
        fac_info_lines = []
        
        # Build and print information
        self._build_nca_info(nca_info_lines)
        self._build_key_area_info(nca_info_lines)
        self._build_section_info(section_info_lines, npdm_info_lines, kac_info_lines, sac_info_lines, fac_info_lines)
        
        # Print all collected information
        self._print_all_info(nca_info_lines, npdm_info_lines, kac_info_lines, sac_info_lines, fac_info_lines, section_info_lines)
    
    def _build_nca_info(self, lines):
        """Build basic NCA header information."""
        lines.append('NCA:')
        lines.append(f'Magic:                              {self.ncaheader.magic}')
        lines.append(f'Fixed-Key Index:                    {hex(self.ncaheader.keyIndex)}')
        
        # Handle signature formatting
        sig1 = self.ncaheader.signature1 if isinstance(self.ncaheader.signature1, str) else self.ncaheader.signature1.hex().upper()
        sig2 = self.ncaheader.signature2 if isinstance(self.ncaheader.signature2, str) else self.ncaheader.signature2.hex().upper()
        
        util.print_split_hex('Fixed-Key Signature:', sig1, lines)
        util.print_split_hex('NPDM Signature:', sig2, lines)
        
        lines.append(f'Content Size:                       0x{self.ncaheader.size:012x}')
        lines.append(f'Title ID:                           {self.ncaheader.titleId}')
        lines.append(f'SDK Version:                        {self.ncaheader.sdkVersion}')
        lines.append(f'Distribution type:                  {self.ncaheader.distribution_type}')
        lines.append(f'Content Type:                       {self.ncaheader.contentType}')
        lines.append(f'Master Key Revision:                {hex(self.nca.master_key_revision)}')
        lines.append(f'Encryption Type:                    {self.nca.encryption_type}')
    
    def _build_key_area_info(self, lines):
        """Build key area information."""
        if self.nca.rightsid != RIGHTS_ID_NULL:
            lines.append(f'Rights ID:                          {self.nca.rightsid}')
            lines.append(f'Titlekey (Encrypted):               {self.nca.encrypted_titlekey.hex().upper()}')
            lines.append(f'Titlekey (Decrypted):               {self.nca.decrypted_titlekey.hex().upper()}')
        else:
            self._build_standard_key_info(lines)
    
    def _build_standard_key_info(self, lines):
        """Build standard (fixed key) encryption key information."""
        key_type_name = self.nca.key_area_key_type.lower()
        lines.append(f'Key Area Encryption Key Type:       key_area_key_{key_type_name}_{self.nca.master_key_revision:02X}')
        lines.append(f'Key Area Encryption Key:            {self.nca.key_area_key.hex().upper()}')
        
        lines.append('Key Area (Encrypted):')
        for i in range(4):
            lines.append(f'    Key {i} (Encrypted):              {self.ncaheader.EncryptedKeyArea[i].hex().upper()}')
        
        lines.append('Key Area (Decrypted):')
        for i in range(4):
            lines.append(f'    Key {i} (Decrypted):              {self.nca.DecryptedKeyArea[i].hex().upper()}')
    
    def _build_section_info(self, section_lines, npdm_lines, kac_lines, sac_lines, fac_lines):
        """Build section information for all 4 sections."""
        section_lines.append('Sections:')
        
        for i in range(4):
            fsheader = self.nca.fsheaders[i]
            if fsheader.section_has_content:
                self._build_single_section_info(i, section_lines, npdm_lines, kac_lines, sac_lines, fac_lines)
    
    def _build_single_section_info(self, section_idx, section_lines, npdm_lines, kac_lines, sac_lines, fac_lines):
        """Build information for a single section."""
        fsheader = self.nca.fsheaders[section_idx]
        section_table = self.nca.header.sectionTables[section_idx]
        section_size = section_table.endOffset - section_table.offset
        
        # Build CTR
        ctr1 = fsheader.CryptoCounterCtr.hex().upper()[:-8]
        ctr2 = f'{(section_table.offset >> 4):08x}'
        
        section_lines.append(f'    Section {section_idx}')
        section_lines.append(f'        Offset:                     0x{section_table.offset:012x}')
        section_lines.append(f'        Size:                       0x{section_size:012x}')
        section_lines.append(f'        Partition Type:             {fsheader.fsType}')
        section_lines.append(f'        Section CTR:                {ctr1}{ctr2}')
        section_lines.append(f'        Superblock Hash:            {fsheader.hashData.master_hash.hex().upper()}')
        
        if fsheader.fsType == "RomFS":
            self._build_romfs_info(section_idx, fsheader, section_lines)
        elif fsheader.fsType == "PFS0":
            self._build_pfs0_info(section_idx, fsheader, section_lines, npdm_lines, kac_lines, sac_lines, fac_lines)
    
    def _build_romfs_info(self, section_idx, fsheader, section_lines):
        """Build RomFS-specific section information."""
        section_lines.append(f'        Magic:                      {fsheader.magic}')
        section_lines.append(f'        ID:                         {fsheader.id:08x}')
        
        level_count = fsheader.hashData.max_layer_count
        for level_idx in range(level_count):
            ivfc_level = fsheader.ivfc_levels[level_idx + 1]
            ivfc_level_prev = fsheader.ivfc_levels[level_idx]
            hash_block_size = fsheader.ivfc_levels[1].data_size
            
            section_lines.append(f'        Level {level_idx}:')
            section_lines.append(f'            Data Offset:            0x{ivfc_level.data_offset:012x}')
            section_lines.append(f'            Data Size:              0x{ivfc_level.data_size:012x}')
            
            if level_idx != 0:
                section_lines.append(f'            Hash Offset:            0x{ivfc_level_prev.data_offset:012x}')
            section_lines.append(f'            Hash Block Size:        0x{hash_block_size:08x}')
    
    def _build_pfs0_info(self, section_idx, fsheader, section_lines, npdm_lines, kac_lines, sac_lines, fac_lines):
        """Build PFS0-specific section information."""
        section_lines.append('        Hash Table:')
        section_lines.append(f'            Offset:                 {fsheader.hashData.region_0_offset:012X}')
        section_lines.append(f'            Size:                   {fsheader.hashData.region_0_size:012X}')
        section_lines.append(f'            Block Size:             0x{fsheader.hashData.block_size:X}')
        section_lines.append(f'        PFS0 Offset:                {fsheader.hashData.region_1_offset:012X}')
        section_lines.append(f'        PFS0 Size:                  {fsheader.hashData.region_1_size:012X}')
        
        # Extract and parse NPDM
        npdm_data = self._extract_npdm(section_idx)
        if npdm_data:
            npdm.NpdmInfoPrint(npdm_data, npdm_lines, kac_lines, sac_lines, fac_lines)

    def _extract_npdm(self, section_idx):
            """Extract NPDM data from a PFS0 section."""
            decrypted_section = self.nca.decrypted_sections[section_idx]
            fsheader = self.nca.fsheaders[section_idx]
            pfs0_data = decrypted_section[fsheader.content_start:fsheader.content_end]  # Slice to PFS0 content only
            match = re.search(self.NPDM_PATTERN, pfs0_data)
            
            if not match:
                return None
            
            start_of_npdm = match.start()
            
            # Read ACI offset and size from NPDM header
            aci_offset_pos = start_of_npdm + self.NPDM_ACI_OFFSET_OFFSET
            aci_offset = int.from_bytes(pfs0_data[aci_offset_pos:aci_offset_pos + self.NPDM_ACI_OFFSET_SIZE], 
                                    byteorder='little', signed=False)
            
            aci_size_pos = start_of_npdm + self.NPDM_ACI_SIZE_OFFSET
            aci_size = int.from_bytes(pfs0_data[aci_size_pos:aci_size_pos + self.NPDM_ACI_SIZE_SIZE], 
                                    byteorder='little', signed=False)
            
            end_of_npdm = aci_offset + aci_size + start_of_npdm
            return pfs0_data[start_of_npdm:end_of_npdm]


    
    def _print_all_info(self, nca_lines, npdm_lines, kac_lines, sac_lines, fac_lines, section_lines):
        """Print all collected information."""
        for line in nca_lines:
            print(line)
        for line in npdm_lines:
            print(line)
        for line in kac_lines:
            print(line)
        for line in sac_lines:
            print(line)
        for line in fac_lines:
            print(line)
        for line in section_lines:
            print(line)


# ============================================================================
# Section Extraction Utilities
# ============================================================================

class SectionExtractor:
    """
    Utility class for extracting and saving NCA sections.
    """
    
    @staticmethod
    def save_section_raw(nca, section_idx, output_path):
        """
        Save a section as raw bytes to a file. (This saves the FULL decrypted section, including hashes/IVFC.)
        
        Args:
            nca: Nca object
            section_idx: Section index (0-3)
            output_path: Path to save file
        
        Returns:
            bool: True if successful
        """
        try:
            section_data = nca.get_decrypted_section_bytes(section_idx)
            with open(output_path, 'wb') as f:
                f.write(section_data)
            return True
        except Exception as e:
            print(f"Error saving section {section_idx}: {e}")
            return False
        
    @staticmethod
    def save_header(nca, output_path, encrypted=False):
        """
        Save NCA header to a file.
        
        Args:
            nca: Nca object
            output_path: Path to save file
            encrypted: If True, save encrypted header; if False, save decrypted
        
        Returns:
            bool: True if successful
        """
        try:
            header_data = nca.get_encrypted_header_bytes() if encrypted else nca.get_header_bytes()
            with open(output_path, 'wb') as f:
                f.write(header_data)
            return True
        except Exception as e:
            print(f"Error saving header: {e}")
            return False
    
    @staticmethod
    def _find_romfs_section(nca):
        """
        Find the RomFS section in the NCA.
        
        Args:
            nca: Nca object
        
        Returns:
            int: Section index (0-3) or -1 if not found
        """
        for i in range(4):
            if nca.has_section(i) and nca.get_section_type(i) == "RomFS":
                return i
        return -1
    
    @staticmethod
    def _find_pfs0_section(nca):
        """
        Find the PFS0 section in the NCA.
        
        Args:
            nca: Nca object
        
        Returns:
            int: Section index (0-3) or -1 if not found
        """
        for i in range(4):
            if nca.has_section(i) and nca.get_section_type(i) == "PFS0":
                return i
        return -1
    
    @staticmethod
    def save_section_as_romfs(nca, output_path):
        """
        Save a RomFS section as a romfs file. (Slices to content only.)
        
        Automatically finds the RomFS section in the NCA.
        
        Args:
            nca: Nca object
            output_path: Path to save file
        
        Returns:
            bool: True if successful
        """
        section_idx = SectionExtractor._find_romfs_section(nca)
        if section_idx == -1:
            print("The input NCA has no RomFS")
            return False
        
        try:
            full_data = nca.get_decrypted_section_bytes(section_idx)
            fs_header = nca.fsheaders[section_idx]
            content_data = full_data[fs_header.content_start:fs_header.content_end]  # Slice to pure RomFS
            with open(output_path, 'wb') as f:
                f.write(content_data)
            return True
        except Exception as e:
            print(f"Error saving RomFS section {section_idx}: {e}")
            return False
    
    @staticmethod
    def save_section_as_pfs0(nca, output_path):
        """
        Save a PFS0 section as a pfs0 file. (Slices to content only.)
        
        Automatically finds the PFS0 section in the NCA.
        
        Args:
            nca: Nca object
            output_path: Path to save file
        
        Returns:
            bool: True if successful
        """
        section_idx = SectionExtractor._find_pfs0_section(nca)
        if section_idx == -1:
            print("The input NCA has no PFS0 with content")
            return False
        
        try:
            full_data = nca.get_decrypted_section_bytes(section_idx)
            fs_header = nca.fsheaders[section_idx]
            content_data = full_data[fs_header.content_start:fs_header.content_end]  # Slice to pure PFS0
            with open(output_path, 'wb') as f:
                f.write(content_data)
            return True
        except Exception as e:
            print(f"Error saving PFS0 section {section_idx}: {e}")
            return False
    
    @staticmethod
    def extract_section_romfs(nca, output_dir):
        """
        Extract a RomFS section to a directory. (Slices to content only.)
        
        Automatically finds the RomFS section in the NCA.
        
        Args:
            nca: Nca object
            output_dir: Directory to extract to
        
        Returns:
            bool: True if successful
        """
        section_idx = SectionExtractor._find_romfs_section(nca)
        if section_idx == -1:
            print("The input NCA has no RomFS")
            return False
        
        try:
            full_data = nca.get_decrypted_section_bytes(section_idx)
            fs_header = nca.fsheaders[section_idx]
            content_data = full_data[fs_header.content_start:fs_header.content_end]  # Slice to pure RomFS
            romfs.romfs_process(content_data, output_path=Path(output_dir), 
                              list_only=False, print_info=False)
            return True
        except Exception as e:
            print(f"Error extracting RomFS section {section_idx}: {e}")
            return False
    
    @staticmethod
    def extract_section_pfs0(nca, output_dir):
        """
        Extract a PFS0 section to a directory. (Slices to content only.)
        
        Automatically finds the PFS0 section in the NCA.
        
        Args:
            nca: Nca object
            output_dir: Directory to extract to
        
        Returns:
            bool: True if successful
        """
        section_idx = SectionExtractor._find_pfs0_section(nca)
        if section_idx == -1:
            print("The input NCA has no PFS0 with content")
            return False
        
        try:
            full_data = nca.get_decrypted_section_bytes(section_idx)
            fs_header = nca.fsheaders[section_idx]
            content_data = full_data[fs_header.content_start:fs_header.content_end]  # Slice to pure PFS0
            pfs0.extract_pfs0(content_data, output_dir)
            return True
        except Exception as e:
            print(f"Error extracting PFS0 section {section_idx}: {e}")
            return False
    
    @staticmethod
    def list_romfs_contents(nca):
        """
        List contents of a RomFS section. (Slices to content only.)
        
        Automatically finds the RomFS section in the NCA.
        
        Args:
            nca: Nca object
        
        Returns:
            list: List of file entries or None if error
        """
        section_idx = SectionExtractor._find_romfs_section(nca)
        if section_idx == -1:
            print("The input NCA has no RomFS")
            return None
        
        try:
            full_data = nca.get_decrypted_section_bytes(section_idx)
            fs_header = nca.fsheaders[section_idx]
            content_data = full_data[fs_header.content_start:fs_header.content_end]  # Slice to pure RomFS
            # Use romfs_process with list_only=True
            results = romfs.romfs_process(content_data, output_path=None,
                                         list_only=True, print_info=False)
            return results
        except Exception as e:
            print(f"Error listing RomFS section {section_idx}: {e}")
            return None
    
    @staticmethod
    def extract_section(nca, section_idx, output_dir):
        """
        Extract a section (RomFS or PFS0) to a directory. (Slices to content only.)
        
        Extracts the specified section if it has valid content.
        Automatically detects whether the section is RomFS or PFS0.
        
        Args:
            nca: Nca object
            section_idx: Section index (0-3)
            output_dir: Directory to extract to
        
        Returns:
            bool: True if successful
        """
        if section_idx < 0 or section_idx > 3:
            print(f"Invalid section index: {section_idx}")
            return False
        
        if not nca.has_section(section_idx):
            print(f"Section {section_idx} does not have valid content")
            return False
        
        section_type = nca.get_section_type(section_idx)
        
        try:
            full_data = nca.get_decrypted_section_bytes(section_idx)
            fs_header = nca.fsheaders[section_idx]
            content_data = full_data[fs_header.content_start:fs_header.content_end]  # Slice to content only
            
            if section_type == "RomFS":
                romfs.romfs_process(content_data, output_path=Path(output_dir), 
                                  list_only=False, print_info=False)
                return True
            elif section_type == "PFS0":
                pfs0.extract_pfs0(content_data, output_dir)
                return True
            else:
                print(f"Unknown section type: {section_type}")
                return False
        except Exception as e:
            print(f"Error extracting section {section_idx}: {e}")
            return False
    
    @staticmethod
    def save_plaintext_nca(nca, output_path):
        """
        Save NCA in plaintext format.
        
        Plaintext format consists of the encrypted NCA header followed by
        the raw bytes of all 4 decrypted sections concatenated in order.
        
        Args:
            nca: Nca object
            output_path: Path to save file
        
        Returns:
            bool: True if successful
        """
        try:
            with open(output_path, 'wb') as f:
                # Write encrypted header
                f.write(nca.get_encrypted_header_bytes())
                
                # Write all 4 decrypted sections
                for i in range(4):
                    f.write(nca.get_decrypted_section_bytes(i))
            
            return True
        except Exception as e:
            print(f"Error saving plaintext NCA: {e}")
            return False
