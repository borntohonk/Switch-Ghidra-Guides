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
import bktr

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
NCA_MAGIC_SIZE = 0x4
NCA_DISTRIBUTION_OFFSET = 0x204
NCA_CONTENT_TYPE_OFFSET = 0x205
NCA_CRYPTO_TYPE_OFFSET = 0x206
NCA_KEY_INDEX_OFFSET = 0x207
NCA_SIZE_OFFSET = 0x208
NCA_SIZE_SIZE = 0x8
NCA_TITLE_ID_OFFSET = 0x210
NCA_TITLE_ID_SIZE = 0x8
NCA_CONTENT_INDEX_OFFSET = 0x218
NCA_SDK_VERSION_OFFSET = 0x21C
NCA_SDK_VERSION_SIZE = 0x4
NCA_KEY_GENERATION_OFFSET = 0x220
NCA_CRYPTO_TYPE2_OFFSET = 0x221
NCA_RIGHTS_ID_OFFSET = 0x230
NCA_RIGHTS_ID_SIZE = 0x10
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
FS_HEADER_COMPRESSION_INFO_OFFSET = 0x178
FS_HEADER_META_DATA_HASH_DATA_INFO_OFFSET = 0x1A0
FS_HEADER_RESERVED = 0x1D0
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
BKTR_MAGIC = B'BKTR'
IVFC_MAGIC = b'IVFC'
PFS0_MAGIC = b'PFS0'
RIGHTS_ID_NULL = "00000000000000000000000000000000"
ZERO_HASH = bytearray(b"\x00" * 16)

def _section_content_extents(nca_object, i):
    """
    Resolve (start, end) byte range of the FS payload within a section.

    Prefers FsHeader content_start/end; falls back to HierarchicalSha256
    region_1 (PFS0) or IVFC last-level (RomFS).
    """
    fs = nca_object.fsheaders[i]
    start = fs.content_start
    end = fs.content_end
    if end > start:
        return start, end

    # HierarchicalSha256 (PFS0 / ExeFS)
    hd = getattr(fs, "hashData", None)
    if hd is not None and hasattr(hd, "region_1_offset"):
        r1_off = hd.region_1_offset
        r1_size = hd.region_1_size
        if r1_size > 0:
            return r1_off, r1_off + r1_size

    # IVFC (RomFS) — last level
    if hd is not None and hasattr(hd, "levels") and getattr(hd, "max_layers", 0):
        try:
            max_layer = hd.max_layers - 1
            lvl = hd.levels[max_layer]
            return lvl.logical_offset, lvl.logical_offset + lvl.hash_data_size
        except Exception:
            pass

    # Sparse/Indirect storage range as last resort (may be large)
    for attr in ("indirect_storages", "sparse_storages"):
        stores = getattr(nca_object, attr, None)
        if stores and stores[i] is not None:
            st = stores[i]
            return st.start_offset, st.end_offset

    return start, end


def save_section(nca_object, i, output_path=None):
    """
    Extract a decrypted section content region from an NCA file.

    Only the content payload (RomFS/PFS0 body) is read — not the full
    virtual sparse image.  Sparse/Indirect layers are read on demand for
    just [content_start, content_end), avoiding multi-GB allocations.

    Args:
        nca_object: NCA object
        i: Section index (0-3)
        output_path: (deprecated) Unused parameter kept for compatibility

    Returns:
        bytes: Decrypted section content (RomFS or PFS0 payload region)
    """
    start, end = _section_content_extents(nca_object, i)

    if hasattr(nca_object, "read_section"):
        if hasattr(nca_object, "_ensure_section_decrypted"):
            nca_object._ensure_section_decrypted(i)

        has_layer = (
            (getattr(nca_object, "indirect_storages", None)
             and nca_object.indirect_storages[i] is not None)
            or (getattr(nca_object, "sparse_storages", None)
                and nca_object.sparse_storages[i] is not None)
        )
        if has_layer:
            if end > start:
                return nca_object.read_section(i, start, end - start)
            raise ValueError(
                f"Section {i}: sparse/Indirect layer present but content "
                f"extents are empty (start=0x{start:X} end=0x{end:X})"
            )

    if hasattr(nca_object, "_ensure_section_decrypted"):
        nca_object._ensure_section_decrypted(i)

    decrypted_section = nca_object.decrypted_sections[i]
    if not decrypted_section:
        raise ValueError(
            f"Section {i}: no decrypted data available "
            f"(sparse={nca_object.fsheaders[i].IsSparse}, "
            f"layer="
            f"{bool(getattr(nca_object, 'sparse_storages', [None]*4)[i])})"
        )
    if end > len(decrypted_section):
        end = len(decrypted_section)
    if start >= end:
        return decrypted_section
    return decrypted_section[start:end]

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
        self.IsSparse = False
        self.has_patch_indirect = False
        self.has_patch_aes_ctr_ex = False
        self.patchInfo = self.fsheader[FS_HEADER_PATCH_INFO_OFFSET:FS_HEADER_PATCH_INFO_OFFSET + 0x40]
        # NcaPatchInfo (0x40): indirect_bucket (0x20) + aes_ctr_ex_bucket (0x20)
        self.indirectBucketOffset = int.from_bytes(self.patchInfo[0x0:0x8], 'little')
        self.indirectBucketSize = int.from_bytes(self.patchInfo[0x8:0x10], 'little')
        self.indirectBucketHeader = self.patchInfo[0x10:0x20]
        self.indirectBucketEntryCount = int.from_bytes(self.indirectBucketHeader[0x8:0xC], 'little')
        self.aesCtrExBucketOffset = int.from_bytes(self.patchInfo[0x20:0x28], 'little')
        self.aesCtrExBucketSize = int.from_bytes(self.patchInfo[0x28:0x30], 'little')
        self.aesCtrExBucketHeader = self.patchInfo[0x30:0x40]
        self.aesCtrExBucketEntryCount = int.from_bytes(self.aesCtrExBucketHeader[0x8:0xC], 'little')
        if self.indirectBucketSize > 0:
            self.has_patch_indirect = True
        if self.aesCtrExBucketSize > 0:
            self.has_patch_aes_ctr_ex = True
        self.generation = self.fsheader[FS_HEADER_GENERATION_OFFSET:FS_HEADER_GENERATION_OFFSET + 0x4]
        self.secureValue = self.fsheader[FS_HEADER_SECURE_VALUE_OFFSET:FS_HEADER_SECURE_VALUE_OFFSET + 0x4]
        self.sparseInfo = self.fsheader[FS_HEADER_SPARSE_INFO_OFFSET:FS_HEADER_SPARSE_INFO_OFFSET + 0x30]
        # NcaSparseInfo layout (0x30):
        #   [0x00] bucket.offset (u64)   — offset of the BKTR table within the sparse region
        #   [0x08] bucket.size   (u64)
        #   [0x10] bucket.header (BKTR magic/version/entry_count)
        #   [0x20] physical_offset (u64) — absolute NCA offset of the sparse physical region
        #   [0x28] generation (u16)      — non-zero means sparse layer is present
        #   [0x2A] reserved (6 bytes)
        self.sparseBucketOffset = int.from_bytes(self.sparseInfo[0x0:0x8], byteorder='little', signed=False)
        self.sparseTableSize = int.from_bytes(self.sparseInfo[0x8:0x10], byteorder='little', signed=False)
        self.sparseTableHeader = self.sparseInfo[0x10:0x20]
        self.sparseTableHeaderMagic = self.sparseTableHeader[0x0:0x4]
        if self.sparseTableHeaderMagic == BKTR_MAGIC:
            self.sparseTableHeaderMagic = "BKTR"
        self.sparseTableHeaderVersion = int.from_bytes(self.sparseTableHeader[0x4:0x8], byteorder='little', signed=False)
        self.sparseTableHeaderEntryCount = int.from_bytes(self.sparseTableHeader[0x8:0xC], byteorder='little', signed=False)
        self.sparseTableHeaderReserved = self.sparseTableHeader[0xC:0x10]
        self.sparsePhysicalOffset = int.from_bytes(self.sparseInfo[0x20:0x28], byteorder='little', signed=False)
        self.sparseGeneration = int.from_bytes(self.sparseInfo[0x28:0x2A], byteorder='little', signed=False)
        self.sparseReserved = self.sparseInfo[0x2A:0x30]
        # Match nxdumptool: has_sparse_layer = (sparse_info.generation != 0)
        if self.sparseGeneration != 0:
            self.IsSparse = True
        # Absolute NCA offset of the encrypted sparse BKTR table
        self.sparseTableOffset = self.sparsePhysicalOffset + self.sparseBucketOffset
        # Virtual section size reported by the sparse bucket (table lives at the end)
        self.sparseVirtualSize = self.sparseBucketOffset + self.sparseTableSize
        # Legacy alias kept for existing call-sites / print code
        self.sparseTabletOffset = self.sparseBucketOffset
        self.compressionInfo = self.fsheader[FS_HEADER_COMPRESSION_INFO_OFFSET:FS_HEADER_COMPRESSION_INFO_OFFSET + 0x28]
        self.metadatahashdataInfo = self.fsheader[FS_HEADER_META_DATA_HASH_DATA_INFO_OFFSET:FS_HEADER_META_DATA_HASH_DATA_INFO_OFFSET + 0x30]
        self.reserved = self.fsheader[FS_HEADER_RESERVED:FS_HEADER_RESERVED + 0x30]
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
            
            content_start = self.hashData.levels[self.max_layer].logical_offset
            content_size = self.hashData.levels[self.max_layer].hash_data_size
            
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
    def __init__(self, nca_data, isdev=False):
        """
        Args:
            nca_data: Complete NCA file data (at least first 0xC00 bytes)
        """
        isdev=isdev
        self.nca_data = nca_data
        self.sections = []
        
        # Decrypt the NCA header
        self.encrypted_header = nca_data[0x0:NCA_HEADER_SIZE]
        self.root_keys = RootKeys()
        key_sources = KeySources()
        self.tsec_keys = crypto.TsecKeygen(key_sources.tsec_secret_26)
        self.header_key = crypto.Keygen(self.tsec_keys, isdev).header_key
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
    def __init__(self, nca_data, master_kek_source=None, titlekey=None, isdev=False):
        """
        Args:
            nca_data: Complete NCA file data
            titlekey: Optional titlekey for titlekey-encrypted content
        """
        isdev=isdev
        self.nca_data = nca_data
        self.sections = []
        
        # Decrypt the NCA header
        self.encrypted_header = nca_data[0x0:NCA_HEADER_SIZE]
        self.root_keys = RootKeys()
        key_sources = KeySources()
        self.tsec_keys = crypto.TsecKeygen(key_sources.tsec_secret_26)
        self.header_key = crypto.Keygen(self.tsec_keys, isdev).header_key
        self.decrypted_nca_header = crypto.decrypt_xts(self.encrypted_header, self.header_key)
        
        # Parse the header
        self.header = NcaHeader(self.decrypted_nca_header)
        
        # Extract key properties
        self._extract_properties()
        
        # Parse filesystem headers first so sparse physical extents are known
        self.fsheaders = [
            FsHeader(self.decrypted_nca_header[0x400 + i * FS_HEADER_SIZE:0x400 + (i + 1) * FS_HEADER_SIZE])
            for i in range(4)
        ]

        # Extract raw section data.  For sparse sections the section-table
        # media range can be empty or not cover the sparse body; bind the
        # physical sparse region from sparsePhysicalOffset instead.
        self.sections = []
        for i in range(4):
            st = self.header.sectionTables[i]
            fs = self.fsheaders[i]
            if fs.IsSparse and fs.sparsePhysicalOffset > 0:
                # Physical sparse region starts at sparsePhysicalOffset.
                # Size from bucket (offset+size) or section-table span or
                # remainder of the NCA file.
                phys_size = fs.sparseBucketOffset + fs.sparseTableSize
                if phys_size == 0:
                    phys_size = max(0, st.endOffset - st.offset)
                if phys_size == 0:
                    # No size in header — take bytes from physical offset
                    # to EOF (or next non-empty section start).
                    next_starts = [
                        self.header.sectionTables[j].offset
                        for j in range(4)
                        if j != i
                        and self.header.sectionTables[j].offset > fs.sparsePhysicalOffset
                    ]
                    limit = min(next_starts) if next_starts else len(nca_data)
                    phys_size = max(0, limit - fs.sparsePhysicalOffset)
                start = fs.sparsePhysicalOffset
                end = min(len(nca_data), start + phys_size)
                if st.endOffset > st.offset and st.endOffset - st.offset > end - start:
                    start = st.offset
                    end = st.endOffset
                self.sections.append(nca_data[start:end])
                fs._sparse_section_base = start
            else:
                self.sections.append(nca_data[st.offset:st.endOffset])
                fs._sparse_section_base = st.offset

        # Setup key area
        self._setup_key_area()

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
    
    def _setup_key_area(self, isdev=False):
        """Setup key area and derive decryption keys."""
        isdev = isdev
        key_sources = KeySources()
        self.tsec_keys = crypto.TsecKeygen(key_sources.tsec_secret_26)
        self.keygen = crypto.Keygen(self.tsec_keys, isdev)
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
        """Decrypt sections based on encryption type, then initialise sparse layers."""
        self.IsSparse = False
        self.sparse_storages = [None, None, None, None]
        self.indirect_storages = [None, None, None, None]
        self.section_ctr_keys = [None, None, None, None]
        self._paired_base_nca = None

        if self.encryption_type == ENCRYPTION_TYPE_TITLEKEY:
            self._decrypt_sections_titlekey(titlekey)
        else:
            self._decrypt_sections_standard()

        # Build sparse layered storage for any section that carries a sparse BKTR.
        # Non-sparse sections keep their bulk-decrypted buffers unchanged.
        for i in range(4):
            if self.fsheaders[i].IsSparse:
                self.IsSparse = True
                self._init_sparse_storage(i)

    def _section_ctr_key(self, section_idx):
        """Return the AES-CTR key used for a given FS section."""
        if self.section_ctr_keys[section_idx] is not None:
            return self.section_ctr_keys[section_idx]
        if self.encryption_type == ENCRYPTION_TYPE_TITLEKEY:
            key = self.decrypted_titlekey
        else:
            key = self.DecryptedKeyArea[2]
        self.section_ctr_keys[section_idx] = key
        return key

    def _decrypt_sections_titlekey(self, titlekey):
        """Set up titlekey crypto. Section bodies are decrypted lazily."""
        self.encrypted_titlekey = titlekey
        self.decrypted_titlekey = crypto.decrypt_ecb(self.encrypted_titlekey, self.titlekek)
        # None = not yet decrypted; b"" = sparse placeholder; bytes = ready
        self.decrypted_sections = [None, None, None, None]
        for i in range(4):
            if self.fsheaders[i].IsSparse:
                self.decrypted_sections[i] = b""

    def _decrypt_sections_standard(self):
        """Set up key-area crypto. Section bodies are decrypted lazily."""
        self.DecryptedKeyArea = []
        for i in range(4):
            self.DecryptedKeyArea.append(
                crypto.decrypt_ecb(self.header.EncryptedKeyArea[i], self.key_area_key)
            )
        self.decrypted_sections = [None, None, None, None]
        for i in range(4):
            if self.fsheaders[i].IsSparse:
                self.decrypted_sections[i] = b""

    def _ensure_section_decrypted(self, section_idx):
        """
        Lazily bulk-decrypt a non-sparse section on first use.

        Sparse / Indirect sections are never bulk-decrypted; callers must
        use read_section() which goes through the layered storage.
        """
        if section_idx < 0 or section_idx > 3:
            raise ValueError(f"Invalid section index: {section_idx}")
        if self.fsheaders[section_idx].IsSparse:
            return
        if self.indirect_storages and self.indirect_storages[section_idx] is not None:
            return
        if self.decrypted_sections[section_idx] is not None:
            return

        key = self._section_ctr_key(section_idx)
        self.decrypted_sections[section_idx] = crypto.decrypt_ctr(
            self.sections[section_idx],
            key,
            self.fsheaders[section_idx].CryptoCounterCtr,
            self.header.sectionTables[section_idx].offset,
        )

    # ------------------------------------------------------------------
    # Sparse layered storage
    # ------------------------------------------------------------------

    def _decrypt_sparse_table(self, section_idx):
        """
        Read and decrypt the sparse BKTR table for a section.

        Matches nxdumptool:
          - table lives at sparsePhysicalOffset + sparseBucketOffset
          - CTR upper-IV generation field is (sparseGeneration << 16)
          - CTR starts at the absolute table offset
        """
        fs = self.fsheaders[section_idx]
        table_offset = fs.sparseTableOffset
        table_size = fs.sparseTableSize
        if table_size == 0 or table_offset + table_size > len(self.nca_data):
            raise ValueError(
                f"Sparse table out of bounds for section {section_idx}: "
                f"offset=0x{table_offset:X} size=0x{table_size:X}"
            )

        encrypted_table = self.nca_data[table_offset : table_offset + table_size]

        # Build sparse-specific upper IV: generation = sparseGeneration << 16
        # Normal CryptoCounterCtr is (zeros[8] || generation[4] || secureValue[4])[::-1]
        # which as big-endian CTR nonce is secureValue || generation.
        # For the sparse table we replace generation with (sparseGeneration << 16).
        sparse_gen = (fs.sparseGeneration & 0xFFFF) << 16
        sparse_gen_bytes = sparse_gen.to_bytes(4, "little")
        sparse_ctr = bytearray((b"\x00" * 8) + sparse_gen_bytes + fs.secureValue)[::-1]

        key = self._section_ctr_key(section_idx)
        return crypto.decrypt_ctr(encrypted_table, key, bytes(sparse_ctr), table_offset)

    def _sparse_physical_read(self, section_idx, phys_offset, size, virtual_offset):
        """
        Decrypt `size` bytes of physical section data at `phys_offset`,
        using the *virtual* offset for the AES-CTR IV (sparse requirement).

        phys_offset is relative to the sparse physical base (section start
        or sparsePhysicalOffset).  virtual_offset is the virtual offset
        within the sparse storage (used for CTR IV).
        """
        fs = self.fsheaders[section_idx]
        key = self._section_ctr_key(section_idx)

        # Absolute NCA offset of the physical base for this sparse section
        sparse_base = getattr(fs, "_sparse_section_base", None)
        if sparse_base is None:
            sparse_base = (
                fs.sparsePhysicalOffset
                if fs.sparsePhysicalOffset > 0
                else self.header.sectionTables[section_idx].offset
            )

        # Prefer reading from the bound section buffer; fall back to nca_data
        section_data = self.sections[section_idx]
        abs_phys = sparse_base + phys_offset

        # CTR base is the FS section media offset (nxdumptool section_offset)
        ctr_base = self.header.sectionTables[section_idx].offset
        if ctr_base == 0:
            ctr_base = sparse_base

        if phys_offset >= 0 and phys_offset + size <= len(section_data):
            enc = section_data[phys_offset : phys_offset + size]
        elif abs_phys + size <= len(self.nca_data):
            enc = self.nca_data[abs_phys : abs_phys + size]
        else:
            available = max(0, len(self.nca_data) - abs_phys)
            if available <= 0:
                return b"\x00" * size
            enc = self.nca_data[abs_phys : abs_phys + available]
            ctr_offset = ctr_base + virtual_offset
            dec = crypto.decrypt_ctr(enc, key, fs.CryptoCounterCtr, ctr_offset)
            return dec + (b"\x00" * (size - available))

        # CTR IV: section_offset + virtual_offset (sparse requirement)
        ctr_offset = ctr_base + virtual_offset
        return crypto.decrypt_ctr(enc, key, fs.CryptoCounterCtr, ctr_offset)

    def _init_sparse_storage(self, section_idx):
        """
        Initialise a SparseStorage for the given section.

        Does **not** materialise the virtual image (that can be multi-GB).
        FS-header entry_count/size can be wrong; we still try the on-disk
        BKTR table whenever generation != 0.
        """
        fs = self.fsheaders[section_idx]
        if not fs.IsSparse:
            return

        table_offset = fs.sparseTableOffset
        table_size = fs.sparseTableSize

        # Do not bail solely on header entry_count == 0; the on-disk table
        # is authoritative.  Only degrade when we have no table location.
        if table_size == 0 or table_offset == 0:
            self._init_sparse_degraded(section_idx)
            return

        try:
            decrypted_table = self._decrypt_sparse_table(section_idx)
        except Exception as e:
            raise ValueError(
                f"Section {section_idx}: failed to decrypt sparse BKTR table "
                f"at 0x{table_offset:X} size 0x{table_size:X}: {e}"
            ) from e

        if len(decrypted_table) < 0x4000:
            raise ValueError(
                f"Section {section_idx}: sparse BKTR table too short "
                f"({len(decrypted_table)} bytes) at 0x{table_offset:X}"
            )

        try:
            table = bktr.parse_sparse_table(decrypted_table)
        except Exception as e:
            raise ValueError(
                f"Section {section_idx}: failed to parse sparse BKTR table: {e}"
            ) from e

        if table.end_offset <= table.start_offset:
            raise ValueError(
                f"Section {section_idx}: sparse BKTR has empty virtual range "
                f"[0x{table.start_offset:X}, 0x{table.end_offset:X})"
            )

        def physical_read(phys_off, size, virt_off, _idx=section_idx):
            return self._sparse_physical_read(_idx, phys_off, size, virt_off)

        storage = bktr.SparseStorage(
            table=table,
            physical_read=physical_read,
            storage_type=bktr.StorageType.SPARSE,
        )
        self.sparse_storages[section_idx] = storage

        self._refresh_content_extents(section_idx)

    def _init_sparse_degraded(self, section_idx):
        """
        Sparse flag set but no usable BKTR table location. Bulk-decrypt
        whatever physical bytes exist so the section is not left empty.
        """
        fs = self.fsheaders[section_idx]
        if not self.sections[section_idx]:
            return
        key = self._section_ctr_key(section_idx)
        base = getattr(fs, "_sparse_section_base", None)
        if base is None:
            base = (
                fs.sparsePhysicalOffset
                if fs.sparsePhysicalOffset > 0
                else self.header.sectionTables[section_idx].offset
            )
        self.decrypted_sections[section_idx] = crypto.decrypt_ctr(
            self.sections[section_idx],
            key,
            fs.CryptoCounterCtr,
            base,
        )
        self._refresh_content_extents(section_idx)

    def _refresh_content_extents(self, section_idx):
        """Fill content_start/end from hash superblock when missing."""
        fs = self.fsheaders[section_idx]
        if fs.content_end > fs.content_start:
            fs.section_has_content = True
            return

        hd = getattr(fs, "hashData", None)
        if hd is not None and hasattr(hd, "region_1_offset") and hd.region_1_size > 0:
            fs.content_start = hd.region_1_offset
            fs.content_end = hd.region_1_offset + hd.region_1_size
            fs.section_has_content = True
            if not isinstance(fs.fsType, str):
                fs.fsType = "PFS0"
            fs.content_extension = ".pfs0"
            return

        if hd is not None and hasattr(hd, "levels") and getattr(hd, "max_layers", 0):
            try:
                max_layer = hd.max_layers - 1
                lvl = hd.levels[max_layer]
                fs.content_start = lvl.logical_offset
                fs.content_end = lvl.logical_offset + lvl.hash_data_size
                fs.section_has_content = True
                if not isinstance(fs.fsType, str):
                    fs.fsType = "RomFS"
                fs.content_extension = ".romfs"
            except Exception:
                pass

    def _decrypt_section_bucket_table(self, section_idx, bucket_offset, bucket_size):
        """
        Decrypt a BKTR table that lives inside a section at a section-relative
        offset (Indirect / AesCtrEx buckets from PatchInfo).
        Uses normal section CTR (not the sparse-table special IV).
        """
        if bucket_size == 0:
            raise ValueError("Empty bucket")
        section_nca_offset = self.header.sectionTables[section_idx].offset
        fs = self.fsheaders[section_idx]
        key = self._section_ctr_key(section_idx)
        section_data = self.sections[section_idx]
        if bucket_offset + bucket_size > len(section_data):
            raise ValueError(
                f"Bucket [0x{bucket_offset:X}, +0x{bucket_size:X}) exceeds "
                f"section {section_idx} size 0x{len(section_data):X}"
            )
        enc = section_data[bucket_offset : bucket_offset + bucket_size]
        return crypto.decrypt_ctr(
            enc, key, fs.CryptoCounterCtr, section_nca_offset + bucket_offset
        )

    def _regular_physical_read(self, section_idx, phys_offset, size, virtual_offset):
        """
        Decrypt size bytes at a section-relative physical offset using the
        physical (section_nca_offset + phys_offset) CTR IV — used for
        AesCtrEx / regular patch data, not sparse.
        """
        section_nca_offset = self.header.sectionTables[section_idx].offset
        fs = self.fsheaders[section_idx]
        key = self._section_ctr_key(section_idx)
        section_data = self.sections[section_idx]
        if phys_offset + size > len(section_data):
            available = max(0, len(section_data) - phys_offset)
            if available <= 0:
                return b"\x00" * size
            enc = section_data[phys_offset : phys_offset + available]
            dec = crypto.decrypt_ctr(
                enc, key, fs.CryptoCounterCtr, section_nca_offset + phys_offset
            )
            return dec + (b"\x00" * (size - available))
        enc = section_data[phys_offset : phys_offset + size]
        return crypto.decrypt_ctr(
            enc, key, fs.CryptoCounterCtr, section_nca_offset + phys_offset
        )

    def _aes_ctr_ex_physical_read(self, section_idx, phys_offset, size, virtual_offset, aes_table):
        """
        Decrypt patch data using AesCtrEx generation-based CTR.

        Handles non-16-byte-aligned starts (critical — mid-block reads must
        decrypt the full AES block and discard the prefix).
        """
        section_nca_offset = self.header.sectionTables[section_idx].offset
        fs = self.fsheaders[section_idx]
        key = self._section_ctr_key(section_idx)
        section_data = self.sections[section_idx]

        out = bytearray()
        remaining = size
        cur_phys = phys_offset

        while remaining > 0:
            try:
                entry, next_off = bktr.find_aes_ctr_ex_entry(aes_table, cur_phys)
            except Exception:
                # Fall back to regular CTR
                chunk = self._regular_physical_read(
                    section_idx, cur_phys, remaining, virtual_offset + (cur_phys - phys_offset)
                )
                out.extend(chunk)
                break

            span = max(1, next_off - cur_phys)
            want = min(remaining, span)

            # Align to AES block for correct CTR stream position
            block_ofs = cur_phys & 0xF
            aligned_phys = cur_phys - block_ofs
            # Read enough encrypted bytes to cover prefix + want
            enc_need = block_ofs + want
            # Round up to full blocks for clean CTR
            enc_need_aligned = (enc_need + 0xF) & ~0xF

            if aligned_phys >= len(section_data):
                out.extend(b"\x00" * remaining)
                break

            enc_end = min(len(section_data), aligned_phys + enc_need_aligned)
            enc = section_data[aligned_phys:enc_end]
            if not enc:
                out.extend(b"\x00" * remaining)
                break

            abs_off = section_nca_offset + aligned_phys
            if entry.encryption == 0:  # Enabled
                ctr = bktr.make_aes_ctr_ex_ctr(
                    fs.CryptoCounterCtr, entry.generation, abs_off
                )
                dec = crypto.decrypt_ctr(enc, key, ctr, None)
            else:
                dec = bytes(enc)

            # Discard alignment prefix; take the bytes we need
            piece = dec[block_ofs : block_ofs + want]
            if len(piece) < want:
                # Truncated at section end — pad
                piece = piece + b"\x00" * (want - len(piece))
            out.extend(piece[:want])
            got = want
            cur_phys += got
            remaining -= got

        return bytes(out)

    def _init_indirect_storage(self, section_idx, base_nca=None):
        """
        Initialise an Indirect storage for a Patch section, optionally
        wiring a base NCA's corresponding section (Sparse or Regular) as
        ORIGINAL substorage.

        Mirrors nxdumptool ncaStorageInitializeContext for Patch RomFS.
        """
        fs = self.fsheaders[section_idx]
        if not fs.has_patch_indirect:
            return None

        if fs.indirectBucketSize == 0 or fs.indirectBucketEntryCount == 0:
            return None

        decrypted_table = self._decrypt_section_bucket_table(
            section_idx, fs.indirectBucketOffset, fs.indirectBucketSize
        )
        table = bktr.parse_sparse_table(decrypted_table)

        # AesCtrEx table for PATCH substorage (generation-based CTR)
        aes_ctr_ex_table = None
        if fs.has_patch_aes_ctr_ex and fs.aesCtrExBucketSize > 0:
            try:
                aes_raw = self._decrypt_section_bucket_table(
                    section_idx, fs.aesCtrExBucketOffset, fs.aesCtrExBucketSize
                )
                aes_ctr_ex_table = bktr.parse_aes_ctr_ex_table(aes_raw)
            except Exception as e:
                print(f"[WARN] AesCtrEx table parse failed for section {section_idx}: {e}")

        def patch_physical_read(phys_off, size, virt_off, _idx=section_idx, _aes=aes_ctr_ex_table):
            if _aes is not None:
                return self._aes_ctr_ex_physical_read(_idx, phys_off, size, virt_off, _aes)
            return self._regular_physical_read(_idx, phys_off, size, virt_off)

        base_read = None
        if base_nca is not None:
            base_fs = base_nca.fsheaders[section_idx] if section_idx < 4 else None
            base_sparse = (
                base_nca.sparse_storages[section_idx]
                if getattr(base_nca, "sparse_storages", None)
                else None
            )

            if base_sparse is not None:
                # Base section is sparse: ORIGINAL physical_offset is an
                # offset into the base sparse virtual address space.
                def base_read(phys_off, size, virt_off, _bs=base_sparse):
                    try:
                        return _bs.read(phys_off, size)
                    except (ValueError, Exception):
                        return _bs.read(virt_off, size)
            elif base_fs is not None and not base_fs.IsSparse:
                def base_read(phys_off, size, virt_off, _bn=base_nca, _idx=section_idx):
                    return _bn._regular_physical_read(_idx, phys_off, size, virt_off)

        storage = bktr.SparseStorage(
            table=table,
            physical_read=patch_physical_read,
            storage_type=bktr.StorageType.INDIRECT,
            base_read=base_read,
        )
        self.indirect_storages[section_idx] = storage
        return storage

    def pair_with_base(self, base_nca, section_indices=None):
        """
        Pair this (update/patch) NCA with a base NCA.

        Builds Indirect layered storage for patch sections (no full-image
        materialisation).  Optional section_indices limits work to e.g. [0]
        when only ExeFS is needed.

        Args:
            base_nca: Nca instance for the base application of the same title
            section_indices: iterable of section indices to pair (default: all 4)
        """
        self._paired_base_nca = base_nca
        indices = list(section_indices) if section_indices is not None else [0, 1, 2, 3]

        for i in indices:
            if i < 0 or i > 3:
                continue
            fs = self.fsheaders[i]
            base_fs = base_nca.fsheaders[i]
            base_sparse = (
                base_nca.sparse_storages[i]
                if getattr(base_nca, "sparse_storages", None)
                else None
            )

            if fs.has_patch_indirect:
                storage = self._init_indirect_storage(i, base_nca=base_nca)
                if storage is not None:
                    if not fs.section_has_content and base_fs.section_has_content:
                        fs.content_start = base_fs.content_start
                        fs.content_end = base_fs.content_end
                        fs.section_has_content = True
                        fs.fsType = base_fs.fsType
                        fs.content_extension = base_fs.content_extension
                    continue

            if base_sparse is not None:
                if not (fs.section_has_content and self.decrypted_sections[i]):
                    # Point this section's sparse slot at the base layer so
                    # read_section on the update side can serve base data.
                    self.sparse_storages[i] = base_sparse
                    if not fs.section_has_content and base_fs.section_has_content:
                        fs.content_start = base_fs.content_start
                        fs.content_end = base_fs.content_end
                        fs.section_has_content = True
                        fs.fsType = base_fs.fsType
                        fs.content_extension = base_fs.content_extension

    def apply_update_pairing(self, update_nca, section_indices=None):
        """
        Pair an update onto this base NCA (storage layers only — no
        multi-GB materialisation).

        Args:
            update_nca: Nca instance for a matching update/patch
            section_indices: optional subset of sections (default all)
        """
        indices = list(section_indices) if section_indices is not None else [0, 1, 2, 3]
        update_nca.pair_with_base(self, section_indices=indices)
        for i in indices:
            if i < 0 or i > 3:
                continue
            if update_nca.indirect_storages[i] is not None:
                self.indirect_storages[i] = update_nca.indirect_storages[i]
                if update_nca.fsheaders[i].section_has_content:
                    self.fsheaders[i].content_start = update_nca.fsheaders[i].content_start
                    self.fsheaders[i].content_end = update_nca.fsheaders[i].content_end
                    self.fsheaders[i].section_has_content = True
                    self.fsheaders[i].fsType = update_nca.fsheaders[i].fsType
                    self.fsheaders[i].content_extension = update_nca.fsheaders[i].content_extension

    def read_section(self, section_idx, offset, size):
        """
        Read from a section's virtual address space.

        Priority: Indirect (paired) > Sparse > bulk-decrypted buffer (lazy).
        """
        if section_idx < 0 or section_idx > 3:
            raise ValueError(f"Invalid section index: {section_idx}")

        indirect = self.indirect_storages[section_idx] if self.indirect_storages else None
        if indirect is not None:
            return indirect.read(offset, size)

        storage = self.sparse_storages[section_idx] if self.sparse_storages else None
        if storage is not None:
            return storage.read(offset, size)

        self._ensure_section_decrypted(section_idx)
        data = self.decrypted_sections[section_idx]
        if not data:
            return b""
        return data[offset : offset + size]

    def get_decrypted_section_bytes(self, section_idx):
        """
        Get decrypted section data.

        For sparse/Indirect sections this materialises only via the layer
        for the full virtual range — prefer save_section() / read_section()
        to avoid large allocations.
        """
        if section_idx < 0 or section_idx > 3:
            raise ValueError(f"Invalid section index: {section_idx}")

        indirect = self.indirect_storages[section_idx] if self.indirect_storages else None
        if indirect is not None:
            return indirect.read_all()

        storage = self.sparse_storages[section_idx] if self.sparse_storages else None
        if storage is not None:
            return storage.read_all()

        self._ensure_section_decrypted(section_idx)
        return self.decrypted_sections[section_idx] or b""

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
        lines.append(f'Magic:                                    {self.ncaheader.magic}')
        lines.append(f'Fixed-Key Index:                          {hex(self.ncaheader.keyIndex)}')
        
        # Handle signature formatting
        sig1 = self.ncaheader.signature1 if isinstance(self.ncaheader.signature1, str) else self.ncaheader.signature1.hex().upper()
        sig2 = self.ncaheader.signature2 if isinstance(self.ncaheader.signature2, str) else self.ncaheader.signature2.hex().upper()
        
        util.print_split_hex('Fixed-Key Signature:', sig1, lines)
        util.print_split_hex('NPDM Signature:', sig2, lines)
        
        lines.append(f'Content Size:                             0x{self.ncaheader.size:012x}')
        lines.append(f'Title ID:                                 {self.ncaheader.titleId}')
        lines.append(f'SDK Version:                              {self.ncaheader.sdkVersion}')
        lines.append(f'Distribution type:                        {self.ncaheader.distribution_type}')
        lines.append(f'Content Type:                             {self.ncaheader.contentType}')
        lines.append(f'Master Key Revision:                      {hex(self.nca.master_key_revision)}')
        lines.append(f'Encryption Type:                          {self.nca.encryption_type}')
    
    def _build_key_area_info(self, lines):
        """Build key area information."""
        if self.nca.rightsid != RIGHTS_ID_NULL:
            lines.append(f'Rights ID:                                {self.nca.rightsid}')
            lines.append(f'Titlekey (Encrypted):                     {self.nca.encrypted_titlekey.hex().upper()}')
            lines.append(f'Titlekey (Decrypted):                     {self.nca.decrypted_titlekey.hex().upper()}')
        else:
            self._build_standard_key_info(lines)
    
    def _build_standard_key_info(self, lines):
        """Build standard (fixed key) encryption key information."""
        key_type_name = self.nca.key_area_key_type.lower()
        lines.append(f'Key Area Encryption Key Type:             key_area_key_{key_type_name}_{self.nca.master_key_revision:02X}')
        lines.append(f'Key Area Encryption Key:                  {self.nca.key_area_key.hex().upper()}')
        
        lines.append('Key Area (Encrypted):')
        for i in range(4):
            lines.append(f'    Key {i} (Encrypted):                    {self.ncaheader.EncryptedKeyArea[i].hex().upper()}')
        
        lines.append('Key Area (Decrypted):')
        for i in range(4):
            lines.append(f'    Key {i} (Decrypted):                    {self.nca.DecryptedKeyArea[i].hex().upper()}')
    
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
        
        if fsheader.IsSparse == True:
            section_lines.append(f'    Section {section_idx} - Sparse section detected')
            section_lines.append(f'        SparseInfo:')
            section_lines.append(f'            sparseTabletOffset:           0x{fsheader.sparseTabletOffset:012x}')
            section_lines.append(f'            sparseTableSize:              0x{fsheader.sparseTableSize:012x}')
            section_lines.append(f'            sparseTableHeaderMagic:       0x{fsheader.sparseTableHeaderMagic}')
            section_lines.append(f'            sparseTableHeaderVersion:     0x{fsheader.sparseTableHeaderVersion:012x}')
            section_lines.append(f'            sparseTableHeaderEntryCount:  0x{fsheader.sparseTableHeaderEntryCount:012x}')
            section_lines.append(f'            sparsePhysicalOffset:         0x{fsheader.sparsePhysicalOffset:012x}')
            section_lines.append(f'            sparseGeneration:             0x{fsheader.sparseGeneration:012x}')
        else:
            section_lines.append(f'    Section {section_idx}')
        section_lines.append(f'        Offset:                           0x{section_table.offset:012x}')
        section_lines.append(f'        Size:                             0x{section_size:012x}')
        section_lines.append(f'        Partition Type:                   {fsheader.fsType}')
        section_lines.append(f'        Section CTR:                      {ctr1}{ctr2}')
        section_lines.append(f'        Superblock Hash:                  {fsheader.hashData.master_hash.hex().upper()}')
        
        if fsheader.fsType == "RomFS":
            self._build_romfs_info(section_idx, fsheader, section_lines)
        elif fsheader.fsType == "PFS0":
            self._build_pfs0_info(section_idx, fsheader, section_lines, npdm_lines, kac_lines, sac_lines, fac_lines)
    
    def _build_romfs_info(self, section_idx, fsheader, section_lines):
        """Build RomFS-specific section information."""
        section_lines.append(f'        Magic:                            {fsheader.magic}')
        section_lines.append(f'        ID:                               {fsheader.id:08x}')
        
        level_count = fsheader.hashData.max_layer_count
        for level_idx in range(level_count):
            ivfc_level = fsheader.ivfc_levels[level_idx + 1]
            ivfc_level_prev = fsheader.ivfc_levels[level_idx]
            hash_block_size = fsheader.ivfc_levels[1].block_size
            
            section_lines.append(f'        Level {level_idx}:')
            section_lines.append(f'            Data Offset:                  0x{ivfc_level.logical_offset:012x}')
            section_lines.append(f'            Data Size:                    0x{ivfc_level.hash_data_size:012x}')
            
            if level_idx != 0:
                section_lines.append(f'            Hash Offset:                  0x{ivfc_level_prev.logical_offset:012x}')
            section_lines.append(f'            Hash Block Size:              0x{hash_block_size:08x}')
    
    def _build_pfs0_info(self, section_idx, fsheader, section_lines, npdm_lines, kac_lines, sac_lines, fac_lines):
        """Build PFS0-specific section information."""
        section_lines.append('        Hash Table:')
        section_lines.append(f'            Offset:                       {fsheader.hashData.region_0_offset:012X}')
        section_lines.append(f'            Size:                         {fsheader.hashData.region_0_size:012X}')
        section_lines.append(f'            Block Size:                   0x{fsheader.hashData.block_size:X}')
        section_lines.append(f'        PFS0 Offset:                      {fsheader.hashData.region_1_offset:012X}')
        section_lines.append(f'        PFS0 Size:                        {fsheader.hashData.region_1_size:012X}')
        
        # Extract and parse NPDM
        npdm_data = self._extract_npdm(section_idx)
        if npdm_data:
            npdm.NpdmInfoPrint(npdm_data, npdm_lines, kac_lines, sac_lines, fac_lines)

    def _extract_npdm(self, section_idx):
        """Extract NPDM data from a PFS0 section.

        Uses save_section() so lazy-decrypt and sparse/Indirect layers work
        the same as the rest of the pipeline (decrypted_sections may be None).
        """
        try:
            pfs0_data = save_section(self.nca, section_idx)
        except Exception:
            return None
        if not pfs0_data:
            return None

        match = re.search(self.NPDM_PATTERN, pfs0_data)
        if not match:
            return None

        start_of_npdm = match.start()

        # Read ACI offset and size from NPDM header
        aci_offset_pos = start_of_npdm + self.NPDM_ACI_OFFSET_OFFSET
        aci_offset = int.from_bytes(
            pfs0_data[aci_offset_pos:aci_offset_pos + self.NPDM_ACI_OFFSET_SIZE],
            byteorder='little', signed=False,
        )

        aci_size_pos = start_of_npdm + self.NPDM_ACI_SIZE_OFFSET
        aci_size = int.from_bytes(
            pfs0_data[aci_size_pos:aci_size_pos + self.NPDM_ACI_SIZE_SIZE],
            byteorder='little', signed=False,
        )

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
    def extract_section_romfs(
        nca,
        output_dir,
        section_idx=None,
        chunk_size=4 * 1024 * 1024,
        stream_threshold=32 * 1024 * 1024,
        verbose=False,
    ):
        """
        Extract a RomFS section to a directory (content region only).

        For sparse/Indirect or large sections, walks the RomFS tree using
        on-demand layered reads — never builds a multi-GiB intermediate image.
        Metadata tables are loaded once; each file is streamed in chunks.

        Args:
            nca: Nca object (may be base+update paired)
            output_dir: Directory to extract to
            section_idx: Optional explicit section index (else auto-detect)
            chunk_size: Per-file stream chunk size
            stream_threshold: Max size for the simple in-memory path

        Returns:
            bool: True if successful
        """
        if section_idx is None:
            section_idx = SectionExtractor._find_romfs_section(nca)
        if section_idx == -1:
            print("The input NCA has no RomFS")
            return False

        try:
            start, end = _section_content_extents(nca, section_idx)
            size = end - start
            if size <= 0:
                print(
                    f"Error extracting RomFS section {section_idx}: "
                    f"empty extents start=0x{start:X} end=0x{end:X}"
                )
                return False

            has_layer = (
                (getattr(nca, "indirect_storages", None)
                 and nca.indirect_storages[section_idx] is not None)
                or (getattr(nca, "sparse_storages", None)
                    and nca.sparse_storages[section_idx] is not None)
            )

            # Small, non-layered only
            if not has_layer and size <= stream_threshold:
                content_data = save_section(nca, section_idx)
                if not content_data or len(content_data) < 0x50:
                    print(
                        f"Error extracting RomFS section {section_idx}: "
                        f"empty content "
                        f"({len(content_data) if content_data else 0} bytes)"
                    )
                    return False
                romfs.romfs_process(
                    content_data,
                    output_path=Path(output_dir),
                    list_only=False,
                    print_info=False,
                )
                return True

            # On-demand layered extract (no full-image materialisation)
            return SectionExtractor._extract_romfs_layered(
                nca, section_idx, start, size, Path(output_dir), chunk_size,
                verbose=verbose,
            )
        except Exception as e:
            print(f"Error extracting RomFS section {section_idx}: {e}")
            import traceback
            traceback.print_exc()
            return False

    @staticmethod
    def _extract_romfs_layered(nca, section_idx, content_base, content_size,
                               output_dir, chunk_size, verbose=False):
        """
        Walk RomFS via layered reads: load metadata tables only, stream
        each file's payload from the layer into the output tree.
        """
        ROMFS_ENTRY_EMPTY = 0xFFFFFFFF
        ROMFS_HEADER_SIZE = 0x50

        def _vprint(*args, **kwargs):
            if verbose:
                _vprint(*args, **kwargs)

        def layer_read(rel_off, n):
            """Read n bytes at offset relative to RomFS content start."""
            if n <= 0:
                return b""
            abs_off = content_base + rel_off
            return nca.read_section(section_idx, abs_off, n)

        _vprint(
            f"[ROMFS] On-demand layered extract "
            f"(content 0x{content_size:X} / {content_size / (1024 ** 3):.2f} GiB) "
            f"→ {output_dir}"
        )

        hdr_raw = layer_read(0, ROMFS_HEADER_SIZE)
        if len(hdr_raw) < ROMFS_HEADER_SIZE:
            _vprint(f"[ROMFS] Failed to read header ({len(hdr_raw)} bytes)")
            return False

        header = romfs.RomfsHeader(hdr_raw)
        _vprint(
            f"[ROMFS] data_offset=0x{header.data_offset:X} "
            f"dir_meta=0x{header.dir_meta_table_offset:X}+0x{header.dir_meta_table_size:X} "
            f"file_meta=0x{header.file_meta_table_offset:X}+0x{header.file_meta_table_size:X}"
        )
        _vprint(f"[ROMFS] header bytes: {hdr_raw[:0x50].hex()}")

        def _sane(off, sz, label):
            if sz == 0:
                return True
            if off >= content_size or off + sz > content_size:
                _vprint(f"[ROMFS] Bad {label}: off=0x{off:X} size=0x{sz:X} content=0x{content_size:X}")
                return False
            return True

        if not (
            _sane(header.dir_meta_table_offset, header.dir_meta_table_size, "dir_meta")
            and _sane(header.file_meta_table_offset, header.file_meta_table_size, "file_meta")
            and header.data_offset < content_size
            and header.header_size <= 0x1000
        ):
            _vprint("[ROMFS] Header looks invalid — likely wrong decryption (AesCtrEx?)")
            return False

        max_meta = 512 * 1024 * 1024
        if header.dir_meta_table_size > max_meta or header.file_meta_table_size > max_meta:
            _vprint(
                f"[ROMFS] Metadata tables too large "
                f"(dir=0x{header.dir_meta_table_size:X} "
                f"file=0x{header.file_meta_table_size:X})"
            )
            return False

        dir_meta = layer_read(header.dir_meta_table_offset, header.dir_meta_table_size)
        file_meta = layer_read(header.file_meta_table_offset, header.file_meta_table_size)
        if len(dir_meta) < header.dir_meta_table_size or len(file_meta) < header.file_meta_table_size:
            _vprint(
                f"[ROMFS] Incomplete metadata "
                f"(dir {len(dir_meta)}/{header.dir_meta_table_size}, "
                f"file {len(file_meta)}/{header.file_meta_table_size})"
            )
            return False

        # Diagnose Indirect mapping at header and meta offsets
        try:
            storage = None
            if getattr(nca, "indirect_storages", None) and nca.indirect_storages[section_idx]:
                storage = nca.indirect_storages[section_idx]
            elif getattr(nca, "sparse_storages", None) and nca.sparse_storages[section_idx]:
                storage = nca.sparse_storages[section_idx]
            if storage is not None and hasattr(storage, "table"):
                for label, rel in (("hdr", 0), ("dir_meta", header.dir_meta_table_offset), ("file_meta", header.file_meta_table_offset)):
                    abs_v = content_base + rel
                    try:
                        ent, nxt = storage.table.find_entry(abs_v)
                        _vprint(
                            f"[ROMFS] layer {label} @ sec+0x{abs_v:X}: "
                            f"virt=0x{ent.virt_offset:X} phys=0x{ent.phys_offset:X} "
                            f"idx={ent.storage_index} next=0x{nxt:X}"
                        )
                    except Exception as e:
                        _vprint(f"[ROMFS] layer {label} @ sec+0x{abs_v:X}: {e}")
        except Exception as e:
            _vprint(f"[ROMFS] layer diag: {e}")

        _vprint(f"[ROMFS] dir_meta[0:0x40]={dir_meta[:0x40].hex()}")
        _vprint(f"[ROMFS] file_meta[0:0x40]={file_meta[:0x40].hex()}")

        # Parse root directory entry for diagnostics
        if len(dir_meta) >= 0x18:
            root = romfs.RomfsDirEntry(dir_meta, 0)
            _vprint(
                f"[ROMFS] root: parent=0x{root.parent:X} sibling=0x{root.sibling:X} "
                f"child=0x{root.child:X} file=0x{root.file:X} "
                f"name_size={root.name_size} name={root.name!r}"
            )

        util.mkdirp(output_dir)
        file_count = [0]
        byte_count = [0]
        last_report = [0]
        visited_dirs = set()
        visited_files = set()

        def visit_file(file_offset, dir_path):
            guard = 0
            while file_offset != ROMFS_ENTRY_EMPTY:
                if file_offset in visited_files:
                    break
                visited_files.add(file_offset)
                guard += 1
                if guard > 100000:
                    _vprint("[ROMFS] file walk guard limit hit")
                    break
                if file_offset + 0x20 > len(file_meta):
                    _vprint(f"[ROMFS] file offset 0x{file_offset:X} past file_meta")
                    break
                entry = romfs.RomfsFileEntry(file_meta, file_offset)
                # Clamp absurd name sizes
                if entry.name_size > 0x1000:
                    _vprint(f"[ROMFS] absurd file name_size={entry.name_size} at 0x{file_offset:X}")
                    break
                rel = dir_path / entry.name if entry.name else dir_path / f"file_{file_offset:X}"
                out_path = output_dir / rel
                out_path.parent.mkdir(parents=True, exist_ok=True)

                data_rel = header.data_offset + entry.offset
                remaining = entry.size
                # Guard against sizes that exceed the content image
                if entry.size > content_size or data_rel + entry.size > content_size + 0x1000:
                    _vprint(
                        f"[ROMFS] skip suspicious file {rel} "
                        f"size=0x{entry.size:X} data_rel=0x{data_rel:X}"
                    )
                    file_offset = entry.sibling
                    continue

                pos = 0
                with open(out_path, "wb") as out_f:
                    while remaining > 0:
                        n = min(chunk_size, remaining)
                        chunk = layer_read(data_rel + pos, n)
                        if not chunk:
                            break
                        out_f.write(chunk)
                        got = len(chunk)
                        pos += got
                        remaining -= got
                        byte_count[0] += got

                file_count[0] += 1
                if file_count[0] <= 5:
                    _vprint(
                        f"[ROMFS] file {rel} size=0x{entry.size:X} "
                        f"wrote=0x{entry.size - remaining:X}"
                    )
                if byte_count[0] - last_report[0] >= 256 * 1024 * 1024:
                    _vprint(
                        f"[ROMFS] extracted {file_count[0]} files, "
                        f"{byte_count[0] / (1024 ** 3):.2f} GiB"
                    )
                    last_report[0] = byte_count[0]

                file_offset = entry.sibling

        def visit_dir(dir_offset, parent_path):
            if dir_offset == ROMFS_ENTRY_EMPTY:
                return
            if dir_offset in visited_dirs:
                return
            visited_dirs.add(dir_offset)
            if dir_offset + 0x18 > len(dir_meta):
                _vprint(f"[ROMFS] dir offset 0x{dir_offset:X} past dir_meta")
                return
            entry = romfs.RomfsDirEntry(dir_meta, dir_offset)
            if entry.name_size > 0x1000:
                _vprint(f"[ROMFS] absurd dir name_size={entry.name_size} at 0x{dir_offset:X}")
                return
            rel = parent_path / entry.name if entry.name else parent_path
            full = output_dir / rel
            full.mkdir(parents=True, exist_ok=True)

            if entry.file != ROMFS_ENTRY_EMPTY:
                visit_file(entry.file, rel)
            if entry.child != ROMFS_ENTRY_EMPTY:
                visit_dir(entry.child, rel)
            if entry.sibling != ROMFS_ENTRY_EMPTY:
                visit_dir(entry.sibling, parent_path)

        visit_dir(0, Path(""))
        _vprint(
            f"[ROMFS] Done: {file_count[0]} files, "
            f"{byte_count[0] / (1024 ** 3):.2f} GiB written → {output_dir} "
            f"(dirs visited={len(visited_dirs)})"
        )
        return file_count[0] > 0

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
    def extract_section_pfs0_main_only(nca, main_output_location):
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
            pfs0.extract_pfs0_main(content_data, output_file=main_output_location)
            return True
        except Exception as e:
            print(f"Error extracting PFS0 section {section_idx}: {e}")
            return False
        
    @staticmethod
    def extract_section_pfs0_sdk_object_only(nca):
        """
        Extract a sdk file object from a PFS0 section
        
        Automatically finds the PFS0 section in the NCA.
        """
        section_idx = SectionExtractor._find_pfs0_section(nca)
        if section_idx == -1:
            print("The input NCA has no PFS0 with content")
            return False
        
        try:
            full_data = nca.get_decrypted_section_bytes(section_idx)
            fs_header = nca.fsheaders[section_idx]
            content_data = full_data[fs_header.content_start:fs_header.content_end]  # Slice to pure PFS0
            decompressed_sdk = pfs0.extract_pfs0_sdk_object(content_data)
            return decompressed_sdk
        except Exception as e:
            print(f"Error extracting PFS0 section {section_idx}: {e}")
            return False


    @staticmethod
    def extract_section_romfs_browser_only(nca):
        """
        Extract a specific browser file from a RomFS section.
        
        Automatically finds the RomFS section in the NCA and extracts the requested browser file.
        
        Args:
            nca: Nca object
        
        Returns:
            bytes: Browser file data, or None if not found or on error
        """

        browser_paths = {
            0: ["nro/netfront/core_3/Default/cfi_nncfi/webkit_wkc.nro.lz4", "nro/netfront/core_3/default/cfi_enabled/webkit_wkc.nro.lz4"]
        }

        if 0 not in browser_paths:
            print(f"Invalid browser type: 0 (only 0 is supported)")
            return None
        
        target_paths = browser_paths[0]
        section_idx = SectionExtractor._find_romfs_section(nca)
        if section_idx == -1:
            print("The input NCA has no RomFS")
            return None
        
        try:
            full_data = nca.get_decrypted_section_bytes(section_idx)
            fs_header = nca.fsheaders[section_idx]
            romfs_data = full_data[fs_header.content_start:fs_header.content_end]  # Slice to pure RomFS
            
            # Try each path format until one succeeds
            browser_data = None
            decompressed_browser_object = None

            # show full RomFS structure for debugging
            #romfs.romfs_process(romfs_data, None, True, True)

            for path in target_paths:
                try:
                    # Try the full path first, then fall back to the basename if not found
                    browser_data = romfs.extract_file_from_romfs(romfs_data, path)
                    if browser_data is None:
                        browser_data = romfs.extract_file_from_romfs(romfs_data, Path(path).name)

                    if browser_data is not None:
                        decompressed_browser_data = util.decompress_foss_nro_object(browser_data)
                        return decompressed_browser_data
                except:
                    continue
            
            print(f"Could not find browser file at any of these paths: {', '.join(target_paths)}")
            return None
        except Exception as e:
            print(f"Error extracting browser file from RomFS section {section_idx}: {e}")
            return None

    @staticmethod
    def extract_section_romfs_packages_only(nca, package_type):
        """
        Extract a specific package file from a RomFS section.
        
        Automatically finds the RomFS section in the NCA and extracts the requested package file.
        
        Args:
            nca: Nca object
            package_type: Package to extract (0=erista package1, 1=mariko package1, 2=package2)
        
        Returns:
            bytes: Package file data, or None if not found or on error
        """
        # Map package type to RomFS paths (try multiple formats)
        package_paths = {
            0: ["/nx/package1"],
            1: ["/a/package1"],
            2: ["/nx/package2"]
        }
        
        if package_type not in package_paths:
            print(f"Invalid package type: {package_type} (must be 0, 1, or 2)")
            return None
        
        target_paths = package_paths[package_type]
        
        section_idx = SectionExtractor._find_romfs_section(nca)
        if section_idx == -1:
            print("The input NCA has no RomFS")
            return None
        
        try:
            full_data = nca.get_decrypted_section_bytes(section_idx)
            fs_header = nca.fsheaders[section_idx]
            romfs_data = full_data[fs_header.content_start:fs_header.content_end]  # Slice to pure RomFS
            
            # Try each path format until one succeeds
            package_data = None
            for path in target_paths:
                try:
                    package_data = romfs.extract_file_from_romfs(romfs_data, path)
                    if package_data is not None:
                        #print(f"Found package at path: {path}")
                        return package_data
                except:
                    continue
            
            print(f"Could not find package {package_type} at any of these paths: {', '.join(target_paths)}")
            return None
        except Exception as e:
            print(f"Error extracting package {package_type} from RomFS section {section_idx}: {e}")
            return None

    @staticmethod
    def extract_section_romfs_system_update_calibration_only(nca, cal_type):
        """
        Extract a specific system update calibration file from a RomFS section.
        
        Automatically finds the RomFS section in the NCA and extracts the requested calibration file.
        
        Args:
            nca: Nca object
            cal_type: Calibration type to extract (0=file, 1=digest)

        Returns:
            bytes: System calibration file data, or None if not found or on error
        """

        # Map package type to RomFS paths (try multiple formats)
        cal_paths = {
            0: ["file"],
            1: ["digest"],
        }

        if cal_type not in cal_paths:
            print(f"Invalid calibration type: {cal_type} (must be 0 or 1)")
            return None
        
        target_paths = cal_paths[cal_type]
        section_idx = SectionExtractor._find_romfs_section(nca)
        if section_idx == -1:
            print("The input NCA has no RomFS")
            return None
        
        try:
            full_data = nca.get_decrypted_section_bytes(section_idx)
            fs_header = nca.fsheaders[section_idx]
            romfs_data = full_data[fs_header.content_start:fs_header.content_end]  # Slice to pure RomFS
            
            # Try each path format until one succeeds
            cal_data = None
            for path in target_paths:
                try:
                    cal_data = romfs.extract_file_from_romfs(romfs_data, path)
                    if cal_data is not None:
                        #print(f"Found calibration file at path: {path}")
                        return cal_data
                except:
                    continue
            
            print(f"Could not find calibration file {cal_type} at any of these paths: {', '.join(target_paths)}")
            return None
        except Exception as e:
            print(f"Error extracting calibration file {cal_type} from RomFS section {section_idx}: {e}")
            return None
    
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
