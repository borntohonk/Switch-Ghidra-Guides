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

"""
CNMT (Content Meta) Parser
Fully compliant with https://switchbrew.org/wiki/CNMT specification

This module parses PackagedContentMeta (CNMT) files from Nintendo Switch content packages.
A CNMT is found within section0 (pfs0) of a .cnmt.nca file.
"""

import struct
import hashlib
from enum import IntEnum
from dataclasses import dataclass, field
from typing import List, Optional


class ContentMetaType(IntEnum):
    """CNMT content meta type"""
    SYSTEM_PROGRAM = 0x00
    SYSTEM_DATA = 0x01
    SYSTEM_UPDATE = 0x02
    FIRMWARE_PACKAGE_A = 0x03
    FIRMWARE_PACKAGE_B = 0x04
    APPLICATION = 0x80
    PATCH = 0x81
    ADD_ON_CONTENT = 0x82
    DELTA = 0x83
    DATA_PATCH = 0x84


class ContentType(IntEnum):
    """Content type"""
    META = 0x00
    PROGRAM = 0x01
    DATA = 0x02
    CONTROL = 0x03
    HTML_DOCUMENT = 0x04
    LEGAL_INFORMATION = 0x05
    DELTA_FRAGMENT = 0x06


class ContentMetaPlatform(IntEnum):
    """Content meta platform (v17.0.0+)"""
    NX = 0x00


class ContentMetaAttributeFlag(IntEnum):
    """Content meta attributes"""
    INCLUDE_EXFAT_DRIVER = 0x01


class StorageId(IntEnum):
    """Storage ID"""
    NONE = 0x00
    HOST = 0x01
    DEVICE = 0x02
    SD_CARD = 0x03


class ContentInstallType(IntEnum):
    """Content install type"""
    FULL = 0x00
    GAMECARD = 0x01
    INSTALLED = 0x02


class InstallStateFlag(IntEnum):
    """Install state flags"""
    COMMITTED = 0x01
    COMMITTED_CANCEL = 0x02
    UNCOMMITTED = 0x04
    VERIFY_WAIT = 0x08
    NOT_COMMITTED = 0x10


class UpdateType(IntEnum):
    """Delta update type"""
    APPLY_AS_DELTA = 0x00
    OVERWRITE = 0x01
    CREATE = 0x02


# Struct definitions
PACKAGED_CONTENT_META_HEADER_SIZE = 0x20
PACKAGED_CONTENT_INFO_SIZE_V15_PLUS = 0x38  # 0x20 hash + 0x10 id + 0x5 size + 0x1 attributes + 0x1 type + 0x1 offset
PACKAGED_CONTENT_INFO_SIZE_LEGACY = 0x39   # legacy (0x20 hash + 0x10 id + 0x6 size + 0x1 type + 0x1 offset)
CONTENT_META_INFO_SIZE = 0x10  # 0x8 id + 0x4 version + 0x1 type + 0x1 attributes + 0x2 reserved


@dataclass
class PackagedContentInfo:
    """Represents a PackagedContentInfo entry"""
    hash: bytes  # SHA256 hash (32 bytes)
    content_id: bytes  # Content ID (16 bytes)
    size: int  # Content size (48-bit or 56-bit depending on version)
    content_attributes: int = 0  # Content attributes (v15.0.0+)
    content_type: ContentType = ContentType.PROGRAM
    id_offset: int = 0

    def __repr__(self):
        return (f"PackagedContentInfo(type={ContentType(self.content_type).name}, "
                f"id={self.content_id.hex().upper()}, size=0x{self.size:x})")


@dataclass
class ContentMetaInfo:
    """Represents a ContentMetaInfo entry"""
    title_id: int  # 8 bytes
    version: int  # 4 bytes
    content_meta_type: ContentMetaType  # 1 byte
    attributes: int  # 1 byte
    reserved: int = 0  # 2 bytes

    def __repr__(self):
        return (f"ContentMetaInfo(id=0x{self.title_id:016x}, "
                f"version=v{self.version}, type={ContentMetaType(self.content_meta_type).name})")


@dataclass
class ApplicationMetaExtendedHeader:
    """Extended header for Application type content meta"""
    patch_id: int = 0  # 8 bytes
    required_system_version: int = 0  # 4 bytes
    required_application_version: int = 0  # 4 bytes

    @staticmethod
    def size():
        return 0x10

    def from_bytes(self, data: bytes):
        if len(data) < self.size():
            raise ValueError("Insufficient data for ApplicationMetaExtendedHeader")
        self.patch_id = struct.unpack('<Q', data[0:8])[0]
        self.required_system_version = struct.unpack('<I', data[8:12])[0]
        self.required_application_version = struct.unpack('<I', data[12:16])[0]

    def __repr__(self):
        return (f"ApplicationMetaExtendedHeader(patch_id=0x{self.patch_id:016x}, "
                f"req_sys=v{self.required_system_version}, req_app=v{self.required_application_version})")


@dataclass
class PatchMetaExtendedHeader:
    """Extended header for Patch type content meta"""
    application_id: int = 0  # 8 bytes
    required_system_version: int = 0  # 4 bytes
    extended_data_size: int = 0  # 4 bytes
    reserved: int = 0  # 8 bytes

    @staticmethod
    def size():
        return 0x18

    def from_bytes(self, data: bytes):
        if len(data) < self.size():
            raise ValueError("Insufficient data for PatchMetaExtendedHeader")
        self.application_id = struct.unpack('<Q', data[0:8])[0]
        self.required_system_version = struct.unpack('<I', data[8:12])[0]
        self.extended_data_size = struct.unpack('<I', data[12:16])[0]
        self.reserved = struct.unpack('<Q', data[16:24])[0]

    def __repr__(self):
        return (f"PatchMetaExtendedHeader(app_id=0x{self.application_id:016x}, "
                f"req_sys=v{self.required_system_version}, ex_size=0x{self.extended_data_size:x})")


@dataclass
class AddOnContentMetaExtendedHeader:
    """Extended header for AddOnContent type content meta"""
    application_id: int = 0  # 8 bytes
    required_application_version: int = 0  # 4 bytes
    content_accessibilities: int = 0  # 1 byte (v15.0.0+)
    reserved: int = 0  # 3 bytes
    data_patch_id: int = 0  # 8 bytes (v15.0.0+)

    @staticmethod
    def size():
        return 0x20

    def from_bytes(self, data: bytes):
        if len(data) < self.size():
            raise ValueError("Insufficient data for AddOnContentMetaExtendedHeader")
        self.application_id = struct.unpack('<Q', data[0:8])[0]
        self.required_application_version = struct.unpack('<I', data[8:12])[0]
        self.content_accessibilities = data[12]
        # 3 bytes reserved
        self.data_patch_id = struct.unpack('<Q', data[16:24])[0]

    def __repr__(self):
        return (f"AddOnContentMetaExtendedHeader(app_id=0x{self.application_id:016x}, "
                f"req_app=v{self.required_application_version})")


@dataclass
class DeltaMetaExtendedHeader:
    """Extended header for Delta type content meta"""
    application_id: int = 0  # 8 bytes
    extended_data_size: int = 0  # 4 bytes
    reserved: int = 0  # 4 bytes

    @staticmethod
    def size():
        return 0x10

    def from_bytes(self, data: bytes):
        if len(data) < self.size():
            raise ValueError("Insufficient data for DeltaMetaExtendedHeader")
        self.application_id = struct.unpack('<Q', data[0:8])[0]
        self.extended_data_size = struct.unpack('<I', data[8:12])[0]
        self.reserved = struct.unpack('<I', data[12:16])[0]

    def __repr__(self):
        return (f"DeltaMetaExtendedHeader(app_id=0x{self.application_id:016x}, "
                f"ex_size=0x{self.extended_data_size:x})")


@dataclass
class SystemUpdateMetaExtendedHeader:
    """Extended header for SystemUpdate type content meta"""
    extended_data_size: int = 0  # 4 bytes

    @staticmethod
    def size():
        return 0x04

    def from_bytes(self, data: bytes):
        if len(data) < self.size():
            raise ValueError("Insufficient data for SystemUpdateMetaExtendedHeader")
        self.extended_data_size = struct.unpack('<I', data[0:4])[0]

    def __repr__(self):
        return f"SystemUpdateMetaExtendedHeader(ex_size=0x{self.extended_data_size:x})"


@dataclass
class DataPatchMetaExtendedHeader:
    """Extended header for DataPatch type content meta (v15.0.0+)"""
    data_id: int = 0  # 8 bytes
    application_id: int = 0  # 8 bytes
    required_application_version: int = 0  # 4 bytes
    extended_data_size: int = 0  # 4 bytes
    reserved: int = 0  # 8 bytes

    @staticmethod
    def size():
        return 0x20

    def from_bytes(self, data: bytes):
        if len(data) < self.size():
            raise ValueError("Insufficient data for DataPatchMetaExtendedHeader")
        self.data_id = struct.unpack('<Q', data[0:8])[0]
        self.application_id = struct.unpack('<Q', data[8:16])[0]
        self.required_application_version = struct.unpack('<I', data[16:20])[0]
        self.extended_data_size = struct.unpack('<I', data[20:24])[0]
        self.reserved = struct.unpack('<Q', data[24:32])[0]

    def __repr__(self):
        return (f"DataPatchMetaExtendedHeader(data_id=0x{self.data_id:016x}, "
                f"app_id=0x{self.application_id:016x})")


@dataclass
class SystemUpdateMetaExtendedData:
    """Extended data for SystemUpdate type content meta"""
    format_version: int = 0
    firmware_variations: List = field(default_factory=list)

    def from_bytes(self, data: bytes):
        if len(data) < 8:
            raise ValueError("Insufficient data for SystemUpdateMetaExtendedData")
        
        self.format_version = struct.unpack('<I', data[0:4])[0]
        variation_count = struct.unpack('<I', data[4:8])[0]
        
        self.firmware_variations = []
        offset = 8

        if self.format_version == 1:
            # Version 1: 0x20 bytes per variation
            for i in range(variation_count):
                if offset + 0x20 > len(data):
                    raise ValueError("Insufficient data for firmware variation")
                variation_id = struct.unpack('<I', data[offset:offset+4])[0]
                self.firmware_variations.append({
                    'variation_id': variation_id,
                    'metadata': []
                })
                offset += 0x20
        elif self.format_version == 2:
            # Version 2: variable layout
            # First read all variation IDs
            variation_ids = []
            for i in range(variation_count):
                if offset + 4 > len(data):
                    raise ValueError("Insufficient data for firmware variation ID")
                var_id = struct.unpack('<I', data[offset:offset+4])[0]
                variation_ids.append(var_id)
                offset += 4
            
            # Then read FirmwareVariationInfo structures
            for i in range(variation_count):
                if offset + 0x20 > len(data):
                    raise ValueError("Insufficient data for firmware variation info v2")
                
                refer_to_base = data[offset] != 0
                meta_count = struct.unpack('<I', data[offset+4:offset+8])[0]
                
                meta_list = []
                if not refer_to_base:
                    # Read ContentMetaInfo entries
                    info_offset = offset + 0x20
                    for j in range(meta_count):
                        if info_offset + CONTENT_META_INFO_SIZE > len(data):
                            raise ValueError("Insufficient data for ContentMetaInfo")
                        cmi = self._parse_content_meta_info(data[info_offset:])
                        meta_list.append(cmi)
                        info_offset += CONTENT_META_INFO_SIZE
                
                self.firmware_variations.append({
                    'variation_id': variation_ids[i],
                    'refer_to_base': refer_to_base,
                    'metadata': meta_list
                })
                offset += 0x20

    @staticmethod
    def _parse_content_meta_info(data: bytes) -> ContentMetaInfo:
        if len(data) < CONTENT_META_INFO_SIZE:
            raise ValueError("Insufficient data for ContentMetaInfo")
        
        title_id = struct.unpack('<Q', data[0:8])[0]
        version = struct.unpack('<I', data[8:12])[0]
        content_meta_type = ContentMetaType(data[12])
        attributes = data[13]
        
        return ContentMetaInfo(
            title_id=title_id,
            version=version,
            content_meta_type=content_meta_type,
            attributes=attributes
        )


@dataclass
class CNMT:
    """
    Main CNMT parser class
    
    This class parses a complete CNMT (Content Meta) file.
    The CNMT is the decrypted section 0 of a .cnmt.nca file,
    starting at offset 0x60 from the beginning of section 0.
    """
    
    # Core header fields
    title_id: int = 0
    version: int = 0
    content_meta_type: ContentMetaType = ContentMetaType.SYSTEM_PROGRAM
    content_meta_platform: ContentMetaPlatform = ContentMetaPlatform.NX
    extended_header_size: int = 0
    content_count: int = 0
    content_meta_count: int = 0
    attributes: int = 0
    required_download_system_version: int = 0
    
    # Extended headers
    application_extended_header: Optional[ApplicationMetaExtendedHeader] = None
    patch_extended_header: Optional[PatchMetaExtendedHeader] = None
    addon_extended_header: Optional[AddOnContentMetaExtendedHeader] = None
    delta_extended_header: Optional[DeltaMetaExtendedHeader] = None
    system_update_extended_header: Optional[SystemUpdateMetaExtendedHeader] = None
    data_patch_extended_header: Optional[DataPatchMetaExtendedHeader] = None
    
    # Content entries
    content_infos: List[PackagedContentInfo] = field(default_factory=list)
    content_meta_infos: List[ContentMetaInfo] = field(default_factory=list)
    
    # Extended data
    patch_extended_data: bytes = b''
    delta_extended_data: bytes = b''
    system_update_extended_data: Optional[SystemUpdateMetaExtendedData] = None
    
    # Digest
    digest: bytes = b''
    
    # Raw binary (for validation/export)
    raw_binary: bytes = b''

    def parse(self, data: bytes):
        """
        Parse CNMT data
        
        Args:
            data: The CNMT binary data (decrypted section 0 starting at offset 0x60)
        """
        if len(data) < PACKAGED_CONTENT_META_HEADER_SIZE:
            raise ValueError("CNMT data too small for header")
        
        # Parse header
        self._parse_header(data)
        
        # Parse extended header
        exhdr_offset = PACKAGED_CONTENT_META_HEADER_SIZE
        if self.extended_header_size > 0:
            self._parse_extended_header(data, exhdr_offset)
        
        # Parse content info
        content_info_offset = exhdr_offset + self.extended_header_size
        if self.content_count > 0:
            self._parse_content_infos(data, content_info_offset)
        
        # Parse content meta info
        content_meta_info_offset = content_info_offset + (self.content_count * PACKAGED_CONTENT_INFO_SIZE_V15_PLUS)
        if self.content_meta_count > 0:
            self._parse_content_meta_infos(data, content_meta_info_offset)
        
        # Parse extended data
        extended_data_offset = content_meta_info_offset + (self.content_meta_count * CONTENT_META_INFO_SIZE)
        extended_data_size = self._get_extended_data_size()
        
        if extended_data_size > 0:
            self._parse_extended_data(data, extended_data_offset, extended_data_size)
        
        # Parse digest (always last 0x20 bytes)
        digest_offset = extended_data_offset + extended_data_size
        if digest_offset + 32 <= len(data):
            self.digest = data[digest_offset:digest_offset + 32]
        
        # Store raw binary
        self.raw_binary = data[:digest_offset + 32] if digest_offset + 32 <= len(data) else data

    def _parse_header(self, data: bytes):
        """Parse the PackagedContentMetaHeader"""
        if len(data) < PACKAGED_CONTENT_META_HEADER_SIZE:
            raise ValueError("Insufficient data for CNMT header")
        
        self.title_id = struct.unpack('<Q', data[0:8])[0]
        self.version = struct.unpack('<I', data[8:12])[0]
        self.content_meta_type = ContentMetaType(data[12])
        self.content_meta_platform = ContentMetaPlatform(data[13])
        self.extended_header_size = struct.unpack('<H', data[14:16])[0]
        self.content_count = struct.unpack('<H', data[16:18])[0]
        self.content_meta_count = struct.unpack('<H', data[18:20])[0]
        self.attributes = data[20]
        # 3 bytes reserved (21-23)
        self.required_download_system_version = struct.unpack('<I', data[24:28])[0]
        # 4 bytes reserved (28-31)

    def _parse_extended_header(self, data: bytes, offset: int):
        """Parse the appropriate extended header based on content meta type"""
        exhdr_data = data[offset:offset + self.extended_header_size]
        
        if self.content_meta_type == ContentMetaType.APPLICATION:
            self.application_extended_header = ApplicationMetaExtendedHeader()
            self.application_extended_header.from_bytes(exhdr_data)
        elif self.content_meta_type == ContentMetaType.PATCH:
            self.patch_extended_header = PatchMetaExtendedHeader()
            self.patch_extended_header.from_bytes(exhdr_data)
        elif self.content_meta_type == ContentMetaType.ADD_ON_CONTENT:
            self.addon_extended_header = AddOnContentMetaExtendedHeader()
            self.addon_extended_header.from_bytes(exhdr_data)
        elif self.content_meta_type == ContentMetaType.DELTA:
            self.delta_extended_header = DeltaMetaExtendedHeader()
            self.delta_extended_header.from_bytes(exhdr_data)
        elif self.content_meta_type == ContentMetaType.SYSTEM_UPDATE:
            self.system_update_extended_header = SystemUpdateMetaExtendedHeader()
            self.system_update_extended_header.from_bytes(exhdr_data)
        elif self.content_meta_type == ContentMetaType.DATA_PATCH:
            self.data_patch_extended_header = DataPatchMetaExtendedHeader()
            self.data_patch_extended_header.from_bytes(exhdr_data)

    def _parse_content_infos(self, data: bytes, offset: int):
        """Parse all PackagedContentInfo entries"""
        self.content_infos = []
        
        for i in range(self.content_count):
            content_offset = offset + (i * PACKAGED_CONTENT_INFO_SIZE_V15_PLUS)
            if content_offset + PACKAGED_CONTENT_INFO_SIZE_V15_PLUS > len(data):
                raise ValueError(f"Insufficient data for content info {i}")
            
            info = self._parse_content_info(data[content_offset:])
            self.content_infos.append(info)

    def _parse_content_info(self, data: bytes) -> PackagedContentInfo:
        """Parse a single PackagedContentInfo entry"""
        if len(data) < PACKAGED_CONTENT_INFO_SIZE_V15_PLUS:
            raise ValueError("Insufficient data for PackagedContentInfo")
        
        hash_data = data[0:32]
        content_id = data[32:48]
        size_bytes = data[48:53]  # 5 bytes
        size = int.from_bytes(size_bytes, 'little')
        content_attributes = data[53]
        content_type = ContentType(data[54])
        id_offset = data[55]
        
        return PackagedContentInfo(
            hash=hash_data,
            content_id=content_id,
            size=size,
            content_attributes=content_attributes,
            content_type=content_type,
            id_offset=id_offset
        )

    def _parse_content_meta_infos(self, data: bytes, offset: int):
        """Parse all ContentMetaInfo entries"""
        self.content_meta_infos = []
        
        for i in range(self.content_meta_count):
            info_offset = offset + (i * CONTENT_META_INFO_SIZE)
            if info_offset + CONTENT_META_INFO_SIZE > len(data):
                raise ValueError(f"Insufficient data for content meta info {i}")
            
            info = self._parse_content_meta_info(data[info_offset:])
            self.content_meta_infos.append(info)

    @staticmethod
    def _parse_content_meta_info(data: bytes) -> ContentMetaInfo:
        """Parse a single ContentMetaInfo entry"""
        if len(data) < CONTENT_META_INFO_SIZE:
            raise ValueError("Insufficient data for ContentMetaInfo")
        
        title_id = struct.unpack('<Q', data[0:8])[0]
        version = struct.unpack('<I', data[8:12])[0]
        content_meta_type = ContentMetaType(data[12])
        attributes = data[13]
        
        return ContentMetaInfo(
            title_id=title_id,
            version=version,
            content_meta_type=content_meta_type,
            attributes=attributes
        )

    def _get_extended_data_size(self) -> int:
        """Get extended data size based on content meta type"""
        if self.content_meta_type == ContentMetaType.PATCH and self.patch_extended_header:
            return self.patch_extended_header.extended_data_size
        elif self.content_meta_type == ContentMetaType.DELTA and self.delta_extended_header:
            return self.delta_extended_header.extended_data_size
        elif self.content_meta_type == ContentMetaType.SYSTEM_UPDATE and self.system_update_extended_header:
            return self.system_update_extended_header.extended_data_size
        elif self.content_meta_type == ContentMetaType.DATA_PATCH and self.data_patch_extended_header:
            return self.data_patch_extended_header.extended_data_size
        return 0

    def _parse_extended_data(self, data: bytes, offset: int, size: int):
        """Parse extended data based on content meta type"""
        if offset + size > len(data):
            raise ValueError("Insufficient data for extended data")
        
        exdata = data[offset:offset + size]
        
        if self.content_meta_type == ContentMetaType.PATCH:
            self.patch_extended_data = exdata
        elif self.content_meta_type == ContentMetaType.DELTA:
            self.delta_extended_data = exdata
        elif self.content_meta_type == ContentMetaType.SYSTEM_UPDATE:
            self.system_update_extended_data = SystemUpdateMetaExtendedData()
            self.system_update_extended_data.from_bytes(exdata)
        elif self.content_meta_type == ContentMetaType.DATA_PATCH:
            # Store as raw bytes for now
            self.patch_extended_data = exdata

    def __repr__(self):
        return (f"CNMT(id=0x{self.title_id:016x}, version=v{self.version}, "
                f"type={ContentMetaType(self.content_meta_type).name}, "
                f"contents={self.content_count}, meta_contents={self.content_meta_count})")

    def print_info(self, verbose: bool = False):
        """Pretty print CNMT information"""
        if not verbose:
            return

        print(f"\n[ContentMeta]")
        print(f"  TitleId:                        0x{self.title_id:016x}")
        print(f"  Version:                        v{self.version}")
        print(f"  Type:                           {ContentMetaType(self.content_meta_type).name}")
        print(f"  Platform:                       {ContentMetaPlatform(self.content_meta_platform).name}")
        print(f"  Attributes:                     0x{self.attributes:02x}")
        if self.attributes & ContentMetaAttributeFlag.INCLUDE_EXFAT_DRIVER:
            print(f"                                 [INCLUDE_EXFAT_DRIVER]")
        print(f"  RequiredDownloadSystemVersion:  v{self.required_download_system_version}")
        
        # Print type-specific extended headers
        if self.content_meta_type == ContentMetaType.APPLICATION and self.application_extended_header:
            print(f"  ApplicationMetaExtendedHeader:")
            print(f"    PatchId:                    0x{self.application_extended_header.patch_id:016x}")
            print(f"    RequiredSystemVersion:      v{self.application_extended_header.required_system_version}")
            print(f"    RequiredApplicationVersion: v{self.application_extended_header.required_application_version}")
        elif self.content_meta_type == ContentMetaType.PATCH and self.patch_extended_header:
            print(f"  PatchMetaExtendedHeader:")
            print(f"    ApplicationId:              0x{self.patch_extended_header.application_id:016x}")
            print(f"    RequiredSystemVersion:      v{self.patch_extended_header.required_system_version}")
            print(f"    ExtendedDataSize:           0x{self.patch_extended_header.extended_data_size:x}")
        elif self.content_meta_type == ContentMetaType.ADD_ON_CONTENT and self.addon_extended_header:
            print(f"  AddOnContentMetaExtendedHeader:")
            print(f"    ApplicationId:              0x{self.addon_extended_header.application_id:016x}")
            print(f"    RequiredApplicationVersion: v{self.addon_extended_header.required_application_version}")
        elif self.content_meta_type == ContentMetaType.DELTA and self.delta_extended_header:
            print(f"  DeltaMetaExtendedHeader:")
            print(f"    ApplicationId:              0x{self.delta_extended_header.application_id:016x}")
            print(f"    ExtendedDataSize:           0x{self.delta_extended_header.extended_data_size:x}")
        elif self.content_meta_type == ContentMetaType.SYSTEM_UPDATE and self.system_update_extended_header:
            print(f"  SystemUpdateMetaExtendedHeader:")
            print(f"    ExtendedDataSize:           0x{self.system_update_extended_header.extended_data_size:x}")
        elif self.content_meta_type == ContentMetaType.DATA_PATCH and self.data_patch_extended_header:
            print(f"  DataPatchMetaExtendedHeader:")
            print(f"    DataId:                     0x{self.data_patch_extended_header.data_id:016x}")
            print(f"    ApplicationId:              0x{self.data_patch_extended_header.application_id:016x}")
            print(f"    RequiredApplicationVersion: v{self.data_patch_extended_header.required_application_version}")
            print(f"    ExtendedDataSize:           0x{self.data_patch_extended_header.extended_data_size:x}")
        
        # Print content info
        if self.content_infos:
            print(f"  ContentInfo: ({len(self.content_infos)} entries)")
            for i, info in enumerate(self.content_infos):
                print(f"    [{i}] {ContentType(info.content_type).name}")
                print(f"        ContentId: {info.content_id.hex().upper()}")
                print(f"        Size:      0x{info.size:x}")
                print(f"        Hash:      {info.hash.hex().upper()}")
                if verbose:
                    print(f"        Attributes: 0x{info.content_attributes:02x}")
                    print(f"        IdOffset:   {info.id_offset}")
        
        # Print content meta info
        if self.content_meta_infos:
            print(f"  ContentMetaInfo: ({len(self.content_meta_infos)} entries)")
            for i, info in enumerate(self.content_meta_infos):
                print(f"    [{i}] {ContentMetaType(info.content_meta_type).name}")
                print(f"        TitleId:   0x{info.title_id:016x}")
                print(f"        Version:   v{info.version}")
                if verbose:
                    print(f"        Attributes: 0x{info.attributes:02x}")
        
        # Print system update extended data if present
        if self.system_update_extended_data:
            print(f"  SystemUpdateMetaExtendedData:")
            print(f"    FormatVersion: {self.system_update_extended_data.format_version}")
            print(f"    FirmwareVariations: ({len(self.system_update_extended_data.firmware_variations)} entries)")
            for i, variation in enumerate(self.system_update_extended_data.firmware_variations):
                print(f"      [{i}] FirmwareVariationId: 0x{variation['variation_id']:x}")
                if 'refer_to_base' in variation:
                    print(f"          ReferToBase: {variation['refer_to_base']}")
                if variation['metadata']:
                    print(f"          ContentMeta: ({len(variation['metadata'])} entries)")
                    for j, meta in enumerate(variation['metadata']):
                        print(f"            [{j}] {meta}")
        
        # Print digest
        print(f"  Digest: {self.digest.hex().upper()}")


def parse_cnmt(data: bytes) -> CNMT:
    """
    Convenience function to parse CNMT data
    
    Args:
        data: The CNMT binary data (decrypted section 0 starting at offset 0x60)
    
    Returns:
        Parsed CNMT object
    """
    cnmt = CNMT()
    cnmt.parse(data)
    return cnmt

# example use:
# with open("cnmt.cnmt", "rb") as f:
#     data = f.read()
#     cnmt = parse_cnmt(data)
#     cnmt.print_info(verbose=True)
#
# or
#
# nca_file = nca.Nca(util.InitializeFile("path_to_nca"), titlekeys[0]) # rightsid
# nca_file = nca.Nca(util.InitializeFile("path_to_nca"))
# data = nca.save_section(nca_file, 0)[0x60:]
# cnmt = parse_cnmt(data)
# cnmt.print_info(verbose=True)
#