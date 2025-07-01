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
import struct
from pathlib import Path
from typing import List, NamedTuple, Union

import util

# PFS0 Format Constants (per switchbrew.org/wiki/NCA#PFS0)
PFS0_MAGIC = b'PFS0'
PFS0_MAGIC_HFS0 = b'HFS0'  # Alternative header type
PFS0_HEADER_SIZE_BASE = 0x10
PFS0_FILE_ENTRY_SIZE = 0x18

# Struct format strings (little-endian)
U32 = 'I'  # unsigned 32-bit
U64 = 'Q'  # unsigned 64-bit
# Use '<' prefix when calling struct.unpack() for little-endian byte order


class Pfs0FileEntry(NamedTuple):
    """PFS0 PartitionEntry as per spec: offset (u64) + size (u64) + string_offset (u32) + reserved (u32)"""
    offset: int
    size: int
    string_offset: int
    reserved: int

    @classmethod
    def from_bytes(cls, data: bytes) -> 'Pfs0FileEntry':
        """Parse a 0x18-byte PFS0 file entry."""
        if len(data) < PFS0_FILE_ENTRY_SIZE:
            raise ValueError(f"File entry data too short: {len(data)} < {PFS0_FILE_ENTRY_SIZE}")
        offset, size, str_off, reserved = struct.unpack('<QQII', data[:PFS0_FILE_ENTRY_SIZE])
        return cls(offset, size, str_off, reserved)


class Pfs0Header:
    """PFS0 Header parser following switchbrew.org specification."""
    
    def __init__(self, data: bytes):
        if len(data) < PFS0_HEADER_SIZE_BASE:
            raise ValueError(f"PFS0 header data too short: {len(data)} < {PFS0_HEADER_SIZE_BASE}")

        self.magic = data[0:4]
        if self.magic not in (PFS0_MAGIC, PFS0_MAGIC_HFS0):
            raise ValueError(f"Invalid PFS0 magic: {self.magic!r}")

        (self.num_files, self.string_table_size, self.reserved) = struct.unpack(
            '<III', data[4:16]
        )

        # Validate file count is reasonable
        if self.num_files > 1_000_000:
            raise ValueError(f"Unreasonable file count: {self.num_files:,}")
        
        # Calculate offsets
        self.entry_table_offset = PFS0_HEADER_SIZE_BASE
        self.string_table_offset = self.entry_table_offset + (self.num_files * PFS0_FILE_ENTRY_SIZE)
        self.data_offset = self.string_table_offset + self.string_table_size
        
        # Validate header fits in provided data
        if self.data_offset > len(data):
            raise ValueError(
                f"PFS0 header implies data starts at 0x{self.data_offset:x} "
                f"but input is only 0x{len(data):x} bytes"
            )
    
    def get_header_size(self) -> int:
        """Total size of PFS0 header (magic + entries + string table)."""
        return self.data_offset


class Pfs0HashData:
    """PFS0 Hash Data parser for HierarchicalSha256 verification (used in NCA sections)."""
    
    def __init__(self, hash_data: bytes):
        """Parse PFS0 superblock hash data (0xF8 bytes from FsHeader offset 0x8-0x100).
        
        Args:
            hash_data: The hash info section from FsHeader (0x8-0x100, which is 0xF8 bytes)
        """
        if len(hash_data) < 0x80:
            raise ValueError(f"Hash data too short: {len(hash_data)} < 0x80")
        
        self.hash_data = hash_data
        self.master_hash = hash_data[0x0:0x20]
        
        (self.block_size, self.layer_count) = struct.unpack(
            '<II', hash_data[0x20:0x28]
        )
        
        # Layer regions: 0x28-0x78 contains up to 4 region entries (8 bytes each)
        self.layer_regions = hash_data[0x28:0x78]
        self.reserved = hash_data[0x78:0x80]
        
        # Region 0: Hash table
        self.region_0_offset = struct.unpack('<Q', self.layer_regions[0x0:0x8])[0]
        self.region_0_size = struct.unpack('<Q', self.layer_regions[0x8:0x10])[0]
        
        # Region 1: PFS0 data
        self.region_1_offset = struct.unpack('<Q', self.layer_regions[0x10:0x18])[0]
        self.region_1_size = struct.unpack('<Q', self.layer_regions[0x18:0x20])[0]
    
def extract_pfs0(
    source: Union[str, Path, bytes],
    output_dir: Union[str, Path],
    *,
    print_progress: bool = False
) -> None:
    """
    Extract PFS0 contents following the official specification.

    Args:
        source:         path (str/Path) or raw bytes of the PFS0 file
        output_dir:     where to write extracted files
        print_progress: whether to print file names/sizes during extraction
    
    Raises:
        FileNotFoundError: if source file doesn't exist
        ValueError: if PFS0 structure is invalid
        TypeError: if source type is invalid
    """
    output_dir = Path(output_dir)
    util.mkdirp(output_dir)

    # ── Load input data ───────────────────────────────────────────
    if isinstance(source, (str, Path)):
        path = Path(source)
        if not path.is_file():
            raise FileNotFoundError(f"Not found or not a file: {path}")
        raw = path.read_bytes()
        source_name = path.name
    elif isinstance(source, bytes):
        raw = source
        source_name = "<bytes input>"
    else:
        raise TypeError(f"source must be str, Path or bytes, got {type(source)}")

    # ── Parse header ──────────────────────────────────────────────
    try:
        header = Pfs0Header(raw)
    except ValueError as e:
        raise ValueError(f"Invalid PFS0 header from {source_name}: {e}")

    if print_progress:
        magic_str = header.magic.decode('ascii', errors='replace')
        print(f"PFS0 ({magic_str}): {header.num_files} files (from {source_name})")

    # ── Read and parse file entries ───────────────────────────────
    entries: List[Pfs0FileEntry] = []
    try:
        for i in range(header.num_files):
            pos = header.entry_table_offset + (i * PFS0_FILE_ENTRY_SIZE)
            chunk = raw[pos : pos + PFS0_FILE_ENTRY_SIZE]
            if len(chunk) < PFS0_FILE_ENTRY_SIZE:
                raise ValueError(f"Truncated file entry {i}: got {len(chunk)} bytes")
            entries.append(Pfs0FileEntry.from_bytes(chunk))
    except (struct.error, ValueError) as e:
        raise ValueError(f"Failed to parse file entries: {e}")

    # ── Validate file entries (per hactool implementation) ─────────
    max_offset = 0
    for i, entry in enumerate(entries):
        if entry.offset < max_offset:
            raise ValueError(f"File {i} offset (0x{entry.offset:x}) < previous offset (0x{max_offset:x})")
        max_offset = entry.offset + entry.size

    # ── Extract string table ──────────────────────────────────────
    strtab_start = header.string_table_offset
    strtab_end = strtab_start + header.string_table_size
    if strtab_end > len(raw):
        raise ValueError(f"String table overflows input (0x{strtab_end:x} > 0x{len(raw):x})")
    strtab = raw[strtab_start:strtab_end]

    # ── Extract files ─────────────────────────────────────────────
    extracted_count = 0
    for i, entry in enumerate(entries):
        # Parse filename from string table
        str_offset = entry.string_offset
        if str_offset >= len(strtab):
            if print_progress:
                print(f"  ✗ File {i}: string offset 0x{str_offset:x} out of bounds")
            continue

        # Find null terminator
        name_end = strtab.find(b'\x00', str_offset)
        if name_end == -1:
            # Unterminated string - use rest of table
            name_end = len(strtab)
            if print_progress:
                print(f"  ⚠ File {i}: unterminated string")

        filename_bytes = strtab[str_offset:name_end]
        
        # Decode filename
        try:
            filename = filename_bytes.decode('utf-8')
        except UnicodeDecodeError:
            filename = f"file_{i:04d}.bin"
            if print_progress:
                print(f"  ⚠ File {i}: invalid UTF-8 → using {filename}")

        if not filename or not filename.strip():
            filename = f"unnamed_{i:04d}.bin"

        # Extract file data
        file_start = header.data_offset + entry.offset
        file_end = file_start + entry.size

        if file_end > len(raw):
            if print_progress:
                print(f"  ✗ {filename}: overflows input "
                      f"(0x{file_end:x} > 0x{len(raw):x})")
            continue

        out_path = output_dir / filename
        try:
            out_path.write_bytes(raw[file_start:file_end])
            extracted_count += 1
            if print_progress:
                print(f"  → {filename:<40} {entry.size:>12,d} B")
        except (IOError, OSError) as e:
            if print_progress:
                print(f"  ✗ {filename}: write failed - {e}")

    if print_progress:
        print(f"✓ Extracted {extracted_count}/{len(entries)} files to {output_dir}")


def main() -> None:
    """Command-line entry point for PFS0 extraction."""
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.pfs0> <output_directory>")
        print("Example:")
        print(f"  python {sys.argv[0]} firmware.pfs0 output/")
        sys.exit(1)

    input_file = sys.argv[1]
    out_dir = sys.argv[2]

    try:
        extract_pfs0(input_file, out_dir, print_progress=True)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
