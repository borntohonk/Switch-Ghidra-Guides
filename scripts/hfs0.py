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

import struct
import hashlib
from pathlib import Path

MAGIC_HFS0 = 0x30534648  # "HFS0"


class Hfs0Header:
    """HFS0 header structure."""
    def __init__(self, data):
        if len(data) < 16:
            raise ValueError(f"HFS0 header too small: {len(data)} < 16")
        
        magic, num_files, string_table_size, reserved = struct.unpack('<4I', data[0:16])
        
        if magic != MAGIC_HFS0:
            raise ValueError(f"Invalid HFS0 magic: 0x{magic:08X}, expected 0x{MAGIC_HFS0:08X}")
        
        self.magic = magic
        self.num_files = num_files
        self.string_table_size = string_table_size
        self.reserved = reserved
    
    def to_bytes(self):
        """Serialize header to bytes."""
        return struct.pack('<4I', self.magic, self.num_files, self.string_table_size, self.reserved)


class Hfs0FileEntry:
    """HFS0 file entry (mirrors hactool's hfs0_file_entry_t)."""
    SIZE = 0x40  # 64 bytes
    
    def __init__(self, data, offset=0):
        if len(data) < offset + self.SIZE:
            raise ValueError(f"HFS0 file entry data too small")
        
        self.offset = int.from_bytes(data[offset+0x0:offset+0x8], 'little')
        self.size = int.from_bytes(data[offset+0x8:offset+0x10], 'little')
        self.string_table_offset = struct.unpack('<I', data[offset+0x10:offset+0x14])[0]
        self.hashed_size = struct.unpack('<I', data[offset+0x14:offset+0x18])[0]
        self.reserved = int.from_bytes(data[offset+0x18:offset+0x20], 'little')
        self.hash = data[offset+0x20:offset+0x40]  # SHA256 hash
    
    def to_bytes(self):
        """Serialize entry to bytes."""
        return (
            struct.pack('<QQ', self.offset, self.size) +
            struct.pack('<II', self.string_table_offset, self.hashed_size) +
            struct.pack('<Q', self.reserved) +
            self.hash
        )


class Hfs0Context:
    """HFS0 processing context (mirrors hactool's hfs0_ctx_t)."""
    def __init__(self, hfs0_data, offset=0, output_path=None, verbose=False, name="hfs0"):
        self.hfs0_data = hfs0_data
        self.offset = offset
        self.output_path = Path(output_path) if output_path else None
        self.verbose = verbose
        self.name = name
        
        # Parse header
        self.header = Hfs0Header(hfs0_data[offset:offset+16])
        
        # Calculate header size: magic(4) + num_files(4) + string_table_size(4) + reserved(4) + entries + string_table
        header_size = 16 + (self.header.num_files * Hfs0FileEntry.SIZE) + self.header.string_table_size
        self.header_size = header_size
        
        # Store raw header data including entries and string table
        self.header_data = hfs0_data[offset:offset+header_size]
        
        # Load entries and string table
        entries_offset = 16
        self.entries = []
        for i in range(self.header.num_files):
            entry = Hfs0FileEntry(self.header_data, entries_offset + i * Hfs0FileEntry.SIZE)
            self.entries.append(entry)
        
        # String table starts after all entries
        self.string_table_offset = entries_offset + self.header.num_files * Hfs0FileEntry.SIZE
        self.string_table = self.header_data[self.string_table_offset:]
    
    def get_entry(self, index):
        """Get file entry by index."""
        if index < 0 or index >= len(self.entries):
            return None
        return self.entries[index]
    
    def get_file_name(self, index):
        """Get file name for entry at index."""
        entry = self.get_entry(index)
        if entry is None:
            return None
        
        # Extract name from string table
        offset = entry.string_table_offset
        # Find null terminator
        end = offset
        while end < len(self.string_table) and self.string_table[end] != 0:
            end += 1
        
        return self.string_table[offset:end].decode('utf-8', errors='replace')
    
    def get_file_data(self, index):
        """Get raw file data for entry at index."""
        entry = self.get_entry(index)
        if entry is None:
            return None
        
        # Calculate file position relative to hfs0 start
        file_offset = self.offset + self.header_size + entry.offset
        file_end = file_offset + entry.size
        
        return self.hfs0_data[file_offset:file_end]
    
    def verify_file_hash(self, index):
        """Verify SHA256 hash of file (optional validation).
        
        Args:
            index: File entry index
            
        Returns:
            tuple: (is_valid, expected_hash, computed_hash) or (False, None, None) if error
        """
        entry = self.get_entry(index)
        if entry is None:
            return False, None, None
        
        # Get file data (use hashed_size if different from size)
        file_offset = self.offset + self.header_size + entry.offset
        hashed_size = entry.hashed_size if entry.hashed_size > 0 else entry.size
        
        if file_offset + hashed_size > len(self.hfs0_data):
            return False, None, None
        
        file_data = self.hfs0_data[file_offset:file_offset + hashed_size]
        computed_hash = hashlib.sha256(file_data).digest()
        expected_hash = entry.hash
        
        return computed_hash == expected_hash, expected_hash, computed_hash
    
    def verify_all_hashes(self):
        """Verify all file hashes. Returns dict of {filename: is_valid}.
        
        Returns:
            dict: {filename: (is_valid, expected_hash, computed_hash)}
        """
        results = {}
        for i in range(self.header.num_files):
            file_name = self.get_file_name(i)
            if file_name:
                is_valid, expected, computed = self.verify_file_hash(i)
                results[file_name] = (is_valid, expected, computed)
        return results


def hfs0_extract_file(ctx, index, output_dir):
    """Extract a single file from HFS0."""
    entry = ctx.get_entry(index)
    if entry is None:
        return False
    
    file_name = ctx.get_file_name(index)
    if not file_name:
        return False
    
    # Build output path
    output_path = output_dir / file_name
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    if ctx.verbose:
        print(f"Extracting {file_name} (0x{entry.offset:X}-0x{entry.offset + entry.size:X})...")
    
    # Extract file data
    file_data = ctx.get_file_data(index)
    if file_data:
        with open(output_path, 'wb') as f:
            f.write(file_data)
        return True
    
    return False


def hfs0_list_files(ctx):
    """List all files in HFS0."""
    print(f"HFS0 '{ctx.name}': {ctx.header.num_files} files")
    for i in range(ctx.header.num_files):
        entry = ctx.get_entry(i)
        file_name = ctx.get_file_name(i)
        if entry and file_name:
            print(f"  [{i:2d}] {file_name:48s} 0x{entry.offset:012X}-0x{entry.offset + entry.size:012X} (size: 0x{entry.size:X})")


def hfs0_verify_hashes(ctx, verbose=False):
    """Verify all file hashes and print results.
    
    Args:
        ctx: Hfs0Context instance
        verbose: Print detailed results
        
    Returns:
        bool: True if all hashes valid, False otherwise
    """
    results = ctx.verify_all_hashes()
    
    all_valid = True
    for file_name, (is_valid, expected, computed) in results.items():
        if is_valid:
            if verbose:
                print(f"  ✓ {file_name}")
        else:
            all_valid = False
            if expected and computed:
                print(f"  ✗ {file_name}")
                print(f"    Expected: {expected.hex()}")
                print(f"    Got:      {computed.hex()}")
            else:
                print(f"  ✗ {file_name} (validation error)")
    
    return all_valid


def hfs0_print(ctx):
    """Print HFS0 information."""
    print(f"\nHFS0 Information ({ctx.name}):")
    print(f"  Magic: 0x{ctx.header.magic:08X}")
    print(f"  Number of files: {ctx.header.num_files}")
    print(f"  String Table Size: 0x{ctx.header.string_table_size:X}")
    print(f"  Header Size: 0x{ctx.header_size:X}")
    print("\nFiles:")
    hfs0_list_files(ctx)


def hfs0_process(hfs0_data, offset=0, output_path=None, list_only=False, print_info=False, verify_hashes=False, name="hfs0"):
    """Process HFS0 - main entry point (mirrors hactool's hfs0_process).
    
    Args:
        hfs0_data: Binary data containing HFS0
        offset: Offset within data to HFS0 header
        output_path: Path to extract files to
        list_only: Only list files, don't extract
        print_info: Print header information
        verify_hashes: Verify SHA256 hashes (optional validation)
        name: Name for this HFS0 (for logging)
        
    Returns:
        Hfs0Context: Parsing context
    """
    # Create context
    ctx = Hfs0Context(hfs0_data, offset=offset, output_path=output_path, verbose=print_info, name=name)
    
    # Print info if requested
    if print_info:
        hfs0_print(ctx)
    
    # Verify hashes if requested
    if verify_hashes:
        print(f"\nVerifying SHA256 hashes for '{name}'...")
        all_valid = hfs0_verify_hashes(ctx, verbose=print_info)
        if all_valid:
            print(f"✓ All hashes valid")
        else:
            print(f"✗ Hash verification failed")
    
    # List files if requested
    if list_only:
        hfs0_list_files(ctx)
        return ctx
    
    # Extract files if output path provided
    if output_path:
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        for i in range(ctx.header.num_files):
            hfs0_extract_file(ctx, i, output_dir)
    
    return ctx
