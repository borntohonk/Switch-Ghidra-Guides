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

import util
from pathlib import Path

ROMFS_ENTRY_EMPTY = 0xFFFFFFFF
ROMFS_HEADER_SIZE = 0x50


class RomfsHeader:
    """RomFS header structure."""
    def __init__(self, data):
        if len(data) < ROMFS_HEADER_SIZE:
            raise ValueError(f"RomFS header too small: {len(data)} < {ROMFS_HEADER_SIZE}")
        
        self.header_size = int.from_bytes(data[0x0:0x8], 'little')
        self.dir_hash_table_offset = int.from_bytes(data[0x8:0x10], 'little')
        self.dir_hash_table_size = int.from_bytes(data[0x10:0x18], 'little')
        self.dir_meta_table_offset = int.from_bytes(data[0x18:0x20], 'little')
        self.dir_meta_table_size = int.from_bytes(data[0x20:0x28], 'little')
        self.file_hash_table_offset = int.from_bytes(data[0x28:0x30], 'little')
        self.file_hash_table_size = int.from_bytes(data[0x30:0x38], 'little')
        self.file_meta_table_offset = int.from_bytes(data[0x38:0x40], 'little')
        self.file_meta_table_size = int.from_bytes(data[0x40:0x48], 'little')
        self.data_offset = int.from_bytes(data[0x48:0x50], 'little')


class RomfsDirEntry:
    """RomFS directory entry."""
    def __init__(self, data, offset=0):
        self._data = data
        self._offset = offset
        
        self.parent = int.from_bytes(data[offset+0x0:offset+0x4], 'little')
        self.sibling = int.from_bytes(data[offset+0x4:offset+0x8], 'little')
        self.child = int.from_bytes(data[offset+0x8:offset+0xC], 'little')
        self.file = int.from_bytes(data[offset+0xC:offset+0x10], 'little')
        self.hash = int.from_bytes(data[offset+0x10:offset+0x14], 'little')
        self.name_size = int.from_bytes(data[offset+0x14:offset+0x18], 'little')
        
        name_end = offset + 0x18 + self.name_size
        self.name = data[offset+0x18:name_end].decode('utf-8', errors='ignore')
        
        # Calculate entry size for proper alignment
        self.entry_size = ((0x18 + self.name_size + 3) // 4) * 4


class RomfsFileEntry:
    """RomFS file entry."""
    def __init__(self, data, offset=0):
        self._data = data
        self._offset = offset
        
        self.parent = int.from_bytes(data[offset+0x0:offset+0x4], 'little')
        self.sibling = int.from_bytes(data[offset+0x4:offset+0x8], 'little')
        self.offset = int.from_bytes(data[offset+0x8:offset+0x10], 'little')
        self.size = int.from_bytes(data[offset+0x10:offset+0x18], 'little')
        self.hash = int.from_bytes(data[offset+0x18:offset+0x1C], 'little')
        self.name_size = int.from_bytes(data[offset+0x1C:offset+0x20], 'little')
        
        name_end = offset + 0x20 + self.name_size
        self.name = data[offset+0x20:name_end].decode('utf-8', errors='ignore')
        
        # Calculate entry size for proper alignment
        self.entry_size = ((0x20 + self.name_size + 3) // 4) * 4


class RomfsContext:
    """RomFS processing context (mirrors hactools romfs_ctx_t)."""
    def __init__(self, romfs_data, output_path=None, verbose=False):
        self.romfs_data = romfs_data
        self.output_path = Path(output_path) if output_path else None
        self.verbose = verbose
        self.romfs_offset = 0
        
        # Parse header
        self.header = RomfsHeader(romfs_data[0x0:0x50])
        
        # Load directory and file caches
        dir_offset = self.header.dir_meta_table_offset
        dir_size = self.header.dir_meta_table_size
        self.directories = romfs_data[dir_offset:dir_offset + dir_size]
        
        file_offset = self.header.file_meta_table_offset
        file_size = self.header.file_meta_table_size
        self.files = romfs_data[file_offset:file_offset + file_size]
    
    def get_direntry(self, offset):
        """Get directory entry at given offset."""
        if offset == ROMFS_ENTRY_EMPTY or offset >= len(self.directories):
            return None
        return RomfsDirEntry(self.directories, offset)
    
    def get_fentry(self, offset):
        """Get file entry at given offset."""
        if offset == ROMFS_ENTRY_EMPTY or offset >= len(self.files):
            return None
        return RomfsFileEntry(self.files, offset)


def romfs_visit_file(ctx, file_offset, dir_path):
    """Visit and process a file entry and its siblings (mirrors hactools romfs_visit_file)."""
    while file_offset != ROMFS_ENTRY_EMPTY:
        entry = ctx.get_fentry(file_offset)
        if entry is None:
            break
        
        # Build relative path
        rel_path = dir_path / entry.name if entry.name else dir_path
        
        # Extract file
        file_start = ctx.header.data_offset + entry.offset
        file_end = file_start + entry.size
        
        if ctx.output_path:
            # Build full path and create parent directories
            full_path = ctx.output_path / rel_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            if ctx.verbose:
                print(f"Extracting {rel_path}...")
            with open(full_path, 'wb') as f:
                f.write(ctx.romfs_data[file_start:file_end])
        else:
            if ctx.verbose:
                print(f"rom:/{rel_path}")
        
        file_offset = entry.sibling


def romfs_visit_dir(ctx, dir_offset, parent_path):
    """Recursively visit and process directory entries (mirrors hactools romfs_visit_dir)."""
    entry = ctx.get_direntry(dir_offset)
    if entry is None:
        return
    
    # Build relative path
    rel_path = parent_path / entry.name if entry.name else parent_path
    
    # Create directory if extracting
    if ctx.output_path:
        full_path = ctx.output_path / rel_path
        full_path.mkdir(parents=True, exist_ok=True)
    
    # Process files in this directory
    if entry.file != ROMFS_ENTRY_EMPTY:
        romfs_visit_file(ctx, entry.file, rel_path)
    
    # Process child directories
    if entry.child != ROMFS_ENTRY_EMPTY:
        romfs_visit_dir(ctx, entry.child, rel_path)
    
    # Process sibling directories
    if entry.sibling != ROMFS_ENTRY_EMPTY:
        romfs_visit_dir(ctx, entry.sibling, parent_path)


def romfs_print(ctx):
    """Print RomFS information."""
    print("RomFS Information:")
    print(f"  Header Size: 0x{ctx.header.header_size:X}")
    print(f"  Dir Hash Table Offset: 0x{ctx.header.dir_hash_table_offset:X}")
    print(f"  Dir Hash Table Size: 0x{ctx.header.dir_hash_table_size:X}")
    print(f"  Dir Meta Table Offset: 0x{ctx.header.dir_meta_table_offset:X}")
    print(f"  Dir Meta Table Size: 0x{ctx.header.dir_meta_table_size:X}")
    print(f"  File Hash Table Offset: 0x{ctx.header.file_hash_table_offset:X}")
    print(f"  File Hash Table Size: 0x{ctx.header.file_hash_table_size:X}")
    print(f"  File Meta Table Offset: 0x{ctx.header.file_meta_table_offset:X}")
    print(f"  File Meta Table Size: 0x{ctx.header.file_meta_table_size:X}")
    print(f"  Data Offset: 0x{ctx.header.data_offset:X}")


def romfs_process(romfs_data, output_path=None, list_only=False, print_info=False):
    """Process RomFS - main entry point (mirrors hactools romfs_process)."""
    # Create context - only set output_path if not in list_only mode
    if list_only:
        ctx = RomfsContext(romfs_data, output_path=None, verbose=print_info)
    else:
        ctx = RomfsContext(romfs_data, output_path=output_path, verbose=print_info)
    
    # Print info if requested
    if print_info:
        romfs_print(ctx)
    
    # List or extract starting from root
    root_path = Path("")
    romfs_visit_dir(ctx, 0, root_path)

def extract_file_from_romfs(romfs_data: bytes, filename: str) -> bytes:
    """
    Extract a specific file from RomFS data.
    
    Args:
        romfs_data: Complete RomFS section data
        filename: Filename to extract (e.g., "control.nacp")
    
    Returns:
        File contents as bytes, or None if not found
    """
    ROMFS_ENTRY_EMPTY = 0xFFFFFFFF
    ROMFS_HEADER_SIZE = 0x50
    
    if len(romfs_data) < ROMFS_HEADER_SIZE:
        return None
    
    # Parse header
    header_size = int.from_bytes(romfs_data[0x0:0x8], 'little')
    dir_meta_offset = int.from_bytes(romfs_data[0x18:0x20], 'little')
    dir_meta_size = int.from_bytes(romfs_data[0x20:0x28], 'little')
    file_meta_offset = int.from_bytes(romfs_data[0x38:0x40], 'little')
    file_meta_size = int.from_bytes(romfs_data[0x40:0x48], 'little')
    data_offset = int.from_bytes(romfs_data[0x48:0x50], 'little')
    
    # Extract metadata sections
    dir_meta = romfs_data[dir_meta_offset:dir_meta_offset + dir_meta_size]
    file_meta = romfs_data[file_meta_offset:file_meta_offset + file_meta_size]
    
    # Normalise: strip leading slash, split into parts if a path was given
    filename = filename.lstrip('/')
    path_parts = filename.split('/') if '/' in filename else None

    def extract_at(file_offset):
        f_data_offset = int.from_bytes(file_meta[file_offset+0x8:file_offset+0x10], 'little')
        f_size = int.from_bytes(file_meta[file_offset+0x10:file_offset+0x18], 'little')
        data_start = data_offset + f_data_offset
        return romfs_data[data_start:data_start + f_size]

    def find_by_name(dir_offset):
        """Depth-first search for bare filename anywhere in the tree."""
        if dir_offset == ROMFS_ENTRY_EMPTY or dir_offset >= len(dir_meta):
            return None

        sibling   = int.from_bytes(dir_meta[dir_offset+0x4:dir_offset+0x8], 'little')
        child     = int.from_bytes(dir_meta[dir_offset+0x8:dir_offset+0xC], 'little')
        file_entry = int.from_bytes(dir_meta[dir_offset+0xC:dir_offset+0x10], 'little')

        if file_entry != ROMFS_ENTRY_EMPTY:
            fo = file_entry
            while fo != ROMFS_ENTRY_EMPTY and fo < len(file_meta):
                f_sibling   = int.from_bytes(file_meta[fo+0x4:fo+0x8], 'little')
                f_name_size = int.from_bytes(file_meta[fo+0x1C:fo+0x20], 'little')
                f_name = file_meta[fo+0x20:fo+0x20+f_name_size].decode('utf-8', errors='ignore')
                if f_name == filename:
                    return extract_at(fo)
                fo = f_sibling

        if child != ROMFS_ENTRY_EMPTY:
            result = find_by_name(child)
            if result is not None:
                return result

        if sibling != ROMFS_ENTRY_EMPTY:
            result = find_by_name(sibling)
            if result is not None:
                return result

        return None

    def find_dir_child(dir_offset, name):
        """Walk child+sibling links to find a subdirectory named `name`."""
        cur = int.from_bytes(dir_meta[dir_offset+0x8:dir_offset+0xC], 'little')  # first child
        while cur != ROMFS_ENTRY_EMPTY and cur < len(dir_meta):
            name_size = int.from_bytes(dir_meta[cur+0x14:cur+0x18], 'little')
            dir_name  = dir_meta[cur+0x18:cur+0x18+name_size].decode('utf-8', errors='ignore')
            if dir_name == name:
                return cur
            cur = int.from_bytes(dir_meta[cur+0x4:cur+0x8], 'little')  # sibling
        return None

    def find_file_in_dir(dir_offset, name):
        """Walk file entries in a directory to find a file named `name`."""
        fo = int.from_bytes(dir_meta[dir_offset+0xC:dir_offset+0x10], 'little')  # first file
        while fo != ROMFS_ENTRY_EMPTY and fo < len(file_meta):
            f_name_size = int.from_bytes(file_meta[fo+0x1C:fo+0x20], 'little')
            f_name = file_meta[fo+0x20:fo+0x20+f_name_size].decode('utf-8', errors='ignore')
            if f_name == name:
                return extract_at(fo)
            fo = int.from_bytes(file_meta[fo+0x4:fo+0x8], 'little')  # sibling
        return None

    def find_by_path(parts):
        """Navigate directories for each component then find the file."""
        cur_dir = 0  # root
        for part in parts[:-1]:
            cur_dir = find_dir_child(cur_dir, part)
            if cur_dir is None:
                return None
        return find_file_in_dir(cur_dir, parts[-1])

    if path_parts is None:
        return find_by_name(0)
    else:
        return find_by_path(path_parts)