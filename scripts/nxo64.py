#!/usr/bin/env python3

# The following is adapted from https://github.com/reswitched/loaders/blob/master/nxo64.py
#
# ===========================================================================================
#
# Copyright 2017-2026 Reswitched Team
#
# Permission to use, copy, modify, and/or distribute this software for any purpose with or
# without fee is hereby granted, provided that the above copyright notice and this permission
# notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
# SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
# THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
# CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE
# OR PERFORMANCE OF THIS SOFTWARE.

from struct import calcsize, unpack, unpack_from, pack
from typing import Union, Tuple, BinaryIO
import hashlib

# pip install lz4
import lz4.block

uncompress = lz4.block.decompress

# KIP1 format offsets and constants
KIP1_HEADER_SIZE = 0x100
KIP1_MAGIC = b'KIP1'
KIP1_TEXT_OFFSET = 0x20
KIP1_RO_OFFSET = 0x30
KIP1_DATA_OFFSET = 0x40
KIP1_FLAGS_OFFSET = 0x1F
KIP1_COMPRESSION_FLAGS_MASK = 0xF8
KIP1_SEGMENT_COMPRESSED_SIZE_OFFSET = 0x28

# NSO0 format offsets and constants
NSO_HEADER_SIZE = 0x100
NSO_MAGIC = b'NSO0'
NSO_FLAGS_OFFSET = 0x0C
NSO_SEGMENTS_OFFSET = 0x10
NSO_SEGMENT_SIZE = 0x10
NSO_COMPRESSED_SIZES_OFFSET = 0x60
NSO_TEXT_COMPRESS_FLAG = 1
NSO_RO_COMPRESS_FLAG = 2
NSO_DATA_COMPRESS_FLAG = 4
NSO_COMPRESSION_FLAGS_MASK = 0xF8

# Segment indices
SEGMENT_TEXT = 0
SEGMENT_RO = 1
SEGMENT_DATA = 2
NUM_SEGMENTS = 3

def read_file(filename: str) -> bytes:
    """Read entire file into bytes."""
    with open(filename, 'rb') as f:
        data = f.read()
    return data

def write_file(filename: str, data: Union[bytes, bytearray]) -> None:
    """Write bytes/bytearray to file."""
    with open(filename, 'wb') as f:
        f.write(data)

def kip1_blz_decompress(compressed: bytes, decompressed_size: int) -> bytes:
    """Decompress KIP1 BLZ-compressed data.
    
    Args:
        compressed: Compressed data buffer
        decompressed_size: Target decompressed size
        
    Returns:
        Decompressed data
        
    Raises:
        IndexError: If compression is out of bounds
    """
    uncompressed_additional_size = unpack_from('<I', compressed, -4)[0]
    header_size = unpack_from('<I', compressed, -8)[0]
    compressed_and_header_size = unpack_from('<I', compressed, -12)[0]
    
    compressed_start = len(compressed) - compressed_and_header_size
    compressed_offset = compressed_and_header_size - header_size
    out_offset = compressed_and_header_size + uncompressed_additional_size
    
    out = bytearray(decompressed_size)
    out[0:len(compressed)] = compressed
    
    while out_offset > 0:
        compressed_offset -= 1
        control = out[compressed_start + compressed_offset]
        
        for i in range(8):
            if (control & 0x80) > 0:
                if compressed_offset < 2:
                    raise IndexError("Compression out of bounds!")
                
                compressed_offset -= 2
                
                segment_value = (out[compressed_start + compressed_offset + 1] << 8) | out[compressed_start + compressed_offset]
                segment_size = ((segment_value >> 12) & 0xF) + 3
                segment_offset = (segment_value & 0x0FFF) + 3
                
                if out_offset < segment_size:
                    segment_size = out_offset
                
                out_offset -= segment_size
                
                for j in range(segment_size):
                    out[compressed_start + out_offset + j] = out[compressed_start + out_offset + j + segment_offset]
            else:
                if compressed_offset < 1:
                    raise IndexError("Compression out of bounds!")
                
                out_offset -= 1
                compressed_offset -= 1
                out[compressed_start + out_offset] = out[compressed_start + compressed_offset]
            
            control <<= 1
            
            if out_offset == 0:
                break
    
    return bytes(out)

class BinFile(object):
    """Binary file wrapper for reading struct-formatted data."""
    
    def __init__(self, li: BinaryIO) -> None:
        self._f = li

    def read(self, arg: Union[str, int, None]) -> Union[bytes, int, Tuple]:
        """Read and unpack data.
        
        Args:
            arg: Format string (e.g., '4s', 'I'), byte count (int), or None for all
            
        Returns:
            Unpacked value(s) or raw bytes
        """
        if isinstance(arg, str):
            fmt = '<' + arg
            size = calcsize(fmt)
            raw = self._f.read(size)
            out = unpack(fmt, raw)
            if len(out) == 1:
                return out[0]
            return out
        elif arg is None:
            return self._f.read()
        else:
            out = self._f.read(arg)
            return out

    def read_from(self, arg: Union[str, int], offset: int) -> Union[bytes, int, Tuple]:
        """Read data from specific offset without changing file position.
        
        Args:
            arg: Format string or byte count
            offset: File offset to read from
            
        Returns:
            Unpacked value(s) or raw bytes
        """
        old = self.tell()
        try:
            self.seek(offset)
            out = self.read(arg)
        finally:
            self.seek(old)
        return out

    def seek(self, off: int) -> None:
        """Seek to offset."""
        self._f.seek(off)

    def close(self) -> None:
        """Close file."""
        self._f.close()

    def tell(self) -> int:
        """Get current file position."""
        return self._f.tell()

def decompress_kip(fileobj: BinaryIO) -> bytes:
    """Decompress KIP1 executable file.
    
    Decompresses all three segments (text, read-only, data) and updates
    the header to reflect the decompressed sizes and clear compression flags.
    
    Args:
        fileobj: File object positioned at start of KIP1 file
        
    Returns:
        Fully decompressed KIP1 file with updated header
        
    Raises:
        Exception: If magic number is not 'KIP1'
    """
    f = BinFile(fileobj)

    if f.read_from('4s', 0) != KIP1_MAGIC:
        raise Exception('Invalid KIP magic')

    tloc, tsize, tfilesize = f.read_from('3I', KIP1_TEXT_OFFSET)
    rloc, rsize, rfilesize = f.read_from('3I', KIP1_RO_OFFSET)
    dloc, dsize, dfilesize = f.read_from('3I', KIP1_DATA_OFFSET)

    text = kip1_blz_decompress(f.read_from(tfilesize, KIP1_HEADER_SIZE), tsize)
    ro   = kip1_blz_decompress(f.read_from(rfilesize, KIP1_HEADER_SIZE + tfilesize), rsize)
    data = kip1_blz_decompress(f.read_from(dfilesize, KIP1_HEADER_SIZE + tfilesize + rfilesize), dsize)

    text = text.ljust(tsize, b'\x00')
    ro   = ro.ljust(rsize, b'\x00')
    data = data.ljust(dsize, b'\x00')

    orig_header = f.read_from(KIP1_HEADER_SIZE, 0)
    new_header = bytearray(orig_header)

    # Clear compression flags (lowest 3 bits)
    flags_byte = new_header[KIP1_FLAGS_OFFSET]
    new_flags_byte = flags_byte & KIP1_COMPRESSION_FLAGS_MASK
    new_header[KIP1_FLAGS_OFFSET] = new_flags_byte

    # Update compressed sizes to decompressed sizes
    new_header[KIP1_SEGMENT_COMPRESSED_SIZE_OFFSET:KIP1_SEGMENT_COMPRESSED_SIZE_OFFSET+4] = pack('<I', tsize)
    new_header[KIP1_SEGMENT_COMPRESSED_SIZE_OFFSET+0x10:KIP1_SEGMENT_COMPRESSED_SIZE_OFFSET+0x14] = pack('<I', rsize)
    new_header[KIP1_SEGMENT_COMPRESSED_SIZE_OFFSET+0x20:KIP1_SEGMENT_COMPRESSED_SIZE_OFFSET+0x24] = pack('<I', dsize)

    full = bytearray(new_header)
    full += text
    full += ro
    full += data

    return bytes(full)

def decompress_nso(fileobj: BinaryIO) -> bytes:
    """Decompress NSO0 executable file.
    
    Decompresses all three segments (text, read-only, data) using LZ4
    if needed, and updates the header to reflect the decompressed sizes
    and clear compression flags.
    
    Args:
        fileobj: File object positioned at start of NSO0 file
        
    Returns:
        Fully decompressed NSO0 file with updated header
        
    Raises:
        Exception: If magic number is not 'NSO0'
    """
    f = BinFile(fileobj)

    if f.read_from('4s', 0) != NSO_MAGIC:
        raise Exception('Invalid NSO magic')

    orig_header = f.read_from(NSO_HEADER_SIZE, 0)

    flags = unpack_from('<I', orig_header, NSO_FLAGS_OFFSET)[0]
    segments = [unpack_from('<IIII', orig_header, NSO_SEGMENTS_OFFSET + i*NSO_SEGMENT_SIZE) for i in range(NUM_SEGMENTS)]
    compressed_sizes = unpack_from('<III', orig_header, NSO_COMPRESSED_SIZES_OFFSET)

    toff, tloc, tsize, talign = segments[0]
    roff, rloc, rsize, roalign = segments[1]
    doff, dloc, dsize, dalign = segments[2]

    tfilesize, rfilesize, dfilesize = compressed_sizes

    text_compr = bool(flags & NSO_TEXT_COMPRESS_FLAG)
    ro_compr = bool(flags & NSO_RO_COMPRESS_FLAG)
    data_compr = bool(flags & NSO_DATA_COMPRESS_FLAG)

    text_content = f.read_from(tfilesize if tfilesize > 0 else tsize, toff)
    ro_content = f.read_from(rfilesize if rfilesize > 0 else rsize, roff)
    data_content = f.read_from(dfilesize if dfilesize > 0 else dsize, doff)

    text = text_content if not (text_compr and tfilesize > 0) else uncompress(text_content, uncompressed_size=tsize)
    ro = ro_content if not (ro_compr and rfilesize > 0) else uncompress(ro_content, uncompressed_size=rsize)
    data = data_content if not (data_compr and dfilesize > 0) else uncompress(data_content, uncompressed_size=dsize)

    text = text.ljust(tsize, b'\x00')
    ro = ro.ljust(rsize, b'\x00')
    data = data.ljust(dsize, b'\x00')

    new_header = bytearray(orig_header)
    new_flags = flags & NSO_COMPRESSION_FLAGS_MASK
    new_header[NSO_FLAGS_OFFSET:NSO_FLAGS_OFFSET+4] = pack('<I', new_flags)

    for i, seg_size in enumerate([tsize, rsize, dsize]):
        dst_off = unpack_from('<I', orig_header, NSO_SEGMENTS_OFFSET + 0x4 + i*NSO_SEGMENT_SIZE)[0]
        file_off = dst_off + NSO_HEADER_SIZE
        new_header[NSO_SEGMENTS_OFFSET + i*NSO_SEGMENT_SIZE : NSO_SEGMENTS_OFFSET + 0x4 + i*NSO_SEGMENT_SIZE] = pack('<I', file_off)
        new_header[NSO_COMPRESSED_SIZES_OFFSET + i*4 : NSO_COMPRESSED_SIZES_OFFSET + (i+1)*4] = pack('<I', seg_size)

    new_header[0x1C:0x20] = pack('<I', NSO_HEADER_SIZE)
    new_header[0x2C:0x30] = pack('<I', 0)
    ends = [unpack_from('<I', new_header, NSO_SEGMENTS_OFFSET + i*NSO_SEGMENT_SIZE)[0] + [tsize, rsize, dsize][i] for i in range(NUM_SEGMENTS)]
    full_size = max(ends)

    full = bytearray(full_size)
    full[0:NSO_HEADER_SIZE] = new_header

    full[segments[0][1] + NSO_HEADER_SIZE : segments[0][1] + NSO_HEADER_SIZE + tsize] = text
    full[segments[1][1] + NSO_HEADER_SIZE : segments[1][1] + NSO_HEADER_SIZE + rsize] = ro
    full[segments[2][1] + NSO_HEADER_SIZE : segments[2][1] + NSO_HEADER_SIZE + dsize] = data

    return bytes(full)