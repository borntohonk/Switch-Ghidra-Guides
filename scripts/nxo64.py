#!/usr/bin/env python3

# The following is adapted from https://github.com/reswitched/loaders/blob/master/nxo64.py
#
# ===========================================================================================
#
# Copyright 2017 Reswitched Team
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

import os
from struct import calcsize, unpack, unpack_from
from typing import Union

# pip install lz4
import lz4.block

uncompress = lz4.block.decompress

def read_file(filename: str) -> bytes:
    with open(filename, 'rb') as f:
        data = f.read()
    return data

def write_file(filename: str, data: Union[bytes, bytearray]) -> None:
    with open(filename, 'wb') as f:
        f.write(data)

def kip1_blz_decompress(compressed):
    (compressed_size, init_index, uncompressed_addl_size) = unpack_from('<3I', compressed, -0xC)
    decompressed = bytearray(compressed[:] + b'\x00' * uncompressed_addl_size)
    decompressed_size = len(decompressed)
    if len(compressed) != compressed_size:
        assert len(compressed) > compressed_size
        compressed = compressed[len(compressed) - compressed_size:]
    if not (compressed_size + uncompressed_addl_size):
        return b''
    index = compressed_size - init_index
    outindex = decompressed_size
    while outindex > 0:
        index -= 1
        control = compressed[index]
        for i in range(8):
            if control & 0x80:
                index -= 2
                segmentoffset = compressed[index] | (
                    compressed[index + 1] << 8)
                segmentsize = ((segmentoffset >> 12) & 0xF) + 3
                segmentoffset &= 0x0FFF
                segmentoffset += 2
                for j in range(segmentsize):
                    data = decompressed[outindex + segmentoffset]
                    outindex -= 1
                    decompressed[outindex] = data
            else:
                outindex -= 1
                index -= 1
                decompressed[outindex] = compressed[index]
            control <<= 1
            control &= 0xFF
            if not outindex:
                break
    return decompressed

class BinFile(object):
    def __init__(self, li):
        self._f = li

    def read(self, arg):
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

    def read_from(self, arg, offset):
        old = self.tell()
        try:
            self.seek(offset)
            out = self.read(arg)
        finally:
            self.seek(old)
        return out

    def seek(self, off):
        self._f.seek(off)

    def close(self):
        self._f.close()

    def tell(self):
        return self._f.tell()

def decompress_kip(fileobj):
    f = BinFile(fileobj)

    if f.read_from('4s', 0) != b'KIP1':
        raise Exception('Invalid KIP magic')

    tloc, tsize, tfilesize = f.read_from('3I', 0x20)
    rloc, rsize, rfilesize = f.read_from('3I', 0x30)
    dloc, dsize, dfilesize = f.read_from('3I', 0x40)

    hoff = 0x00
    hfilesize = 0x100
    toff = 0x100
    roff = toff + tfilesize
    doff = roff + rfilesize

    header = f.read_from(hfilesize, hoff)
    text = kip1_blz_decompress(f.read_from(tfilesize, toff))
    ro = kip1_blz_decompress(f.read_from(rfilesize, roff))
    data = kip1_blz_decompress(f.read_from(dfilesize, doff))

    full = header
    full += text
    if rloc >= len(full):
        full += b'\0' * (rloc - len(full))
    else:
        full = full[:rloc]
    full += ro
    if dloc >= len(full):
        full += b'\0' * (dloc - len(full))
    else:
        full = full[:dloc]
    full += data

    return full

def decompress_nso(fileobj):
    f = BinFile(fileobj)

    if f.read_from('4s', 0) != b'NSO0':
        raise Exception('Invalid NSO magic')

    toff, tloc, tsize = f.read_from('3I', 0x10)
    roff, rloc, rsize = f.read_from('3I', 0x20)
    doff, dloc, dsize = f.read_from('3I', 0x30)

    tfilesize, rfilesize, dfilesize = f.read_from('3I', 0x60)
    bsssize = f.read_from('I', 0x3C)

    text = uncompress(f.read_from(tfilesize, toff), uncompressed_size=tsize)
    ro = uncompress(f.read_from(rfilesize, roff), uncompressed_size=rsize)
    data = uncompress(f.read_from(dfilesize, doff), uncompressed_size=dsize)

    full = text
    if rloc >= len(full):
        full += b'\0' * (rloc - len(full))
    else:
        full = full[:rloc]
    full += ro
    if dloc >= len(full):
        full += b'\0' * (dloc - len(full))
    else:
        full = full[:dloc]
    full += data

    return full
