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
Bucket Tree (BKTR) storage support for NCA sections.

Supports:
  - Indirect storage (patch NCAs): maps virtual offsets to base or patch data
  - AesCtrEx storage (patch NCAs): subsection CTR generation values
  - Sparse storage (base NCAs): maps virtual offsets to physical data in the
    same NCA, or zero-fill. Uses virtual offsets for AES-CTR IV construction.

Sparse is implemented as Indirect-with-a-twist:
  storage_index 0 -> Regular substorage (same NCA, virtual-offset CTR)
  storage_index 1 -> ZeroStorage
"""

from __future__ import annotations

import struct
import sys
from enum import IntEnum
from typing import Callable, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAGIC_BKTR = 0x52544B42  # "BKTR" little-endian as u32
BKTR_MAGIC_BYTES = b"BKTR"

BKTR_NODE_HEADER_SIZE = 0x10
BKTR_NODE_SIZE = 0x4000

BKTR_INDIRECT_ENTRY_SIZE = 0x14
BKTR_AES_CTR_EX_ENTRY_SIZE = 0x10
BKTR_COMPRESSED_ENTRY_SIZE = 0x18

BKTR_OFFSETS_PER_NODE = (BKTR_NODE_SIZE - BKTR_NODE_HEADER_SIZE) // 8  # 2046


class StorageType(IntEnum):
    INDIRECT = 0
    AES_CTR_EX = 1
    COMPRESSED = 2
    SPARSE = 3


class IndirectStorageIndex(IntEnum):
    ORIGINAL = 0  # base / same-NCA physical data
    PATCH = 1     # AesCtrEx (patch) or ZeroStorage (sparse)


# ---------------------------------------------------------------------------
# Low-level structures
# ---------------------------------------------------------------------------

class BktrHeader:
    """NcaBucketTreeHeader embedded in NcaBucketInfo (0x10 bytes)."""

    def __init__(self, data: bytes):
        if len(data) < 0x10:
            raise ValueError("Data too short for BktrHeader")
        self.magic, self.version, self.num_entries, self.reserved = struct.unpack(
            "<IIII", data[:0x10]
        )
        if self.magic != MAGIC_BKTR:
            raise ValueError(f"Invalid BKTR magic: 0x{self.magic:08X}")

    @classmethod
    def from_bucket_info(cls, data: bytes) -> "BktrHeader":
        """Parse header from a 0x20-byte NcaBucketInfo (offset 0x10)."""
        return cls(data[0x10:0x20])


class BucketInfo:
    """NcaBucketInfo: offset + size + header (0x20 bytes)."""

    def __init__(self, data: bytes):
        if len(data) < 0x20:
            raise ValueError("Data too short for BucketInfo")
        self.offset, self.size = struct.unpack("<QQ", data[:0x10])
        self.header = BktrHeader(data[0x10:0x20])


class IndirectEntry:
    """BucketTreeIndirectStorageEntry (0x14 bytes)."""

    __slots__ = ("virt_offset", "phys_offset", "storage_index")

    def __init__(self, data: bytes):
        if len(data) < BKTR_INDIRECT_ENTRY_SIZE:
            raise ValueError("Data too short for IndirectEntry")
        self.virt_offset, self.phys_offset, self.storage_index = struct.unpack(
            "<QQI", data[:BKTR_INDIRECT_ENTRY_SIZE]
        )

    def __repr__(self) -> str:
        return (
            f"IndirectEntry(virt=0x{self.virt_offset:X}, "
            f"phys=0x{self.phys_offset:X}, idx={self.storage_index})"
        )


class AesCtrExEntry:
    """BucketTreeAesCtrExStorageEntry (0x10 bytes)."""

    __slots__ = ("offset", "encryption", "generation")

    def __init__(self, data: bytes):
        if len(data) < BKTR_AES_CTR_EX_ENTRY_SIZE:
            raise ValueError("Data too short for AesCtrExEntry")
        self.offset, enc_res, self.generation = struct.unpack(
            "<QII", data[:BKTR_AES_CTR_EX_ENTRY_SIZE]
        )
        # enc_res packs encryption (u8) + reserved[3]
        self.encryption = enc_res & 0xFF


# ---------------------------------------------------------------------------
# Compatibility wrappers (legacy SGG API)
# ---------------------------------------------------------------------------

class BktrRelocationEntry:
    """Legacy alias for IndirectEntry used by existing patch code."""

    def __init__(self, data: bytes):
        if len(data) < 20:
            raise ValueError("Data too short for BktrRelocationEntry")
        self.virt_offset, self.phys_offset, self.is_patch = struct.unpack("<QQI", data)


class BktrRelocationBucket:
    SIZE = BKTR_NODE_SIZE
    ENTRY_SIZE = BKTR_INDIRECT_ENTRY_SIZE
    MAX_ENTRIES = 0x3FF0 // ENTRY_SIZE  # 818

    def __init__(self, data: bytes):
        if len(data) != self.SIZE:
            raise ValueError(f"Invalid size for BktrRelocationBucket: {len(data)}")
        self.index, self.num_entries, self.virtual_offset_end = struct.unpack(
            "<IIQ", data[:16]
        )
        self.entries: List[BktrRelocationEntry] = []
        offset = 16
        for _ in range(self.num_entries):
            self.entries.append(BktrRelocationEntry(data[offset:offset + self.ENTRY_SIZE]))
            offset += self.ENTRY_SIZE


class BktrRelocationBlock:
    HEADER_SIZE = BKTR_NODE_SIZE
    OFFSETS_COUNT = BKTR_OFFSETS_PER_NODE

    def __init__(self, data: bytes, entry_count: int = 0):
        header_data = data[: self.HEADER_SIZE]
        self.index, self.num_buckets, self.total_size = struct.unpack(
            "<IIQ", header_data[:16]
        )
        offsets_format = "<" + "Q" * self.OFFSETS_COUNT
        self.bucket_virtual_offsets = list(
            struct.unpack(offsets_format, header_data[16 : 16 + 8 * self.OFFSETS_COUNT])
        )
        self.start_offset = self.bucket_virtual_offsets[0]
        self.buckets: List[BktrRelocationBucket] = []
        buckets_offset = self.HEADER_SIZE
        for _ in range(self.num_buckets):
            bucket_data = data[buckets_offset : buckets_offset + BktrRelocationBucket.SIZE]
            self.buckets.append(BktrRelocationBucket(bucket_data))
            buckets_offset += BktrRelocationBucket.SIZE


def bktr_get_relocation_bucket(block: BktrRelocationBlock, i: int) -> BktrRelocationBucket:
    return block.buckets[i]


def bktr_get_relocation(block: BktrRelocationBlock, offset: int) -> BktrRelocationEntry:
    if offset > block.total_size or offset < block.start_offset:
        print("Too big offset looked up in BKTR relocation table!", file=sys.stderr)
        sys.exit(1)
    bucket_num = 0
    for i in range(1, block.num_buckets):
        if block.bucket_virtual_offsets[i] <= offset:
            bucket_num += 1
    bucket = bktr_get_relocation_bucket(block, bucket_num)
    if bucket.num_entries == 1:
        return bucket.entries[0]
    low, high = 0, bucket.num_entries - 1
    while low <= high:
        mid = (low + high) // 2
        if bucket.entries[mid].virt_offset > offset:
            high = mid - 1
        else:
            if (
                mid == bucket.num_entries - 1
                or bucket.entries[mid + 1].virt_offset > offset
            ):
                return bucket.entries[mid]
            low = mid + 1
    print(f"Failed to find offset {offset:012x} in BKTR relocation table!", file=sys.stderr)
    sys.exit(1)


class BktrSubsectionEntry:
    def __init__(self, data: bytes):
        if len(data) < 16:
            raise ValueError("Data too short for BktrSubsectionEntry")
        self.offset, self._0x8, self.ctr_val = struct.unpack("<QII", data)


class BktrSubsectionBucket:
    SIZE = BKTR_NODE_SIZE
    ENTRY_SIZE = 16
    MAX_ENTRIES = 0x3FF0 // ENTRY_SIZE  # 1023

    def __init__(self, data: bytes):
        if len(data) != self.SIZE:
            raise ValueError(f"Invalid size for BktrSubsectionBucket: {len(data)}")
        self.index, self.num_entries, self.physical_offset_end = struct.unpack(
            "<IIQ", data[:16]
        )
        self.entries: List[BktrSubsectionEntry] = []
        offset = 16
        for _ in range(self.num_entries):
            self.entries.append(BktrSubsectionEntry(data[offset:offset + self.ENTRY_SIZE]))
            offset += self.ENTRY_SIZE


class BktrSubsectionBlock:
    HEADER_SIZE = BKTR_NODE_SIZE
    OFFSETS_COUNT = BKTR_OFFSETS_PER_NODE

    def __init__(self, data: bytes, entry_count: int = 0):
        header_data = data[: self.HEADER_SIZE]
        self.index, self.num_buckets, self.total_size = struct.unpack(
            "<IIQ", header_data[:16]
        )
        offsets_format = "<" + "Q" * self.OFFSETS_COUNT
        self.bucket_physical_offsets = list(
            struct.unpack(offsets_format, header_data[16 : 16 + 8 * self.OFFSETS_COUNT])
        )
        self.start_offset = self.bucket_physical_offsets[0]
        self.buckets: List[BktrSubsectionBucket] = []
        buckets_offset = self.HEADER_SIZE
        for _ in range(self.num_buckets):
            bucket_data = data[buckets_offset : buckets_offset + BktrSubsectionBucket.SIZE]
            self.buckets.append(BktrSubsectionBucket(bucket_data))
            buckets_offset += BktrSubsectionBucket.SIZE


def bktr_get_subsection_bucket(block: BktrSubsectionBlock, i: int) -> BktrSubsectionBucket:
    return block.buckets[i]


def bktr_get_subsection(block: BktrSubsectionBlock, offset: int) -> BktrSubsectionEntry:
    if offset > block.total_size or offset < block.start_offset:
        print("Too big offset looked up in BKTR subsection table!", file=sys.stderr)
        sys.exit(1)
    last_bucket = bktr_get_subsection_bucket(block, block.num_buckets - 1)
    if last_bucket.num_entries > 0 and offset >= last_bucket.entries[last_bucket.num_entries - 1].offset:
        return last_bucket.entries[last_bucket.num_entries - 1]
    bucket_num = 0
    for i in range(1, block.num_buckets):
        if block.bucket_physical_offsets[i] <= offset:
            bucket_num += 1
    bucket = bktr_get_subsection_bucket(block, bucket_num)
    if bucket.num_entries == 1:
        return bucket.entries[0]
    low, high = 0, bucket.num_entries - 1
    while low <= high:
        mid = (low + high) // 2
        if bucket.entries[mid].offset > offset:
            high = mid - 1
        else:
            if mid == bucket.num_entries - 1 or bucket.entries[mid + 1].offset > offset:
                return bucket.entries[mid]
            low = mid + 1
    print(f"Failed to find offset {offset:012x} in BKTR subsection table!", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Modern BucketTree table (Indirect / Sparse)
# ---------------------------------------------------------------------------

class BucketTreeOffsetNode:
    """First 0x4000-byte segment of a BucketTreeTable."""

    def __init__(self, data: bytes):
        if len(data) < BKTR_NODE_SIZE:
            raise ValueError("Offset node data too short")
        self.index, self.count, self.offset = struct.unpack("<IIQ", data[:0x10])
        # count = number of entry nodes; offset = virtual end (total_size)
        n = min(self.count + 1, BKTR_OFFSETS_PER_NODE)  # offsets[0..count]
        fmt = "<" + "Q" * BKTR_OFFSETS_PER_NODE
        all_offsets = list(struct.unpack(fmt, data[0x10:0x10 + 8 * BKTR_OFFSETS_PER_NODE]))
        self.offsets = all_offsets  # full array; valid range is [0 .. count]


class BucketTreeEntryNode:
    """0x4000-byte entry node holding Indirect or AesCtrEx entries."""

    def __init__(self, data: bytes, entry_size: int = BKTR_INDIRECT_ENTRY_SIZE):
        if len(data) < BKTR_NODE_SIZE:
            raise ValueError("Entry node data too short")
        self.index, self.count, self.offset = struct.unpack("<IIQ", data[:0x10])
        self.entry_size = entry_size
        self.entries = []
        pos = 0x10
        for _ in range(self.count):
            chunk = data[pos : pos + entry_size]
            if entry_size == BKTR_INDIRECT_ENTRY_SIZE:
                self.entries.append(IndirectEntry(chunk))
            elif entry_size == BKTR_AES_CTR_EX_ENTRY_SIZE:
                self.entries.append(AesCtrExEntry(chunk))
            pos += entry_size


class BucketTreeTable:
    """
    Full decrypted Bucket Tree table for Indirect or Sparse storage.

    Layout:
      [OffsetNode 0x4000]
      [EntryNode 0x4000] * offset_node.count
    """

    def __init__(self, data: bytes, entry_size: int = BKTR_INDIRECT_ENTRY_SIZE):
        if len(data) < BKTR_NODE_SIZE:
            raise ValueError("BucketTree table data too short")
        self.entry_size = entry_size
        self.offset_node = BucketTreeOffsetNode(data[:BKTR_NODE_SIZE])
        self.entry_nodes: List[BucketTreeEntryNode] = []
        pos = BKTR_NODE_SIZE
        for i in range(self.offset_node.count):
            if pos + BKTR_NODE_SIZE > len(data):
                # Truncated table — stop at what we have
                break
            self.entry_nodes.append(
                BucketTreeEntryNode(data[pos : pos + BKTR_NODE_SIZE], entry_size)
            )
            pos += BKTR_NODE_SIZE

        self.start_offset = (
            self.offset_node.offsets[0] if self.offset_node.offsets else 0
        )
        # Virtual end is stored in the offset-node header's `offset` field
        self.end_offset = self.offset_node.offset

    @property
    def num_entry_nodes(self) -> int:
        return len(self.entry_nodes)

    def find_entry(self, virtual_offset: int) -> Tuple[IndirectEntry, int]:
        """
        Locate the IndirectEntry covering `virtual_offset`.

        Returns:
            (entry, next_virt_offset) where next_virt_offset is the start of
            the following entry, or self.end_offset if this is the last one.
        """
        if virtual_offset < self.start_offset or virtual_offset >= self.end_offset:
            raise ValueError(
                f"Virtual offset 0x{virtual_offset:X} outside storage range "
                f"[0x{self.start_offset:X}, 0x{self.end_offset:X})"
            )

        # Select entry-node via the offset array
        node_idx = 0
        for i in range(1, self.offset_node.count + 1):
            if i < len(self.offset_node.offsets) and self.offset_node.offsets[i] <= virtual_offset:
                node_idx = i
            else:
                break

        if node_idx >= len(self.entry_nodes):
            node_idx = len(self.entry_nodes) - 1

        node = self.entry_nodes[node_idx]
        if node.count == 0:
            raise ValueError(f"Empty entry node {node_idx}")

        def _eoff(e):
            # IndirectEntry.virt_offset or AesCtrExEntry.offset
            return getattr(e, "virt_offset", None) or getattr(e, "offset", 0)

        # Binary search within the node
        entries = node.entries
        low, high = 0, node.count - 1
        found = 0
        while low <= high:
            mid = (low + high) // 2
            if _eoff(entries[mid]) > virtual_offset:
                high = mid - 1
            else:
                found = mid
                if mid == node.count - 1 or _eoff(entries[mid + 1]) > virtual_offset:
                    break
                low = mid + 1

        entry = entries[found]

        # Determine next virtual offset
        if found + 1 < node.count:
            next_virt = _eoff(entries[found + 1])
        elif node_idx + 1 < len(self.entry_nodes) and self.entry_nodes[node_idx + 1].count > 0:
            next_virt = _eoff(self.entry_nodes[node_idx + 1].entries[0])
        else:
            next_virt = self.end_offset

        return entry, next_virt


# ---------------------------------------------------------------------------
# Sparse / Indirect storage reader
# ---------------------------------------------------------------------------

# Type alias: callback(phys_offset, size, virtual_offset) -> bytes
PhysicalReadFn = Callable[[int, int, int], bytes]


class SparseStorage:
    """
    Sparse (or plain Indirect) BucketTree storage.

    For Sparse:
      - storage_index ORIGINAL (0): read from the same NCA using *virtual*
        offsets for the AES-CTR IV.
      - storage_index PATCH (1): zero-fill (ZeroStorage).

    For Indirect (patch):
      - storage_index ORIGINAL (0): read from a base NCA storage (optional).
      - storage_index PATCH (1): read from AesCtrEx / patch data.

    The `physical_read` callback is responsible for performing the actual
    NCA section decryption at the requested physical offset.  For sparse
    reads it receives the virtual offset so the CTR IV can be built correctly.
    """

    def __init__(
        self,
        table: BucketTreeTable,
        physical_read: PhysicalReadFn,
        storage_type: StorageType = StorageType.SPARSE,
        base_read: Optional[PhysicalReadFn] = None,
    ):
        self.table = table
        self.physical_read = physical_read
        self.storage_type = storage_type
        self.base_read = base_read  # for Indirect ORIGINAL when base is available
        self.is_sparse = storage_type == StorageType.SPARSE

    @property
    def start_offset(self) -> int:
        return self.table.start_offset

    @property
    def end_offset(self) -> int:
        return self.table.end_offset

    @property
    def size(self) -> int:
        return self.end_offset - self.start_offset

    def read(self, offset: int, size: int) -> bytes:
        """
        Read `size` bytes starting at virtual `offset`.

        Returns a contiguous buffer; holes are zero-filled for sparse storage.
        """
        if size == 0:
            return b""
        if offset < self.start_offset or offset + size > self.end_offset:
            raise ValueError(
                f"Read [0x{offset:X}, 0x{offset + size:X}) outside storage "
                f"[0x{self.start_offset:X}, 0x{self.end_offset:X})"
            )

        out = bytearray(size)
        remaining = size
        cur = offset
        written = 0

        while remaining > 0:
            entry, next_virt = self.table.find_entry(cur)
            # How much of this entry we still need
            entry_remaining = next_virt - cur
            chunk = min(remaining, entry_remaining)

            # Physical offset within the entry's mapped region
            phys_off = entry.phys_offset + (cur - entry.virt_offset)

            if entry.storage_index == IndirectStorageIndex.ORIGINAL:
                if self.is_sparse:
                    # Same NCA, virtual-offset CTR
                    data = self.physical_read(phys_off, chunk, cur)
                elif self.base_read is not None:
                    data = self.base_read(phys_off, chunk, cur)
                else:
                    # No base available — zero-fill (incomplete patch without base)
                    data = b"\x00" * chunk
                out[written : written + chunk] = data
            else:
                # PATCH index
                if self.is_sparse:
                    # ZeroStorage
                    # (already zero-initialized, nothing to do)
                    pass
                else:
                    # AesCtrEx / patch data via physical_read
                    data = self.physical_read(phys_off, chunk, cur)
                    out[written : written + chunk] = data

            cur += chunk
            written += chunk
            remaining -= chunk

        return bytes(out)

    def read_all(self) -> bytes:
        """Materialise the entire virtual storage image."""
        return self.read(self.start_offset, self.size)


def parse_sparse_table(decrypted_table_data: bytes) -> BucketTreeTable:
    """Parse a decrypted sparse/indirect BucketTree table."""
    return BucketTreeTable(decrypted_table_data, entry_size=BKTR_INDIRECT_ENTRY_SIZE)


def make_aes_ctr_ex_ctr(section_ctr: bytes, generation: int, byte_offset: int) -> bytes:
    """
    Build a 16-byte AES-CTR IV for AesCtrEx (matches hactool nca_update_ctr_ex /
    nxdumptool aes128CtrUpdatePartialCtrEx).

    - Bytes 0-3: retained from section upper IV
    - Bytes 4-7: generation (little-endian placement)
    - Bytes 8-15: (byte_offset >> 4) as big-endian via reverse write
    """
    ctr = bytearray(section_ctr[:16] if len(section_ctr) >= 16 else section_ctr.ljust(16, b"\x00"))
    g = generation & 0xFFFFFFFF
    for j in range(4):
        ctr[0x8 - j - 1] = g & 0xFF
        g >>= 8
    o = byte_offset >> 4
    for j in range(8):
        ctr[0x10 - j - 1] = o & 0xFF
        o >>= 8
    return bytes(ctr)


def parse_aes_ctr_ex_table(decrypted_table_data: bytes) -> BucketTreeTable:
    """Parse an AesCtrEx BKTR table (entry size 0x10)."""
    return BucketTreeTable(decrypted_table_data, entry_size=BKTR_AES_CTR_EX_ENTRY_SIZE)


def find_aes_ctr_ex_entry(table: BucketTreeTable, offset: int):
    """
    Locate the AesCtrEx entry covering `offset`.
    Returns (AesCtrExEntry, next_offset).
    """
    if not table.entry_nodes:
        raise ValueError("Empty AesCtrEx table")
    # Linear search across entry nodes (tables are small)
    all_entries = []
    for node in table.entry_nodes:
        all_entries.extend(node.entries)
    if not all_entries:
        raise ValueError("No AesCtrEx entries")
    # Entries sorted by offset
    chosen = all_entries[0]
    next_off = table.end_offset
    for i, e in enumerate(all_entries):
        if e.offset <= offset:
            chosen = e
            next_off = all_entries[i + 1].offset if i + 1 < len(all_entries) else table.end_offset
        else:
            break
    return chosen, next_off
