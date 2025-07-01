import struct
import sys

MAGIC_BKTR = 0x52544B42

class BktrHeader:
    def __init__(self, data):
        if len(data) < 32:
            raise ValueError("Data too short for BktrHeader")
        self.offset, self.size, self.magic, self.version, self.num_entries, self.reserved = struct.unpack('<QQIIII', data[:32])
        if self.magic != MAGIC_BKTR:
            raise ValueError("Invalid BKTR magic")

class BktrRelocationEntry:
    def __init__(self, data):
        if len(data) < 20:
            raise ValueError("Data too short for BktrRelocationEntry")
        self.virt_offset, self.phys_offset, self.is_patch = struct.unpack('<QQI', data)

class BktrRelocationBucket:
    SIZE = 0x4000
    ENTRY_SIZE = 20
    MAX_ENTRIES = 0x3FF0 // ENTRY_SIZE  # 818

    def __init__(self, data):
        if len(data) != self.SIZE:
            raise ValueError(f"Invalid size for BktrRelocationBucket: {len(data)}")
        self.index, self.num_entries, self.virtual_offset_end = struct.unpack('<IIQ', data[:16])
        self.entries = []
        offset = 16
        for i in range(self.num_entries):
            entry_data = data[offset:offset + self.ENTRY_SIZE]
            self.entries.append(BktrRelocationEntry(entry_data))
            offset += self.ENTRY_SIZE

class BktrRelocationBlock:
    HEADER_SIZE = 0x4000
    OFFSETS_COUNT = 0x3FF0 // 8  # 2046

    def __init__(self, data, entry_count):
        header_data = data[:self.HEADER_SIZE]
        self.index, self.num_buckets, self.total_size = struct.unpack('<IIQ', header_data[:16])
        offsets_format = '<' + 'Q' * self.OFFSETS_COUNT
        self.bucket_virtual_offsets = list(struct.unpack(offsets_format, header_data[16:16 + 8 * self.OFFSETS_COUNT]))
        self.start_offset = self.bucket_virtual_offsets[0]
        self.buckets = []
        buckets_offset = self.HEADER_SIZE
        for _ in range(self.num_buckets):
            bucket_data = data[buckets_offset:buckets_offset + BktrRelocationBucket.SIZE]
            self.buckets.append(BktrRelocationBucket(bucket_data))
            buckets_offset += BktrRelocationBucket.SIZE
        # Note: entry_count is used for potential future L2 support, but assuming no L2 for now

def bktr_get_relocation_bucket(block, i):
    return block.buckets[i]

def bktr_get_relocation(block, offset):
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
    # Binary search
    low = 0
    high = bucket.num_entries - 1
    while low <= high:
        mid = (low + high) // 2
        if bucket.entries[mid].virt_offset > offset:
            high = mid - 1
        else:
            if mid == bucket.num_entries - 1 or bucket.entries[mid + 1].virt_offset > offset:
                return bucket.entries[mid]
            low = mid + 1
    print(f"Failed to find offset {offset:012x} in BKTR relocation table!", file=sys.stderr)
    sys.exit(1)

class BktrSubsectionEntry:
    def __init__(self, data):
        if len(data) < 16:
            raise ValueError("Data too short for BktrSubsectionEntry")
        self.offset, self._0x8, self.ctr_val = struct.unpack('<QII', data)

class BktrSubsectionBucket:
    SIZE = 0x4000
    ENTRY_SIZE = 16
    MAX_ENTRIES = 0x3FF0 // ENTRY_SIZE  # 1023

    def __init__(self, data):
        if len(data) != self.SIZE:
            raise ValueError(f"Invalid size for BktrSubsectionBucket: {len(data)}")
        self.index, self.num_entries, self.physical_offset_end = struct.unpack('<IIQ', data[:16])
        self.entries = []
        offset = 16
        for i in range(self.num_entries):
            entry_data = data[offset:offset + self.ENTRY_SIZE]
            self.entries.append(BktrSubsectionEntry(entry_data))
            offset += self.ENTRY_SIZE

class BktrSubsectionBlock:
    HEADER_SIZE = 0x4000
    OFFSETS_COUNT = 0x3FF0 // 8  # 2046

    def __init__(self, data, entry_count):
        header_data = data[:self.HEADER_SIZE]
        self.index, self.num_buckets, self.total_size = struct.unpack('<IIQ', header_data[:16])
        offsets_format = '<' + 'Q' * self.OFFSETS_COUNT
        self.bucket_physical_offsets = list(struct.unpack(offsets_format, header_data[16:16 + 8 * self.OFFSETS_COUNT]))
        self.start_offset = self.bucket_physical_offsets[0]
        self.buckets = []
        buckets_offset = self.HEADER_SIZE
        for _ in range(self.num_buckets):
            bucket_data = data[buckets_offset:buckets_offset + BktrSubsectionBucket.SIZE]
            self.buckets.append(BktrSubsectionBucket(bucket_data))
            buckets_offset += BktrSubsectionBucket.SIZE
        # Note: entry_count is used for potential future L2 support, but assuming no L2 for now

def bktr_get_subsection_bucket(block, i):
    return block.buckets[i]

def bktr_get_subsection(block, offset):
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
    # Binary search
    low = 0
    high = bucket.num_entries - 1
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