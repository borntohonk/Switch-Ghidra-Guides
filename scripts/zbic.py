#!/usr/bin/env python3
"""
Pure-Python ZBIC → standard zstd frame converter.

Nintendo ZBIC (firmware 22.0.0+) is zstd with two changes:
  1. Magic 0x4349425A ("ZBIC") instead of 0xFD2FB528
  2. FSE normalized-count tables use Binary Interpolative Coding
     (FSE_readNCount_bic) instead of the usual bit-packed format

This module rewrites ZBIC frames into ordinary zstd frames so stock
python-zstandard can decompress them.  No extra packages required.
"""

from __future__ import annotations

from typing import List, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
ZBIC_MAGIC = b"\x5a\x42\x49\x43"  # little-endian "ZBIC"

FSE_MIN_TABLELOG = 5
FSE_MAX_TABLELOG = 12

# Precomputed (middle, first, last) index triples.  Copied from
# Atmosphere / kinnay zstd.c  BIC_table[0x300].
_BIC_TABLE = [
    0x80, 0x0, 0x100, 0xC0, 0x80, 0x100, 0xE0, 0xC0,
    0x100, 0xF0, 0xE0, 0x100, 0xF8, 0xF0, 0x100, 0xFC,
    0xF8, 0x100, 0xFE, 0xFC, 0x100, 0xFF, 0xFE, 0x100,
    0xFD, 0xFC, 0xFE, 0xFA, 0xF8, 0xFC, 0xFB, 0xFA,
    0xFC, 0xF9, 0xF8, 0xFA, 0xF4, 0xF0, 0xF8, 0xF6,
    0xF4, 0xF8, 0xF7, 0xF6, 0xF8, 0xF5, 0xF4, 0xF6,
    0xF2, 0xF0, 0xF4, 0xF3, 0xF2, 0xF4, 0xF1, 0xF0,
    0xF2, 0xE8, 0xE0, 0xF0, 0xEC, 0xE8, 0xF0, 0xEE,
    0xEC, 0xF0, 0xEF, 0xEE, 0xF0, 0xED, 0xEC, 0xEE,
    0xEA, 0xE8, 0xEC, 0xEB, 0xEA, 0xEC, 0xE9, 0xE8,
    0xEA, 0xE4, 0xE0, 0xE8, 0xE6, 0xE4, 0xE8, 0xE7,
    0xE6, 0xE8, 0xE5, 0xE4, 0xE6, 0xE2, 0xE0, 0xE4,
    0xE3, 0xE2, 0xE4, 0xE1, 0xE0, 0xE2, 0xD0, 0xC0,
    0xE0, 0xD8, 0xD0, 0xE0, 0xDC, 0xD8, 0xE0, 0xDE,
    0xDC, 0xE0, 0xDF, 0xDE, 0xE0, 0xDD, 0xDC, 0xDE,
    0xDA, 0xD8, 0xDC, 0xDB, 0xDA, 0xDC, 0xD9, 0xD8,
    0xDA, 0xD4, 0xD0, 0xD8, 0xD6, 0xD4, 0xD8, 0xD7,
    0xD6, 0xD8, 0xD5, 0xD4, 0xD6, 0xD2, 0xD0, 0xD4,
    0xD3, 0xD2, 0xD4, 0xD1, 0xD0, 0xD2, 0xC8, 0xC0,
    0xD0, 0xCC, 0xC8, 0xD0, 0xCE, 0xCC, 0xD0, 0xCF,
    0xCE, 0xD0, 0xCD, 0xCC, 0xCE, 0xCA, 0xC8, 0xCC,
    0xCB, 0xCA, 0xCC, 0xC9, 0xC8, 0xCA, 0xC4, 0xC0,
    0xC8, 0xC6, 0xC4, 0xC8, 0xC7, 0xC6, 0xC8, 0xC5,
    0xC4, 0xC6, 0xC2, 0xC0, 0xC4, 0xC3, 0xC2, 0xC4,
    0xC1, 0xC0, 0xC2, 0xA0, 0x80, 0xC0, 0xB0, 0xA0,
    0xC0, 0xB8, 0xB0, 0xC0, 0xBC, 0xB8, 0xC0, 0xBE,
    0xBC, 0xC0, 0xBF, 0xBE, 0xC0, 0xBD, 0xBC, 0xBE,
    0xBA, 0xB8, 0xBC, 0xBB, 0xBA, 0xBC, 0xB9, 0xB8,
    0xBA, 0xB4, 0xB0, 0xB8, 0xB6, 0xB4, 0xB8, 0xB7,
    0xB6, 0xB8, 0xB5, 0xB4, 0xB6, 0xB2, 0xB0, 0xB4,
    0xB3, 0xB2, 0xB4, 0xB1, 0xB0, 0xB2, 0xA8, 0xA0,
    0xB0, 0xAC, 0xA8, 0xB0, 0xAE, 0xAC, 0xB0, 0xAF,
    0xAE, 0xB0, 0xAD, 0xAC, 0xAE, 0xAA, 0xA8, 0xAC,
    0xAB, 0xAA, 0xAC, 0xA9, 0xA8, 0xAA, 0xA4, 0xA0,
    0xA8, 0xA6, 0xA4, 0xA8, 0xA7, 0xA6, 0xA8, 0xA5,
    0xA4, 0xA6, 0xA2, 0xA0, 0xA4, 0xA3, 0xA2, 0xA4,
    0xA1, 0xA0, 0xA2, 0x90, 0x80, 0xA0, 0x98, 0x90,
    0xA0, 0x9C, 0x98, 0xA0, 0x9E, 0x9C, 0xA0, 0x9F,
    0x9E, 0xA0, 0x9D, 0x9C, 0x9E, 0x9A, 0x98, 0x9C,
    0x9B, 0x9A, 0x9C, 0x99, 0x98, 0x9A, 0x94, 0x90,
    0x98, 0x96, 0x94, 0x98, 0x97, 0x96, 0x98, 0x95,
    0x94, 0x96, 0x92, 0x90, 0x94, 0x93, 0x92, 0x94,
    0x91, 0x90, 0x92, 0x88, 0x80, 0x90, 0x8C, 0x88,
    0x90, 0x8E, 0x8C, 0x90, 0x8F, 0x8E, 0x90, 0x8D,
    0x8C, 0x8E, 0x8A, 0x88, 0x8C, 0x8B, 0x8A, 0x8C,
    0x89, 0x88, 0x8A, 0x84, 0x80, 0x88, 0x86, 0x84,
    0x88, 0x87, 0x86, 0x88, 0x85, 0x84, 0x86, 0x82,
    0x80, 0x84, 0x83, 0x82, 0x84, 0x81, 0x80, 0x82,
    0x40, 0x0, 0x80, 0x60, 0x40, 0x80, 0x70, 0x60,
    0x80, 0x78, 0x70, 0x80, 0x7C, 0x78, 0x80, 0x7E,
    0x7C, 0x80, 0x7F, 0x7E, 0x80, 0x7D, 0x7C, 0x7E,
    0x7A, 0x78, 0x7C, 0x7B, 0x7A, 0x7C, 0x79, 0x78,
    0x7A, 0x74, 0x70, 0x78, 0x76, 0x74, 0x78, 0x77,
    0x76, 0x78, 0x75, 0x74, 0x76, 0x72, 0x70, 0x74,
    0x73, 0x72, 0x74, 0x71, 0x70, 0x72, 0x68, 0x60,
    0x70, 0x6C, 0x68, 0x70, 0x6E, 0x6C, 0x70, 0x6F,
    0x6E, 0x70, 0x6D, 0x6C, 0x6E, 0x6A, 0x68, 0x6C,
    0x6B, 0x6A, 0x6C, 0x69, 0x68, 0x6A, 0x64, 0x60,
    0x68, 0x66, 0x64, 0x68, 0x67, 0x66, 0x68, 0x65,
    0x64, 0x66, 0x62, 0x60, 0x64, 0x63, 0x62, 0x64,
    0x61, 0x60, 0x62, 0x50, 0x40, 0x60, 0x58, 0x50,
    0x60, 0x5C, 0x58, 0x60, 0x5E, 0x5C, 0x60, 0x5F,
    0x5E, 0x60, 0x5D, 0x5C, 0x5E, 0x5A, 0x58, 0x5C,
    0x5B, 0x5A, 0x5C, 0x59, 0x58, 0x5A, 0x54, 0x50,
    0x58, 0x56, 0x54, 0x58, 0x57, 0x56, 0x58, 0x55,
    0x54, 0x56, 0x52, 0x50, 0x54, 0x53, 0x52, 0x54,
    0x51, 0x50, 0x52, 0x48, 0x40, 0x50, 0x4C, 0x48,
    0x50, 0x4E, 0x4C, 0x50, 0x4F, 0x4E, 0x50, 0x4D,
    0x4C, 0x4E, 0x4A, 0x48, 0x4C, 0x4B, 0x4A, 0x4C,
    0x49, 0x48, 0x4A, 0x44, 0x40, 0x48, 0x46, 0x44,
    0x48, 0x47, 0x46, 0x48, 0x45, 0x44, 0x46, 0x42,
    0x40, 0x44, 0x43, 0x42, 0x44, 0x41, 0x40, 0x42,
    0x20, 0x0, 0x40, 0x30, 0x20, 0x40, 0x38, 0x30,
    0x40, 0x3C, 0x38, 0x40, 0x3E, 0x3C, 0x40, 0x3F,
    0x3E, 0x40, 0x3D, 0x3C, 0x3E, 0x3A, 0x38, 0x3C,
    0x3B, 0x3A, 0x3C, 0x39, 0x38, 0x3A, 0x34, 0x30,
    0x38, 0x36, 0x34, 0x38, 0x37, 0x36, 0x38, 0x35,
    0x34, 0x36, 0x32, 0x30, 0x34, 0x33, 0x32, 0x34,
    0x31, 0x30, 0x32, 0x28, 0x20, 0x30, 0x2C, 0x28,
    0x30, 0x2E, 0x2C, 0x30, 0x2F, 0x2E, 0x30, 0x2D,
    0x2C, 0x2E, 0x2A, 0x28, 0x2C, 0x2B, 0x2A, 0x2C,
    0x29, 0x28, 0x2A, 0x24, 0x20, 0x28, 0x26, 0x24,
    0x28, 0x27, 0x26, 0x28, 0x25, 0x24, 0x26, 0x22,
    0x20, 0x24, 0x23, 0x22, 0x24, 0x21, 0x20, 0x22,
    0x10, 0x0, 0x20, 0x18, 0x10, 0x20, 0x1C, 0x18,
    0x20, 0x1E, 0x1C, 0x20, 0x1F, 0x1E, 0x20, 0x1D,
    0x1C, 0x1E, 0x1A, 0x18, 0x1C, 0x1B, 0x1A, 0x1C,
    0x19, 0x18, 0x1A, 0x14, 0x10, 0x18, 0x16, 0x14,
    0x18, 0x17, 0x16, 0x18, 0x15, 0x14, 0x16, 0x12,
    0x10, 0x14, 0x13, 0x12, 0x14, 0x11, 0x10, 0x12,
    0x8, 0x0, 0x10, 0xC, 0x8, 0x10, 0xE, 0xC,
    0x10, 0xF, 0xE, 0x10, 0xD, 0xC, 0xE, 0xA,
    0x8, 0xC, 0xB, 0xA, 0xC, 0x9, 0x8, 0xA,
    0x4, 0x0, 0x8, 0x6, 0x4, 0x8, 0x7, 0x6,
    0x8, 0x5, 0x4, 0x6, 0x2, 0x0, 0x4, 0x3,
    0x2, 0x4, 0x1, 0x0, 0x2, 0x0, 0x0, 0x1,
]
assert len(_BIC_TABLE) == 0x300


class ZbicError(Exception):
    pass


# ---------------------------------------------------------------------------
# BIC NCount decoder  (port of FSE_readNCount_bic)
# ---------------------------------------------------------------------------
def fse_read_ncount_bic(
    header: bytes, max_symbol_value: int = 255
) -> Tuple[List[int], int, int, int]:
    """
    Decode a BIC-encoded FSE NCount header.

    Returns (normalized_counter, max_sv, table_log, bytes_consumed)
    """
    if not header:
        raise ZbicError("empty NCount header")

    bit0 = header[0]
    raw_data_size = bit0 & 0x7F
    use_low_prob = bit0 >> 7
    if raw_data_size >= len(header):
        raise ZbicError(
            "NCount rawDataSize %d >= buffer %d" % (raw_data_size, len(header))
        )
    data_size = raw_data_size + 1
    if data_size > len(header):
        raise ZbicError(
            "NCount dataSize %d > buffer %d" % (data_size, len(header))
        )

    payload = header[:data_size]
    MASK64 = (1 << 64) - 1

    def pull(acc: int, rds: int) -> Tuple[int, int]:
        """Match the C for-loop over U64:
            for (acc = init; rawDataSize; acc = *(ip + rawDataSize--) | (acc << 8))
                if ((acc >> 32) & 0xFFFFFFFF) >= 0x100) break;
        Body checks high bits *before* the increment consumes another byte.
        All arithmetic is masked to 64 bits to match C U64 wraparound.
        """
        acc &= MASK64
        while rds:
            if ((acc >> 32) & 0xFFFFFFFF) >= 0x100:
                break
            rds -= 1
            acc = (payload[rds + 1] | ((acc << 8) & MASK64)) & MASK64
        return acc, rds

    i, rds = 0, raw_data_size
    i, rds = pull(i, rds)

    encoded_char_table = i // 0x34
    j = i % 0x34
    encoded_char_table, rds = pull(encoded_char_table, rds)

    char_num = j + 1
    if char_num > max_symbol_value:
        raise ZbicError("charNum too large (%d > %d)" % (char_num, max_symbol_value))

    char_table = encoded_char_table >> 3
    k = encoded_char_table & 0x7
    char_table, rds = pull(char_table, rds)

    table_log = k + 5
    remaining = 1 << table_log

    l = char_table // remaining
    l, rds = pull(l, rds)

    char_last = (char_table % remaining) + 1
    if use_low_prob:
        char_last = char_num + (char_table % remaining) + 2

    n = char_num
    n |= n >> 1
    n |= n >> 2
    n |= n >> 4
    n |= n >> 8
    n |= n >> 16
    char_num_next_pow2 = n + 1
    if char_num_next_pow2 > 0xFF:
        raise ZbicError("charNumNextPow2 overflow")

    bic_counter = [0] * 257
    bic_counter[char_num_next_pow2] = char_last

    if char_num_next_pow2 != 0xFF:
        bic_count = 0
        while bic_count < char_num_next_pow2:
            off = 3 * (bic_count - char_num_next_pow2 + 0x100)
            mid = _BIC_TABLE[off]
            first = _BIC_TABLE[off + 1]
            last = _BIC_TABLE[off + 2]
            bc_first = bic_counter[first]
            bc_last = bic_counter[last]

            if bc_first == bc_last:
                idx = first + 1
                while idx < last:
                    bic_counter[idx] = bc_first
                    idx += 1
            else:
                denom = bc_last - bc_first + 1
                # U64 division / modulo
                l &= MASK64
                l_next = l // denom
                l_entry = l % denom
                l = l_next
                l, rds = pull(l, rds)
                bic_counter[mid] = l_entry + bc_first

            bic_count += 1

    normalized: List[int] = [0] * (char_num + 1)
    if char_num != 0xFF:
        acc = 0
        rem = remaining
        for s in range(char_num + 1):
            # Match C: short bcCount = *(short *)bc++  (LE low 16 bits, signed)
            bc = bic_counter[s + 1] & 0xFFFF
            if bc >= 0x8000:
                bc -= 0x10000
            dist = bc - acc
            count = dist - use_low_prob
            acc += dist
            normalized[s] = count
            rem -= abs(count)
        if rem != 0:
            nonzero = [(i, c) for i, c in enumerate(normalized) if c]
            raise ZbicError(
                "NCount remaining mismatch (%d) tableLog=%d charNum=%d "
                "useLowProb=%d dataSize=%d header=%s nonzero=%s"
                % (
                    rem,
                    table_log,
                    char_num,
                    use_low_prob,
                    data_size,
                    header[: min(data_size, 48)].hex(),
                    nonzero[:30],
                )
            )

    if rds != 0:
        raise ZbicError(
            "NCount trailing data rds=%d dataSize=%d header=%s"
            % (rds, data_size, header[: min(data_size, 48)].hex())
        )

    return normalized, char_num, table_log, data_size


# ---------------------------------------------------------------------------
# Standard FSE NCount encoder  (port of FSE_writeNCount_generic)
# ---------------------------------------------------------------------------
def fse_write_ncount(normalized: List[int], table_log: int) -> bytes:
    """Port of FSE_writeNCount_generic (zstd)."""
    max_sv = len(normalized) - 1
    out = bytearray()
    bit_stream = 0
    bit_count = 0

    bit_stream += (table_log - FSE_MIN_TABLELOG) << bit_count
    bit_count += 4

    table_size = 1 << table_log
    remaining = table_size + 1
    threshold = table_size
    nb_bits = table_log + 1
    symbol = 0
    alphabet = max_sv + 1
    previous_is_0 = 0

    def flush16() -> None:
        nonlocal bit_stream, bit_count
        if bit_count > 16:
            out.append(bit_stream & 0xFF)
            out.append((bit_stream >> 8) & 0xFF)
            bit_stream >>= 16
            bit_count -= 16

    while symbol < alphabet and remaining > 1:
        if previous_is_0:
            start = symbol
            while symbol < alphabet and normalized[symbol] == 0:
                symbol += 1
            if symbol == alphabet:
                break  # only trailing zeroes
            while symbol >= start + 24:
                start += 24
                bit_stream += 0xFFFF << bit_count
                bit_count += 16
                flush16()
            while symbol >= start + 3:
                start += 3
                bit_stream += 3 << bit_count
                bit_count += 2
            bit_stream += (symbol - start) << bit_count
            bit_count += 2
            previous_is_0 = 0

        count = normalized[symbol]
        symbol += 1
        maxv = (2 * threshold - 1) - remaining
        remaining -= -count if count < 0 else count
        count += 1  # +1 for extra accuracy
        if count >= threshold:
            count += maxv
        bit_stream += count << bit_count
        bit_count += nb_bits
        bit_count -= 1 if count < maxv else 0
        previous_is_0 = 1 if count == 1 else 0
        if remaining < 1:
            raise ZbicError("writeNCount remaining < 1")
        while remaining < threshold:
            nb_bits -= 1
            threshold >>= 1
        flush16()

    if remaining != 1:
        raise ZbicError("writeNCount remaining != 1 (got %d)" % remaining)

    # Final flush: write enough bytes for the remaining bits (not a full
    # 2-byte flush that would then truncate the whole buffer).
    final_bytes = (bit_count + 7) // 8
    if final_bytes >= 1:
        out.append(bit_stream & 0xFF)
    if final_bytes >= 2:
        out.append((bit_stream >> 8) & 0xFF)
    return bytes(out)


def convert_ncount(header: bytes, max_sv: int = 255) -> bytes:
    """BIC NCount header → standard FSE NCount header."""
    global _debug_ncount_dumps
    norm, char_num, table_log, consumed = fse_read_ncount_bic(header, max_sv)
    out = fse_write_ncount(norm, table_log)
    if _DEBUG and _debug_ncount_dumps < 12:
        _debug_ncount_dumps += 1
        # Show non-zero counts so we can spot garbage distributions
        nonzero = [(i, c) for i, c in enumerate(norm) if c]
        weight_sum = sum(abs(c) for c in norm)
        _dbg(
            "  NCount dump #%d: maxSV=%d tableLog=%d consumed=%d written=%d "
            "weight_sum=%d (expect %d) nonzero=%s"
            % (
                _debug_ncount_dumps,
                char_num,
                table_log,
                consumed,
                len(out),
                weight_sum,
                1 << table_log,
                nonzero[:40],
            )
        )
        _dbg("  NCount raw in[%d]: %s" % (consumed, header[:consumed].hex()))
        _dbg("  NCount raw out[%d]: %s" % (len(out), out.hex()))
    return out


# ---------------------------------------------------------------------------
# Frame / block helpers
# ---------------------------------------------------------------------------
def _read_le24(data: bytes, off: int) -> int:
    return data[off] | (data[off + 1] << 8) | (data[off + 2] << 16)


def _write_le24(val: int) -> bytes:
    return bytes((val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF))


def _skip_frame_header(data: bytes, pos: int) -> int:
    """Advance past Frame_Header; *pos* points at Frame_Header_Descriptor."""
    fhd = data[pos]
    pos += 1
    # Window_Descriptor present when Single_Segment_flag is clear
    if (fhd & 0x20) == 0:
        pos += 1
    # Dictionary_ID
    pos += (0, 1, 2, 4)[fhd & 3]
    # Frame_Content_Size
    fcs_bits = fhd >> 6
    if (fhd & 0x20) and fcs_bits == 0:
        pos += 1
    else:
        pos += (0, 2, 4, 8)[fcs_bits]
    return pos


def _rewrite_literals_section(src: bytes, pos: int) -> Tuple[bytes, int]:
    """
    Rewrite the Literals_Section starting at *pos*.
    Returns (rewritten_bytes, new_pos_in_src).

    Only rewrites when an FSE/BIC Huffman weight table is present and
    converted; otherwise the original bytes are copied unchanged so we
    cannot introduce size-field encoding bugs.
    """
    lit_hdr = src[pos]
    lit_type = lit_hdr & 3  # 0=Raw 1=RLE 2=Compressed 3=Treeless
    size_fmt = (lit_hdr >> 2) & 3
    start = pos
    pos += 1

    if lit_type in (0, 1):  # Raw / RLE — no FSE tables
        # Raw/RLE size_format encoding (different from Compressed!)
        if size_fmt in (0, 2):
            regen_size = lit_hdr >> 3
        elif size_fmt == 1:
            regen_size = (lit_hdr >> 4) | (src[pos] << 4)
            pos += 1
        else:
            regen_size = (lit_hdr >> 4) | (src[pos] << 4) | (src[pos + 1] << 12)
            pos += 2
        pos += 1 if lit_type == 1 else regen_size
        return src[start:pos], pos

    # Compressed or Treeless — header encodes both regenerated_size and
    # compressed_size.  Per zstd format / ZSTD_decodeLiteralsBlock:
    #   size_format 00/01: 3-byte header, 10+10 bit sizes
    #                      (00 = single stream, 01 = 4 streams)
    #   size_format 10:    4-byte header, 14+14 bit sizes
    #   size_format 11:    5-byte header, 18+18 bit sizes
    lhc = src[start] | (src[start + 1] << 8) | (src[start + 2] << 16)
    if start + 3 < len(src):
        lhc |= src[start + 3] << 24

    if size_fmt <= 1:
        # 3-byte header total (already consumed 1, need 2 more)
        lh_size = 3
        # lit_size = (lhc >> 4) & 0x3FF  (unused here)
        c_size = (lhc >> 14) & 0x3FF
    elif size_fmt == 2:
        lh_size = 4
        c_size = lhc >> 18
    else:
        lh_size = 5
        c_size = (lhc >> 22) + ((src[start + 4] << 10) if start + 4 < len(src) else 0)

    payload_start = start + lh_size
    section_end = payload_start + c_size
    pos = section_end

    # Treeless has no tree; Compressed may have FSE-compressed weights.
    # HUF_readStats layout when headerByte < 128:
    #   payload[0]           = iSize  (size of FSE-compressed weight block)
    #   payload[1:1+iSize]   = FSE block = NCount header + weight bitstream
    #   payload[1+iSize:]    = jump table (optional) + literal streams
    # We must convert only the NCount and keep the weight bitstream intact.
    if lit_type != 2:
        return src[start:section_end], section_end

    payload = bytearray(src[payload_start:section_end])
    if not payload or payload[0] >= 128:
        # Direct weights or empty — nothing to convert
        return src[start:section_end], section_end

    i_size = payload[0]
    if 1 + i_size > len(payload):
        raise ZbicError("Huffman FSE weight table truncated")
    fse_block = bytes(payload[1 : 1 + i_size])
    rest = bytes(payload[1 + i_size :])

    # Split FSE block into BIC NCount + remaining weight bitstream
    try:
        _norm, _cn, _tlog, nc_size = fse_read_ncount_bic(fse_block, 12)
    except ZbicError as e:
        _dbg("  Huffman NCount parse failed: %s — leaving original" % e)
        return src[start:section_end], section_end

    new_nc = fse_write_ncount(_norm, _tlog)
    weight_bitstream = fse_block[nc_size:]
    new_fse_block = new_nc + weight_bitstream
    if len(new_fse_block) >= 128:
        raise ZbicError("converted Huffman FSE block too large for hSize field")

    new_payload = bytes([len(new_fse_block)]) + new_fse_block + rest
    new_c_size = len(new_payload)
    _dbg(
        "  Huffman FSE block %d -> %d (NCount %d -> %d, bitstream %d)"
        % (i_size, len(new_fse_block), nc_size, len(new_nc), len(weight_bitstream))
    )

    if new_c_size == c_size and new_payload == bytes(payload):
        return src[start:section_end], section_end

    # Size changed — rebuild Literals_Section_Header keeping regenerated_size
    # and encoding the new compressed_size with the same size_format.
    out = bytearray()
    if size_fmt <= 1:
        # 3-byte: [type:2][szfmt:2][regen:10][csize:10]
        regen = (lhc >> 4) & 0x3FF
        if new_c_size > 0x3FF:
            raise ZbicError("new c_size %d too large for size_fmt %d" % (new_c_size, size_fmt))
        packed = (lit_type) | (size_fmt << 2) | (regen << 4) | (new_c_size << 14)
        out.append(packed & 0xFF)
        out.append((packed >> 8) & 0xFF)
        out.append((packed >> 16) & 0xFF)
    elif size_fmt == 2:
        # 4-byte: [type:2][szfmt:2][regen:14][csize:14]
        regen = (lhc >> 4) & 0x3FFF
        if new_c_size > 0x3FFF:
            raise ZbicError("new c_size %d too large for size_fmt 2" % new_c_size)
        packed = (lit_type) | (size_fmt << 2) | (regen << 4) | (new_c_size << 18)
        out.append(packed & 0xFF)
        out.append((packed >> 8) & 0xFF)
        out.append((packed >> 16) & 0xFF)
        out.append((packed >> 24) & 0xFF)
    else:
        # 5-byte: [type:2][szfmt:2][regen:18][csize:18]
        regen = (lhc >> 4) & 0x3FFFF
        if new_c_size > 0x3FFFF:
            raise ZbicError("new c_size %d too large for size_fmt 3" % new_c_size)
        # first 4 bytes hold type+szfmt+regen(18)+csize low 10 bits; 5th has csize high 8
        # csize encoding: (lhc >> 22) + (byte4 << 10), so low 10 bits in bits 22-31 of first 4
        packed = (lit_type) | (size_fmt << 2) | (regen << 4) | ((new_c_size & 0x3FF) << 22)
        out.append(packed & 0xFF)
        out.append((packed >> 8) & 0xFF)
        out.append((packed >> 16) & 0xFF)
        out.append((packed >> 24) & 0xFF)
        out.append((new_c_size >> 10) & 0xFF)

    out.extend(new_payload)
    return bytes(out), section_end


def _rewrite_sequences_section(src: bytes, pos: int, block_end: int) -> Tuple[bytes, int]:
    """
    Rewrite Sequences_Section starting at *pos*.
    Returns (rewritten_bytes, new_pos).
    """
    start = pos
    if pos >= block_end:
        return b"", pos

    # Number_of_Sequences
    seq0 = src[pos]
    pos += 1
    if seq0 < 128:
        nb_seq = seq0
    elif seq0 < 255:
        nb_seq = ((seq0 - 128) << 8) + src[pos]
        pos += 1
    else:
        nb_seq = src[pos] + (src[pos + 1] << 8) + 0x7F00
        pos += 2

    if nb_seq == 0:
        return src[start:pos], pos

    modes = src[pos]
    pos += 1

    out = bytearray(src[start:pos])  # keep nbSeq + modes bytes as-is
    mode_names = {0: "Predef", 1: "RLE", 2: "FSE", 3: "Repeat"}
    table_names = ("LL", "OF", "ML")

    # bits 7-6 LL, 5-4 OF, 3-2 ML
    for ti, (shift, max_sv) in enumerate(((6, 35), (4, 31), (2, 52))):
        mode = (modes >> shift) & 3
        if mode == 2:  # FSE_Compressed → BIC NCount
            # Only the remainder of THIS block is valid input — do not
            # let the BIC decoder read into the next block.
            available = src[pos:block_end]
            if not available:
                raise ZbicError(
                    "seq %s FSE NCount starts past block end" % table_names[ti]
                )
            new_nc = convert_ncount(available, max_sv=max_sv)
            _, _, _, old_sz = fse_read_ncount_bic(available, max_sv)
            if old_sz > len(available):
                raise ZbicError(
                    "seq %s FSE NCount size %d exceeds block remainder %d"
                    % (table_names[ti], old_sz, len(available))
                )
            _dbg("  seq %s FSE NCount %d -> %d bytes"
                 % (table_names[ti], old_sz, len(new_nc)))
            out.extend(new_nc)
            pos += old_sz
        elif mode == 1:  # RLE
            if pos >= block_end:
                raise ZbicError("seq %s RLE past block end" % table_names[ti])
            out.append(src[pos])
            pos += 1
            _dbg("  seq %s RLE" % table_names[ti])
        else:
            _dbg("  seq %s %s" % (table_names[ti], mode_names.get(mode, "?")))

    # remainder of the block is the bit-packed sequences bitstream
    out.extend(src[pos:block_end])
    return bytes(out), block_end


def _rewrite_compressed_block(src: bytes, block_start: int, block_size: int) -> bytes:
    """Return a rewritten compressed-block body (no 3-byte header)."""
    pos = block_start
    end = block_start + block_size

    lit_bytes, pos = _rewrite_literals_section(src, pos)
    seq_bytes, pos = _rewrite_sequences_section(src, pos, end)

    return lit_bytes + seq_bytes


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
# Set ZBIC_DEBUG=1 (or a path) for conversion diagnostics.
# ZBIC_DEBUG=1           → write to zbic_debug.log in cwd
# ZBIC_DEBUG=/tmp/x.log  → write to that path
import os as _os
_DEBUG_RAW = _os.environ.get("ZBIC_DEBUG", "")
_DEBUG = _DEBUG_RAW not in ("", "0", "false", "False")
_DEBUG_PATH = (
    _DEBUG_RAW
    if _DEBUG and _DEBUG_RAW not in ("1", "true", "True", "yes", "Yes")
    else "zbic_debug.log"
)
_debug_fp = None
_debug_ncount_dumps = 0  # limit detailed NCount dumps


def _dbg(msg: str) -> None:
    global _debug_fp
    if not _DEBUG:
        return
    if _debug_fp is None:
        _debug_fp = open(_DEBUG_PATH, "w")
    _debug_fp.write(msg + "\n")
    _debug_fp.flush()


def zbic_to_zstd(compressed: bytes) -> bytes:
    """
    Convert a ZBIC frame into a standard zstd frame.

    Raises ZbicError on malformed input.
    """
    if not compressed.startswith(ZBIC_MAGIC):
        raise ZbicError(
            "not a ZBIC frame (bad magic %s)" % compressed[:4].hex()
        )
    if len(compressed) < 6:
        raise ZbicError("frame too short")

    src = compressed
    out = bytearray()
    out += ZSTD_MAGIC

    # Frame header (unchanged aside from magic)
    pos = 4
    fhd = src[pos]
    hdr_end = _skip_frame_header(src, pos)
    out += src[pos:hdr_end]
    _dbg("frame header: fhd=0x%02x hdr_len=%d single_segment=%d checksum=%d"
         % (fhd, hdr_end - 4, bool(fhd & 0x20), bool(fhd & 0x04)))
    pos = hdr_end

    block_idx = 0
    # Blocks
    while pos + 3 <= len(src):
        bh = _read_le24(src, pos)
        last = bh & 1
        btype = (bh >> 1) & 3
        bsize = bh >> 3
        pos += 3
        _dbg("block %d: type=%d size=%d last=%d off=%d"
             % (block_idx, btype, bsize, last, pos - 3))

        if btype == 0:  # Raw
            out += _write_le24(bh)
            out += src[pos : pos + bsize]
            pos += bsize
        elif btype == 1:  # RLE
            out += _write_le24(bh)
            out += src[pos : pos + 1]
            pos += 1
        elif btype == 2:  # Compressed
            body = _rewrite_compressed_block(src, pos, bsize)
            pos += bsize
            new_bh = (len(body) << 3) | (btype << 1) | last
            out += _write_le24(new_bh)
            out += body
            _dbg("block %d: rewritten body %d -> %d bytes"
                 % (block_idx, bsize, len(body)))
        else:
            raise ZbicError("reserved block type %d" % btype)

        block_idx += 1
        if last:
            break

    # Optional content checksum (4 bytes) — copy remaining
    if pos < len(src):
        _dbg("trailing %d bytes (checksum?)" % (len(src) - pos))
        out += src[pos:]

    _dbg("output frame %d bytes (input was %d)" % (len(out), len(src)))
    return bytes(out)


def decompress(compressed: bytes, max_output_size: int = 0) -> bytes:
    """
    Convenience: convert ZBIC → zstd then decompress with stock zstandard.
    """
    import zstandard as zstd

    frame = zbic_to_zstd(compressed)
    dctx = zstd.ZstdDecompressor()
    if max_output_size:
        return dctx.decompress(frame, max_output_size=max_output_size)
    return dctx.decompress(frame)
