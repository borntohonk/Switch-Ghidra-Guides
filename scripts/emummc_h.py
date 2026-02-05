#!/usr/bin/env python3
"""
emummc_h.py - Extract FS offsets from Switch KIP1 for emummc (21.0.0 tuned)
Produces headers matching Atmosphere-NX emummc/source/FS/offsets/2100*.h
"""

import sys
import re

try:
    from capstone import *
    from capstone.arm64 import *
except ModuleNotFoundError:
    print("capstone required: pip install capstone")
    sys.exit(1)

def page_align_down(addr: int) -> int:
    return addr & ~0xFFF

def sign_extend_21bit(imm: int) -> int:
    if imm & (1 << 20):
        imm |= ~((1 << 21) - 1)
    return imm

def decode_adrp_imm(adrp_bytes: bytes) -> int:
    if len(adrp_bytes) != 4:
        raise ValueError("ADRP must be 4 bytes")
    word = int.from_bytes(adrp_bytes, "little")
    immlo = (word >> 29) & 0b11
    immhi = (word >> 5) & 0x7FFFF
    imm21 = (immhi << 2) | immlo
    return sign_extend_21bit(imm21) << 12

def compute_adrp_base(pc_addr: int, adrp_bytes: bytes) -> int:
    return page_align_down(pc_addr) + decode_adrp_imm(adrp_bytes)

def compute_full_address(
    function_addr: int,
    adrp_pc_offset: int,
    adrp_bytes: bytes,
    add_imm: int = 0,
    final_offset: int = 0
) -> int:
    adrp_addr = function_addr + adrp_pc_offset
    page_base = compute_adrp_base(adrp_addr, adrp_bytes)
    return page_base + add_imm + final_offset

def uintptr_to_int64_c_expr(value: int) -> str:
    u64 = value & 0xFFFFFFFFFFFFFFFF
    i64 = u64 - (1 << 64) if u64 & (1 << 63) else u64
    if -0x100 <= i64 < 0:
        hex_abs = hex(-i64)[2:].upper()
        return f"((uintptr_t)(INT64_C(-0x{hex_abs})))"
    return f"((uintptr_t)(INT64_C({i64})))"

def get_arm_operand(raw_bytes: bytes) -> int:
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for i in md.disasm(raw_bytes, 0):
        if '#' in i.op_str:
            part = i.op_str.split('#')[-1].strip().rstrip(']! \t')
            try:
                return int(part, 0)
            except ValueError:
                pass
    return 0

def get_opcode_reg(raw_bytes: bytes) -> int:
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    for i in md.disasm(raw_bytes, 0):
        mnemonic = i.mnemonic.lower()
        if "adrp" in mnemonic:
            if len(i.operands) > 0 and i.operands[0].type == ARM64_OP_REG:
                reg_enum = i.operands[0].reg
                if ARM64_REG_X0 <= reg_enum <= ARM64_REG_X30:
                    reg_num = reg_enum - ARM64_REG_X0
                    return reg_num
            if ',' in i.op_str:
                reg_part = i.op_str.split(',')[0].strip()
                if reg_part.startswith(('x', 'w')):
                    try:
                        reg_num = int(reg_part[1:])
                        return reg_num
                    except ValueError:
                        pass
    print("[REG DEBUG] Not recognized as ADRP or no reg found")
    return 0

FS_OFFSET_SDMMC_ACCESSOR_GC_PATTERN = "fd7bb.a9f...0..9f...0.......00...8......08.......8........0..0...........0....................................................9.e0............9..0......6..200........9...........0800"
FS_OFFSET_SDMMC_ACCESSOR_SD_PATTERN = "00000000..7.........0.91..0............0....0...........c0035fd6..0.0...............0.....03........0..."
FS_OFFSET_SDMMC_ACCESSOR_NAND_PATTERN = "00000000fd7bb.a9f......9f...0.......00...8......08.......8........0..0...........0........................7...........................9.e0............9..0.........200........9...........0900"

FS_OFFSET_SDMMC_WRAPPER_READ_PATTERN = "fd7bbda9f65701a9f44f02a9fd030091f60300aae003022af303042af403032af50301aac7000094080040f9e103142a"
FS_OFFSET_SDMMC_WRAPPER_WRITE_PATTERN = "fd7bbda9f65701a9f44f02a9fd030091f30304aaf40303aaf503022af603012ab0000094080040f9e103162ae203152a"
FS_OFFSET_RTLD_PATTERN = "0694....0035................................1f0d0071"

FS_OFFSET_CLKRST_SET_MIN_V_CLK_RATE_PATTERN = "ff8300d1fd7b01a9fd430091000040f9e203012a080040f9082540f900013fd6"
FS_OFFSET_LOCK_MUTEX_PATTERN = "fd7bbea9f44f01a9fd03009168d03bd5f30300aa14fd40f908044039..0.00....0..0....0.............60..00"
FS_OFFSET_UNLOCK_MUTEX_PATTERN = "080840b908050071080800b940000054c0035fd61f0800f900600091..1.0014fd7bbda9f50b00f9f44f02a9fd030091"
FS_OFFSET_SDMMC_WRAPPER_CONTROLLER_OPEN_PATTERN = "fd7bbfa9fd030091de000094080040f9011140f9fd7bc1a820001fd600000000fd7bbfa9fd030091d6000094080040f9"
FS_OFFSET_SDMMC_WRAPPER_CONTROLLER_CLOSE_PATTERN = "fd7bbfa9fd030091d6000094080040f9011540f9fd7bc1a820001fd600000000fd7bbda9f65701a9f44f02a9fd030091"
FS_OFFSET_SD_DAS_INIT_PATTERN = "94....0036....00..73....91e00313aa......9468....39..0500..2000805236008052"

NINTENDO_PATH_PATTERNS = [
    "63.8..91.40.00.084.0..91",
    ".3................00...0..0035.20.00.042....91.30.00.0",
    "84....91e0.30191a1c301d102088052",
    "84.0..91e0e30091a14301d1020880",
]

def produce_emummc_h(kip_path: str, firmware: str, prefix: str = ""):
    with open(kip_path, "rb") as f:
        data = f.read()[0x100:]
        hex_data = data.hex()

    def find(pat: str, adjust: int = 0, from_end: bool = False) -> int:
        m = re.search(pat, hex_data)
        if not m:
            print(f"Warning: pattern not found: {pat[:40]}...")
            return 0
        pos = m.end() if from_end else m.start()
        return pos // 2 + adjust

    off_gc    = find(FS_OFFSET_SDMMC_ACCESSOR_GC_PATTERN)
    off_sd    = find(FS_OFFSET_SDMMC_ACCESSOR_SD_PATTERN, 4)
    off_nand  = find(FS_OFFSET_SDMMC_ACCESSOR_NAND_PATTERN, 4)

    off_read  = find(FS_OFFSET_SDMMC_WRAPPER_READ_PATTERN)
    off_write = find(FS_OFFSET_SDMMC_WRAPPER_WRITE_PATTERN)
    off_rtld  = find(FS_OFFSET_RTLD_PATTERN, from_end=True)

    off_clk   = find(FS_OFFSET_CLKRST_SET_MIN_V_CLK_RATE_PATTERN)
    off_lock  = find(FS_OFFSET_LOCK_MUTEX_PATTERN)
    off_unlock = find(FS_OFFSET_UNLOCK_MUTEX_PATTERN)
    off_ctrl_open  = find(FS_OFFSET_SDMMC_WRAPPER_CONTROLLER_OPEN_PATTERN)
    off_ctrl_close = find(FS_OFFSET_SDMMC_WRAPPER_CONTROLLER_CLOSE_PATTERN)
    off_das_init   = find(FS_OFFSET_SD_DAS_INIT_PATTERN, from_end=True)

    bl1 = off_sd + 8
    bl1_target = bl1 + get_arm_operand(data[bl1:bl1+4])

    adrp_sd = bl1_target + 0x30
    adrp_sd_bytes = data[adrp_sd:adrp_sd+4]
    add1_sd = get_arm_operand(data[adrp_sd+4:adrp_sd+8])

    bl2 = bl1_target + 0xc8
    bl2_target = bl2 + get_arm_operand(data[bl2:bl2+4])
    add2_sd = get_arm_operand(data[bl2_target + 0xa0 : bl2_target + 0xa4])

    sd_mutex = compute_full_address(off_sd, 0, adrp_sd_bytes, add1_sd, add2_sd)

    adrp_nand_off = off_nand + 0x20
    adrp_nand_bytes = data[adrp_nand_off:adrp_nand_off+4]
    add1_nand = get_arm_operand(data[adrp_nand_off+4:adrp_nand_off+8])

    tbz_nand = off_nand + 0x18
    tbz_imm = get_arm_operand(data[tbz_nand:tbz_nand+4])
    bl_nand = tbz_nand + tbz_imm + 0x20
    second_func = bl_nand + get_arm_operand(data[bl_nand:bl_nand+4])

    add2_nand = get_arm_operand(data[second_func + 0x98 : second_func + 0x9c])
    active_imm = get_arm_operand(data[second_func + 0xec : second_func + 0xf0])

    nand_mutex = compute_full_address(off_nand, 0, adrp_nand_bytes, add1_nand, add2_nand)
    active_part = compute_full_address(off_nand, 0, adrp_nand_bytes, add1_nand, active_imm)

    das_rel = off_das_init + get_arm_operand(data[off_das_init:off_das_init+4])
    das_adrp = das_rel + 0x50
    das_adrp_bytes = data[das_adrp:das_adrp+4]
    das_add_imm = get_arm_operand(data[das_adrp+4:das_adrp+8])
    das_handle = compute_full_address(das_rel, 0, das_adrp_bytes, das_add_imm)

    rtld_imm = get_arm_operand(data[off_rtld:off_rtld+4])
    rtld_c = uintptr_to_int64_c_expr(rtld_imm)

    n_paths = []

    patterns_n = [
        ("PATH_1", NINTENDO_PATH_PATTERNS[0], False),
        ("PATH_2", NINTENDO_PATH_PATTERNS[1], True),
        ("PATH_3", NINTENDO_PATH_PATTERNS[2], False),
        ("PATH_4", NINTENDO_PATH_PATTERNS[3], False),
    ]

    for name, pat, use_end in patterns_n:
        m = re.search(pat, hex_data)
        if not m:
            print(f"[NINTENDO DEBUG] {name} pattern DID NOT MATCH at all")
            continue

        pos_bytes = m.end() if use_end else m.start()
        off = pos_bytes // 2 - 4

        if off < 0 or off + 4 > len(data):
            print(f"  → Invalid offset (out of bounds)")
            continue

        adrp_bytes = data[off:off+4]

        reg = get_opcode_reg(adrp_bytes)

        if reg > 0:
            n_paths.append((reg, off))
        else:
            print(f"  → Rejected (not valid ADRP reg)")

    guard = f"__FS_{firmware}_{prefix}H__".upper()
    print(f"#ifndef {guard}")
    print(f"#define {guard}\n")

    print("// Accessor vtable getters")
    print(f"#define FS_OFFSET_{firmware}_{prefix}SDMMC_ACCESSOR_GC   0x{off_gc:X}")
    print(f"#define FS_OFFSET_{firmware}_{prefix}SDMMC_ACCESSOR_SD   0x{off_sd:X}")
    print(f"#define FS_OFFSET_{firmware}_{prefix}SDMMC_ACCESSOR_NAND 0x{off_nand:X}\n")

    print("// Hooks")
    print(f"#define FS_OFFSET_{firmware}_{prefix}SDMMC_WRAPPER_READ  0x{off_read:X}")
    print(f"#define FS_OFFSET_{firmware}_{prefix}SDMMC_WRAPPER_WRITE 0x{off_write:X}")
    print(f"#define FS_OFFSET_{firmware}_{prefix}RTLD                0x{off_rtld:X}")
    print(f"#define FS_OFFSET_{firmware}_{prefix}RTLD_DESTINATION    {rtld_c}\n")

    print(f"#define FS_OFFSET_{firmware}_{prefix}CLKRST_SET_MIN_V_CLK_RATE 0x{off_clk:X}\n")

    print("// Misc funcs")
    print(f"#define FS_OFFSET_{firmware}_{prefix}LOCK_MUTEX          0x{off_lock:X}")
    print(f"#define FS_OFFSET_{firmware}_{prefix}UNLOCK_MUTEX        0x{off_unlock:X}\n")

    print(f"#define FS_OFFSET_{firmware}_{prefix}SDMMC_WRAPPER_CONTROLLER_OPEN  0x{off_ctrl_open:X}")
    print(f"#define FS_OFFSET_{firmware}_{prefix}SDMMC_WRAPPER_CONTROLLER_CLOSE 0x{off_ctrl_close:X}\n")

    print("// Misc Data")
    print(f"#define FS_OFFSET_{firmware}_{prefix}SD_MUTEX            0x{sd_mutex:X}")
    print(f"#define FS_OFFSET_{firmware}_{prefix}NAND_MUTEX          0x{nand_mutex:X}")
    print(f"#define FS_OFFSET_{firmware}_{prefix}ACTIVE_PARTITION    0x{active_part:X}")
    print(f"#define FS_OFFSET_{firmware}_{prefix}SDMMC_DAS_HANDLE    0x{das_handle:X}\n")

    print("// NOPs")
    print(f"#define FS_OFFSET_{firmware}_{prefix}SD_DAS_INIT         0x{off_das_init:X}\n")

    print("// Nintendo Paths")
    if n_paths:
        print("{ \\")
        for reg, off in n_paths:
            print(f"    {{.opcode_reg = {reg}, .adrp_offset = 0x{off:08X}, .add_rel_offset = 0x00000004}}, \\")
        print("    {{.opcode_reg = 0, .adrp_offset = 0, .add_rel_offset = 0}}, \\")
        print("}")
    else:
        print("// No Nintendo paths found (check patterns or KIP variant)")
    print(f"\n#endif // {guard}")

def main():
    if len(sys.argv) != 4:
        print("Usage: python emummc_h.py <kip1_file> <version e.g. 2100> <prefix e.g. '' or EXFAT_>")
        sys.exit(1)
    produce_emummc_h(sys.argv[1], sys.argv[2], sys.argv[3])

if __name__ == "__main__":
    main()