import sys
import re
try:
    from capstone import *
    from capstone.arm64 import *

except ModuleNotFoundError:
    print('Please install capstone first!')
    sys.exit(1)

def page_align_down(addr: int) -> int:
    """Align address down to the nearest 4 KiB page boundary (ARM64 page size)."""
    return addr & ~0xFFF  # Equivalent to addr - (addr & 0xFFF)


def sign_extend_21bit(imm: int) -> int:
    """Sign-extend a 21-bit immediate value to 64 bits."""
    if imm & (1 << 20):
        imm |= ~((1 << 21) - 1)   # negative → fill with 1s
    return imm


def decode_adrp_imm(adrp_bytes: bytes) -> int:
    """
    Extract and decode the 21-bit page offset immediate from an ADRP instruction.
    Returns the value *already shifted left by 12* (i.e. the page offset to add).
    
    Expected format: little-endian 4 bytes
    Example: b'\x00\x72\x00\xd0' → ADRP x0, #0xe42000
    """
    if len(adrp_bytes) != 4:
        raise ValueError("ADRP must be exactly 4 bytes")
    
    word = int.from_bytes(adrp_bytes, "little")
    
    immlo = (word >> 29) & 0b11
    immhi = (word >> 5)  & 0x7FFFF   # 19 bits
    
    imm21 = (immhi << 2) | immlo
    page_offset = sign_extend_21bit(imm21) << 12   # already <<12
    
    return page_offset


def compute_adrp_base(pc_addr: int, adrp_bytes: bytes) -> int:
    """
    Given the actual runtime address of the ADRP instruction (pc_addr)
    and its 4-byte encoding, compute the 4 KiB page base it points to.
    
    This is the correct ADRP target page:
        target_page = page_align_down(pc_addr) + adrp_page_offset
    """
    page_offset = decode_adrp_imm(adrp_bytes)
    return page_align_down(pc_addr) + page_offset


def compute_full_address(
    function_addr: int,          # e.g. 0x1b8100
    adrp_pc_offset: int,         # offset of ADRP inside the function, e.g. 0x10
    adrp_bytes: bytes,
    add_imm: int = 0,            # immediate from following ADD, e.g. 0xa88
    final_offset: int = 0        # e.g. #0x268 from another ADD or STR offset
) -> int:
    """
    Convenience function to compute the final address from:
    - function base
    - offset of ADRP inside function
    - ADRP instruction bytes
    - optional ADD immediate
    - optional final offset (e.g. from LDR/STR #imm)
    
    Example usage:
        compute_full_address(0x1b8100, 0x14, b'\x00\x72\x00\xd0', 0xa88, 0x268)
    """
    adrp_addr = function_addr + adrp_pc_offset
    page_base = compute_adrp_base(adrp_addr, adrp_bytes)
    return page_base + add_imm + final_offset


def uintptr_to_int64_c_expr(value):
    u64 = value & 0xFFFFFFFFFFFFFFFF
    
    if u64 & (1 << 63):
        i64 = u64 - (1 << 64)
    else:
        i64 = u64
    
    if -0x100 <= i64 < 0:
        hex_abs = hex(-i64)[2:].upper()
        return f"((uintptr_t)(INT64_C(-0x{hex_abs})))"
    else:
        return f"((uintptr_t)(INT64_C({i64})))"
    
def sum_arm64_immediates(arm_bytes):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    total = 0
    for i in md.disasm(arm_bytes, 0x0):
        print(i.op_str)
        if '#' in i.op_str:
            part = i.op_str.split('#')[-1].strip().rstrip(']! \t')
            try:
                total += int(part, 0)
            except ValueError:
                pass
    return total

def get_arm_operand(raw_bytes):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for i in md.disasm(raw_bytes, 0x0):
        if '#' in i.op_str:
            arm_operand = i.op_str.split('#')[-1].strip().rstrip(']! \t')
            return int(arm_operand, 0)
        
def get_opcode_reg(raw_bytes):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for i in md.disasm(raw_bytes, 0x0):
        opcode_register = i.op_str.split(',')[0].strip().split('x')[1].strip()
        return opcode_register
        

FS_OFFSET_SDMMC_ACCESSOR_GC_PATTERN                  = "fd7bb.a9f...0..9f...0.......00...8......08.......8........0..0...........0....................................................9.e0............9..0......6..200........9...........0800" # .start()
FS_OFFSET_SDMMC_ACCESSOR_SD_PATTERN                  = "00000000..7.........0.91..0............0....0...........c0035fd6..0.0...............0.....03........0..." # .start()+4
FS_OFFSET_SDMMC_ACCESSOR_NAND_PATTERN                = "00000000fd7bb.a9f......9f...0.......00...8......08.......8........0..0...........0........................7...........................9.e0............9..0.........200........9...........0900" # .start()
FS_OFFSET_SDMMC_WRAPPER_READ_PATTERN                 = "fd7bbda9f65701a9f44f02a9fd030091f60300aae003022af303042af403032af50301aac7000094080040f9e103142a" # .start()
FS_OFFSET_SDMMC_WRAPPER_WRITE_PATTERN                = "fd7bbda9f65701a9f44f02a9fd030091f30304aaf40303aaf503022af603012ab0000094080040f9e103162ae203152a" # .start()
FS_OFFSET_RTLD_PATTERN                               = "0694....0035................................1f0d0071" # .end()
FS_OFFSET_CLKRST_SET_MIN_V_CLK_RATE_PATTERN          = "ff8300d1fd7b01a9fd430091000040f9e203012a080040f9082540f900013fd6" # .start()
FS_OFFSET_LOCK_MUTEX_PATTERN                         = "fd7bbea9f44f01a9fd03009168d03bd5f30300aa14fd40f908044039..0.00....0..0....0.............60..00" # .start()
FS_OFFSET_UNLOCK_MUTEX_PATTERN                       = "080840b908050071080800b940000054c0035fd61f0800f900600091..1.0014fd7bbda9f50b00f9f44f02a9fd030091" # .start()
FS_OFFSET_SDMMC_WRAPPER_CONTROLLER_OPEN_PATTERN      = "fd7bbfa9fd030091de000094080040f9011140f9fd7bc1a820001fd600000000fd7bbfa9fd030091d6000094080040f9" # .start()
FS_OFFSET_SDMMC_WRAPPER_CONTROLLER_CLOSE_PATTERN     = "fd7bbfa9fd030091d6000094080040f9011540f9fd7bc1a820001fd600000000fd7bbda9f65701a9f44f02a9fd030091" # .start()
FS_OFFSET_SD_DAS_INIT_PATTERN                        = "94....0036....00..73....91e00313aa......9468....39..0500..2000805236008052" # .end()

NINTENDO_PATH_1_PATTERN = "63.8..91.40.00.084.0..91" # .(start() - 4)
NINTENDO_PATH_2_PATTERN = ".3................00...0..0035.20.00.042....91.30.00.0" # .(end() -4)
NINTENDO_PATH_3_PATTERN = "84....91e0.30191a1c301d102088052" # .start() - 4
NINTENDO_PATH_4_PATTERN = "84.0..91e0e30091a14301d1020880" # (start() - 4)

def produce_emummc_h(uncompressed_kip_path, firmware_version, fs_type):

    with open(uncompressed_kip_path, "rb") as f:
        data = f.read()[0x100:] # cut off the header
        hex_data = data.hex()

        fs_offset_sdmmc_accessor_gc_result = re.search(FS_OFFSET_SDMMC_ACCESSOR_GC_PATTERN, hex_data)
        fs_offset_sdmmc_accessor_sd_result = re.search(FS_OFFSET_SDMMC_ACCESSOR_SD_PATTERN, hex_data)
        fs_offset_sdmmc_accessor_nand_result = re.search(FS_OFFSET_SDMMC_ACCESSOR_NAND_PATTERN, hex_data)

        fs_offset_sdmmc_wrapper_read_result = re.search(FS_OFFSET_SDMMC_WRAPPER_READ_PATTERN, hex_data)
        fs_offset_sdmmc_wrapper_write_result = re.search(FS_OFFSET_SDMMC_WRAPPER_WRITE_PATTERN, hex_data)
        fs_offset_sdmmc_rtld_result = re.search(FS_OFFSET_RTLD_PATTERN, hex_data)

        fs_offset_clkrst_set_min_v_clk_rate_result = re.search(FS_OFFSET_CLKRST_SET_MIN_V_CLK_RATE_PATTERN, hex_data)

        fs_offset_lock_mutex_result = re.search(FS_OFFSET_LOCK_MUTEX_PATTERN, hex_data)
        fs_offset_unlock_mutex_result = re.search(FS_OFFSET_UNLOCK_MUTEX_PATTERN, hex_data)

        fs_offset_sdmmc_wrapper_controller_open_result = re.search(FS_OFFSET_SDMMC_WRAPPER_CONTROLLER_OPEN_PATTERN, hex_data)
        fs_offset_sdmmc_wrapper_controller_close_result = re.search(FS_OFFSET_SDMMC_WRAPPER_CONTROLLER_CLOSE_PATTERN, hex_data)



        fs_offset_sd_das_init_result = re.search(FS_OFFSET_SD_DAS_INIT_PATTERN, hex_data)

        nintendo_path_adrp_result_1 = re.search(NINTENDO_PATH_1_PATTERN, hex_data)
        nintendo_path_adrp_result_2 = re.search(NINTENDO_PATH_2_PATTERN, hex_data)
        nintendo_path_adrp_result_3 = re.search(NINTENDO_PATH_3_PATTERN, hex_data)
        nintendo_path_adrp_result_4 = re.search(NINTENDO_PATH_4_PATTERN, hex_data)


        fs_offset_sdmmc_accesor_gc_offset = int(fs_offset_sdmmc_accessor_gc_result.start() / 2)
        fs_offset_sdmmc_accesor_sd_offset = int(fs_offset_sdmmc_accessor_sd_result.start() / 2 + 4)
        fs_offset_sdmmc_accesor_nand_offset = int(fs_offset_sdmmc_accessor_nand_result.start() / 2 + 4)

        fs_offset_sdmmc_accesor_sd_bl_rel_start_1 = (fs_offset_sdmmc_accesor_sd_offset + 8)
        fs_offset_sdmmc_accesor_sd_bl_rel_end_1 = fs_offset_sdmmc_accesor_sd_bl_rel_start_1 + 4
        fs_offset_sdmmc_accesor_sd_bl_jump_1 = fs_offset_sdmmc_accesor_sd_bl_rel_start_1 + get_arm_operand(data[fs_offset_sdmmc_accesor_sd_bl_rel_start_1:fs_offset_sdmmc_accesor_sd_bl_rel_end_1])
        
        fs_offset_sdmmc_accesor_sd_adrp_start = fs_offset_sdmmc_accesor_sd_bl_jump_1 + 0x30 # the + 0x30 value is correct in 21.0.0 - validate in future firmware versions
        fs_offset_sdmmc_accesor_sd_adrp_end = fs_offset_sdmmc_accesor_sd_adrp_start + 4
        fs_offset_sdmmc_accesor_sd_add_start_1 = fs_offset_sdmmc_accesor_sd_adrp_end
        fs_offset_sdmmc_accesor_sd_add_end_1 = fs_offset_sdmmc_accesor_sd_add_start_1 + 4

        fs_offset_sdmmc_accesor_sd_bl_rel_start_2 = fs_offset_sdmmc_accesor_sd_bl_jump_1 + 0xc8 # the + 0xc8 value is correct in 21.0.0 - validate in future firmware versions
        fs_offset_sdmmc_accesor_sd_bl_rel_end_2 = fs_offset_sdmmc_accesor_sd_bl_rel_start_2 + 4
        fs_offset_sdmmc_accesor_sd_bl_jump_2 = fs_offset_sdmmc_accesor_sd_bl_rel_start_2 + get_arm_operand(data[fs_offset_sdmmc_accesor_sd_bl_rel_start_2:fs_offset_sdmmc_accesor_sd_bl_rel_end_2])

        fs_offset_sdmmc_accesor_sd_add_start_2 = fs_offset_sdmmc_accesor_sd_bl_jump_2 + 0xa0 # the + 0xa0 value is correct in 21.0.0 - validate in future firmware versions
        fs_offset_sdmmc_accesor_sd_add_end_2 = fs_offset_sdmmc_accesor_sd_add_start_2 + 4

        fs_offset_sdmmc_accesor_sd_adrp_bytes = data[fs_offset_sdmmc_accesor_sd_adrp_start:fs_offset_sdmmc_accesor_sd_adrp_end]
        fs_offset_sdmmc_accesor_sd_add_bytes_1 = data[fs_offset_sdmmc_accesor_sd_add_start_1:fs_offset_sdmmc_accesor_sd_add_end_1]
        fs_offset_sdmmc_accesor_sd_add_bytes_2 = data[fs_offset_sdmmc_accesor_sd_add_start_2:fs_offset_sdmmc_accesor_sd_add_end_2]

        



        fs_offset_sdmmc_accesor_nand_adrp_start = fs_offset_sdmmc_accesor_nand_offset + 0x20 # the + 0x20 value is correct in 21.0.0 - validate in future firmware versions
        fs_offset_sdmmc_accesor_nand_adrp_end = fs_offset_sdmmc_accesor_nand_adrp_start + 4
        fs_offset_sdmc_accesor_nand_add_start_1 = fs_offset_sdmmc_accesor_nand_adrp_end
        fs_offset_sdmc_accesor_nand_add_end_1 = fs_offset_sdmc_accesor_nand_add_start_1 + 4


        fs_offset_sdmmc_accesor_nand_adrp_bytes = data[fs_offset_sdmmc_accesor_nand_adrp_start:fs_offset_sdmmc_accesor_nand_adrp_end]
        fs_offset_sdmc_accesor_nand_add_1_bytes = data[fs_offset_sdmc_accesor_nand_add_start_1:fs_offset_sdmc_accesor_nand_add_end_1]
        fs_offset_sdmmc_accesor_nand_tbz_start = fs_offset_sdmmc_accesor_nand_offset + 0x18 # the + 0x18 value is correct in 21.0.0 - validate in future firmware versions
        fs_offset_sdmmc_accesor_nand_tbz_end = fs_offset_sdmmc_accesor_nand_tbz_start + 4
        fs_offset_sdmmc_accesor_nand_tbz_bytes = data[fs_offset_sdmmc_accesor_nand_tbz_start:fs_offset_sdmmc_accesor_nand_tbz_end]
        fs_offset_sdmmc_accesor_nand_bl_relative_to_tbz_jump = fs_offset_sdmmc_accesor_nand_tbz_start + get_arm_operand(fs_offset_sdmmc_accesor_nand_tbz_bytes) + 0x20
        fs_offset_sdmmc_accesor_nand_bl_end = fs_offset_sdmmc_accesor_nand_bl_relative_to_tbz_jump + 4
        fs_offset_sdmmc_accesor_nand_bl_bytes = data[fs_offset_sdmmc_accesor_nand_bl_relative_to_tbz_jump:fs_offset_sdmmc_accesor_nand_bl_end]
        fs_offset_sdmmc_accesor_nand_second_function_start = fs_offset_sdmmc_accesor_nand_bl_relative_to_tbz_jump + get_arm_operand(fs_offset_sdmmc_accesor_nand_bl_bytes)
        fs_offset_sdmc_accesor_nand_add_start_2 = fs_offset_sdmmc_accesor_nand_second_function_start + 0x98 # the + 0x98 value is correct in 21.0.0 - validate in future firmware versions
        fs_offset_sdmc_accesor_nand_add_end_2 = fs_offset_sdmc_accesor_nand_add_start_2 + 4
        fs_offset_sdmc_accesor_nand_add_bytes_2 = data[fs_offset_sdmc_accesor_nand_add_start_2:fs_offset_sdmc_accesor_nand_add_end_2]
        active_partition_add_start = fs_offset_sdmmc_accesor_nand_second_function_start + 0xEC # the + 0xEC value is correct in 21.0.0 - validate in future firmware versions
        active_partition_add_end = active_partition_add_start + 4
        active_partition_add_bytes = data[active_partition_add_start:active_partition_add_end]


        fs_offset_sdmmc_wrapper_read_offset = int(fs_offset_sdmmc_wrapper_read_result.start() / 2)
        fs_offset_sdmmc_wrapper_write_offset = int(fs_offset_sdmmc_wrapper_write_result.start() / 2)
        fs_offset_sdmmc_rtld_start = int(fs_offset_sdmmc_rtld_result.end() / 2)

        fs_offset_clkrst_set_min_v_clk_rate_offset = int(fs_offset_clkrst_set_min_v_clk_rate_result.start() / 2)

        fs_offset_lock_mutex_offset = int(fs_offset_lock_mutex_result.start() / 2)
        fs_offset_unlock_mutex_offset = int(fs_offset_unlock_mutex_result.start() / 2)

        fs_offset_sdmmc_wrapper_controller_open_offset = int(fs_offset_sdmmc_wrapper_controller_open_result.start() / 2)
        fs_offset_sdmmc_wrapper_controller_close_offset = int(fs_offset_sdmmc_wrapper_controller_close_result.start() / 2)

        fs_offset_sd_das_init_offset_start = int(fs_offset_sd_das_init_result.end() / 2)

        nintendo_path_adrp_offset_start_1 = int(nintendo_path_adrp_result_1.start() / 2 - 4)
        nintendo_path_adrp_offset_start_2 = int(nintendo_path_adrp_result_2.end() / 2 - 4)
        nintendo_path_adrp_offset_start_3 = int(nintendo_path_adrp_result_3.start() / 2 - 4)
        nintendo_path_adrp_offset_start_4 = int(nintendo_path_adrp_result_4.start() / 2 - 4)


        fs_offset_sdmmc_rtld_end = fs_offset_sdmmc_rtld_start + 4

        fs_offset_sd_das_init_offset_end = fs_offset_sd_das_init_offset_start + 4

        nintendo_path_adrp_offset_end_1 = nintendo_path_adrp_offset_start_1 + 4
        nintendo_path_adrp_offset_end_2 = nintendo_path_adrp_offset_start_2 + 4
        nintendo_path_adrp_offset_end_3 = nintendo_path_adrp_offset_start_3 + 4
        nintendo_path_adrp_offset_end_4 = nintendo_path_adrp_offset_start_4 + 4
        fs_offset_sdmc_rtld_bytes = data[fs_offset_sdmmc_rtld_start:fs_offset_sdmmc_rtld_end]
        fs_offset_das_init_bytes = data[fs_offset_sd_das_init_offset_start:fs_offset_sd_das_init_offset_end]
        das_init_relative = fs_offset_sd_das_init_offset_start + get_arm_operand(fs_offset_das_init_bytes)
        fs_offset_sdmmc_das_handle_adrp_start = das_init_relative + 0x50 # the + 0x50 value is correct in 21.0.0 - validate in future firmware versions
        fs_offset_sdmmc_das_handle_adrp_end = fs_offset_sdmmc_das_handle_adrp_start + 4
        fs_offset_sdmmc_das_handle_add_start = fs_offset_sdmmc_das_handle_adrp_end
        fs_offset_sdmmc_das_handle_add_end = fs_offset_sdmmc_das_handle_add_start + 4
        fs_offset_sdmmc_das_handle_adrp_bytes = data[fs_offset_sdmmc_das_handle_adrp_start:fs_offset_sdmmc_das_handle_adrp_end]
        fs_offset_sdmmc_das_handle_add_bytes = data[fs_offset_sdmmc_das_handle_add_start:fs_offset_sdmmc_das_handle_add_end]

        nintendo_path_adrp_bytes_1 = data[nintendo_path_adrp_offset_start_1:nintendo_path_adrp_offset_end_1]
        nintendo_path_adrp_bytes_2 = data[nintendo_path_adrp_offset_start_2:nintendo_path_adrp_offset_end_2]
        nintendo_path_adrp_bytes_3 = data[nintendo_path_adrp_offset_start_3:nintendo_path_adrp_offset_end_3]
        nintendo_path_adrp_bytes_4 = data[nintendo_path_adrp_offset_start_4:nintendo_path_adrp_offset_end_4]

        FS_OFFSET_RTLD_DESTINATION  = uintptr_to_int64_c_expr(get_arm_operand(fs_offset_sdmc_rtld_bytes))
        nintendo_path_adrp_opcode_reg_1 = get_opcode_reg(nintendo_path_adrp_bytes_1)
        nintendo_path_adrp_opcode_reg_2 = get_opcode_reg(nintendo_path_adrp_bytes_2)
        nintendo_path_adrp_opcode_reg_3 = get_opcode_reg(nintendo_path_adrp_bytes_3)
        nintendo_path_adrp_opcode_reg_4 = get_opcode_reg(nintendo_path_adrp_bytes_4)

        FS_OFFSET_SD_MUTEX = compute_full_address(function_addr=fs_offset_sdmmc_accesor_sd_offset, adrp_pc_offset=0x0, adrp_bytes=fs_offset_sdmmc_accesor_sd_adrp_bytes, add_imm=get_arm_operand(fs_offset_sdmmc_accesor_sd_add_bytes_1), final_offset=get_arm_operand(fs_offset_sdmmc_accesor_sd_add_bytes_2))
        FS_OFFSET_NAND_MUTEX = compute_full_address(function_addr=fs_offset_sdmmc_accesor_nand_offset, adrp_pc_offset=0x0, adrp_bytes=fs_offset_sdmmc_accesor_nand_adrp_bytes, add_imm=get_arm_operand(fs_offset_sdmc_accesor_nand_add_1_bytes), final_offset=get_arm_operand(fs_offset_sdmc_accesor_nand_add_bytes_2))
        FS_OFFSET_ACTIVE_PARTITION = compute_full_address(function_addr=fs_offset_sdmmc_accesor_nand_offset, adrp_pc_offset=0x0, adrp_bytes=fs_offset_sdmmc_accesor_nand_adrp_bytes, add_imm=get_arm_operand(fs_offset_sdmc_accesor_nand_add_1_bytes), final_offset=get_arm_operand(active_partition_add_bytes))
        FS_OFFSET_SDMMC_DAS_HANDLE = compute_full_address(function_addr=das_init_relative, adrp_pc_offset=0x0, adrp_bytes=fs_offset_sdmmc_das_handle_adrp_bytes, add_imm=get_arm_operand(fs_offset_sdmmc_das_handle_add_bytes), final_offset=0x0)






        print(f'#ifndef __FS_{firmware_version}_{fs_type}H__')
        print(f'#define __FS_{firmware_version}_{fs_type}H__')
        print(f'')

        print(f'// Accessor vtable getters')
        print(f'#define FS_OFFSET_{firmware_version}_{fs_type}SDMMC_ACCESSOR_GC   0x{fs_offset_sdmmc_accesor_gc_offset:X}')
        print(f'#define FS_OFFSET_{firmware_version}_{fs_type}SDMMC_ACCESSOR_SD   0x{fs_offset_sdmmc_accesor_sd_offset:X}')
        print(f'#define FS_OFFSET_{firmware_version}_{fs_type}SDMMC_ACCESSOR_NAND 0x{fs_offset_sdmmc_accesor_nand_offset:X}')
        print(f'')

        print(f'// Hooks')
        print(f'#define FS_OFFSET_{firmware_version}_{fs_type}SDMMC_WRAPPER_READ  0x{fs_offset_sdmmc_wrapper_read_offset:X}')
        print(f'#define FS_OFFSET_{firmware_version}_{fs_type}SDMMC_WRAPPER_WRITE 0x{fs_offset_sdmmc_wrapper_write_offset:X}')
        print(f'#define FS_OFFSET_{firmware_version}_{fs_type}RTLD                0x{fs_offset_sdmmc_rtld_start:X}')
        print(f'#define FS_OFFSET_{firmware_version}_{fs_type}RTLD_DESTINATION    {FS_OFFSET_RTLD_DESTINATION}')
        print(f'')

        print(f'#define FS_OFFSET_{firmware_version}_{fs_type}CLKRST_SET_MIN_V_CLK_RATE 0x{fs_offset_clkrst_set_min_v_clk_rate_offset:X}')
        print(f'')

        print(f'// Misc funcs')
        print(f'#define FS_OFFSET_{firmware_version}_{fs_type}LOCK_MUTEX          0x{fs_offset_lock_mutex_offset:X}')
        print(f'#define FS_OFFSET_{firmware_version}_{fs_type}UNLOCK_MUTEX        0x{fs_offset_unlock_mutex_offset:X}')
        print(f'')

        print(f'#define FS_OFFSET_{firmware_version}_{fs_type}SDMMC_WRAPPER_CONTROLLER_OPEN  0x{fs_offset_sdmmc_wrapper_controller_open_offset:X}')
        print(f'#define FS_OFFSET_{firmware_version}_{fs_type}SDMMC_WRAPPER_CONTROLLER_CLOSE 0x{fs_offset_sdmmc_wrapper_controller_close_offset:X}')
        print(f'')

        print(f'// Misc Data')
        print(f'#define FS_OFFSET_{firmware_version}_{fs_type}SD_MUTEX            0x{FS_OFFSET_SD_MUTEX:X}')
        print(f'#define FS_OFFSET_{firmware_version}_{fs_type}NAND_MUTEX          0x{FS_OFFSET_NAND_MUTEX:X}')
        print(f'#define FS_OFFSET_{firmware_version}_{fs_type}ACTIVE_PARTITION    0x{FS_OFFSET_ACTIVE_PARTITION:X}')
        print(f'#define FS_OFFSET_{firmware_version}_{fs_type}SDMMC_DAS_HANDLE    0x{FS_OFFSET_SDMMC_DAS_HANDLE:X}')
        print(f'')

        print(f'// NOPs')
        print(f'#define FS_OFFSET_{firmware_version}_{fs_type}SD_DAS_INIT         0x{fs_offset_sd_das_init_offset_start:X}')
        print(f'')


        print(f'// Nintendo Paths')
        print(f'{{ \\')
        print(f'    {{.opcode_reg = {nintendo_path_adrp_opcode_reg_1}, .adrp_offset = 0x{nintendo_path_adrp_offset_start_1:08X}, .add_rel_offset = 0x00000004}}, \\')
        print(f'    {{.opcode_reg = {nintendo_path_adrp_opcode_reg_2}, .adrp_offset = 0x{nintendo_path_adrp_offset_start_2:08X}, .add_rel_offset = 0x00000004}}, \\')
        print(f'    {{.opcode_reg = {nintendo_path_adrp_opcode_reg_3}, .adrp_offset = 0x{nintendo_path_adrp_offset_start_3:08X}, .add_rel_offset = 0x00000004}}, \\')
        print(f'    {{.opcode_reg = {nintendo_path_adrp_opcode_reg_4}, .adrp_offset = 0x{nintendo_path_adrp_offset_start_4:08X}, .add_rel_offset = 0x00000004}}, \\')
        print(f'    {{.opcode_reg = 0, .adrp_offset = 0, .add_rel_offset = 0}}, \\')
        print(f'}}')
        print(f'')

        print(f'#endif // __FS_{firmware_version}_{fs_type}H__')




# example usage
# version = "2100"
# exfat_kip = "21.2.0_exfat_uFS.kip1"
# fat32_kip = "21.0.0_fat32_uFS.kip1"
# file_input = fat32_kip

# produce_emummc_h(exfat_kip, "2120", "EXFAT_")
# produce_emummc_h(fat32_kip, "2100", "")