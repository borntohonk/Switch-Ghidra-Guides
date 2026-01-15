#!/usr/bin/env python

# Copyright (c) 2025 borntohonk
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

import re
import hashlib
import os
import ast
import binascii
import sys
import shutil
import errno
from urllib.request import Request, urlopen
import argparse
from dataclasses import dataclass
from typing import Tuple, List, Dict, Optional, Callable

import package3_and_stratosphere

try:
    from capstone import *
    from capstone.arm64 import *

except ModuleNotFoundError:
    print('Please install capstone first!')
    sys.exit(1)

parser = argparse.ArgumentParser()

parser.add_argument(
    '--ams',
    action='store_true',
)

args = parser.parse_args()


def convert_sys_patch_nibble_string(input_string):
    if not isinstance(input_string, str):
        raise TypeError("Input must be a string")

    modified_string = input_string.replace('?', '.')
    return modified_string


def log_patch_success(
    log_file,
    module_name: str,
    version: str,
    rule_name: str,
    offset_hex: str,
    existing_hex: str,
    mnemonic: str,
    patch_hex: str,
    sys_patch_pattern: str,
    diff_str: str = ""
):
    log_file.write(f"({module_name}) Pattern matched: {rule_name} for {version}\n")
    log_file.write(f"({module_name}) sys-patch pattern: {sys_patch_pattern}\n")
    ghidra_patch_pattern = ' '.join([sys_patch_pattern[i:i+2] for i in range(0, len(sys_patch_pattern), 2)])
    log_file.write(f"({module_name}) ghidra pattern: {ghidra_patch_pattern}\n")
    log_file.write(f"({module_name}) Offset: 0x{offset_hex}\n")
    log_file.write(f"({module_name}) Instruction: {mnemonic}\n")
    log_file.write(f"({module_name}) Existing bytes: {existing_hex}\n")
    log_file.write(f"({module_name}) Patch applied: {patch_hex}\n")
    if diff_str:
        log_file.write(f"({module_name}) Pattern diff (context):\n{diff_str}\n")
    log_file.write("\n")

def find_and_patch(
    module_path: str,
    version: str,
    module_name: str,
    log_file,
    pattern_diffs: Dict[str, str],
    pattern_offsets: Dict[str, tuple],
    ips_patch_database: List[tuple],
    hekate_patch_db: List[tuple] = None,
    is_fs: bool = False,
    fs_type: str = "",
    prior_patch_fragment: str = None,
    compressed_path: Optional[str] = None,
    atmosphere_string: Optional[str] = None
) -> Optional[str]:
    """
    Generic patch finder and applicator.
    Returns IPS fragment string if generated (for chaining), else None.
    Appends to ips_patch_database and hekate_patch_db when appropriate.
    """

    if not os.path.exists(module_path):
        log_file.write(f"({module_name}) File not found: {module_path}\n")
        return None

    with open(module_path, 'rb') as f:
        data = f.read()
        hex_data = data.hex().upper()

    rules = [
        r for r in PATCH_RULES.get(module_name, [])
        if MAKEHOSVERSION(r.min_version, r.max_version, version)
    ]

    if not rules:
        log_file.write(f"({module_name}) No matching PatchRule for version {version}\n")
        return None

    collected_ips_records = []
    hekate_lines = []
    found_any = False

    module_id = get_module_id(module_path)

    if compressed_path and os.path.exists(compressed_path):
        file_hash = hashlib.sha256(open(compressed_path, 'rb').read()).hexdigest().upper()
        log_file.write(f"({module_name}) Using compressed hash from {compressed_path}\n")
        short_hash = file_hash[:16]
        module_id = file_hash

    for rule in rules:
        pattern_regex = convert_sys_patch_nibble_string(rule.pattern)
        match = re.search(pattern_regex, hex_data)

        if not match:
            log_file.write(f"({module_name}) Pattern not matched: {rule.name} / {rule.pattern}\n")
            continue

        found_any = True

        match_start = match.start() // 2
        patch_offset = match_start + rule.offset
        head_offset = patch_offset + rule.head_offset

        patch_size_int = int(rule.patch_size_hex, 16)
        existing = data[head_offset : head_offset + patch_size_int]
        mnemonic = get_arm_cond(existing, head_offset)

        if mnemonic not in rule.condition_mnemonics:
            log_file.write(
                f"({module_name}) Condition failed at 0x{patch_offset:X}\n"
                f"(got {mnemonic}, expected one of {rule.condition_mnemonics})\n"
            )
            continue

        diff_start = max(0, patch_offset - 0x20)
        diff_end = diff_start + 0x60
        diff_bytes = data[diff_start:diff_end]
        diff_str = diff_bytes.hex().upper()
        pattern_diffs[version] = diff_str

        offset_hex = f"{patch_offset:X}".zfill(6).upper()

        if module_name in ["FS", "LOADER"]:
            log_file.write(f"({module_name}) SHA256 of {compressed_path} is:\n")
        else:
            log_file.write(f"({module_name}) moduleid of {module_path} is:\n")
        log_file.write(f"({module_name}) {module_id}\n")
        log_patch_success(
            log_file,
            module_name,
            version,
            rule.name,
            offset_hex,
            existing.hex().upper(),
            mnemonic,
            rule.patch_bytes.hex().upper(),
            rule.pattern,
            diff_str,
        )

        write_arm_bytes_and_patch(rule.patch_bytes, existing, head_offset, log_file)
        get_arm_instruction_order(diff_bytes, head_offset, log_file)

        # ----------------------------------------------------------------------
        #  IPS style database entry
        # ----------------------------------------------------------------------
        ips_record = build_ips_record(head_offset, rule.patch_size_hex, rule.patch_bytes)
        collected_ips_records.append(ips_record)

        pattern_offsets[version] = (module_name, existing.hex().upper(), offset_hex, module_id)

        # ----------------------------------------------------------------------
        #  Hekate / .nosigchk style entry (only when hekate_patch_db is passed)
        # ----------------------------------------------------------------------
        if hekate_patch_db is not None:
            head_offset = head_offset - 0x100
            original_hex = existing.hex().upper()
            patch_hex = rule.patch_bytes.hex().upper()
            line = (
                f".nosigchk=0:0x{head_offset:06X}:0x{patch_size_int:X}:"
                f"{original_hex},{patch_hex}"
            )
            hekate_lines.append(line)

    if not found_any:
        log_file.write(f"({module_name}) No valid patch location found for {version}\n")
        return None

    # -------------------------------------------------------------------------
    #  Build final IPS content (used for both Atmosphere IPS and reference)
    # -------------------------------------------------------------------------
    if collected_ips_records:
        if prior_patch_fragment:
            # Very rare — mostly for NIM + NIM-FW combination
            full_ips_content = prior_patch_fragment + "".join(collected_ips_records)
        else:
            magic = ips32_magic if len(collected_ips_records) > 1 else patch_magic
            end_magic = eeof_magic if magic == ips32_magic else eof_magic
            full_ips_content = build_ips_file(magic, collected_ips_records, end_magic)

        if module_name in ["FS", "LOADER"]:
            subfolder = "fs_patches" if module_name == "FS" else "loader_patches"
            patch_path = f"patches/atmosphere/kip_patches/{subfolder}/"
        else:
            patch_path = f"patches/atmosphere/exefs_patches/{module_name.lower()}_patches/"

        ips_patch_database.append((version, module_id, patch_path, full_ips_content))
    else:
        full_ips_content = None

    # -------------------------------------------------------------------------
    #  Build hekate-style patch_db entry
    # -------------------------------------------------------------------------
    if hekate_patch_db is not None and hekate_lines:
        if is_fs:
            title = f"[FS:{short_hash}]\n"
            if version_to_tuple(version) <= version_to_tuple("9.99.9"):
                content = "\n".join(hekate_lines) + "\n\n"
            else:
                content = "\n".join(hekate_lines) + "\n\n"
            entry = (version, title + content, fs_type)
        else:
            title = f"[{module_name}:{short_hash}]\n"
            content = "\n".join(hekate_lines) + "\n\n"
            patch_block = title + content

            if module_name == "LOADER" and atmosphere_string:
                entry = (version, patch_block, module_name, atmosphere_string)
            else:
                entry = (version, patch_block, module_name)

        hekate_patch_db.append(entry)
        log_file.write(f"({module_name}-{fs_type}) Generated hekate-style patch block for {version}\n")
        log_file.write(f"   {title}")
        for ln in hekate_lines:
            log_file.write(f"     {ln}\n")
        log_file.write('\n')

    return full_ips_content

def mkdirp(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def remove_duplicates_by_index(list_of_tuples, index_to_check):
    seen_values = set()
    unique_list = []
    for current_tuple in list_of_tuples:
        value_to_check = current_tuple[index_to_check]

        if value_to_check not in seen_values:
            unique_list.append(current_tuple)
            seen_values.add(value_to_check)
            
    return unique_list


def load_existing_pattern_diffs(filepath: str) -> Dict[str, Dict[str, str]]:
    """
    Loads pattern_diffs.py and converts lists of tuples back to dicts for merging.
    Returns the same internal structure as before (dict of dicts).
    """
    existing = {
        'es_pattern_diffs': {},
        'blankcal0crashfix_pattern_diffs': {},
        'blockfirmwareupdates_pattern_diffs': {},
        'nifm_pattern_diffs': {},
        'olsc_pattern_diffs': {},
        'fat32_noncasigchk_pattern_diffs': {},
        'exfat_noncasigchk_pattern_diffs': {},
        'fat32_noacidsigchk1_pattern_diffs': {},
        'exfat_noacidsigchk1_pattern_diffs': {},
        'fat32_noacidsigchk2_pattern_diffs': {},
        'exfat_noacidsigchk2_pattern_diffs': {},
        'fat32_nocntchk_pattern_diffs': {},
        'exfat_nocntchk_pattern_diffs': {},
        'loader_pattern_diffs': {},
        'erpt_pattern_diffs': {},
    }

    if not os.path.exists(filepath):
        return existing

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        local_ns = {}
        exec(content, {"__builtins__": {}}, local_ns)

        for key in existing:
            value = local_ns.get(key)
            if isinstance(value, dict):
                existing[key] = value
            elif isinstance(value, list):
                existing[key] = {ver: bytes_val for ver, bytes_val in value}

    except Exception as e:
        print(f"Warning: Could not parse {filepath}: {e}")
        print("   → Starting with empty diffs.")

    return existing

def load_existing_patches(filepath: str) -> List[Tuple]:
    patches = []
    if not os.path.exists(filepath):
        return patches
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.endswith(','):
                    line = line[:-1]
                if line:
                    patches.append(ast.literal_eval(line))
    except Exception as e:
        print(f"Warning: Could not parse existing {filepath}: {e}")
        patches = []
    return patches


def update_patch_file(filepath: str, current_db: List[Tuple], unique_index: int = 1):
    existing = load_existing_patches(filepath)
    seen = {item[unique_index] for item in existing}
    new_entries = [item for item in current_db if item[unique_index] not in seen]
    
    if not new_entries:
        print(f"No new entries for {filepath} — unchanged.")
        return False

    combined = existing + new_entries

    combined = remove_duplicates_by_index(combined, unique_index)

    combined.sort(key=lambda x: version_to_tuple(x[0]))

    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            for entry in combined:
                f.write(f"{entry},\n")
        print(f"Appended {len(new_entries)} new entries to {filepath}")
        return True
    except Exception as e:
        print(f"Error writing {filepath}: {e}")
        return False

def version_to_tuple(version_string):
    parts = version_string.split('-')[0].split('.')
    return tuple(int(p) for p in parts)

def MAKEHOSVERSION(lowest_firmware, highest_firmware, current_firmware):
    target_low_version_tuple = version_to_tuple(lowest_firmware)
    target_high_version_tuple = version_to_tuple(highest_firmware)
    current_version_tuple = version_to_tuple(current_firmware)

    if current_version_tuple >= target_low_version_tuple and current_version_tuple <= target_high_version_tuple:
        return True
    else:
        return False

def get_arm_cond(raw_bytes, arm_offset):
	md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
	for i in md.disasm(raw_bytes, arm_offset):
		arm_cond = i.mnemonic
		return arm_cond

def write_arm_bytes_and_patch(raw_patch_bytes, raw_bytes, arm_offset, file):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    file.write('Patch data:\n')
    for i in md.disasm(raw_bytes, arm_offset):
        file.write('from: 0x%06X: (%s) %s %s\n' %(i.address, i.bytes.hex().upper(), i.mnemonic, i.op_str))
    for i in md.disasm(raw_patch_bytes, arm_offset):
        file.write('to:   0x%06X: (%s) %s %s\n' %(i.address, i.bytes.hex().upper(), i.mnemonic, i.op_str))
    file.write('\n')

def get_arm_instruction_order(arm_diff_string, arm_offset, file):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    instruction_order = []
    file.write(f'Instruction order, the offset being patched is 0x{hex(arm_offset)[2:].upper()}:\n\n')
    for i in md.disasm(arm_diff_string, arm_offset - 0x20):
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        instruction_order.append(i.mnemonic)
        if i.address == arm_offset:
            hex_bytearray = i.bytes.hex().upper()
            formatted_hex_bytearray = ' '.join([hex_bytearray[i:i+2] for i in range(0, len(hex_bytearray), 2)])
            file.write(f"\n0x{i.address:06X}:\t ({formatted_hex_bytearray})\t{i.mnemonic}\t{i.op_str}\n\n")
        else:
            hex_bytearray = i.bytes.hex().upper()
            formatted_hex_bytearray = ' '.join([hex_bytearray[i:i+2] for i in range(0, len(hex_bytearray), 2)])
            file.write(f"0x{i.address:06X}:\t ({formatted_hex_bytearray})\t{i.mnemonic}\t{i.op_str}\n")
    file.write(f'\ninstruction order:\n')
    file.write(" ".join(instruction_order))
    file.write(f'\n\n')

def build_ips_record(offset: int, size_hex: str, patch_data: bytes) -> str:
    return f"{offset:08X}{size_hex}{patch_data.hex().upper()}"

def build_ips_file(magic: str, records: list[str], end_magic: str = "454F46") -> str:
    return magic + "".join(records) + end_magic

# sys-patch logic explanation:
# "(49, 0,) +49" (nifm/ctest) from start from the start the string found in it's entirity, as sys-patch tests things stupid, then it reads from 0x0 of the end in decimals where the "head" was placed (49),
# and the 4th byte from there is what is tested (for most cond checks), the next number determines where from the tested byte is being patched. (should be 0, otherwise its not testing the bytes being patched!)
# should be noted ams loader patch being (6,2) is different from this general rule of not testing for what is being patched.
# as it finds searches for "009401C0BE12(6)1F00(2)", testing 4 bytes from from offset (6) for cmp_cond byte of "6B",
# and then applies the patch of "00", two bytes offset after the testing point (0)1F00(2), turning (6)1F00(2)->01<-6B - cmp w0, w1 -  into (6)1F00(2)->00<-6B - cmp w0, w0

patch_magic = "5041544348" # "PATCH"
ips32_magic = "4950533332" # "IPS32"
eof_magic = "454F46" # "EOF"
eeof_magic = "45454F46" # "EEOF"
FW_VER_ANY = '99.99.99'

@dataclass
class PatchRule:
    name: str
    module: str
    min_version: str
    max_version: str
    pattern: str
    offset: int
    head_offset: int
    condition_mnemonics: tuple[str, ...]
    patch_bytes: bytes
    patch_size_hex: str
    description: str = ""
    extra_condition: Optional[Callable[[str, bytes], bool]] = None

PATCH_RULES: Dict[str, List[PatchRule]] = {
    "ES": [
        PatchRule(
            name="es_1.0.0-8.1.1",
            module="ES",
            min_version="1.0.0",
            max_version="8.1.1",
            pattern="0091....0094..7E4092",
            offset=10,
            head_offset=0,
            condition_mnemonics=("sub", "ldp", "mov", "and", "mov"),
            patch_bytes=b"\xE0\x03\x1F\xAA",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="es_9.0.0-11.0.1",
            module="ES",
            min_version="9.0.0",
            max_version="11.0.1",
            pattern="00..........A0....D1....FF97",
            offset=14,
            head_offset=0,
            condition_mnemonics=("sub", "ldp", "mov", "and", "mov"),
            patch_bytes=b"\xE0\x03\x1F\xAA",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="es_12.0.0-18.1.0",
            module="ES",
            min_version="19.0.0",
            max_version="18.1.0",
            pattern="02........D2..52....0091",
            offset=32,
            head_offset=0,
            condition_mnemonics=("sub", "ldp", "mov", "and", "mov"),
            patch_bytes=b"\xE0\x03\x1F\xAA",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="es_19.0.0+",
            module="ES",
            min_version="19.0.0",
            max_version=FW_VER_ANY,
            pattern="A1........031F2A....0091",
            offset=32,
            head_offset=0,
            condition_mnemonics=("sub", "ldp", "mov", "and", "mov"),
            patch_bytes=b"\xE0\x03\x1F\xAA",
            patch_size_hex="0004",
        )
    ],
    "NIFM" : [
        PatchRule(
            name="nifm_1.0.0-19.0.1",
            module="NIFM",
            min_version="1.0.0",
            max_version="19.0.1",
            pattern="03..AAE003..AA......39....04F8........E0",
            offset=-29,
            head_offset=0,
            condition_mnemonics=("str", "stp"),
            patch_bytes=b"\x00\x30\x9A\xD2\x00\x1E\xA1\xF2\x61\x01\x00\xD4\xE0\x03\x1F\xAA\xC0\x03\x5F\xD6",
            patch_size_hex="0014",
        ),
        PatchRule(
            name="nifm_20.0.0+",
            module="NIFM",
            min_version="20.0.0",
            max_version=FW_VER_ANY,
            pattern="03..AA......AA..................0314AA....14AA",
            offset=-17,
            head_offset=0,
            condition_mnemonics=("str", "stp"),
            patch_bytes=b"\x00\x30\x9A\xD2\x00\x1E\xA1\xF2\x61\x01\x00\xD4\xE0\x03\x1F\xAA\xC0\x03\x5F\xD6",
            patch_size_hex="0014",
        )
    ],
    "OLSC" : [
        PatchRule(
            name="olsc_6.0.0-14.1.2",
            module="OLSC",
            min_version="6.0.0",
            max_version="14.1.2",
            pattern="00..73....F9....4039",
            offset=42,
            head_offset=0,
            condition_mnemonics=("bl"),
            patch_bytes=b"\x20\x00\x80\xD2",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="olsc_15.0.0-18.1.0",
            module="OLSC",
            min_version="15.0.0",
            max_version="18.1.0",
            pattern="00..73....F9....4039",
            offset=38,
            head_offset=0,
            condition_mnemonics=("bl"),
            patch_bytes=b"\x20\x00\x80\xD2",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="olsc_19.0.0+",
            module="OLSC",
            min_version="19.0.0",
            max_version=FW_VER_ANY,
            pattern="00..73....F9....4039",
            offset=42,
            head_offset=0,
            condition_mnemonics=("bl"),
            patch_bytes=b"\x20\x00\x80\xD2",
            patch_size_hex="0004",
        )
    ],
    "NIM" : [
        PatchRule(
            name="nim_blankcal0_17.0.0+",
            module="NIM",
            min_version="17.0.0",
            max_version=FW_VER_ANY,
            pattern="03D5..............................97....0094....00..........61",
            offset=2,
            head_offset=0,
            condition_mnemonics=("adr"),
            patch_bytes=b"\xE2\x03\x1F\xAA",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="nim_blockfw_1.0.0-5.1.0",
            module="NIM-FW",
            min_version="1.0.0",
            max_version="5.1.0",
            pattern="1139F3",
            offset=-30,
            head_offset=0,
            condition_mnemonics=("str", "stp"),
            patch_bytes=b"\xE0\x03\x1F\x2A\xC0\x03\x5F\xD6",
            patch_size_hex="0008",
        ),
        PatchRule(
            name="nim_blockfw_6.0.0-6.2.0",
            module="NIM-FW",
            min_version="6.0.0",
            max_version="6.2.0",
            pattern="F30301AA..4E",
            offset=-40,
            head_offset=0,
            condition_mnemonics=("str", "stp"),
            patch_bytes=b"\xE0\x03\x1F\x2A\xC0\x03\x5F\xD6",
            patch_size_hex="0008",
        ),
        PatchRule(
            name="nim_blockfw_7.0.0-10.2.0",
            module="NIM-FW",
            min_version="7.0.0",
            max_version="10.2.0",
            pattern="F30301AA014C",
            offset=-36,
            head_offset=0,
            condition_mnemonics=("str", "stp"),
            patch_bytes=b"\xE0\x03\x1F\x2A\xC0\x03\x5F\xD6",
            patch_size_hex="0008",
        ),
        PatchRule(
            name="nim_blockfw_11.0.0-11.0.1",
            module="NIM-FW",
            min_version="11.0.0",
            max_version="11.0.1",
            pattern="9AF0....................C0035FD6",
            offset=16,
            head_offset=0,
            condition_mnemonics=("str", "stp"),
            patch_bytes=b"\xE0\x03\x1F\x2A\xC0\x03\x5F\xD6",
            patch_size_hex="0008",
        ),
        PatchRule(
            name="nim_blockfw_12.0.0+",
            module="NIM-FW",
            min_version="12.0.0",
            max_version=FW_VER_ANY,
            pattern="41....4C............C0035FD6",
            offset=14,
            head_offset=0,
            condition_mnemonics=("str", "stp"),
            patch_bytes=b"\xE0\x03\x1F\x2A\xC0\x03\x5F\xD6",
            patch_size_hex="0008",
        )
    ],
    "FS": [
        PatchRule(
            name="fs_noacidsigchk1_1.0.0-9.2.0",
            module="FS",
            min_version="1.0.0",
            max_version="9.2.0",
            pattern="C8FE4739",
            offset=-24,
            head_offset=0,
            condition_mnemonics=("bl"),
            patch_bytes=b"\xE0\x03\x1F\x2A",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="fs_noacidsigchk2_1.0.0-9.2.0",
            module="FS",
            min_version="1.0.0",
            max_version="9.2.0",
            pattern="0210911F000072",
            offset=-5,
            head_offset=0,
            condition_mnemonics=("bl"),
            patch_bytes=b"\xE0\x03\x1F\x2A",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="fs_noncasigchk_1.0.0-3.0.2",
            module="FS",
            min_version="1.0.0",
            max_version="3.0.2",
            pattern="88..42..58",
            offset=-4,
            head_offset=0,
            condition_mnemonics=("tbz"),
            patch_bytes=b"\x1F\x20\x03\xD5",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="fs_noncasigchk_4.0.0-16.1.0",
            module="FS",
            min_version="4.0.0",
            max_version="16.1.0",
            pattern="1E4839....00......0054",
            offset=-17,
            head_offset=0,
            condition_mnemonics=("tbz"),
            patch_bytes=b"\x1F\x20\x03\xD5",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="fs_noncasigchk_17.0.0+",
            module="FS",
            min_version="17.0.0",
            max_version=FW_VER_ANY,
            pattern="0694....00..42..0091",
            offset=-18,
            head_offset=0,
            condition_mnemonics=("tbz"),
            patch_bytes=b"\x1F\x20\x03\xD5",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="fs_nocntchk_1.0.0-18.1.0",
            module="FS",
            min_version="1.0.0",
            max_version="18.1.0",
            pattern="40F9........081C00121F05",
            offset=2,
            head_offset=0,
            condition_mnemonics=("bl"),
            patch_bytes=b"\xE0\x03\x1F\x2A",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="fs_nocntchk_19.0.0+",
            module="FS",
            min_version="19.0.0",
            max_version=FW_VER_ANY,
            pattern="40F9............40B9091C",
            offset=2,
            head_offset=0,
            condition_mnemonics=("bl"),
            patch_bytes=b"\xE0\x03\x1F\x2A",
            patch_size_hex="0004",
        )
    ],
    "LOADER" : [
        PatchRule(
            name="noacidsigchk_10.0.0+",
            module="LOADER",
            min_version="10.0.0",
            max_version=FW_VER_ANY,
            pattern="009401C0BE121F00",
            offset=6,
            head_offset=0,
            condition_mnemonics=("cmp"),
            patch_bytes=b"\x1F\x00\x00\x6B",
            patch_size_hex="0004",
        )
    ],
    "ERPT" : [
        PatchRule(
            name="no_erpt",
            module="ERPT",
            min_version="10.0.0",
            max_version=FW_VER_ANY,
            pattern="FD7B02A9FD830091F76305A9",
            offset=-4,
            head_offset=0,
            condition_mnemonics=("sub"),
            patch_bytes=b"\xE0\x03\x1F\x2A\xC0\x03\x5F\xD6",
            patch_size_hex="0008",
        )
    ],
}

def get_module_id(nso0):
    with open(nso0, 'rb') as f:
        f.seek(0x40)
        return binascii.hexlify(f.read(0x14)).decode('utf-8').upper()


def is_valid_version_format(version_str: str) -> bool:
    """Check if version string matches semantic versioning pattern X.Y.Z"""
    try:
        parts = version_str.split('.')
        if len(parts) < 2 or len(parts) > 3:
            return False
        for part in parts:
            if not part.isdigit():
                return False
        return True
    except Exception:
        return False


def get_valid_version_folders(output_dir: str = 'output') -> List[str]:
    """Get all valid version folders from output directory"""
    valid_versions = []

    if not os.path.isdir(output_dir):
        print(f"Error: Output directory '{output_dir}' not found.")
        sys.exit(1)

    try:
        entries = os.listdir(output_dir)
    except Exception as e:
        print(f"Error: Failed to read directory '{output_dir}': {e}")
        sys.exit(1)

    for entry in entries:
        folder_path = os.path.join(output_dir, entry)
        if os.path.isdir(folder_path) and is_valid_version_format(entry):
            valid_versions.append(entry)

    if not valid_versions:
        print(f"Error: No folders matching version format (X.Y.Z) found in '{output_dir}'.")

    valid_versions.sort(key=version_to_tuple)
    return valid_versions


def hex_string_to_python_bytes(hex_str: str) -> str:
    """Convert hex string to Python byte string representation"""
    hex_str = hex_str.strip()
    byte_list = [f"\\x{hex_str[i:i+2].lower()}" for i in range(0, len(hex_str), 2)]
    return "b'" + "".join(byte_list) + "'"

fs_kip_patch_database = []
ldr_kip_patch_database = []
ips_patch_database = []

es_pattern_diffs = {}
blockfirmwareupdates_pattern_diffs = {}
blankcal0crashfix_pattern_diffs = {}
nifm_pattern_diffs = {}
olsc_pattern_diffs = {}

fat32_nocntchk_pattern_diffs = {}
exfat_nocntchk_pattern_diffs = {}
fat32_noncasigchk_pattern_diffs = {}
exfat_noncasigchk_pattern_diffs = {}

fat32_noacidsigchk1_pattern_diffs = {}
exfat_noacidsigchk1_pattern_diffs = {}
fat32_noacidsigchk2_pattern_diffs = {}
exfat_noacidsigchk2_pattern_diffs = {}

es_pattern_offsets = {}
blockfirmwareupdates_pattern_offsets = {}
blankcal0crashfix_pattern_offsets = {}
nifm_pattern_offsets = {}
olsc_pattern_offsets = {}
fat32_noncasigchk_pattern_offsets = {}
exfat_noncasigchk_pattern_offsets = {}
fat32_nocntchk_pattern_offsets = {}
exfat_nocntchk_pattern_offsets = {}

fat32_nosigchk1_pattern_offsets = {}
fat32_nosigchk2_pattern_offsets = {}

exfat_nosigchk1_pattern_offsets = {}
exfat_nosigchk2_pattern_offsets = {}

fat32_noacidsigchk1_pattern_offsets = {}
exfat_noacidsigchk1_pattern_offsets = {}
fat32_noacidsigchk2_pattern_offsets = {}
exfat_noacidsigchk2_pattern_offsets = {}

if args.ams:
    erpt_pattern_diffs = {}
    erpt_pattern_offsets = {}
    loader_pattern_diffs = {}
    loader_pattern_offsets = {}

mkdirp("output")

valid_versions = get_valid_version_folders('output')

if not valid_versions:
    print("No valid version folders found in 'output/'.")
    print("Skipping all per-version processing (pattern searching, summaries, debug logs, diffs).\n")
else:
    print(f"Found {len(valid_versions)} valid version folders: {', '.join(valid_versions)}\n")

    for version in valid_versions:
        current_firmware_version = version

        es_path = f'output/{version}/{version}_uncompressed_es.nso0'
        nim_path = f'output/{version}/{version}_uncompressed_nim.nso0'
        nifm_path = f'output/{version}/{version}_uncompressed_nifm.nso0'
        olsc_path = f'output/{version}/{version}_uncompressed_olsc.nso0'
        ssl_path = f'output/{version}/{version}_uncompressed_ssl.nso0'
        compressed_fat32_path = f'output/{version}/{version}_fat32_FS.kip1'
        decompressed_fat32_path = f'output/{version}/{version}_fat32_uFS.kip1'
        compressed_exfat_path = f'output/{version}/{version}_exfat_FS.kip1'
        decompressed_exfat_path = f'output/{version}/{version}_exfat_uFS.kip1'

        if os.path.exists(compressed_fat32_path):
            fat32hash = hashlib.sha256(open(compressed_fat32_path, 'rb').read()).hexdigest().upper()
        if os.path.exists(compressed_exfat_path):
            exfathash = hashlib.sha256(open(compressed_exfat_path, 'rb').read()).hexdigest().upper()

        with open(f'output/{version}/{version}_patch_summary_with_diff_strings.txt', 'w') as find_patterns:

            find_and_patch(
                es_path, version, "ES", find_patterns,
                es_pattern_diffs, es_pattern_offsets,
                ips_patch_database,
                hekate_patch_db=None
            )

            find_and_patch(
                olsc_path, version, "OLSC", find_patterns,
                olsc_pattern_diffs, olsc_pattern_offsets,
                ips_patch_database,
                hekate_patch_db=None
            )

            find_and_patch(
                nifm_path, version, "NIFM", find_patterns,
                nifm_pattern_diffs, nifm_pattern_offsets,
                ips_patch_database,
                hekate_patch_db=None
            )

            block_fw_fragment = find_and_patch(
                nim_path, version, "NIM-FW", find_patterns,
                blockfirmwareupdates_pattern_diffs, blockfirmwareupdates_pattern_offsets,
                ips_patch_database,
                hekate_patch_db=None
            )

            find_and_patch(
                nim_path, version, "NIM", find_patterns,
                blankcal0crashfix_pattern_diffs, blankcal0crashfix_pattern_offsets,
                ips_patch_database,
                hekate_patch_db=None,
                prior_patch_fragment=block_fw_fragment
            )

            find_and_patch(
                decompressed_fat32_path, version, "FS", find_patterns,
                fat32_noncasigchk_pattern_diffs,
                fat32_noncasigchk_pattern_offsets,
                ips_patch_database,
                hekate_patch_db=fs_kip_patch_database,
                is_fs=True,
                fs_type="FAT32",
                compressed_path=compressed_fat32_path
            )

            find_and_patch(
                decompressed_exfat_path, version, "FS", find_patterns,
                exfat_noncasigchk_pattern_diffs,
                exfat_noncasigchk_pattern_offsets,
                ips_patch_database,
                hekate_patch_db=fs_kip_patch_database,
                is_fs=True,
                fs_type="EXFAT",
                compressed_path=compressed_exfat_path
            )

            patchvalue5 = "08" # SSL
            patchvalue6 = "1300" # SSL
            patchvalue7 = "14" # SSL
            patchvalue8 = "08008052" # SSL

            ssl_pattern1 = rb'\x08\x00\x80\x12\x69\x12\x05\x91\x7f\x1e\x00\xf9\x68\x42\x00\xb9'
            ssl_pattern2 = rb'\x24\x09\x43\x7a\xa0\x00\x00\x54'
            ssl_pattern3 = rb'\x88\x16\x00\x12'
            ssl_offset1 = 16 # # ssl_pattern1
            ssl_offset2 = 4 # ssl_pattern2
            ssl_offset3 = 7 # ssl_pattern2
            ssl_offset4 = 8 # ssl_pattern3

            if version_to_tuple(version) >= version_to_tuple("21.0.0"):
                with open(f'{ssl_path}', 'rb') as decompressed_ssl_nso:
                    read_data = decompressed_ssl_nso.read()
                    result1 = re.search(ssl_pattern1, read_data)
                    result2 = re.search(ssl_pattern2, read_data)
                    result3 = re.search(ssl_pattern3, read_data)
                    if not result1:
                        find_patterns.write(f'(SSL) {version} SSL pattern 1 no match found\n')
                        find_patterns.write(f'(SSL) SSL pattern 1 is invalid for: {version}\n\n')
                    if not result2:
                        find_patterns.write(f'(SSL) {version} SSL pattern 2 no match found\n')
                        find_patterns.write(f'(SSL) SSL pattern 2 is invalid for: {version}\n\n')
                    if not result3:
                        find_patterns.write(f'(SSL) {version} SSL pattern 3 no match found\n')
                        find_patterns.write(f'(SSL) SSL pattern 3 is invalid for: {version}\n\n')
                    if (result1 and result2 and result3):
                        offset1 = '%06X' % (result1.start() + ssl_offset1)
                        offset2 = '%06X' % (result2.start() + ssl_offset2)
                        offset3 = '%06X' % (result2.start() + ssl_offset3)
                        offset4 = '%06X' % (result3.start() + ssl_offset4)
                        decompressed_ssl_nso.seek(result1.start() + ssl_offset1)
                        ssl_patch1_bytes = decompressed_ssl_nso.read(0x4).hex().upper()
                        decompressed_ssl_nso.seek(result2.start() + ssl_offset2)
                        ssl_patch2_bytes = decompressed_ssl_nso.read(0x4).hex().upper()
                        decompressed_ssl_nso.seek(result3.start() + ssl_offset4)
                        ssl_patch3_bytes = decompressed_ssl_nso.read(0x4).hex().upper()
                        patch1 = '%08X%s%s' % (result1.start() + ssl_offset1, '0001', f'{patchvalue5}')
                        patch2 = '%08X%s%s' % (result2.start() + ssl_offset2, '0002', f'{patchvalue6}')
                        patch3 = '%08X%s%s' % (result2.start() + ssl_offset3, '0001', f'{patchvalue7}')
                        patch4 = '%08X%s%s' % (result3.start() + ssl_offset4, '0004', f'{patchvalue8}')
                        find_patterns.write(f'(SSL) patterns found results for: {version}\n')
                        find_patterns.write(f'(SSL) pattern 1 found at: {offset1} ## 21.0.0+ 0x119B60\n') 
                        find_patterns.write(f'(SSL) The ghidra-equivalent pattern used was: 08 00 80 12 69 12 05 91 7f 1e 00 f9 68 42 00 b9\n')
                        find_patterns.write(f'(SSL) The existing bytes at the offset are: {ssl_patch1_bytes}\n') # 21.0.0+ // 680080D2 // mov x8, #3
                        find_patterns.write(f'(SSL) this is patched out to become {patchvalue5}0080D2 (mov x8, #0), to make make register x8 (x10 20.5.0 and below) zero, so that the movk turns the value used into 0x100000000 instead of 0x100000003 - seen in the ghidra decompiled view\n')
                        find_patterns.write(f'(SSL) pattern 2 found at: {offset2} ## 21.0.0+ 0x11A914\n') 
                        find_patterns.write(f'(SSL) pattern 3 found at: {offset3} ## 21.0.0+ 0x11A917\n') 
                        find_patterns.write(f'(SSL) The ghidra-equivalent pattern used was: 24 09 43 7a a0 00 00 54\n')
                        find_patterns.write(f'(SSL) The existing bytes at the two offsets combined are: {ssl_patch2_bytes}\n') # 21.0.0+ // A0000054 // b.eq #0x14
                        find_patterns.write(f'(SSL) this is patched out to become  {patchvalue6}00{patchvalue7} (b #0x4c) to target the second branch instead of comparing values (b.eq #0x14) and going to the first one\n')
                        find_patterns.write(f'(SSL) pattern 4 found at: {offset4} ## 21.0.0+ 0x11A968\n') 
                        find_patterns.write(f'(SSL) The ghidra-equivalent pattern used was: 88 16 00 12\n')
                        find_patterns.write(f'(SSL) The existing bytes at the offset are: {ssl_patch3_bytes}\n') # 21.0.0+ // 684601B9 // str w8, [x19, #0x144]
                        find_patterns.write(f'(SSL) this is patched out to become {patchvalue8} (mov w8, #0), to prepare register w8 with a zero, for the purpose of making the function return 0 (success) later on.\n')
                        find_patterns.write(f'(SSL) {version} SSL moduleid (and what .ips filename should be): {get_module_id(ssl_path)}\n\n')
                        find_patterns.write(f'(SSL) IPS patch bytes would be:\n')
                        find_patterns.write(f'(SSL) {ips32_magic}{patch1}{patch2}{patch3}{patch4}{eeof_magic}\n\n')
                    else:
                        find_patterns.write(f'(SSL) one or more SSL patterns were not found\n\n')
            else:
                find_patterns.write(f'\n(SSL) only the very latest pattern is supported (21.0.0+), current version is: {version}\n\n')
        patch_summary_file = f'output/{version}/{version}_patch_summary_with_diff_strings.txt'  

if args.ams:
    if os.path.exists('package3_and_stratosphere_extracted'):
        shutil.rmtree('package3_and_stratosphere_extracted')
    ams_string = package3_and_stratosphere.download_and_extract_package3_and_stratosphere_romfs()
    uncompressed_erpt_path = f'package3_and_stratosphere_extracted/uncompressed_erpt.nso0'

    with open('output/erpt_patch_summary.txt', 'w', encoding='utf-8') as erpt_log:
        find_and_patch(
            uncompressed_erpt_path, version, "ERPT", erpt_log,
            erpt_pattern_diffs, erpt_pattern_offsets,
            ips_patch_database,
            hekate_patch_db=None
        )

    loader_path = f'package3_and_stratosphere_extracted/u_loader.kip1'
    compressed_loader_path = f'package3_and_stratosphere_extracted/loader.kip1' 

    if os.path.exists(compressed_loader_path):
        with open('output/loader_patch_summary.txt', 'w', encoding='utf-8') as loader_log:
            find_and_patch(
                loader_path, version, "LOADER", loader_log,
                loader_pattern_diffs, loader_pattern_offsets,
                ips_patch_database,
                hekate_patch_db=ldr_kip_patch_database,
                is_fs=False,
                compressed_path=compressed_loader_path,
                atmosphere_string=ams_string
            )

        try:
            if not version:
                pass

        except NameError:
            version = "latest"
            try:
                url = "https://raw.githubusercontent.com/Atmosphere-NX/Atmosphere/master/libraries/libvapours/include/vapours/ams/ams_api_version.h"
                req = Request(url)
                req.add_header('User-Agent', 'Mozilla/5.0 (compatible; find_patterns.py)')

                with urlopen(req) as response:
                    content = response.read().decode('utf-8')

                major_match = re.search(r'#define ATMOSPHERE_SUPPORTED_HOS_VERSION_MAJOR\s+(\d+)', content)
                minor_match = re.search(r'#define ATMOSPHERE_SUPPORTED_HOS_VERSION_MINOR\s+(\d+)', content)
                micro_match = re.search(r'#define ATMOSPHERE_SUPPORTED_HOS_VERSION_MICRO\s+(\d+)', content)

                if major_match and minor_match and micro_match:
                    version = f"{major_match.group(1)}.{minor_match.group(1)}.{micro_match.group(1)}"
                    print(f"Fetched latest supported HOS version from Atmosphere: {version}")
                else:
                    print("Warning: Could not parse version macros — using 'latest'.")
            except Exception as e:
                print(f"Warning: Failed to fetch latest HOS version: {e}. Using 'latest'.")


print("\n" + "="*80)
print("Updating scripts/pattern_diffs.py and patch databases incrementally...")
print("="*80 + "\n")

pattern_diffs_path = 'scripts/pattern_diffs.py'
existing_diffs = load_existing_pattern_diffs(pattern_diffs_path)

diff_categories = [
    ('es_pattern_diffs', es_pattern_diffs),
    ('blankcal0crashfix_pattern_diffs', blankcal0crashfix_pattern_diffs),
    ('blockfirmwareupdates_pattern_diffs', blockfirmwareupdates_pattern_diffs),
    ('nifm_pattern_diffs', nifm_pattern_diffs),
    ('olsc_pattern_diffs', olsc_pattern_diffs),
    ('fat32_noacidsigchk1_pattern_diffs', fat32_noacidsigchk1_pattern_diffs),
    ('exfat_noacidsigchk1_pattern_diffs', exfat_noacidsigchk1_pattern_diffs),
    ('fat32_noacidsigchk2_pattern_diffs', fat32_noacidsigchk2_pattern_diffs),
    ('exfat_noacidsigchk2_pattern_diffs', exfat_noacidsigchk2_pattern_diffs),
    ('fat32_noncasigchk_pattern_diffs', fat32_noncasigchk_pattern_diffs),
    ('exfat_noncasigchk_pattern_diffs', exfat_noncasigchk_pattern_diffs),
    ('fat32_nocntchk_pattern_diffs', fat32_nocntchk_pattern_diffs),
    ('exfat_nocntchk_pattern_diffs', exfat_nocntchk_pattern_diffs),
]

if args.ams:
    diff_categories += [
        ('loader_pattern_diffs', loader_pattern_diffs),
        ('erpt_pattern_diffs', erpt_pattern_diffs),
    ]

updated = False
for category_name, new_dict in diff_categories:
    old_dict = existing_diffs[category_name]
    for version, diff_str in new_dict.items():
        py_bytes = hex_string_to_python_bytes(diff_str)
        if version not in old_dict or old_dict[version] != py_bytes:
            old_dict[version] = py_bytes
            updated = True

if updated or not os.path.exists(pattern_diffs_path):
    try:
        with open(pattern_diffs_path, 'w', encoding='utf-8') as f:
            f.write("# Auto-generated pattern diff strings\n")
            f.write("# Generated from find_patterns.py\n")
            f.write("# Do not edit manually unless you know what you're doing — new runs will preserve entries.\n\n")

            for category_name, _ in diff_categories:
                data = existing_diffs[category_name]
                
                entries = sorted(
                    data.items(),
                    key=lambda x: version_to_tuple(x[0])
                )
                
                if not entries:
                    f.write(f"{category_name} = []\n\n")
                    continue
                    
                f.write(f"{category_name} = [\n")
                for version, py_bytes in entries:
                    f.write(f"    ('{version}', {py_bytes}),\n")
                f.write("]\n\n")

        print(f"Updated {pattern_diffs_path} with new/missing versions.")
        total_entries = sum(len(d) for d in existing_diffs.values())
        print(f"  Total diff entries preserved/added: {total_entries}")
    except Exception as e:
        print(f"Error writing {pattern_diffs_path}: {e}")
else:
    print(f"No new pattern diffs to add — {pattern_diffs_path} unchanged.")


fs_kip_patch_database = remove_duplicates_by_index(fs_kip_patch_database, 1)
ldr_kip_patch_database = remove_duplicates_by_index(ldr_kip_patch_database, 1)
ips_patch_database = remove_duplicates_by_index(ips_patch_database, 1)

fs_kip_updated = update_patch_file('patch_database/fs_kip_patches.txt', fs_kip_patch_database)
ldr_kip_updated = update_patch_file('patch_database/ldr_kip_patches.txt', ldr_kip_patch_database)
ips_updated = update_patch_file('patch_database/ips_patches.txt', ips_patch_database)

if not fs_kip_updated and not ips_updated and not ldr_kip_updated:
    print("All patch databases already up to date.")

print("\nMerging SDK versions into fs_kip_patches.txt (adding missing SDK versions only)...")

fs_kip_file = 'patch_database/fs_kip_patches.txt'
fs_sdk_file = 'patch_database/fs_sdk_versions.txt'

if not os.path.exists(fs_sdk_file):
    print(f"{fs_sdk_file} not found — skipping SDK version merge.")
else:
    sdk_entries = load_existing_patches(fs_sdk_file)
    print(f"Loaded {len(sdk_entries)} entries from fs_sdk_versions.txt")

    sdk_map = {}
    for entry in sdk_entries:
        if len(entry) >= 3:
            fw_version = entry[0]
            short_16 = entry[1]
            full_hash = entry[2].upper()
            sdk_version = entry[3]
            sdk_map[(fw_version, short_16)] = sdk_version

    print(f"Built SDK map with {len(sdk_map)} unique (fw_version, 16-char short) entries")

    kip_entries = load_existing_patches(fs_kip_file)
    print(f"Loaded {len(kip_entries)} entries from fs_kip_patches.txt")

    added_count = 0
    new_kip_entries = []

    for entry in kip_entries:
        if len(entry) == 4:
            new_kip_entries.append(entry)
            continue
        if len(entry) != 3:
            new_kip_entries.append(entry)
            continue

        fw_version = entry[0]
        patch_str = entry[1]
        fs_type = entry[2]

        match = re.search(r'\[FS:([0-9A-F]{16})\]', patch_str[:21])
        if not match:
            print(f"Warning: Could not parse 16-char TitleID from: {patch_str[:21].strip()}")
            new_kip_entries.append(entry)
            continue

        short_16 = match.group(1).upper()

        key = (fw_version, short_16)
        sdk_version = sdk_map.get(key)

        if sdk_version:
            new_entry = (fw_version, patch_str, fs_type, sdk_version)
            new_kip_entries.append(new_entry)
            added_count += 1
            print(f"Added SDK {sdk_version} to {fw_version} {fs_type} ({short_16})")
        else:
            print(f"No exact 16-char match for {fw_version} {fs_type} ({short_16})")
            new_kip_entries.append(entry)

    if added_count > 0:
        try:
            with open(fs_kip_file, 'w', encoding='utf-8') as f:
                for entry in new_kip_entries:
                    f.write(f"{entry},\n")
            print(f"\nSuccessfully appended SDK version to {added_count} entries in fs_kip_patches.txt!")
        except Exception as e:
            print(f"Error writing {fs_kip_file}: {e}")
    else:
        print("\nNo SDK versions appended — all entries either already have SDK or no exact 16-char match found.")

print("="*80)

# Cleanup AMS temp files if used
if os.path.exists('package3_and_stratosphere_extracted'):
    shutil.rmtree('package3_and_stratosphere_extracted')

print("\nIncremental update complete!")