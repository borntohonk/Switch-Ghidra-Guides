#!/usr/bin/env python

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

import re
from pathlib import Path
from hashlib import sha256
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

args, _ = parser.parse_known_args()


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
    suppress_logging: bool = False,
    is_fs: bool = False,
    fs_type: str = "",
    prior_patch_fragment: str = None,
    hash_path: Optional[str] = None,
    atmosphere_string: Optional[str] = None
) -> Optional[str]:
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
    raw_ips_components = []  # Store raw components to rebuild with correct format after magic is determined
    hekate_lines = []
    successful_patches = []  # collect for grouped logging

    module_id = get_module_id(module_path)

    short_hash = None
    if hash_path and os.path.exists(hash_path):
        if hash_path.endswith(".kip1"):
            file_hash = sha256(Path(hash_path).read_bytes()).hexdigest().upper()
        else:
            file_hash = Path(hash_path).read_text(encoding="utf-8").strip()
        log_file.write(f"({module_name}) Using compressed hash from {hash_path}\n")
        short_hash = file_hash[:16]
        module_id = file_hash  # override for FS

    found_any = False

    for rule in rules:
        pattern_regex = convert_sys_patch_nibble_string(rule.pattern)
        all_matches = list(re.finditer(pattern_regex, hex_data))
        try:
            match = all_matches[rule.match_position]
        except:
            match = None

        if not match:
            print(f"no match found for {version} - {module_name} with the pattern of '{rule.pattern}'")
            continue

        found_any = True

        match_start = match.start() // 2
        patch_offset = match_start + rule.offset
        head_offset = patch_offset + rule.head_offset

        patch_size_int = int(rule.patch_size_hex, 16)
        patch_size_int_for_mnemonic = patch_size_int
        if patch_size_int_for_mnemonic < 4:
            patch_size_int_for_mnemonic = 4
        existing = data[head_offset:head_offset + patch_size_int_for_mnemonic]
        mnemonic = get_arm_cond(existing, head_offset)

        if mnemonic not in rule.condition_mnemonics:
            log_file.write(
                f"({module_name}) Condition failed for '{rule.name}' at 0x{patch_offset:X} "
                f"(got {mnemonic}, expected one of {rule.condition_mnemonics})\n"
            )
            continue

        if module_name == "NOGC":
            patch_offset = patch_offset + 0x101
            head_offset = head_offset + 0x101
            if rule.name == "fs_nogc3_19.0.0+":
                patch_offset = patch_offset - 0x1
                head_offset = head_offset - 0x1

        diff_start = max(0, patch_offset - 0x20)
        diff_end = diff_start + 0x60
        diff_bytes = data[diff_start:diff_end]
        diff_str = diff_bytes.hex().upper()
        pattern_diffs[version] = diff_str

        offset_hex = f"{patch_offset:X}".zfill(6).upper()

        # ─── Collect for later grouped logging ───
        successful_patches.append({
            'rule_name': rule.name,
            'offset_hex': offset_hex,
            'existing_hex': existing.hex().upper(),
            'mnemonic': mnemonic,
            'patch_hex': rule.patch_bytes.hex().upper(),
            'sys_patch_pattern': rule.pattern,
            'diff_str': diff_str,
            'head_offset': head_offset,
            'patch_size_int': patch_size_int,
            'patch_bytes': rule.patch_bytes,
        })

        # Build IPS record (will use correct format once magic is determined)
        ips_record = build_ips_record(head_offset, rule.patch_size_hex, rule.patch_bytes)
        collected_ips_records.append(ips_record)
        raw_ips_components.append((head_offset, rule.patch_size_hex, rule.patch_bytes))

        pattern_offsets[version] = (module_name, existing.hex().upper(), offset_hex, module_id)

        # Hekate style entry
        if hekate_patch_db is not None:
            hekate_offset = head_offset - 0x100
            original_hex = existing.hex().upper()
            patch_hex = rule.patch_bytes.hex().upper()
            line = (
                f".nosigchk=0:0x{hekate_offset:06X}:0x{patch_size_int:X}:"
                f"{original_hex},{patch_hex}"
            )
            hekate_lines.append(line)

    # ──────────────────────────────────────────────────────────────
    #   Grouped logging — happens only once per module call
    # ──────────────────────────────────────────────────────────────
    if successful_patches and not suppress_logging:
        # Header (printed only once)
        if module_name in ["FS", "LOADER"]:
            log_file.write(f"({module_name}) SHA256 of {hash_path} is:\n")
            log_file.write(f"({module_name}) {module_id}\n")
        else:
            log_file.write(f"({module_name}) moduleid of {module_path} is:\n")
            log_file.write(f"({module_name}) {module_id}\n")

        log_file.write(f"({module_name}) Found {len(successful_patches)} patch location(s) for {version}\n\n")

        for patch in successful_patches:
            log_patch_success(
                log_file,
                module_name,
                version,
                patch['rule_name'],
                patch['offset_hex'],
                patch['existing_hex'],
                patch['mnemonic'],
                patch['patch_hex'],
                patch['sys_patch_pattern'],
                patch['diff_str']
            )

            # Disassembly of before/after for this specific patch
            write_arm_bytes_and_patch(
                patch['patch_bytes'],
                data[patch['head_offset']:patch['head_offset'] + patch['patch_size_int']],
                patch['head_offset'],
                log_file
            )

            # Instruction context around this patch
            ctx_start = max(0, patch['head_offset'] - 0x20)
            ctx_end = patch['head_offset'] + 0x40
            get_arm_instruction_order(
                data[ctx_start:ctx_end],
                patch['head_offset'],
                log_file
            )

            #log_file.write("-" * 60 + "\n")

        log_file.write("\n")

    if not found_any:
        log_file.write(f"({module_name}) No valid patch location found for {version}\n\n")
        return None

    collect_embedded_patches(module_name, version, module_id, successful_patches)

    # ─── IPS fragment building (unchanged) ───
    if collected_ips_records:
        if prior_patch_fragment:
            full_ips_content = prior_patch_fragment + "".join(collected_ips_records)
        else:
            magic = ips32_magic if len(collected_ips_records) > 1 else patch_magic
            end_magic = eeof_magic if magic == ips32_magic else eof_magic
            # Rebuild records with correct offset format based on magic type
            rebuilt_records = [build_ips_record(offset, size_hex, patch_data, magic) 
                              for offset, size_hex, patch_data in raw_ips_components]
            full_ips_content = build_ips_file(magic, rebuilt_records, end_magic)

        # patch path logic unchanged
        if module_name in ["FS", "LOADER"]:
            subfolder = "fs_patches" if module_name == "FS" else "loader_patches"
            patch_path = f"patches/atmosphere/kip_patches/{subfolder}/"
        elif module_name == "BROWSER":
            patch_path = 'patches/atmosphere/nro_patches/disable_browser_ca_verification/'
        elif module_name == "SSL":
            patch_path = 'patches/atmosphere/exefs_patches/disable_ca_verification/'
        else:
            patch_path = f"patches/atmosphere/exefs_patches/{module_name.lower()}_patches/"

        ips_patch_database.append((version, module_id, patch_path, full_ips_content))

    # ─── Hekate patch block (unchanged, uses is_fs, fs_type, atmosphere_string) ───
    if hekate_patch_db is not None and hekate_lines:
        if is_fs:
            title = f"[FS:{short_hash}]\n"
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

    return full_ips_content if collected_ips_records else None

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
        'ns_pattern_diffs': {},
        'usb_pattern_1_diffs': {},
        'usb_pattern_2_diffs': {},
        'usb_pattern_3_diffs': {},
        'olsc_pattern_diffs': {},
        'am_pattern_diffs': {},
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
        'browser_pattern_diffs': {},
        'ssl_pattern_1_diffs': {},
        'ssl_pattern_2_diffs': {},
        'ssl_pattern_3_diffs': {},
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

EMBEDDED_PATCH_EXCLUDED_MODULES = {"FS", "LOADER", "NOGC", "ERPT", "OLSC", "SSL", "BROWSER"}
EMBEDDED_MODULE_PATCH_GROUPS = {
    "NIM": ("NimPatches", "Patch NIM firmware update blocking and blank PRODINFO handling."),
}
EMBEDDED_PATCH_NAMES = {
    ("AM", "am-22.0.0+"): ("AmDisableTeardownPatches", "Patch teardown function call to NOP."),
}


def _strip_rule_version_suffix(rule_name: str) -> str:
    return re.sub(r'[-_]\d+\.\d+\.\d+.*$', '', rule_name)


def _to_pascal_identifier(value: str) -> str:
    words = re.findall(r'[A-Z]+(?=[A-Z][a-z]|\d|\b)|[A-Z]?[a-z]+|\d+', value)
    return ''.join(word[:1].upper() + word[1:].lower() for word in words)


def _embedded_patch_metadata(module_name: str, rule_name: str) -> Tuple[str, str]:
    mapped = EMBEDDED_MODULE_PATCH_GROUPS.get(module_name)
    if mapped:
        return mapped

    mapped = EMBEDDED_PATCH_NAMES.get((module_name, rule_name))
    if mapped:
        return mapped

    base_name = _strip_rule_version_suffix(rule_name)
    module_prefix = module_name.lower()
    if base_name.lower().startswith(module_prefix + "_"):
        base_name = base_name[len(module_prefix) + 1:]
    elif base_name.lower().startswith(module_prefix + "-"):
        base_name = base_name[len(module_prefix) + 1:]

    patch_name = _to_pascal_identifier(module_name + "_" + base_name)
    if patch_name == _to_pascal_identifier(module_name):
        patch_name += "Patch"

    return f"{patch_name}Patches", f"{rule_name}."


def _format_cpp_version_suffix(version: str) -> str:
    return re.sub(r'[^A-Za-z0-9]', '_', version)


def _format_cpp_byte_string(patch_bytes: bytes) -> str:
    return ''.join(f"\\x{byte:02X}" for byte in patch_bytes)


def collect_embedded_patches(
    module_name: str,
    version: str,
    module_id: str,
    successful_patches: List[Dict]
):
    if module_name in EMBEDDED_PATCH_EXCLUDED_MODULES:
        return

    module_type = module_name.lower()
    for patch in successful_patches:
        patch_name, comment = _embedded_patch_metadata(module_name, patch['rule_name'])
        patch_group = embedded_patch_database.setdefault(
            (module_type, patch_name),
            {
                'module_type': module_type,
                'patch_name': patch_name,
                'comment': comment,
                'versions': {},
            }
        )

        version_group = patch_group['versions'].setdefault(
            version,
            {
                'module_id': module_id,
                'entries': [],
            }
        )

        entry = (patch['head_offset'] - 0x100, patch['patch_bytes'])
        if entry not in version_group['entries']:
            version_group['entries'].append(entry)


def write_embedded_patch_files(output_dir: str = 'output'):
    if not embedded_patch_database:
        print("No embedded patches generated.")
        return

    grouped_by_module = {}
    for patch_group in embedded_patch_database.values():
        grouped_by_module.setdefault(patch_group['module_type'], []).append(patch_group)

    for module_type, patch_groups in sorted(grouped_by_module.items()):
        filepath = os.path.join(output_dir, f"ldr_embedded_{module_type}_patches.inc")
        with open(filepath, 'w', encoding='utf-8', newline='\n') as f:
            f.write("/*\n")
            f.write(" * Copyright (c) Atmosphère-NX\n")
            f.write(" *\n")
            f.write(" * This program is free software; you can redistribute it and/or modify it\n")
            f.write(" * under the terms and conditions of the GNU General Public License,\n")
            f.write(" * version 2, as published by the Free Software Foundation.\n")
            f.write(" *\n")
            f.write(" * This program is distributed in the hope it will be useful, but WITHOUT\n")
            f.write(" * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or\n")
            f.write(" * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for\n")
            f.write(" * more details.\n")
            f.write(" *\n")
            f.write(" * You should have received a copy of the GNU General Public License\n")
            f.write(" * along with this program.  If not, see <http://www.gnu.org/licenses/>.\n")
            f.write(" */\n\n")

            for patch_group in sorted(patch_groups, key=lambda item: item['patch_name']):
                patch_name = patch_group['patch_name']
                f.write(f"/* {patch_group['comment']} */\n")

                patch_variants = []
                patch_variant_map = {}
                for version, version_group in sorted(
                    patch_group['versions'].items(),
                    key=lambda item: version_to_tuple(item[0])
                ):
                    sorted_entries = tuple(sorted(version_group['entries'], key=lambda item: item[0]))
                    variant_key = (version_group['module_id'], sorted_entries)
                    if variant_key not in patch_variant_map:
                        patch_variant = {
                            'array_version': version,
                            'module_id': version_group['module_id'],
                            'entries': sorted_entries,
                            'versions': [],
                        }
                        patch_variant_map[variant_key] = patch_variant
                        patch_variants.append(patch_variant)

                    patch_variant_map[variant_key]['versions'].append(version)

                for patch_variant in patch_variants:
                    version_suffix = _format_cpp_version_suffix(patch_variant['array_version'])
                    f.write(f"constexpr inline const EmbeddedPatchEntry {patch_name}_{version_suffix}[] = {{\n")

                    for offset, patch_bytes in patch_variant['entries']:
                        f.write(
                            f"    {{ 0x{offset:X}, \"{_format_cpp_byte_string(patch_bytes)}\", {len(patch_bytes)} }},\n"
                        )

                    f.write("};\n\n")

                f.write(f"constexpr inline const EmbeddedPatch {patch_name}[] = {{\n")
                for patch_variant in patch_variants:
                    version_suffix = _format_cpp_version_suffix(patch_variant['array_version'])
                    entry_name = f"{patch_name}_{version_suffix}"
                    versions = ", ".join(patch_variant['versions'])
                    f.write(
                        f"    {{ ParseModuleId(\"{patch_variant['module_id']}\"), "
                        f"util::size({entry_name}), {entry_name} }}, /* {versions} */\n"
                    )
                f.write("};\n\n")

        print(f"Wrote embedded patch file: {filepath}")

def write_nogc_atmosphere_patch(patch_db, output_path='patch_database/nogc_atmosphere_patch.txt'):
    """Generate C++ switch-case block for fusee_stratosphere.cpp NoGC patches."""
    fat32_groups = {}  # offset_key → [version, ...]
    exfat_groups = {}

    for entry in patch_db:
        version, patch_string, fs_type = entry[0], entry[1], entry[2]
        offsets = re.findall(r'\.nosigchk=0:0x([0-9A-Fa-f]+):', patch_string)
        if len(offsets) != 3:
            continue
        key = tuple(o.upper() for o in offsets)
        if fs_type == 'FAT32':
            fat32_groups.setdefault(key, []).append(version)
        elif fs_type == 'EXFAT':
            exfat_groups.setdefault(key, []).append(version)

    for key in fat32_groups:
        fat32_groups[key].sort(key=version_to_tuple)
    for key in exfat_groups:
        exfat_groups[key].sort(key=version_to_tuple)

    # Match fat32/exfat groups by their frozenset of versions, sort by min version
    vs_to_fat32 = {frozenset(v): (k, v) for k, v in fat32_groups.items()}
    vs_to_exfat = {frozenset(v): (k, v) for k, v in exfat_groups.items()}
    all_vs = sorted(
        vs_to_fat32.keys() | vs_to_exfat.keys(),
        key=lambda vs: version_to_tuple(min(vs, key=version_to_tuple))
    )

    lines = []
    for vs in all_vs:
        if vs in vs_to_fat32:
            key, versions = vs_to_fat32[vs]
            for version in versions:
                lines.append(f'                case FsVersion_{version.replace(".", "_")}:')
            off1, off2, off3 = key
            lines.append(f'                    AddPatch(fs_meta, 0x{off1}, NogcPatch0, sizeof(NogcPatch0));')
            lines.append(f'                    AddPatch(fs_meta, 0x{off2}, NogcPatch0, sizeof(NogcPatch0));')
            lines.append(f'                    AddPatch(fs_meta, 0x{off3}, NogcPatch1, sizeof(NogcPatch1));')
            lines.append(f'                    break;')
        if vs in vs_to_exfat:
            key, versions = vs_to_exfat[vs]
            for version in versions:
                lines.append(f'                case FsVersion_{version.replace(".", "_")}_Exfat:')
            off1, off2, off3 = key
            lines.append(f'                    AddPatch(fs_meta, 0x{off1}, NogcPatch0, sizeof(NogcPatch0));')
            lines.append(f'                    AddPatch(fs_meta, 0x{off2}, NogcPatch0, sizeof(NogcPatch0));')
            lines.append(f'                    AddPatch(fs_meta, 0x{off3}, NogcPatch1, sizeof(NogcPatch1));')
            lines.append(f'                    break;')

    lines.append('                default:')
    lines.append('                    break;')

    with open(output_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(lines) + '\n')
    print(f"Written NoGC atmosphere patch to {output_path}")


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

def build_ips_record(offset: int, size_hex: str, patch_data: bytes, magic: str = None) -> str:
    """Build an IPS record with correct offset format based on magic type.
    Uses 06X for PATCH magic, 08X for IPS32 magic.
    """
    is_ips32 = magic == ips32_magic if magic else True  # Default to IPS32 format
    offset_format = "08X" if is_ips32 else "06X"
    return f"{offset:{offset_format}}{size_hex}{patch_data.hex().upper()}"

def build_ips_file(magic: str, records: list[str], end_magic: str = "454F46") -> str:
    return magic + "".join(records) + end_magic

# sys-patch logic explanation:
# "(49, 0,) +49" (nifm/ctest) from start from the start the string found in it's entirity, as sys-patch tests things stupid, then it reads from 0x0 of the end in decimals where the "head" was placed (49),
# and the 4th byte from there is what is tested (for most cond checks), the next number determines where from the tested byte is being patched. (should be 0, otherwise its not testing the bytes being patched!)
# should be noted ams loader patch being (6,2) is different from this general rule of not testing for what is being patched.
# as it finds searches for "009401C0BE12(6)1F00(2)", testing 4 bytes from from offset (6) for cmp_cond byte of "6B",
# and then applies the patch of "00", two bytes offset after the testing point (0)1F00(2), turning (6)1F00(2)->01<-6B - cmp w0, w1 -  into (6)1F00(2)->00<-6B - cmp w0, w0

# mov 200 -> mov 400 (80 patch) ("first nogc patch") .start() + 12/0xc (13/0xd for what actually needs to be patched)
# .start() + 13
#fd 7b be a9 f. .. 0. .9 fd 03 00 91 .. 40 80 52 .. 01 ae 72 02 40 80 52
#fd7bbea9f...0..9fd030091..408052..01ae7202408052

# mov 200 -> mov 400 (80 patch) ("second nogc patch")
# this moved in 21.0.0 - pattern cannot match backwards and new one.

# 21.0.0+
# .start() + 33
#fd 7b be a9 f. .. 0. .9 fd 03 00 91 .. 40 80 52 .. 01 ae 72 02 40 80 52
#fd7bbea9f...0..9fd030091..408052..01ae7202408052

# offset of nogc patch 1 + 0x14 (0x15 if first pattern is 0x0)
# this pattern cannot support both 21.0.0+ and below at same time

# 19.0.0 to 20.0.0 
# .start() + 1
# 16 40 80 52 76 01 ae 72 e0 03 15 aa e1 03 16 aa 02 40 80 52 a6 16 00 94 .8 05 00 .0 e0 03 16 aa 08 .. .. f9 01 40 80 52 08 41 00 91 a8 02 00 f9
# 164080527601ae72e00315aae10316aa02408052a6160094.80500.0e00316aa08....f90140805208410091a80200f9


#stp patch mov + ret == ("third nogc patch") -> .start() + 4
# 00 00 00 00 fd 7b bd a9 f5 0b 00 f9 f4 4f 02 a9 fd 03 00 91 f3 03 00 aa .. 2. 00 94 08 0c 40 39 .. 0. 00 .. .. 0. .. .. .. 0. .. .. .. .. 00 94
# 00000000fd7bbda9f50b00f9f44f02a9fd030091f30300aa..2.0094080c4039..0.00....0.......0.........0094

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
    match_position: int
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
            match_position=0,
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
            match_position=0,
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
            match_position=0,
            condition_mnemonics=("sub", "ldp", "mov", "and", "mov"),
            patch_bytes=b"\xE0\x03\x1F\xAA",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="es_19.0.0-21.2.0",
            module="ES",
            min_version="19.0.0",
            max_version="21.2.0",
            pattern="A1........031F2A....0091",
            offset=32,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("sub", "ldp", "mov", "and", "mov"),
            patch_bytes=b"\xE0\x03\x1F\xAA",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="es_22.0.0+",
            module="ES",
            min_version="22.0.0",
            max_version=FW_VER_ANY,
            pattern="A0630091....FE97A08300D1....FE97",
            offset=16,
            head_offset=0,
            match_position=0,
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
            match_position=0,
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
            match_position=0,
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
            match_position=0,
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
            match_position=0,
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
            match_position=0,
            condition_mnemonics=("bl"),
            patch_bytes=b"\x20\x00\x80\xD2",
            patch_size_hex="0004",
        )
    ],
    "AM" : [
        PatchRule(
            name="am-22.0.0+",
            module="AM",
            min_version="22.0.0",
            max_version=FW_VER_ANY,
            pattern="682646391F0500716100005460420691794DFF97",
            offset=16,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("bl"),
            patch_bytes=b"\x1F\x20\x03\xD5",
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
            match_position=0,
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
            match_position=0,
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
            match_position=0,
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
            match_position=0,
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
            match_position=0,
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
            match_position=0,
            condition_mnemonics=("str", "stp"),
            patch_bytes=b"\xE0\x03\x1F\x2A\xC0\x03\x5F\xD6",
            patch_size_hex="0008",
        )
    ],
    "NS" : [
        PatchRule(
            name="TerraGameCardRegionBypass",
            module="NS",
            min_version="9.0.0",
            max_version=FW_VER_ANY,
            pattern="35E8134039F4031F..68020039",
            offset=9,
            head_offset=0,
            match_position=1,
            condition_mnemonics=("strb"),
            patch_bytes=b"\x7f\x02\x00\x39", # strb wzr,[x19] 
            patch_size_hex="0004",
        ),
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
            match_position=0,
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
            match_position=0,
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
            match_position=0,
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
            match_position=0,
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
            match_position=0,
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
            match_position=0,
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
            match_position=0,
            condition_mnemonics=("bl"),
            patch_bytes=b"\xE0\x03\x1F\x2A",
            patch_size_hex="0004",
        )
    ],
    "NOGC" : [
        PatchRule(
            name="fs_nogc1_19.0.0+",
            module="FS",
            min_version="19.0.0",
            max_version=FW_VER_ANY,
            pattern="FD7BBEA9F...0..9FD030091..408052..01AE7202408052",
            offset=13,
            head_offset=-1,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x80",
            patch_size_hex="0001",
        ),
        PatchRule(
            name="fs_nogc2_19.0.0-20.1.1",
            module="FS",
            min_version="19.0.0",
            max_version="20.5.0",
            pattern="164080527601AE72E00315AAE10316AA02408052A6160094.80500.0E00316AA08....F90140805208410091A80200F9",
            offset=1,
            head_offset=-1,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x80",
            patch_size_hex="0001",
        ),
        PatchRule(
            name="fs_nogc2_21.0.0+",
            module="FS",
            min_version="21.0.0",
            max_version=FW_VER_ANY,
            pattern="FD7BBEA9F...0..9FD030091..408052..01AE7202408052",
            offset=37,
            head_offset=-1,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x80",
            patch_size_hex="0001",
        ),
        PatchRule(
            name="fs_nogc3_19.0.0+",
            module="FS",
            min_version="19.0.0",
            max_version=FW_VER_ANY,
            pattern="00000000FD7BBDA9F50B00F9F44F02A9FD030091F30300AA..2.0094080C4039..0.00....0.......0.........0094",
            offset=4,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("stp"),
            patch_bytes=b"\xE0\x03\x1F\x2A\xC0\x03\x5F\xD6",
            patch_size_hex="0008",
        )
    ],
    "USB" : [
        PatchRule(
            name="Usb30ForceEnablePatches",
            module="USB",
            min_version="9.0.0",
            max_version="10.2.0",
            pattern="019408000012A92B8A52",
            offset=-2,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("sub"),
            patch_bytes=b"\x20\x00\x80\x52",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="Usb30ForceEnablePatches",
            module="USB",
            min_version="11.0.0",
            max_version=FW_VER_ANY,
            pattern="FFC300D1FD7B02A9FD83009188",
            offset=0,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("sub"),
            patch_bytes=b"\x20\x00\x80\x52\xC0\x03\x5F\xD6",
            patch_size_hex="0008",
        ),
        PatchRule(
            name="Usb30ForceEnablePatches",
            module="USB",
            min_version="11.0.0",
            max_version=FW_VER_ANY,
            pattern="FFC300D1FD7B02A9FD83009188",
            offset=0,
            head_offset=0,
            match_position=1,
            condition_mnemonics=("sub"),
            patch_bytes=b"\x20\x00\x80\x52\xC0\x03\x5F\xD6",
            patch_size_hex="0008",
        ),
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
            match_position=0,
            condition_mnemonics=("cmp"),
            patch_bytes=b"\x1F\x00\x00\x6B",
            patch_size_hex="0004",
        )
    ],
    "ERPT" : [
        PatchRule(
            name="no_erpt",
            module="ERPT",
            min_version="22.5.0",
            max_version=FW_VER_ANY,
            pattern="FD7B02A9FD830091F55B04A9",
            offset=-4,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("sub"),
            patch_bytes=b"\xE0\x03\x1F\x2A\xC0\x03\x5F\xD6",
            patch_size_hex="0008",
        )
    ],
    "BROWSER" : [
        PatchRule(
            name="verifyhost",
            module="BROWSER",
            min_version="22.5.0",
            max_version=FW_VER_ANY,
            pattern="E213881A210A805236008052F8F00294A0B641F9",
            offset=-4,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\xE8\x03\x1F\x2A",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="verifypeer",
            module="BROWSER",
            min_version="22.5.0",
            max_version=FW_VER_ANY,
            pattern="E213881A210A805236008052F8F00294A0B641F9",
            offset=20,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("bic"),
            patch_bytes=b"\xE2\x03\x1F\x2A",
            patch_size_hex="0004",
        )
    ],
    "SSL" : [
        PatchRule(
            name="disable_ca_verification",
            module="SSL1",
            min_version="22.0.0",
            max_version=FW_VER_ANY,
            pattern="08008012.9120591.F1E00F..84200B9",
            offset=16,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x08\x00\x80\xD2",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="disable_ca_verification",
            module="SSL2",
            min_version="22.0.0",
            max_version=FW_VER_ANY,
            pattern="880600121F0D0071A0000054",  
            offset=8, # 4 - 7
            head_offset=0,
            match_position=0,
            condition_mnemonics=("b.eq"),
            patch_bytes=b"\x13\x00\x00\x14",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="disable_ca_verification",
            module="SSL3",
            min_version="22.0.0",
            max_version=FW_VER_ANY,
            pattern="88160012",
            offset=8,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("str"),
            patch_bytes=b"\x08\x00\x08\x52",
            patch_size_hex="0004",
        )
    ]
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
ssl_ips_patch_database = []
embedded_patch_database = {}

nogc_kip_patch_database = []
nogc_ips_patch_database = []
nogc_pattern_diffs = {}

es_pattern_diffs = {}
blockfirmwareupdates_pattern_diffs = {}
blankcal0crashfix_pattern_diffs = {}
nifm_pattern_diffs = {}
ns_pattern_diffs = {}
usb_pattern_1_diffs = {}
usb_pattern_2_diffs = {}
usb_pattern_3_diffs = {}
olsc_pattern_diffs = {}
am_pattern_diffs = {}
fat32_nocntchk_pattern_diffs = {}
exfat_nocntchk_pattern_diffs = {}
fat32_noncasigchk_pattern_diffs = {}
exfat_noncasigchk_pattern_diffs = {}
fat32_noacidsigchk1_pattern_diffs = {}
exfat_noacidsigchk1_pattern_diffs = {}
fat32_noacidsigchk2_pattern_diffs = {}
exfat_noacidsigchk2_pattern_diffs = {}
browser_pattern_diffs = {}
ssl_pattern_1_diffs = {}
ssl_pattern_2_diffs = {}
ssl_pattern_3_diffs = {}

# Pattern offsets (used internally but can be simplified)
pattern_offsets_map = {
    'es': {}, 'nifm': {}, 'olsc': {}, 'am': {}, 'nim': {}, 'ns': {}, 'usb': {}, 'browser': {},
    'fat32_nc': {}, 'exfat_nc': {}, 'fat32_nogc': {}, 'exfat_nogc': {}, 'ssl_1': {}, 'ssl_2': {}, 'ssl_3': {},
}

if args.ams:
    erpt_pattern_diffs = {}
    loader_pattern_diffs = {}


def _process_firmware_version(version: str):
    """Process all patches for a single firmware version."""
    # Define file paths for this version
    files = {
        'es': f'output/{version}/{version}_es.nso0',
        'nim': f'output/{version}/{version}_nim.nso0',
        'ns': f'output/{version}/{version}_ns.nso0',
        'nifm': f'output/{version}/{version}_nifm.nso0',
        'olsc': f'output/{version}/{version}_olsc.nso0',
        'am': f'output/{version}/{version}_am.nso0',
        'ssl': f'output/{version}/{version}_ssl.nso0',
        'usb': f'output/{version}/{version}_usb.nso0',
        'fat32_hash': f'output/{version}/{version}_fat32.hash',
        'fat32': f'output/{version}/{version}_fat32_FS.kip1',
        'exfat_hash': f'output/{version}/{version}_exfat.hash',
        'exfat': f'output/{version}/{version}_exfat_FS.kip1',
        'browser': f'output/{version}/{version}_foss_browser_ssl.nro',
    }
    
    # Check which files exist
    existing_files = {k: v for k, v in files.items() if os.path.exists(v)}
    
    patch_summary_file = f'output/{version}/{version}_patch_summary_with_diff_strings.txt'
    
    with open(patch_summary_file, 'w') as log:
        # Process standard modules (only if files exist)
        if 'es' in existing_files:
            find_and_patch(existing_files['es'], version, "ES", log,
                es_pattern_diffs, pattern_offsets_map['es'], ips_patch_database)
        
        if 'olsc' in existing_files:
            find_and_patch(existing_files['olsc'], version, "OLSC", log,
                olsc_pattern_diffs, pattern_offsets_map['olsc'], ips_patch_database)
            
        if 'am' in existing_files:
            find_and_patch(existing_files['am'], version, "AM", log,
                am_pattern_diffs, pattern_offsets_map['am'], ips_patch_database)
        
        if 'nifm' in existing_files:
            find_and_patch(existing_files['nifm'], version, "NIFM", log,
                nifm_pattern_diffs, pattern_offsets_map['nifm'], ips_patch_database)

        if 'ns' in existing_files:
            find_and_patch(existing_files['ns'], version, "NS", log,
                ns_pattern_diffs, pattern_offsets_map['ns'], ips_patch_database)
            
        if 'nifm' in existing_files:
            find_and_patch(existing_files['nifm'], version, "NIFM", log,
                nifm_pattern_diffs, pattern_offsets_map['nifm'], ips_patch_database)
            
        if 'usb' in existing_files:
            if MAKEHOSVERSION("9.0.0", "10.2.0", version):
                find_and_patch(existing_files['usb'], version, "USB", log,
                    usb_pattern_1_diffs, pattern_offsets_map['usb'], ips_patch_database)
            if MAKEHOSVERSION("11.0.0", FW_VER_ANY, version):
                usb_patch_3 = find_and_patch(existing_files['usb'], version, "USB", log,
                    usb_pattern_2_diffs, pattern_offsets_map['usb'], ips_patch_database)

                find_and_patch(existing_files['usb'], version, "USB", log,
                    usb_pattern_3_diffs, pattern_offsets_map['usb'], ips_patch_database,
                    prior_patch_fragment=usb_patch_3, suppress_logging=True)
        
        # NIM has multiple patches (firmware block + crash fix)
        if 'nim' in existing_files:
            block_fw_fragment = find_and_patch(existing_files['nim'], version, "NIM", log,
                blockfirmwareupdates_pattern_diffs, pattern_offsets_map['nim'], ips_patch_database)
            
            find_and_patch(existing_files['nim'], version, "NIM", log,
                blankcal0crashfix_pattern_diffs, pattern_offsets_map['nim'], ips_patch_database,
                prior_patch_fragment=block_fw_fragment, suppress_logging=True)
        
        # Filesystem patches
        if 'fat32' in existing_files:
            find_and_patch(existing_files['fat32'], version, "FS", log,
                fat32_noncasigchk_pattern_diffs, pattern_offsets_map['fat32_nc'],
                ips_patch_database, hekate_patch_db=fs_kip_patch_database,
                is_fs=True, fs_type="FAT32", hash_path=existing_files.get('fat32_hash'))
            
            find_and_patch(existing_files['fat32'], version, "NOGC", log,
                nogc_pattern_diffs, pattern_offsets_map['fat32_nogc'],
                nogc_ips_patch_database, hekate_patch_db=nogc_kip_patch_database,
                is_fs=True, fs_type="FAT32", hash_path=existing_files.get('fat32_hash'))
        
        if 'exfat' in existing_files:
            find_and_patch(existing_files['exfat'], version, "FS", log,
                exfat_noncasigchk_pattern_diffs, pattern_offsets_map['exfat_nc'],
                ips_patch_database, hekate_patch_db=fs_kip_patch_database,
                is_fs=True, fs_type="EXFAT", hash_path=existing_files.get('exfat_hash'))
            
            find_and_patch(existing_files['exfat'], version, "NOGC", log,
                nogc_pattern_diffs, pattern_offsets_map['exfat_nogc'],
                nogc_ips_patch_database, hekate_patch_db=nogc_kip_patch_database,
                is_fs=True, fs_type="EXFAT", hash_path=existing_files.get('exfat_hash'))
        
        # Browser patch
        if 'browser' in existing_files:
            find_and_patch(existing_files['browser'], version, "BROWSER", log,
                browser_pattern_diffs, pattern_offsets_map['browser'],
                ssl_ips_patch_database)
        
        # SSL has multiple patterns (3 separate patches)
        if 'ssl' in existing_files:
            ssl_frag_1 = find_and_patch(existing_files['ssl'], version, "SSL", log,
                ssl_pattern_1_diffs, pattern_offsets_map['ssl_1'], ssl_ips_patch_database)
            
            ssl_frag_2 = find_and_patch(existing_files['ssl'], version, "SSL", log,
                ssl_pattern_2_diffs, pattern_offsets_map['ssl_2'], ssl_ips_patch_database,
                prior_patch_fragment=ssl_frag_1, suppress_logging=True)
            
            find_and_patch(existing_files['ssl'], version, "SSL", log,
                ssl_pattern_3_diffs, pattern_offsets_map['ssl_3'], ssl_ips_patch_database,
                prior_patch_fragment=ssl_frag_2, suppress_logging=True)


def _process_ams_modules(version: str):
    """Process ERPT and LOADER modules from Atmosphere package."""
    ams_string = package3_and_stratosphere.download_and_extract_package3_and_stratosphere_romfs()
    uncompressed_erpt_path = f'package3_and_stratosphere_extracted/uncompressed_erpt.nso0'
    
    with open('output/erpt_patch_summary.txt', 'w', encoding='utf-8') as erpt_log:
        find_and_patch(
            uncompressed_erpt_path, version, "ERPT", erpt_log,
            erpt_pattern_diffs, {}, ips_patch_database
        )
    
    loader_path = f'package3_and_stratosphere_extracted/u_loader.kip1'
    compressed_loader_path = f'package3_and_stratosphere_extracted/loader.kip1'
    
    if os.path.exists(compressed_loader_path):
        with open('output/loader_patch_summary.txt', 'w', encoding='utf-8') as loader_log:
            find_and_patch(
                loader_path, version, "LOADER", loader_log,
                loader_pattern_diffs, {}, ips_patch_database,
                hekate_patch_db=ldr_kip_patch_database,
                hash_path=compressed_loader_path,
                atmosphere_string=ams_string
            )


def _get_atmosphere_version() -> str:
    """Fetch latest supported Atmosphere HOS version from GitHub."""
    try:
        url = "https://raw.githubusercontent.com/Atmosphere-NX/Atmosphere/master/libraries/libvapours/include/vapours/ams/ams_api_version.h"
        req = Request(url)
        req.add_header('User-Agent', 'Mozilla/5.0 (compatible; find_patterns.py)')
        
        with urlopen(req) as response:
            content = response.read().decode('utf-8')
        
        major = re.search(r'#define ATMOSPHERE_SUPPORTED_HOS_VERSION_MAJOR\s+(\d+)', content)
        minor = re.search(r'#define ATMOSPHERE_SUPPORTED_HOS_VERSION_MINOR\s+(\d+)', content)
        micro = re.search(r'#define ATMOSPHERE_SUPPORTED_HOS_VERSION_MICRO\s+(\d+)', content)
        
        if major and minor and micro:
            version = f"{major.group(1)}.{minor.group(1)}.{micro.group(1)}"
            print(f"Fetched Atmosphere HOS version: {version}")
            return version
    except Exception as e:
        print(f"Warning: Failed to fetch HOS version: {e}")
    
    return "latest"


# ============================================================================
# Main Processing
# ============================================================================

if __name__ == '__main__':
    mkdirp("output")
    valid_versions = get_valid_version_folders('output')

    if not valid_versions:
        print("No valid version folders found in 'output/'.")
        print("Skipping pattern searching and patch database generation.\n")
    else:
        print(f"Found {len(valid_versions)} valid version folder(s): {', '.join(valid_versions)}\n")

        for version in valid_versions:
            _process_firmware_version(version)

    if args.ams:
        version = valid_versions[-1] if valid_versions else _get_atmosphere_version()
        _process_ams_modules(version)


def _update_pattern_diffs(existing_diffs, diff_categories, pattern_diffs_path):
    """Update the pattern diffs file with new entries."""
    output_categories = list(diff_categories)
    known_category_names = {category_name for category_name, _ in output_categories}
    for category_name in existing_diffs:
        if category_name not in known_category_names:
            output_categories.append((category_name, {}))

    updated = False
    for category_name, new_dict in diff_categories:
        old_dict = existing_diffs[category_name]
        for version, diff_str in new_dict.items():
            new_bytes = bytes.fromhex(diff_str)
            py_bytes = hex_string_to_python_bytes(diff_str)
            old_value = old_dict.get(version)
            if isinstance(old_value, bytes):
                old_bytes = old_value
            elif isinstance(old_value, str):
                try:
                    old_bytes = ast.literal_eval(old_value)
                except Exception:
                    old_bytes = None
            else:
                old_bytes = None

            if old_bytes != new_bytes:
                old_dict[version] = py_bytes
                updated = True

    if not updated and os.path.exists(pattern_diffs_path):
        print(f"No new pattern diffs to add — {pattern_diffs_path} unchanged.")
        return

    try:
        with open(pattern_diffs_path, 'w', encoding='utf-8') as f:
            f.write("# Auto-generated pattern diff strings\n")
            f.write("# Generated from find_patterns.py\n")
            f.write("# Do not edit manually — new runs will preserve entries.\n\n")

            for category_name, _ in output_categories:
                data = existing_diffs[category_name]
                entries = sorted(data.items(), key=lambda x: version_to_tuple(x[0]))
                
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


def _merge_sdk_versions():
    """Merge SDK versions from fs_sdk_versions.txt into fs_kip_patches.txt."""
    fs_kip_file = 'patch_database/fs_kip_patches.txt'
    fs_sdk_file = 'patch_database/fs_sdk_versions.txt'

    if not os.path.exists(fs_sdk_file):
        print(f"{fs_sdk_file} not found — skipping SDK version merge.")
        return

    sdk_entries = load_existing_patches(fs_sdk_file)
    sdk_map = {(entry[0], entry[1]): entry[3] for entry in sdk_entries if len(entry) >= 4}

    kip_entries = load_existing_patches(fs_kip_file)
    new_kip_entries = []
    added_count = 0

    for entry in kip_entries:
        if len(entry) == 4:
            new_kip_entries.append(entry)
            continue
        if len(entry) != 3:
            new_kip_entries.append(entry)
            continue

        fw_version, patch_str, fs_type = entry
        match = re.search(r'\[FS:([0-9A-F]{16})\]', patch_str[:21])
        
        if not match:
            new_kip_entries.append(entry)
            continue

        short_16 = match.group(1).upper()
        sdk_version = sdk_map.get((fw_version, short_16))

        if sdk_version:
            new_entry = (fw_version, patch_str, fs_type, sdk_version)
            new_kip_entries.append(new_entry)
            added_count += 1
            print(f"Added SDK {sdk_version} to {fw_version} {fs_type} ({short_16})")
        else:
            new_kip_entries.append(entry)

    if added_count > 0:
        try:
            with open(fs_kip_file, 'w', encoding='utf-8') as f:
                for entry in new_kip_entries:
                    f.write(f"{entry},\n")
            print(f"Successfully appended SDK version to {added_count} entries!")
        except Exception as e:
            print(f"Error writing {fs_kip_file}: {e}")
    else:
        print("No SDK versions appended — all entries already have SDK or no match found.")


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == '__main__':
    print("\n" + "="*80)
    print("Updating patch databases incrementally...")
    print("="*80 + "\n")

    # Remove duplicates from all databases
    nogc_kip_patch_database = remove_duplicates_by_index(nogc_kip_patch_database, 1)
    fs_kip_patch_database = remove_duplicates_by_index(fs_kip_patch_database, 1)
    ldr_kip_patch_database = remove_duplicates_by_index(ldr_kip_patch_database, 1)
    ips_patch_database = remove_duplicates_by_index(ips_patch_database, 1)
    ssl_ips_patch_database = remove_duplicates_by_index(ssl_ips_patch_database, 1)

    # Update patch files
    nogc_kip_updated = update_patch_file('patch_database/nogc_kip_patches.txt', nogc_kip_patch_database)
    write_nogc_atmosphere_patch(load_existing_patches('patch_database/nogc_kip_patches.txt'))
    fs_kip_updated = update_patch_file('patch_database/fs_kip_patches.txt', fs_kip_patch_database)
    ldr_kip_updated = update_patch_file('patch_database/ldr_kip_patches.txt', ldr_kip_patch_database)
    ips_updated = update_patch_file('patch_database/ips_patches.txt', ips_patch_database)
    ssl_ips_updated = update_patch_file('patch_database/ssl_ips_patches.txt', ssl_ips_patch_database)

    if not fs_kip_updated and not ips_updated and not ldr_kip_updated:
        print("All patch databases already up to date.")

    write_embedded_patch_files('output')

    # Update pattern diffs
    pattern_diffs_path = 'scripts/pattern_diffs.py'
    existing_diffs = load_existing_pattern_diffs(pattern_diffs_path)

    diff_categories = [
        ('es_pattern_diffs', es_pattern_diffs),
        ('blankcal0crashfix_pattern_diffs', blankcal0crashfix_pattern_diffs),
        ('blockfirmwareupdates_pattern_diffs', blockfirmwareupdates_pattern_diffs),
        ('nifm_pattern_diffs', nifm_pattern_diffs),
        ('ns_pattern_diffs', ns_pattern_diffs),
        ('usb_pattern_1_diffs', usb_pattern_1_diffs),
        ('usb_pattern_2_diffs', usb_pattern_2_diffs),
        ('usb_pattern_3_diffs', usb_pattern_3_diffs),
        ('olsc_pattern_diffs', olsc_pattern_diffs),
        ('am_pattern_diffs', am_pattern_diffs),
        ('fat32_noacidsigchk1_pattern_diffs', fat32_noacidsigchk1_pattern_diffs),
        ('exfat_noacidsigchk1_pattern_diffs', exfat_noacidsigchk1_pattern_diffs),
        ('fat32_noacidsigchk2_pattern_diffs', fat32_noacidsigchk2_pattern_diffs),
        ('exfat_noacidsigchk2_pattern_diffs', exfat_noacidsigchk2_pattern_diffs),
        ('fat32_noncasigchk_pattern_diffs', fat32_noncasigchk_pattern_diffs),
        ('exfat_noncasigchk_pattern_diffs', exfat_noncasigchk_pattern_diffs),
        ('fat32_nocntchk_pattern_diffs', fat32_nocntchk_pattern_diffs),
        ('exfat_nocntchk_pattern_diffs', exfat_nocntchk_pattern_diffs),
        ('browser_pattern_diffs', browser_pattern_diffs),
        ('ssl_pattern_1_diffs', ssl_pattern_1_diffs),
        ('ssl_pattern_2_diffs', ssl_pattern_2_diffs),
        ('ssl_pattern_3_diffs', ssl_pattern_3_diffs),
    ]

    if args.ams:
        diff_categories += [
            ('loader_pattern_diffs', loader_pattern_diffs),
            ('erpt_pattern_diffs', erpt_pattern_diffs),
        ]

    _update_pattern_diffs(existing_diffs, diff_categories, pattern_diffs_path)

    # Merge SDK versions
    print("\nMerging SDK versions into fs_kip_patches.txt...")
    _merge_sdk_versions()

    print("="*80)

    # Cleanup AMS temp files
    if os.path.exists('package3_and_stratosphere_extracted'):
        shutil.rmtree('package3_and_stratosphere_extracted')

    print("\nIncremental update complete!")
