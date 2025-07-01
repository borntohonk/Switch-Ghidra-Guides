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
import os
import ast
import binascii
import sys
import errno
from dataclasses import dataclass, field
from typing import Tuple, List, Dict, Optional, Callable

try:
    from capstone import *
    from capstone.arm64 import *

except ModuleNotFoundError:
    print('Please install capstone first!')
    sys.exit(1)

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

@dataclass
class PatchChain:
    """State carried between chained find_and_patch calls (prior_patch_fragment): the successful
    patches (for embedded output) and the rules that failed so far. Only the committing call
    records anything, and only if no rule in the chain failed."""
    patches: List[Dict] = field(default_factory=list)
    failed: List[str] = field(default_factory=list)


def find_and_patch(
    module_path: str,
    version: str,
    module_name: str,
    log_file,
    pattern_diffs: Dict[str, str],
    pattern_offsets: Dict[str, tuple],
    suppress_logging: bool = False,
    prior_patch_fragment: Optional[PatchChain] = None,
    hash_path: Optional[str] = None,
    rule_tag: Optional[str] = None,
    commit: bool = True
) -> Optional[PatchChain]:
    if not os.path.exists(module_path):
        log_file.write(f"({module_name}) File not found: {module_path}\n")
        return None

    with open(module_path, 'rb') as f:
        data = f.read()
        hex_data = data.hex().upper()

    rules = [
        r for r in PATCH_RULES.get(module_name, [])
        if MAKEHOSVERSION(r.min_version, r.max_version, version)
        and (rule_tag is None or r.tag == rule_tag)
    ]

    if not rules:
        log_file.write(f"({module_name}) No matching PatchRule for version {version}\n")
        return prior_patch_fragment

    successful_patches = []  # collect for grouped logging
    failed_rules = []  # "<tag or name> [<pattern>]" of every rule that did not match or failed its condition

    module_id = get_module_id(module_path)

    if hash_path and os.path.exists(hash_path):
        file_hash = Path(hash_path).read_text(encoding="utf-8").strip()
        log_file.write(f"({module_name}) Using compressed hash from {hash_path}\n")
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
            failed_rules.append(f"{rule.tag or rule.name} [{rule.pattern}]")
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
            failed_rules.append(f"{rule.tag or rule.name} [{rule.pattern}]")
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
            'rule_tag': rule.tag,
        })

        pattern_offsets[version] = (module_name, existing.hex().upper(), offset_hex, module_id)

    # ──────────────────────────────────────────────────────────────
    #   Grouped logging — happens only once per module call
    # ──────────────────────────────────────────────────────────────
    if successful_patches and not suppress_logging:
        # Header (printed only once)
        if module_name == "FS":
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

    prior = prior_patch_fragment or PatchChain()
    chain = PatchChain(
        patches=prior.patches + successful_patches,
        failed=prior.failed + failed_rules,
    )

    # Only the committing call of a chain (commit=True, the default) records the embedded output,
    # and only when every rule in the chain applied: a partial patch set is reported by rule name
    # instead of being recorded.
    if not commit:
        return chain

    if chain.failed:
        failed = list(dict.fromkeys(chain.failed))
        warning = (f"WARNING: ({module_name}) {version}: {len(failed)} pattern(s) failed, "
                   f"no embedded patch written: {', '.join(failed)}")
        print(warning)
        log_file.write(warning + "\n\n")
        return chain

    collect_embedded_patches(module_name, version, module_id, chain.patches)
    return chain

def mkdirp(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


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
        'systemweb_pattern_diffs_1': {},
        'systemweb_pattern_diffs_2': {},
        'systemweb_pattern_diffs_3': {},
        'systemweb_pattern_diffs_4': {},
        'systemweb_pattern_diffs_5': {},
        'systemweb_pattern_diffs_6': {},
        'openweb_pattern_diffs_1': {},
        'openweb_pattern_diffs_2': {},
        'openweb_pattern_diffs_3': {},
        'openweb_pattern_diffs_4': {},
        'openweb_pattern_diffs_5': {},
        'openweb_pattern_diffs_6': {},
        'offlineweb_pattern_diffs_1': {},
        'offlineweb_pattern_diffs_2': {},
        'offlineweb_pattern_diffs_3': {},
        'offlineweb_pattern_diffs_4': {},
        'offlineweb_pattern_diffs_5': {},
        'offlineweb_pattern_diffs_6': {},
        'libappletweb_pattern_diffs_1': {},
        'libappletweb_pattern_diffs_2': {},
        'libappletweb_pattern_diffs_3': {},
        'libappletweb_pattern_diffs_4': {},
        'libappletweb_pattern_diffs_5': {},
        'libappletweb_pattern_diffs_6': {},
        'libappletshop_pattern_diffs_1': {},
        'libappletshop_pattern_diffs_2': {},
        'libappletshop_pattern_diffs_3': {},
        'libappletshop_pattern_diffs_4': {},
        'libappletshop_pattern_diffs_5': {},
        'libappletshop_pattern_diffs_6': {},
        'libappletlns_pattern_diffs_1': {},
        'libappletlns_pattern_diffs_2': {},
        'libappletlns_pattern_diffs_3': {},
        'libappletlns_pattern_diffs_4': {},
        'libappletlns_pattern_diffs_5': {},
        'libappletlns_pattern_diffs_6': {},
        'libappletauth_pattern_diffs_1': {},
        'libappletauth_pattern_diffs_2': {},
        'libappletauth_pattern_diffs_3': {},
        'libappletauth_pattern_diffs_4': {},
        'libappletauth_pattern_diffs_5': {},
        'libappletauth_pattern_diffs_6': {},
        'fat32_noncasigchk_pattern_diffs': {},
        'exfat_noncasigchk_pattern_diffs': {},
        'fat32_noacidsigchk1_pattern_diffs': {},
        'exfat_noacidsigchk1_pattern_diffs': {},
        'fat32_noacidsigchk2_pattern_diffs': {},
        'exfat_noacidsigchk2_pattern_diffs': {},
        'fat32_nocntchk_pattern_diffs': {},
        'exfat_nocntchk_pattern_diffs': {},
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

EMBEDDED_PATCH_EXCLUDED_MODULES = {"FS", "NOGC", "OLSC"}
EMBEDDED_MODULE_PATCH_GROUPS = {
    "NIM": ("NimPatches", "Patch NIM firmware update blocking and blank PRODINFO handling."),
    "SYSTEMWEB": ("SystemWebMemoryPatches", "SystemWeb memory patches."),
    "OPENWEB": ("OpenWebMemoryPatches", "OpenWeb memory patches."),
    "OFFLINEWEB": ("OfflineWebMemoryPatches", "OfflineWeb memory patches."),
    "LIBAPPLETWEB": ("LibAppletWebMemoryPatches", "LibAppletWeb memory patches."),
    "LIBAPPLETSHOP": ("LibAppletShopMemoryPatches", "LibAppletShop memory patches."),
    "LIBAPPLETLNS": ("LibAppletLnsMemoryPatches", "LibAppletLns memory patches."),
    "LIBAPPLETAUTH": ("LibAppletAuthMemoryPatches", "LibAppletAuth memory patches."),
}

# Browser applet modules: written together to ldr_embedded_web_patches.inc (one WebMemoryPatches table, in this
# order) instead of one file per module, with each version's entries in patch order (#1-#6, from the rule tag).
EMBEDDED_WEB_MODULES = ["systemweb", "openweb", "offlineweb", "libappletweb", "libappletshop", "libappletlns", "libappletauth"]
EMBEDDED_WEB_HEADER = """/* The following patches reduce memory usage by the browser applets: */
/*   OfflineWeb (LibAppletOff): 20.0.0+ */
/*   SystemWeb, OpenWeb: 22.0.0+ (these applets were added in 22.0.0) */
/*   LibAppletWeb, LibAppletShop, LibAppletLns, LibAppletAuth: 20.0.0 - 21.2.0 (stubs from 22.0.0+) */
/* Breakdown of each patch in order: */
/* #1 - Set TotalAvailableMemorySize to 1GB. */
/* #2 - Change the root heap "Reserved" region allocation size to 0 (from 0xF7E000 on 20.x, 0x47E000 on 21.0.0-22.0.0, 0x43E000 on 22.5.0+). */
/* #3 - Patch the initial memory block allocation size (from 0xAE00000 to 0xAA00000 on 20.x, from 0xB400000 to 0xB000000 on 21.0.0+). */
/* #4 - Patch the initial memory block heap size from 0xB400000 to 0xB000000 (21.0.0+) */
/* #5 - Patch the browser engine memory capacity from 0xAA00000 to 0x9000000. */
/* #6 - Patch the browser engine memory allocation size from 0xAA00000 to 0x9000000. */
"""
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
                'order': {},
            }
        )

        entry = (patch['head_offset'] - 0x100, patch['patch_bytes'])
        if entry not in version_group['entries']:
            version_group['entries'].append(entry)
        # patch number from a chained rule's tag ("..._3" -> 3), used to write web entries in patch order
        tag = patch.get('rule_tag') or ''
        if re.search(r'_\d+$', tag):
            version_group['order'][entry] = int(tag.rsplit('_', 1)[1])


EMBEDDED_LICENSE_HEADER = """/*
 * Copyright (c) Atmosphère-NX
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

"""


def _embedded_patch_variants(patch_group, in_patch_order=False):
    """One variant per distinct (module_id, entries), in version order, with every version that shares it."""
    patch_variants = []
    patch_variant_map = {}
    for version, version_group in sorted(
        patch_group['versions'].items(),
        key=lambda item: version_to_tuple(item[0])
    ):
        if in_patch_order:
            order = version_group.get('order', {})
            sorted_entries = tuple(sorted(version_group['entries'], key=lambda item: (order.get(item, 0), item[0])))
        else:
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
    return patch_variants


def _write_embedded_entry_arrays(f, patch_name, patch_variants):
    for patch_variant in patch_variants:
        version_suffix = _format_cpp_version_suffix(patch_variant['array_version'])
        f.write(f"constexpr inline const EmbeddedPatchEntry {patch_name}_{version_suffix}[] = {{\n")

        offset_width = max([6] + [len(f"{offset:X}") for offset, _ in patch_variant['entries']])
        for offset, patch_bytes in patch_variant['entries']:
            f.write(
                f"    {{ 0x{offset:0{offset_width}X}, \"{_format_cpp_byte_string(patch_bytes)}\", {len(patch_bytes)} }},\n"
            )

        f.write("};\n\n")


def _write_embedded_web_patch_file(output_dir, patch_groups):
    """All browser applet modules in one file: entry arrays per module and version, then one WebMemoryPatches table."""
    filepath = os.path.join(output_dir, "ldr_embedded_web_patches.inc")
    by_module = {patch_group['module_type']: patch_group for patch_group in patch_groups}
    modules = [(module_type, by_module[module_type]['patch_name'],
                _embedded_patch_variants(by_module[module_type], in_patch_order=True))
               for module_type in EMBEDDED_WEB_MODULES if module_type in by_module]

    with open(filepath, 'w', encoding='utf-8', newline='\n') as f:
        f.write(EMBEDDED_LICENSE_HEADER)
        f.write(EMBEDDED_WEB_HEADER)
        f.write("\n")

        for _, patch_name, patch_variants in modules:
            _write_embedded_entry_arrays(f, patch_name, patch_variants)

        rows = []
        for _, patch_name, patch_variants in modules:
            module_rows = []
            for patch_variant in patch_variants:
                entry_name = f"{patch_name}_{_format_cpp_version_suffix(patch_variant['array_version'])}"
                module_rows.append((patch_variant['module_id'], entry_name, ", ".join(patch_variant['versions'])))
            rows.append(module_rows)

        width = max((len(entry_name) for module_rows in rows for _, entry_name, _ in module_rows), default=0)
        f.write("constexpr inline const EmbeddedPatch WebMemoryPatches[] = {\n")
        for i, module_rows in enumerate(rows):
            if i:
                f.write("\n")
            for module_id, entry_name, versions in module_rows:
                size_arg = f"util::size({entry_name}),".ljust(width + len("util::size(),") + 1)
                f.write(f"    {{ ParseModuleId(\"{module_id}\"), {size_arg}{entry_name.ljust(width)} }}, /* {versions} */\n")
        f.write("};\n")

    print(f"Wrote embedded patch file: {filepath}")


def write_embedded_patch_files(output_dir: str = 'output'):
    if not embedded_patch_database:
        print("No embedded patches generated.")
        return

    grouped_by_module = {}
    for patch_group in embedded_patch_database.values():
        grouped_by_module.setdefault(patch_group['module_type'], []).append(patch_group)

    web_groups = [patch_group for module_type in EMBEDDED_WEB_MODULES for patch_group in grouped_by_module.pop(module_type, [])]
    if web_groups:
        _write_embedded_web_patch_file(output_dir, web_groups)

    for module_type, patch_groups in sorted(grouped_by_module.items()):
        filepath = os.path.join(output_dir, f"ldr_embedded_{module_type}_patches.inc")
        with open(filepath, 'w', encoding='utf-8', newline='\n') as f:
            f.write(EMBEDDED_LICENSE_HEADER)

            for patch_group in sorted(patch_groups, key=lambda item: item['patch_name']):
                patch_name = patch_group['patch_name']
                f.write(f"/* {patch_group['comment']} */\n")

                patch_variants = _embedded_patch_variants(patch_group)
                _write_embedded_entry_arrays(f, patch_name, patch_variants)

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

# sys-patch logic explanation:
# "(49, 0,) +49" (nifm/ctest) from start from the start the string found in it's entirity, as sys-patch tests things stupid, then it reads from 0x0 of the end in decimals where the "head" was placed (49),
# and the 4th byte from there is what is tested (for most cond checks), the next number determines where from the tested byte is being patched. (should be 0, otherwise its not testing the bytes being patched!)

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
    tag: Optional[str] = None  # unique per-rule selector for chained find_and_patch calls; distinct from `name`, which is used for embedded-patch grouping

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
            name="am-22.0.0", # this patch is only necessary for 22.0.0
            module="AM",
            min_version="22.0.0",
            max_version="22.0.0",
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
    "SYSTEMWEB" : [
        PatchRule(
            name="SystemWebMemoryPatches",
            tag="SystemWebMemoryPatches_1",
            module="SYSTEMWEB",
            min_version="22.0.0",
            max_version=FW_VER_ANY,
            pattern="A1028052C2FF8F12E3031FAA",
            offset=32,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("ldr"),
            patch_bytes=b"\x09\x00\xA8\xD2",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="SystemWebMemoryPatches",
            tag="SystemWebMemoryPatches_2",
            module="SYSTEMWEB",
            min_version="22.0.0",
            max_version=FW_VER_ANY,
            pattern="02009C52....A072",
            offset=4,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("movk"),
            patch_bytes=b"\x02\x00\x80\x52",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="SystemWebMemoryPatches",
            tag="SystemWebMemoryPatches_3",
            module="SYSTEMWEB",
            min_version="22.0.0",
            max_version=FW_VER_ANY,
            pattern="0168A152",
            offset=0,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x60\xA1\x52",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="SystemWebMemoryPatches",
            tag="SystemWebMemoryPatches_4",
            module="SYSTEMWEB",
            min_version="22.0.0",
            max_version=FW_VER_ANY,
            pattern="60820691..68A152",
            offset=4,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x03\x60\xA1\x52",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="SystemWebMemoryPatches",
            tag="SystemWebMemoryPatches_5",
            module="SYSTEMWEB",
            min_version="22.0.0",
            max_version=FW_VER_ANY,
            pattern="B5......910154A152",
            offset=5,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x20\xA1\x52",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="SystemWebMemoryPatches",
            tag="SystemWebMemoryPatches_6",
            module="SYSTEMWEB",
            min_version="22.0.0",
            max_version=FW_VER_ANY,
            pattern="A90154A152",
            offset=1,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x20\xA1\x52",
            patch_size_hex="0004",
        ),
    ],
    "OPENWEB" : [
        PatchRule(
            name="OpenWebMemoryPatches",
            tag="OpenWebMemoryPatches_1",
            module="OPENWEB",
            min_version="22.0.0",
            max_version=FW_VER_ANY,
            pattern="A1028052C2FF8F12E3031FAA",
            offset=32,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("ldr"),
            patch_bytes=b"\x09\x00\xA8\xD2",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="OpenWebMemoryPatches",
            tag="OpenWebMemoryPatches_2",
            module="OPENWEB",
            min_version="22.0.0",
            max_version=FW_VER_ANY,
            pattern="02009C52....A072",
            offset=4,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("movk"),
            patch_bytes=b"\x02\x00\x80\x52",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="OpenWebMemoryPatches",
            tag="OpenWebMemoryPatches_3",
            module="OPENWEB",
            min_version="22.0.0",
            max_version=FW_VER_ANY,
            pattern="0168A152",
            offset=0,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x60\xA1\x52",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="OpenWebMemoryPatches",
            tag="OpenWebMemoryPatches_4",
            module="OPENWEB",
            min_version="22.0.0",
            max_version=FW_VER_ANY,
            pattern="60820691..68A152",
            offset=4,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x03\x60\xA1\x52",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="OpenWebMemoryPatches",
            tag="OpenWebMemoryPatches_5",
            module="OPENWEB",
            min_version="22.0.0",
            max_version=FW_VER_ANY,
            pattern="B5......910154A152",
            offset=5,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x20\xA1\x52",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="OpenWebMemoryPatches",
            tag="OpenWebMemoryPatches_6",
            module="OPENWEB",
            min_version="22.0.0",
            max_version=FW_VER_ANY,
            pattern="A90154A152",
            offset=1,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x20\xA1\x52",
            patch_size_hex="0004",
        ),
    ],
    "OFFLINEWEB" : [
        PatchRule(
            name="OfflineWebMemoryPatches",
            tag="OfflineWebMemoryPatches_1",
            module="OFFLINEWEB",
            min_version="21.0.0",
            max_version=FW_VER_ANY,
            pattern="A1028052C2FF8F12E3031FAA",
            offset=32,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("ldr"),
            patch_bytes=b"\x09\x00\xA8\xD2",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="OfflineWebMemoryPatches",
            tag="OfflineWebMemoryPatches_2",
            module="OFFLINEWEB",
            min_version="21.0.0",
            max_version=FW_VER_ANY,
            pattern="02009C52....A072",
            offset=4,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("movk"),
            patch_bytes=b"\x02\x00\x80\x52",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="OfflineWebMemoryPatches",
            tag="OfflineWebMemoryPatches_3",
            module="OFFLINEWEB",
            min_version="21.0.0",
            max_version=FW_VER_ANY,
            pattern="0168A152",
            offset=0,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x60\xA1\x52",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="OfflineWebMemoryPatches",
            tag="OfflineWebMemoryPatches_4",
            module="OFFLINEWEB",
            min_version="21.0.0",
            max_version=FW_VER_ANY,
            pattern="E10300AA60....91..68A152",
            offset=8,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x02\x60\xA1\x52",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="OfflineWebMemoryPatches",
            tag="OfflineWebMemoryPatches_5",
            module="OFFLINEWEB",
            min_version="21.0.0",
            max_version=FW_VER_ANY,
            pattern="B5......910154A152",
            offset=5,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x20\xA1\x52",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="OfflineWebMemoryPatches",
            tag="OfflineWebMemoryPatches_6",
            module="OFFLINEWEB",
            min_version="21.0.0",
            max_version=FW_VER_ANY,
            pattern="A90154A152",
            offset=1,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x20\xA1\x52",
            patch_size_hex="0004",
        ),
        PatchRule(
            name="OfflineWebMemoryPatches",
            tag="OfflineWebMemoryPatches_1",
            module="OFFLINEWEB",
            min_version="20.0.0",
            max_version="20.5.0",
            pattern="A1028052E0230091C2FF8F12E3031FAA",
            offset=36,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("ldr"),
            patch_bytes=b"\x09\x00\xA8\xD2",
            patch_size_hex="0004",
            description="Set TotalAvailableMemorySize to 1GB.",
        ),
        PatchRule(
            name="OfflineWebMemoryPatches",
            tag="OfflineWebMemoryPatches_2",
            module="OFFLINEWEB",
            min_version="20.0.0",
            max_version="20.5.0",
            pattern="02009C52E21EA072",
            offset=4,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("movk"),
            patch_bytes=b"\x02\x00\x80\x52",
            patch_size_hex="0004",
            description="Change the root heap Reserved region allocation size from 0xF7E000 to 0.",
        ),
        PatchRule(
            name="OfflineWebMemoryPatches",
            tag="OfflineWebMemoryPatches_3",
            module="OFFLINEWEB",
            min_version="20.0.0",
            max_version="20.5.0",
            pattern="195CA152E00318AAE10319AA",
            offset=0,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x19\x54\xA1\x52",
            patch_size_hex="0004",
            description="Patch the initial memory block allocation and heap size from 0xAE00000 to 0xAA00000.",
        ),
        PatchRule(
            name="OfflineWebMemoryPatches",
            tag="OfflineWebMemoryPatches_5",
            module="OFFLINEWEB",
            min_version="20.0.0",
            max_version="20.5.0",
            pattern="0154A152E00317AA",
            offset=0,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x20\xA1\x52",
            patch_size_hex="0004",
            description="Patch the browser engine memory capacity from 0xAA00000 to 0x9000000.",
        ),
        PatchRule(
            name="OfflineWebMemoryPatches",
            tag="OfflineWebMemoryPatches_6",
            module="OFFLINEWEB",
            min_version="20.0.0",
            max_version="20.5.0",
            pattern="1454A152E10314AA",
            offset=0,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x14\x20\xA1\x52",
            patch_size_hex="0004",
            description="Patch the browser engine memory allocation and heap size from 0xAA00000 to 0x9000000.",
        ),
    ],
    # LibAppletWeb / LibAppletShop / LibAppletLns / LibAppletAuth (20.x): same patches as the 20.x OfflineWeb group,
    # but these are built with return-address hardening and different register allocation, so the patterns differ
    # (initial memory block size in w23 instead of w25). No _4: _3 covers both sizes, as on OfflineWeb 20.x.
    # 21.x uses the 21.0.0+ OfflineWeb patterns, except _4: the heap size goes in w3 (as on SystemWeb / OpenWeb).
    # From 22.0.0 these applets are stubs, so there is nothing to patch.
    "LIBAPPLETWEB" : [
        PatchRule(
            name="LibAppletWebMemoryPatches",
            tag="LibAppletWebMemoryPatches_1",
            module="LIBAPPLETWEB",
            min_version="20.0.0",
            max_version="20.5.0",
            pattern="A1028052E0230091C2FF8F12E3031FAA",
            offset=36,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("ldr"),
            patch_bytes=b"\x09\x00\xA8\xD2",
            patch_size_hex="0004",
            description="Set TotalAvailableMemorySize to 1GB.",
        ),
        PatchRule(
            name="LibAppletWebMemoryPatches",
            tag="LibAppletWebMemoryPatches_2",
            module="LIBAPPLETWEB",
            min_version="20.0.0",
            max_version="20.5.0",
            pattern="02009C52E21EA072",
            offset=4,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("movk"),
            patch_bytes=b"\x02\x00\x80\x52",
            patch_size_hex="0004",
            description="Change the root heap Reserved region allocation size from 0xF7E000 to 0.",
        ),
        PatchRule(
            name="LibAppletWebMemoryPatches",
            tag="LibAppletWebMemoryPatches_3",
            module="LIBAPPLETWEB",
            min_version="20.0.0",
            max_version="20.5.0",
            pattern="175CA152E00316AAE10317AA",
            offset=0,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x17\x54\xA1\x52",
            patch_size_hex="0004",
            description="Patch the initial memory block allocation and heap size from 0xAE00000 to 0xAA00000.",
        ),
        PatchRule(
            name="LibAppletWebMemoryPatches",
            tag="LibAppletWebMemoryPatches_5",
            module="LIBAPPLETWEB",
            min_version="20.0.0",
            max_version="20.5.0",
            pattern="0154A152E0031CAA",
            offset=0,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x20\xA1\x52",
            patch_size_hex="0004",
            description="Patch the browser engine memory capacity from 0xAA00000 to 0x9000000.",
        ),
        PatchRule(
            name="LibAppletWebMemoryPatches",
            tag="LibAppletWebMemoryPatches_6",
            module="LIBAPPLETWEB",
            min_version="20.0.0",
            max_version="20.5.0",
            pattern="1454A152........F30300AAE10314AA",
            offset=0,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x14\x20\xA1\x52",
            patch_size_hex="0004",
            description="Patch the browser engine memory allocation and heap size from 0xAA00000 to 0x9000000.",
        ),
        PatchRule(
            name="LibAppletWebMemoryPatches",
            tag="LibAppletWebMemoryPatches_1",
            module="LIBAPPLETWEB",
            min_version="21.0.0",
            max_version="21.2.0",
            pattern="A1028052C2FF8F12E3031FAA",
            offset=32,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("ldr"),
            patch_bytes=b"\x09\x00\xA8\xD2",
            patch_size_hex="0004",
            description="Set TotalAvailableMemorySize to 1GB.",
        ),
        PatchRule(
            name="LibAppletWebMemoryPatches",
            tag="LibAppletWebMemoryPatches_2",
            module="LIBAPPLETWEB",
            min_version="21.0.0",
            max_version="21.2.0",
            pattern="02009C52....A072",
            offset=4,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("movk"),
            patch_bytes=b"\x02\x00\x80\x52",
            patch_size_hex="0004",
            description="Change the root heap Reserved region allocation size from 0x47E000 to 0.",
        ),
        PatchRule(
            name="LibAppletWebMemoryPatches",
            tag="LibAppletWebMemoryPatches_3",
            module="LIBAPPLETWEB",
            min_version="21.0.0",
            max_version="21.2.0",
            pattern="0168A152",
            offset=0,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x60\xA1\x52",
            patch_size_hex="0004",
            description="Patch the initial memory block allocation size from 0xB400000 to 0xB000000.",
        ),
        PatchRule(
            name="LibAppletWebMemoryPatches",
            tag="LibAppletWebMemoryPatches_4",
            module="LIBAPPLETWEB",
            min_version="21.0.0",
            max_version="21.2.0",
            pattern="E20300AA........60....910368A152",
            offset=12,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x03\x60\xA1\x52",
            patch_size_hex="0004",
            description="Patch the initial memory block heap size from 0xB400000 to 0xB000000.",
        ),
        PatchRule(
            name="LibAppletWebMemoryPatches",
            tag="LibAppletWebMemoryPatches_5",
            module="LIBAPPLETWEB",
            min_version="21.0.0",
            max_version="21.2.0",
            pattern="B5......910154A152",
            offset=5,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x20\xA1\x52",
            patch_size_hex="0004",
            description="Patch the browser engine memory capacity from 0xAA00000 to 0x9000000.",
        ),
        PatchRule(
            name="LibAppletWebMemoryPatches",
            tag="LibAppletWebMemoryPatches_6",
            module="LIBAPPLETWEB",
            min_version="21.0.0",
            max_version="21.2.0",
            pattern="A90154A152",
            offset=1,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x20\xA1\x52",
            patch_size_hex="0004",
            description="Patch the browser engine memory allocation size from 0xAA00000 to 0x9000000.",
        ),
    ],
    "LIBAPPLETSHOP" : [
        PatchRule(
            name="LibAppletShopMemoryPatches",
            tag="LibAppletShopMemoryPatches_1",
            module="LIBAPPLETSHOP",
            min_version="20.0.0",
            max_version="20.5.0",
            pattern="A1028052E0230091C2FF8F12E3031FAA",
            offset=36,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("ldr"),
            patch_bytes=b"\x09\x00\xA8\xD2",
            patch_size_hex="0004",
            description="Set TotalAvailableMemorySize to 1GB.",
        ),
        PatchRule(
            name="LibAppletShopMemoryPatches",
            tag="LibAppletShopMemoryPatches_2",
            module="LIBAPPLETSHOP",
            min_version="20.0.0",
            max_version="20.5.0",
            pattern="02009C52E21EA072",
            offset=4,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("movk"),
            patch_bytes=b"\x02\x00\x80\x52",
            patch_size_hex="0004",
            description="Change the root heap Reserved region allocation size from 0xF7E000 to 0.",
        ),
        PatchRule(
            name="LibAppletShopMemoryPatches",
            tag="LibAppletShopMemoryPatches_3",
            module="LIBAPPLETSHOP",
            min_version="20.0.0",
            max_version="20.5.0",
            pattern="175CA152E00316AAE10317AA",
            offset=0,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x17\x54\xA1\x52",
            patch_size_hex="0004",
            description="Patch the initial memory block allocation and heap size from 0xAE00000 to 0xAA00000.",
        ),
        PatchRule(
            name="LibAppletShopMemoryPatches",
            tag="LibAppletShopMemoryPatches_5",
            module="LIBAPPLETSHOP",
            min_version="20.0.0",
            max_version="20.5.0",
            pattern="0154A152E0031CAA",
            offset=0,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x20\xA1\x52",
            patch_size_hex="0004",
            description="Patch the browser engine memory capacity from 0xAA00000 to 0x9000000.",
        ),
        PatchRule(
            name="LibAppletShopMemoryPatches",
            tag="LibAppletShopMemoryPatches_6",
            module="LIBAPPLETSHOP",
            min_version="20.0.0",
            max_version="20.5.0",
            pattern="1454A152........F30300AAE10314AA",
            offset=0,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x14\x20\xA1\x52",
            patch_size_hex="0004",
            description="Patch the browser engine memory allocation and heap size from 0xAA00000 to 0x9000000.",
        ),
        PatchRule(
            name="LibAppletShopMemoryPatches",
            tag="LibAppletShopMemoryPatches_1",
            module="LIBAPPLETSHOP",
            min_version="21.0.0",
            max_version="21.2.0",
            pattern="A1028052C2FF8F12E3031FAA",
            offset=32,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("ldr"),
            patch_bytes=b"\x09\x00\xA8\xD2",
            patch_size_hex="0004",
            description="Set TotalAvailableMemorySize to 1GB.",
        ),
        PatchRule(
            name="LibAppletShopMemoryPatches",
            tag="LibAppletShopMemoryPatches_2",
            module="LIBAPPLETSHOP",
            min_version="21.0.0",
            max_version="21.2.0",
            pattern="02009C52....A072",
            offset=4,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("movk"),
            patch_bytes=b"\x02\x00\x80\x52",
            patch_size_hex="0004",
            description="Change the root heap Reserved region allocation size from 0x47E000 to 0.",
        ),
        PatchRule(
            name="LibAppletShopMemoryPatches",
            tag="LibAppletShopMemoryPatches_3",
            module="LIBAPPLETSHOP",
            min_version="21.0.0",
            max_version="21.2.0",
            pattern="0168A152",
            offset=0,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x60\xA1\x52",
            patch_size_hex="0004",
            description="Patch the initial memory block allocation size from 0xB400000 to 0xB000000.",
        ),
        PatchRule(
            name="LibAppletShopMemoryPatches",
            tag="LibAppletShopMemoryPatches_4",
            module="LIBAPPLETSHOP",
            min_version="21.0.0",
            max_version="21.2.0",
            pattern="E20300AA........60....910368A152",
            offset=12,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x03\x60\xA1\x52",
            patch_size_hex="0004",
            description="Patch the initial memory block heap size from 0xB400000 to 0xB000000.",
        ),
        PatchRule(
            name="LibAppletShopMemoryPatches",
            tag="LibAppletShopMemoryPatches_5",
            module="LIBAPPLETSHOP",
            min_version="21.0.0",
            max_version="21.2.0",
            pattern="B5......910154A152",
            offset=5,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x20\xA1\x52",
            patch_size_hex="0004",
            description="Patch the browser engine memory capacity from 0xAA00000 to 0x9000000.",
        ),
        PatchRule(
            name="LibAppletShopMemoryPatches",
            tag="LibAppletShopMemoryPatches_6",
            module="LIBAPPLETSHOP",
            min_version="21.0.0",
            max_version="21.2.0",
            pattern="A90154A152",
            offset=1,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x20\xA1\x52",
            patch_size_hex="0004",
            description="Patch the browser engine memory allocation size from 0xAA00000 to 0x9000000.",
        ),
    ],
    "LIBAPPLETLNS" : [
        PatchRule(
            name="LibAppletLnsMemoryPatches",
            tag="LibAppletLnsMemoryPatches_1",
            module="LIBAPPLETLNS",
            min_version="20.0.0",
            max_version="20.5.0",
            pattern="A1028052E0230091C2FF8F12E3031FAA",
            offset=36,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("ldr"),
            patch_bytes=b"\x09\x00\xA8\xD2",
            patch_size_hex="0004",
            description="Set TotalAvailableMemorySize to 1GB.",
        ),
        PatchRule(
            name="LibAppletLnsMemoryPatches",
            tag="LibAppletLnsMemoryPatches_2",
            module="LIBAPPLETLNS",
            min_version="20.0.0",
            max_version="20.5.0",
            pattern="02009C52E21EA072",
            offset=4,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("movk"),
            patch_bytes=b"\x02\x00\x80\x52",
            patch_size_hex="0004",
            description="Change the root heap Reserved region allocation size from 0xF7E000 to 0.",
        ),
        PatchRule(
            name="LibAppletLnsMemoryPatches",
            tag="LibAppletLnsMemoryPatches_3",
            module="LIBAPPLETLNS",
            min_version="20.0.0",
            max_version="20.5.0",
            pattern="175CA152E00316AAE10317AA",
            offset=0,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x17\x54\xA1\x52",
            patch_size_hex="0004",
            description="Patch the initial memory block allocation and heap size from 0xAE00000 to 0xAA00000.",
        ),
        PatchRule(
            name="LibAppletLnsMemoryPatches",
            tag="LibAppletLnsMemoryPatches_5",
            module="LIBAPPLETLNS",
            min_version="20.0.0",
            max_version="20.5.0",
            pattern="0154A152E0031CAA",
            offset=0,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x20\xA1\x52",
            patch_size_hex="0004",
            description="Patch the browser engine memory capacity from 0xAA00000 to 0x9000000.",
        ),
        PatchRule(
            name="LibAppletLnsMemoryPatches",
            tag="LibAppletLnsMemoryPatches_6",
            module="LIBAPPLETLNS",
            min_version="20.0.0",
            max_version="20.5.0",
            pattern="1454A152........F30300AAE10314AA",
            offset=0,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x14\x20\xA1\x52",
            patch_size_hex="0004",
            description="Patch the browser engine memory allocation and heap size from 0xAA00000 to 0x9000000.",
        ),
        PatchRule(
            name="LibAppletLnsMemoryPatches",
            tag="LibAppletLnsMemoryPatches_1",
            module="LIBAPPLETLNS",
            min_version="21.0.0",
            max_version="21.2.0",
            pattern="A1028052C2FF8F12E3031FAA",
            offset=32,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("ldr"),
            patch_bytes=b"\x09\x00\xA8\xD2",
            patch_size_hex="0004",
            description="Set TotalAvailableMemorySize to 1GB.",
        ),
        PatchRule(
            name="LibAppletLnsMemoryPatches",
            tag="LibAppletLnsMemoryPatches_2",
            module="LIBAPPLETLNS",
            min_version="21.0.0",
            max_version="21.2.0",
            pattern="02009C52....A072",
            offset=4,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("movk"),
            patch_bytes=b"\x02\x00\x80\x52",
            patch_size_hex="0004",
            description="Change the root heap Reserved region allocation size from 0x47E000 to 0.",
        ),
        PatchRule(
            name="LibAppletLnsMemoryPatches",
            tag="LibAppletLnsMemoryPatches_3",
            module="LIBAPPLETLNS",
            min_version="21.0.0",
            max_version="21.2.0",
            pattern="0168A152",
            offset=0,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x60\xA1\x52",
            patch_size_hex="0004",
            description="Patch the initial memory block allocation size from 0xB400000 to 0xB000000.",
        ),
        PatchRule(
            name="LibAppletLnsMemoryPatches",
            tag="LibAppletLnsMemoryPatches_4",
            module="LIBAPPLETLNS",
            min_version="21.0.0",
            max_version="21.2.0",
            pattern="E20300AA........60....910368A152",
            offset=12,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x03\x60\xA1\x52",
            patch_size_hex="0004",
            description="Patch the initial memory block heap size from 0xB400000 to 0xB000000.",
        ),
        PatchRule(
            name="LibAppletLnsMemoryPatches",
            tag="LibAppletLnsMemoryPatches_5",
            module="LIBAPPLETLNS",
            min_version="21.0.0",
            max_version="21.2.0",
            pattern="B5......910154A152",
            offset=5,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x20\xA1\x52",
            patch_size_hex="0004",
            description="Patch the browser engine memory capacity from 0xAA00000 to 0x9000000.",
        ),
        PatchRule(
            name="LibAppletLnsMemoryPatches",
            tag="LibAppletLnsMemoryPatches_6",
            module="LIBAPPLETLNS",
            min_version="21.0.0",
            max_version="21.2.0",
            pattern="A90154A152",
            offset=1,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x20\xA1\x52",
            patch_size_hex="0004",
            description="Patch the browser engine memory allocation size from 0xAA00000 to 0x9000000.",
        ),
    ],
    "LIBAPPLETAUTH" : [
        PatchRule(
            name="LibAppletAuthMemoryPatches",
            tag="LibAppletAuthMemoryPatches_1",
            module="LIBAPPLETAUTH",
            min_version="20.0.0",
            max_version="20.5.0",
            pattern="A1028052E0230091C2FF8F12E3031FAA",
            offset=36,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("ldr"),
            patch_bytes=b"\x09\x00\xA8\xD2",
            patch_size_hex="0004",
            description="Set TotalAvailableMemorySize to 1GB.",
        ),
        PatchRule(
            name="LibAppletAuthMemoryPatches",
            tag="LibAppletAuthMemoryPatches_2",
            module="LIBAPPLETAUTH",
            min_version="20.0.0",
            max_version="20.5.0",
            pattern="02009C52E21EA072",
            offset=4,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("movk"),
            patch_bytes=b"\x02\x00\x80\x52",
            patch_size_hex="0004",
            description="Change the root heap Reserved region allocation size from 0xF7E000 to 0.",
        ),
        PatchRule(
            name="LibAppletAuthMemoryPatches",
            tag="LibAppletAuthMemoryPatches_3",
            module="LIBAPPLETAUTH",
            min_version="20.0.0",
            max_version="20.5.0",
            pattern="175CA152E00316AAE10317AA",
            offset=0,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x17\x54\xA1\x52",
            patch_size_hex="0004",
            description="Patch the initial memory block allocation and heap size from 0xAE00000 to 0xAA00000.",
        ),
        PatchRule(
            name="LibAppletAuthMemoryPatches",
            tag="LibAppletAuthMemoryPatches_5",
            module="LIBAPPLETAUTH",
            min_version="20.0.0",
            max_version="20.5.0",
            pattern="0154A152E0031CAA",
            offset=0,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x20\xA1\x52",
            patch_size_hex="0004",
            description="Patch the browser engine memory capacity from 0xAA00000 to 0x9000000.",
        ),
        PatchRule(
            name="LibAppletAuthMemoryPatches",
            tag="LibAppletAuthMemoryPatches_6",
            module="LIBAPPLETAUTH",
            min_version="20.0.0",
            max_version="20.5.0",
            pattern="1454A152........F30300AAE10314AA",
            offset=0,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x14\x20\xA1\x52",
            patch_size_hex="0004",
            description="Patch the browser engine memory allocation and heap size from 0xAA00000 to 0x9000000.",
        ),
        PatchRule(
            name="LibAppletAuthMemoryPatches",
            tag="LibAppletAuthMemoryPatches_1",
            module="LIBAPPLETAUTH",
            min_version="21.0.0",
            max_version="21.2.0",
            pattern="A1028052C2FF8F12E3031FAA",
            offset=32,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("ldr"),
            patch_bytes=b"\x09\x00\xA8\xD2",
            patch_size_hex="0004",
            description="Set TotalAvailableMemorySize to 1GB.",
        ),
        PatchRule(
            name="LibAppletAuthMemoryPatches",
            tag="LibAppletAuthMemoryPatches_2",
            module="LIBAPPLETAUTH",
            min_version="21.0.0",
            max_version="21.2.0",
            pattern="02009C52....A072",
            offset=4,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("movk"),
            patch_bytes=b"\x02\x00\x80\x52",
            patch_size_hex="0004",
            description="Change the root heap Reserved region allocation size from 0x47E000 to 0.",
        ),
        PatchRule(
            name="LibAppletAuthMemoryPatches",
            tag="LibAppletAuthMemoryPatches_3",
            module="LIBAPPLETAUTH",
            min_version="21.0.0",
            max_version="21.2.0",
            pattern="0168A152",
            offset=0,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x60\xA1\x52",
            patch_size_hex="0004",
            description="Patch the initial memory block allocation size from 0xB400000 to 0xB000000.",
        ),
        PatchRule(
            name="LibAppletAuthMemoryPatches",
            tag="LibAppletAuthMemoryPatches_4",
            module="LIBAPPLETAUTH",
            min_version="21.0.0",
            max_version="21.2.0",
            pattern="E20300AA........60....910368A152",
            offset=12,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x03\x60\xA1\x52",
            patch_size_hex="0004",
            description="Patch the initial memory block heap size from 0xB400000 to 0xB000000.",
        ),
        PatchRule(
            name="LibAppletAuthMemoryPatches",
            tag="LibAppletAuthMemoryPatches_5",
            module="LIBAPPLETAUTH",
            min_version="21.0.0",
            max_version="21.2.0",
            pattern="B5......910154A152",
            offset=5,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x20\xA1\x52",
            patch_size_hex="0004",
            description="Patch the browser engine memory capacity from 0xAA00000 to 0x9000000.",
        ),
        PatchRule(
            name="LibAppletAuthMemoryPatches",
            tag="LibAppletAuthMemoryPatches_6",
            module="LIBAPPLETAUTH",
            min_version="21.0.0",
            max_version="21.2.0",
            pattern="A90154A152",
            offset=1,
            head_offset=0,
            match_position=0,
            condition_mnemonics=("mov"),
            patch_bytes=b"\x01\x20\xA1\x52",
            patch_size_hex="0004",
            description="Patch the browser engine memory allocation size from 0xAA00000 to 0x9000000.",
        ),
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

embedded_patch_database = {}

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
systemweb_pattern_diffs_1 = {}
systemweb_pattern_diffs_2 = {}
systemweb_pattern_diffs_3 = {}
systemweb_pattern_diffs_4 = {}
systemweb_pattern_diffs_5 = {}
systemweb_pattern_diffs_6 = {}

openweb_pattern_diffs_1 = {}
openweb_pattern_diffs_2 = {}
openweb_pattern_diffs_3 = {}
openweb_pattern_diffs_4 = {}
openweb_pattern_diffs_5 = {}
openweb_pattern_diffs_6 = {}

offlineweb_pattern_diffs_1 = {}
offlineweb_pattern_diffs_2 = {}
offlineweb_pattern_diffs_3 = {}
offlineweb_pattern_diffs_4 = {}
offlineweb_pattern_diffs_5 = {}
offlineweb_pattern_diffs_6 = {}

libappletweb_pattern_diffs_1 = {}
libappletweb_pattern_diffs_2 = {}
libappletweb_pattern_diffs_3 = {}
libappletweb_pattern_diffs_4 = {}
libappletweb_pattern_diffs_5 = {}
libappletweb_pattern_diffs_6 = {}

libappletshop_pattern_diffs_1 = {}
libappletshop_pattern_diffs_2 = {}
libappletshop_pattern_diffs_3 = {}
libappletshop_pattern_diffs_4 = {}
libappletshop_pattern_diffs_5 = {}
libappletshop_pattern_diffs_6 = {}

libappletlns_pattern_diffs_1 = {}
libappletlns_pattern_diffs_2 = {}
libappletlns_pattern_diffs_3 = {}
libappletlns_pattern_diffs_4 = {}
libappletlns_pattern_diffs_5 = {}
libappletlns_pattern_diffs_6 = {}

libappletauth_pattern_diffs_1 = {}
libappletauth_pattern_diffs_2 = {}
libappletauth_pattern_diffs_3 = {}
libappletauth_pattern_diffs_4 = {}
libappletauth_pattern_diffs_5 = {}
libappletauth_pattern_diffs_6 = {}
fat32_nocntchk_pattern_diffs = {}
exfat_nocntchk_pattern_diffs = {}
fat32_noncasigchk_pattern_diffs = {}
exfat_noncasigchk_pattern_diffs = {}
fat32_noacidsigchk1_pattern_diffs = {}
exfat_noacidsigchk1_pattern_diffs = {}
fat32_noacidsigchk2_pattern_diffs = {}
exfat_noacidsigchk2_pattern_diffs = {}

# Pattern offsets (used internally but can be simplified)
pattern_offsets_map = {
    'es': {}, 'nifm': {}, 'olsc': {}, 'am': {}, 'nim': {}, 'ns': {}, 'usb': {},
    'systemweb_1': {}, 'systemweb_2': {}, 'systemweb_3': {}, 'systemweb_4': {}, 'systemweb_5': {}, 'systemweb_6': {},
    'openweb_1': {}, 'openweb_2': {}, 'openweb_3': {}, 'openweb_4': {}, 'openweb_5': {}, 'openweb_6': {},
    'offlineweb_1': {}, 'offlineweb_2': {}, 'offlineweb_3': {}, 'offlineweb_4': {}, 'offlineweb_5': {}, 'offlineweb_6': {},
    'libappletweb_1': {}, 'libappletweb_2': {}, 'libappletweb_3': {}, 'libappletweb_4': {}, 'libappletweb_5': {}, 'libappletweb_6': {},
    'libappletshop_1': {}, 'libappletshop_2': {}, 'libappletshop_3': {}, 'libappletshop_4': {}, 'libappletshop_5': {}, 'libappletshop_6': {},
    'libappletlns_1': {}, 'libappletlns_2': {}, 'libappletlns_3': {}, 'libappletlns_4': {}, 'libappletlns_5': {}, 'libappletlns_6': {},
    'libappletauth_1': {}, 'libappletauth_2': {}, 'libappletauth_3': {}, 'libappletauth_4': {}, 'libappletauth_5': {}, 'libappletauth_6': {},
    'fat32_nc': {}, 'exfat_nc': {}, 'fat32_nogc': {}, 'exfat_nogc': {},
}

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
        'usb': f'output/{version}/{version}_usb.nso0',
        'systemweb': f'output/{version}/{version}_systemWeb.nso0',
        'openweb': f'output/{version}/{version}_openWeb.nso0',
        'offlineweb': f'output/{version}/{version}_LibAppletOff.nso0',
        'libappletweb': f'output/{version}/{version}_LibAppletWeb.nso0',
        'libappletshop': f'output/{version}/{version}_LibAppletShop.nso0',
        'libappletlns': f'output/{version}/{version}_LibAppletLns.nso0',
        'libappletauth': f'output/{version}/{version}_LibAppletAuth.nso0',
        'fat32_hash': f'output/{version}/{version}_fat32.hash',
        'fat32': f'output/{version}/{version}_fat32_FS.kip1',
        'exfat_hash': f'output/{version}/{version}_exfat.hash',
        'exfat': f'output/{version}/{version}_exfat_FS.kip1',
    }
    
    # Check which files exist
    existing_files = {k: v for k, v in files.items() if os.path.exists(v)}
    
    patch_summary_file = f'output/{version}/{version}_patch_summary_with_diff_strings.txt'
    
    with open(patch_summary_file, 'w') as log:
        # Process standard modules (only if files exist)
        if 'es' in existing_files:
            find_and_patch(existing_files['es'], version, "ES", log,
                es_pattern_diffs, pattern_offsets_map['es'])
        
        if 'olsc' in existing_files:
            find_and_patch(existing_files['olsc'], version, "OLSC", log,
                olsc_pattern_diffs, pattern_offsets_map['olsc'])
            
        if 'am' in existing_files:
            find_and_patch(existing_files['am'], version, "AM", log,
                am_pattern_diffs, pattern_offsets_map['am'])
        
        if 'nifm' in existing_files:
            find_and_patch(existing_files['nifm'], version, "NIFM", log,
                nifm_pattern_diffs, pattern_offsets_map['nifm'])

        if 'ns' in existing_files:
            find_and_patch(existing_files['ns'], version, "NS", log,
                ns_pattern_diffs, pattern_offsets_map['ns'])
            
        if 'nifm' in existing_files:
            find_and_patch(existing_files['nifm'], version, "NIFM", log,
                nifm_pattern_diffs, pattern_offsets_map['nifm'])
            
        if 'usb' in existing_files:
            if MAKEHOSVERSION("9.0.0", "10.2.0", version):
                find_and_patch(existing_files['usb'], version, "USB", log,
                    usb_pattern_1_diffs, pattern_offsets_map['usb'])
            if MAKEHOSVERSION("11.0.0", FW_VER_ANY, version):
                usb_patch_3 = find_and_patch(existing_files['usb'], version, "USB", log,
                    usb_pattern_2_diffs, pattern_offsets_map['usb'],
                    commit=False)

                find_and_patch(existing_files['usb'], version, "USB", log,
                    usb_pattern_3_diffs, pattern_offsets_map['usb'],
                    prior_patch_fragment=usb_patch_3, suppress_logging=False)

        if 'systemweb' in existing_files:
            if MAKEHOSVERSION("22.0.0", FW_VER_ANY, version):
                systemweb_frag_1 = find_and_patch(existing_files['systemweb'], version, "SYSTEMWEB", log,
                    systemweb_pattern_diffs_1, pattern_offsets_map['systemweb_1'],
                    rule_tag="SystemWebMemoryPatches_1",
                    commit=False)

                systemweb_frag_2 = find_and_patch(existing_files['systemweb'], version, "SYSTEMWEB", log,
                    systemweb_pattern_diffs_2, pattern_offsets_map['systemweb_2'],
                    prior_patch_fragment=systemweb_frag_1, suppress_logging=False,
                    rule_tag="SystemWebMemoryPatches_2",
                    commit=False)

                systemweb_frag_3 = find_and_patch(existing_files['systemweb'], version, "SYSTEMWEB", log,
                    systemweb_pattern_diffs_3, pattern_offsets_map['systemweb_3'],
                    prior_patch_fragment=systemweb_frag_2, suppress_logging=False,
                    rule_tag="SystemWebMemoryPatches_3",
                    commit=False)

                systemweb_frag_4 = find_and_patch(existing_files['systemweb'], version, "SYSTEMWEB", log,
                    systemweb_pattern_diffs_4, pattern_offsets_map['systemweb_4'],
                    prior_patch_fragment=systemweb_frag_3, suppress_logging=False,
                    rule_tag="SystemWebMemoryPatches_4",
                    commit=False)

                systemweb_frag_5 = find_and_patch(existing_files['systemweb'], version, "SYSTEMWEB", log,
                    systemweb_pattern_diffs_5, pattern_offsets_map['systemweb_5'],
                    prior_patch_fragment=systemweb_frag_4, suppress_logging=False,
                    rule_tag="SystemWebMemoryPatches_5",
                    commit=False)

                find_and_patch(existing_files['systemweb'], version, "SYSTEMWEB", log,
                    systemweb_pattern_diffs_6, pattern_offsets_map['systemweb_6'],
                    prior_patch_fragment=systemweb_frag_5, suppress_logging=False,
                    rule_tag="SystemWebMemoryPatches_6")

        if 'openweb' in existing_files:
            if MAKEHOSVERSION("22.0.0", FW_VER_ANY, version):
                openweb_frag_1 = find_and_patch(existing_files['openweb'], version, "OPENWEB", log,
                    openweb_pattern_diffs_1, pattern_offsets_map['openweb_1'],
                    rule_tag="OpenWebMemoryPatches_1",
                    commit=False)

                openweb_frag_2 = find_and_patch(existing_files['openweb'], version, "OPENWEB", log,
                    openweb_pattern_diffs_2, pattern_offsets_map['openweb_2'],
                    prior_patch_fragment=openweb_frag_1, suppress_logging=False,
                    rule_tag="OpenWebMemoryPatches_2",
                    commit=False)

                openweb_frag_3 = find_and_patch(existing_files['openweb'], version, "OPENWEB", log,
                    openweb_pattern_diffs_3, pattern_offsets_map['openweb_3'],
                    prior_patch_fragment=openweb_frag_2, suppress_logging=False,
                    rule_tag="OpenWebMemoryPatches_3",
                    commit=False)

                openweb_frag_4 = find_and_patch(existing_files['openweb'], version, "OPENWEB", log,
                    openweb_pattern_diffs_4, pattern_offsets_map['openweb_4'],
                    prior_patch_fragment=openweb_frag_3, suppress_logging=False,
                    rule_tag="OpenWebMemoryPatches_4",
                    commit=False)

                openweb_frag_5 = find_and_patch(existing_files['openweb'], version, "OPENWEB", log,
                    openweb_pattern_diffs_5, pattern_offsets_map['openweb_5'],
                    prior_patch_fragment=openweb_frag_4, suppress_logging=False,
                    rule_tag="OpenWebMemoryPatches_5",
                    commit=False)

                find_and_patch(existing_files['openweb'], version, "OPENWEB", log,
                    openweb_pattern_diffs_6, pattern_offsets_map['openweb_6'],
                    prior_patch_fragment=openweb_frag_5, suppress_logging=False,
                    rule_tag="OpenWebMemoryPatches_6")

        if 'offlineweb' in existing_files:
            if MAKEHOSVERSION("20.0.0", FW_VER_ANY, version):
                offlineweb_frag_1 = find_and_patch(existing_files['offlineweb'], version, "OFFLINEWEB", log,
                    offlineweb_pattern_diffs_1, pattern_offsets_map['offlineweb_1'],
                    rule_tag="OfflineWebMemoryPatches_1",
                    commit=False)

                offlineweb_frag_2 = find_and_patch(existing_files['offlineweb'], version, "OFFLINEWEB", log,
                    offlineweb_pattern_diffs_2, pattern_offsets_map['offlineweb_2'],
                    prior_patch_fragment=offlineweb_frag_1, suppress_logging=False,
                    rule_tag="OfflineWebMemoryPatches_2",
                    commit=False)

                offlineweb_frag_3 = find_and_patch(existing_files['offlineweb'], version, "OFFLINEWEB", log,
                    offlineweb_pattern_diffs_3, pattern_offsets_map['offlineweb_3'],
                    prior_patch_fragment=offlineweb_frag_2, suppress_logging=False,
                    rule_tag="OfflineWebMemoryPatches_3",
                    commit=False)

                offlineweb_frag_4 = find_and_patch(existing_files['offlineweb'], version, "OFFLINEWEB", log,
                    offlineweb_pattern_diffs_4, pattern_offsets_map['offlineweb_4'],
                    prior_patch_fragment=offlineweb_frag_3, suppress_logging=False,
                    rule_tag="OfflineWebMemoryPatches_4",
                    commit=False)

                offlineweb_frag_5 = find_and_patch(existing_files['offlineweb'], version, "OFFLINEWEB", log,
                    offlineweb_pattern_diffs_5, pattern_offsets_map['offlineweb_5'],
                    prior_patch_fragment=offlineweb_frag_4, suppress_logging=False,
                    rule_tag="OfflineWebMemoryPatches_5",
                    commit=False)

                find_and_patch(existing_files['offlineweb'], version, "OFFLINEWEB", log,
                    offlineweb_pattern_diffs_6, pattern_offsets_map['offlineweb_6'],
                    prior_patch_fragment=offlineweb_frag_5, suppress_logging=False,
                    rule_tag="OfflineWebMemoryPatches_6")

        if 'libappletweb' in existing_files:
            if MAKEHOSVERSION("20.0.0", FW_VER_ANY, version):
                libappletweb_frag_1 = find_and_patch(existing_files['libappletweb'], version, "LIBAPPLETWEB", log,
                    libappletweb_pattern_diffs_1, pattern_offsets_map['libappletweb_1'],
                    rule_tag="LibAppletWebMemoryPatches_1",
                    commit=False)

                libappletweb_frag_2 = find_and_patch(existing_files['libappletweb'], version, "LIBAPPLETWEB", log,
                    libappletweb_pattern_diffs_2, pattern_offsets_map['libappletweb_2'],
                    prior_patch_fragment=libappletweb_frag_1, suppress_logging=False,
                    rule_tag="LibAppletWebMemoryPatches_2",
                    commit=False)

                libappletweb_frag_3 = find_and_patch(existing_files['libappletweb'], version, "LIBAPPLETWEB", log,
                    libappletweb_pattern_diffs_3, pattern_offsets_map['libappletweb_3'],
                    prior_patch_fragment=libappletweb_frag_2, suppress_logging=False,
                    rule_tag="LibAppletWebMemoryPatches_3",
                    commit=False)

                libappletweb_frag_4 = find_and_patch(existing_files['libappletweb'], version, "LIBAPPLETWEB", log,
                    libappletweb_pattern_diffs_4, pattern_offsets_map['libappletweb_4'],
                    prior_patch_fragment=libappletweb_frag_3, suppress_logging=False,
                    rule_tag="LibAppletWebMemoryPatches_4",
                    commit=False)

                libappletweb_frag_5 = find_and_patch(existing_files['libappletweb'], version, "LIBAPPLETWEB", log,
                    libappletweb_pattern_diffs_5, pattern_offsets_map['libappletweb_5'],
                    prior_patch_fragment=libappletweb_frag_4, suppress_logging=False,
                    rule_tag="LibAppletWebMemoryPatches_5",
                    commit=False)

                find_and_patch(existing_files['libappletweb'], version, "LIBAPPLETWEB", log,
                    libappletweb_pattern_diffs_6, pattern_offsets_map['libappletweb_6'],
                    prior_patch_fragment=libappletweb_frag_5, suppress_logging=False,
                    rule_tag="LibAppletWebMemoryPatches_6")

        if 'libappletshop' in existing_files:
            if MAKEHOSVERSION("20.0.0", FW_VER_ANY, version):
                libappletshop_frag_1 = find_and_patch(existing_files['libappletshop'], version, "LIBAPPLETSHOP", log,
                    libappletshop_pattern_diffs_1, pattern_offsets_map['libappletshop_1'],
                    rule_tag="LibAppletShopMemoryPatches_1",
                    commit=False)

                libappletshop_frag_2 = find_and_patch(existing_files['libappletshop'], version, "LIBAPPLETSHOP", log,
                    libappletshop_pattern_diffs_2, pattern_offsets_map['libappletshop_2'],
                    prior_patch_fragment=libappletshop_frag_1, suppress_logging=False,
                    rule_tag="LibAppletShopMemoryPatches_2",
                    commit=False)

                libappletshop_frag_3 = find_and_patch(existing_files['libappletshop'], version, "LIBAPPLETSHOP", log,
                    libappletshop_pattern_diffs_3, pattern_offsets_map['libappletshop_3'],
                    prior_patch_fragment=libappletshop_frag_2, suppress_logging=False,
                    rule_tag="LibAppletShopMemoryPatches_3",
                    commit=False)

                libappletshop_frag_4 = find_and_patch(existing_files['libappletshop'], version, "LIBAPPLETSHOP", log,
                    libappletshop_pattern_diffs_4, pattern_offsets_map['libappletshop_4'],
                    prior_patch_fragment=libappletshop_frag_3, suppress_logging=False,
                    rule_tag="LibAppletShopMemoryPatches_4",
                    commit=False)

                libappletshop_frag_5 = find_and_patch(existing_files['libappletshop'], version, "LIBAPPLETSHOP", log,
                    libappletshop_pattern_diffs_5, pattern_offsets_map['libappletshop_5'],
                    prior_patch_fragment=libappletshop_frag_4, suppress_logging=False,
                    rule_tag="LibAppletShopMemoryPatches_5",
                    commit=False)

                find_and_patch(existing_files['libappletshop'], version, "LIBAPPLETSHOP", log,
                    libappletshop_pattern_diffs_6, pattern_offsets_map['libappletshop_6'],
                    prior_patch_fragment=libappletshop_frag_5, suppress_logging=False,
                    rule_tag="LibAppletShopMemoryPatches_6")

        if 'libappletlns' in existing_files:
            if MAKEHOSVERSION("20.0.0", FW_VER_ANY, version):
                libappletlns_frag_1 = find_and_patch(existing_files['libappletlns'], version, "LIBAPPLETLNS", log,
                    libappletlns_pattern_diffs_1, pattern_offsets_map['libappletlns_1'],
                    rule_tag="LibAppletLnsMemoryPatches_1",
                    commit=False)

                libappletlns_frag_2 = find_and_patch(existing_files['libappletlns'], version, "LIBAPPLETLNS", log,
                    libappletlns_pattern_diffs_2, pattern_offsets_map['libappletlns_2'],
                    prior_patch_fragment=libappletlns_frag_1, suppress_logging=False,
                    rule_tag="LibAppletLnsMemoryPatches_2",
                    commit=False)

                libappletlns_frag_3 = find_and_patch(existing_files['libappletlns'], version, "LIBAPPLETLNS", log,
                    libappletlns_pattern_diffs_3, pattern_offsets_map['libappletlns_3'],
                    prior_patch_fragment=libappletlns_frag_2, suppress_logging=False,
                    rule_tag="LibAppletLnsMemoryPatches_3",
                    commit=False)

                libappletlns_frag_4 = find_and_patch(existing_files['libappletlns'], version, "LIBAPPLETLNS", log,
                    libappletlns_pattern_diffs_4, pattern_offsets_map['libappletlns_4'],
                    prior_patch_fragment=libappletlns_frag_3, suppress_logging=False,
                    rule_tag="LibAppletLnsMemoryPatches_4",
                    commit=False)

                libappletlns_frag_5 = find_and_patch(existing_files['libappletlns'], version, "LIBAPPLETLNS", log,
                    libappletlns_pattern_diffs_5, pattern_offsets_map['libappletlns_5'],
                    prior_patch_fragment=libappletlns_frag_4, suppress_logging=False,
                    rule_tag="LibAppletLnsMemoryPatches_5",
                    commit=False)

                find_and_patch(existing_files['libappletlns'], version, "LIBAPPLETLNS", log,
                    libappletlns_pattern_diffs_6, pattern_offsets_map['libappletlns_6'],
                    prior_patch_fragment=libappletlns_frag_5, suppress_logging=False,
                    rule_tag="LibAppletLnsMemoryPatches_6")

        if 'libappletauth' in existing_files:
            if MAKEHOSVERSION("20.0.0", FW_VER_ANY, version):
                libappletauth_frag_1 = find_and_patch(existing_files['libappletauth'], version, "LIBAPPLETAUTH", log,
                    libappletauth_pattern_diffs_1, pattern_offsets_map['libappletauth_1'],
                    rule_tag="LibAppletAuthMemoryPatches_1",
                    commit=False)

                libappletauth_frag_2 = find_and_patch(existing_files['libappletauth'], version, "LIBAPPLETAUTH", log,
                    libappletauth_pattern_diffs_2, pattern_offsets_map['libappletauth_2'],
                    prior_patch_fragment=libappletauth_frag_1, suppress_logging=False,
                    rule_tag="LibAppletAuthMemoryPatches_2",
                    commit=False)

                libappletauth_frag_3 = find_and_patch(existing_files['libappletauth'], version, "LIBAPPLETAUTH", log,
                    libappletauth_pattern_diffs_3, pattern_offsets_map['libappletauth_3'],
                    prior_patch_fragment=libappletauth_frag_2, suppress_logging=False,
                    rule_tag="LibAppletAuthMemoryPatches_3",
                    commit=False)

                libappletauth_frag_4 = find_and_patch(existing_files['libappletauth'], version, "LIBAPPLETAUTH", log,
                    libappletauth_pattern_diffs_4, pattern_offsets_map['libappletauth_4'],
                    prior_patch_fragment=libappletauth_frag_3, suppress_logging=False,
                    rule_tag="LibAppletAuthMemoryPatches_4",
                    commit=False)

                libappletauth_frag_5 = find_and_patch(existing_files['libappletauth'], version, "LIBAPPLETAUTH", log,
                    libappletauth_pattern_diffs_5, pattern_offsets_map['libappletauth_5'],
                    prior_patch_fragment=libappletauth_frag_4, suppress_logging=False,
                    rule_tag="LibAppletAuthMemoryPatches_5",
                    commit=False)

                find_and_patch(existing_files['libappletauth'], version, "LIBAPPLETAUTH", log,
                    libappletauth_pattern_diffs_6, pattern_offsets_map['libappletauth_6'],
                    prior_patch_fragment=libappletauth_frag_5, suppress_logging=False,
                    rule_tag="LibAppletAuthMemoryPatches_6")
        
        # NIM has multiple patches (firmware block + crash fix)
        if 'nim' in existing_files:
            block_fw_fragment = find_and_patch(existing_files['nim'], version, "NIM", log,
                blockfirmwareupdates_pattern_diffs, pattern_offsets_map['nim'],
                commit=False)
            
            find_and_patch(existing_files['nim'], version, "NIM", log,
                blankcal0crashfix_pattern_diffs, pattern_offsets_map['nim'],
                prior_patch_fragment=block_fw_fragment, suppress_logging=False)
        
        # Filesystem patches
        if 'fat32' in existing_files:
            find_and_patch(existing_files['fat32'], version, "FS", log,
                fat32_noncasigchk_pattern_diffs, pattern_offsets_map['fat32_nc'], hash_path=existing_files.get('fat32_hash'))
            
            find_and_patch(existing_files['fat32'], version, "NOGC", log,
                nogc_pattern_diffs, pattern_offsets_map['fat32_nogc'], hash_path=existing_files.get('fat32_hash'))
        
        if 'exfat' in existing_files:
            find_and_patch(existing_files['exfat'], version, "FS", log,
                exfat_noncasigchk_pattern_diffs, pattern_offsets_map['exfat_nc'], hash_path=existing_files.get('exfat_hash'))
            
            find_and_patch(existing_files['exfat'], version, "NOGC", log,
                nogc_pattern_diffs, pattern_offsets_map['exfat_nogc'], hash_path=existing_files.get('exfat_hash'))


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


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == '__main__':
    print("\n" + "="*80)
    print("Writing embedded patches and pattern diffs...")
    print("="*80 + "\n")

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
        ('systemweb_pattern_diffs_1', systemweb_pattern_diffs_1),
        ('systemweb_pattern_diffs_2', systemweb_pattern_diffs_2),
        ('systemweb_pattern_diffs_3', systemweb_pattern_diffs_3),
        ('systemweb_pattern_diffs_4', systemweb_pattern_diffs_4),
        ('systemweb_pattern_diffs_5', systemweb_pattern_diffs_5),
        ('systemweb_pattern_diffs_6', systemweb_pattern_diffs_6),
        ('openweb_pattern_diffs_1', openweb_pattern_diffs_1),
        ('openweb_pattern_diffs_2', openweb_pattern_diffs_2),
        ('openweb_pattern_diffs_3', openweb_pattern_diffs_3),
        ('openweb_pattern_diffs_4', openweb_pattern_diffs_4),
        ('openweb_pattern_diffs_5', openweb_pattern_diffs_5),
        ('openweb_pattern_diffs_6', openweb_pattern_diffs_6),
        ('offlineweb_pattern_diffs_1', offlineweb_pattern_diffs_1),
        ('offlineweb_pattern_diffs_2', offlineweb_pattern_diffs_2),
        ('offlineweb_pattern_diffs_3', offlineweb_pattern_diffs_3),
        ('offlineweb_pattern_diffs_4', offlineweb_pattern_diffs_4),
        ('offlineweb_pattern_diffs_5', offlineweb_pattern_diffs_5),
        ('offlineweb_pattern_diffs_6', offlineweb_pattern_diffs_6),
        ('libappletweb_pattern_diffs_1', libappletweb_pattern_diffs_1),
        ('libappletweb_pattern_diffs_2', libappletweb_pattern_diffs_2),
        ('libappletweb_pattern_diffs_3', libappletweb_pattern_diffs_3),
        ('libappletweb_pattern_diffs_4', libappletweb_pattern_diffs_4),
        ('libappletweb_pattern_diffs_5', libappletweb_pattern_diffs_5),
        ('libappletweb_pattern_diffs_6', libappletweb_pattern_diffs_6),
        ('libappletshop_pattern_diffs_1', libappletshop_pattern_diffs_1),
        ('libappletshop_pattern_diffs_2', libappletshop_pattern_diffs_2),
        ('libappletshop_pattern_diffs_3', libappletshop_pattern_diffs_3),
        ('libappletshop_pattern_diffs_4', libappletshop_pattern_diffs_4),
        ('libappletshop_pattern_diffs_5', libappletshop_pattern_diffs_5),
        ('libappletshop_pattern_diffs_6', libappletshop_pattern_diffs_6),
        ('libappletlns_pattern_diffs_1', libappletlns_pattern_diffs_1),
        ('libappletlns_pattern_diffs_2', libappletlns_pattern_diffs_2),
        ('libappletlns_pattern_diffs_3', libappletlns_pattern_diffs_3),
        ('libappletlns_pattern_diffs_4', libappletlns_pattern_diffs_4),
        ('libappletlns_pattern_diffs_5', libappletlns_pattern_diffs_5),
        ('libappletlns_pattern_diffs_6', libappletlns_pattern_diffs_6),
        ('libappletauth_pattern_diffs_1', libappletauth_pattern_diffs_1),
        ('libappletauth_pattern_diffs_2', libappletauth_pattern_diffs_2),
        ('libappletauth_pattern_diffs_3', libappletauth_pattern_diffs_3),
        ('libappletauth_pattern_diffs_4', libappletauth_pattern_diffs_4),
        ('libappletauth_pattern_diffs_5', libappletauth_pattern_diffs_5),
        ('libappletauth_pattern_diffs_6', libappletauth_pattern_diffs_6),
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
    ]

    _update_pattern_diffs(existing_diffs, diff_categories, pattern_diffs_path)

    print("="*80)

    print("\nIncremental update complete!")