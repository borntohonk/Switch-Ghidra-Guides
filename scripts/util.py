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
import errno
import os
import ast
import lz4.block
import nca
from pathlib import Path
import romfs
import nxo64
from typing import List, Tuple

def print_split_hex(label, hex_string, lines_to_append_to):
    hex_upper = hex_string.upper() if isinstance(hex_string, str) else hex_string.hex().upper()
    label_padded = f'{label:<35}'
    lines_to_append_to.append(f'{label_padded} {hex_upper[:64]}')
    for i in range(64, len(hex_upper), 64):
        chunk = hex_upper[i:i+64]
        lines_to_append_to.append(f'                                    {chunk}')

def mkdirp(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

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


def remove_duplicates_by_index(list_of_tuples, index_to_check):
    seen_values = set()
    unique_list = []
    for current_tuple in list_of_tuples:
        value_to_check = current_tuple[index_to_check]

        if value_to_check not in seen_values:
            unique_list.append(current_tuple)
            seen_values.add(value_to_check)
            
    return unique_list


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

    written_count = 0
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            for entry in combined:
                #if version_to_tuple(entry[0]) >= version_to_tuple("10.0.0"):
                f.write(f"{entry},\n")
                written_count += 1
        if written_count > 0:
            print(f"Appended {written_count} new entries (version ≥10.0.0) to {filepath}")
        else:
            print(f"No new entries written to {filepath} (all below version 10.0.0)")
        return written_count > 0
    except Exception as e:
        print(f"Error writing {filepath}: {e}")
        return False


def version_to_tuple(version_string):
    parts = version_string.split('-')[0].split('.')
    return tuple(int(p) for p in parts)

def print_hash_summary(hash_summary_file_path):
    try:
        with open(hash_summary_file_path, 'r') as file:
            file_content = file.read()
            print(file_content)
    except FileNotFoundError:
        print(f"Error: The file '{hash_summary_file_path}' was not found.")
    except Exception as e:
        print(f"An error occurred in loading the hash_summary: {e}")

def get_user_agent(decompressed_account_path):
    with open(decompressed_account_path, 'rb') as f:
        data = f.read()
        hex_data = data.hex().upper()
        account_pattern = "6C69626375726C2028" # = "libcurl ("
        match = re.search(account_pattern, hex_data)
        if not match:
            return "Unknown"
            
        start_pos = match.start() // 2
        raw = data[start_pos : start_pos + 0x80].decode('utf-8', errors='ignore')
        cleaned = raw.split('\x00')[0].strip()
        if cleaned.startswith("User-Agent: "):
            cleaned = cleaned[12:].strip()
        return cleaned
    
def get_dauth_address(decompressed_acount_path):
    with open(decompressed_acount_path, 'rb') as f:
        data = f.read()
        hex_data = data.hex().upper()
        account_pattern = "68747470733A2F2F64617574682D252E6E6461732E7372762E6E696E74656E646F2E6E6574"
        dauth_address_result = re.search(account_pattern, hex_data)
        dauth_address_result_hex = int(dauth_address_result.start() / 2)
        dauth_address_result_hex_end = dauth_address_result_hex + 41
        dauth_address = data[dauth_address_result_hex:dauth_address_result_hex_end].decode('utf-8').replace(chr(0), "").replace("%", "lp1")
        return dauth_address

def get_dauth_strings(dauth_file_path):
    with open(dauth_file_path, 'rb') as f:
        data_read = f.read()
        firmware_version = data_read[0x68:0x6E].decode('utf-8').replace(chr(0), "")
        firmware_version_no_dot = firmware_version.replace(".", "")
        firmware_revision = data_read[0x28:0x50].decode('utf-8').replace(chr(0), "")
        firmware_string = data_read[0x9C:0xA6].decode('utf-8').replace(chr(0), "")
    return firmware_version_no_dot, firmware_revision, firmware_string

def get_dauth_digest(dauth_digest_path):
    try:
        with open(dauth_digest_path, 'r') as f:
            data_read = f.read()
            digest = data_read[0x0:0x3B]
        return digest
    except FileNotFoundError:
        return "Unknown"

def decompress_exefs(main_path, nso_name):
    main_path = main_path
    nso_name = nso_name
    with open(main_path, 'rb') as compressed_exefs_file:
        decompressed_nso = nxo64.decompress_nso(compressed_exefs_file)
        with open(nso_name, 'wb') as decompressed_exefs_file:
            decompressed_exefs_file.write(decompressed_nso)
            decompressed_exefs_file.close()
            compressed_exefs_file.close()

def decompress_kip(kip_path, kip_name):
    kip_path = kip_path
    kip_name = kip_name
    with open(kip_path, 'rb') as compressed_kip_file:
        decompressed_kip = nxo64.decompress_kip(compressed_kip_file)
        with open(kip_name, 'wb') as decompressed_kip_file:
            decompressed_kip_file.write(decompressed_kip)
            decompressed_kip_file.close()
            compressed_kip_file.close()

def get_module_id(input):
    with open(input, 'rb') as f:
        f.seek(0x40)
        return(f.read(0x10).hex().upper())
    
def extract_browser_dll_romfs(nca_path, version):
    nca_file = nca.Nca(InitializeFile(nca_path), master_kek_source=None, titlekey=None)
    romfs_data = nca.save_section(nca_file, 0)
    romfs.romfs_process(romfs_data, output_path=Path(f"sorted_firmware/{version}/by-type/Data/0100000000000803/romfs"), list_only=False, print_info=False)


def decompress_foss_nro(nro_path, nro_name):
    nro_path = nro_path
    nro_name = nro_name
    with open(nro_path, 'rb') as file:
        input_data = file.read()
        decompressed = lz4.block.decompress(input_data)
        decompressed_browser_file = open(nro_name, 'wb')
        decompressed_browser_file.write(decompressed)
        decompressed_browser_file.close()

def InitializeFile(input):
    with open(input, 'rb') as f:
        data = f.read()
    return data