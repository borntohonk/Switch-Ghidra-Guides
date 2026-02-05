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

import os
import sys
import shutil
import argparse
import crypto
from pathlib import Path
import nca
from key_sources import KeySources
import extract_packages
from hashlib import sha256
import romfs
import util
import pfs0
import emummc_h
from keys import RootKeys

def format_bytes_as_hex(data: bytes) -> str:
    """Transforms bytes into a comma-separated hex string."""
    return "bytes([" + ", ".join(f"0x{b:02X}" for b in data) + "]),"

def to_c_hex_array_16(hex_str: str) -> str:
    """
    Converts a hex string (at least 32 chars) into this exact format:
    { 0xAF, 0x1D, 0xBD, 0xC7, 0x82, 0x98, 0x3C, 0xBD }
    
    Only uses the first 16 bytes / 32 hex characters.
    """

    hex_str = hex_str.strip().upper()
    if len(hex_str) < 16:
        raise ValueError("Input must contain at least 16 hex characters")

    data = hex_str[:16]
    bytes_formatted = [f"0x{data[i:i+2]}" for i in range(0, 16, 2)]
    inner = ", ".join(bytes_formatted)
    
    return f"{{ {inner} }}"

titleids_to_store = [
    '0100000000000809', # system_update
    '0100000000000819', # fat32
    '010000000000081B', # exfat
    '010000000000001E', # account
    '0100000000000033', # es
    '010000000000000F', # nifm
    '010000000000003E', # olsc
    '0100000000000025', # nim
    '0100000000000024', # ssl
    '0100000000000006', # usb
    '0100000000000803', # browser
]

def move_and_overwrite_folder(source_folder, destination_folder):
    """
    Moves a source folder and its contents to a destination folder, 
    overwriting the destination if it already exists.
    
    Args:
        source_folder (str): Path to the source folder.
        destination_folder (str): Path to the destination folder.
    """
    # Step 1: Check if the destination folder already exists and remove it
    if os.path.exists(destination_folder):
        #print(f"Destination folder '{destination_folder}' found. Removing existing folder...")
        shutil.rmtree(destination_folder) # Recursively removes the directory and all its contents
        #print(f"Removed '{destination_folder}'.")

    # Step 2: Move the source folder to the destination location
    #print(f"Moving '{source_folder}' to '{destination_folder}'...")
    shutil.move(source_folder, destination_folder)
    #print("Move complete.")

def _extract_system_version(system_nca_path, mkeksource):
    """Extract firmware version from system update NCA."""
    # Clean temp directory if it exists from previous runs
    if os.path.isdir("temp"):
        shutil.rmtree("temp")
    util.mkdirp("temp")
    
    system_nca = nca.Nca(util.InitializeFile(system_nca_path), master_kek_source=mkeksource, titlekey=None)
    
    romfs_data = nca.save_section(system_nca, 0)
    romfs.romfs_process(romfs_data, output_path=Path("temp"), list_only=False, print_info=False)
    
    with open('temp/file', 'rb') as file:
        data_read = file.read()
        firmware_version = data_read[0x68:0x6E].decode('utf-8').replace(chr(0), "")
    
    util.mkdirp(f'output/{firmware_version}')
    
    # Move digest file if it exists
    if os.path.exists('temp/digest'):
        shutil.move('temp/digest', f'output/{firmware_version}/{firmware_version}_system_digest')
    
    # Move system update file if it exists
    if os.path.exists('temp/file'):
        shutil.move('temp/file', f'output/{firmware_version}/{firmware_version}_system_update_file')
    
    # Clean up temp directory
    if os.path.isdir("temp"):
        shutil.rmtree("temp")
    
    return firmware_version


def _copy_sorted_nca(titleId, content_type, nca_path):
    """Copy NCA file to sorted firmware directory."""
    try:
        output_dir = f"sorted_firmware/temp/by-type/{content_type}/{titleId}"
        util.mkdirp(output_dir)
        shutil.copy(nca_path, f"{output_dir}/data.nca")
    except Exception as e:
        print(f"Warning: Failed to copy NCA {titleId}: {e}")


def sort_nca(location):
    """Sort and extract NCA files from firmware location."""
    nca_files = []
    sorted_nca_files = []
    
    # Collect all non-CNMT NCA files
    for nca_file in os.listdir(location):
        nca_path = os.path.join(location, nca_file)
        if not nca_path.endswith(".cnmt.nca"):
            nca_files.append(nca_path)
    
    # Filter for target title IDs
    for nca_path in nca_files:
        nca_header = nca.NcaHeaderOnly(util.InitializeFile(nca_path))
        if nca_header.titleId in titleids_to_store:
            sorted_nca_files.append((nca_header.titleId, nca_header.content_type, nca_path))
    
    # Extract system version from system update NCA
    master_key_rev = None
    temp_folder = "temp"
    
    # Copy remaining NCAs to sorted directory
    for titleId, content_type, nca_path in sorted_nca_files:
        _copy_sorted_nca(titleId, content_type, nca_path)
        if titleId == "0100000000000809":  # system_update
            nca_header = nca.NcaHeaderOnly(util.InitializeFile(nca_path))
            master_key_rev = nca_header.master_key_revision
    
    return temp_folder, master_key_rev

keygen_revisions = [
    (0x00, '1.0.0'), # KeyGenerationOld 0x00
    (0x01, '2.0.0'), # KeyGenerationOld 0x01 (Unused)
    (0x02, '3.0.0'), # KeyGenerationOld 0x02
    (0x03, '3.0.1'),
    (0x04, '4.0.0'),
    (0x05, '5.0.0'),
    (0x06, '6.0.0'),
    (0x07, '6.2.0'),
    (0x08, '7.0.0'),
    (0x09, '8.1.0'),
    (0x0A, '9.0.0'),
    (0x0B, '9.1.0'),
    (0x0C, '12.1.0'),
    (0x0D, '13.0.0'),
    (0x0E, '14.0.0'),
    (0x0F, '15.0.0'),
    (0x10, '16.0.0'),
    (0x11, '17.0.0'),
    (0x12, '18.0.0'),
    (0x13, '19.0.0'),
    (0x14, '20.0.0'),
    (0x15, '21.0.0'),
]

# ============================================================================
# Program Title ID to NCA mapping for extraction
# ============================================================================

PROGRAM_TITLES = {
    '0100000000000033': 'es',
    '010000000000001E': 'account',
    '010000000000000F': 'nifm',
    '010000000000003E': 'olsc',
    '0100000000000025': 'nim',
    '0100000000000024': 'ssl',
}

DATA_TITLES = {
    '0100000000000819': 'fat32',
    '010000000000081B': 'exfat',
    '0100000000000803': 'browser',
    '0100000000000809': 'SystemVersion',
}


def _extract_nca_data(titleId, system_version, nca_type='Program'):
    """Extract and process a single NCA file."""
    nca_path = Path(f'sorted_firmware/{system_version}/by-type/{nca_type}/{titleId}/data.nca')
    if not nca_path.exists():
        return None
    
    nca_data = nca.Nca(util.InitializeFile(nca_path), master_kek_source=None, titlekey=None)
    pfs0_section = nca.save_section(nca_data, 0)
    return pfs0_section


def _extract_pfs0_and_get_module_id(titleId, system_version, title_name, nca_type='Program'):
    """Extract PFS0 section and get module ID."""
    pfs0_section = _extract_nca_data(titleId, system_version, nca_type)
    if pfs0_section is None:
        return None
    
    exefs_path = Path(f'sorted_firmware/{system_version}/by-type/{nca_type}/{titleId}/exefs/')
    pfs0.extract_pfs0(pfs0_section, exefs_path)
    
    main_path = exefs_path / 'main'
    if main_path.exists():
        return util.get_module_id(main_path)
    return None


def _process_filesystem_packages(master_key_revision, key_sources):
    """Process fat32 and exfat filesystem packages."""
    master_kek_source = None
    fat32_sdkversion = None
    exfat_sdkversion = None
    fat32_path = Path(f'sorted_firmware/temp/by-type/Data/0100000000000819/data.nca')
    exfat_path = Path(f'sorted_firmware/temp/by-type/Data/010000000000081B/data.nca')
    
    master_key_keygen_list = [revision[0] for revision in keygen_revisions]
    
    # New key derivation workflow
    if master_key_revision not in master_key_keygen_list or master_key_revision == master_key_keygen_list[-1]:
        root_keys = RootKeys()
        if fat32_path.exists():
            master_kek_source, device_master_key_source_source, fat32_sdkversion, package1_version = extract_packages.erista_process_package_with_key_derivation(fat32_path)
            if sha256(root_keys.mariko_bek).hexdigest().upper() == "491A836813E0733A0697B2FA27D0922D3D6325CE3C6BBEA982CF4691FAF6451A":
                mariko_master_kek_source, mariko_master_kek_source_dev = extract_packages.mariko_process_package_with_key_derivation(fat32_path)
        if exfat_path.exists() and master_kek_source:
            exfat_sdkversion, exfat_bootloader_version = extract_packages.process_filesystem_package(exfat_path, master_kek_source)[1]
        
        if master_kek_source and master_kek_source not in key_sources.master_kek_sources:
            print("A new master_kek_source was detected, add it to key_sources.py")
            tsec_root_key_02, tsec_root_key_02_dev = crypto.tsec_keygen()
            keygen = crypto.Keygen(tsec_root_key_02)
            keygen_dev = crypto.KeygenDev(tsec_root_key_02_dev)
            master_key_00_dev = keygen_dev.master_key[0]
            master_key_00 = keygen.master_key[0]
            master_kek, master_key, package2_key, titlekek, key_area_key_system, key_area_key_ocean, key_area_key_application = crypto.single_keygen_master_kek(master_kek_source)
            master_kek_dev, master_key_dev, package2_key_dev, titlekek_dev, key_area_key_system_dev, key_area_key_ocean_dev, key_area_key_application_dev = crypto.single_keygen_dev(master_kek_source)
            
            print(f'new master_kek:                      {master_kek.hex().upper()}')
            print(f'new master_key:                      {master_key.hex().upper()}')
            print(f'new package2_key:                    {package2_key.hex().upper()}')
            print(f'new titlekek:                        {titlekek.hex().upper()}')
            print(f'new key_area_key_system:             {key_area_key_system.hex().upper()}')
            print(f'new key_area_key_ocean:              {key_area_key_ocean.hex().upper()}')
            print(f'new key_area_key_application:        {key_area_key_application.hex().upper()}')
            print("")
            print(f'new master_kek_dev:                  {master_kek_dev.hex().upper()}')
            print(f'new master_key_dev:                  {master_key_dev.hex().upper()}')
            print(f'new package2_key_dev:                {package2_key_dev.hex().upper()}')
            print(f'new titlekek_dev:                    {titlekek_dev.hex().upper()}')
            print(f'new key_area_key_system_dev:         {key_area_key_system_dev.hex().upper()}')
            print(f'new key_area_key_ocean_dev:          {key_area_key_ocean_dev.hex().upper()}')
            print(f'new key_area_key_application_dev:    {key_area_key_application_dev.hex().upper()}') 
            DeviceMasterKek = crypto.decrypt_ecb(key_sources.DeviceMasterKekSource, master_kek)
            DeviceMasterKekSourceSource = crypto.encrypt_ecb(DeviceMasterKek, master_key_00)
            DeviceMasterKek_dev = crypto.decrypt_ecb(key_sources.DeviceMasterKekSource, master_kek_dev)
            DeviceMasterKekSourceSource_dev = crypto.encrypt_ecb(DeviceMasterKek_dev, master_key_00_dev)
            print(f"atmosphere specific keys:")
            print(f'package1 version:                    {package1_version}')
            print(f'package1 version belongs in fusee/program/source/fusee_setup_horizon.cpp')
            print(f'master_kek_source =                  {format_bytes_as_hex(master_kek_source)}')
            print(f'DeviceMasterKeySourceSource          {format_bytes_as_hex(device_master_key_source_source)}')
            print(f'DeviceMasterKekSource =              {format_bytes_as_hex(DeviceMasterKekSourceSource)}')
            print(f'DeviceMasterKekSourceDev =           {format_bytes_as_hex(DeviceMasterKekSourceSource_dev)}')
            if sha256(root_keys.mariko_bek).hexdigest().upper() == "491A836813E0733A0697B2FA27D0922D3D6325CE3C6BBEA982CF4691FAF6451A":
                print(f'mariko_master_kek_source =           {format_bytes_as_hex(mariko_master_kek_source)}')
                print(f'mariko_master_kek__source_dev =      {format_bytes_as_hex(mariko_master_kek_source_dev)}')
            else:
                print("No mariko_bek, or incorrect mariko_bek in keys.py")
            print(f'master_kek_sources belong in exosphere/program/source/boot/secmon_boot_key_data.s')
            print(f'they also belong in fusee/program/source/fusee_key_derivation.cpp')
            print("Add all the keys to their respective sections inside of key_sources.py, then re-run process_firwmare.py")
            # refer to https://github.com/Atmosphere-NX/Atmosphere/commit/18bb1fdea00781dac30a051aad6ae1d80ad67137 as to what values should go where
            # emummc/keyless update https://github.com/Atmosphere-NX/Atmosphere/commit/1e88f37892555da4c38ca6c95f43c56cc6bb87e6
            # some values are made with scripts/find_patterns.py
            sys.exit(1)
        else:
            print(f"Update keygen_revisions (in this file) to include the new firmware revision, example if latest entry is 0x14, add 0x15, then re-run process_firwmare.py")
            print(f'also in exosphere/program/source/boot/secmon_package2.cpp')
            print(f'and in fusee/program/source/fusee_package2.cpp')
            print(f'and libraries/libexosphere/include/exosphere/pkg1/pkg1_key_generation.hpp')
            sys.exit(1)
    
    # Existing key workflow
    else:
        key_index = master_key_revision
        master_kek_source = key_sources.master_kek_sources[key_index - 0x8]
        
        if fat32_path.exists():
            fat32_sdkversion, bootloader_version = extract_packages.process_filesystem_package(fat32_path, master_kek_source)
        
        if exfat_path.exists():
            exfat_sdkversion, bootloader_version = extract_packages.process_filesystem_package(exfat_path, master_kek_source)

    return master_kek_source, fat32_sdkversion, exfat_sdkversion, bootloader_version


def _copy_kip1_files(system_version):
    """Copy KIP1 filesystem files to output directory."""
    fat32_kip1_path = Path(f'sorted_firmware/{system_version}/by-type/Data/0100000000000819/romfs/nx/FS.kip1')
    exfat_kip1_path = Path(f'sorted_firmware/{system_version}/by-type/Data/010000000000081B/romfs/nx/FS.kip1')
    
    if fat32_kip1_path.exists():
        shutil.copy(fat32_kip1_path, f'output/{system_version}/{system_version}_fat32_FS.kip1')
        util.decompress_kip(fat32_kip1_path, f'output/{system_version}/{system_version}_fat32_uFS.kip1')
 
    if exfat_kip1_path.exists():
        shutil.copy(exfat_kip1_path, f'output/{system_version}/{system_version}_exfat_FS.kip1')
        util.decompress_kip(exfat_kip1_path, f'output/{system_version}/{system_version}_exfat_uFS.kip1')


def _copy_exefs_files(system_version):
    """Copy compressed and decompressed exefs files to output directory."""
    files_to_process = [
        ('es', '0100000000000033'),
        ('account', '010000000000001E'),
        ('nifm', '010000000000000F'),
        ('olsc', '010000000000003E'),
        ('nim', '0100000000000025'),
        ('ssl', '0100000000000024'),
    ]
    
    for name, titleId in files_to_process:
        main_path = Path(f'sorted_firmware/{system_version}/by-type/Program/{titleId}/exefs/main')
        if main_path.exists():
            shutil.copy(main_path, f'output/{system_version}/{system_version}_compressed_{name}.nso0')
            util.decompress_exefs(main_path, f'output/{system_version}/{system_version}_uncompressed_{name}.nso0')


def _write_hashes_file(system_version, module_ids, bootloader_version):
    """Write module IDs and filesystem hashes to output file."""
    hash_file_path = f'output/{system_version}/{system_version}_hashes.txt'

    version_with_underscores = system_version.replace(".", "_")
    version_no_dot = system_version.replace(".", "")
    
    fat32_kip1_path = Path(f'sorted_firmware/{system_version}/by-type/Data/0100000000000819/romfs/nx/FS.kip1')
    exfat_kip1_path = Path(f'sorted_firmware/{system_version}/by-type/Data/010000000000081B/romfs/nx/FS.kip1')
    
    with open(hash_file_path, 'w') as f:
        if fat32_kip1_path.exists():
            fat32_hash = sha256(open(fat32_kip1_path, 'rb').read()).hexdigest().upper()
            f.write(f'{system_version} fat32 sha256 = {fat32_hash} */\n')
            f.write(f'{to_c_hex_array_16(fat32_hash)}, /* FsVersion_{version_with_underscores}\n')
            f.write(f'^ add to fusee/program/source/fusee_stratosphere.cpp\n')
        else:
            f.write(f'{system_version} No fat32 present in this firmware version\n')
        
        if exfat_kip1_path.exists():
            exfat_hash = sha256(open(exfat_kip1_path, 'rb').read()).hexdigest().upper()
            f.write(f'{system_version} exfat sha256 = {exfat_hash}\n')
            f.write(f'{to_c_hex_array_16(exfat_hash)}, /* FsVersion_{version_with_underscores}_Exfat */\n')
            f.write(f'^ add to fusee/program/source/fusee_stratosphere.cpp\n')
        else:
            f.write(f'{system_version} No exFAT present in this firmware version\n')
        f.write(f'\n\nThe following list of files also need FS related updates in atmosphere:\n')
        f.write(f'the package2 bootloader version is: {bootloader_version}\n')
        f.write(f'emummc/source/FS/FS_offsets.c\n')
        f.write(f'emummc/source/FS/FS_versions.h\n')
        f.write(f'fusee/program/source/fusee_stratosphere.cpp\n')
        f.write(f'libraries/libstratosphere/include/stratosphere/hos/hos_types.hpp\n')
        f.write(f'libraries/libvapours/include/vapours/ams/ams_api_version.h\n')
        f.write(f'libraries/libvapours/include/vapours/ams/ams_target_firmware.h\n')
        f.write(f'creation of the two emummc.h files:\n')
        f.write(f'emummc/source/FS/offsets/{version_no_dot}.h\n')
        f.write(f'emummc/source/FS/offsets/{version_no_dot}_exfat.h\n\n')
        # Write module IDs
        for title_name, title_id in module_ids.items():
            f.write(f'{system_version} {title_name}_moduleid: {title_id}\n')


def _write_firmware_strings(system_version, key_revision, dauth_file_path, dauth_digest_path):
    """Write dAuth firmware strings for firmware update."""
    if util.version_to_tuple(system_version) < util.version_to_tuple("9.0.0"):
        return
    
    firmware_version_no_dot, firmware_revision, firmware_string = util.get_dauth_strings(dauth_file_path)
    digest = util.get_dauth_digest(dauth_digest_path)
    user_agent = util.get_user_agent(f'output/{system_version}/{system_version}_uncompressed_account.nso0')
    dauth_address = util.get_dauth_address(f'output/{system_version}/{system_version}_uncompressed_account.nso0')
    
    if util.version_to_tuple(system_version) <= util.version_to_tuple("19.99.99"):
        firmware_revision = digest
    
    strings_file = f'output/{system_version}/{system_version}_firmware_strings.txt'
    with open(strings_file, 'w') as f:
        f.write('    "cdn": {\n')
        f.write(f'        "firmware": "{firmware_string}",\n')
        f.write('        "calibration": "PRODINFO.bin",\n')
        f.write('        "dAuth": {\n')
        f.write(f'            "keyGeneration": {key_revision},\n')
        f.write(f'            "fw_revision": "{firmware_revision}",\n')
        f.write(f'            "userAgent": "{user_agent.strip()}",\n')
        f.write(f'            "sysDigest": {firmware_version_no_dot},\n')
        f.write(f'            "baseURL": "{dauth_address}"\n')
        f.write('        }\n')
        f.write('    },\n')
    
    # Extract FOSS browser if available (21.0.0+)
    if util.version_to_tuple(system_version) >= util.version_to_tuple("21.0.0"):
        browser_path = Path(f'sorted_firmware/{system_version}/by-type/Data/0100000000000803/data.nca')
        if browser_path.exists():
            util.extract_browser_dll_romfs(browser_path, system_version)
            browser_nro_path = Path(f'sorted_firmware/{system_version}/by-type/Data/0100000000000803/romfs/nro/netfront/core_3/Default/cfi_nncfi/webkit_wkc.nro.lz4')
            if browser_nro_path.exists():
                util.decompress_foss_nro(browser_nro_path, f'output/{system_version}/{system_version}_foss_browser_ssl.nro')
                browser_module_id = util.get_module_id(f'output/{system_version}/{system_version}_foss_browser_ssl.nro')
                with open(strings_file, 'a') as f:
                    f.write(f'{system_version} foss_ssl_browser_moduleid: {browser_module_id}')


    if util.version_to_tuple(system_version) > util.version_to_tuple("21.0.0"):
        exfat_kip = f'output/{system_version}/{system_version}_exfat_uFS.kip1'
        fat32_kip = f'output/{system_version}/{system_version}_fat32_uFS.kip1'
        print(f'exfat emummc.h for {system_version}')
        emummc_h.produce_emummc_h(exfat_kip, firmware_version_no_dot, "EXFAT_")
        print('\n\n')
        print(f'fat32 emummc.h for {system_version}')
        emummc_h.produce_emummc_h(fat32_kip, firmware_version_no_dot, "")


def _get_valid_firmware_folders(firmwares_dir='firmwares'):
    """Discover all valid firmware folders with .nca files."""
    valid_folders = {}
    
    if not os.path.isdir(firmwares_dir):
        print(f"Error: Firmwares directory '{firmwares_dir}' not found.")
        return valid_folders
    
    try:
        entries = os.listdir(firmwares_dir)
    except Exception as e:
        print(f"Error: Failed to read directory '{firmwares_dir}': {e}")
        return valid_folders
    
    for entry in entries:
        folder_path = os.path.join(firmwares_dir, entry)
        if os.path.isdir(folder_path):
            nca_files = [f for f in os.listdir(folder_path) if f.lower().endswith('.nca')]
            if len(nca_files) > 0:
                valid_folders[entry] = len(nca_files)
    
    return valid_folders


def _process_cdn_only(firmware_location='firmware'):
    """Extract CDN-related data from firmware (system version and keys only)."""
    nca_files = []
    sorted_nca_files = []
    
    # Collect all non-CNMT NCA files
    for nca_file in os.listdir(firmware_location):
        nca_path = os.path.join(firmware_location, nca_file)
        if not nca_path.endswith(".cnmt.nca"):
            nca_files.append(nca_path)
    
    # Filter for system_update and account only
    cdn_titleids = ['0100000000000809', '010000000000001E']
    for nca_path in nca_files:
        nca_header = nca.NcaHeaderOnly(util.InitializeFile(nca_path))
        if nca_header.titleId in cdn_titleids:
            sorted_nca_files.append((nca_header.titleId, nca_header.content_type, nca_path))
    
    system_version = None
    master_key_rev = None
    
    # Extract system version from system_update NCA
    for titleId, content_type, nca_path in sorted_nca_files:
        if titleId == "0100000000000809":  # system_update
            nca_header = nca.NcaHeaderOnly(util.InitializeFile(nca_path))
            master_key_rev = nca_header.master_key_revision
            system_version = _extract_system_version(nca_path)
            break
    
    if system_version is None:
        print("Error: Could not find system_update NCA in firmware")
        return None, None
    
    # Copy account NCA for CDN extraction
    for titleId, content_type, nca_path in sorted_nca_files:
        if titleId == "010000000000001E":  # account
            try:
                account_dir = f"sorted_firmware/{system_version}/by-type/Program/010000000000001E"
                util.mkdirp(account_dir)
                shutil.copy(nca_path, f"{account_dir}/data.nca")
            except Exception as e:
                print(f"Warning: Failed to copy account NCA: {e}")
    
    return system_version, master_key_rev


def sort_and_process_single(firmware_location='firmware', key_sources_override=None, sdk_versions_list=None):
    """Main firmware extraction and processing pipeline for a single firmware.
    
    Args:
        firmware_location: Path to firmware folder (default: 'firmware')
        key_sources_override: Optional KeySources instance (will create if None)
        sdk_versions_list: Optional list to append SDK versions to (for batch processing)
    """
    if key_sources_override is None:
        key_sources = KeySources()
    else:
        key_sources = key_sources_override
    
    util.mkdirp('output')
    
    # Extract and sort NCAs
    temp_folder, master_key_revision = sort_nca(firmware_location)
    key_revision = master_key_revision + 1
    
    # Process filesystem packages (fat32/exfat)
    master_kek_source, fat32_sdkversion, exfat_sdkversion, bootloader_version = _process_filesystem_packages(master_key_revision, key_sources)
    
    system_update_data_patch = f'sorted_firmware/temp/by-type/Data/0100000000000809/data.nca'
    system_version = _extract_system_version(system_update_data_patch, master_kek_source)
    print(f'\nFirmware version: {system_version}\n')
    move_and_overwrite_folder(f'sorted_firmware/{temp_folder}', f'sorted_firmware/{system_version}')

    # Extract program NCAs and get module IDs
    module_ids = {}
    for titleId, name in PROGRAM_TITLES.items():
        nca_type = 'Program'
        module_id = _extract_pfs0_and_get_module_id(titleId, system_version, name, nca_type)
        if module_id:
            module_ids[name] = module_id
    
    # Copy KIP1 files and exefs files
    _copy_kip1_files(system_version)
    _copy_exefs_files(system_version)
    
    # Write hashes and metadata
    _write_hashes_file(system_version, module_ids, bootloader_version)
    
    dauth_file_path = f'output/{system_version}/{system_version}_system_update_file'
    dauth_digest_path = f'output/{system_version}/{system_version}_system_digest'
    _write_firmware_strings(system_version, key_revision, dauth_file_path, dauth_digest_path)
    
    # Print summary
    hash_summary_file = f'output/{system_version}/{system_version}_hashes.txt'
    util.print_hash_summary(hash_summary_file)
    print("")
    
    firmware_strings_file = f'output/{system_version}/{system_version}_firmware_strings.txt'
    if os.path.exists(firmware_strings_file):
        util.print_hash_summary(firmware_strings_file)
    
    # Collect SDK versions
    sdk_versions = []
    if fat32_sdkversion:
        fat32_hash = sha256(open(f'sorted_firmware/{system_version}/by-type/Data/0100000000000819/romfs/nx/FS.kip1', 'rb').read()).hexdigest().upper()
        sdk_versions.append((system_version, fat32_hash[:16], fat32_hash, fat32_sdkversion))
    if exfat_sdkversion:
        exfat_hash = sha256(open(f'sorted_firmware/{system_version}/by-type/Data/010000000000081B/romfs/nx/FS.kip1', 'rb').read()).hexdigest().upper()
        sdk_versions.append((system_version, exfat_hash[:16], exfat_hash, exfat_sdkversion))
    
    # For batch processing, append to provided list; otherwise update database
    if sdk_versions_list is not None:
        sdk_versions_list.extend(sdk_versions)
    elif sdk_versions:
        sdk_versions_updated = util.update_patch_file('patch_database/fs_sdk_versions.txt', sdk_versions)
        if not sdk_versions_updated:
            print("SDK version strings up to date")


def sort_and_process():
    """Backward compatible wrapper for single firmware processing."""
    sort_and_process_single('firmware')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Process Nintendo Switch firmware for extraction and analysis'
    )
    parser.add_argument(
        '--batch',
        action='store_true',
        help='Process all firmware folders in firmwares/ directory instead of single firmware/ folder'
    )
    parser.add_argument(
        '--cdn',
        action='store_true',
        help='Extract CDN data only (system version, keys, and user agent)'
    )
    
    args = parser.parse_args()
    
    util.mkdirp('output')
    key_sources = KeySources()
    
    if args.batch:
        # Batch processing mode - process all firmwares
        firmware_folders = _get_valid_firmware_folders('firmwares')
        
        if not firmware_folders:
            print("Error: No valid firmware folders found in 'firmwares/' directory")
            sys.exit(1)
        
        print(f"\nFound {len(firmware_folders)} valid firmware folder(s):")
        for folder_name, nca_count in firmware_folders.items():
            print(f"  - {folder_name}: {nca_count} .nca files")
        print()
        
        sdk_versions = []
        
        # Process each firmware folder
        for firmware_folder_name in sorted(firmware_folders.keys(), key=util.version_to_tuple):
            firmware_location = f'firmwares/{firmware_folder_name}'
            print(f"\n{'='*80}")
            print(f"Processing firmware from: {firmware_location}")
            print(f"{'='*80}\n")
            
            sort_and_process_single(firmware_location, key_sources, sdk_versions)
        
        print(f"\n{'='*80}")
        print(f"Batch processing completed successfully!")
        print(f"{'='*80}\n")
        
        # Update SDK database with all collected versions
        if sdk_versions:
            sdk_versions_updated = util.update_patch_file('patch_database/fs_sdk_versions.txt', sdk_versions)
            if not sdk_versions_updated:
                print("SDK version strings up to date")
    
    elif args.cdn:
        # CDN extraction mode - system version, keys, and user agent only
        print("\n" + "="*80)
        print("Extracting CDN data only from firmware/")
        print("="*80 + "\n")
        
        system_version, master_key_rev = _process_cdn_only("firmware")
        
        if system_version is None:
            sys.exit(1)
        
        key_revision = master_key_rev + 1
        
        # Extract account for user agent and dAuth address
        account_path = Path(f'sorted_firmware/{system_version}/by-type/Program/010000000000001E/data.nca')
        if account_path.exists():
            try:
                _extract_pfs0_and_get_module_id('010000000000001E', system_version, 'account', 'Program')
                util.decompress_exefs(
                    f'sorted_firmware/{system_version}/by-type/Program/010000000000001E/exefs/main',
                    f'output/{system_version}/{system_version}_uncompressed_account.nso0'
                )
            except Exception as e:
                print(f"Warning: Failed to extract account: {e}")
        
        # Extract CDN strings
        dauth_file_path = f'output/{system_version}/{system_version}_system_update_file'
        dauth_digest_path = f'output/{system_version}/{system_version}_system_digest'
        
        _write_firmware_strings(system_version, key_revision, dauth_file_path, dauth_digest_path)
        
        firmware_strings_file = f'output/{system_version}/{system_version}_firmware_strings.txt'
        if os.path.exists(firmware_strings_file):
            util.print_hash_summary(firmware_strings_file)
        
        print("\nCDN extraction completed successfully!")
    
    else:
        # Default mode - process single firmware/ folder
        sort_and_process()