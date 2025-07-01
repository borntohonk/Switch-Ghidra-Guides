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
import argparse
import difflib
import json
import glob
import crypto
from pathlib import Path
import nca
from key_sources import KeySources
import extract_packages
from hashlib import sha256
import util
import emummc_h
from organize_firmware_files import sort_nca
from keys import RootKeys

def format_bytes_as_hex(data: bytes) -> str:
    """Transforms bytes into a comma-separated hex string."""
    return ", ".join(f"0x{b:02X}" for b in data)

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

def _extract_system_version(system_nca_object, mkeksource):
    """Extract firmware version from system update NCA object."""

    system_nca_object = system_nca_object

    cal_file_object = nca.SectionExtractor.extract_section_romfs_system_update_calibration_only(system_nca_object, 0)
    cal_digest_object = nca.SectionExtractor.extract_section_romfs_system_update_calibration_only(system_nca_object, 1)
    firmware_version = cal_file_object[0x68:0x6E].decode('utf-8').replace(chr(0), "")

    util.mkdirp(f'output/{firmware_version}')

    try:
        util.write_file(f'output/{firmware_version}/{firmware_version}_system_digest', cal_digest_object)
    except:
        pass
    try:
        util.write_file(f'output/{firmware_version}/{firmware_version}_system_update_file', cal_file_object)
    except:
        pass

    # return object for digest, and file
    return firmware_version #, cal_file_object, cal_digest_object

keygen_revisions = [
    (0x00, '1.0.0'), # KeyGenerationOld 0x00
    (0x01, '3.0.0'), # KeyGenerationOld 0x02
    (0x02, '3.0.1'),
    (0x03, '4.0.0'),
    (0x04, '5.0.0'),
    (0x05, '6.0.0'),
    (0x06, '6.2.0'),
    (0x07, '7.0.0'),
    (0x08, '8.1.0'),
    (0x09, '9.0.0'),
    (0x0A, '9.1.0'),
    (0x0B, '12.1.0'),
    (0x0C, '13.0.0'),
    (0x0D, '14.0.0'),
    (0x0E, '15.0.0'),
    (0x0F, '16.0.0'),
    (0x10, '17.0.0'),
    (0x11, '18.0.0'),
    (0x12, '19.0.0'),
    (0x13, '20.0.0'),
    (0x14, '21.0.0'),
    (0x15, '22.0.0'),
]

# ============================================================================
# Program Title ID to NCA mapping for extraction
# ============================================================================



DATA_TITLES = {
    '0100000000000819': 'fat32',
    '010000000000081B': 'exfat',
    '0100000000000803': 'browser',
    '0100000000000809': 'SystemVersion',
}


def _extract_pfs0_and_get_module_id(nca_data, titleId, system_version, title_name, nca_type='Program'):
    if (
        titleId == '010000000000003E'
        and title_name == 'olsc'
        and util.version_to_tuple(system_version) < util.version_to_tuple('6.0.0')
    ):
        print(f"Skipping {title_name} ({titleId}) for firmware {system_version}; title is only present on 6.0.0+")
        return None

    exefs_path = Path(f'output/{system_version}/{system_version}_{title_name}.nso0')
    exefs_data = nca.SectionExtractor.extract_section_pfs0_main_only(nca_data, exefs_path)
    exefs_data
    main_path = exefs_path
    return util.get_module_id(main_path)

def _process_filesystem_packages(master_key_revision, key_sources, fat32_nca_object=None, exfat_nca_object=None):
    """Process fat32 and exfat filesystem packages."""
    master_kek_source = None
    fat32_sdkversion = None
    exfat_sdkversion = None
    fat32_hash = None
    exfat_hash = None
    fat32_kip_objects = None
    exfat_kip_objects = None
    bootloader_version = None
    
    master_key_keygen_list = [revision[0] for revision in keygen_revisions]
    # New key derivation workflow
    if master_key_revision not in master_key_keygen_list or master_key_revision == master_key_keygen_list[-1]:
        root_keys = RootKeys()
        if fat32_nca_object != None:
            fat32_data = fat32_nca_object
            fat32_sdkversion = fat32_data.sdkversion
            erista_package1_data = nca.SectionExtractor.extract_section_romfs_packages_only(fat32_data, 0)
            master_kek_source, device_master_key_source_source, package1_version = extract_packages.erista_process_package_object_with_key_derivation(erista_package1_data)   
            if sha256(root_keys.mariko_bek).hexdigest().upper() == "491A836813E0733A0697B2FA27D0922D3D6325CE3C6BBEA982CF4691FAF6451A":
                mariko_package1_data = nca.SectionExtractor.extract_section_romfs_packages_only(fat32_data, 1)
                mariko_master_kek_source, mariko_master_kek_source_dev = extract_packages.mariko_process_package_object_with_key_derivation(mariko_package1_data)
        if exfat_nca_object != None and master_kek_source:
            exfat_data = exfat_nca_object
            exfat_sdkversion = exfat_data.sdkversion
        if master_kek_source and master_kek_source not in key_sources.master_kek_sources:
            print("A new master_kek_source was detected, add it to key_sources.py")
            tsec_root_key_02, tsec_root_key_02_dev = crypto.tsec_keygen()
            keygen = crypto.Keygen(tsec_root_key_02)
            keygen_dev = crypto.KeygenDev(tsec_root_key_02_dev)
            master_key_00_dev = keygen_dev.master_key[0]
            previous_master_key_dev = keygen_dev.master_key[-1]
            master_key_00 = keygen.master_key[0]
            previous_master_key = keygen.master_key[-1]
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
            DevelopmentMasterKeyVector = crypto.encrypt_ecb(previous_master_key_dev, master_key_dev)
            ProductionMasterKeyVector = crypto.encrypt_ecb(previous_master_key, master_key)
            DeviceMasterKek = crypto.decrypt_ecb(key_sources.DeviceMasterKekSource, master_kek)
            DeviceMasterKekSourceSource = crypto.encrypt_ecb(DeviceMasterKek, master_key_00)
            DeviceMasterKek_dev = crypto.decrypt_ecb(key_sources.DeviceMasterKekSource, master_kek_dev)
            DeviceMasterKekSourceSource_dev = crypto.encrypt_ecb(DeviceMasterKek_dev, master_key_00_dev)

            # the input of this and output is console unique:
            # device_master_key_source_kek_source = key_sources.device_master_key_source_kek_source
            # KeyblobKeySource = key_sources.KeyblobKeySource
            # work_buffer = crypto.decrypt_ecb(KeyblobKeySource, tsec_key)
            # AesKeySlot_Device = crypto.decrypt_ecb(work_buffer, secure_boot_key)
            # DeviceMasterKeySourceKekErista = crypto.decrypt_ecb(device_master_key_source_kek_source, AesKeySlot_Device)
            # DeviceMasterKek = crypto.decrypt_ecb(DeviceMasterKekSourceSource, master_key_00)
            # device_master_key_source = crypto.decrypt_ecb(device_master_key_source_source, DeviceMasterKeySourceKekErista)


            print(f'Additionally add these to key_sources.py:')
            print(f'device_master_key_source_sources:')
            print(f'bytes([{format_bytes_as_hex(device_master_key_source_source)}]),')
            print(f'device_master_kek_sources:')
            print(f'bytes([{format_bytes_as_hex(DeviceMasterKekSourceSource)}]),')

            print(f'master_key_vectors:')
            print(f'bytes([{format_bytes_as_hex(ProductionMasterKeyVector)}]),')

            print(f'master_kek_sources:')
            print(f'bytes([{format_bytes_as_hex(master_kek_source)}]),')


            if sha256(root_keys.mariko_bek).hexdigest().upper() == "491A836813E0733A0697B2FA27D0922D3D6325CE3C6BBEA982CF4691FAF6451A":
                print(f'mariko_master_kek_sources:')
                print(f'bytes([{format_bytes_as_hex(mariko_master_kek_source)}]),')
            else:
                print("No mariko_bek, or incorrect mariko_bek in keys.py")

            print(f'master_key_vectors_dev:')
            print(f'bytes([{format_bytes_as_hex(DevelopmentMasterKeyVector)}]),')

            #print(f"atmosphere specific keys:\n")
            # the following is intended to be writing to a file:
            print(f'\n\nIn "exosphere/program/source/boot/secmon_boot_key_data.s":\n')

            print(f'Replace the key under "/* Mariko Development Master Kek Source. */", with:')
            print(f'.byte {format_bytes_as_hex(mariko_master_kek_source_dev)}')

            print(f'Replace the key under "/* Mariko Production Master Kek Source. */", with:')
            print(f'.byte {format_bytes_as_hex(mariko_master_kek_source)}')

            print(f'Under "/* Development Master Key Vectors. */", add the following at the end:')
            print(f'.byte {format_bytes_as_hex(DevelopmentMasterKeyVector)} /* Master Key {master_key_keygen_list[-2]:02X} encrypted with Master Key {master_key_revision:02X}. */')

            print(f'Under "/* Production Master Key Vectors. */", add the following at the end:')
            print(f'.byte {format_bytes_as_hex(ProductionMasterKeyVector)} /* Master Key {master_key_keygen_list[-2]:02X} encrypted with Master Key {master_key_revision:02X}. */')

            print(f'Under "/* Device Master Key Source Sources. */", add the following at the end:')
            print(f'.byte {format_bytes_as_hex(device_master_key_source_source)} /* XX.XX.XX Device Master Key Source Source. */')

            print(f'Under "/* Development Device Master Kek Sources. */", add the following at the end:')
            print(f'.byte {format_bytes_as_hex(DeviceMasterKekSourceSource_dev)} /* XX.XX.XX Device Master Kek Source. */')

            print(f'Under "/* Production Device Master Kek Sources. */", add the following at the end:')
            print(f'.byte {format_bytes_as_hex(DeviceMasterKekSourceSource)} /* XX.XX.XX Device Master Kek Source. *\n')
            print(f'That concludes what needs to be added to "exosphere/program/source/boot/secmon_boot_key_data.s"\n')

            print(f'in "fusee/program/source/fusee_key_derivation.cpp":\n')
            print(f'Replace "MarikoMasterKekSource" with:')
            print(f'{format_bytes_as_hex(mariko_master_kek_source)}')
            print(f'Replace "MarikoMasterKekSourceDev" with:')
            print(f'{format_bytes_as_hex(mariko_master_kek_source_dev)}')
            print(f'Replace "EristaMasterKekSource" with:')
            print(f'{format_bytes_as_hex(master_kek_source)}')

            print(f'Under "DeviceMasterKeySourceSources", add the following at the end:')
            print(f'{{ {format_bytes_as_hex(device_master_key_source_source)} }}, /* XX.XX.XX Device Master Key Source Source. */')
            
            print(f'Under "DeviceMasterKekSources", add the following at the end:')
            print(f'{{ {format_bytes_as_hex(DeviceMasterKekSourceSource)} }}, /* XX.XX.XX Device Master Kek Source. */')

            print(f'Under "DeviceMasterKekSourcesDev", add the following at the end:')
            print(f'{{ {format_bytes_as_hex(DeviceMasterKekSourceSource_dev)} }}, /* XX.XX.XX Device Master Kek Source. */')

            print(f'Under "MasterKeySources", add the following at the end:')
            print(f'{{ {format_bytes_as_hex(ProductionMasterKeyVector)} }}, /* Master Key {master_key_keygen_list[-2]:02X} encrypted with Master Key {master_key_revision:02X}. */')

            print(f'Under "MasterKeySourcesDev", add the following at the end:')
            print(f'{{ {format_bytes_as_hex(DevelopmentMasterKeyVector)} }}, /* Master Key {master_key_keygen_list[-2]:02X} encrypted with Master Key {master_key_revision:02X}. */\n')

            print(f'That concludes what needs to be added to "fusee/program/source/fusee_key_derivation.cpp"\n')

            print(f'In "exosphere/program/source/boot/secmon_package2.cpp":\n')
            print(f'at line 97; replace the line with this:')
            print(f'static_assert(pkg1::KeyGeneration_Count == {master_key_revision + 1});\n')
            print(f'That concludes what needs to be added to "exosphere/program/source/boot/secmon_package2.cpp"\n')
            
            print(f'in "fusee/program/source/fusee_setup_horizon.cpp":\n')
            print(f'add the following two lines:')
            print(f' }} else if (std::memcmp(package1 + 0x10, "{package1_version}", 8) == 0) {{')
            print(f'return ams::TargetFirmware_XX_XX_XX;\n')
            print(f'That concludes what needs to be added to "fusee/program/source/fusee_setup_horizon.cpp"\n')

            print(f'this file only needs +1 keygeneration')
            print(f'libraries/libexosphere/include/exosphere/pkg1/pkg1_key_generation.hpp\n')

            print(f'this "needs" package2 bootloader version (the regular process_firmware.py with new sources added to key_sources.py and keygen revision added to keygen_revisions will output that)')
            print(f'libraries/libexosphere/include/exosphere/pkg2.hpp\n')

            print(f'this needs just new TargetFirmware_XX_XX_XX')
            print(f'libraries/libexosphere/source/fuse/fuse_api.cpp\n')

            print(f'this also just need new TargetFirmware_XX_XX_XX')
            print(f'libraries/libstratosphere/include/stratosphere/hos/hos_types.hpp\n')

            print(f'this needs to reference the pkg1 keygeneration for the new version, and define the range of firmware versions')
            print(f'libraries/libstratosphere/source/fs/impl/fs_id_string_impl.os.generic.cpp\n')

            print(f'this needs to change the atmosphere version, and supported firmware version')
            print(f'libraries/libvapours/include/vapours/ams/ams_api_version.h\n')

            print(f'this is updated with the target')
            print(f'libraries/libvapours/include/vapours/ams/ams_target_firmware.h\n')

            print(f"don't forget to replace XX.XX.XX and XX_XX_XX with ex 21_00_00, 22_00_00, and so on \n\n")

            # refer to https://github.com/Atmosphere-NX/Atmosphere/commit/18bb1fdea00781dac30a051aad6ae1d80ad67137 as to what values should go where
            # emummc/keyless update https://github.com/Atmosphere-NX/Atmosphere/commit/1e88f37892555da4c38ca6c95f43c56cc6bb87e6
            # some values are made with scripts/find_patterns.py
            _keygen_state = {
                'master_kek_source': list(master_kek_source),
                'mariko_master_kek_source': list(mariko_master_kek_source) if mariko_master_kek_source else None,
                'mariko_master_kek_source_dev': list(mariko_master_kek_source_dev) if mariko_master_kek_source_dev else None,
                'DevelopmentMasterKeyVector': list(DevelopmentMasterKeyVector),
                'ProductionMasterKeyVector': list(ProductionMasterKeyVector),
                'device_master_key_source_source': list(device_master_key_source_source),
                'DeviceMasterKekSourceSource': list(DeviceMasterKekSourceSource),
                'DeviceMasterKekSourceSource_dev': list(DeviceMasterKekSourceSource_dev),
                'package1_version': package1_version,
                'master_key_revision': master_key_revision,
                'master_key_keygen_list': master_key_keygen_list,
            }
            os.makedirs('output', exist_ok=True)
            _keygen_json_path = f'output/keygen_state_{master_key_revision:02X}.json'
            with open(_keygen_json_path, 'w') as _f:
                json.dump(_keygen_state, _f, indent=2)
            print(f"Keygen state saved to {_keygen_json_path} — re-run after updating key_sources.py and keygen_revisions to generate atmosphere patch")
            sys.exit(1)
        else:
            if not master_kek_source or master_key_revision not in master_key_keygen_list:
                print(f"Update keygen_revisions (in this file) to include the new firmware revision, example if latest entry is 0x14, add 0x15, then re-run process_firwmare.py")
                print(f'also in exosphere/program/source/boot/secmon_package2.cpp')
                print(f'and in fusee/program/source/fusee_package2.cpp')
                print(f'and libraries/libexosphere/include/exosphere/pkg1/pkg1_key_generation.hpp')
                sys.exit(1)
            # Key is known AND revision is in keygen_revisions — fall through to existing-key workflow
            key_index = master_key_revision
            master_kek_source = key_sources.master_kek_sources[key_index - 0x8]
            if fat32_nca_object != None:
                fat32_data = fat32_nca_object
                fat32_sdkversion = fat32_data.sdkversion
                fat32_package2_data = nca.SectionExtractor.extract_section_romfs_packages_only(fat32_data, 2)
                fat32_kip_hashes, bootloader_version, fat32_kip_objects = extract_packages.process_filesystem_package_object(fat32_package2_data, "fat32")
                fat32_hash = fat32_kip_hashes[0]
            if exfat_nca_object != None:
                exfat_data = exfat_nca_object
                exfat_sdkversion = exfat_data.sdkversion
                exfat_package2_data = nca.SectionExtractor.extract_section_romfs_packages_only(exfat_data, 2)
                exfat_kip_hashes, bootloader_version, exfat_kip_objects = extract_packages.process_filesystem_package_object(exfat_package2_data, "exfat")
                exfat_hash = exfat_kip_hashes[3]

    # Existing key workflow
    else:
        key_index = master_key_revision
        master_kek_source = key_sources.master_kek_sources[key_index - 0x8]

        if fat32_nca_object != None:
            fat32_data = fat32_nca_object
            fat32_sdkversion = fat32_data.sdkversion
            fat32_package2_data = nca.SectionExtractor.extract_section_romfs_packages_only(fat32_data, 2)
            fat32_kip_hashes, bootloader_version, fat32_kip_objects = extract_packages.process_filesystem_package_object(fat32_package2_data, "fat32")
            fat32_hash = fat32_kip_hashes[0]

        if exfat_nca_object != None:
            exfat_data = exfat_nca_object
            exfat_sdkversion = exfat_data.sdkversion
            exfat_package2_data = nca.SectionExtractor.extract_section_romfs_packages_only(exfat_data, 2)
            exfat_kip_hashes, bootloader_version, exfat_kip_objects = extract_packages.process_filesystem_package_object(exfat_package2_data, "exfat")
            exfat_hash = exfat_kip_hashes[3]

    return master_kek_source, fat32_sdkversion, exfat_sdkversion, bootloader_version, fat32_hash, exfat_hash, fat32_kip_objects, exfat_kip_objects

def _write_kip1_files(fat32_kip_objects, exfat_kip_objects, system_version):
    """Write KIP1 filesystem files to output directory."""

    if fat32_kip_objects != None:
        for i, x in fat32_kip_objects:
            if i == "fat32_FS":
                fat32_kip1_path = f'output/{system_version}/{system_version}_fat32_FS.kip1'
                util.write_file(fat32_kip1_path, x)
            else:
                continue

    if exfat_kip_objects != None:
        for i, x in exfat_kip_objects:
            if i == "exfat_FS":
                exfat_kip1_path = f'output/{system_version}/{system_version}_exfat_FS.kip1'
                util.write_file(exfat_kip1_path, x)
            else:
                continue

def _write_hash_files(system_version, fat32_hash=None, exfat_hash=None):
    if fat32_hash != None:
        hash_file_path = f'output/{system_version}/{system_version}_fat32.hash'
        with open(hash_file_path, 'w') as f:
                f.write(fat32_hash)
                f.close()

    if exfat_hash != None:
        hash_file_path = f'output/{system_version}/{system_version}_exfat.hash'
        with open(hash_file_path, 'w') as f:
            f.write(exfat_hash)
            f.close()

def _write_hashes_file(system_version, module_ids, bootloader_version, fat32_hash=None, exfat_hash=None):
    """Write module IDs and filesystem hashes to output file."""
    hash_file_path = f'output/{system_version}/{system_version}_hashes.txt'

    version_with_underscores = system_version.replace(".", "_")
    version_no_dot = system_version.replace(".", "")
    
    with open(hash_file_path, 'w') as f:
        if fat32_hash != None:
            f.write(f'{system_version} fat32 sha256 = {fat32_hash} */\n')
            f.write(f'{to_c_hex_array_16(fat32_hash)}, /* FsVersion_{version_with_underscores}\n')
            f.write(f'^ add to fusee/program/source/fusee_stratosphere.cpp\n')
        else:
            f.write(f'{system_version} No fat32 present in this firmware version\n')
        
        if exfat_hash != None:
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
        fat32_h_out  = f'output/{system_version}/{version_no_dot}.h'
        exfat_h_out  = f'output/{system_version}/{version_no_dot}_exfat.h'
        atm_fat32_h  = f'atmosphere/emummc/source/FS/offsets/{version_no_dot}.h'
        atm_exfat_h  = f'atmosphere/emummc/source/FS/offsets/{version_no_dot}_exfat.h'
        h_fat32  = fat32_h_out  if os.path.isfile(fat32_h_out)  else atm_fat32_h
        h_exfat  = exfat_h_out  if os.path.isfile(exfat_h_out)  else atm_exfat_h
        f.write(f'creation of the two emummc.h files:\n')
        f.write(f'{h_fat32}\n')
        f.write(f'{h_exfat}\n\n')
        # Write module IDs
        for title_name, title_id in module_ids.items():
            f.write(f'{system_version} {title_name}_moduleid: {title_id}\n')


def _write_atmosphere_keygen_patch(
    system_version,
    master_kek_source,
    mariko_master_kek_source,
    mariko_master_kek_source_dev,
    DevelopmentMasterKeyVector,
    ProductionMasterKeyVector,
    device_master_key_source_source,
    DeviceMasterKekSourceSource,
    DeviceMasterKekSourceSource_dev,
    package1_version,
    master_key_revision,
    master_key_keygen_list,
):
    atm_dir = './atmosphere'
    if not os.path.isdir(atm_dir):
        print("[WARN] ./atmosphere not found — skipping keygen patch generation")
        return
    if not os.listdir(atm_dir):
        print("[WARN] ./atmosphere is empty — skipping keygen patch generation")
        return

    ver_under = system_version.replace('.', '_')
    prev_key_hex = f'{master_key_keygen_list[-2]:02X}'
    curr_key_hex = f'{master_key_revision:02X}'

    def read_lines(rel_path):
        with open(os.path.join(atm_dir, rel_path), newline='') as f:
            content = f.read()
        return content.replace('\r\n', '\n').replace('\r', '\n').splitlines(keepends=True)

    def make_diff(rel_path, orig, modified):
        diff = list(difflib.unified_diff(orig, modified,
                    fromfile=f'a/{rel_path}', tofile=f'b/{rel_path}', lineterm='\n'))
        return ''.join(diff) if diff else ''

    def fmt_asm(data):
        return '.byte ' + ', '.join(f'0x{b:02X}' for b in data)

    def fmt_hex(data):
        return ', '.join(f'0x{b:02X}' for b in data)

    def fmt_cpp(data):
        return '{ ' + fmt_hex(data) + ' }'

    diffs = []

    # ── exosphere/program/source/boot/secmon_boot_key_data.s ───────────────
    rel = 'exosphere/program/source/boot/secmon_boot_key_data.s'
    lines = read_lines(rel)
    modified = list(lines)

    section = None
    positions = {}
    for i, line in enumerate(modified):
        stripped = line.strip()
        if '/* Mariko Development Master Kek Source. */' in stripped:
            section = 'mariko_dev'
        elif '/* Mariko Production Master Kek Source. */' in stripped:
            section = 'mariko_prod'
        elif '/* Development Master Key Vectors. */' in stripped:
            section = 'dev_vec'
        elif '/* Production Master Key Vectors. */' in stripped:
            section = 'prod_vec'
        elif '/* Device Master Key Source Sources. */' in stripped:
            section = 'dmkss'
        elif '/* Development Device Master Kek Sources. */' in stripped:
            section = 'dev_kek'
        elif '/* Production Device Master Kek Sources. */' in stripped:
            section = 'prod_kek'
        if section and stripped.startswith('.byte'):
            positions[section] = i

    mods = []
    if mariko_master_kek_source_dev and 'mariko_dev' in positions:
        mods.append(('replace', positions['mariko_dev'], fmt_asm(mariko_master_kek_source_dev) + '\n'))
    if mariko_master_kek_source and 'mariko_prod' in positions:
        mods.append(('replace', positions['mariko_prod'], fmt_asm(mariko_master_kek_source) + '\n'))
    if 'prod_kek' in positions:
        mods.append(('insert_after', positions['prod_kek'],
            f'{fmt_asm(DeviceMasterKekSourceSource)} /* {system_version} Device Master Kek Source. */\n'))
    if 'dev_kek' in positions:
        mods.append(('insert_after', positions['dev_kek'],
            f'{fmt_asm(DeviceMasterKekSourceSource_dev)} /* {system_version} Device Master Kek Source. */\n'))
    if 'dmkss' in positions:
        mods.append(('insert_after', positions['dmkss'],
            f'{fmt_asm(device_master_key_source_source)} /* {system_version} Device Master Key Source Source. */\n'))
    if 'prod_vec' in positions:
        mods.append(('insert_after', positions['prod_vec'],
            f'{fmt_asm(ProductionMasterKeyVector)} /* Master Key {prev_key_hex} encrypted with Master Key {curr_key_hex}. */\n'))
    if 'dev_vec' in positions:
        mods.append(('insert_after', positions['dev_vec'],
            f'{fmt_asm(DevelopmentMasterKeyVector)} /* Master Key {prev_key_hex} encrypted with Master Key {curr_key_hex}. */\n'))

    for op, idx, content in sorted(mods, key=lambda x: x[1], reverse=True):
        if op == 'replace':
            modified[idx] = content
        else:
            modified.insert(idx + 1, content)

    diffs.append(make_diff(rel, lines, modified))

    # ── fusee/program/source/fusee_key_derivation.cpp ──────────────────────
    rel = 'fusee/program/source/fusee_key_derivation.cpp'
    lines = read_lines(rel)
    modified = list(lines)

    all_mods = []
    for marker, data in [
        ('MarikoMasterKekSource[se::AesBlockSize]', mariko_master_kek_source),
        ('MarikoMasterKekSourceDev[se::AesBlockSize]', mariko_master_kek_source_dev),
        ('EristaMasterKekSource[se::AesBlockSize]', master_kek_source),
    ]:
        if not data:
            continue
        in_array = False
        for i, line in enumerate(modified):
            if marker in line and '= {' in line:
                in_array = True
                continue
            if in_array:
                s = line.strip()
                if s and not s.startswith('/*') and not s.startswith('}') and '0x' in s:
                    all_mods.append(('replace', i, f'            {fmt_hex(data)}\n'))
                    break
                if s == '};':
                    break

    for marker, data, comment in [
        ('DeviceMasterKeySourceSources[pkg1::OldDeviceMasterKeyCount]', device_master_key_source_source,
            f'{system_version} Device Master Key Source Source.'),
        ('DeviceMasterKekSources[pkg1::OldDeviceMasterKeyCount]', DeviceMasterKekSourceSource,
            f'{system_version} Device Master Kek Source.'),
        ('DeviceMasterKekSourcesDev[pkg1::OldDeviceMasterKeyCount]', DeviceMasterKekSourceSource_dev,
            f'{system_version} Device Master Kek Source.'),
        ('MasterKeySources[pkg1::KeyGeneration_Count]', ProductionMasterKeyVector,
            f'Master Key {prev_key_hex} encrypted with Master Key {curr_key_hex}.'),
        ('MasterKeySourcesDev[pkg1::KeyGeneration_Count]', DevelopmentMasterKeyVector,
            f'Master Key {prev_key_hex} encrypted with Master Key {curr_key_hex}.'),
    ]:
        in_array = False
        for i, line in enumerate(modified):
            if marker in line and '= {' in line:
                in_array = True
                continue
            if in_array and line.strip() == '};':
                all_mods.append(('insert_before', i, f'            {fmt_cpp(data)}, /* {comment} */\n'))
                break

    for op, idx, content in sorted(all_mods, key=lambda x: x[1], reverse=True):
        if op == 'replace':
            modified[idx] = content
        elif op == 'insert_before':
            modified.insert(idx, content)

    diffs.append(make_diff(rel, lines, modified))

    # ── exosphere/program/source/boot/secmon_package2.cpp ──────────────────
    rel = 'exosphere/program/source/boot/secmon_package2.cpp'
    lines = read_lines(rel)
    modified = list(lines)
    for i, line in enumerate(modified):
        if 'static_assert(pkg1::KeyGeneration_Count ==' in line:
            modified[i] = f'        static_assert(pkg1::KeyGeneration_Count == {master_key_revision + 1});\n'
            break
    diffs.append(make_diff(rel, lines, modified))

    # ── fusee/program/source/fusee_setup_horizon.cpp ───────────────────────
    rel = 'fusee/program/source/fusee_setup_horizon.cpp'
    lines = read_lines(rel)
    modified = list(lines)
    last_break = -1
    for i, line in enumerate(modified):
        if (line.strip() == 'break;' and
                i > 0 and modified[i - 1].strip() == '}' and
                modified[i - 1].startswith('                    ')):
            last_break = i
    if last_break >= 0:
        modified[last_break - 1:last_break - 1] = [
            f'                    }} else if (std::memcmp(package1 + 0x10, "{package1_version}", 8) == 0) {{\n',
            f'                        return ams::TargetFirmware_{ver_under};\n',
        ]
    diffs.append(make_diff(rel, lines, modified))

    # ── libraries/libexosphere/include/exosphere/pkg1/pkg1_key_generation.hpp
    rel = 'libraries/libexosphere/include/exosphere/pkg1/pkg1_key_generation.hpp'
    lines = read_lines(rel)
    modified = list(lines)
    if f'KeyGeneration_{ver_under}' not in ''.join(lines):
        for i, line in enumerate(modified):
            if 'KeyGeneration_Count,' in line:
                insert_pos = i - 1 if i > 0 and modified[i - 1].strip() == '' else i
                modified.insert(insert_pos, f'        KeyGeneration_{ver_under} = 0x{master_key_revision:02X},\n')
                break
    diffs.append(make_diff(rel, lines, modified))

    # ── write patch ─────────────────────────────────────────────────────────
    patch_content = ''.join(d for d in diffs if d)
    if not patch_content:
        print("No keygen changes needed — atmosphere files already up to date.")
        return

    patch_path = f'output/{system_version}/{system_version}_atmosphere_keygen.patch'
    with open(patch_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(patch_content)
    print(f"Atmosphere keygen patch written to {patch_path}")
    print(f"Apply with: cd atmosphere && git apply ../{patch_path}")


def _write_atmosphere_patch(system_version, fat32_hash=None, exfat_hash=None):
    atm_dir = './atmosphere'
    if not os.path.isdir(atm_dir):
        print("[WARN] ./atmosphere not found — skipping patch generation")
        return
    if not os.listdir(atm_dir):
        print("[WARN] ./atmosphere is empty — skipping patch generation")
        return

    parts = system_version.split('.')
    major, minor, micro = int(parts[0]), int(parts[1]), int(parts[2])
    ver_under = system_version.replace('.', '_')
    ver_nodot  = system_version.replace('.', '')

    def read_lines(rel_path):
        with open(os.path.join(atm_dir, rel_path), newline='') as f:
            content = f.read()
        normalized = content.replace('\r\n', '\n').replace('\r', '\n')
        return normalized.splitlines(keepends=True)

    def make_diff(rel_path, orig, modified):
        diff = list(difflib.unified_diff(orig, modified,
                    fromfile=f'a/{rel_path}', tofile=f'b/{rel_path}', lineterm='\n'))
        return ''.join(diff) if diff else ''

    diffs = []

    # --- fusee/program/source/fusee_stratosphere.cpp ---
    rel = 'fusee/program/source/fusee_stratosphere.cpp'
    lines = read_lines(rel)
    modified = list(lines)
    if f'FsVersion_{ver_under},' not in ''.join(lines):
        # FsVersion enum: insert pair before FsVersion_Count, with blank line below
        for i, line in enumerate(modified):
            if 'FsVersion_Count,' in line:
                modified[i:i] = [
                    f'            FsVersion_{ver_under},\n',
                    f'            FsVersion_{ver_under}_Exfat,\n',
                    '\n',
                ]
                break

        # FsHashes array: find last line with /* FsVersion_ then the }; that closes the array
        last_hash_line = -1
        for i, line in enumerate(modified):
            if '/* FsVersion_' in line and '{' in line:
                last_hash_line = i
        if last_hash_line >= 0:
            for i in range(last_hash_line + 1, len(modified)):
                if modified[i].strip() == '};':
                    ins = ['\n']
                    if fat32_hash is not None:
                        ins.append(f'            {to_c_hex_array_16(fat32_hash)}, /* FsVersion_{ver_under} */\n')
                    if exfat_hash is not None:
                        ins.append(f'            {to_c_hex_array_16(exfat_hash)}, /* FsVersion_{ver_under}_Exfat */\n')
                    modified[i:i] = ins
                    break

        # NoGcPatch switch: add stub cases before the default: that follows FsVersion_ cases
        last_fs_case = -1
        for i, line in enumerate(modified):
            if 'case FsVersion_' in line:
                last_fs_case = i
        if last_fs_case >= 0:
            for i in range(last_fs_case + 1, len(modified)):
                if modified[i].strip() == 'default:':
                    modified[i:i] = [
                        f'                case FsVersion_{ver_under}:\n',
                        f'                    break;\n',
                        f'                case FsVersion_{ver_under}_Exfat:\n',
                        f'                    break;\n',
                    ]
                    break

    diffs.append(make_diff(rel, lines, modified))

    # --- emummc/source/FS/FS_versions.h ---
    rel = 'emummc/source/FS/FS_versions.h'
    lines = read_lines(rel)
    modified = list(lines)
    if f'FS_VER_{ver_under.upper()},' not in ''.join(lines):
        for i, line in enumerate(modified):
            if 'FS_VER_MAX,' in line:
                modified[i:i] = [
                    f'    FS_VER_{ver_under.upper()},\n',
                    f'    FS_VER_{ver_under.upper()}_EXFAT,\n',
                    '\n',
                ]
                break
    diffs.append(make_diff(rel, lines, modified))

    # --- emummc/source/FS/FS_offsets.c ---
    rel = 'emummc/source/FS/FS_offsets.c'
    lines = read_lines(rel)
    modified = list(lines)
    if f'"offsets/{ver_nodot}.h"' not in ''.join(lines):
        # #include block: insert before fatal.h
        for i, line in enumerate(modified):
            if '#include "../utils/fatal.h"' in line:
                modified.insert(i, f'#include "offsets/{ver_nodot}_exfat.h"\n')
                modified.insert(i, f'#include "offsets/{ver_nodot}.h"\n')
                break

        # DEFINE_OFFSET_STRUCT block: insert after the last DEFINE_OFFSET_STRUCT line
        last_define = -1
        for i, line in enumerate(modified):
            if 'DEFINE_OFFSET_STRUCT(' in line:
                last_define = i
        if last_define >= 0:
            modified.insert(last_define + 1, f'DEFINE_OFFSET_STRUCT(_{ver_nodot.upper()}_EXFAT);\n')
            modified.insert(last_define + 1, f'DEFINE_OFFSET_STRUCT(_{ver_nodot.upper()});\n')

        # switch statement: insert two cases before default:
        for i, line in enumerate(modified):
            if line.strip() == 'default:':
                modified[i:i] = [
                    f'        case FS_VER_{ver_under.upper()}:\n',
                    f'            return &(GET_OFFSET_STRUCT_NAME(_{ver_nodot.upper()}));\n',
                    f'        case FS_VER_{ver_under.upper()}_EXFAT:\n',
                    f'            return &(GET_OFFSET_STRUCT_NAME(_{ver_nodot.upper()}_EXFAT));\n',
                ]
                break
    diffs.append(make_diff(rel, lines, modified))

    # --- libraries/libstratosphere/include/stratosphere/hos/hos_types.hpp ---
    rel = 'libraries/libstratosphere/include/stratosphere/hos/hos_types.hpp'
    lines = read_lines(rel)
    modified = list(lines)
    if f'Version_{ver_under}' not in ''.join(lines):
        for i, line in enumerate(modified):
            if 'Version_Current' in line:
                insert_pos = i - 1 if i > 0 and modified[i - 1].strip() == '' else i
                modified.insert(insert_pos, f'        Version_{ver_under}  = ::ams::TargetFirmware_{ver_under},\n')
                break
    diffs.append(make_diff(rel, lines, modified))

    # --- libraries/libvapours/include/vapours/ams/ams_target_firmware.h ---
    rel = 'libraries/libvapours/include/vapours/ams/ams_target_firmware.h'
    lines = read_lines(rel)
    modified = list(lines)
    if f'#define ATMOSPHERE_TARGET_FIRMWARE_{ver_under.upper()} ' not in ''.join(lines):
        # Insert new macro and update CURRENT
        for i, line in enumerate(modified):
            if line.startswith('#define ATMOSPHERE_TARGET_FIRMWARE_CURRENT '):
                # Insert before the blank line that precedes CURRENT so it sits between the new macro and CURRENT
                insert_pos = i - 1 if i > 0 and modified[i - 1].strip() == '' else i
                new_macro = f'#define ATMOSPHERE_TARGET_FIRMWARE_{ver_under.upper()} ATMOSPHERE_TARGET_FIRMWARE({major:2d}, {minor:2d}, {micro:2d})\n'
                modified.insert(insert_pos, new_macro)
                modified[i + 1] = f'#define ATMOSPHERE_TARGET_FIRMWARE_CURRENT ATMOSPHERE_TARGET_FIRMWARE_{ver_under.upper()}\n'
                break

        # Insert TargetFirmware enum entry before TargetFirmware_Current
        for i, line in enumerate(modified):
            if 'TargetFirmware_Current' in line and '=' in line:
                modified.insert(i, f'        TargetFirmware_{ver_under}  = ATMOSPHERE_TARGET_FIRMWARE_{ver_under.upper()},\n')
                break

    diffs.append(make_diff(rel, lines, modified))

    # --- libraries/libvapours/include/vapours/ams/ams_api_version.h ---
    rel = 'libraries/libvapours/include/vapours/ams/ams_api_version.h'
    lines = read_lines(rel)
    modified = list(lines)
    for i, line in enumerate(modified):
        if line.startswith('#define ATMOSPHERE_SUPPORTED_HOS_VERSION_MAJOR'):
            modified[i] = f'#define ATMOSPHERE_SUPPORTED_HOS_VERSION_MAJOR {major}\n'
        elif line.startswith('#define ATMOSPHERE_SUPPORTED_HOS_VERSION_MINOR'):
            modified[i] = f'#define ATMOSPHERE_SUPPORTED_HOS_VERSION_MINOR {minor}\n'
        elif line.startswith('#define ATMOSPHERE_SUPPORTED_HOS_VERSION_MICRO'):
            modified[i] = f'#define ATMOSPHERE_SUPPORTED_HOS_VERSION_MICRO {micro}\n'
    diffs.append(make_diff(rel, lines, modified))

    patch_content = ''.join(diffs)
    if not patch_content.strip():
        print(f"[INFO] No atmosphere changes detected for {system_version} (already present?)")
        return

    patch_path = f'output/{system_version}/{system_version}_atmosphere.patch'
    with open(patch_path, 'w', newline='\n') as f:
        f.write(patch_content)
    print(f"Atmosphere patch written to {patch_path}")
    print(f"Apply with: cd atmosphere && git apply ../{patch_path}")


def _write_firmware_strings(system_version, key_revision, dauth_file_path, dauth_digest_path):
    """Write dAuth firmware strings for firmware update."""
    if util.version_to_tuple(system_version) < util.version_to_tuple("9.0.0"):
        return
    
    firmware_version_no_dot, firmware_revision, firmware_string = util.get_dauth_strings(dauth_file_path)
    digest = util.get_dauth_digest(dauth_digest_path)
    user_agent = util.get_user_agent(f'output/{system_version}/{system_version}_account.nso0')
    dauth_address = util.get_dauth_address(f'output/{system_version}/{system_version}_account.nso0')
    
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

    if util.version_to_tuple(system_version) > util.version_to_tuple("21.0.0"):
        exfat_kip = f'output/{system_version}/{system_version}_exfat_FS.kip1'
        fat32_kip = f'output/{system_version}/{system_version}_fat32_FS.kip1'
        print(f'exfat emummc.h for {system_version}')
        emummc_h.produce_emummc_h(exfat_kip, firmware_version_no_dot, "EXFAT_", version=system_version)
        print('\n\n')
        print(f'fat32 emummc.h for {system_version}')
        emummc_h.produce_emummc_h(fat32_kip, firmware_version_no_dot, "", version=system_version)


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
    nca_files, master_key_revision = sort_nca(firmware_location)
    key_revision = master_key_revision + 1

    for line in nca_files:
        nca_titleId, nca_content_type, nca_path, nca_titleid_type, nca_titleid_name = line
        if nca_titleId == "0100000000000819":  # fat32
            fat32_nca_path = nca_path
            fat32_nca_object = nca.Nca(util.InitializeFile(nca_path), master_kek_source=None)
        if nca_titleId == "010000000000081B":  # exfat
            exfat_nca_path = nca_path
            exfat_nca_object = nca.Nca(util.InitializeFile(nca_path), master_kek_source=None)

    try: 
        if exfat_nca_object:
            master_kek_source, fat32_sdkversion, exfat_sdkversion, bootloader_version, fat32_hash, exfat_hash, fat32_kip_objects, exfat_kip_objects = _process_filesystem_packages(master_key_revision, key_sources, fat32_nca_object, exfat_nca_object)
    except:
        master_kek_source, fat32_sdkversion, exfat_sdkversion, bootloader_version, fat32_hash, exfat_hash, fat32_kip_objects, exfat_kip_objects = _process_filesystem_packages(master_key_revision, key_sources, fat32_nca_object, None)


    PROGRAM_TITLES = {}
    for line in nca_files:
        nca_titleId, nca_content_type, nca_path, nca_titleid_type, nca_titleid_name = line
        if nca_titleId == "0100000000000809":  # system_update
            system_update_nca_path = nca_path
            system_update_nca_object = nca.Nca(util.InitializeFile(nca_path), master_kek_source=None)
        if nca_titleId == "010000000000001E":  # account
            account_nca_path = nca_path
            account_nca_object = nca.Nca(util.InitializeFile(nca_path), master_kek_source=None)
            PROGRAM_TITLES[nca_titleId] = (nca_titleid_name, account_nca_object)
        if nca_titleId == "010000000000001F":  # ns
            ns_nca_path = nca_path
            ns_nca_object = nca.Nca(util.InitializeFile(nca_path), master_kek_source=None)
            PROGRAM_TITLES[nca_titleId] = (nca_titleid_name, ns_nca_object)
        if nca_titleId == "0100000000000023":  # am
            am_nca_path = nca_path
            am_nca_object = nca.Nca(util.InitializeFile(nca_path), master_kek_source=None)
            PROGRAM_TITLES[nca_titleId] = (nca_titleid_name, am_nca_object)
        if nca_titleId == "0100000000000024":  # ssl
            ssl_nca_path = nca_path
            ssl_nca_object = nca.Nca(util.InitializeFile(nca_path), master_kek_source=None)
            PROGRAM_TITLES[nca_titleId] = (nca_titleid_name, ssl_nca_object)
        if nca_titleId == "0100000000000025":  # nim
            nim_nca_path = nca_path
            nim_nca_object = nca.Nca(util.InitializeFile(nca_path), master_kek_source=None)
            PROGRAM_TITLES[nca_titleId] = (nca_titleid_name, nim_nca_object)
        if nca_titleId == "010000000000000F":  # nifm
            nifm_nca_path = nca_path
            nifm_nca_object = nca.Nca(util.InitializeFile(nca_path), master_kek_source=None)
            PROGRAM_TITLES[nca_titleId] = (nca_titleid_name, nifm_nca_object)
        if nca_titleId == "0100000000000033":  # es
            es_nca_path = nca_path
            es_nca_object = nca.Nca(util.InitializeFile(nca_path), master_kek_source=None)
            PROGRAM_TITLES[nca_titleId] = (nca_titleid_name, es_nca_object)
        if nca_titleId == "010000000000003E":  # olsc
            olsc_nca_path = nca_path
            olsc_nca_object = nca.Nca(util.InitializeFile(nca_path), master_kek_source=None)
            PROGRAM_TITLES[nca_titleId] = (nca_titleid_name, olsc_nca_object)
        if nca_titleId == "0100000000000006":  # usb
            usb_nca_path = nca_path
            usb_nca_object = nca.Nca(util.InitializeFile(nca_path), master_kek_source=None)
            PROGRAM_TITLES[nca_titleId] = (nca_titleid_name, usb_nca_object)
        if nca_titleId == "0100000000000803":  # browser
            browser_nca_path = nca_path
            browser_nca_object = nca.Nca(util.InitializeFile(nca_path), master_kek_source=None)

    system_version = _extract_system_version(system_update_nca_object, master_kek_source)
    print(f'\nFirmware version: {system_version}\n')

    for _keygen_path in glob.glob('output/keygen_state_*.json'):
        with open(_keygen_path) as _f:
            _kd = json.load(_f)
        _write_atmosphere_keygen_patch(
            system_version=system_version,
            master_kek_source=bytes(_kd['master_kek_source']),
            mariko_master_kek_source=bytes(_kd['mariko_master_kek_source']) if _kd['mariko_master_kek_source'] else None,
            mariko_master_kek_source_dev=bytes(_kd['mariko_master_kek_source_dev']) if _kd['mariko_master_kek_source_dev'] else None,
            DevelopmentMasterKeyVector=bytes(_kd['DevelopmentMasterKeyVector']),
            ProductionMasterKeyVector=bytes(_kd['ProductionMasterKeyVector']),
            device_master_key_source_source=bytes(_kd['device_master_key_source_source']),
            DeviceMasterKekSourceSource=bytes(_kd['DeviceMasterKekSourceSource']),
            DeviceMasterKekSourceSource_dev=bytes(_kd['DeviceMasterKekSourceSource_dev']),
            package1_version=_kd['package1_version'],
            master_key_revision=_kd['master_key_revision'],
            master_key_keygen_list=_kd['master_key_keygen_list'],
        )
        os.remove(_keygen_path)

    # Extract program NCAs and get module IDs
    module_ids = {}
    for titleId, (name, nca_object_data) in PROGRAM_TITLES.items():
        nca_type = 'Program'
        module_id = _extract_pfs0_and_get_module_id(nca_object_data, titleId, system_version, name, nca_type)
        if module_id:
            module_ids[name] = module_id

    _write_kip1_files(fat32_kip_objects, exfat_kip_objects, system_version)

    # Write hashes and metadata
    _write_hashes_file(system_version, module_ids, bootloader_version, fat32_hash, exfat_hash)
    if util.version_to_tuple(system_version) < util.version_to_tuple('22.0.0'):
        _write_atmosphere_patch(system_version, fat32_hash, exfat_hash)

    _write_hash_files(system_version, fat32_hash, exfat_hash)
    
    dauth_file_path = f'output/{system_version}/{system_version}_system_update_file'
    dauth_digest_path = f'output/{system_version}/{system_version}_system_digest'
    _write_firmware_strings(system_version, key_revision, dauth_file_path, dauth_digest_path)

    # Extract FOSS browser if available (21.0.0+)
    if util.version_to_tuple(system_version) >= util.version_to_tuple("21.0.0"):
        decompressed_browser_object = nca.SectionExtractor.extract_section_romfs_browser_only(browser_nca_object)
        if decompressed_browser_object != None:
            util.write_file(f'output/{system_version}/{system_version}_foss_browser_ssl.nro', decompressed_browser_object)
            browser_module_id = util.get_module_id(f'output/{system_version}/{system_version}_foss_browser_ssl.nro')
            strings_file = f'output/{system_version}/{system_version}_firmware_strings.txt'
            with open(strings_file, 'a') as f:
                f.write(f'{system_version} foss_ssl_browser_moduleid: {browser_module_id}')
    
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
        sdk_versions.append((system_version, fat32_hash[:16], fat32_hash, fat32_sdkversion))
    if exfat_sdkversion:
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
    
    else:
        # Default mode - process single firmware/ folder
        sort_and_process()
