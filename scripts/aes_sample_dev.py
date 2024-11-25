import argparse
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
import key_sources as key_sources

argParser = argparse.ArgumentParser()
argParser.add_argument("-k", "--keys", help="Where you want the keys to be saved")
args = argParser.parse_args()
prod_keys = "%s" % args.keys


if prod_keys == "None":
    keys = "dev.keys"
else: 
    keys = prod_keys

def hash(i):
    h = SHA256.new()
    h.update(i)
    return h.hexdigest()

def decrypt(input, key):
    cipher = AES.new(key, AES.MODE_ECB)
    output = cipher.decrypt(input)
    return output

def encrypt(input, key):
    cipher = AES.new(key, AES.MODE_ECB)
    output = cipher.encrypt(input)
    return output

def generateKek(src, masterKey, kek_seed, key_seed):
    kek = []
    src_kek = []

    kek = decrypt(kek_seed ,masterKey)
    src_kek = decrypt(src ,kek)
    if key_seed is not None:
        return decrypt(key_seed ,src_kek)
    else:
        return src_kek

HAVE_SECRET_26 = False 
tsec_root_key_02_Dev = key_sources.tsec_root_key_02_dev

if key_sources.tsec_secret_26 != key_sources.zeroes:
    if hash(key_sources.tsec_secret_26) == "cefe01c9e3eeef1a73b8c10d742ae386279b7dff30a2fbc0aabd058c1f135833":
        HAVE_SECRET_26 = True
        HOVI_KEK = key_sources.tsec_secret_26
        Tsec_Hovi_IV_key = key_sources.HOVI_ENC_KEY_IV1
        Package1_Mac_Kek_Source_Dev = key_sources.HOVI_SIG_KEY_DEV
        Package1_Kek_Source_Dev = key_sources.HOVI_ENC_KEY_DEV
        Tsec_Root_Kek_Source_Dev = key_sources.HOVI_KEK_KEY_DEV

        tsec_root_kek_00_Dev = encrypt(Tsec_Root_Kek_Source_Dev, HOVI_KEK)
        tsec_root_kek_01_Dev = tsec_root_kek_00_Dev 
        tsec_root_kek_02_Dev = decrypt(Tsec_Root_Kek_Source_Dev, HOVI_KEK)
        package1_kek_00_Dev = encrypt(Package1_Kek_Source_Dev, HOVI_KEK)
        package1_kek_01_Dev = package1_kek_00_Dev
        package1_kek_02_Dev = decrypt(Package1_Kek_Source_Dev, HOVI_KEK)
        package1_mac_kek_00_Dev = encrypt(Package1_Mac_Kek_Source_Dev, HOVI_KEK)
        package1_mac_kek_01_Dev = package1_mac_kek_00_Dev
        package1_mac_kek_02_Dev = decrypt(Package1_Mac_Kek_Source_Dev, HOVI_KEK)

        tsec_root_key_00_Dev = encrypt(key_sources.tsec_auth_signature_00, tsec_root_kek_00_Dev)
        tsec_root_key_01_Dev = encrypt(key_sources.tsec_auth_signature_01, tsec_root_kek_01_Dev)
        tsec_root_key_02_Dev = encrypt(key_sources.tsec_auth_signature_02, tsec_root_kek_02_Dev)
        package1_key_06_Dev = encrypt(key_sources.tsec_auth_signature_00, package1_kek_00_Dev)
        package1_key_07_Dev = encrypt(key_sources.tsec_auth_signature_01, package1_kek_01_Dev)
        package1_key_08_Dev = encrypt(key_sources.tsec_auth_signature_02, package1_kek_02_Dev)
        package1_mac_key_06_Dev = encrypt(key_sources.tsec_auth_signature_00, package1_mac_kek_00_Dev)
        package1_mac_key_07_Dev = encrypt(key_sources.tsec_auth_signature_01, package1_mac_kek_01_Dev)
        package1_mac_key_08_Dev = encrypt(key_sources.tsec_auth_signature_02, package1_mac_kek_02_Dev)

with open(keys, 'w') as manual_crypto:
    if HAVE_SECRET_26 == True:
        manual_crypto.write(f'tsec_secret_26 = ' + f'{key_sources.tsec_secret_26.hex().upper()}\n\n')
        manual_crypto.write(f'tsec_root_kek_00_dev = ' + f'{tsec_root_kek_00_Dev.hex().upper()}\n')
        manual_crypto.write(f'tsec_root_kek_01_dev = ' + f'{tsec_root_kek_01_Dev.hex().upper()}\n')
        manual_crypto.write(f'tsec_root_kek_02_dev = ' + f'{tsec_root_kek_02_Dev.hex().upper()}\n\n')
        manual_crypto.write(f'package1_mac_kek_00_dev = ' + f'{package1_mac_kek_00_Dev.hex().upper()}\n')
        manual_crypto.write(f'package1_mac_kek_01_dev = ' + f'{package1_mac_kek_01_Dev.hex().upper()}\n')
        manual_crypto.write(f'package1_mac_kek_02_dev = ' + f'{package1_mac_kek_02_Dev.hex().upper()}\n\n')
        manual_crypto.write(f'package1_kek_00_dev = ' + f'{package1_kek_00_Dev.hex().upper()}\n')
        manual_crypto.write(f'package1_kek_01_dev = ' + f'{package1_kek_01_Dev.hex().upper()}\n')
        manual_crypto.write(f'package1_kek_02_dev = ' + f'{package1_kek_02_Dev.hex().upper()}\n\n')
    
    manual_crypto.write(f'tsec_auth_signature_00 = ' + f'{key_sources.tsec_auth_signature_00.hex().upper()}\n')
    manual_crypto.write(f'tsec_auth_signature_01 = ' + f'{key_sources.tsec_auth_signature_00.hex().upper()}\n')
    manual_crypto.write(f'tsec_auth_signature_02 = ' + f'{key_sources.tsec_auth_signature_00.hex().upper()}\n\n')

    if HAVE_SECRET_26 == True:
        manual_crypto.write(f'tsec_root_key_00 = ' + f'{tsec_root_key_00_Dev.hex().upper()}\n')
        manual_crypto.write(f'tsec_root_key_01 = ' + f'{tsec_root_key_01_Dev.hex().upper()}\n')
        manual_crypto.write(f'tsec_root_key_02 = ' + f'{tsec_root_key_02_Dev.hex().upper()}\n\n')
    else:
        manual_crypto.write(f'tsec_root_key_02 = ' + f'{tsec_root_key_02_Dev.hex().upper()}\n\n')

    manual_crypto.write(f'keyblob_mac_key_source = ' + f'{key_sources.keyblob_mac_key_source.hex().upper()}\n')
    # Write keyblob_key_source_%%
    count = -1
    for i in key_sources.Keyblob_Key_Sources:
        count = count + 0x1
        keys = f'keyblob_key_source_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
        manual_crypto.write(f'{keys}\n')

    manual_crypto.write(f'\n')
    # Write master_kek_sources
    count = 0x5
    for i in key_sources.master_kek_sources:
        count = count + 0x1
        keys = f'master_kek_source_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
        manual_crypto.write(f'{keys}\n')

    manual_crypto.write(f'\n')

    # Write mariko_master_kek_sources
    count = 0x4
    for i in key_sources.mariko_master_kek_sources:
        count = count + 0x1
        keys = f'mariko_master_kek_source_dev_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
        manual_crypto.write(f'{keys}\n')

    manual_crypto.write(f'\n')
    # generate master_kek_%% from all provided mariko_master_kek_sources
    master_keks = [decrypt(i, key_sources.tsec_root_key_02_dev) for i in key_sources.master_kek_sources]
    count = 0x5
    for i in master_keks:
        count = count + 0x1
        keys = f'master_kek_dev_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
        manual_crypto.write(f'{keys}\n')
    
    manual_crypto.write(f'\n')
    manual_crypto.write(f'master_key_source = ' + f'{key_sources.master_key_source.hex().upper()}\n\n')

    # generate master_key_%% from all provided master_kek_%% using master_key_source
    current_master_key = decrypt(key_sources.master_key_source, master_keks[-1])

    current_master_key_revision = len(key_sources.Master_Key_Sources_Dev)
    master_keys = []
    first = True
    for i in reversed(key_sources.Master_Key_Sources_Dev):
        if first:
            first = False
            previous_key = i
            next_master_key = decrypt(previous_key, current_master_key)
            current_master_key_revision = current_master_key_revision -1
            master_keys.append(current_master_key)
            master_keys.append(next_master_key)
        else:
            key = previous_key
            previous_key = i
            next_master_key = decrypt(previous_key, next_master_key)
            current_master_key_revision = current_master_key_revision -1
            master_keys.append(next_master_key)

    master_keys.reverse()
    # Write master_key_%%
    count = -0x1
    for i in master_keys:
        count = count + 0x1
        keys = f'master_key_dev_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
        manual_crypto.write(f'{keys}\n')

    if HAVE_SECRET_26 == True:
        manual_crypto.write(f'package1_key_06_dev = ' + f'{package1_key_06_Dev.hex().upper()}\n')
        manual_crypto.write(f'package1_key_07_dev = ' + f'{package1_key_07_Dev.hex().upper()}\n')
        manual_crypto.write(f'package1_key_08_dev = ' + f'{package1_key_08_Dev.hex().upper()}\n\n')
        manual_crypto.write(f'package1_mac_key_06_dev = ' + f'{package1_mac_key_06_Dev.hex().upper()}\n')
        manual_crypto.write(f'package1_mac_key_07_dev = ' + f'{package1_mac_key_07_Dev.hex().upper()}\n')
        manual_crypto.write(f'package1_mac_key_08_dev = ' + f'{package1_mac_key_08_Dev.hex().upper()}\n\n')

    manual_crypto.write(f'\n')
    manual_crypto.write(f'package2_key_source = ' + f'{key_sources.package2_key_source.hex().upper()}\n\n')

    # generate package2_key_%% from all provided master_key_%% using package2_key_source
    package2_key = [decrypt(key_sources.package2_key_source, i) for i in master_keys]
    count = -0x1
    for i in package2_key:
        count = count + 0x1
        keys = f'package2_key_dev_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
        manual_crypto.write(f'{keys}\n')

    manual_crypto.write(f'\n')
    manual_crypto.write(f'bis_kek_source = ' + f'{key_sources.bis_kek_source.hex().upper()}\n')
    # Write bis_key_source_%%
    count = -1
    for i in key_sources.Bis_Key_Sources:
        count = count + 0x1
        keys = f'bis_key_source_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
        manual_crypto.write(f'{keys}\n')

    manual_crypto.write(f'\n')
    manual_crypto.write(f'per_console_key_source = ' + f'{key_sources.per_console_key_source.hex().upper()}\n')
    manual_crypto.write(f'retail_specific_aes_key_source = ' + f'{key_sources.retail_specific_aes_key_source.hex().upper()}\n')
    manual_crypto.write(f'aes_kek_generation_source = ' + f'{key_sources.aes_kek_generation_source.hex().upper()}\n')
    manual_crypto.write(f'aes_key_generation_source = ' + f'{key_sources.aes_key_generation_source.hex().upper()}\n')
    manual_crypto.write(f'titlekek_source = ' + f'{key_sources.titlekek_source.hex().upper()}\n\n')

    # generate title_kek_%% from all provided master_key_%% using titlekek_source
    titlekek = [decrypt(key_sources.titlekek_source, i) for i in master_keys]
    count = -0x1
    for i in titlekek:
        count = count + 0x1
        keys = f'titlekek_dev_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
        manual_crypto.write(f'{keys}\n')

    manual_crypto.write(f'\n')

    manual_crypto.write(f'header_kek_source = ' + f'{key_sources.header_kek_source.hex().upper()}\n')
    manual_crypto.write(f'header_key_source = ' + f'{key_sources.header_key_source.hex().upper()}\n')
    manual_crypto.write(f'header_key = ' + f'{key_sources.header_key.hex().upper()}\n\n')

    manual_crypto.write(f'key_area_key_system_source = ' + f'{key_sources.key_area_key_system_source.hex().upper()}\n')
    manual_crypto.write(f'key_area_key_application_source = ' + f'{key_sources.key_area_key_application_source.hex().upper()}\n')
    manual_crypto.write(f'key_area_key_ocean_source = ' + f'{key_sources.key_area_key_ocean_source.hex().upper()}\n\n')

    manual_crypto.write(f'save_mac_kek_source = ' + f'{key_sources.save_mac_kek_source.hex().upper()}\n')
    manual_crypto.write(f'save_mac_key_source_00 = ' + f'{key_sources.save_mac_key_source_00.hex().upper()}\n')
    manual_crypto.write(f'save_mac_key_source_01 = ' + f'{key_sources.save_mac_key_source_01.hex().upper()}\n')
    manual_crypto.write(f'save_mac_sd_card_kek_source = ' + f'{key_sources.save_mac_sd_card_kek_source.hex().upper()}\n')
    manual_crypto.write(f'save_mac_sd_card_key_source = ' + f'{key_sources.save_mac_sd_card_key_source.hex().upper()}\n')
    manual_crypto.write(f'sd_card_kek_source = ' + f'{key_sources.sd_card_kek_source.hex().upper()}\n\n')


    # generate key_area_key_application_%% from all provided master_key_%% using key_area_key_application_source
    key_area_key_application = [generateKek(key_sources.key_area_key_application_source, i, key_sources.aes_kek_generation_source, key_sources.aes_key_generation_source) for i in master_keys]
    count = -0x1
    for i in key_area_key_application:
        count = count +0x1
        keys = f'key_area_key_application_dev_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
        manual_crypto.write(f'{keys}\n')

    manual_crypto.write(f'\n')

    # generate key_area_key_ocean_%% from all provided master_key_%% using key_area_key_ocean_source
    key_area_key_ocean = [generateKek(key_sources.key_area_key_ocean_source, i, key_sources.aes_kek_generation_source, key_sources.aes_key_generation_source) for i in master_keys]
    count = -0x1
    for i in key_area_key_ocean:
        count = count +0x1
        keys = f'key_area_key_ocean_dev_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
        manual_crypto.write(f'{keys}\n')

    manual_crypto.write(f'\n')

    # generate key_area_key_system_%% from all provided master_key_%% using key_area_key_system_source
    key_area_key_system = [generateKek(key_sources.key_area_key_system_source, i, key_sources.aes_kek_generation_source, key_sources.aes_key_generation_source) for i in master_keys]
    count = -0x1
    for i in key_area_key_system:
        count = count +0x1
        keys = f'key_area_key_system_dev_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
        manual_crypto.write(f'{keys}\n')
