import re
import subprocess
import sys
import argparse
import platform
import os

try:
    from Cryptodome.Cipher import AES
except ModuleNotFoundError:
    try:
        from Crypto.Cipher import AES
    except ModuleNotFoundError:
        print('Please install pycryptodome(ex) first!')
        sys.exit(1)

import key_sources as key_sources
import aes_sample

argParser = argparse.ArgumentParser()
argParser.add_argument("-f", "--firmware", help="firmware folder")
args = argParser.parse_args()
firmware = "%s" % args.firmware

def decrypt(input, key):
    cipher = AES.new(key, AES.MODE_ECB)
    output = cipher.decrypt(input)
    return output

def encrypt(input, key):
    cipher = AES.new(key, AES.MODE_ECB)
    output = cipher.encrypt(input)
    return output

if firmware == "None":
    firmware = "firmware"

if platform.system() == "Windows":
    if subprocess.getstatusoutput("hactoolnet"):
        hactoolnet = "hactoolnet"
        hshell = False
    else:
        hactoolnet = "tools/hactoolnet-windows.exe"
        hshell = False
elif platform.system() == "Linux":
    if subprocess.getstatusoutput("hactoolnet"):
        hactoolnet = "hactoolnet"
        hshell = True
    else:
        hactoolnet = "tools/hactoolnet-linux"
        hshell = True
elif platform.system() == "MacOS":
    if subprocess.getstatusoutput("hactoolnet"):
        hactoolnet = "hactoolnet"
        hshell = True
    else:
        hactoolnet = "tools/hactoolnet-macos"
        hshell = True
else:
    print(f"Unknown Platform: {platform.system()}, proide your own hactoolnet, falling back to backup keygen")
    hactoolnet = False

    
aes_sample.do_keygen()
subprocess.run(f'{hactoolnet} --keyset prod.keys -t switchfs {firmware} --title 0100000000000819 --romfsdir {firmware}/titleid/0100000000000819/romfs/', shell = hshell, stdout = subprocess.DEVNULL)
subprocess.run(f'{hactoolnet} --keyset prod.keys -t pk11 {firmware}/titleid/0100000000000819/romfs/a/package1 --outdir {firmware}/titleid/0100000000000819/romfs/a/pkg1', shell = hshell , stdout = subprocess.DEVNULL)

# extract master_mariko_kek_source, and generate keys / calculate master_kek_source
with open(f'{firmware}/titleid/0100000000000819/romfs/a/pkg1/Decrypted.bin', 'rb') as decrypted_bin:
    secmon_data = decrypted_bin.read()
    result = re.search(b'\x4F\x59\x41\x53\x55\x4D\x49', secmon_data)
    byte_alignment = decrypted_bin.seek(result.end() + 0x22)
    mariko_master_kek_source_dev_key = decrypted_bin.read(0x10)
    byte_alignment = decrypted_bin.seek(result.end() + 0x32)
    mariko_master_kek_source_key = decrypted_bin.read(0x10)
    byte_alignment = decrypted_bin.seek(0x150)
    revision = decrypted_bin.read(0x01).hex().upper()
    incremented_revision = int(revision) - 0x1

    # check if tsec_root_key_02 is still valid
    with open(f'{firmware}/titleid/0100000000000819/romfs/nx/package1', 'rb') as encrypted_bin:
        package1_data = encrypted_bin.read()
        result = re.search(b'\x1D\xE3\x64\x58\xFA\x9E\xC2\x98\xD5\xB4\x57\x74\xB5\x82\xE7\x11', package1_data)
        byte_alignment = encrypted_bin.seek(result.start() + 0x30)
        tsec_auth_hash = encrypted_bin.read(0x10)
        if tsec_auth_hash != key_sources.tsec_auth_signature_02:
            if incremented_revision <= 11:
                print(f'!!tsec_auth_signature has changed, tsec_root_key_02 is outdated!!')
                print(f'tsec_auth_signature_03 = {tsec_auth_hash.hex().upper()}')
                print(f'master_kek_source is incorrectly calculated, master_key_dev will be incorrect')
                print(f'master_key, master_kek generated are correct, as they are derived using mariko_kek and master_mariko_kek_source')
                print(f'')
                encrypted_bin.close()
                # todo: if this for whatever reason is triggered, obtain newest root key
        encrypted_bin.close()

    if mariko_master_kek_source_key in key_sources.mariko_master_kek_sources:
        new_master_kek = decrypt(mariko_master_kek_source_key, key_sources.mariko_kek)
        new_master_key = decrypt(key_sources.Master_Key_Source, new_master_kek)
        new_master_kek_source = encrypt(new_master_kek, key_sources.tsec_root_key_02)
        new_master_kek_dev =  decrypt(new_master_kek_source, key_sources.tsec_root_key_02_dev)
        new_master_key_dev =  decrypt(key_sources.Master_Key_Source, new_master_kek_dev)
        print(f'mariko_master_kek_source_{incremented_revision} = {mariko_master_kek_source_key.hex().upper()}')
        print(f'master_kek_source_{incremented_revision} = ' + new_master_kek_source.hex().upper())
        print(f'master_kek_{incremented_revision} = '  + new_master_kek.hex().upper())
        print(f'master_key_{incremented_revision} = '  + new_master_key.hex().upper())
        print(f'mariko_master_kek_source_dev_{incremented_revision} = {mariko_master_kek_source_dev_key.hex().upper()}')
        print(f'master_kek_dev_{incremented_revision} = '  + new_master_kek_dev.hex().upper())
        print(f'master_key_dev_{incremented_revision} = '  + new_master_key_dev.hex().upper())
        print(f'no new master_key_source_vector')
    else:
        new_master_kek = decrypt(mariko_master_kek_source_key, key_sources.mariko_kek)
        new_master_key = decrypt(key_sources.Master_Key_Source, new_master_kek)
        new_master_kek_source = encrypt(new_master_kek, key_sources.tsec_root_key_02)
        new_master_kek_dev =  decrypt(new_master_kek_source, key_sources.tsec_root_key_02_dev)
        new_master_key_dev =  decrypt(key_sources.Master_Key_Source, new_master_kek_dev)
        previous_mariko_master_kek_source = key_sources.mariko_master_kek_sources[-1]
        previous_master_kek = decrypt(previous_mariko_master_kek_source, key_sources.mariko_kek)
        previous_master_key = decrypt(key_sources.Master_Key_Source, previous_master_kek)
        previous_master_kek_source = encrypt(previous_master_kek, key_sources.tsec_root_key_02)
        previous_master_kek_dev =  decrypt(previous_master_kek_source, key_sources.tsec_root_key_02_dev)
        previous_master_key_dev =  decrypt(key_sources.Master_Key_Source, previous_master_kek_dev)
        new_master_key_source_vector = encrypt(previous_master_key, new_master_key).hex().upper()
        new_master_key_source_vector_dev = encrypt(previous_master_key_dev, new_master_key_dev).hex().upper()
        formatted_mariko_master_kek_source = '0x' + ', 0x'.join(mariko_master_kek_source_key.hex().upper()[i:i+2] for i in range(0, len(mariko_master_kek_source_key.hex().upper()), 2))
        formatted_mariko_master_kek_source_dev = '0x' + ', 0x'.join(mariko_master_kek_source_dev_key.hex().upper()[i:i+2] for i in range(0, len(mariko_master_kek_source_dev_key.hex().upper()), 2))
        formatted_vector = '0x' + ', 0x'.join(new_master_key_source_vector[i:i+2] for i in range(0, len(new_master_key_source_vector), 2))
        formatted_vector_dev = '0x' + ', 0x'.join(new_master_key_source_vector_dev[i:i+2] for i in range(0, len(new_master_key_source_vector_dev), 2))
        formatted_master_kek_source = '0x' + ', 0x'.join(new_master_kek_source.hex().upper()[i:i+2] for i in range(0, len(new_master_kek_source.hex().upper()), 2))
        print(f'mariko_master_kek_source_{incremented_revision} = {mariko_master_kek_source_key.hex().upper()}')
        print(f'master_kek_source_{incremented_revision} = {new_master_kek_source.hex().upper()}')
        print(f'master_kek_{incremented_revision} = ' + new_master_kek.hex().upper())
        print(f'master_key_{incremented_revision} = '  +   new_master_key.hex().upper())
        print()
        print(f'bytes([{formatted_vector}]),') # "MasterKeySources" https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L116-L136
        print(f'^ add this string to Production_Master_Key_Vectors array ^')
        print(f'bytes([{formatted_master_kek_source}]),') # "EristaMasterKekSource" https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L34-L37
        print(f'^ add this string to master_kek_sources array ^')
        print(f'bytes([{formatted_mariko_master_kek_source}]),') # "MarikoMasterKekSource" https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L24-L27
        print(f'^ add this string to mariko_master_kek_sources array ^')
        print()
        print(f'mariko_master_kek_source_dev_{incremented_revision} = {mariko_master_kek_source_dev_key.hex().upper()}')
        print(f'master_kek_dev_{incremented_revision} = ' + new_master_kek_dev.hex().upper())
        print(f'master_key_dev_{incremented_revision} = '  +   new_master_key_dev.hex().upper())
        print()
        print(f'bytes([{formatted_vector_dev}]),')
        print(f'^ add this string to Development_Master_Key_Vectors array ^') # "MasterKeySourcesDev" https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L138-L158
        print(f'bytes([{formatted_mariko_master_kek_source_dev}]),')
        print(f'^ unused, but output for consistency ^') # "MarikoMasterKekSourceDev" https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L29-L32
    decrypted_bin.close()
    os.remove('prod.keys')
