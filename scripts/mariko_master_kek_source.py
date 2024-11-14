import re
import subprocess
import argparse
import platform
import os
import aes128
import key_sources as key_sources
from base64 import b64decode

argParser = argparse.ArgumentParser()
argParser.add_argument("-f", "--firmware", help="firmware folder")
args = argParser.parse_args()
firmware = "%s" % args.firmware

def decrypt(key, decryption_key):
	crypto = aes128.AESECB(decryption_key)
	return crypto.decrypt(key)

def encrypt(key, encryption_key):
	crypto = aes128.AESECB(encryption_key)
	return crypto.encrypt(key)

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

# ^ todo: add latest mariko_master_kek_source from https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L26
with open('temp.keys', 'w') as temp_keys:
    temp_keys.write(f'mariko_kek = {key_sources.mariko_kek.hex().upper()}\n')
    temp_keys.write(f'mariko_bek = {key_sources.mariko_bek.hex().upper()}\n')
    temp_keys.write(f'master_key_source = {key_sources.master_key_source.hex().upper()}\n')

    master_keks = [decrypt(i, key_sources.mariko_kek) for i in key_sources.mariko_master_kek_sources]
    master_keks_dev = [decrypt(i, key_sources.tsec_root_key_02_dev) for i in key_sources.master_kek_sources]

    count = 0x4
    for i in master_keks:
        count = count + 0x1
        keys = f'master_kek_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
        temp_keys.write(f'{keys}\n')

    # generate master_key_%% from all provided master_kek_%% using master_key_source
    current_master_key = decrypt(key_sources.master_key_source, master_keks[-1])

    current_master_key_revision = len(key_sources.Master_Key_Sources)
    master_keys = []
    first = True
    for i in reversed(key_sources.Master_Key_Sources):
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

    # generate master_key_dev_%% from all provided master_kek_dev_%% using master_key_source
    current_master_key_dev = decrypt(key_sources.master_key_source, master_keks_dev[-1])

    current_master_key_revision_dev = len(key_sources.Master_Key_Sources_Dev)
    master_keys_dev = []
    first = True
    for i in reversed(key_sources.Master_Key_Sources_Dev):
        if first:
            first = False
            previous_key_dev = i
            next_master_key_dev = decrypt(previous_key_dev, current_master_key_dev)
            current_master_key_revision_dev = current_master_key_revision_dev -1
            master_keys_dev.append(current_master_key_dev)
            master_keys_dev.append(next_master_key_dev)
        else:
            key = previous_key_dev
            previous_key_dev = i
            next_master_key_dev = decrypt(previous_key_dev, next_master_key_dev)
            current_master_key_revision_dev = current_master_key_revision_dev -1
            master_keys_dev.append(next_master_key_dev)

	# Write master_key_%%
    count = -0x1
    for i in reversed(master_keys):
        count = count + 0x1
        keys = f'master_key_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
        temp_keys.write(f'{keys}\n')

    temp_keys.close()
    subprocess.run(f'{hactoolnet} --keyset temp.keys -t switchfs {firmware} --title 0100000000000819 --romfsdir {firmware}/titleid//0100000000000819/romfs/', shell = hshell, stdout = subprocess.DEVNULL)
    subprocess.run(f'{hactoolnet} --keyset temp.keys -t pk11 {firmware}/titleid//0100000000000819/romfs/a/package1 --outdir {firmware}/titleid/0100000000000819/romfs/a/pkg1', shell = hshell, stdout = subprocess.DEVNULL)
    with open(f'{firmware}/titleid//0100000000000819/romfs/a/pkg1/Decrypted.bin', 'rb') as decrypted_bin:
        secmon_data = decrypted_bin.read()
        result = re.search(b'\x4F\x59\x41\x53\x55\x4D\x49', secmon_data)
        byte_alignment = decrypted_bin.seek(result.end() + 0x22)
        mariko_master_kek_source_dev_key = decrypted_bin.read(0x10)
        byte_alignment = decrypted_bin.seek(result.end() + 0x32)
        mariko_master_kek_source_key = decrypted_bin.read(0x10)
        byte_alignment = decrypted_bin.seek(0x150)
        revision = decrypted_bin.read(0x01).hex().upper()
        incremented_revision = int(revision) - 0x1
        if mariko_master_kek_source_key == key_sources.mariko_master_kek_sources[-1]:
            new_master_kek = decrypt(mariko_master_kek_source_key, key_sources.mariko_kek)
            new_master_kek_source = encrypt(new_master_kek, key_sources.tsec_root_key_02)
            print(f'mariko_master_kek_source_{incremented_revision} = {mariko_master_kek_source_key.hex().upper()}')
            print(f'master_kek_source_{incremented_revision} = ' + new_master_kek_source.hex().upper())
            print(f'master_kek_{incremented_revision} = '  + (master_keks[-1].hex().upper()))
            print(f'master_key_{incremented_revision} = '  + (master_keys[0].hex().upper()))
            print(f'mariko_master_kek_source_dev_{incremented_revision} = {mariko_master_kek_source_dev_key.hex().upper()}')
            print(f'master_kek_dev_{incremented_revision} = '  + (master_keks_dev[-1].hex().upper()))
            print(f'master_key_dev_{incremented_revision} = '  + (master_keys_dev[0].hex().upper()))
            print(f'no new master_key_source_vector')
        else:
            new_master_kek = decrypt(mariko_master_kek_source_key, key_sources.mariko_kek)
            new_master_key =  decrypt(key_sources.master_key_source, decrypt(mariko_master_kek_source_key, key_sources.mariko_kek))
            new_master_kek_source = encrypt(new_master_kek, key_sources.tsec_root_key_02)
            new_master_key_dev =  decrypt(key_sources.master_key_source, decrypt(new_master_kek_source, key_sources.tsec_root_key_02_dev))
            new_master_kek_dev =  decrypt(new_master_kek_source, key_sources.tsec_root_key_02_dev)
            new_master_key_source_vector = encrypt(master_keys[0], new_master_key).hex().upper()
            new_master_key_source_vector_dev = encrypt(master_keys_dev[0], new_master_key_dev).hex().upper()
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
            print(formatted_vector) # "MasterKeySources" https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L116-L136
            print(f'^ add this string to master_key_sources array ^')
            print(formatted_master_kek_source) # "EristaMasterKekSource" https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L34-L37
            print(f'^ add this string to master_kek_sources array ^')
            print(formatted_mariko_master_kek_source) # "MarikoMasterKekSource" https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L24-L27
            print(f'^ add this string to mariko_master_kek_sources array ^')
            print()
            print(f'mariko_master_kek_source_dev_{incremented_revision} = {mariko_master_kek_source_dev_key.hex().upper()}')
            print(f'master_kek_dev_{incremented_revision} = ' + new_master_kek_dev.hex().upper())
            print(f'master_key_dev_{incremented_revision} = '  +   new_master_key_dev.hex().upper())
            print()
            print(formatted_vector_dev)
            print(f'^ add this string to master_key_sources_dev array ^') # "MasterKeySourcesDev" https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L138-L158
            print(formatted_mariko_master_kek_source_dev)
            print(f'^ unused, but output for consistency ^') # "MarikoMasterKekSourceDev" https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L29-L32
        decrypted_bin.close()
        os.remove('temp.keys')
        