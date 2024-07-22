import re
import subprocess
import argparse
import os
import shutil
import platform
from base64 import b64decode

argParser = argparse.ArgumentParser()
argParser.add_argument("-f", "--firmware", help="firmware folder")
argParser.add_argument("-k", "--keys", help="Where you want the keys to be saved")
argParser.add_argument("-d", "--dev", help="Initiates dev keyset keygen", action='store_true')
args = argParser.parse_args()
firmware = "%s" % args.firmware
prod_keys = "%s" % args.keys
dev = "%s" % args.dev


user_folder = os.path.expanduser('~/.switch')
user_keys = os.path.expanduser('~/.switch/prod.keys')

if firmware == "None":
    firmware = "firmware"

if prod_keys == "None" and dev == "True":
    keys = "dev.keys"
elif prod_keys == "None" and dev == "False":
    keys = "prod.keys"
elif prod_keys == "None" and os.path.exists(user_keys):
    keys = user_keys
    shutil.copy(user_keys, "temp.keys")
else: 
    keys = prod_keys

if platform.system() == "Windows":
    hactoolnet = "tools/hactoolnet-windows.exe"
elif platform.system() == "Linux":
    hactoolnet = "tools/hactoolnet-linux"
elif platform.system() == "MacOS":
    hactoolnet = "tools/hactoolnet-macos"
else:
    print(f"Unknown Platform: {platform.system()}, proide your own hactoolnet")
    hactoolnet = "hactoolnet"

with open('temp.keys', 'a') as temp_keys:
    temp_keys.write(b64decode('bWFyaWtvX2JlayAgICAgICAgICAgICAgICAgICAgICAgID0gNkE1RDE2OEIxNEU2NENBREQ3MERBOTM0QTA2Q0MyMjI=').decode('utf-8') + '\n')
    temp_keys.write(b64decode('bWFyaWtvX2tlayAgICAgICAgICAgICAgICAgICAgICAgID0gNDEzMEI4Qjg0MkREN0NEMkVBOEZENTBEM0Q0OEI3N0M=').decode('utf-8') + '\n')
    temp_keys.write(b64decode('bWFzdGVyX2tleV8wMCAgICAgICAgICAgICAgICAgICAgID0gQzJDQUFGRjA4OUI5QUVENTU2OTQ4NzYwNTUyNzFDN0Q=').decode('utf-8') + '\n')
    temp_keys.close()
    subprocess.run(f'{hactoolnet} --keyset temp.keys -t switchfs {firmware} --title 0100000000000819 --romfsdir 0100000000000819/romfs/', stdout = subprocess.DEVNULL)
    subprocess.run(f'{hactoolnet} --keyset temp.keys -t pk11 0100000000000819/romfs/a/package1 --outdir 0100000000000819/romfs/a/pkg1', stdout = subprocess.DEVNULL)
    with open('0100000000000819/romfs/a/pkg1/Decrypted.bin', 'rb') as decrypted_bin:
        secmon_data = decrypted_bin.read()
        result = re.search(b'\x4F\x59\x41\x53\x55\x4D\x49', secmon_data)
        byte_alignment = decrypted_bin.seek(result.end() + 0x22)
        mariko_master_kek_source_dev_key = decrypted_bin.read(0x10).hex().upper()
        byte_alignment = decrypted_bin.seek(result.end() + 0x32)
        mariko_master_kek_source_key = decrypted_bin.read(0x10).hex().upper()
        byte_alignment = decrypted_bin.seek(0x150)
        revision = decrypted_bin.read(0x01).hex().upper()
        incremented_revision = int(revision) - 0x1
        mariko_master_kek_source = f'mariko_master_kek_source_{incremented_revision}       = {mariko_master_kek_source_key}'
        mariko_master_kek_source_dev = f'mariko_master_kek_source_{incremented_revision}       = {mariko_master_kek_source_dev_key}'
        decrypted_bin.close()
        with open('temp.keys', 'a') as keygen:
            keygen.write(f'\n')
            if dev == "False":
                keygen.write(f'{mariko_master_kek_source}')
                keygen.close()
            elif dev == "True":
                keygen.write(f'{mariko_master_kek_source_dev}')
                keygen.close()

        with open(keys, 'w') as new_prod_keys:
            if dev == "True":
                subprocess.run(f'{hactoolnet} --dev --keyset temp.keys -t keygen', stdout=new_prod_keys)
                print(f'# You just generated a dev keyset, which are only useful for developer ncas written with nnsdk keyset, and they have been output to {keys}')
            elif dev == "False":
                subprocess.run(f'{hactoolnet} --keyset temp.keys -t keygen', stdout=new_prod_keys)
            new_prod_keys.close()
            os.remove('temp.keys')
        subprocess.run(f'{hactoolnet} --keyset {keys} -t switchfs {firmware} --title 0100000000000809 --romfsdir 0100000000000809/romfs/', stdout = subprocess.DEVNULL)
        with open(f'0100000000000809/romfs/file', 'rb') as get_version:
                byte_alignment = get_version.seek(0x68)
                read_version_number = get_version.read(0x6).hex().upper()
                version = (bytes.fromhex(read_version_number).decode('utf-8'))
                print(f'# Firmware version number generated keys for is: {version}')
                print(f'# key revision generated keys for ends with _{incremented_revision}')
                print(f'# Keygen completed and output to {keys}, exiting.')
        shutil.rmtree('0100000000000819')
        shutil.rmtree('0100000000000809')
        if not os.path.exists(user_folder):
            os.makedirs(user_folder)
        if not os.path.exists(user_keys):
            shutil.copy(keys, user_keys)
        exit()