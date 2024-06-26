import re
import subprocess
import argparse
import os
import shutil
import hashlib

argParser = argparse.ArgumentParser()
argParser.add_argument("-f", "--firmware", help="firmware folder")
argParser.add_argument("-k", "--keys", help="Where you want the keys to be saved")
argParser.add_argument("-d", "--dev", help="Initiates dev keyset keygen", action='store_true')
args = argParser.parse_args()
firmware = "%s" % args.firmware
prod_keys = "%s" % args.keys
dev = "%s" % args.dev

if firmware == "None":
    firmware = "firmware"

if prod_keys == "None" and dev == "True":
    prod_keys = "dev.keys"
if prod_keys == "None" and dev == "False":
    prod_keys == "prod.keys"

mariko_bek_key = '6A5DXXXXXXXXXXXXXXXXXXXXXXXXXX' # fill in mariko_bek here
mariko_kek_key = '4130XXXXXXXXXXXXXXXXXXXXXXXXXX' # fill in mariko_kek here
master_key_00_key = 'C2CAXXXXXXXXXXXXXXXXXXXXXXXXXX' # fill in master_key_00 here
mariko_bek = f'mariko_bek                        = {mariko_bek_key}'
mariko_kek = f'mariko_kek                        = {mariko_kek_key}'
master_key_00 = f'master_key_00                     = {master_key_00_key}'
bek_hash = hashlib.sha256(mariko_bek_key.encode('utf-8')).hexdigest()
kek_hash = hashlib.sha256(mariko_kek_key.encode('utf-8')).hexdigest()
key_hash = hashlib.sha256(master_key_00_key.encode('utf-8')).hexdigest()

if bek_hash != "ca0fabfd30a3f567aec3e5432428d1a14a0926f49b1093416f00914bc71373ab":
    print("You have filled in the wrong key for mariko_bek, exiting.")
    exit()

if kek_hash != "53be3a736bdb7ff26868ce73e9e5b8ad3b652039be75dfce89a91d11a4c69866":
    print("You have filled in the wrong key for mariko_kek, exiting.")
    exit()

if key_hash != "a2f21eb6b64c18ca50ef4f3403e917dc5f0b39713445a77beba848876d1b1af7":
    print("You have filled in the wrong key for master_key_00, exiting.")
    exit()

with open('temp.keys', 'w') as temp_keys:
    temp_keys.write(f'{mariko_bek}')
    temp_keys.write(f'\n')
    temp_keys.write(f'{mariko_kek}')
    temp_keys.write(f'\n')
    temp_keys.write(f'{master_key_00}')
    temp_keys.close()
    subprocess.run(f'hactoolnet --keyset temp.keys -t switchfs {firmware} --title 0100000000000819 --romfsdir 0100000000000819/romfs/', stdout = subprocess.DEVNULL)
    subprocess.run(f'hactoolnet --keyset temp.keys -t pk11 0100000000000819/romfs/a/package1 --outdir 0100000000000819/romfs/a/pkg1', stdout = subprocess.DEVNULL)
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
        mariko_master_kek_source = f'mariko_master_kek_source_{incremented_revision}       = ' + mariko_master_kek_source_key
        mariko_master_kek_source_dev = f'mariko_master_kek_source_{incremented_revision}       = ' + mariko_master_kek_source_dev_key
        decrypted_bin.close()
        with open('temp.keys', 'a') as keygen:
            keygen.write(f'\n')
            if dev == "False":
                keygen.write(f'{mariko_master_kek_source}')
                keygen.close()
            elif dev == "True":
                keygen.write(f'{mariko_master_kek_source_dev}')
                keygen.close()

        with open(prod_keys, 'w') as new_prod_keys:
            if dev == "True":
                subprocess.run(f'hactoolnet --dev --keyset temp.keys -t keygen', stdout=new_prod_keys)
                print(f'You just generated a dev keyset, which are only useful for developer ncas written with nnsdk keyset, and they have been output to {prod_keys}')
            elif dev == "False":
                subprocess.run(f'hactoolnet --keyset temp.keys -t keygen', stdout=new_prod_keys)
            new_prod_keys.close()
            os.remove('temp.keys')
            print(f'# Keygen completed and output to {prod_keys}, exiting.')
            shutil.rmtree('0100000000000819')
            exit()