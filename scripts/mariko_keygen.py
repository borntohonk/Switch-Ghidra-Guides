import re
import subprocess
import os
import argparse

argParser = argparse.ArgumentParser()
argParser.add_argument("-f", "--firmware", help="firmware folder")
argParser.add_argument("-k", "--keys", help="keyfile to use")
args = argParser.parse_args()
firmware = "%s" % args.firmware
prod_keys = "%s" % args.keys

if firmware == "None":
    firmware = "firmware"

if prod_keys == "None":
    prod_keys = os.path.expanduser('~/.switch/prod.keys')

with open(prod_keys, 'r') as keycheck:
    check_key = keycheck.read()
    if 'mariko_bek' in check_key:
            print('# Extracting ROMFS BootImagePackage from provided firmware files.')
            subprocess.run(f'hactoolnet --keyset prod.keys -t switchfs {firmware} --title 0100000000000819 --romfsdir 0100000000000819/romfs/', stdout = subprocess.DEVNULL)
            with open('0100000000000819/romfs/a/package1', 'rb') as package1:
                byte_alignment = package1.seek(0x150)
                revision = package1.read(0x01).hex().upper()
                incremented_revision = int(revision) - 0x1
                mariko_master_kek_source_key_revision = f'mariko_master_kek_source_{incremented_revision}'
                if mariko_master_kek_source_key_revision in check_key:
                    print(f'# new mariko_master_kek_source already exists in prod.keys at {prod_keys}, no need to initiate keygen. Exiting.')
                    package1.close()
                    exit()
                else:
                    package1.close()
                    print('# Extracting Package1 from ROMFS')
                    subprocess.run(f'hactoolnet --keyset prod.keys -t pk11 0100000000000819/romfs/a/package1 --outdir 0100000000000819/romfs/a/pkg1', stdout = subprocess.DEVNULL)
                    print('# Checking if a new mariko_master_kek_source is found in Package1.')
                    with open('0100000000000819/romfs/a/pkg1/Decrypted.bin', 'rb') as decrypted_bin:
                        secmon_data = decrypted_bin.read()
                        result = re.search(b'\x4F\x59\x41\x53\x55\x4D\x49', secmon_data)
                        byte_alignment = decrypted_bin.seek(result.end() + 0x32)
                        mariko_master_kek_source_key = decrypted_bin.read(0x10).hex().upper()
                        byte_alignment = decrypted_bin.seek(0x150)
                        revision = decrypted_bin.read(0x01).hex().upper()
                        incremented_revision = int(revision) - 0x1
                        mariko_master_kek_source = f'mariko_master_kek_source_{incremented_revision}       = ' + mariko_master_kek_source_key
                        if 'mariko_kek' in check_key:
                            keycheck.close()
                            os.rename(prod_keys, 'temp.keys')
                            with open('temp.keys', 'a') as temp_keys:
                                temp_keys.write(f'\n')
                                temp_keys.write(f'{mariko_master_kek_source}')
                                temp_keys.close()
                                with open(prod_keys, 'w') as new_prod_keys:
                                    subprocess.run(f'hactoolnet --keyset "temp.keys" -t keygen', stdout=new_prod_keys)
                                    new_prod_keys.close()
                                    os.remove('temp.keys')
                                    print(f'# Keygen completed and output to {prod_keys}, exiting.')
                                    exit()
                        else:
                            keycheck.close()
                            print(f'# mariko_kek is missing in {prod_keys}, we cannot derive a new master_kek from the new mariko_master_kek_source, keygen will not yield new keys. Exiting.')
                            exit()
    else:
        keycheck.close()
        print(f'# mariko_bek is missing in {prod_keys}, we cannot proceed with keygen as package1 cannot be opened for the purpose of obtaining mariko_master_kek_source. Exiting.')
        exit()