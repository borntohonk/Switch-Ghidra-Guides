import re
import subprocess
import os
import argparse
import shutil

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
    if 'package1_key_' in check_key:
            print('# Extracting ROMFS BootImagePackage from provided firmware files.')
            subprocess.run(f'hactoolnet --keyset {prod_keys} -t switchfs {firmware} --title 0100000000000819 --romfsdir 0100000000000819/romfs/', stdout = subprocess.DEVNULL)
            print('# Extracting Package1 from ROMFS')
            subprocess.run(f'hactoolnet --keyset {prod_keys} -t pk11 0100000000000819/romfs/nx/package1 --outdir 0100000000000819/romfs/nx/pkg1', stdout = subprocess.DEVNULL)
            print('# Checking if a new master_kek_source is found in Package1.')
            with open('0100000000000819/romfs/nx/pkg1/Decrypted.bin', 'rb') as decrypted_bin:
                secmon_data = decrypted_bin.read()
                result = re.search(b'\x4F\x59\x41\x53\x55\x4D\x49', secmon_data)
                byte_alignment = decrypted_bin.seek(result.end() + 0x32)
                erista_master_kek_source_key = decrypted_bin.read(0x10).hex().upper()
                byte_alignment = decrypted_bin.seek(0x1e)
                revision = decrypted_bin.read(0x01).hex().upper()
                incremented_revision = int(revision) - 0x1
                erista_master_kek_source = f'master_kek_source_{incremented_revision}       = ' + erista_master_kek_source_key
                decrypted_bin.close()
                if 'tsec_root_key_' in check_key:
                    keycheck.close()
                    os.rename(prod_keys, 'temp.keys')
                    with open('temp.keys', 'a') as temp_keys:
                        temp_keys.write(f'\n')
                        temp_keys.write(f'{erista_master_kek_source}')
                        temp_keys.close()
                        with open(prod_keys, 'w') as new_prod_keys:
                            subprocess.run(f'hactoolnet --keyset "temp.keys" -t keygen', stdout=new_prod_keys)
                            new_prod_keys.close()
                            os.remove('temp.keys')
                            print(f'# Keygen completed and output to {prod_keys}, exiting.')
                            shutil.rmtree('0100000000000819')
                            exit()
                else:
                    keycheck.close()
                    shutil.rmtree('0100000000000819')
                    print(f'# tsec_root_key_%% is missing in {prod_keys}, we cannot derive a new master_kek from the new master_kek_source, keygen will not yield new keys. Exiting.')
                    exit()
    else:
        keycheck.close()
        print(f'# package1_key_%% is missing in {prod_keys}, we cannot proceed with keygen as package1 cannot be opened for the purpose of obtaining master_kek_source. Exiting.')
        exit()
