import re
import subprocess
import os

prod_keys = os.path.expanduser('~/.switch/prod.keys')
with open(prod_keys, 'r') as keycheck:
    check_key = keycheck.read()
    if 'mariko_bek' in check_key:
            print("# Checking if latest mariko_master_kek_source is needed from package1 retrieved from BootImagePackage")
            subprocess.run('hactoolnet --keyset prod.keys -t switchfs firmware --title 0100000000000819 --romfsdir firmware/titleid/0100000000000819/romfs/', stdout = subprocess.DEVNULL)
            subprocess.run('hactoolnet --keyset prod.keys -t pk11 firmware/titleid/0100000000000819/romfs/a/package1 --outdir firmware/titleid/0100000000000819/romfs/a/pkg1', stdout = subprocess.DEVNULL)
            with open('firmware/titleid/0100000000000819/romfs/a/pkg1/Decrypted.bin', 'rb') as decrypted_bin:
                secmon_data = decrypted_bin.read()
                result = re.search(b'\x4F\x59\x41\x53\x55\x4D\x49', secmon_data)
                hekate_bytes = decrypted_bin.seek(result.end() + 0x32)
                mariko_master_kek_source_key = decrypted_bin.read(0x10).hex().upper()
                if mariko_master_kek_source_key in check_key:
                    print(f'Key already exists in prod.keys at {prod_keys}, no need to initiate keygen')
                    keycheck.close()
                else:
                    revision = re.findall(r'mariko_master_kek_source_\w{2}', check_key)
                    incremented_revision = (int(max(revision).split('mariko_master_kek_source_')[1]) + 0x1)
                    mariko_master_kek_source = f'mariko_master_kek_source_{incremented_revision}       = ' + mariko_master_kek_source_key
                    if 'tsec_root_key_02' in check_key:
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
                                print(f'# Keygen completed and output to {prod_keys}')
                    else:
                        keycheck.close()
                        print('tsec_root_key_02 is missing, we cannot derive master keys, keygen will not yield viable keyset.')
    else:
        keycheck.close()
        print('mariko_bek keys not found, cannot proceed with keygen as package1 cannot be opened')