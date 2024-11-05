import re
import subprocess
import argparse
import platform
from base64 import b64decode

argParser = argparse.ArgumentParser()
argParser.add_argument("-f", "--firmware", help="firmware folder")
args = argParser.parse_args()
firmware = "%s" % args.firmware

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

if not hactoolnet == False:
    with open('temp.keys', 'a') as temp_keys:
            temp_keys.write(b64decode('bWFyaWtvX2JlayAgICAgICAgICAgICAgICAgICAgICAgID0gNkE1RDE2OEIxNEU2NENBREQ3MERBOTM0QTA2Q0MyMjI=').decode('utf-8') + '\n')
            temp_keys.write(b64decode('bWFyaWtvX2tlayAgICAgICAgICAgICAgICAgICAgICAgID0gNDEzMEI4Qjg0MkREN0NEMkVBOEZENTBEM0Q0OEI3N0M=').decode('utf-8') + '\n')
            temp_keys.write(b64decode('bWFzdGVyX2tleV8wMCAgICAgICAgICAgICAgICAgICAgID0gQzJDQUFGRjA4OUI5QUVENTU2OTQ4NzYwNTUyNzFDN0Q=').decode('utf-8') + '\n')
            temp_keys.close()
            subprocess.run(f'{hactoolnet} --keyset temp.keys -t switchfs {firmware} --title 0100000000000819 --romfsdir 0100000000000819/romfs/', shell = hshell, stdout = subprocess.DEVNULL)
            subprocess.run(f'{hactoolnet} --keyset temp.keys -t pk11 0100000000000819/romfs/a/package1 --outdir 0100000000000819/romfs/a/pkg1', shell = hshell, stdout = subprocess.DEVNULL)
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
                mariko_master_kek_source_dev = f'mariko_master_kek_source_dev_{incremented_revision}       = {mariko_master_kek_source_dev_key}'
                decrypted_bin.close()
                print(mariko_master_kek_source)
                print(mariko_master_kek_source_dev)