#!/usr/bin/env python

import re
import subprocess
import shutil
import os

VERBOSE = False

def get_es_build_id():
    with open(esuncompressed, 'rb') as f:
        f.seek(0x40)
        return f.read(0x14).hex().upper()

def get_nifm_build_id():
    with open(nifmuncompressed, 'rb') as f:
        f.seek(0x40)
        return f.read(0x14).hex().upper()

def get_usb_build_id():
    with open(usbuncompressed, 'rb') as f:
        f.seek(0x40)
        return f.read(0x14).hex().upper()

def run(args):
    r = subprocess.run(args, capture_output=True)
    assert r.returncode == 0, r.stderr
    return r.stdout.decode()

def get_ncaid(filename):
    return run(['sha256sum', filename])[:32]

def get_info(filename):
    return run(['hactool', '--intype=nca', filename])

def get_content_type(info):
    m = re.search(r'Content Type:\s*([^\s]*)', info)
    return m[1] if m else None

def get_title_id(info):
    m = re.search(r'Title ID:\s*([^\s]*)', info)
    return m[1] if m else None

def print_verbose(*args, **kwargs):
    if VERBOSE:
        print(*args, **kwargs)


print('# Normalizing the nca folder')
for nca in os.listdir('firmware'):
    if nca == 'titleid':
        continue
    ncaFull = 'firmware/' + nca

    if os.path.isdir(ncaFull):
        print_verbose(f'{ncaFull}/00 -> {ncaFull}')
        os.rename(ncaFull, ncaFull + '_folder')
        os.rename(ncaFull + '_folder/00', ncaFull)
        os.rmdir(ncaFull + '_folder')

    # Ensure the NCAID is correct (It's wrong when dumped from the
    # Placeholder folder on a Switch NAND
    ncaid = get_ncaid(ncaFull)
    newName = 'firmware/' + ncaid + '.' + nca.split('.', maxsplit=1)[1]
    if ncaFull != newName:
        print_verbose(f'{ncaFull} -> {newName}')
        os.rename(ncaFull, newName)
        ncaFull = newName

    # Ensure meta files have .cnmt.nca extension
    info = get_info(ncaFull)
    contentType = get_content_type(info)
    newName = ncaFull.split('.', maxsplit=1)[0] + '.cnmt.nca'
    if contentType == 'Meta' and ncaFull != newName:
        print_verbose(f'{ncaFull} -> {newName}')
        os.rename(ncaFull, newName)

print('# Sort by titleid')
for nca in os.listdir('firmware'):
    if nca == 'titleid':
        continue
    ncaFull = 'firmware/' + nca
    info = get_info(ncaFull)
    contentType = get_content_type(info)
    titleId = get_title_id(info)
    os.makedirs('firmware/titleid/' + titleId, exist_ok=True)
    newName = 'firmware/titleid/' + titleId + '/' + contentType + '.nca'
    print_verbose(f'{ncaFull} -> {newName}')
    shutil.copyfile(ncaFull, newName)
    # shutil.move(ncaFull, newName)

print('# Extracting ES')
esuncompressed = 'uncompressed_es.nso0'
run(['hactool', '--intype=nca', '--exefsdir=firmware/titleid/0100000000000033/exefs/',
     'firmware/titleid/0100000000000033/Program.nca'])
run(['hactool', '--intype=nso0', '--uncompressed=' + esuncompressed,
     'firmware/titleid/0100000000000033/exefs/main'])

print('# Extracting NIFM')
nifmuncompressed = 'uncompressed_nifm.nso0'
run(['hactool', '--intype=nca', '--exefsdir=firmware/titleid/010000000000000f/exefs/',
     'firmware/titleid/010000000000000f/Program.nca'])
run(['hactool', '--intype=nso0', '--uncompressed=' + nifmuncompressed,
     'firmware/titleid/010000000000000f/exefs/main'])

print('# Extracting USB')
usbuncompressed = 'uncompressed_usb.nso0'
run(['hactool', '--intype=nca', '--exefsdir=firmware/titleid/0100000000000006/exefs/',
     'firmware/titleid/0100000000000006/Program.nca'])
run(['hactool', '--intype=nso0', '--uncompressed=' + usbuncompressed,
     'firmware/titleid/0100000000000006/exefs/main'])

print('# Extracting fat32')
ncaParent = 'firmware/titleid/0100000000000819'
romfsdir = ncaParent + '/romfs'
ini1dir = romfsdir + '/nx/ini1'
run(['hactool', '--intype=nca', '--romfsdir=' + romfsdir, ncaParent + '/Data.nca'])
run(['hactool', '--intype=pk21', '--ini1dir=' + ini1dir, romfsdir + '/nx/package2'])
run(['hactool', '--intype=kip1', '--uncompressed=uncompressed_fat32.kip1', ini1dir + '/FS.kip1'])
fat32compressed = 'compressed_fat32.kip1'
shutil.copyfile(ini1dir + '/FS.kip1', fat32compressed)

print('# Extracting exfat')
ncaParent = 'firmware/titleid/010000000000081b'
romfsdir = ncaParent + '/romfs'
ini1dir = romfsdir + '/nx/ini1'
run(['hactool', '--intype=nca', '--romfsdir=' + romfsdir, ncaParent + '/Data.nca'])
run(['hactool', '--intype=pk21', '--ini1dir=' + ini1dir, romfsdir + '/nx/package2'])
run(['hactool', '--intype=kip1', '--uncompressed=uncompressed_exfat.kip1', ini1dir + '/FS.kip1'])
exfatcompressed = 'compressed_exfat.kip1'
shutil.copyfile(ini1dir + '/FS.kip1', exfatcompressed)

print('===== Printing relevant hashes and buildids =====')
print('es build-id:', get_es_build_id())
print('nifm build-id:', get_nifm_build_id())
print('usb build-id:', get_usb_build_id())
print('exfat sha256:', run(['sha256sum', exfatcompressed])[:64].upper())
print('fat32 sha256:', run(['sha256sum', fat32compressed])[:64].upper())
