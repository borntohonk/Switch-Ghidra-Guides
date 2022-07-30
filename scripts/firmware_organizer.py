#!/usr/bin/env python

from pathlib import Path
import subprocess
import shutil
import os
import hashlib
import errno
VERBOSE = False

def get_es_build_id():
    with open('uncompressed_es.nso0', 'rb') as f:
        f.seek(0x40)
        return(f.read(0x14).hex().upper())

def get_nifm_build_id():
    with open('uncompressed_nifm.nso0', 'rb') as f:
        f.seek(0x40)
        return(f.read(0x14).hex().upper())

def get_usb_build_id():
    with open('uncompressed_usb.nso0', 'rb') as f:
        f.seek(0x40)
        return(f.read(0x14).hex().upper())

def mkdirp(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

def get_ncaid(filename):
    BLOCKSIZE = 65536
    hasher = hashlib.sha256()
    with open(filename, 'rb') as afile:
        buf = afile.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(BLOCKSIZE)
    return hasher.hexdigest()[:32]

def print_verbose(*args, **kwargs):
    if VERBOSE:
        print(*args, **kwargs)

    # Ignore files (only treat directories)
    # Rename CNMTs to make them easier to find. Also, if nca is a folder,
    # get its content. Also, get the hash, and give it the proper ncaid name
print(f'===== Handling firmware files =====')

HACTOOL_PROGRAM = 'hactool'
if os.path.isfile('firmware' + '/dev'):
    HACTOOL_PROGRAM += ' --dev'

print(f'# Normalizing the nca folder')
for nca in os.listdir('firmware'):

    ncaFull = 'firmware' + '/' + nca
    # Fix 'folder-as-file' files when dumped from Switch NAND
    if nca == 'titleid':
        continue
    if os.path.isdir(ncaFull):
        print_verbose(f'{ncaFull}/00 -> {ncaFull}')
        os.rename(ncaFull, ncaFull + '_folder')
        os.rename(ncaFull + '_folder/00', ncaFull)
        os.rmdir(ncaFull + '_folder')
    # Ensure the NCAID is correct (It's wrong when dumped from the
    # Placeholder folder on a Switch NAND
    ncaid = get_ncaid(ncaFull)
    newName = 'firmware' + '/' + ncaid + '.' + '.'.join(os.path.basename(ncaFull).split('.')[1:])
    print_verbose(f'{ncaFull} -> {newName}')
    os.rename(ncaFull, newName)
    ncaFull = newName

    # Ensure meta files have .cnmt.nca extension
    process = subprocess.Popen(['hactool', '--intype=nca', ncaFull], stdout=subprocess.PIPE, universal_newlines=True)
    contentType = process.communicate()[0].split('Content Type:                       ')[1].split('\n')[0]
    if contentType == 'Meta' and not nca.endswith('.cnmt.nca'):
        print_verbose(ncaFull + ' -> ' + '.'.join(ncaFull.split('.')[:-1]) + '.cnmt.nca')
        shutil.move(ncaFull, '.'.join(ncaFull.split('.')[:-1]) + '.cnmt.nca')

print('# Sort by titleid')
for nca in os.listdir('firmware'):
    ncaFull = 'firmware' + '/' + nca
    process = subprocess.Popen(['hactool', '--intype=nca', ncaFull], stdout=subprocess.PIPE, universal_newlines=True)
    titleId = process.communicate()[0].split('Title ID:                           ')[1].split('\n')[0]
    process = subprocess.Popen(['hactool', '--intype=nca', ncaFull], stdout=subprocess.PIPE, universal_newlines=True)
    contentType = process.communicate()[0].split('Content Type:                       ')[1].split('\n')[0]
    mkdirp('firmware' + '/titleid/' + titleId)
    print_verbose('firmware' + '/titleid/' + titleId + '/' + contentType + '.nca -> ' + '../../' + nca)
    shutil.move('firmware' + '/' + nca, 'firmware' + '/titleid/' + titleId + '/' + contentType + '.nca')

print('# Extracting ES')
esFull = 'firmware' + '/'
ncaParent = 'firmware' + '/titleid/0100000000000033'
ncaPartial = ncaParent + '/Program.nca'
ncaFull = 'firmware' + '/titleid/0100000000000033/exefs/main'
process = subprocess.Popen(['hactool', '--intype=nca', '--exefsdir=' + 'firmware' + '/titleid/0100000000000033/exefs/', 'firmware' + '/titleid/0100000000000033/Program.nca'], stdout=subprocess.DEVNULL)
process.wait()
process = subprocess.Popen(['hactool', '--intype=nso0', '--uncompressed=uncompressed_es.nso0', ncaFull], stdout=subprocess.DEVNULL)
process.wait()

print('# Extracting NIFM')
nifmFull = 'firmware' + '/'
ncaParent = 'firmware' + '/titleid/010000000000000f'
ncaPartial = ncaParent + '/Program.nca'
ncaFull = 'firmware' + '/titleid/010000000000000f/exefs/main'
process = subprocess.Popen(['hactool', '--intype=nca', '--exefsdir=' + 'firmware' + '/titleid/010000000000000f/exefs/', 'firmware' + '/titleid/010000000000000f/Program.nca'], stdout=subprocess.DEVNULL)
process.wait()
process = subprocess.Popen(['hactool', '--intype=nso0', '--uncompressed=uncompressed_nifm.nso0', ncaFull], stdout=subprocess.DEVNULL)
process.wait()

print('# Extracting USB')
nifmFull = 'firmware' + '/'
ncaParent = 'firmware' + '/titleid/0100000000000006'
ncaPartial = ncaParent + '/Program.nca'
ncaFull = 'firmware' + '/titleid/0100000000000006/exefs/main'
process = subprocess.Popen(['hactool', '--intype=nca', '--exefsdir=' + 'firmware' + '/titleid/0100000000000006/exefs/', 'firmware' + '/titleid/0100000000000006/Program.nca'], stdout=subprocess.DEVNULL)
process.wait()
process = subprocess.Popen(['hactool', '--intype=nso0', '--uncompressed=uncompressed_usb.nso0', ncaFull], stdout=subprocess.DEVNULL)
process.wait()

print('# Extracting fat32')
ncaParent = 'firmware' + '/titleid/0100000000000819'
pk21dir = ncaParent + '/romfs/nx/package2'
ini1dir = ncaParent + '/romfs/nx/ini1'
ncaFull = ncaParent + '/Data.nca'
process = subprocess.Popen(['hactool', '--intype=nca', '--romfsdir=' + ncaParent + '/romfs', ncaFull], stdout=subprocess.DEVNULL)
process.wait()
process = subprocess.Popen(['hactool', '--intype=pk21', '--ini1dir=' + ini1dir, pk21dir], stdout=subprocess.DEVNULL)
process.wait()
process = subprocess.Popen(['hactool', '--intype=kip1', '--uncompressed=uncompressed_fat32.kip1', ini1dir + '/FS.kip1'], stdout=subprocess.DEVNULL)
process.wait()
fat32Compressed = 'firmware' + '/titleid/0100000000000819/romfs/nx/ini1/FS.kip1'
fsCopy = 'compressed_fat32.kip1'
process = shutil.copyfile(fat32Compressed, fsCopy)

print('# Extracting exfat')
ncaParent = 'firmware' + '/titleid/010000000000081b'
pk21dir = ncaParent + '/romfs/nx/package2'
ini1dir = ncaParent + '/romfs/nx/ini1'
ncaFull = ncaParent + '/Data.nca'
process = subprocess.Popen(['hactool', '--intype=nca', '--romfsdir=' + ncaParent + '/romfs', ncaFull], stdout=subprocess.DEVNULL)
process.wait()
process = subprocess.Popen(['hactool', '--intype=pk21', '--ini1dir=' + ini1dir, pk21dir], stdout=subprocess.DEVNULL)
process.wait()
process = subprocess.Popen(['hactool', '--intype=kip1', '--uncompressed=uncompressed_exfat.kip1', ini1dir + '/FS.kip1'], stdout=subprocess.DEVNULL)
process.wait()
exfatCompressed = 'firmware' + '/titleid/010000000000081b/romfs/nx/ini1/FS.kip1'
fsCopy = 'compressed_exfat.kip1'
process = shutil.copyfile(exfatCompressed, fsCopy)

print(f'===== Printing relevant hashes and buildids =====')
esuncompressed = 'uncompressed_es.nso0'
nifmuncompressed = 'uncompressed_nifm.nso0'
usbuncompressed = 'uncompressed_usb.nso0'
fat32compressed = 'compressed_exfat.kip1'
exfatcompressed = 'compressed_fat32.kip1'

print('es build-id: ' + get_es_build_id())
print('nifm build-id: ' + get_nifm_build_id())
print('usb build-id: ' + get_usb_build_id())
exfathash = hashlib.sha256(open(exfatcompressed, 'rb').read()).hexdigest().upper()
print('exfat sha256: ' + exfathash)
fat32hash = hashlib.sha256(open(fat32compressed, 'rb').read()).hexdigest().upper()
print('fat32 sha256: ' + fat32hash)
