import struct
from io import BytesIO

from unicorn import *
from unicorn.arm64_const import *

import nxo64

def load_nxo_to_unicorn(uc, f, loadbase):
    for sym in f.symbols:
        if sym.shndx:
            sym.resolved = loadbase + sym.value
        else:
            sym.resolved = 0

    resultw = BytesIO()
    f.binfile.seek(0)
    resultw.write(f.binfile.read_to_end())

    def read_qword(ea):
        resultw.seek(ea - loadbase)
        return struct.unpack('<Q', resultw.read(8))[0]

    def write_qword(ea, val):
        resultw.seek(ea - loadbase)
        resultw.write(struct.pack('<Q', val))

    for offset, r_type, sym, addend in f.relocations:
        ea = loadbase + offset

        if r_type == nxo64.R_AARCH64_RELATIVE:
            assert sym is None, 'R_AARCH64_RELATIVE with sym?'
            newval = (loadbase + addend)
            write_qword(ea, newval)
        elif r_type == nxo64.R_AARCH64_JUMP_SLOT or r_type == nxo64.R_AARCH64_GLOB_DAT:
            assert sym is not None
            assert addend == 0
            newval = sym.resolved
            write_qword(ea, newval)
        elif r_type == nxo64.R_AARCH64_ABS64:
            assert sym is not None
            newval = sym.resolved
            if addend != 0:
                #assert sym.shndx # huge mess if we do this on an extern
                newval += addend
            write_qword(ea, newval)
        elif r_type == nxo64.R_FAKE_RELR:
            assert not f.armv7 # TODO
            addend = read_qword(ea)
            write_qword(ea, addend + loadbase)
        else:
            print('TODO: r_type=0x%x sym=%r ea=%X addend=%X' % (r_type, sym, ea, addend))
            continue

    binary = resultw.getvalue()
    uc.mem_map(loadbase, (max(len(binary), f.bssend) + 0xFFF) & ~0xFFF)
    uc.mem_write(loadbase, binary)

def create_unicorn_arm64(): # enables float
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

    addr = 0x1000
    mu.reg_write(UC_ARM64_REG_X0, 3 << 20)
    mu.mem_map(addr, 0x1000)
    fpstartinstrs = b'\x41\x10\x38\xd5\x00\x00\x01\xaa\x40\x10\x18\xd5\x40\x10\x38\xd5\xc0\x03\x5f\xd6'
    mu.mem_write(addr, fpstartinstrs)
    mu.emu_start(addr, addr + len(fpstartinstrs) - 4)
    mu.mem_unmap(addr, 0x1000)

    return mu
