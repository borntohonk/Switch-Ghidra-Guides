import struct
import sys
import re
import bisect
import hashlib
from functools import partial

from unicorn import *
from unicorn.arm64_const import *
from capstone import *

import nxo64
from demangling import get_demangled
from unicornhelpers import load_nxo_to_unicorn, create_unicorn_arm64

DEFAULT_LOAD_BASE = 0x7100000000

def demangle(s):
    return get_demangled(s)

class MemoryChunk(object):
    def __init__(self, name, base, size):
        self.name = name
        self.base = base
        self.size = size

    @property
    def end(self):
        return self.base + self.size

    def __repr__(self):
        return 'MemoryChunk(name=%r, base=0x%X, size=0x%X)' % (self.name, self.base, self.size)

class AllocatingChunk(MemoryChunk):
    def __init__(self, name, base, size):
        super(AllocatingChunk, self).__init__(name, base, size)
        self.reset()

    def reset(self):
        self._next_ptr = self.base
        self.bytes_allocated = 0

    def alloc(self, size):
        available = self.end - self._next_ptr
        assert available > 0
        allocation_size = (size + 0xF) & ~0xF
        if allocation_size > available:
            raise Exception('Could not allocate 0x%X bytes from AllocatingChunk %r' % size, self.name)
        result = self._next_ptr
        self._next_ptr += allocation_size
        self.bytes_allocated += size
        return result

    def __repr__(self):
        return 'MemoryChunk(name=%r, base=0x%X, size=0x%X)' % (self.name, self.base, self.size)

class Nx64Simulator(object):
    def __init__(self, nxo, stack_size=0x2000, host_heap_size=0x100000, runtime_heap_size=0x2000, loadbase=DEFAULT_LOAD_BASE, trace_instructions=False):
        self.uc = create_unicorn_arm64()
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.loadbase = loadbase
        load_nxo_to_unicorn(self.uc, nxo, loadbase)

        self._last_chunk_base = 0
        self._chunk_step = 0x100000000
        self._chunks = []

        self.stack = self.create_chunk('stack', stack_size)
        self.host_heap = self.create_chunk('host_heap', host_heap_size, AllocatingChunk)
        self.runtime_heap = self.create_chunk('runtime_heap', runtime_heap_size, AllocatingChunk)
        self.function_pointer_chunk = self.create_chunk('function_pointers', 0)
        self.next_function_pointer = self.function_pointer_chunk.base

        self._data_for_reset = []

        self.current_trace = None

        self._hook_functions = {}

        self.return_pointer = self.create_trace_function_pointer(self.on_return_hook_function)

        self.trace_instructions = trace_instructions

        self.trace_instruction_hooks = []

    def on_return_hook_function(self, uc):
        #print 'on_return_hook_function'
        return False

    def create_trace_function_pointer(self, func):
        function_pointer = self.next_function_pointer
        self.next_function_pointer += 8

        self._hook_functions[function_pointer] = func
        return function_pointer

    def create_chunk(self, name, size, cls=MemoryChunk):
        base = self._last_chunk_base + self._chunk_step
        chunk = cls(name, base, size)
        if size:
            self.uc.mem_map(base, size)
        self._last_chunk_base = base
        return chunk

    def load_host_data(self, data, reset=False):
        p = self.host_heap.alloc(len(data))
        self.uc.mem_write(p, data)
        if reset:
            self._data_for_reset.append((p, data))
        return p

    def dump_regs():
        values = []
        for i in range(28):
            values.append(('X%d' % i, self.uc.reg_read(UC_ARM64_REG_X0+i)))
        values.append(('X29', self.uc.reg_read(UC_ARM64_REG_X29)))
        values.append(('X30', self.uc.reg_read(UC_ARM64_REG_X30)))
        values.append(('SP',  self.uc.reg_read(UC_ARM64_REG_SP)))
        values.append(('PC',  self.uc.reg_read(UC_ARM64_REG_PC)))
        print(', '.join('%s=%X' % i for i in values))

    def qword(self, addr):
        return struct.unpack('<Q', self.uc.mem_read(addr, 8))[0]

    def dword(self, addr):
        return struct.unpack('<I', self.uc.mem_read(addr, 4))[0]

    def sdword(self, addr):
        return struct.unpack('<i', self.uc.mem_read(addr, 4))[0]

    def write_qword(self, addr, value):
        self.uc.mem_write(addr, struct.pack('<Q', value))

    def write_dword(self, addr, value):
        self.uc.mem_write(addr, struct.pack('<I', value))

    def reset_host_data(self):
        for addr, data in self._data_for_reset:
            self.uc.mem_write(addr, data)

    def get_instruction(self, addr):
        instructions = list(self.cs.disasm(bytes(self.uc.mem_read(addr, 4)), addr))
        if instructions:
            assert len(instructions) == 1
            return instructions[0]
        return None

    def add_trace_instruction_hook(self, cb):
        self.trace_instruction_hooks.append(cb)

    def trace_call(self, funcptr, args, trace_object=None):
        if trace_object is None:
            trace_object = {}

        self.reset_host_data()

        register_args, stack_args = args[:8],  args[8:]

        for i, v in enumerate(register_args):
            self.uc.reg_write(UC_ARM64_REG_X0 + i, v)

        for i in range(len(register_args), 9):
            self.uc.reg_write(UC_ARM64_REG_X0 + i, 0)

        sp = self.stack.end
        if stack_args:
            stack_space = len(stack_args) * 8
            stack_space = (stack_space + 0xF) & ~0xF
            sp -= stack_space
            for i, v in enumerate(stack_args):
                self.write_qword(sp + i * 8, v)

        self.uc.reg_write(UC_ARM64_REG_SP, sp)
        self.uc.reg_write(UC_ARM64_REG_PC, funcptr)

        self.uc.reg_write(UC_ARM64_REG_X30, self.return_pointer)

        assert self.current_trace is None
        self.current_trace = trace_object

        try:
            while True:
                try:
                    pc = self.uc.reg_read(UC_ARM64_REG_PC)
                    if self.trace_instruction_hooks:
                        instruction = self.get_instruction(pc)
                        for cb in self.trace_instruction_hooks:
                            cb(self.uc, instruction)

                    if self.trace_instructions:
                        instruction = self.get_instruction(pc)
                        if instruction is not None:
                            print('0x%08x:    %s  %s' % (instruction.address, instruction.mnemonic, instruction.op_str))
                        else:
                            print('0x%08x:    [INVALID]' % (pc,))
                    self.uc.emu_start(self.uc.reg_read(UC_ARM64_REG_PC), 0, count=1)
                except UcError as e:
                    pc = self.uc.reg_read(UC_ARM64_REG_PC)
                    if pc in self._hook_functions:
                        #print 'hook function for %X' % (pc,)
                        if self._hook_functions[pc](self.uc):
                            continue
                        else:
                            break

                    print('UcError @ pc 0x%X' % (pc,))
                    print('', e)
                    raise
        finally:
            self.trace_instruction_hooks = []
            self.current_trace = None

    def invoke_trace_method(self, method_name, *args, **kwargs):
        assert self.current_trace is not None
        try:
            method = getattr(self.current_trace, method_name)
        except AttributeError:
            raise NotImplementedError("Class %r does not implement %r" % (self.current_trace.__class__.__name__, method_name))
        return method(*args, **kwargs)


class IPCServerSimulator(Nx64Simulator):
    def __init__(self, nxo):
        super(IPCServerSimulator, self).__init__(nxo)
        self.message_ptr   = self.load_host_data(b'\x00' * 0x200)
        self.object_buffer = self.load_host_data(b'\xCC' * 0x10000)
        self.object_ptr    = self.load_host_data(struct.pack('<Q', self.object_buffer) * 0x2000)
        self.uc.reg_write(UC_ARM64_REG_TPIDRRO_EL0, self.message_ptr)
        self.should_check = set([])
        self.checked = set([])

    def reset_trace_state(self, cmd_id):
        self.target_cmd_id  = None
        self.hipc_header    = None
        self.special_header = None
        self.last_cmp       = None
        self.tail_call      = False
        self.msg_buf_regs   = []
        self.cmd_id_regs    = []
        self.cmd_id_ofs     = []
        self.uc.mem_write(self.message_ptr, struct.pack('<H', cmd_id) + bytes(range(2, 0x100)) + b'\x00'*0x100)
        self.add_trace_instruction_hook(self.trace_tipc_insn)

    def get_val_or_reg(self, uc, part):
        if part.startswith('#'):
            val = int(part[1:], 0)
        elif part.startswith('x') or part.startswith('w'):
            val = uc.reg_read(UC_ARM64_REG_X0 + int(part[1:]))
            if part.startswith('w'):
                val &= 0xFFFFFFFF
        return val

    def trace_tipc_insn(self, uc, insn):
        parts = insn.op_str.replace(',', ' ').replace('[', ' ').replace(']', ' ').split()
        if insn.mnemonic in ['ldr', 'ldp'] and (parts[0] == 'x30' or parts[1] == 'x30'):
            self.tail_call = True
        # parse out
        #print self.tail_call, insn.mnemonic, insn.op_str
        if insn.mnemonic == 'mrs' and parts[-1] == 'tpidrro_el0':
            self.msg_buf_regs.append(parts[0])
        elif insn.mnemonic == 'ldrh':
            if any(insn.op_str.endswith('[%s]' % r) for r in self.msg_buf_regs):
                reg_idx = int(parts[0][1:])
                if reg_idx not in self.cmd_id_regs:
                    self.cmd_id_regs.append(reg_idx)
                    self.cmd_id_ofs.append(0)
                else:
                    self.cmd_id_ofs[self.cmd_id_regs.index(parts[0])] = 0
        elif insn.mnemonic == 'ldr' and parts[0][0] in 'xw':
            reg_idx = int(parts[0][1:])
            if parts[0] in self.msg_buf_regs:
                self.msg_buf_regs.remove(parts[0])
                #print 'no longer %s' % parts[0]
            if reg_idx in self.cmd_id_regs:
                dst_idx = self.cmd_id_regs.index(reg_idx)
                self.cmd_id_regs.pop(dst_idx)
                self.cmd_id_ofs.pop(dst_idx)
                #print 'no longer cmd %s' % parts[0]
        elif insn.mnemonic == 'ldp':
            if parts[0][0] in 'xw':
                reg_idx = int(parts[0][1:])
                if parts[0] in self.msg_buf_regs:
                    self.msg_buf_regs.remove(parts[0])
                    #print 'no longer %s' % parts[0]
                if reg_idx in self.cmd_id_regs:
                    dst_idx = self.cmd_id_regs.index(reg_idx)
                    self.cmd_id_regs.pop(dst_idx)
                    self.cmd_id_ofs.pop(dst_idx)
                    #print 'no longer cmd %s' % parts[0]
            if parts[1][0] in 'xw':
                reg_idx = int(parts[1][1:])
                if parts[1] in self.msg_buf_regs:
                    self.msg_buf_regs.remove(parts[1])
                    #print 'no longer %s' % parts[1]
                if reg_idx in self.cmd_id_regs:
                    dst_idx = self.cmd_id_regs.index(reg_idx)
                    self.cmd_id_regs.pop(dst_idx)
                    self.cmd_id_ofs.pop(dst_idx)
                    #print 'no longer cmd %s' % parts[1]
        elif insn.mnemonic.startswith('mov') and parts[0][0] in 'xw':
            reg_idx = int(parts[0][1:])
            if parts[0] in self.msg_buf_regs:
                self.msg_buf_regs.remove(parts[0])
                #print 'no longer %s' % parts[0]
            if reg_idx in self.cmd_id_regs:
                dst_idx = self.cmd_id_regs.index(reg_idx)
                self.cmd_id_regs.pop(dst_idx)
                self.cmd_id_ofs.pop(dst_idx)
                #print 'no longer cmd %s' % parts[0]
        elif (insn.mnemonic.startswith('add') or insn.mnemonic.startswith('sub')) and parts[0][0] in 'xw':
            reg_idx = int(parts[0][1:])
            if parts[0] in self.msg_buf_regs:
                self.msg_buf_regs.remove(parts[0])
                #print 'no longer %s' % parts[0]
            if reg_idx in self.cmd_id_regs:
                dst_idx = self.cmd_id_regs.index(reg_idx)
                if int(parts[1][1:]) in self.cmd_id_regs:
                    src_idx = self.cmd_id_regs.index(int(parts[1][1:]))
                    self.cmd_id_ofs[dst_idx] = self.cmd_id_ofs[src_idx] + (1 if insn.mnemonic.startswith('add') else -1) * self.get_val_or_reg(uc, parts[2])
                    #print 'cmd: %s -> ofs %x' % (parts[0], self.cmd_id_ofs[dst_idx])
                else:
                    self.cmd_id_regs.pop(dst_idx)
                    self.cmd_id_ofs.pop(dst_idx)
                    #print 'no longer cmd %s' % parts[0]
        elif insn.mnemonic.startswith('cmp'):
            reg_idx = int(parts[0][1:])
            if reg_idx in self.cmd_id_regs:
                assert len(parts) == 2
                self.last_cmp = ('cmd_id', reg_idx, self.get_val_or_reg(uc, parts[1]))
            else:
                lhs, rhs = self.get_val_or_reg(uc, parts[0]), self.get_val_or_reg(uc, parts[1])
                if ((lhs & 0xFFFFFFFFFFFF0000) == 0x0706050403020000) or ((rhs & 0xFFFFFFFFFFFF0000) == 0x0706050403020000):
                    is_lhs = (lhs & 0xFFFFFFFFFFFF0000) == 0x0706050403020000
                    if is_lhs:
                        self.target_cmd_id = rhs & 0xFFFF
                        self.hipc_header   = rhs
                    else:
                        self.target_cmd_id = lhs & 0xFFFF
                        self.hipc_header   = lhs
                    if parts[0][0] in 'xw':
                        uc.reg_write(UC_ARM64_REG_X0 + int(parts[0][1:]), self.hipc_header)
                    if parts[1][0] in 'xw':
                        uc.reg_write(UC_ARM64_REG_X0 + int(parts[1][1:]), self.hipc_header)
                    uc.mem_write(self.message_ptr, struct.pack('<Q', self.hipc_header))
                    #print 'HIPC header: %X' % self.hipc_header
                if self.hipc_header is not None and (self.hipc_header & 0x8000000000000000) and (((lhs & 0xFFFFFFFF) == 0x0B0A0908) or ((rhs & 0xFFFFFFFF) == 0x0B0A0908)):
                    is_lhs = (lhs & 0xFFFFFFFF) == 0x0B0A0908
                    if is_lhs:
                        self.special_header = rhs & 0xFFFFFFFF
                    else:
                        self.special_header = lhs & 0xFFFFFFFF
                    if parts[0][0] in 'xw':
                        uc.reg_write(UC_ARM64_REG_X0 + int(parts[0][1:]), (uc.reg_read(UC_ARM64_REG_X0 + int(parts[0][1:])) & 0xFFFFFFFF00000000) | self.special_header)
                    if parts[1][0] in 'xw':
                        uc.reg_write(UC_ARM64_REG_X0 + int(parts[1][1:]), (uc.reg_read(UC_ARM64_REG_X0 + int(parts[1][1:])) & 0xFFFFFFFF00000000) | self.special_header)
                    #print 'Special header: %X' % self.special_header
                #print 'Compare %x %x' % (lhs, rhs)
                self.last_cmp = None
        elif insn.mnemonic.startswith('b.') and self.last_cmp is not None:
            cmp_type, reg_idx, val = self.last_cmp
            self.last_cmp = None
            if cmp_type == 'cmd_id':
                idx = self.cmd_id_regs.index(reg_idx)
                if insn.mnemonic.endswith('.hi'):
                    # comparing to range, that range is of interest
                    for i in range(val + 1):
                        #print 'We should check %d' % (i - self.cmd_id_ofs[idx])
                        self.should_check.add(i - self.cmd_id_ofs[idx])
                elif insn.mnemonic.endswith('.eq') or insn.mnemonic.endswith('.ne'):
                    # If comparing command id to specific value, that value is of interest.
                    #print 'We should check %d' % (val - self.cmd_id_ofs[idx])
                    self.should_check.add(val - self.cmd_id_ofs[idx])
                else:
                    print('Unknown command id comparison %s' % insn.mnemonic)
                    assert False
        elif insn.mnemonic == 'b':
            if self.tail_call:
                #print '!!! default'
                # Verify we're default
                assert bytes(uc.mem_read(self.message_ptr, 8)) == b'\x0F\x00\x02\x03\x04\x05\x06\x07'
                self.found_default = True
                self.default_func  = self.get_val_or_reg(uc, parts[0])
                #print '!!! default func %x' % self.default_func
                uc.mem_write(uc.reg_read(UC_ARM64_REG_PC), b'\xC0\x03\x5F\xD6')
                uc.reg_write(UC_ARM64_REG_X0, 0xFEED9A62)
        elif insn.mnemonic == 'bl':
            # nop out
            if bytes(uc.mem_read(self.message_ptr, 8)) == b'\x0F\x00\x02\x03\x04\x05\x06\x07':
                self.found_default = True
                self.default_func  = self.get_val_or_reg(uc, parts[0])
            uc.mem_write(uc.reg_read(UC_ARM64_REG_PC), b'\x1F\x20\x03\xD5')
            uc.reg_write(UC_ARM64_REG_X0, 0xFEED9A62)

    def trace_command(self, process_function, cmd_id):
        #print 'Tracing %x %d' % (process_function, cmd_id)
        self.reset_trace_state(cmd_id)
        self.trace_call(DEFAULT_LOAD_BASE + process_function, [self.object_ptr])
        if self.target_cmd_id is not None:
            #print '  Found cmd %X via trace' % cmd_id
            #print '    HIPC header:    %X' % self.hipc_header
            #if self.hipc_header & 0x8000000000000000:
            #    print '    Special Header: %X' % self.special_header
            resp_buffer = self.uc.mem_read(self.message_ptr, 0x100)
            resp_header, resp_special = struct.unpack('<QI', resp_buffer[:0xC])
            #print '    Resp header:    %X' % resp_header
            #if resp_header & 0x8000000000000000:
            #    print '    Resp special:   %X' % resp_special
            self.commands[self.target_cmd_id - 0x10] = (self.hipc_header, self.special_header, resp_header, resp_special)
        self.checked.add(cmd_id)

    def trace_commands(self, process_function):
        #print 'Looking at process function %x' % (process_function)
        self.should_check  = set([])
        self.checked       = set([])
        self.commands = {}
        self.found_default = False
        self.trace_command(process_function, 0xF) # Guaranteed invalid
        while True:
            needs_check = self.should_check - self.checked
            if len(needs_check) == 0:
                break
            for cmd_id in needs_check:
                self.trace_command(process_function, cmd_id)
        if self.found_default:
            self.commands['default'] = self.default_func


def get_command_desc(header_tuple):
    hipc_header, hipc_special, resp_header, resp_special = header_tuple
    num_x   = (hipc_header >> 16) & 0xF
    num_a   = (hipc_header >> 20) & 0xF
    num_b   = (hipc_header >> 24) & 0xF
    num_w   = (hipc_header >> 28) & 0xF
    num_raw = (hipc_header >> 32) & 0x3FF
    num_c   = (hipc_header >> 42) & 0xF
    has_sp  = (hipc_header >> 63) & 0x1
    if has_sp:
        has_pid  = (hipc_special >> 0) & 0x1
        num_copy = (hipc_special >> 1) & 0xF
        num_move = (hipc_special >> 5) & 0xF
    else:
        has_pid  = 0
        num_copy = 0
        num_move = 0

    out_x   = (resp_header >> 16) & 0xF
    out_a   = (resp_header >> 20) & 0xF
    out_b   = (resp_header >> 24) & 0xF
    out_w   = (resp_header >> 28) & 0xF
    out_raw = (resp_header >> 32) & 0x3FF
    out_c   = (resp_header >> 42) & 0xF
    out_sp  = (resp_header >> 63) & 0x1
    assert out_x + out_a + out_b + out_w + out_c == 0

    if out_sp:
        out_pid  = (resp_special >> 0) & 0x1
        out_copy = (resp_special >> 1) & 0xF
        out_move = (resp_special >> 5) & 0xF
    else:
        out_pid  = 0
        out_copy = 0
        out_move = 0

    def s_int(n):
        if (n > 10):
            v = '0x%X' % n
        else:
            v = str(n)
        return v.rjust(5)
    desc = '"inbytes": %s, "outbytes": %s' % (s_int(num_raw * 4), s_int((out_raw - 1) * 4))

    if num_x + num_a + num_b + num_w + num_c:
        desc += ', "buffers": {'
        if num_x:
            desc += '"InPointer": %d' % num_x
        if num_c:
            desc += '"OutPointer": %d' % num_c
        if num_a:
            desc += '"InMapAlias": %d' % num_a
        if num_b:
            desc += '"OutMapAlias": %d' % num_b
        if num_w:
            desc += '"ExchangeMapAlias": %d' % num_w
        desc += '}'

    if num_move + num_copy:
        desc += ', "inhandles": [%d, %d]' % (num_copy, num_move)

    if out_move + out_copy:
        desc += ', "outhandles": [%d, %d]' % (out_copy, out_move)

    if has_pid:
        desc += ', "pid": True'

    return desc

def dump_ipc_filename(fname):
    with open(fname, 'rb') as fileobj:
        f = nxo64.load_nxo(fileobj)

    simulator = IPCServerSimulator(f)

    # Get .got
    data_syms = {}
    fptr_syms = {}
    got_data_syms = {}
    got = (f.got_start, f.got_end)
    for offset, r_type, sym, addend in f.relocations:
        if offset < got[0] or got[1] < offset:
            continue
        if r_type == nxo64.R_FAKE_RELR:
            addend = simulator.qword(0x7100000000 + offset) - 0x7100000000
        if f.dataoff <= offset < f.dataoff + f.datasize:
            if sym and sym.shndx and sym.value < f.textsize:
                fptr_syms[offset] = sym.value
            elif addend and addend < f.textsize:
                fptr_syms[offset] = addend
            elif sym and sym.shndx and sym.value:
                data_syms[offset] = sym.value
            elif addend:
                data_syms[offset] = addend
            if offset in data_syms and (got[0] <= offset or offset <= got[1]):
                got_data_syms[offset] = data_syms[offset]

    # Read .text
    f.binfile.seek(0)
    text = f.binfile.read(f.textsize)

    # Determine "possible" functions
    possible_processors = []
    for offset in got_data_syms:
        vt_ofs = got_data_syms[offset]
        vt_base = vt_ofs+0x7100000000
        if f.dataoff <= vt_ofs and vt_ofs <= f.dataoff + f.datasize:
            func = simulator.qword(vt_base + 0x20)
            func_ofs = func - 0x7100000000
            if f.textoff <= func_ofs and func_ofs <= f.textoff + f.textsize:
                possible_processors.append((vt_ofs, func_ofs))

    # Locate all instances of "MOV W0, #0x1E23" (tipc::ResultInvalidCommandFormat)
    invalid_formats = []
    for i in range(0, f.textsize, 4):
        if text[i:i+4] == b'\x60\xC4\x83\x52':
            invalid_formats.append(i)

    # Work backwards to find the actual processing functions.
    command_processors = []
    sfcos = []
    for err_ofs in invalid_formats:
        i = err_ofs + 0x40
        found = False
        while i > err_ofs - 0x3000 and i > 0 and not found:
            i -= 4
            insn = struct.unpack('<I', text[i:i+4])[0]
            if (insn & 0xFFFFFFE0) == 0x5288CA60 and struct.unpack('<I', text[i+4:i+8])[0] == (0x72A9E860 | (insn & 0x1F)):
                # SFCO backwards-compat, ignore
                found = True
                sfcos.append(err_ofs)
                break
            if (insn & 0xFFFFFFE0) == 0xD53BD060:
                for j,(vt, candidate) in enumerate(possible_processors):
                    if candidate not in command_processors and candidate < i and i < candidate + 0x40:
                        #print '%x %x %x %x' % (i, j, vt, candidate)
                        command_processors.append((vt, candidate, insn & 0x1F))
                        found = True
                        break
            if found:
                break
        if not found:
            raise ValueError('Failed to locate processor function')
    for sfco in sfcos:
        invalid_formats.remove(sfco)
    #print ['(%x,%x,%d)' % x for x in command_processors]
    #print ['%x' % x for x in invalid_formats]
    assert len(command_processors) == len(invalid_formats)

    interfaces = []

    # Try all interfaces
    for (vt, candidate, insn) in command_processors:
        simulator.trace_commands(candidate)
        interfaces.append(simulator.commands)

    process_name = f.get_name()
    if process_name is None:
        process_name = fname

    print('%r: {' % (process_name,))
    for (commands, (vt, candidate, insn)) in zip(interfaces, command_processors):
        print("  '0x%X': { # ProcessMessage = 0x%X" % (vt + DEFAULT_LOAD_BASE, candidate + DEFAULT_LOAD_BASE))
        for cmd_id in commands.keys():
            if cmd_id == 'default':
                print("      'default': {\"func\": 0x%X}," % commands[cmd_id])
            else:
                print("      %s {%s}," % (('%d:        ' % cmd_id)[:len("'default'") + 1], get_command_desc(commands[cmd_id])))
        print("  },")
    print('},')

def main(fnames):
    for i in fnames:
        dump_ipc_filename(i)

if __name__ == '__main__':
    main(sys.argv[1:])

