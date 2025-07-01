import gzip, math, os, re, struct, sys
from unicorn import *
from unicorn.arm64_const import *
from capstone import *

from io import BytesIO

import nxo64
from demangling import get_demangled

'''
TODO: try to turn into mangled symbols:

; nn::sf::cmif::server::detail::CmifProcessFunctionTableGetterImplBase<nn::mmnv::IRequest>::ProcessServerMessage(nn::sf::IServiceObject *, nn::sf::cmif::server::CmifServerMessage *, nn::sf::detail::PointerAndSize const&)
_ZN2nn2sf4cmif6server6detail38CmifProcessFunctionTableGetterImplBaseINS_4mmnv8IRequestEE20ProcessServerMessageEPNS0_14IServiceObjectEPNS2_17CmifServerMessageERKNS0_6detail14PointerAndSizeE


; nn::sf::cmif::server::detail::CmifProcessFunctionTableGetterImpl<nn::mmnv::IRequest>::DispatchServerMessage(nn::sf::cmif::CmifOutHeader **, nn::mmnv::IRequest*, nn::sf::cmif::server::CmifServerMessage *, unsigned int, nn::sf::detail::PointerAndSize &&)
_ZN2nn2sf4cmif6server6detail34CmifProcessFunctionTableGetterImplINS_4mmnv8IRequestEE21DispatchServerMessageEPPNS1_13CmifOutHeaderEPS6_PNS2_17CmifServerMessageEjONS0_6detail14PointerAndSizeE


; nn::sf::cmif::server::detail::CmifProcessFunctionTableGetterImpl<nn::mmnv::IRequest>::Process_Initialize(nn::sf::cmif::CmifOutHeader **, nn::mmnv::IRequest*, nn::sf::cmif::server::CmifServerMessage *, nn::sf::detail::PointerAndSize &&)
_ZN2nn2sf4cmif6server6detail34CmifProcessFunctionTableGetterImplINS_4mmnv8IRequestEE18Process_InitializeEPPNS1_13CmifOutHeaderEPS6_PNS2_17CmifServerMessageEONS0_6detail14PointerAndSizeE
'''

ALL_COMMAND_IDS = set([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 4201, 106, 107, 108, 4205, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 20501, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 2413, 8216, 150, 151, 2201, 2202, 2203, 2204, 2205, 2207, 10400, 2209, 8219, 8220, 8221, 30900, 30901, 30902, 8223, 90300, 190, 8224, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 220, 20701, 222, 223, 230, 231, 250, 251, 252, 2301, 2302, 255, 256, 10500, 261, 2312, 280, 290, 291, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 2101, 20800, 20801, 322, 323, 2102, 8250, 350, 2400, 2401, 2402, 2403, 2404, 2405, 10600, 10601, 2411, 2412, 2450, 2414, 8253, 10610, 2451, 2421, 2422, 2424, 8255, 2431, 8254, 2433, 2434, 406, 8257, 400, 401, 402, 403, 404, 405, 10300, 407, 408, 409, 410, 411, 2460, 20900, 8252, 412, 2501, 10700, 10701, 10702, 8200, 1106, 1107, 500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511, 512, 513, 520, 521, 90200, 8201, 90201, 540, 30810, 542, 543, 544, 545, 546, 30811, 30812, 8202, 8203, 8291, 600, 601, 602, 603, 604, 605, 606, 607, 608, 609, 610, 611, 612, 613, 614, 8295, 620, 8204, 8296, 630, 105, 640, 4203, 8225, 2050, 109, 30830, 2052, 8256, 700, 701, 702, 703, 704, 705, 706, 707, 708, 709, 8207, 20600, 8208, 49900, 751, 11000, 127, 8209, 800, 801, 802, 803, 804, 805, 806, 821, 822, 823, 824, 8211, 850, 851, 852, 7000, 2055, 900, 901, 902, 903, 904, 905, 906, 907, 908, 909, 3000, 3001, 3002, 160, 8012, 8217, 8013, 320, 997, 998, 999, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1020, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1061, 1062, 1063, 21000, 1100, 1101, 1102, 2053, 5202, 5203, 8218, 3200, 3201, 3202, 3203, 3204, 3205, 3206, 3207, 3208, 3209, 3210, 3211, 3214, 3215, 3216, 3217, 40100, 40101, 541, 1200, 1201, 1202, 1203, 1204, 1205, 1206, 1207, 1208, 8292, 547, 20500, 8293, 2054, 2601, 8294, 40200, 40201, 1300, 1301, 1302, 1303, 1304, 8227, 20700, 221, 8228, 8297, 8229, 4206, 1400, 1401, 1402, 1403, 1404, 1405, 1406, 1411, 1421, 1422, 1423, 1424, 30100, 30101, 30102, 1431, 1432, 30110, 30120, 30121, 1451, 1452, 1453, 1454, 1455, 1456, 1457, 1458, 1471, 1472, 1473, 1474, 1500, 1501, 1502, 1503, 1504, 1505, 2300, 30200, 30201, 30202, 30203, 30204, 30205, 30210, 30211, 30212, 30213, 30214, 30215, 30216, 30217, 260, 1600, 1601, 1602, 1603, 60001, 60002, 30300, 2051, 20100, 20101, 20102, 20103, 20104, 20110, 1700, 1701, 1702, 1703, 8222, 30400, 30401, 30402, 631, 20200, 20201, 1800, 1801, 1802, 1803, 2008, 10011, 30500, 7992, 7993, 7994, 7995, 7996, 7997, 7998, 7999, 8000, 8001, 8002, 8011, 20300, 20301, 8021, 1900, 1901, 1902, 6000, 6001, 6002, 10100, 10101, 10102, 10110, 30820, 321, 1941, 1951, 1952, 1953, 8100, 20400, 20401, 8210, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 10200, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 10211, 2020, 2021, 30700, 2030, 2031, 8251, 90100, 90101, 90102])

#ALL_COMMAND_IDS = set(range(30))

def load_nxo_to_capstone(mu, fn, loadbase):
	with open(fn, 'rb') as fileobj:
		f = nxo64.load_nxo(fileobj)

	stables = []
	for sym in f.symbols:
		if 's_Table' in sym.name:
			stables.append((sym.name, loadbase + sym.value))
		if sym.shndx:
			sym.resolved = loadbase + sym.value
		else:
			sym.resolved = 0

	resultw = BytesIO()
	f.binfile.seek(0)
	resultw.write(f.binfile.read_to_end())

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
		else:
			continue

	binary = resultw.getvalue()
	mu.mem_map(loadbase, (len(binary) + 0xFFF) & ~0xFFF) 
	mu.mem_write(loadbase, binary)
	return stables, f.symbols, f.textsize

	
import glob

ADDRESS = 0x7100000000

STACK = 0x1000000
STACK_SIZE = 1024*1024

MEM = STACK + STACK_SIZE + 0x1000
MEM_SIZE = 1024*1024

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

def demangle(s):
	value = get_demangled(s)
	pre = 'nn::sf::cmif::server::detail::CmifProcessFunctionTableGetter<'
	post = ', void>::s_Table'
	if value.startswith(pre) and value.endswith(post):
		value = value[len(pre):-len(post)]
	return value

from struct import unpack as up
def parse_npdm(npdm):
    aci0_off, aci0_size, acid_off, acid_size = up('<IIII', npdm[0x70:0x80])
    aci0, acid = npdm[aci0_off:aci0_off+aci0_size], npdm[acid_off:acid_off+acid_size]
    title_name = npdm[0x20:npdm.index(b'\x00', 0x20)]
    title_id = up('<Q', aci0[0x10:0x18])[0]
    fs_off, fs_sz, srv_off, srv_sz, k_off, k_sz = up('<IIIIII', acid[0x220:0x238])
    return title_name.decode('ascii')

for i in sys.argv[1:]:
	name = i
	if os.path.exists(i+'.npdm'):
		with open(i+'.npdm', 'rb') as f:
			name = parse_npdm(f.read())
	elif i.endswith('.kip'):
		with open(i, 'rb') as f:
			f.seek(4)
			name = f.read(12)
			name = name[:name.index(b'\0')].decode('ascii')
	else:
		name = name.split('/')[-1].split('_')[0].split('-')[0].split('.')[0].lower()
	#title_id = i.split('/')[-3]


	fname = i
	mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)


	stables, symbols, text_size = load_nxo_to_capstone(mu, i, ADDRESS)


	mu.mem_map(STACK, STACK_SIZE)
	mu.mem_map(MEM, MEM_SIZE)

	# enable FP
	addr = 0x1000
	mu.reg_write(UC_ARM64_REG_X0, 3 << 20)
	mu.mem_map(addr, 0x1000)
	fpstartinstrs = b'\x41\x10\x38\xd5\x00\x00\x01\xaa\x40\x10\x18\xd5\x40\x10\x38\xd5\xc0\x03\x5f\xd6'
	mu.mem_write(addr, fpstartinstrs)
	mu.emu_start(addr, addr+len(fpstartinstrs)-4)
	mu.mem_unmap(addr, 0x1000)

	malloc_ptr = MEM
	def malloc(sz):
		global malloc_ptr
		o = malloc_ptr
		malloc_ptr += (sz + 15) & ~15
		return o
	MAGIC = 0x49434653

	def copy_in(buf):
		pointer = malloc(len(buf))
		mu.mem_write(pointer, buf)
		return pointer

	def dump_regs():
		values = []
		for i in range(28):
			values.append(('X%d' % i, mu.reg_read(UC_ARM64_REG_X0+i)))
		values.append(('X29', mu.reg_read(UC_ARM64_REG_X29)))
		values.append(('X30', mu.reg_read(UC_ARM64_REG_X30)))
		values.append(('SP', mu.reg_read(UC_ARM64_REG_SP)))
		values.append(('PC', mu.reg_read(UC_ARM64_REG_PC)))

	message_data = struct.pack('<QQ', MAGIC, 1600) + b''.join(struct.pack('<Q', 0) for i in range(512))
	message = copy_in(message_data)


	message_struct_data = struct.pack('<QQ', message, len(message_data))
	message_struct = copy_in(message_struct_data)

	RET0 = 0x25F44002A8 
	ipc_vtable = copy_in(b''.join(struct.pack('<Q', 0x800000000+i*8) for i in range(512)))
	ipc_object = copy_in(struct.pack('<QQ', ipc_vtable, 0))

	target_vtable = copy_in(b''.join(struct.pack('<Q', 0x900000000+i*8) for i in range(512)))
	target_object = copy_in(struct.pack('<QQ', target_vtable, 0))

	bufbuf = malloc(0x1000)

	outbuf = malloc(0x1000)
	from collections import defaultdict
	names = defaultdict(set)

	def hook_code(uc, address, size, user_data):
		global message_buffer
		global actual_result_thing
		i = next(md.disasm(bytes(mu.mem_read(address, 4)), address))
		if i.mnemonic == 'cmp' and i.op_str.endswith(', x9') and len(actual_result_thing['ininterfaces']) == 1 and actual_result_thing['ininterfaces'][0] is None:
			assert i.op_str == 'x8, x9'
			x9 = mu.reg_read(UC_ARM64_REG_X9)
			mu.reg_write(UC_ARM64_REG_X8, x9)
			mu.reg_write(UC_ARM64_REG_NZCV, 0b0100)
			actual_result_thing['ininterfaces'][0] = demangle([a for a,b in stables if b == x9][0])
		if i.mnemonic == 'bl':
			if mu.reg_read(UC_ARM64_REG_X3) != current_cmd and mu.reg_read(UC_ARM64_REG_X1) == target_object and mu.reg_read(UC_ARM64_REG_X2) == ipc_object:
				if 0:
					lines.append("  %X: %s %s (%X, %X, %X, %X)" % (address, i.mnemonic, i.op_str, 
						mu.reg_read(UC_ARM64_REG_X0),
						mu.reg_read(UC_ARM64_REG_X1),
						mu.reg_read(UC_ARM64_REG_X2),
						mu.reg_read(UC_ARM64_REG_X3),
						))
				message_buffer = mu.reg_read(UC_ARM64_REG_X3)
				pfuncname = 'CmifProcessFunctionTableGetterImpl__%s__::Process_%s' % (str(demangled_interface_name), str(cmd_name))
				names[int(i.op_str[1:],16)].add(pfuncname)

	buffercount = None
	def PrepareForProcess():
		existing.append(current_cmd)
		global buffercount
		global actual_result_thing
		arg = mu.reg_read(UC_ARM64_REG_X1)
		desc = [dword(arg+i) for i in range(0,0x90,4)]
		buffercount = desc[0x18//4]
		bytes_in = desc[8//4] - 0x10
		bytes_out = desc[0x10//4] - 0x10
		actual_result_thing = {
			'inbytes': bytes_in,
			'outbytes': bytes_out,
			'ininterfaces': [None]*desc[0x1c//4],
			'outinterfaces': [None]*desc[0x20//4],
			'inhandles': desc[0x4C//4:0x4C//4+desc[0x24//4]],
			'outhandles': desc[0x6C//4:0x6C//4+desc[0x28//4]],
			'buffers': desc[0x2c//4:0x2c//4+desc[0x18//4]],
			'pid': desc[0] == 1,

			'lr': mu.reg_read(UC_ARM64_REG_LR),
		}
		assert desc[0] in (0,1)
		if True:
			for i in ['outinterfaces', 'inhandles', 'outhandles', 'buffers', 'pid', 'ininterfaces']:
				if not actual_result_thing[i]:
					del actual_result_thing[i]

		mu.reg_write(UC_ARM64_REG_X0, 0)
		mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
		return True #desc[0x20/4] != 0
			
		#return False

	def OverwriteClientProcessId():
		o = mu.reg_read(UC_ARM64_REG_X1)
		mu.mem_write(o, struct.pack('<Q', 0))
		mu.reg_write(UC_ARM64_REG_X0, 0)
		mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
		return True

	def GetBuffers():
		outptr = mu.reg_read(UC_ARM64_REG_X1)
		for i in range(outptr, outptr+buffercount*0x10, 0x10):
			# necessary for 'nn::nifm::detail::IGeneralService' cmd 26
			mu.mem_write(i, struct.pack('<QQ', bufbuf, 0x1000))
		mu.mem_write(bufbuf, struct.pack('<Q', 1))
		mu.reg_write(UC_ARM64_REG_X0, 0)
		mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
		return True

	def GetInNativeHandles():
		mu.reg_write(UC_ARM64_REG_X0, 0)
		mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
		return True

	def BeginPreparingForReply():
		o = mu.reg_read(UC_ARM64_REG_X1)
		mu.mem_write(o, struct.pack('<QQ', outbuf, 0x1000))
		mu.reg_write(UC_ARM64_REG_X0, 0)
		mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
		return True
	
	def EndPreparingForReply():
		mu.reg_write(UC_ARM64_REG_X0, 0)
		mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
		return False

	def SetBuffers():
		mu.reg_write(UC_ARM64_REG_X0, 0)
		mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
		return True

	def SetOutNativeHandles():
		mu.reg_write(UC_ARM64_REG_X0, 0)
		mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
		return True

	def SetOutObjects():
		value = struct.unpack('<Q', mu.mem_read(mu.reg_read(UC_ARM64_REG_X1)+8, 8))[0]
		actual_result_thing['outinterfaces'][0] = demangle([a for a,b in stables if b == value][0])	
		mu.reg_write(UC_ARM64_REG_X0, 0)
		mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
		return False

	def BeginPreparingForErrorReply():
		return False


	def GetInObjects():
		mu.reg_write(UC_ARM64_REG_X0, 0)
		mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
		return True


	def dword(ptr):
		return struct.unpack('I', mu.mem_read(ptr, 4))[0]
	def qword(ptr):
		return struct.unpack('Q', mu.mem_read(ptr, 8))[0]

	funcs = {
		0x800000000: PrepareForProcess,           # PrepareForProcess(nn::sf::cmif::CmifMessageMetaInfo const&)
		0x800000008: OverwriteClientProcessId,    # OverwriteClientProcessId(ulong *)
		0x800000010: GetBuffers,                  # GetBuffers(nn::sf::detail::PointerAndSize *)
		0x800000018: GetInNativeHandles,          # GetInNativeHandles(nn::sf::NativeHandle *)
		0x800000020: GetInObjects,                # GetInObjects(nn::sf::cmif::server::CmifServerObjectInfo *)
		0x800000028: BeginPreparingForReply,      # BeginPreparingForReply(nn::sf::detail::PointerAndSize *)
		0x800000030: SetBuffers,                  # SetBuffers(nn::sf::detail::PointerAndSize *)
		0x800000038: SetOutObjects,               # SetOutObjects(nn::sf::cmif::server::CmifServerObjectInfo *)
		0x800000040: SetOutNativeHandles,         # SetOutNativeHandles(nn::sf::NativeHandle *)
		0x800000048: BeginPreparingForErrorReply, # BeginPreparingForErrorReply(nn::sf::detail::PointerAndSize *,ulong)
		0x800000050: EndPreparingForReply,        # EndPreparingForReply(void)
	}

	mu.hook_add(UC_HOOK_CODE, hook_code)

	for INTERFACE_NAME, stable in stables:
		try:
			TABLEFUNC = qword(stable)
			qword(TABLEFUNC)
		except UcError:
			continue
		if 'CmifDomainServerObject' in INTERFACE_NAME: continue
		#if 'ICommonStateGetter' not in INTERFACE_NAME: continue


		demangled_interface_name = demangle(INTERFACE_NAME)
		if 'nn::sf::hipc::detail::IHipcManager' == demangled_interface_name: continue
		vtaddr = None
		vtcandidates = []
		for sym in symbols:
			if demangled_interface_name.split('::')[-1] not in sym.name: continue
			if demangle(sym.name).startswith((
				'vtable for nn::sf::detail::ObjectImplFactoryWithStatelessAllocator<nn::sf::impl::detail::ImplTemplateBase<' + demangled_interface_name + ',',
				'vtable for nn::sf::detail::ObjectImplFactoryWithStatefulAllocator<nn::sf::impl::detail::ImplTemplateBase<' + demangled_interface_name + ',',
				'vtable for nn::sf::UnmanagedServiceObject<' + demangled_interface_name + ',',
				'vtable for nn::sf::UnmanagedServiceObjectByPointer<' + demangled_interface_name + ',')):

				vtaddr = ADDRESS + sym.value
				while not (ADDRESS <= struct.unpack('<Q', mu.mem_read(vtaddr, 8))[0] < ADDRESS + text_size):
					vtaddr += 8
					assert vtaddr < ADDRESS + sym.value + 0x40
				 
				vtname = demangled_interface_name
				if 'nn::sf::detail::EmplacedImplHolder<' in demangle(sym.name):
					vtname = demangled_interface_name + '_IpcObj_' + demangle(sym.name).split('nn::sf::detail::EmplacedImplHolder<')[1].split('>')[0]
				elif 'nn::sf::detail::StdSmartPtrHolder<std::__1::unique_ptr<' in demangle(sym.name):
					vtname = demangled_interface_name + '_IpcPtrObj_' + demangle(sym.name).split('nn::sf::detail::StdSmartPtrHolder<std::__1::unique_ptr<')[1].split('>')[0].split(',')[0]
				elif 'nn::sf::UnmanagedServiceObject<' in demangle(sym.name):
					vtname = demangled_interface_name + '_IpcService_' + demangle(sym.name).split('nn::sf::UnmanagedServiceObject<')[1].split('>')[0].split(', ')[1]

				vtcandidates.append((vtaddr, vtname))

		existing = []

		for current_cmd in ALL_COMMAND_IDS:
			if '_ZN2nn2sf4cmif6server6detail30CmifProcessFunctionTableGetterINS_5fssrv2sf11IFileSystemEvE7s_TableE' in INTERFACE_NAME and current_cmd == 7: continue

			cmd_name = None #namesdb.get(demangle(INTERFACE_NAME), {}).get(str(current_cmd), {}).get('name')
			if cmd_name is None:
				cmd_name = 'Cmd%d' % (current_cmd,)
			else:
				cmd_name = 'Cmd%d_%s' % (current_cmd, cmd_name)
			actual_result_thing = None
			lines = []
			message_data = struct.pack('<QQ', MAGIC, current_cmd)
			mu.mem_write(message, message_data)
			mu.mem_write(message_struct, message_struct_data)

			mu.reg_write(UC_ARM64_REG_X0, target_object)
			mu.reg_write(UC_ARM64_REG_X1, ipc_object)
			mu.reg_write(UC_ARM64_REG_X2, message_struct)
			for i in range(3, 28):
				mu.reg_write(UC_ARM64_REG_X0+i, 0)
			mu.reg_write(UC_ARM64_REG_X30, 0x700000000)
			mu.reg_write(UC_ARM64_REG_SP, STACK + STACK_SIZE)
			mu.reg_write(UC_ARM64_REG_PC, TABLEFUNC)

			message_buffer = None
			while True:
				try:
					#help(mu.emu_start)
					mu.emu_start(mu.reg_read(UC_ARM64_REG_PC), 0, count=1)
				except UcError as e:
					pc = mu.reg_read(UC_ARM64_REG_PC)
					if pc in funcs:
						if funcs[pc]():
							continue
					elif 0x900000000 <= pc < 0xA00000000:
						#print' vcall: pc=%X lr=%X' % (pc, mu.reg_read(UC_ARM64_REG_LR))
						actual_result_thing['vt'] = pc - 0x900000000
						if actual_result_thing.get('outinterfaces'):
#							break
							mu.reg_write(UC_ARM64_REG_X0, 0)
							mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
							continue


#						existing.append(current_cmd)
					elif pc == 0x700000000:
						error = mu.reg_read(UC_ARM64_REG_X0)
						if False:
							if error != 0: # and error != 0x1BA0A:
								#for i in lines: print i
								print('#  error = 0x%X') % error
					else:
						dump_regs()
						exit(0)
				else:
					if mu.reg_read(UC_ARM64_REG_PC) != 0:

						continue
				if actual_result_thing:
					line = '      ' + ('%d: ' % current_cmd).ljust(7) + '{'
					parts = []
					for my_vtaddr, vtname in vtcandidates:
						if my_vtaddr is not None and 'vt' in actual_result_thing:
							actual_result_thing['func'] = struct.unpack('<Q', mu.mem_read(my_vtaddr + actual_result_thing['vt'], 8))[0]
							names[actual_result_thing['func']].add(vtname + '::' + cmd_name)

					#for i in ['vt', 'lr', 'func', 'inbytes', 'outbytes', 'buffers', 'inhandles', 'outhandles', 'outinterfaces', 'pid', 'ininterfaces']:
					for i in ['inbytes', 'outbytes', 'buffers', 'inhandles', 'outhandles', 'outinterfaces', 'pid', 'ininterfaces']:
						if i not in actual_result_thing: continue
						#if i in ('vt', 'lr'): continue
						v = actual_result_thing[i]
						if isinstance(v, list):
							v = repr(v)
						else:
							if v >= 10:
								v = '0x%X' % v
							else:
								v = str(v)
							v = v.rjust(5)
						parts.append('"%s": %s' % (i, v))
					line += ', '.join(parts)

					line += '},'
				break

	if True:
		for k, v in sorted(names.items()):
			if len(v) != 1:
				print ('#', hex(k), v)
			else:
				print('MakeName(0x%X,%r)' % (k, str(list(v)[0])))
