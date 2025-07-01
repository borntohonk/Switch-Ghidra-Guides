# Copyright (c) 2026 borntohonk
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import struct
from typing import Optional, NamedTuple, List, Tuple, Dict, Any
import util
import json
try:
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

class Npdm:
    def __init__(self, data: bytes):
        if len(data) < 0x80:
            raise ValueError("NPDM data too short (need at least 128 bytes)")

        self.data = data

        # ────────────────────────────────────────────────
        #  NPDM Header (0x00–0x80)
        # ────────────────────────────────────────────────

        hdr = data[0x00:0x80]

        self.magic              = hdr[0x00:0x04].decode("ascii", errors="replace")
        self.signature_key_gen  = int.from_bytes(hdr[0x04:0x08], "little")
        self.flags              = hdr[0x0C]
        self.main_thread_prio   = hdr[0x0E]
        self.main_thread_core   = hdr[0x0F]
        self.system_resource_size = int.from_bytes(hdr[0x14:0x18], "little")
        self.version            = int.from_bytes(hdr[0x18:0x1C], "little")
        self.main_stack_size    = int.from_bytes(hdr[0x1C:0x20], "little")
        self.name               = hdr[0x20:0x30].decode("ascii", errors="ignore").rstrip("\x00")
        self.product_code       = hdr[0x30:0x40].decode("ascii", errors="ignore").rstrip("\x00")
        self.aci0_offset        = int.from_bytes(hdr[0x70:0x74], "little")
        self.aci0_size          = int.from_bytes(hdr[0x74:0x78], "little")
        self.acid_offset        = int.from_bytes(hdr[0x78:0x7C], "little")
        self.acid_size          = int.from_bytes(hdr[0x7C:0x80], "little")
        
        # Parse MMU flags into individual components
        self.is_64_bit          = bool(self.flags & 0x01)
        self.address_space_type = (self.flags >> 1) & 0x07
        self.optimize_memory_allocation = bool((self.flags >> 4) & 0x01)
        self.disable_device_addr_space_merge = bool((self.flags >> 5) & 0x01)
        self.enable_alias_region_extra_size = bool((self.flags >> 6) & 0x01)
        self.prevent_code_reads = bool((self.flags >> 7) & 0x01)

        # ────────────────────────────────────────────────
        #  ACID (Access Control Information Descriptor)
        # ────────────────────────────────────────────────

        acid_start = self.acid_offset
        acid_end   = acid_start + self.acid_size
        if acid_end > len(data):
            raise ValueError("ACID section exceeds file size")

        acid = data[acid_start:acid_end]

        self.acid_signature_1_raw = acid[0x0:0x100]
        self.acid_signature_2_raw = acid[0x100:0x200]

        self.acid_magic         = acid[0x200:0x204].decode("ascii", errors="replace")
        self.acid_size_field    = int.from_bytes(acid[0x204:0x208], "little")
        self.acid_version       = acid[0x208] if len(acid) > 0x208 else 0
        self.acid_flags         = acid[0x20C:0x210]
        
        # Parse ACID flags into individual components
        acid_flags_int = int.from_bytes(self.acid_flags, "little")
        self.acid_is_retail     = bool(acid_flags_int & 0x01)
        self.acid_unqualified_approval = bool((acid_flags_int >> 1) & 0x01)
        self.acid_pool_partition = (acid_flags_int >> 2) & 0x0F
        self.acid_load_browser_core_dll = bool((acid_flags_int >> 7) & 0x01)
        
        self.program_id_min     = acid[0x210:0x218][::-1].hex()
        self.program_id_max     = acid[0x218:0x220][::-1].hex()
        

        self.fac_offset         = int.from_bytes(acid[0x220:0x224], "little")
        self.fac_size           = int.from_bytes(acid[0x224:0x228], "little")
        self.sac_offset         = int.from_bytes(acid[0x228:0x22C], "little")
        self.sac_size           = int.from_bytes(acid[0x22C:0x230], "little")
        self.kc_offset          = int.from_bytes(acid[0x230:0x234], "little")
        self.kc_size            = int.from_bytes(acid[0x234:0x238], "little")

        self.fac_data = acid[self.fac_offset : self.fac_offset + self.fac_size]
        self.sac_data = acid[self.sac_offset : self.sac_offset + self.sac_size]
        self.kc_data  = acid[self.kc_offset  : self.kc_offset  + self.kc_size]
        
        # Parse FAC for Content Owner IDs and Save Data Owner IDs
        self.fac_version = acid[self.fac_offset] if self.fac_size > 0 else 0
        self.fac_coi_count = acid[self.fac_offset + 1] if self.fac_size > 1 else 0
        self.fac_sdoi_count = acid[self.fac_offset + 2] if self.fac_size > 2 else 0
        self.fac_perms = int.from_bytes(acid[self.fac_offset + 4 : self.fac_offset + 12], "little") if self.fac_size > 4 else 0
        self.fac_coi_min = int.from_bytes(acid[self.fac_offset + 0xC : self.fac_offset + 0x14], "little") if self.fac_size > 0xC else 0
        self.fac_coi_max = int.from_bytes(acid[self.fac_offset + 0x14 : self.fac_offset + 0x1C], "little") if self.fac_size > 0x14 else 0
        self.fac_sdoi_min = int.from_bytes(acid[self.fac_offset + 0x1C : self.fac_offset + 0x24], "little") if self.fac_size > 0x1C else 0
        self.fac_sdoi_max = int.from_bytes(acid[self.fac_offset + 0x24 : self.fac_offset + 0x2C], "little") if self.fac_size > 0x24 else 0

        # ────────────────────────────────────────────────
        #  ACI0 (Access Control Information)
        # ────────────────────────────────────────────────

        aci0_start = self.aci0_offset
        aci0_end   = aci0_start + self.aci0_size
        if aci0_end > len(data):
            raise ValueError("ACI0 section exceeds file size")

        aci0 = data[aci0_start:aci0_end]

        self.aci0_magic     = aci0[0x00:0x04].decode("ascii", errors="replace")
        self.program_id     = aci0[0x10:0x18][::-1].hex()

        self.aci0_fac_offset = int.from_bytes(aci0[0x20:0x24], "little")
        self.aci0_fac_size   = int.from_bytes(aci0[0x24:0x28], "little")
        self.aci0_sac_offset = int.from_bytes(aci0[0x28:0x2C], "little")
        self.aci0_sac_size   = int.from_bytes(aci0[0x2C:0x30], "little")
        self.aci0_kc_offset  = int.from_bytes(aci0[0x30:0x34], "little")
        self.aci0_kc_size    = int.from_bytes(aci0[0x34:0x38], "little")

        self.aci0_fac_data = aci0[self.aci0_fac_offset : self.aci0_fac_offset + self.aci0_fac_size]
        self.aci0_sac_data = aci0[self.aci0_sac_offset : self.aci0_sac_offset + self.aci0_sac_size]
        self.aci0_kc_data  = aci0[self.aci0_kc_offset  : self.aci0_kc_offset  + self.aci0_kc_size]
        
        # Parse ACI0 FAH for Content Owner IDs and Save Data Owner IDs [5.0.0+]
        self.aci0_fah_version = aci0[self.aci0_fac_offset] if self.aci0_fac_size > 0 else 0
        self.aci0_fah_perms = int.from_bytes(aci0[self.aci0_fac_offset + 4 : self.aci0_fac_offset + 12], "little") if self.aci0_fac_size > 4 else 0
        self.aci0_coi_offset = int.from_bytes(aci0[self.aci0_fac_offset + 0xC : self.aci0_fac_offset + 0x10], "little") if self.aci0_fac_size > 0xC else 0
        self.aci0_coi_size = int.from_bytes(aci0[self.aci0_fac_offset + 0x10 : self.aci0_fac_offset + 0x14], "little") if self.aci0_fac_size > 0x10 else 0
        self.aci0_sdoi_offset = int.from_bytes(aci0[self.aci0_fac_offset + 0x14 : self.aci0_fac_offset + 0x18], "little") if self.aci0_fac_size > 0x14 else 0
        self.aci0_sdoi_size = int.from_bytes(aci0[self.aci0_fac_offset + 0x18 : self.aci0_fac_offset + 0x1C], "little") if self.aci0_fac_size > 0x18 else 0

    def __str__(self) -> str:
            lines = [
                "NPDM:",
                f"  Magic            : {self.magic}",
                f"  Name             : {self.name.strip()}",
                f"  Version          : {self.version}",
                f"  Main thread prio : {self.main_thread_prio}",
                f"  Main thread core : {self.main_thread_core}",
                f"  Main stack size  : 0x{self.main_stack_size:X}",
                f"  Program ID (ACI0): {self.program_id}",
                f"  ACID range       : {self.program_id_min} - {self.program_id_max}",
                "",
                "→ Sections present:",
                f"  FsAccessControl  : {len(self.fac_data):3d} bytes",
                f"  ServiceAccess    : {len(self.sac_data):3d} bytes",
                f"  KernelCaps       : {len(self.kc_data):3d} bytes",
            ]
            return "\n".join(lines)

def NpdmInfoPrint(npdm, npdm_lines, kac_lines, sac_lines, fac_lines):
    load_npdm = Npdm(npdm)

    acid_signature_1 = load_npdm.acid_signature_1_raw
    acid_signature_2 = load_npdm.acid_signature_2_raw
    sig1_npdm = acid_signature_1.hex().upper() if hasattr(acid_signature_2, 'hex') else str(acid_signature_2).upper()
    sig2_npdm = acid_signature_2.hex().upper() if hasattr(acid_signature_2, 'hex') else str(acid_signature_2).upper()
    npdm_lines.append(f'NPDM:')
    npdm_lines.append(f'    Magic:                          {load_npdm.magic}')
    npdm_lines.append(f'    MMU Flags:                      0x{load_npdm.flags:02X}')
    npdm_lines.append(f'        Is 64-bit:                  {load_npdm.is_64_bit}')
    npdm_lines.append(f'        Address Space Type:         {load_npdm.address_space_type}')
    npdm_lines.append(f'        Optimize Memory Alloc:      {load_npdm.optimize_memory_allocation}')
    npdm_lines.append(f'        Disable DevAddr Space Merge: {load_npdm.disable_device_addr_space_merge}')
    npdm_lines.append(f'        Enable Alias Region Extra:  {load_npdm.enable_alias_region_extra_size}')
    npdm_lines.append(f'        Prevent Code Reads:         {load_npdm.prevent_code_reads}')
    npdm_lines.append(f'    Main Thread Priority:           {load_npdm.main_thread_prio}')
    npdm_lines.append(f'    Default CPU ID:                 {load_npdm.main_thread_core}')
    major = (load_npdm.version >> 26) & 0x3F
    minor = (load_npdm.version >> 20) & 0x3F
    micro = (load_npdm.version >> 16) & 0xF
    build = load_npdm.version & 0xFFFF
    npdm_lines.append(f'    Version:                        {major}.{minor}.{micro}-{build} ({load_npdm.version})')
    npdm_lines.append(f'    Main Thread Stack Size:         0x{load_npdm.main_stack_size:X}')
    if load_npdm.system_resource_size:
        npdm_lines.append(f'    System Resource Size:           0x{load_npdm.system_resource_size:X}')
    npdm_lines.append(f'    Title Name:                     {load_npdm.name}')
    if load_npdm.product_code:
        npdm_lines.append(f'    Product Code:                   {load_npdm.product_code}')
    npdm_lines.append(f'    Signature Key Generation:       {load_npdm.signature_key_gen}')
    npdm_lines.append(f'    ACID:')
    npdm_lines.append(f'        Magic:                      {load_npdm.acid_magic}')
    npdm_lines.append(f'        Version:                    {load_npdm.acid_version}')
    npdm_lines.append(f'        Size:                       0x{load_npdm.acid_size_field:X}')
    util.print_split_hex('        Signature:',            sig1_npdm, npdm_lines)
    util.print_split_hex('        Header Modulus:',       sig2_npdm, npdm_lines)
    npdm_lines.append(f'        Is Retail:                  {load_npdm.acid_is_retail}')
    npdm_lines.append(f'        Unqualified Approval:       {load_npdm.acid_unqualified_approval}')
    npdm_lines.append(f'        Pool Partition:             {load_npdm.acid_pool_partition}')
    npdm_lines.append(f'        Load Browser Core DLL:      {load_npdm.acid_load_browser_core_dll}')
    npdm_lines.append(f'        Title ID Range:             {load_npdm.program_id_min}-{load_npdm.program_id_max}') 
    npdm_lines.append(f'    ACI0:')
    npdm_lines.append(f'        Magic:                      {load_npdm.aci0_magic}')
    npdm_lines.append(f'        Title ID:                   {load_npdm.program_id}')

    interpret_kernel_capabilities(load_npdm.kc_data, kac_lines)
    sac_print(sac_lines, acid_sac=load_npdm.sac_data, acid_size=len(load_npdm.sac_data), aci0_sac=load_npdm.aci0_sac_data, aci0_size=len(load_npdm.aci0_sac_data))
    print_fac_fah_from_bytes(load_npdm.fac_data, load_npdm.aci0_fac_data, fac_lines)

class SacEntry:
    def __init__(self, service: str, valid: bool = True):
        self.service: str = service
        self.valid: bool = valid
        self.next: Optional[SacEntry] = None

    def __repr__(self):
        return f"SacEntry({self.service!r}, valid={self.valid})"


def wildcard_match(pattern: str, text: str) -> bool:
    """Simple wildcard matching with * character."""
    p_idx = 0
    t_idx = 0
    star_idx = -1
    match_idx = 0
    
    while t_idx < len(text):
        if p_idx < len(pattern) and (pattern[p_idx] == '?' or pattern[p_idx] == text[t_idx]):
            p_idx += 1
            t_idx += 1
        elif p_idx < len(pattern) and pattern[p_idx] == '*':
            star_idx = p_idx
            match_idx = t_idx
            p_idx += 1
        elif star_idx != -1:
            p_idx = star_idx + 1
            match_idx += 1
            t_idx = match_idx
        else:
            return False
    
    while p_idx < len(pattern) and pattern[p_idx] == '*':
        p_idx += 1
    
    return p_idx == len(pattern)


def verify_rsa2048_signature(data: bytes, signature: bytes, modulus: bytes) -> bool:
    """Verify RSA-2048-PSS signature (if cryptography library available)."""
    if not HAS_CRYPTO:
        return None  # Cannot verify without library
    
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        
        # Construct RSA public key from modulus and standard exponent (65537)
        e = 65537
        n = int.from_bytes(modulus, 'big')
        public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
        
        # Verify PSS signature
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    except Exception:
        return None


def sac_matches(allowed_list: Optional[List[SacEntry]], service: str) -> bool:
    """Check if service matches against allowed list (with wildcard support)."""
    if not allowed_list:
        return True
    return any(wildcard_match(entry.service, service) for entry in allowed_list)

def sac_parse(
    sac: bytes,
    sac_size: int,
    r_host: Optional[List[SacEntry]] = None,
    r_accesses: Optional[List[SacEntry]] = None,
) -> Tuple[List[SacEntry], List[SacEntry]]:
    hosts: List[SacEntry] = []
    accesses: List[SacEntry] = []

    ofs = 0
    while ofs < sac_size:
        if ofs + 1 > sac_size:
            break

        ctrl = sac[ofs]
        ofs += 1

        service_len = (ctrl & 0xF) + 1

        if ofs + service_len > sac_size:
            break

        service_name_bytes = sac[ofs : ofs + service_len]
        ofs += service_len

        try:
            service_name = service_name_bytes.decode('ascii').rstrip('\x00')
        except UnicodeDecodeError:
            service_name = service_name_bytes.hex()
            valid = False
        else:
            if ctrl & 0x80:
                valid = sac_matches(r_host, service_name)
            else:
                valid = sac_matches(r_accesses, service_name)

        entry = SacEntry(service=service_name, valid=valid)

        if ctrl & 0x80:
            hosts.append(entry)
        else:
            accesses.append(entry)

    return hosts, accesses

def sac_print(lines_to_append_to, acid_sac: bytes, acid_size: int, aci0_sac: bytes, aci0_size: int) -> None:
    acid_hosts, acid_accesses = sac_parse(acid_sac, acid_size)
    aci0_hosts, aci0_accesses = sac_parse(aci0_sac, aci0_size, r_host=acid_hosts, r_accesses=acid_accesses)

    lines_to_append_to.append("    Service Access Control:")
    if not aci0_hosts:
        pass
    else:
        lines_to_append_to.append("        Hosts:")
        for i, entry in enumerate(aci0_hosts):
            prefix = "                                    "
            suffix = "" if entry.valid else " (Invalid)"
            lines_to_append_to.append(f"{prefix}{entry.service:<16}{suffix}")

    lines_to_append_to.append("        Accesses:")
    if not aci0_accesses:
        pass
    else:
        for i, entry in enumerate(aci0_accesses):
            prefix = "                                    "
            suffix = "" if entry.valid else " (Invalid)"
            lines_to_append_to.append(f"{prefix}{entry.service:<16}{suffix}")

MAX_FS_PERM_RW   = 0x27
MAX_FS_PERM_BOOL = 0x1B

FS_PERM_MASK_NODEBUG = 0xBFFFFFFFFFFFFFFF

class FsPerm(NamedTuple):
    name: str
    mask: int

FS_PERMISSIONS_RW = [
    FsPerm("MountContentType2",       0x8000000000000801),
    FsPerm("MountContentType5",       0x8000000000000801),
    FsPerm("MountContentType3",       0x8000000000000801),
    FsPerm("MountContentType4",       0x8000000000000801),
    FsPerm("MountContentType6",       0x8000000000000801),
    FsPerm("MountContentType7",       0x8000000000000801),
    FsPerm("Unknown (0x6)",           0x8000000000000000),
    FsPerm("ContentStorageAccess",    0x8000000000000800),
    FsPerm("ImageDirectoryAccess",    0x8000000000001000),
    FsPerm("MountBisType28",          0x8000000000000084),
    FsPerm("MountBisType29",          0x8000000000000080),
    FsPerm("MountBisType30",          0x8000000000008080),
    FsPerm("MountBisType31",          0x8000000000008080),
    FsPerm("Unknown (0xD)",           0x8000000000000080),
    FsPerm("SdCardAccess",            0xC000000000200000),
    FsPerm("GameCardUser",            0x8000000000000010),
    FsPerm("SaveDataAccess0",         0x8000000000040020),
    FsPerm("SystemSaveDataAccess0",   0x8000000000000028),
    FsPerm("SaveDataAccess1",         0x8000000000000020),
    FsPerm("SystemSaveDataAccess1",   0x8000000000000020),
    FsPerm("BisPartition0",           0x8000000000010082),
    FsPerm("BisPartition10",          0x8000000000010080),
    FsPerm("BisPartition20",          0x8000000000010080),
    FsPerm("BisPartition21",          0x8000000000010080),
    FsPerm("BisPartition22",          0x8000000000010080),
    FsPerm("BisPartition23",          0x8000000000010080),
    FsPerm("BisPartition24",          0x8000000000010080),
    FsPerm("BisPartition25",          0x8000000000010080),
    FsPerm("BisPartition26",          0x8000000000000080),
    FsPerm("BisPartition27",          0x8000000000000084),
    FsPerm("BisPartition28",          0x8000000000000084),
    FsPerm("BisPartition29",          0x8000000000000080),
    FsPerm("BisPartition30",          0x8000000000000080),
    FsPerm("BisPartition31",          0x8000000000000080),
    FsPerm("BisPartition32",          0x8000000000000080),
    FsPerm("Unknown (0x23)",          0xC000000000200000),
    FsPerm("GameCard_System",         0x8000000000000100),
    FsPerm("MountContent_System",     0x8000000000100008),
    FsPerm("HostAccess",              0xC000000000400000),
]

FS_PERMISSIONS_BOOL = [
    FsPerm("BisCache",                0x8000000000000080),
    FsPerm("EraseMmc",                0x8000000000000080),
    FsPerm("GameCardCertificate",     0x8000000000000010),
    FsPerm("GameCardIdSet",           0x8000000000000010),
    FsPerm("GameCardDriver",          0x8000000000000200),
    FsPerm("GameCardAsic",            0x8000000000000200),
    FsPerm("SaveDataCreate",          0x8000000000002020),
    FsPerm("SaveDataDelete0",         0x8000000000000060),
    FsPerm("SystemSaveDataCreate0",   0x8000000000000028),
    FsPerm("SystemSaveDataCreate1",   0x8000000000000020),
    FsPerm("SaveDataDelete1",         0x8000000000004028),
    FsPerm("SaveDataIterators0",      0x8000000000000060),
    FsPerm("SaveDataIterators1",      0x8000000000004020),
    FsPerm("SaveThumbnails",          0x8000000000020000),
    FsPerm("PosixTime",               0x8000000000000400),
    FsPerm("SaveDataExtraData",       0x8000000000004060),
    FsPerm("GlobalMode",              0x8000000000080000),
    FsPerm("SpeedEmulation",          0x8000000000080000),
    FsPerm("(NULL)",                  0),
    FsPerm("PaddingFiles",            0xC000000000800000),
    FsPerm("SaveData_Debug",          0xC000000001000000),
    FsPerm("SaveData_SystemManagement", 0xC000000002000000),
    FsPerm("Unknown (0x16)",          0x8000000004000000),
    FsPerm("Unknown (0x17)",          0x8000000008000000),
    FsPerm("Unknown (0x18)",          0x8000000010000000),
    FsPerm("Unknown (0x19)",          0x8000000000000800),
    FsPerm("Unknown (0x1A)",          0x8000000000004020),
]

class Fac:
    def __init__(self, version: int, perms: int):
        self.version = version
        self.perms   = perms


class Fah:
    def __init__(self, version: int, perms: int):
        self.version = version
        self.perms   = perms

def print_fac_fah_from_bytes(
    fac_bytes: bytes,
    fah_bytes: bytes,
    lines_to_append_to,
    label: str = "    Filesystem Access Control"
) -> None:
    if len(fac_bytes) < 24 or len(fah_bytes) < 24:
        print("Error: one or both buffers too short (< 24 bytes)")
        return

    fac_version = int.from_bytes(fac_bytes[0x00:0x04], "little")
    fac_perms   = int.from_bytes(fac_bytes[0x08:0x18], "little") << 32

    fah_version = int.from_bytes(fah_bytes[0x00:0x04], "little")
    fah_perms   = int.from_bytes(fah_bytes[0x08:0x18], "little") << 32

    effective_perms = fac_perms & fah_perms

    lines_to_append_to.append(f"{label}:")
    
    if fac_version == fah_version:
        lines_to_append_to.append(f"        Version:                    {fac_version}")
    else:
        lines_to_append_to.append(f"        Control Version (FAC/ACID): {fac_version}")
        lines_to_append_to.append(f"        Header Version  (FAH/ACI0): {fah_version}")

    lines_to_append_to.append(f"        Raw Permissions:            0x{effective_perms:016x}")

    lines_to_append_to.append("        RW Permissions:")
    rw_count = 0
    for perm in FS_PERMISSIONS_RW:
        if perm.mask & effective_perms:
            rw_count += 1
            if perm.mask & (effective_perms & FS_PERM_MASK_NODEBUG):
                lines_to_append_to.append(f"                                    {perm.name}")
            else:
                lines_to_append_to.append(f"                                    {perm.name:<32} [DEBUG ONLY]")

    if rw_count == 0:
        lines_to_append_to.append("        (none)")

    lines_to_append_to.append("\n        Boolean Permissions:")
    bool_count = 0
    for perm in FS_PERMISSIONS_BOOL:
        if perm.mask & effective_perms:
            bool_count += 1
            if perm.mask & (effective_perms & FS_PERM_MASK_NODEBUG):
                lines_to_append_to.append(f"                                    {perm.name}")
            else:
                lines_to_append_to.append(f"                                    {perm.name:<32} [DEBUG ONLY]")

    if bool_count == 0:
        lines_to_append_to.append("        (none)")

def parse_acid_flags(flags_bytes: bytes) -> tuple[int, int]:
    if len(flags_bytes) != 4:
        raise ValueError("ACID flags must be exactly 4 bytes")
        
    flags = int.from_bytes(flags_bytes, "little")
    
    is_retail      = flags & 1
    pool_partition = (flags >> 2) & 0x0F
    
    return is_retail, pool_partition

svc_names = [
    ('0x00', 'svcUnknown'), ('0x01', 'svcSetHeapSize'), ('0x02', 'svcSetMemoryPermission'), ('0x03', 'svcSetMemoryAttribute'), ('0x04', 'svcMapMemory'), 
    ('0x05', 'svcUnmapMemory'), ('0x06', 'svcQueryMemory'), ('0x07', 'svcExitProcess'), ('0x08', 'svcCreateThread'), ('0x09', 'svcStartThread'), 
    ('0x0a', 'svcExitThread'), ('0x0b', 'svcSleepThread'), ('0x0c', 'svcGetThreadPriority'), ('0x0d', 'svcSetThreadPriority'), ('0x0e', 'svcGetThreadCoreMask'), 
    ('0x0f', 'svcSetThreadCoreMask'), ('0x10', 'svcGetCurrentProcessorNumber'), ('0x11', 'svcSignalEvent'), ('0x12', 'svcClearEvent'), ('0x13', 'svcMapSharedMemory'), 
    ('0x14', 'svcUnmapSharedMemory'), ('0x15', 'svcCreateTransferMemory'), ('0x16', 'svcCloseHandle'), ('0x17', 'svcResetSignal'), ('0x18', 'svcWaitSynchronization'), 
    ('0x19', 'svcCancelSynchronization'), ('0x1a', 'svcArbitrateLock'), ('0x1b', 'svcArbitrateUnlock'), ('0x1c', 'svcWaitProcessWideKeyAtomic'), ('0x1d', 'svcSignalProcessWideKey'), 
    ('0x1e', 'svcGetSystemTick'), ('0x1f', 'svcConnectToNamedPort'), ('0x20', 'svcSendSyncRequestLight'), ('0x21', 'svcSendSyncRequest'), ('0x22', 'svcSendSyncRequestWithUserBuffer'), 
    ('0x23', 'svcSendAsyncRequestWithUserBuffer'), ('0x24', 'svcGetProcessId'), ('0x25', 'svcGetThreadId'), ('0x26', 'svcBreak'), ('0x27', 'svcOutputDebugString'), 
    ('0x28', 'svcReturnFromException'), ('0x29', 'svcGetInfo'), ('0x2a', 'svcFlushEntireDataCache'), ('0x2b', 'svcFlushDataCache'), ('0x2c', 'svcMapPhysicalMemory'), 
    ('0x2d', 'svcUnmapPhysicalMemory'), ('0x2e', 'svcGetDebugFutureThreadInfo'), ('0x2f', 'svcGetLastThreadInfo'), ('0x30', 'svcGetResourceLimitLimitValue'), ('0x31', 'svcGetResourceLimitCurrentValue'), 
    ('0x32', 'svcSetThreadActivity'), ('0x33', 'svcGetThreadContext3'), ('0x34', 'svcWaitForAddress'), ('0x35', 'svcSignalToAddress'), ('0x36', 'svcSynchronizePreemptionState'), 
    ('0x37', 'svcGetResourceLimitPeakValue'), ('0x38', 'svcUnknown'), ('0x39', 'svcCreateIoPool'), ('0x3a', 'svcCreateIoRegion'), ('0x3b', 'svcUnknown'), 
    ('0x3c', 'svcKernelDebug'), ('0x3d', 'svcChangeKernelTraceState'), ('0x3e', 'svcUnknown'), ('0x3f', 'svcUnknown'), ('0x40', 'svcCreateSession'), ('0x41', 'svcAcceptSession'), 
    ('0x42', 'svcReplyAndReceiveLight'), ('0x43', 'svcReplyAndReceive'), ('0x44', 'svcReplyAndReceiveWithUserBuffer'), ('0x45', 'svcCreateEvent'), ('0x46', 'svcMapIoRegion'), 
    ('0x47', 'svcUnmapIoRegion'), ('0x48', 'svcMapPhysicalMemoryUnsafe'), ('0x49', 'svcUnmapPhysicalMemoryUnsafe'), ('0x4a', 'svcSetUnsafeLimit'), ('0x4b', 'svcCreateCodeMemory'), ('0x4c', 'svcControlCodeMemory'), 
    ('0x4d', 'svcSleepSystem'), ('0x4e', 'svcReadWriteRegister'), ('0x4f', 'svcSetProcessActivity'), ('0x50', 'svcCreateSharedMemory'), ('0x51', 'svcMapTransferMemory'), ('0x52', 'svcUnmapTransferMemory'), 
    ('0x53', 'svcCreateInterruptEvent'), ('0x54', 'svcQueryPhysicalAddress'), ('0x55', 'svcQueryMemoryMapping'), ('0x56', 'svcCreateDeviceAddressSpace'), ('0x57', 'svcAttachDeviceAddressSpace'), 
    ('0x58', 'svcDetachDeviceAddressSpace'), ('0x59', 'svcMapDeviceAddressSpaceByForce'), ('0x5a', 'svcMapDeviceAddressSpaceAligned'), ('0x5b', 'svcMapDeviceAddressSpace'), ('0x5c', 'svcUnmapDeviceAddressSpace'), 
    ('0x5d', 'svcInvalidateProcessDataCache'), ('0x5e', 'svcStoreProcessDataCache'), ('0x5f', 'svcFlushProcessDataCache'), ('0x60', 'svcDebugActiveProcess'), ('0x61', 'svcBreakDebugProcess'), 
    ('0x62', 'svcTerminateDebugProcess'), ('0x63', 'svcGetDebugEvent'), ('0x64', 'svcContinueDebugEvent'), ('0x65', 'svcGetProcessList'), ('0x66', 'svcGetThreadList'), ('0x67', 'svcGetDebugThreadContext'), 
    ('0x68', 'svcSetDebugThreadContext'), ('0x69', 'svcQueryDebugProcessMemory'), ('0x6a', 'svcReadDebugProcessMemory'), ('0x6b', 'svcWriteDebugProcessMemory'), ('0x6c', 'svcSetHardwareBreakPoint'), 
    ('0x6d', 'svcGetDebugThreadParam'), ('0x6e', 'svcUnknown'), ('0x6f', 'svcGetSystemInfo'), ('0x70', 'svcCreatePort'), ('0x71', 'svcManageNamedPort'), 
    ('0x72', 'svcConnectToPort'), ('0x73', 'svcSetProcessMemoryPermission'), ('0x74', 'svcMapProcessMemory'), ('0x75', 'svcUnmapProcessMemory'), ('0x76', 'svcQueryProcessMemory'), 
    ('0x77', 'svcMapProcessCodeMemory'), ('0x78', 'svcUnmapProcessCodeMemory'), ('0x79', 'svcCreateProcess'), ('0x7a', 'svcStartProcess'), ('0x7b', 'svcTerminateProcess'), 
    ('0x7c', 'svcGetProcessInfo'), ('0x7d', 'svcCreateResourceLimit'), ('0x7e', 'svcSetResourceLimitLimitValue'), ('0x7f', 'svcCallSecureMonitor'), ('0x80', 'svcSetMemoryAttribute2'), 
    ('0x81', 'svcUnknown'), ('0x82', 'svcUnknown'), ('0x83', 'svcUnknown'), ('0x84', 'svcUnknown'), ('0x85', 'svcUnknown'), 
    ('0x86', 'svcUnknown'), ('0x87', 'svcUnknown'), ('0x88', 'svcUnknown'), ('0x89', 'svcUnknown'), ('0x8a', 'svcUnknown'), 
    ('0x8b', 'svcUnknown'), ('0x8c', 'svcUnknown'), ('0x8d', 'svcUnknown'), ('0x8e', 'svcUnknown'), ('0x8f', 'svcUnknown'), 
    ('0x90', 'svcMapInsecurePhysicalMemory'), ('0x91', 'svcUnmapInsecurePhysicalMemory'), ('0x92', 'svcUnknown'), ('0x93', 'svcUnknown'), ('0x94', 'svcUnknown'), 
    ('0x95', 'svcUnknown'), ('0x96', 'svcUnknown'), ('0x97', 'svcUnknown'), ('0x98', 'svcUnknown'), ('0x99', 'svcUnknown'), 
    ('0x9a', 'svcUnknown'), ('0x9b', 'svcUnknown'), ('0x9c', 'svcUnknown'), ('0x9d', 'svcUnknown'), ('0x9e', 'svcUnknown'), 
    ('0x9f', 'svcUnknown'), ('0xa0', 'svcUnknown'), ('0xa1', 'svcUnknown'), ('0xa2', 'svcUnknown'), ('0xa3', 'svcUnknown'), 
    ('0xa4', 'svcUnknown'), ('0xa5', 'svcUnknown'), ('0xa6', 'svcUnknown'), ('0xa7', 'svcUnknown'), ('0xa8', 'svcUnknown'), 
    ('0xa9', 'svcUnknown'), ('0xaa', 'svcUnknown'), ('0xab', 'svcUnknown'), ('0xac', 'svcUnknown'), ('0xad', 'svcUnknown'), 
    ('0xae', 'svcUnknown'), ('0xaf', 'svcUnknown'), ('0xb0', 'svcUnknown'), ('0xb1', 'svcUnknown'), ('0xb2', 'svcUnknown'), 
    ('0xb3', 'svcUnknown'), ('0xb4', 'svcUnknown'), ('0xb5', 'svcUnknown'), ('0xb6', 'svcUnknown'), ('0xb7', 'svcUnknown'), 
    ('0xb8', 'svcUnknown'), ('0xb9', 'svcUnknown'), ('0xba', 'svcUnknown'), ('0xbb', 'svcUnknown'), ('0xbc', 'svcUnknown'), 
    ('0xbd', 'svcUnknown'), ('0xbe', 'svcUnknown'), ('0xbf', '(null)')
]

SVC_LOOKUP = {int(hex_str, 16): name for hex_str, name in svc_names}

def interpret_kernel_capabilities(cap_bytes: bytes, lines: list[str]):
    """
    Parse Kernel Capability descriptors and append formatted lines to `lines`.
    Follows hactool-style ordering and conditional printing.
    """
    if len(cap_bytes) % 4 != 0:
        lines.append("        Warning: Kernel caps length not multiple of 4 — skipping parsing")
        return

    num_words = len(cap_bytes) // 4
    caps = struct.unpack('<' + 'I' * num_words, cap_bytes)

    data = {
        'has_kern_flags': False,
        'lowest_prio': 0,
        'highest_prio': 0,
        'min_core': 0,
        'max_core': 0,

        'allowed_svcs': [],

        'has_app_type': False,
        'app_type': 'Unknown',

        'has_handle_size': False,
        'handle_size': 0,

        'has_kernel_version': False,
        'kernel_version': 0,

        'has_debug': False,
        'allow_debug': False,
        'force_debug': False,
        'force_debug_prod': False,
        
        'memory_regions': [],  # [8.0.0+]
    }

    i = 0
    while i < num_words:
        val = caps[i]
        k = 0
        while k < 32 and (val & (1 << k)):
            k += 1

        trailing_mask = (1 << k) - 1
        if (val & trailing_mask) != trailing_mask:
            i += 1
            continue

        if k == 32:
            i += 1
            continue

        if k == 3:
            data['highest_prio']  = (val >>  4) & 0x3F
            data['lowest_prio'] = (val >> 10) & 0x3F
            data['min_core']     = (val >> 16) & 0xFF
            data['max_core']     = (val >> 24) & 0xFF
            data['has_kern_flags'] = True

        elif k == 4:
            group = (val >> 29) & 0x7
            mask  = (val >>  5) & 0xFFFFFF
            base = group * 24
            for bit in range(24):
                if mask & (1 << bit):
                    svc_id = base + bit
                    if svc_id > 0xBF:
                        continue
                    name = SVC_LOOKUP.get(svc_id, f"svcUnknown_{svc_id:02X}")
                    data['allowed_svcs'].append((svc_id, name))

        elif k == 6:
            if i + 1 >= num_words:
                i += 1
                continue
            val2 = caps[i + 1]
            k2 = 0
            while k2 < 32 and (val2 & (1 << k2)):
                k2 += 1
            if k2 != 6:
                i += 1
                continue

            i += 1

        elif k == 7:
            begin_addr = (val >> 8) & 0xFFFFFF
            lines.append(f"{indent}Io Memory Map:              0x{begin_addr:06X}")

        elif k == 11:
            int0 = (val >> 12) & 0x3FF
            int1 = (val >> 22) & 0x3FF
            int0_str = f"{int0}" if int0 != 0x3FF else "None"
            int1_str = f"{int1}" if int1 != 0x3FF else "None"
            lines.append(f"{indent}Enable Interrupts:          {int0_str}, {int1_str}")

        elif k == 10:  # MemoryRegionMap [8.0.0+]
            region_types = {0: 'NoMapping', 1: 'KernelTraceBuffer', 2: 'OnMemoryBootImage', 3: 'DTB'}
            for region_idx in range(3):
                region_type = (val >> (11 + 7 * region_idx)) & 0x3F
                is_ro = bool((val >> (11 + 7 * region_idx + 6)) & 1)
                type_name = region_types.get(region_type, f'Unknown({region_type})')
                if region_type != 0:  # Only show if not NoMapping
                    data['memory_regions'].append((region_idx, type_name, is_ro))

        elif k == 13:
            program_type = (val >> 14) & 0x7
            types = {0: 'System Module', 1: 'Application', 2: 'Applet'}
            data['app_type'] = types.get(program_type, f"Unknown ({program_type})")
            data['has_app_type'] = True

        elif k == 14:
            minor = (val >> 15) & 0xF
            major = (val >> 19) & 0x1FFF
            data['kernel_version'] = (major << 4) | minor
            data['has_kernel_version'] = True

        elif k == 15:
            data['handle_size'] = (val >> 16) & 0x3FF
            data['has_handle_size'] = True

        elif k == 16:
            data['allow_debug']     = bool((val >> 17) & 1)
            data['force_debug_prod']= bool((val >> 18) & 1)
            data['force_debug']     = bool((val >> 19) & 1) if not data['force_debug_prod'] else False
            data['has_debug'] = True

        i += 1

    lines.append("    Kernel Access Control:")

    indent = "        "

    if data['has_kern_flags']:
        lines.append(f"{indent}Lowest Allowed Priority:    {data['lowest_prio']}")
        lines.append(f"{indent}Highest Allowed Priority:   {data['highest_prio']}")
        lines.append(f"{indent}Lowest Allowed CPU ID:      {data['min_core']}")
        lines.append(f"{indent}Highest Allowed CPU ID:     {data['max_core']}")

    if data['allowed_svcs']:
        data['allowed_svcs'].sort(key=lambda x: x[0])
        max_len = max(len(name) for _, name in data['allowed_svcs'])
        col_width = max_len + 2

        first = True
        label = "Allowed SVCs:"
        label_pad = indent + label.ljust(28)

        for svc_id, name in data['allowed_svcs']:
            padded = name.ljust(col_width)
            if first:
                prefix = label_pad
                first = False
            else:
                prefix = " " * len(label_pad)
            lines.append(f"{prefix}{padded}(0x{svc_id:02X})")

    if data['has_app_type']:
        lines.append(f"{indent}Application Type:           {data['app_type']}")

    if data['has_handle_size']:
        lines.append(f"{indent}Handle Table Size:          {data['handle_size']}")

    if data['has_kernel_version']:
        lines.append(f"{indent}Minimum Kernel Version:     {data['kernel_version']}")

    lines.append(f"{indent}Allow Debug:                {data['allow_debug']}")
    lines.append(f"{indent}Force Debug (Prod):         {data['force_debug_prod']}")
    lines.append(f"{indent}Force Debug:                {data['force_debug']}")
    
    if data['memory_regions']:
        lines.append(f"{indent}Memory Regions:             ")
        for region_idx, type_name, is_ro in data['memory_regions']:
            access = "RO" if is_ro else "RW"
            lines.append(f"{indent}                            Region {region_idx}: {type_name} ({access})")


def npdm_to_json(npdm: Npdm) -> Dict[str, Any]:
    """Convert NPDM object to JSON-serializable dictionary."""
    
    # Parse version components
    major = (npdm.version >> 26) & 0x3F
    minor = (npdm.version >> 20) & 0x3F
    micro = (npdm.version >> 16) & 0xF
    build = npdm.version & 0xFFFF
    
    # Map address space type
    address_space_names = {
        0x00: "AddressSpace32Bit",
        0x01: "AddressSpace64BitOld",
        0x02: "AddressSpace32BitNoReserved",
        0x03: "AddressSpace64Bit"
    }
    
    # Build JSON structure
    npdm_json = {
        "name": npdm.name,
        "title_id": npdm.program_id,
        "title_id_range_min": npdm.program_id_min,
        "title_id_range_max": npdm.program_id_max,
        "main_thread_priority": npdm.main_thread_prio,
        "default_cpu_id": npdm.main_thread_core,
        "main_thread_stack_size": f"0x{npdm.main_stack_size:X}",
        "version": f"{major}.{minor}.{micro}-{build}",
        "is_64_bit": npdm.is_64_bit,
        "address_space_type": address_space_names.get(npdm.address_space_type, f"Unknown({npdm.address_space_type})"),
        "optimize_memory_allocation": npdm.optimize_memory_allocation,
        "disable_device_address_space_merge": npdm.disable_device_addr_space_merge,
        "enable_alias_region_extra_size": npdm.enable_alias_region_extra_size,
        "prevent_code_reads": npdm.prevent_code_reads,
        "signature_key_generation": npdm.signature_key_gen,
        "system_resource_size": f"0x{npdm.system_resource_size:X}" if npdm.system_resource_size else "0x0",
    }
    
    # ACID section
    acid_json = {
        "is_retail": npdm.acid_is_retail,
        "unqualified_approval": npdm.acid_unqualified_approval,
        "pool_partition": npdm.acid_pool_partition,
        "load_browser_core_dll": npdm.acid_load_browser_core_dll,
    }
    
    # Try to verify signature if crypto available
    if HAS_CRYPTO:
        try:
            acid_data = npdm.data[npdm.acid_offset + 0x100 : npdm.acid_offset + 0x100 + npdm.acid_size_field]
            sig_valid = verify_rsa2048_signature(acid_data, npdm.acid_signature_1_raw, npdm.acid_signature_2_raw)
            if sig_valid is not None:
                acid_json["signature_valid"] = sig_valid
        except:
            pass
    
    npdm_json["acid"] = acid_json
    
    # FAC (Filesystem Access Control) section
    fac_json = {
        "permissions": f"0x{npdm.fac_perms:016X}",
    }
    if npdm.fac_coi_count > 0:
        fac_json["content_owner_id_range"] = {
            "min": f"0x{npdm.fac_coi_min:016X}",
            "max": f"0x{npdm.fac_coi_max:016X}"
        }
    if npdm.fac_sdoi_count > 0:
        fac_json["save_data_owner_id_range"] = {
            "min": f"0x{npdm.fac_sdoi_min:016X}",
            "max": f"0x{npdm.fac_sdoi_max:016X}"
        }
    npdm_json["filesystem_access_control"] = fac_json
    
    # SAC (Service Access Control) section
    acid_hosts, acid_accesses = sac_parse(npdm.sac_data, len(npdm.sac_data))
    aci0_hosts, aci0_accesses = sac_parse(npdm.aci0_sac_data, len(npdm.aci0_sac_data), 
                                          r_host=acid_hosts, r_accesses=acid_accesses)
    
    sac_json = {
        "hosts": [entry.service for entry in aci0_hosts],
        "accesses": [entry.service for entry in aci0_accesses]
    }
    npdm_json["service_access_control"] = sac_json
    
    # KAC (Kernel Access Control) section
    kac_capabilities = []
    
    if len(npdm.kc_data) % 4 == 0:
        num_words = len(npdm.kc_data) // 4
        caps = struct.unpack('<' + 'I' * num_words, npdm.kc_data)
        
        for cap_val in caps:
            if cap_val == 0xFFFFFFFF:
                continue
            
            # Determine capability type
            k = 0
            while k < 32 and (cap_val & (1 << k)):
                k += 1
            
            if k >= 32:
                continue
            
            trailing_mask = (1 << k) - 1
            if (cap_val & trailing_mask) != trailing_mask:
                continue
            
            # Parse based on type
            if k == 3:  # ThreadInfo
                kac_capabilities.append({
                    "type": "thread_info",
                    "lowest_priority": (cap_val >> 10) & 0x3F,
                    "highest_priority": (cap_val >> 4) & 0x3F,
                    "min_core": (cap_val >> 16) & 0xFF,
                    "max_core": (cap_val >> 24) & 0xFF
                })
            elif k == 4:  # EnableSystemCalls
                group = (cap_val >> 29) & 0x7
                mask = (cap_val >> 5) & 0xFFFFFF
                syscalls = []
                for bit in range(24):
                    if mask & (1 << bit):
                        svc_id = group * 24 + bit
                        if svc_id <= 0xBF:
                            syscalls.append(f"0x{svc_id:02X}")
                kac_capabilities.append({
                    "type": "enable_syscalls",
                    "syscalls": syscalls
                })
            elif k == 13:  # MiscParams
                program_type = (cap_val >> 14) & 0x7
                type_names = {0: 'System', 1: 'Application', 2: 'Applet'}
                kac_capabilities.append({
                    "type": "misc_params",
                    "program_type": type_names.get(program_type, f"Unknown({program_type})")
                })
            elif k == 14:  # KernelVersion
                minor = (cap_val >> 15) & 0xF
                major = (cap_val >> 19) & 0x1FFF
                kac_capabilities.append({
                    "type": "min_kernel_version",
                    "version": f"{major}.{minor}"
                })
            elif k == 15:  # HandleTableSize
                kac_capabilities.append({
                    "type": "handle_table_size",
                    "size": (cap_val >> 16) & 0x3FF
                })
            elif k == 16:  # MiscFlags
                kac_capabilities.append({
                    "type": "misc_flags",
                    "allow_debug": bool((cap_val >> 17) & 1),
                    "force_debug_prod": bool((cap_val >> 18) & 1),
                    "force_debug": bool((cap_val >> 19) & 1)
                })
    
    npdm_json["kernel_capabilities"] = kac_capabilities
    
    return npdm_json


def export_npdm_json(npdm_data: bytes, output_path: str) -> bool:
    """Export NPDM to JSON file."""
    try:
        npdm = Npdm(npdm_data)
        npdm_dict = npdm_to_json(npdm)
        
        with open(output_path, 'w') as f:
            json.dump(npdm_dict, f, indent=2)
        
        return True
    except Exception as e:
        print(f"Error exporting NPDM to JSON: {e}")
        return False