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
import hashlib
from pathlib import Path
import hfs0
from crypto import decrypt_cbc
from key_sources import KeySources

MAGIC_HEAD = 0x44414548  # "HEAD"


class Hfs0Partition:
    """HFS0 partition entry in XCI."""
    pass


class XciHeader:
    """XCI header structure (mirrors hactool's xci_header_t)."""
    SIZE = 0x200  # 512 bytes
    
    def __init__(self, data):
        if len(data) < self.SIZE:
            raise ValueError(f"XCI header too small: {len(data)} < {self.SIZE}")
        
        # 0x000-0x100: RSA signature (256 bytes for RSA-2048)
        self.header_sig = data[0x0:0x100]
        
        # 0x100-0x200: Header data
        magic, secure_offset, _0x108 = struct.unpack('<3I', data[0x100:0x10C])
        
        if magic != MAGIC_HEAD:
            raise ValueError(f"Invalid XCI magic: 0x{magic:08X}, expected 0x{MAGIC_HEAD:08X}")
        
        self.magic = magic
        self.secure_offset = secure_offset
        self._0x108 = _0x108
        self._0x10C = data[0x10C]
        self.cart_type = data[0x10D]  # Cartridge size
        self._0x10E = data[0x10E]
        self._0x10F = data[0x10F]
        self._0x110 = int.from_bytes(data[0x110:0x118], 'little')
        self.cart_size = int.from_bytes(data[0x118:0x120], 'little')  # Actual size = (cart_size + 1) << 20
        
        # IV (reversed)
        self.reversed_iv = data[0x120:0x130]
        self.iv = bytes(reversed(self.reversed_iv))
        
        # HFS0 partition info
        self.hfs0_offset = int.from_bytes(data[0x130:0x138], 'little')
        self.hfs0_header_size = int.from_bytes(data[0x138:0x140], 'little')
        self.hfs0_header_hash = data[0x140:0x160]  # SHA256
        self.crypto_header_hash = data[0x160:0x180]  # SHA256 of encrypted gamecard info
        
        self._0x180 = struct.unpack('<I', data[0x180:0x184])[0]
        self._0x184 = struct.unpack('<I', data[0x184:0x188])[0]
        self._0x188 = struct.unpack('<I', data[0x188:0x18C])[0]
        self._0x18C = struct.unpack('<I', data[0x18C:0x190])[0]
        
        # Encrypted data
        self.encrypted_data = data[0x190:0x200]
    
    def get_signature_hex(self):
        """Get RSA signature as hex string."""
        return self.header_sig.hex()
    
    def verify_hfs0_header_hash(self, hfs0_data, offset):
        """Verify SHA256 hash of HFS0 header.
        
        Args:
            hfs0_data: Full XCI binary data
            offset: Offset to HFS0 header within data
            
        Returns:
            tuple: (is_valid, computed_hash)
        """
        # Read HFS0 header data
        if offset + self.hfs0_header_size > len(hfs0_data):
            return False, None
        
        hfs0_header_data = hfs0_data[offset:offset + self.hfs0_header_size]
        computed_hash = hashlib.sha256(hfs0_header_data).digest()
        
        return computed_hash == self.hfs0_header_hash, computed_hash
    
    def verify_crypto_header_hash(self, decrypted_data):
        """Verify SHA256 hash of decrypted gamecard info.
        
        Args:
            decrypted_data: Decrypted header data (at least 0x70 bytes)
            
        Returns:
            tuple: (is_valid, computed_hash)
        """
        if not decrypted_data or len(decrypted_data) < 0x70:
            return False, None
        
        computed_hash = hashlib.sha256(decrypted_data[:0x70]).digest()
        return computed_hash == self.crypto_header_hash, computed_hash


class XciGamecardInfo:
    """Decrypted gamecard info from XCI (mirrors hactool's xci_gamecard_info_t)."""
    def __init__(self, data, offset=0):
        if len(data) < offset + 0x60:
            raise ValueError("Decrypted header data too small")
        
        self.firmware_version = int.from_bytes(data[offset+0x0:offset+0x8], 'little')
        self.access_control = struct.unpack('<I', data[offset+0x8:offset+0xC])[0]
        self.read_time_wait_1 = struct.unpack('<I', data[offset+0xC:offset+0x10])[0]
        self.read_time_wait_2 = struct.unpack('<I', data[offset+0x10:offset+0x14])[0]
        self.write_time_wait_1 = struct.unpack('<I', data[offset+0x14:offset+0x18])[0]
        self.write_time_wait_2 = struct.unpack('<I', data[offset+0x18:offset+0x1C])[0]
        self.firmware_mode = struct.unpack('<I', data[offset+0x1C:offset+0x20])[0]
        self.cup_version = struct.unpack('<I', data[offset+0x20:offset+0x24])[0]
        self.compatibility_type = data[offset+0x24]
        self._0x25 = data[offset+0x25]
        self._0x26 = data[offset+0x26]
        self._0x27 = data[offset+0x27]
        self.update_partition_hash = data[offset+0x28:offset+0x30]
        self.cup_title_id = int.from_bytes(data[offset+0x30:offset+0x38], 'little')


class XciContext:
    """XCI processing context (mirrors hactool's xci_ctx_t)."""
    def __init__(self, xci_data, output_path=None, xci_key=None, auto_load_keys=True, verify_hashes=False, verbose=False):
        self.xci_data = xci_data
        self.output_path = Path(output_path) if output_path else None
        self.xci_key = xci_key
        self.verify_hashes = verify_hashes
        self.verbose = verbose
        
        # Auto-load XCI key from key_sources if not provided
        if not xci_key and auto_load_keys:
            try:
                ks = KeySources()
                self.xci_key = ks.xci_header_key
                if verbose:
                    print("Loaded XCI header key from key_sources")
            except Exception as e:
                if verbose:
                    print(f"Could not load XCI key from key_sources: {e}")
        
        # Parse XCI header
        self.header = XciHeader(xci_data[0:0x200])
        
        # Initialize partitions
        self.partitions = {
            'update': None,
            'normal': None,
            'secure': None,
            'logo': None
        }
        
        self.has_decrypted_header = False
        self.decrypted_header = None
        self.gamecard_info = None
        self.crypto_hash_valid = None
        
        # Try to decrypt header if key available
        if self.xci_key:
            self._decrypt_header(self.xci_key)
        
        # Parse root partition (always unencrypted)
        self._parse_root_partition()
    
    def _decrypt_header(self, xci_key):
        """Decrypt XCI header data using XCI key."""
        try:
            # Decrypt 0x70 bytes of header data
            decrypted = decrypt_cbc(self.header.encrypted_data, xci_key, self.header.iv)
            self.decrypted_header = decrypted[:0x70]
            self.has_decrypted_header = True
            
            # Parse gamecard info from decrypted data
            self.gamecard_info = XciGamecardInfo(self.decrypted_header, offset=0x10)
            
            # Verify crypto header hash if requested
            if self.verify_hashes:
                is_valid, computed = self.header.verify_crypto_header_hash(self.decrypted_header)
                self.crypto_hash_valid = is_valid
                if self.verbose:
                    if is_valid:
                        print("✓ Crypto header hash valid")
                    else:
                        print(f"✗ Crypto header hash invalid")
                        print(f"  Expected: {self.header.crypto_header_hash.hex()}")
                        print(f"  Got:      {computed.hex() if computed else 'None'}")
            
            if self.verbose:
                print("Successfully decrypted XCI header")
        except Exception as e:
            if self.verbose:
                print(f"Failed to decrypt XCI header: {e}")
            self.has_decrypted_header = False
    
    def _parse_root_partition(self):
        """Parse root HFS0 partition from XCI."""
        try:
            root_ctx = hfs0.Hfs0Context(
                self.xci_data,
                offset=self.header.hfs0_offset,
                verbose=self.verbose,
                name="rootpt"
            )
            
            # Verify HFS0 header hash if requested
            if self.verify_hashes:
                is_valid, computed = self.header.verify_hfs0_header_hash(self.xci_data, self.header.hfs0_offset)
                if self.verbose:
                    if is_valid:
                        print("✓ HFS0 header hash valid")
                    else:
                        print(f"✗ HFS0 header hash invalid")
                        print(f"  Expected: {self.header.hfs0_header_hash.hex()}")
                        print(f"  Got:      {computed.hex() if computed else 'None'}")
            
            if self.verbose:
                print(f"Root partition: {root_ctx.header.num_files} files")
            
            # Extract partition files
            for i in range(root_ctx.header.num_files):
                file_name = root_ctx.get_file_name(i)
                if not file_name:
                    continue
                
                if file_name == "update" and self.partitions['update'] is None:
                    self._parse_partition(file_name, root_ctx, i)
                elif file_name == "normal" and self.partitions['normal'] is None:
                    self._parse_partition(file_name, root_ctx, i)
                elif file_name == "secure" and self.partitions['secure'] is None:
                    self._parse_partition(file_name, root_ctx, i)
                elif file_name == "logo" and self.partitions['logo'] is None:
                    self._parse_partition(file_name, root_ctx, i)
        except Exception as e:
            if self.verbose:
                print(f"Error parsing root partition: {e}")
    
    def _parse_partition(self, partition_name, root_ctx, file_index):
        """Parse a single partition from root HFS0."""
        entry = root_ctx.get_entry(file_index)
        if not entry:
            return
        
        # Calculate absolute offset to partition HFS0
        partition_offset = self.header.hfs0_offset + root_ctx.header_size + entry.offset
        
        try:
            partition_ctx = hfs0.Hfs0Context(
                self.xci_data,
                offset=partition_offset,
                verbose=self.verbose,
                name=partition_name
            )
            self.partitions[partition_name] = partition_ctx
            
            if self.verbose:
                print(f"Partition '{partition_name}': {partition_ctx.header.num_files} files")
        except Exception as e:
            if self.verbose:
                print(f"Error parsing partition '{partition_name}': {e}")


def xci_get_cartridge_type(cart_type):
    """Get human-readable cartridge type string."""
    cart_types = {
        0xFA: "1GB",
        0xF8: "2GB",
        0xF0: "4GB",
        0xE0: "8GB",
        0xE1: "16GB",
        0xE2: "32GB"
    }
    return cart_types.get(cart_type, f"Unknown (0x{cart_type:02X})")


def xci_get_real_cart_size(cart_size):
    """Calculate real cartridge size from cart_size field."""
    return (cart_size + 1) << 20  # Size in bytes = (cart_size + 1) << 20


def xci_print_partition(partition_ctx):
    """Print partition information."""
    if partition_ctx is None:
        print("  [Not Present]")
        return
    
    print(f"  Files: {partition_ctx.header.num_files}")
    hfs0.hfs0_list_files(partition_ctx)


def xci_print(ctx):
    """Print XCI information."""
    print("\nXCI Information:")
    print(f"  Magic: 0x{ctx.header.magic:08X}")
    print(f"  Cartridge Type: {xci_get_cartridge_type(ctx.header.cart_type)}")
    print(f"  Cartridge Size: 0x{xci_get_real_cart_size(ctx.header.cart_size):X} bytes ({xci_get_real_cart_size(ctx.header.cart_size) // (1024**3)}GB)")
    
    print(f"  HFS0 Root Partition Offset: 0x{ctx.header.hfs0_offset:X}")
    print(f"  HFS0 Header Size: 0x{ctx.header.hfs0_header_size:X}")
    
    if ctx.has_decrypted_header and ctx.gamecard_info:
        print("\nDecrypted Gamecard Info:")
        print(f"  Firmware Version: 0x{ctx.gamecard_info.firmware_version:016X}")
        print(f"  Compatibility Type: {ctx.gamecard_info.compatibility_type}")
        print(f"  Cup Title ID: 0x{ctx.gamecard_info.cup_title_id:016X}")
    
    print("\nRoot Partition (Files):")
    for partition_name in ['update', 'normal', 'secure', 'logo']:
        if ctx.partitions[partition_name]:
            print(f"\n{partition_name.upper()} Partition:")
            xci_print_partition(ctx.partitions[partition_name])


def xci_extract_partition(partition_ctx, output_dir):
    """Extract all files from a partition."""
    if partition_ctx is None:
        return
    
    for i in range(partition_ctx.header.num_files):
        hfs0.hfs0_extract_file(partition_ctx, i, output_dir)


def xci_process(xci_data, output_path=None, xci_key=None, auto_load_keys=True, verify_hashes=False, list_only=False, print_info=False):
    """Process XCI - main entry point (mirrors hactool's xci_process).
    
    Args:
        xci_data: Binary data containing XCI
        output_path: Path to extract files to
        xci_key: XCI header key (optional, auto-loaded if available)
        auto_load_keys: Auto-load key from key_sources
        verify_hashes: Verify SHA256 hashes (optional validation)
        list_only: Only list files, don't extract
        print_info: Print header information
        
    Returns:
        XciContext: Parsing context
    """
    # Create context
    ctx = XciContext(
        xci_data,
        output_path=output_path,
        xci_key=xci_key,
        auto_load_keys=auto_load_keys,
        verify_hashes=verify_hashes,
        verbose=print_info
    )
    
    # Print info if requested
    if print_info:
        xci_print(ctx)
    
    # List only - print partition contents
    if list_only:
        for partition_name in ['update', 'normal', 'secure', 'logo']:
            if ctx.partitions[partition_name]:
                hfs0.hfs0_list_files(ctx.partitions[partition_name])
        return ctx
    
    # Extract if output path provided
    if output_path:
        output_dir = Path(output_path)
        
        # Extract each partition
        for partition_name in ['update', 'normal', 'secure', 'logo']:
            if ctx.partitions[partition_name]:
                partition_dir = output_dir / partition_name
                partition_dir.mkdir(parents=True, exist_ok=True)
                xci_extract_partition(ctx.partitions[partition_name], partition_dir)
    
    return ctx
