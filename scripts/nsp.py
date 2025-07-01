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

"""
NSP (Nintendo Submission Package) file handler.

NSP files are PFS0 containers that hold the complete package for a title,
including:
- One or more NCA files (content archives)
- .tik files (tickets) containing titlekeys for decryption
- .cert files (certificates)
- Potentially metadata files

This module provides utilities for:
1. Extracting NSP contents (delegated to pfs0)
2. Finding and parsing .tik files to obtain titlekeys
3. Identifying the primary NCA (usually the largest file)
4. Extracting and parsing CNMT (Content Meta) data
"""

import struct
import tempfile
from pathlib import Path
import re
from typing import Optional, Dict, List, Union
from dataclasses import dataclass

import pfs0
import util
from nca import Nca, SectionExtractor, NcaHeaderOnly, save_section
from romfs import extract_file_from_romfs
from cnmt import parse_cnmt
import sys
import traceback

def process_nsp_info_in_memory(nsp_path: str, nacp_module, verbose_timing=False):
    """
    Process NSP entirely in memory without writing to disk.
    Uses targeted file reads instead of loading the entire NSP upfront.
    """

    # Read only the base PFS0 header (16 bytes) to get entry count and string table size
    with open(nsp_path, 'rb') as f:
        base_header = f.read(pfs0.PFS0_HEADER_SIZE_BASE)

    # Parse just the counts without validation
    num_files, string_table_size, _ = struct.unpack('<III', base_header[4:16])
    full_header_size = (pfs0.PFS0_HEADER_SIZE_BASE
                        + num_files * pfs0.PFS0_FILE_ENTRY_SIZE
                        + string_table_size)

    # Now read the full header and parse it properly
    with open(nsp_path, 'rb') as f:
        full_header_data = f.read(full_header_size)

    header = pfs0.Pfs0Header(full_header_data)

    # Parse all entries and build name→entry map
    strtab = full_header_data[header.string_table_offset:header.string_table_offset + header.string_table_size]

    name_to_entry = {}
    for i in range(header.num_files):
        pos = header.entry_table_offset + (i * pfs0.PFS0_FILE_ENTRY_SIZE)
        chunk = full_header_data[pos:pos + pfs0.PFS0_FILE_ENTRY_SIZE]
        entry = pfs0.Pfs0FileEntry.from_bytes(chunk)

        null_pos = strtab.find(b'\x00', entry.string_offset)
        if null_pos == -1:
            null_pos = len(strtab)
        filename = strtab[entry.string_offset:null_pos].decode('utf-8', errors='replace')
        name_to_entry[filename] = entry


    # Helper: read a specific file directly from disk by name
    def read_file(filename):
        entry = name_to_entry.get(filename)
        if entry is None:
            return None
        abs_offset = header.data_offset + entry.offset
        with open(nsp_path, 'rb') as f:
            f.seek(abs_offset)
            return f.read(entry.size)

    # Extract titlekey from ticket
    titlekey = None
    tik_name = next((n for n in name_to_entry if n.endswith('.tik')), None)
    if tik_name:
        tik_data = read_file(tik_name)
        if tik_data and len(tik_data) >= TITLEKEY_OFFSET + TITLEKEY_SIZE:
            titlekey = tik_data[TITLEKEY_OFFSET:TITLEKEY_OFFSET + TITLEKEY_SIZE]

    # Find CNMT NCA and largest NCA (by entry size, no I/O)
    nca_names = [n for n in name_to_entry if n.endswith('.nca')]
    if not nca_names:
        raise ValueError("No NCA files found in NSP")

    cnmt_nca_name = next((n for n in nca_names if n.endswith('.cnmt.nca')), None)
    if cnmt_nca_name is None:
        raise ValueError("No CNMT NCA found in NSP")

    largest_name = max(
        (n for n in nca_names if n != cnmt_nca_name),
        key=lambda n: name_to_entry[n].size,
        default=None
    )

    # Fetch and parse CNMT NCA
    cnmt_nca_data = read_file(cnmt_nca_name)
    cnmt_nca_obj = Nca(cnmt_nca_data, titlekey=titlekey)

    section0_data = cnmt_nca_obj.decrypted_sections[0][
        cnmt_nca_obj.fsheaders[0].content_start:
        cnmt_nca_obj.fsheaders[0].content_end
    ]

    cnmt_data = section0_data[0x60:]
    cnmt_obj = parse_cnmt(cnmt_data)
    cnmt_obj.print_info(verbose=True)

    # Find Control NCA — scan small NCAs only, skip the large program NCA
    control_nca_data = None

    for name in nca_names:
        if name in (cnmt_nca_name, largest_name):
            continue
        file_data = read_file(name)
        if file_data is None:
            continue
        try:
            nca_hdr = Nca(file_data)
            if nca_hdr.content_type == "Control":
                control_nca_data = file_data
                break
        except Exception:
            continue

    # Last resort: check primary NCA
    if control_nca_data is None and largest_name is not None:
        file_data = read_file(largest_name)
        if file_data:
            try:
                nca_hdr = Nca(file_data)
                if nca_hdr.content_type == "Control":
                    control_nca_data = file_data
            except Exception:
                pass


    if control_nca_data is None:
        print("Warning: Control NCA not found in NSP", file=sys.stderr)
        return

    print("\n" + "="*80)
    print("Application Control Properties (NACP):")
    print("="*80)

    control_nca_obj = Nca(control_nca_data, titlekey=titlekey)

    section_idx = 0
    if not control_nca_obj.fsheaders[section_idx].section_has_content:
        print("Warning: Section 0 has no content", file=sys.stderr)
        return

    section_type = control_nca_obj.get_section_type(section_idx)
    if section_type != "RomFS":
        print(f"Warning: Section 0 is not RomFS (type: {section_type})", file=sys.stderr)
        return

    decrypted_section = control_nca_obj.decrypted_sections[section_idx]
    fs_header = control_nca_obj.fsheaders[section_idx]
    romfs_data = decrypted_section[fs_header.content_start:fs_header.content_end]

    try:
        nacp_data = extract_file_from_romfs(romfs_data, "control.nacp")
        icon_data = extract_file_from_romfs(romfs_data, "icon_AmericanEnglish.dat")
        if nacp_data:
            nacp_obj = nacp_module.parse_nacp(nacp_data)
            nacp_obj.print_info(verbose=True)
        if icon_data:
            with open(f'{control_nca_obj.titleId}_icon.jpg', 'wb') as savepic:
                savepic.write(icon_data)
                savepic.close()        
        else:
            print("Warning: control.nacp not found in RomFS", file=sys.stderr)
    except Exception as nacp_error:
        print(f"Warning: Failed to extract NACP: {nacp_error}", file=sys.stderr)


def process_nsp_info_in_memory_for_sdk_object(nsp_path: str, verbose_timing=False):
    """
    Process NSP entirely in memory without writing to disk.
    Uses targeted file reads instead of loading the entire NSP upfront.
    """

    # Read only the base PFS0 header (16 bytes) to get entry count and string table size
    with open(nsp_path, 'rb') as f:
        base_header = f.read(pfs0.PFS0_HEADER_SIZE_BASE)

    # Parse just the counts without validation
    num_files, string_table_size, _ = struct.unpack('<III', base_header[4:16])
    full_header_size = (pfs0.PFS0_HEADER_SIZE_BASE
                        + num_files * pfs0.PFS0_FILE_ENTRY_SIZE
                        + string_table_size)

    # Now read the full header and parse it properly
    with open(nsp_path, 'rb') as f:
        full_header_data = f.read(full_header_size)

    header = pfs0.Pfs0Header(full_header_data)

    # Parse all entries and build name→entry map
    strtab = full_header_data[header.string_table_offset:header.string_table_offset + header.string_table_size]

    name_to_entry = {}
    for i in range(header.num_files):
        pos = header.entry_table_offset + (i * pfs0.PFS0_FILE_ENTRY_SIZE)
        chunk = full_header_data[pos:pos + pfs0.PFS0_FILE_ENTRY_SIZE]
        entry = pfs0.Pfs0FileEntry.from_bytes(chunk)

        null_pos = strtab.find(b'\x00', entry.string_offset)
        if null_pos == -1:
            null_pos = len(strtab)
        filename = strtab[entry.string_offset:null_pos].decode('utf-8', errors='replace')
        name_to_entry[filename] = entry


    # Helper: read a specific file directly from disk by name
    def read_file(filename):
        entry = name_to_entry.get(filename)
        if entry is None:
            return None
        abs_offset = header.data_offset + entry.offset
        with open(nsp_path, 'rb') as f:
            f.seek(abs_offset)
            return f.read(entry.size)

    # Extract titlekey from ticket
    titlekey = None
    tik_name = next((n for n in name_to_entry if n.endswith('.tik')), None)
    if tik_name:
        tik_data = read_file(tik_name)
        if tik_data and len(tik_data) >= TITLEKEY_OFFSET + TITLEKEY_SIZE:
            titlekey = tik_data[TITLEKEY_OFFSET:TITLEKEY_OFFSET + TITLEKEY_SIZE]

    # Find CNMT NCA and largest NCA (by entry size, no I/O)
    nca_names = [n for n in name_to_entry if n.endswith('.nca')]
    if not nca_names:
        raise ValueError("No NCA files found in NSP")

    cnmt_nca_name = next((n for n in nca_names if n.endswith('.cnmt.nca')), None)
    if cnmt_nca_name is None:
        raise ValueError("No CNMT NCA found in NSP")

    largest_name = max(
        (n for n in nca_names if n != cnmt_nca_name),
        key=lambda n: name_to_entry[n].size,
        default=None
    )

    program_nca_data = None

    for name in nca_names:
        if name in (largest_name):
            file_data = read_file(name)
        try:
            nca_hdr = Nca(file_data, titlekey=titlekey)
            if nca_hdr.content_type == "Program":
                program_nca_data = file_data
                sdk_object = SectionExtractor.extract_section_pfs0_sdk_object_only(nca_hdr)

                pattern = rb"FS_ACCESS: \{ sdk_version: ([^,]+),"
                result = re.search(pattern, sdk_object)
                if result:
                    print(f'input nsp: {nsp_path}')
                    print(f'sdk_version: {result.group(1).decode('utf-8')}')  # prints just the version number
                else:
                    print("failed to obtain sdk object")

                break
        except Exception:
            continue

    if program_nca_data is None:
        print("Warning: Program NCA not found in NSP", file=sys.stderr)
        return

def _process_nsp_info(metadata, nacp_module):
    try:
        # Extract and display CNMT
        cnmt_obj = nsp.extract_cnmt_and_parse(
            metadata,
            titlekey=metadata.primary_titlekey,
            print_progress=False
        )
        cnmt_obj.print_info(verbose=True)

        # Extract and parse NACP from Control NCA
        control_nca = None
        for nca in metadata.nca_files:
            nca_data = util.InitializeFile(nca.filepath)
            nca_header_only = NcaHeaderOnly(nca_data)
            if nca_header_only.content_type == "Control":
                control_nca = nca
                break
        
        if control_nca:
            print("\n" + "="*80)
            print("Application Control Properties (NACP):")
            print("="*80)
            
            # Load Control NCA and extract RomFS
            control_nca_file = util.InitializeFile(control_nca.filepath)
            control_nca_obj = Nca(control_nca_file, titlekey=metadata.primary_titlekey)
            
            # Control NCA RomFS is in section 0
            section_idx = 0
            if control_nca_obj.fsheaders[section_idx].section_has_content:
                section_type = control_nca_obj.get_section_type(section_idx)
                if section_type == "RomFS":
                    # Extract section data
                    decrypted_section = control_nca_obj.decrypted_sections[section_idx]
                    fs_header = control_nca_obj.fsheaders[section_idx]
                    romfs_data = decrypted_section[fs_header.content_start:fs_header.content_end]
                    
                    # Extract control.nacp from RomFS
                    try:
                        nacp_data = nsp.extract_file_from_romfs(romfs_data, "control.nacp")
                        if nacp_data:
                            nacp_obj = nacp_module.parse_nacp(nacp_data)
                            nacp_obj.print_info(verbose=True)
                        else:
                            print("Warning: control.nacp not found in RomFS", file=sys.stderr)
                    except Exception as nacp_error:
                        print(f"Warning: Failed to extract NACP: {nacp_error}", file=sys.stderr)
                else:
                    print(f"Warning: Section 0 is not RomFS (type: {section_type})", file=sys.stderr)
            else:
                print("Warning: Section 0 has no content", file=sys.stderr)
        else:
            print("Warning: Control NCA not found in NSP", file=sys.stderr)
            
    except Exception as e:
        print(f"Error: Failed to process NSP metadata: {e}", file=sys.stderr)
        traceback.print_exc()
        raise


# Constants
TITLEKEY_OFFSET = 0x180
TITLEKEY_SIZE = 0x10  # 16 bytes


@dataclass
class TicketInfo:
    """Information extracted from a .tik (ticket) file."""
    filepath: str
    rights_id: str  # Filename is the RightsID in hex format
    titlekey: bytes  # 16-byte titlekey for decryption

    def __repr__(self):
        return f"TicketInfo(rightsid={self.rights_id}, titlekey={self.titlekey.hex().upper()})"


@dataclass
class NcaFileInfo:
    """Information about an NCA file within an NSP."""
    filename: str
    filepath: str
    size: int
    is_primary: bool = False  # True if this is the largest NCA (primary content)

    def __repr__(self):
        primary_mark = " [PRIMARY]" if self.is_primary else ""
        return f"NcaFileInfo({self.filename}, size=0x{self.size:x}{primary_mark})"


@dataclass
class NspMetadata:
    """Metadata extracted from an NSP file."""
    nsp_filename: str
    extracted_dir: Path
    tickets: Dict[str, TicketInfo] = None
    nca_files: List[NcaFileInfo] = None
    primary_nca: Optional[NcaFileInfo] = None
    primary_titlekey: Optional[bytes] = None

    def __post_init__(self):
        if self.tickets is None:
            self.tickets = {}
        if self.nca_files is None:
            self.nca_files = []


def extract_tik(tik_data: bytes) -> TicketInfo:
    """
    Extract titlekey from a .tik file.

    The titlekey is located at offset 0x180 and is 16 bytes long.

    Args:
        tik_data: Raw bytes from the .tik file

    Returns:
        Extracted titlekey bytes (16 bytes)

    Raises:
        ValueError: If the ticket file is too small
    """
    if len(tik_data) < TITLEKEY_OFFSET + TITLEKEY_SIZE:
        raise ValueError(
            f"Ticket file too small: {len(tik_data)} bytes "
            f"(need at least 0x{TITLEKEY_OFFSET + TITLEKEY_SIZE:x})"
        )

    titlekey = tik_data[TITLEKEY_OFFSET:TITLEKEY_OFFSET + TITLEKEY_SIZE]
    return titlekey


def find_tickets(extracted_dir: Union[str, Path]) -> Dict[str, TicketInfo]:
    """
    Find and parse all .tik files in an extracted NSP directory.

    Ticket filenames are typically the RightsID in hex format.

    Args:
        extracted_dir: Path to the extracted NSP directory

    Returns:
        Dictionary mapping RightsID (filename without extension) to TicketInfo

    Raises:
        FileNotFoundError: If extracted_dir doesn't exist
    """
    extracted_dir = Path(extracted_dir)
    if not extracted_dir.is_dir():
        raise FileNotFoundError(f"Extracted NSP directory not found: {extracted_dir}")

    tickets = {}

    for tik_file in extracted_dir.glob("*.tik"):
        try:
            tik_data = tik_file.read_bytes()
            titlekey = extract_tik(tik_data)

            rights_id = tik_file.stem  # Filename without extension
            ticket_info = TicketInfo(
                filepath=str(tik_file),
                rights_id=rights_id,
                titlekey=titlekey
            )
            tickets[rights_id] = ticket_info
        except (ValueError, IOError) as e:
            print(f"Warning: Failed to parse ticket {tik_file.name}: {e}")
            continue

    return tickets


def find_nca_files(extracted_dir: Union[str, Path]) -> List[NcaFileInfo]:
    """
    Find all .nca files in an extracted NSP directory.

    Args:
        extracted_dir: Path to the extracted NSP directory

    Returns:
        List of NcaFileInfo objects, sorted by size (largest first)

    Raises:
        FileNotFoundError: If extracted_dir doesn't exist
    """
    extracted_dir = Path(extracted_dir)
    if not extracted_dir.is_dir():
        raise FileNotFoundError(f"Extracted NSP directory not found: {extracted_dir}")

    nca_files = []

    for nca_file in extracted_dir.glob("*.nca"):
        try:
            size = nca_file.stat().st_size
            nca_info = NcaFileInfo(
                filename=nca_file.name,
                filepath=str(nca_file),
                size=size
            )
            nca_files.append(nca_info)
        except OSError as e:
            print(f"Warning: Failed to stat NCA file {nca_file.name}: {e}")
            continue

    # Sort by size (largest first)
    nca_files.sort(key=lambda x: x.size, reverse=True)

    # Mark the largest non-CNMT as primary
    # CNMT NCAs are identified by ".cnmt.nca" filename
    for nca in nca_files:
        if not nca.filename.endswith(".cnmt.nca"):
            nca.is_primary = True
            break

    return nca_files


def find_cnmt_nca(nca_files: List[NcaFileInfo]) -> Optional[NcaFileInfo]:
    """
    Find the CNMT NCA file from a list of NCA files.

    CNMT NCAs are identified by the ".cnmt.nca" filename pattern.

    Args:
        nca_files: List of NcaFileInfo objects

    Returns:
        The CNMT NcaFileInfo if found, None otherwise
    """
    for nca in nca_files:
        if nca.filename.endswith(".cnmt.nca"):
            return nca
    return None

def extract_nsp(
    source: Union[str, Path, bytes],
    output_dir: Union[str, Path],
    *,
    print_progress: bool = False
) -> NspMetadata:
    """
    Extract an NSP file and gather metadata.

    This function:
    1. Extracts the NSP (which is just a PFS0)
    2. Finds all .tik (ticket) files and extracts titlekeys
    3. Finds all .nca files and identifies the primary one
    4. Returns comprehensive metadata about the NSP

    Args:
        source:         Path (str/Path) or raw bytes of the NSP file
        output_dir:     Where to write extracted files
        print_progress: Whether to print progress information

    Returns:
        NspMetadata object containing tickets, NCAs, and primary titlekey

    Raises:
        FileNotFoundError: If source file doesn't exist
        ValueError: If NSP/PFS0 structure is invalid
        TypeError: If source type is invalid
    """
    output_dir = Path(output_dir)
    util.mkdirp(output_dir)

    # Determine NSP filename for logging
    if isinstance(source, (str, Path)):
        nsp_filename = Path(source).name
    elif isinstance(source, bytes):
        nsp_filename = "<bytes input>"
    else:
        raise TypeError(f"source must be str, Path or bytes, got {type(source)}")

    if print_progress:
        print(f"[NSP] Extracting {nsp_filename}...")

    # Extract NSP as PFS0
    pfs0.extract_pfs0(source, output_dir, print_progress=print_progress)

    if print_progress:
        print(f"[NSP] Scanning for metadata...")

    # Find tickets and NCAs
    tickets = find_tickets(output_dir)
    nca_files = find_nca_files(output_dir)

    # Build metadata
    metadata = NspMetadata(
        nsp_filename=nsp_filename,
        extracted_dir=output_dir,
        tickets=tickets,
        nca_files=nca_files
    )

    # Determine primary titlekey
    # This is typically from the largest NCA's RightsID
    if nca_files and tickets:
        primary_nca = nca_files[0]
        metadata.primary_nca = primary_nca

        # Try to find matching ticket
        # The RightsID is typically embedded in the NCA filename or metadata
        # For now, use the first available ticket as primary
        if tickets:
            first_ticket = next(iter(tickets.values()))
            metadata.primary_titlekey = first_ticket.titlekey
            if print_progress:
                print(f"[NSP] Primary NCA: {primary_nca.filename} ({primary_nca.size} bytes)")
                print(f"[NSP] Using titlekey: {first_ticket.titlekey.hex().upper()}")

    if print_progress:
        print(f"[NSP] Found {len(tickets)} ticket(s), {len(nca_files)} NCA file(s)")

    return metadata


def extract_cnmt_from_nsp(
    nsp_metadata: NspMetadata,
    titlekey: Optional[bytes] = None,
    *,
    print_progress: bool = False
) -> bytes:
    """
    Extract CNMT data from an NSP's CNMT NCA.

    This function:
    1. Finds the CNMT NCA file (identified by .cnmt.nca extension)
    2. Decrypts section 0 using the provided (or auto-detected) titlekey
    3. Extracts the PFS0 from section 0 (CNMT is stored in PFS0)
    4. Returns the raw CNMT data (decrypted section 0 starting at offset 0x60)

    Args:
        nsp_metadata:   NspMetadata from extract_nsp()
        titlekey:       Optional titlekey override (defaults to primary from NSP)
        print_progress: Whether to print progress information

    Returns:
        Raw CNMT data bytes (ready for cnmt.parse_cnmt())

    Raises:
        FileNotFoundError: If CNMT NCA not found
        ValueError: If decryption or extraction fails
    """

    if titlekey is None:
        titlekey = nsp_metadata.primary_titlekey

    # Find CNMT NCA (identified by .cnmt.nca filename)
    cnmt_nca = find_cnmt_nca(nsp_metadata.nca_files)
    if not cnmt_nca:
        raise ValueError("No CNMT NCA (.cnmt.nca) found in NSP")

    nca_path = cnmt_nca.filepath

    if print_progress:
        print(f"[CNMT] Opening CNMT NCA: {cnmt_nca.filename}")
    # Open and decrypt CNMT NCA
    nca_file = Nca(
        util.InitializeFile(nca_path),
        master_kek_source=None,
        titlekey=titlekey
    )

    if print_progress:
        print(f"[CNMT] Decrypted CNMT NCA sections")

    # Extract section 0 (CNMT is in PFS0 within section 0)
    section0_data = save_section(nca_file, 0)

    # CNMT data starts at offset 0x60 within the PFS0
    cnmt_data = section0_data[0x60:]

    if print_progress:
        print(f"[CNMT] Extracted CNMT data ({len(cnmt_data)} bytes)")

    return cnmt_data


def extract_cnmt_and_parse(
    nsp_metadata: NspMetadata,
    titlekey: Optional[bytes] = None,
    *,
    print_progress: bool = False
):
    """
    Extract and parse CNMT from an NSP in one step.

    Args:
        nsp_metadata:   NspMetadata from extract_nsp()
        titlekey:       Optional titlekey override
        print_progress: Whether to print progress information

    Returns:
        Parsed CNMT object (cnmt.CNMT instance)
    """

    cnmt_data = extract_cnmt_from_nsp(
        nsp_metadata,
        titlekey=titlekey,
        print_progress=print_progress
    )

    return parse_cnmt(cnmt_data)


def print_nsp_metadata(metadata: NspMetadata, verbose: bool = False):
    """
    Pretty print NSP metadata information.

    Args:
        metadata: NspMetadata from extract_nsp()
        verbose:  Whether to print details (header always prints if called)
    """
    if not verbose:
        return

    print(f"\n[NSP Information]")
    print(f"  Filename:        {metadata.nsp_filename}")
    print(f"  Extract Path:    {metadata.extracted_dir}")

    print(f"\n  Tickets: ({len(metadata.tickets)})")
    for rights_id, ticket in metadata.tickets.items():
        print(f"    {rights_id}")
        if verbose:
            print(f"      Titlekey: {ticket.titlekey.hex().upper()}")

    print(f"\n  NCA Files: ({len(metadata.nca_files)})")
    for nca in metadata.nca_files:
        primary = " [PRIMARY]" if nca.is_primary else ""
        print(f"    {nca.filename:<40} {nca.size:>12,d} bytes{primary}")

    if metadata.primary_titlekey:
        print(f"\n  Primary Titlekey: {metadata.primary_titlekey.hex().upper()}")


def extract_exefs_from_nsp(
    source: Union[str, Path, bytes],
    output_dir: Union[str, Path],
    print_progress: bool = False
) -> Path:
    output_base = Path(output_dir)
    util.mkdirp(output_base)

    # ── PHASE 1: Get title ID with disposable temp location ──
    with tempfile.TemporaryDirectory(prefix="nsp_getid_") as tmp_str:
        tmp_path = Path(tmp_str)

        if print_progress:
            print("[INFO] Scanning NSP to determine title ID...")

        meta = extract_nsp(source, tmp_path, print_progress=print_progress)

        if not meta.nca_files or meta.primary_titlekey is None:
            raise ValueError("Missing NCA files or titlekey — cannot get title ID")

        cnmt_obj = extract_cnmt_and_parse(
            meta,
            titlekey=meta.primary_titlekey,
            print_progress=print_progress
        )

        title_id = f"{cnmt_obj.title_id:016X}"

    # ── PHASE 2: Define target paths ──
    final_dir    = output_base / title_id
    nca_dir      = final_dir / "nca"
    exefs_dir    = final_dir / "exefs"
    romfs_dir    = final_dir / "romfs"

    # ── PHASE 3: Skip if already complete (safe version) ──
    if (
        final_dir.is_dir() and
        nca_dir.is_dir()   and next(nca_dir.iterdir(), None) is not None   and
        exefs_dir.is_dir() and next(exefs_dir.iterdir(), None) is not None
    ):
        if print_progress:
            print(f"[SKIP] Already extracted (nca + exefs present): {final_dir}")
            if romfs_dir.is_dir() and next(romfs_dir.iterdir(), None) is None:
                print("      Note: romfs/ is empty (normal for some games)")
        return final_dir

    # ── PHASE 4: Real extraction needed ──
    stem = Path(source).stem if isinstance(source, (str, Path)) else "nsp"
    ph_dir  = output_base / f"_extract_{stem}"
    ph_nca  = ph_dir / "nca"

    util.mkdirp(ph_nca)

    if print_progress:
        print(f"[WORK] Extracting NSP → {ph_nca}")

    metadata = extract_nsp(source, ph_nca, print_progress=print_progress)

    primary_info = next((n for n in metadata.nca_files if n.is_primary), None)
    if primary_info is None:
        raise ValueError("No primary NCA found")

    if not metadata.tickets or metadata.primary_titlekey is None:
        raise ValueError("No tickets / titlekey")

    # Move placeholder → final name
    if final_dir.exists():
        if print_progress:
            print(f"[WARN] {final_dir} existed but incomplete — continuing")
        # Optional: shutil.rmtree(final_dir)  # uncomment to force overwrite
    else:
        ph_dir.rename(final_dir)
        if print_progress:
            print(f"[MOVE] {ph_dir.name} → {title_id}")

    util.mkdirp(exefs_dir)
    util.mkdirp(romfs_dir)

    primary_path = nca_dir / primary_info.filename

    nca_obj = Nca(
        util.InitializeFile(primary_path),
        master_kek_source=None,
        titlekey=metadata.primary_titlekey
    )

    if print_progress:
        print(f"[EXEFS] Extracting → {exefs_dir}")
    SectionExtractor.extract_section_pfs0(nca_obj, exefs_dir)

    if print_progress:
        print(f"[ROMFS] Extracting → {romfs_dir}")
    try:
        SectionExtractor.extract_section_romfs(nca_obj, romfs_dir)
    except Exception as e:
        if print_progress:
            print(f"[ROMFS] Note: {e} (maybe no RomFS section)")

    if print_progress:
        print(f"[DONE] {final_dir}")

    return final_dir

# Convenience aliases for compatibility
extract = extract_nsp
parse_nsp_metadata = print_nsp_metadata
