import shutil
import os
import util
import nca

titleids_to_store = [
    '0100000000000809', # system_update
    '0100000000000819', # fat32
    '010000000000081B', # exfat
    '010000000000001E', # account
    '0100000000000033', # es
    '010000000000000F', # nifm
    '010000000000003E', # olsc
    '0100000000000025', # nim
    '0100000000000024', # ssl
    '0100000000000006', # usb
    '0100000000000803', # browser
]

def _copy_sorted_nca(titleId, content_type, nca_path):
    """Copy NCA file to sorted firmware directory."""
    try:
        output_dir = f"sorted_firmware/temp/by-type/{content_type}/{titleId}"
        util.mkdirp(output_dir)
        shutil.copy(nca_path, f"{output_dir}/data.nca")
    except Exception as e:
        print(f"Warning: Failed to copy NCA {titleId}: {e}")


def sort_nca(location):
    """Sort and extract NCA files from firmware location."""
    nca_files = []
    sorted_nca_files = []
    
    # Collect all non-CNMT NCA files
    for nca_file in os.listdir(location):
        nca_path = os.path.join(location, nca_file)
        if not nca_path.endswith(".cnmt.nca"):
            nca_files.append(nca_path)
    
    # Filter for target title IDs
    for nca_path in nca_files:
        nca_header = nca.NcaHeaderOnly(util.InitializeFile(nca_path))
        if nca_header.titleId in titleids_to_store:
            sorted_nca_files.append((nca_header.titleId, nca_header.content_type, nca_path))
    
    # Extract system version from system update NCA
    master_key_rev = None
    temp_folder = "temp"
    
    # Copy remaining NCAs to sorted directory
    for titleId, content_type, nca_path in sorted_nca_files:
        _copy_sorted_nca(titleId, content_type, nca_path)
        if titleId == "0100000000000809":  # system_update
            nca_header = nca.NcaHeaderOnly(util.InitializeFile(nca_path))
            master_key_rev = nca_header.master_key_revision
    
    return temp_folder, master_key_rev