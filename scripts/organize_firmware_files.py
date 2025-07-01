import os
import util
import nca

titleids_to_store = {
    '0100000000000809': 'system_update',
    '0100000000000819': 'fat32',
    '010000000000081B': 'exfat',
    "010000000000000F": "nifm",
    "010000000000001E": "account",
    "010000000000001F": "ns",
    "0100000000000023": "am",
    "0100000000000024": "ssl",
    "0100000000000025": "nim",
    "0100000000000033": "es",
    "010000000000003E": "olsc",
    '0100000000000006': 'usb',
    '0100000000000803': 'browser',
}

def sort_nca(location):
    """Sort and extract NCA files from firmware location."""
    nca_files = []
    sorted_nca_files = []
    master_key_rev = None

    # Collect all non-CNMT NCA files
    for nca_file in os.listdir(location):
        nca_path = os.path.join(location, nca_file)
        if not nca_path.endswith(".cnmt.nca"):
            nca_files.append(nca_path)
    
    # Filter for target title IDs
    for nca_path in nca_files:
        nca_header = nca.NcaHeaderOnly(util.InitializeFile(nca_path))
        titleid_type = None
        titleid_name = None

        if nca_header.titleId in titleids_to_store:
            titleid_type = "sorted"
            titleid_name = titleids_to_store[nca_header.titleId]
            if nca_header.titleId == "0100000000000809":  # system_update
                master_key_rev = nca_header.master_key_revision

        if titleid_type is not None:
            sorted_nca_files.append((nca_header.titleId, nca_header.content_type, nca_path, titleid_type, titleid_name))
    
    return sorted_nca_files, master_key_rev