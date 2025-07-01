import os
import sys
import util
import nca
import re

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
        titleid_type = None
        titleid_name = None

        if nca_header.titleId is not None:
            sorted_nca_files.append((nca_header.titleId, nca_header.content_type, nca_path))
    
    return sorted_nca_files

if __name__ == "__main__":
    input_folder = "firmware"  # Default
    output_folder = "out"      # Default
    
    if len(sys.argv) > 1:
        input_folder = sys.argv[1]
    if len(sys.argv) > 2:
        output_folder = sys.argv[2]
    
    nca_files = sort_nca(input_folder)

    for line in nca_files:
        titleId, content_type, nca_path = line
        nca_data = nca.Nca(util.InitializeFile(nca_path), master_kek_source=None)
        
        sections = nca_data.decrypted_sections
        pattern = b"virtual game"

        for section_idx, data_to_search in enumerate(sections):
            if not data_to_search:
                continue

            for match in re.finditer(pattern, data_to_search, flags=re.IGNORECASE):
                print(f"Match for {titleId} nca_path = {nca_path}; Section: {section_idx}; the match:: {match.group()} | Offsets: {match.span()}")
