import os
import sys
from pathlib import Path
import util
import nca
import extract_packages

fs_titleid = {
    "0100000000000819": "fs",
    "010000000000081B": "fs-exfat",
}

program_titleids = {
    "0100000000000006": "USB_services",
    "0100000000000007": "TMA_services",
    "0100000000000009": "Settings_services",
    "010000000000000A": "Bus_services",
    "010000000000000B": "Bluetooth_Driver_services",
    "010000000000000C": "BCAT_services",
    "010000000000000E": "Friend_services",
    "010000000000000F": "Network_Interface_services",
    "0100000000000010": "PTM_services",
    "0100000000000012": "Sockets_services",
    "0100000000000013": "HID_services",
    "0100000000000014": "Audio_services",
    "0100000000000015": "Log_services",
    "0100000000000016": "WLAN_services",
    "0100000000000018": "LDN_services",
    "0100000000000019": "NV_services",
    "010000000000001A": "PCV_services",
    "010000000000001B": "Capmtp_services",
    "010000000000001C": "Nvnflinger_services",
    "010000000000001D": "PCIe_services",
    "010000000000001E": "Account_services",
    "010000000000001F": "NS_services",
    "0100000000000020": "NFC_services",
    "0100000000000021": "PSC_services",
    "0100000000000022": "Capture_services",
    "0100000000000023": "Applet_Manager_services",
    "0100000000000024": "SSL_services",
    "0100000000000025": "NIM_services",
    "010000000000002A": "BTM_services",
    "010000000000002B": "Error_Report_services",
    "010000000000002D": "Display_services",
    "010000000000002E": "Parental_Control_services",
    "010000000000002F": "NPNS_services",
    "0100000000000030": "Error_Upload_services",
    "0100000000000031": "Glue_services",
    "0100000000000033": "ETicket_services",
    "0100000000000034": "Fatal_services",
    "0100000000000035": "GRC_services",
    "0100000000000037": "RO_services",
    "0100000000000039": "Shared_Database_services",
    "010000000000003A": "Migration_services",
    "010000000000003B": "JIT_services",
    "010000000000003C": "Jpegdec_services",
    "010000000000003E": "OLSC_services",
    "0100000000000042": "PGL_services",
    "0100000000000045": "OMM_services",
    "0100000000000046": "Ethernet_services",
    "0100000000000050": "NGC_services",
}

applet_titleids = {
    "0100000000001000": "qlaunch",
    "0100000000001001": "auth",
    "0100000000001002": "cabinet",
    "0100000000001003": "controller",
    "0100000000001004": "dataErase",
    "0100000000001005": "error",
    "0100000000001006": "netConnect",
    "0100000000001007": "playerSelect",
    "0100000000001008": "swkbd",
    "0100000000001009": "miiEdit",
    "010000000000100A": "LibAppletWeb",
    "010000000000100B": "LibAppletShop",
    "010000000000100C": "overlayDisp",
    "010000000000100D": "photoViewer",
    "010000000000100F": "offlineWeb",
    "0100000000001010": "LibAppletLns",
    "0100000000001011": "LibAppletAuth",
    "0100000000001012": "starter",
    "0100000000001013": "myPage",
    "0100000000001015": "maintenance",
    "0100000000001042": "systemWeb", # new in 22.0.0
    "0100000000001043": "openWeb", # new in 22.0.0
    "0100000000001048": "splay",
}

NPDM_MAGIC = b'META\x00\x00\x00\x00'
NPDM_TITLE_NAME_OFFSET = 0x20
NPDM_TITLE_NAME_SIZE = 0x10

def get_npdm_title_name(nca_data):
    """Return the npdm Title Name from the first PFS0 section containing a META header, else None."""
    for i in range(4):
        if not (nca_data.has_section(i) and nca_data.get_section_type(i) == "PFS0"):
            continue
        fs_header = nca_data.fsheaders[i]
        pfs0_data = nca_data.decrypted_sections[i][fs_header.content_start:fs_header.content_end]
        start = pfs0_data.find(NPDM_MAGIC)
        if start == -1:
            continue
        raw = pfs0_data[start + NPDM_TITLE_NAME_OFFSET:start + NPDM_TITLE_NAME_OFFSET + NPDM_TITLE_NAME_SIZE]
        return raw.split(b'\x00', 1)[0].decode('utf-8', errors='replace')
    return None

def report_unhandled(unhandled):
    """Print unhandled Program-type titleIDs as one block."""
    if not unhandled:
        return
    print(f"\n[swipc] ===== Unhandled titleIDs ({len(unhandled)}) =====")
    for title_id, nca_path in unhandled:
        try:
            name = get_npdm_title_name(nca.Nca(util.InitializeFile(nca_path), master_kek_source=None))
        except Exception:
            name = None
        print(f"[swipc] 0x{title_id.lower()}  content_type=0  {name or '(no npdm)':<24} {os.path.basename(nca_path)}")
    print("[swipc] =====================================\n")

def sort_nca(location, unhandled=None):
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

        if nca_header.titleId in fs_titleid:
            titleid_type = "kernel"
            titleid_name = fs_titleid[nca_header.titleId] 
        
        if nca_header.titleId in program_titleids:
            titleid_type = "program"
            titleid_name = program_titleids[nca_header.titleId]
        elif nca_header.titleId in applet_titleids:
            titleid_type = "applet"
            titleid_name = applet_titleids[nca_header.titleId]
        
        if titleid_type is not None:
            sorted_nca_files.append((nca_header.titleId, nca_header.content_type, nca_path, titleid_type, titleid_name))

        if titleid_type is None and unhandled is not None \
                and nca_header.content_type == "Program" \
                and all(t != nca_header.titleId for t, _ in unhandled):
            unhandled.append((nca_header.titleId, nca_path))
    
    return sorted_nca_files

if __name__ == "__main__":
    # Parse command-line arguments
    input_folder = "firmware"  # Default
    output_folder = "out"      # Default
    
    if len(sys.argv) > 1:
        input_folder = sys.argv[1]
    if len(sys.argv) > 2:
        output_folder = sys.argv[2]
    
    unhandled = []
    nca_files = sort_nca(input_folder, unhandled)

    for line in nca_files:
        titleId, content_type, nca_path, titleid_type, titleid_name = line
        nca_data = nca.Nca(util.InitializeFile(nca_path), master_kek_source=None)
        util.mkdirp(output_folder)
        util.mkdirp(f'{output_folder}/applets')
        util.mkdirp(f'{output_folder}/programs')
        if titleid_type == "program":
            main_name = f"{output_folder}/programs/{titleid_name}"
        if titleid_type == "applet":
            main_name = f"{output_folder}/applets/{titleid_name}"
        if content_type == "Program":
            exefs_data = nca.SectionExtractor.extract_section_pfs0_main_only(nca_data, main_name)

        if titleid_type == "kernel" and content_type == "Data":
            package2_data = nca.SectionExtractor.extract_section_romfs_packages_only(nca_data, 2)
            if package2_data:
                if titleid_name == "fs":
                    kip_hash, bootloader_version, kip_objects = extract_packages.process_filesystem_package_object(package2_data, None)
                    for i, x in kip_objects:
                        if i == "FS":
                            util.write_file(f"{output_folder}/programs/Filesystem_services", x)
                            util.write_file(f"{output_folder}/programs/Filesystem_services.hash", kip_hash[0].encode())
                        if i == "Loader":
                            util.write_file(f"{output_folder}/programs/Loader_services", x)
                            util.write_file(f"{output_folder}/programs/Loader_services.hash", kip_hash[1].encode())
                        if i == "NCM":
                            util.write_file(f"{output_folder}/programs/NCM_services", x)
                            util.write_file(f"{output_folder}/programs/NCM_services.hash", kip_hash[2].encode())
                        if i == "ProcessMana":
                            util.write_file(f"{output_folder}/programs/Process_Manager_services", x)
                            util.write_file(f"{output_folder}/programs/Process_Manager_services.hash", kip_hash[3].encode())
                        if i == "sm":
                            util.write_file(f"{output_folder}/programs/Services_API", x)
                            util.write_file(f"{output_folder}/programs/Services_API.hash", kip_hash[4].encode())
                        if i == "spl":
                            util.write_file(f"{output_folder}/programs/SPL_services", x)
                            util.write_file(f"{output_folder}/programs/SPL_services.hash", kip_hash[5].encode())
                        if i == "boot":
                            continue

                elif titleid_name == "fs-exfat":
                    kip_hash, bootloader_version, kip_objects = extract_packages.process_filesystem_package_object(package2_data, None)
                    for i, x in kip_objects:
                        if i == "Loader":
                            continue
                        if i == "sm":
                            continue
                        if i == "spl":
                            continue
                        if i == "FS":
                            util.write_file(f"{output_folder}/programs/Filesystem_services_exfat", x)
                            util.write_file(f"{output_folder}/programs/Filesystem_services_exfat.hash", kip_hash[3].encode())
                        if i == "boot":
                            continue
                        if i == "NCM":
                            continue
                        if i == "ProcessMana":
                            continue
    report_unhandled(unhandled)