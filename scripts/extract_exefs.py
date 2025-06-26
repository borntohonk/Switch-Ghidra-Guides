# Copyright (c) 2025 borntohonk
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

import os
from io import BytesIO
import re
from pathlib import Path
import nca
import nxo64
import aes_sample
import key_sources as key_sources

def get_build_id(extracted_pfs0):
    return extracted_pfs0[0x40:0x54].hex().upper()

def prepare_exefs(nca_path, nso_out):
    nso_name = nso_out
    key_area_key_application = aes_sample.single_keygen(key_sources.mariko_master_kek_sources[-1])[6] # this relies on key_sources being updated with the latest master_mariko_source, requires mariko_bek, mariko_kek
    nca_file = nca.Nca(nca_path, key_area_key_application)
    decrypted_nca_header = nca_file.decrypted_nca_header
    decrypted_section_00 = nca_file.decrypted_sections[0]
    titleId = nca_file.titleId
    if titleId != "0100000000000819" or "010000000000081B":
        decrypted_section_00 = nca_file.decrypted_sections[0]
        extracted_pfs0 = nca.extract_pfs0(decrypted_nca_header, decrypted_section_00)
        main_exefs_end_offset = int.from_bytes(extracted_pfs0[0x18:0x1B], "little", signed=False)
        main_exefs = extracted_pfs0[0x60:main_exefs_end_offset + 0x60]
        build_id = get_build_id(main_exefs)
        compressed_exefs = BytesIO(main_exefs)
        decompressed_nso = nxo64.decompress_nso(compressed_exefs)
        with open(nso_name, 'wb') as exefs_file:
            exefs_file.write(decompressed_nso)
            exefs_file.close()
            return build_id
