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

import re
import lz4.block

#20.0.0 romfs/nro/netfront/core_3/default/cfi_enabled/webkit_wkc.nro.lz4
#21.0.0 romfs/nro/netfront/core_3/Default/cfi_nncfi/webkit_wkc.nro.lz4

with open('webkit_wkc.nro.lz4', 'rb') as file:
    input_data = file.read()
    decompressed = lz4.block.decompress(input_data)
    decompressed_browser_file = open('foss_browser_ssl.nro', 'wb')
    decompressed_browser_file.write(decompressed)
    decompressed_browser_file.close()

    
def get_module_id():
    with open('foss_browser_ssl.nro', 'rb') as f:
        f.seek(0x40)
        return(f.read(0x10).hex().upper())

with open('foss_browser_ssl.nro', 'rb') as fi:
    read_data = fi.read()
    result = re.search(rb'\x42\x00\x80\x52\xf4\x40\x05\x94\x20\xf9\xff\x35\xe0\x72\x41\xf9\x01\x08\x80\x52\x22\x00\x80\x52', read_data) # 21.0.0 + (might need diffing in future)
    patch = '%08X%s%s' % (result.start(), '0004', 'E2031F2A') # 21.2.0 apparently
    diff_start = result.start() - 0x20
    diff_end = diff_start + 0x60
    diff_bytes = read_data[diff_start:diff_end]
    text_file = open(get_module_id() + '.ips', 'wb')
    print('browser-ssl build-id: ' + get_module_id())
    print('disable_browser_ca_verification offsets and patches at: ' + patch)
    text_file.write(bytes.fromhex(str(f'4950533332' + patch + '45454F46')))
    text_file.close()
