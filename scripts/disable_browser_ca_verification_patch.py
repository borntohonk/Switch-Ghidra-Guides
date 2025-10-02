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

import re

#20.0.0 romfs/nro/netfront/core_3/default/cfi_enabled/webkit_wkc.nro.lz4


# this should be redundant if one runs scripts/process_firwmare.py
#with open('webkit_wkc.nro.lz4', 'rb') as file:
#    input_data = file.read()
#    decompressed = lz4.block.decompress(input_data)
#    decompressed_browser_file = open('foss_browser_ssl.nro', 'wb')
#    decompressed_browser_file.write(decompressed)
#    decompressed_browser_file.close()

    
def get_build_id():
    with open('foss_browser_ssl.nro', 'rb') as f:
        f.seek(0x40)
        return(f.read(0x10).hex().upper())

with open('foss_browser_ssl.nro', 'rb') as fi:
    read_data = fi.read()
    result = re.search(rb'\x72\x48\x00\x80\x52\xe2\x13\x88\x1a', read_data)
    patch1 = '%08X%s%s' % (result.start() + 0x1, '0004', 'E8031F2A')
    patch2 = '%08X%s%s' % (result.end(), '0001', '1F')
    text_file = open(get_build_id() + '.ips', 'wb')
    print('browser-ssl build-id: ' + get_build_id())
    print('disable_browser_ca_verification offsets and patches at: ' + patch1 + patch2)
    text_file.write(bytes.fromhex(str(f'4950533332' + patch1 + patch2 + '45454F46')))
    text_file.close()
