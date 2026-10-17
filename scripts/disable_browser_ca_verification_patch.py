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

#with open('webkit_wkc.nro.lz4', 'rb') as file:
#    input_data = file.read()
#    decompressed = lz4.block.decompress(input_data)
#    decompressed_browser_file = open('foss_browser_ssl.nro', 'wb')
#    decompressed_browser_file.write(decompressed)
#    decompressed_browser_file.close()

    
def get_module_id():
    with open('foss_browser_ssl.nro', 'rb') as f:
        f.seek(0x40)
        return(f.read(0x10).hex().upper())

with open('foss_browser_ssl.nro', 'rb') as fi:
    read_data = fi.read()
    hex_data = read_data.hex().upper()
    # 22.5.0+ FOSS browser configures the HTTPS transport through curl_easy_setopt:
    #   setopt(ctx, CURLOPT_SSL_VERIFYHOST=0x51, 2)   ... mov w2,#2  (42 00 80 52)
    #   setopt(ctx, CURLOPT_SSL_VERIFYPEER=0x40, 1)   mov w1,#0x40 ; mov w2,#1  (22 00 80 52)
    # on the verify-enabled branch (the sibling branch already passes 0/0). Rewriting both value
    # immediates to "mov w2, wzr" (E2 03 1F 2A) forces host and peer verification off on every branch.
    # The 0x40 option-id mov anchors each pattern uniquely; two identical SSL-setup call sites exist,
    # so each option is patched at both. This replaces the pre-22.5.0 build layout whose pattern
    verify_host = [m.start() // 2 for m in re.finditer('01088052E2031F2A0700001442008052', hex_data)]  # mov w1,#0x40|mov w2,wzr|b|mov w2,#2
    verify_peer = [m.start() // 2 for m in re.finditer('0108805222008052', hex_data)]                   # mov w1,#0x40|mov w2,#1
    records = ''
    for start in verify_host:
        records += '%08X%s%s' % (start + 12, '0004', 'E2031F2A') # VERIFY_HOST = 0
    for start in verify_peer:
        records += '%08X%s%s' % (start + 4, '0004', 'E2031F2A') # VERIFY_PEER = 0
    text_file = open(get_module_id() + '.ips', 'wb')
    print('browser-ssl build-id: ' + get_module_id())
    print('disable_browser_ca_verification offsets and patches at: ' + records)
    text_file.write(bytes.fromhex(str(f'4950533332' + records + '45454F46')))
    text_file.close()