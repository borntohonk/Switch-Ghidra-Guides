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

def get_module_id():
    with open('ssl.nso0', 'rb') as f:
        f.seek(0x40)
        return(f.read(0x14).hex().upper())

with open('ssl.nso0', 'rb') as fi:
    read_data = fi.read()
    hex_data = read_data.hex().upper()
    # 22.0.0+ ssl sysmodule CA-verification check. Nibble wildcards ('.') run against the hex string
    # (a raw-byte regex cannot express a half-byte wildcard, which is why the old \x. pattern was
    # invalid). Offsets are divided back to byte positions.
    # result1 ghidra: 08 00 80 12 69 12 05 91 7f 1e 00 f9 68 42 00 b9 08 00 80 d2   (changed in 22.5.0)
    result1 = re.search('08008012.9120591.F1E00F..84200B9', hex_data)
    # result23 ghidra: 88 06 00 12 1f 0d 00 71 a0 00 00 54                          (changed in 22.0.0)
    result23 = re.search('880600121F0D0071A0000054', hex_data)
    result4 = re.search('88160012', hex_data)
    start1 = result1.start() // 2
    start23 = result23.start() // 2
    start4 = result4.start() // 2
    patch1 = '%08X%s%s' % (start1 + 16, '0004', '080080D2') # mov x8, #0
    patch2 = '%08X%s%s' % (start23 + 8, '0004', '13000014') # unconditional branch past the check
    patch3 = '%08X%s%s' % (start4 + 8, '0004', '08000852') # mov w8, #0x40
    text_file = open(get_module_id() + '.ips', 'wb')
    print('ssl build-id: ' + get_module_id())
    print('disable_ca_verification offsets and patches at: ' + patch1 + patch2 + patch3)
    text_file.write(bytes.fromhex(str(f'4950533332' + patch1 + patch2 + patch3 + '45454F46')))
    text_file.close()
