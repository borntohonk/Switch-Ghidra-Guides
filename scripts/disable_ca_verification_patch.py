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
    #result1 = re.search(rb'\x6a\x00\x80\xd2', read_data)
    result1 = re.search(rb'\x08\x00\x80\x12\x.\x12\x05\x91.\x1E\x00..\x42\x00\xB9', read_data) # changed in 22.5.0
    #result1 ghidra string 08 00 80 12 69 12 05 91 7f 1e 00 f9 68 42 00 b9 08 00 80 d2
    result23 = re.search(rb'\x88\x06\x00\x12\x1F\x0D\x00\x71\xA0\x00\x00\x54', read_data) # changed 22.0.0
    #result23 ghidra 88 06 00 12 1f 0d 00 71 a0 00 00 54
    result4 = re.search(rb'\x88\x16\x00\x12', read_data)
    patch1 = '%08X%s%s' % (result1.start() + 16 , '0001', '08') # 0x119A60 in 21.0.0+ - register x8, register x10 before
    patch2 = '%08X%s%s' % (result23.start() + 8, '0002', '1300') # 1300 in 21.0.0+
    patch3 = '%08X%s%s' % (result23.start() + 11, '0001', '14')
    patch4 = '%08X%s%s' % (result4.start() + 8, '0004', '08008052') # +4 in 21.0.0+
    text_file = open(get_module_id() + '.ips', 'wb')
    print('ssl build-id: ' + get_module_id())
    print('disable_ca_verification offsets and patches at: ' + patch1 + patch2 + patch3 + patch4)
    text_file.write(bytes.fromhex(str(f'4950533332' + patch1 + patch2 + patch3 + patch4 + '45454F46')))
    text_file.close()
