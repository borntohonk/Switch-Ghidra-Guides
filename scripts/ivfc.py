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

class IvfcLevel:
    def __init__(self, ivfclevel):
        self.ivfclevel = ivfclevel
        self.data_offset_raw = self.ivfclevel[0x0:0x8]
        self.data_offset = int.from_bytes(self.data_offset_raw, byteorder='little', signed=False)
        self.data_size_raw = self.ivfclevel[0x8:0x10]
        self.data_size = int.from_bytes(self.data_size_raw, byteorder='little', signed=False)
        self.hash_offset_raw = self.ivfclevel[0x10:0x14]
        self.hash_offset = int.from_bytes(self.hash_offset_raw, byteorder='little', signed=False)
        self.hash_block_size_raw = self.ivfclevel[0x14:0x18]
        self.hash_block_size = int.from_bytes(self.hash_block_size_raw, byteorder='little', signed=False)
        self.reserved = self.ivfclevel[0x1C:0x18]

class Ivfc():
    def __init__(self, hashData):
        self.hashData = hashData
        self.magic = hashData[0x0:0x4]
        self.version = hashData[0x4:0x8]
        self.master_hash_size = hashData[0x8:0xC]
        self.info_level_hash = hashData[0xC:0xC0]
        self.master_hash = hashData[0xC0:0xE0]
        self.reserved = hashData[0xE0:0xF8]
        self.max_layers_raw = self.info_level_hash[0x0:0x4]
        self.max_layers = int.from_bytes(self.max_layers_raw, byteorder='little', signed=False)
        self.max_layer_count = self.max_layers - 1
        self.infolevels = self.hashData[0x10:0xA0]
        self.levels = []
        for i in range(self.max_layers):
            x = i * 0x18
            y = x - 0x18
            self.levels.append(IvfcLevel(self.infolevels[y:x]))