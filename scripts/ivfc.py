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

class InfoLevelHash: # InfoLevelHash
    def __init__(self, infolevelhash):
        self.infolevelhash = infolevelhash
        self.max_layers = self.infolevelhash[0x0:0x4]
        self.ivfc_levels = self.infolevelhash[0x4:0x94]
        self.signature_salt = self.infolevelhash[0x94:0xB4]

class IvfcLevels: # HierarchicalIntegrityVerificationLevelInformation
    def __init__(self, ivfc_levels):
        self.ivfc_levels = ivfc_levels
        self.logical_offset = int.from_bytes(self.ivfc_levels[0x0:0x8], byteorder='little', signed=False)
        self.hash_data_size = int.from_bytes(self.ivfc_levels[0x8:0x10], byteorder='little', signed=False)
        self.block_size = int.from_bytes(self.ivfc_levels[0x10:0x14], byteorder='little', signed=False)
        self.reserved = self.ivfc_levels[0x14:0x18]

class Ivfc(): # IntegrityMetaInfo
    def __init__(self, hashData):
        self.hashData = hashData
        self.magic = self.hashData[0x0:0x4]
        self.version = self.hashData[0x4:0x8]
        self.master_hash_size = self.hashData[0x8:0xC]
        self.info_level_hash = InfoLevelHash(self.hashData[0xC:0xC0])
        self.master_hash = self.hashData[0xC0:0xE0]
        self.reserved = self.hashData[0xE0:0xF8]
        self.max_layers_raw = self.info_level_hash.max_layers
        self.max_layers = int.from_bytes(self.max_layers_raw, byteorder='little', signed=False)
        self.max_layer_count = self.max_layers - 1
        self.info_levels = self.info_level_hash.ivfc_levels
        self.levels = []
        for i in range(self.max_layers):
            x = i * 0x18
            y = x - 0x18
            self.levels.append(IvfcLevels(self.info_levels[y:x]))