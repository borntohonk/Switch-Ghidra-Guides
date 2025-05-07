import re
import lz4.block

#18.0.0 romfs/nro/netfront/core_2/default/cfi_enabled/webkit_wkc.nro.lz4
with open('webkit_wkc.nro.lz4', 'rb') as file:
    input_data = file.read()
    decompressed = lz4.block.decompress(input_data)
    decompressed_browser_file = open('uncompressed_browser_ssl.nro', 'wb')
    decompressed_browser_file.write(decompressed)
    decompressed_browser_file.close()

    
def get_build_id():
    with open('uncompressed_browser_ssl.nro', 'rb') as f:
        f.seek(0x40)
        return(f.read(0x10).hex().upper())

with open('uncompressed_browser_ssl.nro', 'rb') as fi:
    read_data = fi.read()
    result = re.search(rb'\x72\x48\x00\x80\x52\xe2\x13\x88\x1a', read_data)
    patch1 = '%08X%s%s' % (result.start() + 0x1, '0004', 'E8031F2A')
    patch2 = '%08X%s%s' % (result.end(), '0001', '1F')
    text_file = open(get_build_id() + '.ips', 'wb')
    print('browser-ssl build-id: ' + get_build_id())
    print('disable_browser_ca_verification offsets and patches at: ' + patch1 + patch2)
    text_file.write(bytes.fromhex(str(f'4950533332' + patch1 + patch2 + '45454F46')))
    text_file.close()
