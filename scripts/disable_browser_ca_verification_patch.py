import re

def get_build_id():
    with open('uncompressed_browser_ssl.nro', 'rb') as f:
        f.seek(0x40)
        return(f.read(0x10).hex().upper())

with open('uncompressed_browser_ssl.nro', 'rb') as fi:
    read_data = fi.read()
    result = re.search(rb'\x48\x00\x80\x52\xE2\x13\x88\x1A\xE8\x03.\x2A\x21\x0A\x80\x52.\x01\x00\x12..\x04\x94..\x41\xF9\x01\x08\x80\x52\xE2\x03', read_data)
    patch1 = '%08X%s%s' % (result.start(), '0001', '08')
    patch2 = '%08X%s%s' % (result.end(), '0001', '1F')
    text_file = open(get_build_id() + '.ips', 'wb')
    print('browser-ssl build-id: ' + get_build_id())
    print('disable_browser_ca_verification offsets and patches at: ' + patch1 + patch2)
    text_file.write(bytes.fromhex(str(f'4950533332' + patch1 + patch2 + '45454F46')))
    text_file.close()
