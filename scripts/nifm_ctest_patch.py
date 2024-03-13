import re

def get_build_id():
    with open('uncompressed_nifm.nso0', 'rb') as f:
        f.seek(0x40)
        return(f.read(0x14).hex().upper())

with open('uncompressed_nifm.nso0', 'rb') as fi:
    read_data = fi.read()
    result = re.search(b'.{20}\xf4\x03\x00\xaa.{4}\xf3\x03\x14\xaa\xe0\x03\x14\xaa\x9f\x02\x01\x39\x7f\x8e\x04\xf8', read_data)
    patch = '%06X%s%s' % (result.start(), '0014', '00309AD2001EA1F2610100D4E0031FAAC0035FD6')
    text_file = open(get_build_id() + '.ips', 'wb')
    print('nifm build-id: ' + get_build_id())
    print('nifm_ctest offset and patch at: ' + patch)
    text_file.write(bytes.fromhex(str('5041544348' + patch + '454F46')))
    text_file.close()
