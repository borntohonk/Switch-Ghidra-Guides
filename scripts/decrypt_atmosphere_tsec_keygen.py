import sys
from key_sources import KeySources

try:
    from Cryptodome.Cipher import AES
except ModuleNotFoundError:
    try:
        from Crypto.Cipher import AES
    except ModuleNotFoundError:
        print('Please install pycryptodome(ex) first!')
        sys.exit(1)

def decrypt(input, key):
    cipher = AES.new(key, AES.MODE_ECB)
    output = cipher.decrypt(input)
    return output

with open('external_binaries/tsec_keygen.bin', 'rb') as file:
    key_sources = KeySources()
    input_data = file.read()
    unencrypted_block = input_data[0x0:0x410]
    decrypted_block = decrypt(input_data[0x410:], key_sources.tsec_secret_06)
    decrypted_tsec_bin = open('decrypted_tsec_keygen.bin', 'wb')
    decrypted_tsec_bin.write(unencrypted_block)
    decrypted_tsec_bin.write(decrypted_block)
    decrypted_tsec_bin.close()