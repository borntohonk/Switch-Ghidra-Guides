import sys
from key_sources import KeySources
import crypto
from hashlib import sha256

try:
    from Cryptodome.Cipher import AES
except ModuleNotFoundError:
    try:
        from Crypto.Cipher import AES
    except ModuleNotFoundError:
        print('Please install pycryptodome(ex) first!')
        sys.exit(1)

def decrypt_ecb(input, key):
    cipher = AES.new(key, AES.MODE_ECB)
    output = cipher.decrypt(input)
    return output

def encrypt_ecb(input, key):
    cipher = AES.new(key, AES.MODE_ECB)
    output = cipher.encrypt(input)
    return output

def decrypt_cbc(input, key):
    cipher = AES.new(key, AES.MODE_CBC, bytes(16))
    output = cipher.decrypt(input)
    return output

with open('external_binaries/tsec_keygen.bin', 'rb') as file:
    key_sources = KeySources()
    atmosphere_tsec_keygen_auth_hash = bytes([0x86, 0x3A, 0x8C, 0x95, 0xAD, 0x4D, 0xF7, 0xF1, 0x18, 0x0B, 0x51, 0xBF, 0x10, 0x03, 0xDB, 0x14])
    csigenc = encrypt_ecb(atmosphere_tsec_keygen_auth_hash, key_sources.tsec_secret_26)
    c2_reg_nibble_combined = bytes([0xBC, 0xBF, 0xC1, 0x0B, 0x81, 0xD2, 0x47, 0x66, 0x97, 0x93, 0x98, 0x25, 0x6D, 0x83, 0x23, 0xE4])
    c2_reg_key = encrypt_ecb(c2_reg_nibble_combined, csigenc)
    input_data = file.read()
    unencrypted_block = input_data[0x0:0x410]
    decrypted_block = decrypt_ecb(input_data[0x410:0x1A00], key_sources.tsec_secret_06)
    encrypted_block = input_data[0x1A00:]
    decrypted_block_2 = decrypt_cbc(encrypted_block, c2_reg_key)
    decrypted_tsec_bin = open('decrypted_tsec_keygen.bin', 'wb')
    decrypted_tsec_bin.write(unencrypted_block)
    decrypted_tsec_bin.write(decrypted_block)
    decrypted_tsec_bin.write(decrypted_block_2)
    decrypted_tsec_bin.close()
