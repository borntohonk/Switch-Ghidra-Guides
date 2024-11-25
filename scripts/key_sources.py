# (encrypted if _00 and _01 / decrypted if _02 by tsec_secret_26, then the result is then used as key to encrypt tsec_auth_signatures_%%, essentially this falcon instruction chain:)
# buffer = address to stored seed combination hovi + _sig/_kek/_enc + _key + _prd/_dev/_iv1
# csecret $c1, 0x26 (loads csecret 0x26 into $c1)
# ckeyreg $c1 (uses $c1 as key for encryption/decryption)
# cenc/cdec $c0, buffer (result is tsec_root_kek_%% // package1_kek_%% // package1_mac_kek_%%)
# csigenc $c0, $c0 (resulting key is Package1_Key_06/_07/_08 // Package1_Mac_Key_06/_07/_08 // Tsec_Root_Key_00/_01/_02 // hovi_iv_00/_01/_02)
# output by secureboot tsec firmware stage within package1


# The following sources are made out of seed parts of the hex representations of the words:
# [0]"HOVI", [1]"_SIG"/"_ENC"/"_KEK", [2]"_KEY", [3]"_IV1"/"_PRD"/"_DEV"
# key sources that combined hovi seed parts make.
HOVI_SIG_KEY_PRD = bytes([0x48, 0x4F, 0x56, 0x49, 0x5F, 0x53, 0x49, 0x47, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x50, 0x52, 0x44]) # Package1_Mac_Kek_Source
HOVI_ENC_KEY_PRD = bytes([0x48, 0x4F, 0x56, 0x49, 0x5F, 0x45, 0x4E, 0x43, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x50, 0x52, 0x44]) # Package1_Kek_Source
HOVI_KEK_KEY_PRD = bytes([0x48, 0x4F, 0x56, 0x49, 0x5F, 0x4B, 0x45, 0x4B, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x50, 0x52, 0x44]) # Tsec_Root_Kek_Source
HOVI_ENC_KEY_IV1 = bytes([0x48, 0x4F, 0x56, 0x49, 0x5F, 0x45, 0x4E, 0x43, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x49, 0x56, 0x31]) # Tsec_Hovi_IV_key
HOVI_SIG_KEY_DEV = bytes([0x48, 0x4F, 0x56, 0x49, 0x5F, 0x53, 0x49, 0x47, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x44, 0x45, 0x56]) # Package1_Mac_Kek_Source_Dev
HOVI_ENC_KEY_DEV = bytes([0x48, 0x4F, 0x56, 0x49, 0x5F, 0x45, 0x4E, 0x43, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x44, 0x45, 0x56]) # Package1_Kek_Source_Dev
HOVI_KEK_KEY_DEV = bytes([0x48, 0x4F, 0x56, 0x49, 0x5F, 0x4B, 0x45, 0x4B, 0x5F, 0x4B, 0x45, 0x59, 0x5F, 0x44, 0x45, 0x56]) # Tsec_Root_Kek_Source_Dev

# tsec_root_kek_00 == tsec_root_kek_01
# package1_kek_00 == package1_kek_01
# package1_mac_kek_00 == package1_mac_kek_01

# various sources:
mariko_kek                          = bytes([0x41, 0x30, 0xB8, 0xB8, 0x42, 0xDD, 0x7C, 0xD2, 0xEA, 0x8F, 0xD5, 0x0D, 0x3D, 0x48, 0xB7, 0x7C])
mariko_bek                          = bytes([0x6A, 0x5D, 0x16, 0x8B, 0x14, 0xE6, 0x4C, 0xAD, 0xD7, 0x0D, 0xA9, 0x34, 0xA0, 0x6C, 0xC2, 0x22])
keyblob_mac_key_source              = bytes([0x59, 0xC7, 0xFB, 0x6F, 0xBE, 0x9B, 0xBE, 0x87, 0x65, 0x6B, 0x15, 0xC0, 0x53, 0x73, 0x36, 0xA5])
per_console_key_source              = bytes([0x4F, 0x02, 0x5F, 0x0E, 0xB6, 0x6D, 0x11, 0x0E, 0xDC, 0x32, 0x7D, 0x41, 0x86, 0xC2, 0xF4, 0x78])
retail_specific_aes_key_source      = bytes([0xE2, 0xD6, 0xB8, 0x7A, 0x11, 0x9C, 0xB8, 0x80, 0xE8, 0x22, 0x88, 0x8A, 0x46, 0xFB, 0xA1, 0x95])
header_kek_source                   = bytes([0x1F, 0x12, 0x91, 0x3A, 0x4A, 0xCB, 0xF0, 0x0D, 0x4C, 0xDE, 0x3A, 0xF6, 0xD5, 0x23, 0x88, 0x2A])
header_key_source                   = bytes([0x5A, 0x3E, 0xD8, 0x4F, 0xDE, 0xC0, 0xD8, 0x26, 0x31, 0xF7, 0xE2, 0x5D, 0x19, 0x7B, 0xF5, 0xD0, 0x1C, 0x9B, 0x7B, 0xFA, 0xF6, 0x28, 0x18, 0x3D, 0x71, 0xF6, 0x4D, 0x73, 0xF1, 0x50, 0xB9, 0xD2])
save_mac_kek_source                 = bytes([0xD8, 0x9C, 0x23, 0x6E, 0xC9, 0x12, 0x4E, 0x43, 0xC8, 0x2B, 0x03, 0x87, 0x43, 0xF9, 0xCF, 0x1B])
save_mac_key_source_00              = bytes([0xE4, 0xCD, 0x3D, 0x4A, 0xD5, 0x0F, 0x74, 0x28, 0x45, 0xA4, 0x87, 0xE5, 0xA0, 0x63, 0xEA, 0x1F])
save_mac_key_source_01              = bytes([0xEC, 0x24, 0x98, 0x95, 0x65, 0x6A, 0xDF, 0x4A, 0xA0, 0x66, 0xB9, 0x88, 0x0A, 0xC8, 0x2C, 0x4C])
save_mac_sd_card_kek_source         = bytes([0x04, 0x89, 0xEF, 0x5D, 0x32, 0x6E, 0x1A, 0x59, 0xC4, 0xB7, 0xAB, 0x8C, 0x36, 0x7A, 0xAB, 0x17])
save_mac_sd_card_key_source         = bytes([0x6F, 0x64, 0x59, 0x47, 0xC5, 0x61, 0x46, 0xF9, 0xFF, 0xA0, 0x45, 0xD5, 0x95, 0x33, 0x29, 0x18])
sd_card_kek_source                  = bytes([0x88, 0x35, 0x8D, 0x9C, 0x62, 0x9B, 0xA1, 0xA0, 0x01, 0x47, 0xDB, 0xE0, 0x62, 0x1B, 0x54, 0x32])
keyblob_mac_key_source              = bytes([0x59, 0xC7, 0xFB, 0x6F, 0xBE, 0x9B, 0xBE, 0x87, 0x65, 0x6B, 0x15, 0xC0, 0x53, 0x73, 0x36, 0xA5])
bis_kek_source                      = bytes([0x34, 0xC1, 0xA0, 0xC4, 0x82, 0x58, 0xF8, 0xB4, 0xFA, 0x9E, 0x5E, 0x6A, 0xDA, 0xFC, 0x7E, 0x4F])
# tsec auth hash/signature can be found by searching for "1D E3 64 58 FA 9E C2 98 D5 B4 57 74 B5 82 E7 11", selecting the last result +0x1, or +0x30 from start of result found (zeroes encrypted by tsec_secret_06)
tsec_auth_signature_00              = bytes([0xA7, 0x7B, 0x86, 0x58, 0x6A, 0xE1, 0xB0, 0x3D, 0x4F, 0xFB, 0xA3, 0xAD, 0xA8, 0xF8, 0xDE, 0x32]) # source 0x3300 encrypted package1 6.2.0 
tsec_auth_signature_01              = bytes([0xA3, 0xFF, 0xB0, 0xF6, 0xBC, 0x49, 0xA0, 0x6D, 0xF2, 0xFC, 0x79, 0x16, 0x97, 0xD8, 0x1D, 0x32]) # source 0x3B00 encrypted package1 7.0.0
tsec_auth_signature_02              = bytes([0x0B, 0x55, 0xCC, 0x08, 0x20, 0xE6, 0x30, 0x7F, 0xD0, 0x87, 0x47, 0x9E, 0xAA, 0x2E, 0x7F, 0x98]) # source 0x3D00 encrypted package1 8.1.0+
tsec_root_key_00                    = bytes([0xE2, 0x1D, 0x3F, 0x25, 0xBB, 0xEA, 0x7F, 0x52, 0xF3, 0xCD, 0xF8, 0x8B, 0x48, 0x1B, 0xDE, 0x9E])
tsec_root_key_01                    = bytes([0x52, 0x2E, 0x98, 0x74, 0x01, 0xE8, 0x98, 0xB7, 0x5A, 0xEA, 0xEE, 0xFD, 0x76, 0x99, 0xB3, 0x41])
tsec_root_key_02                    = bytes([0x4B, 0x4F, 0xBC, 0xF5, 0x8E, 0x23, 0xCF, 0x49, 0x02, 0xD4, 0x78, 0xB7, 0x6C, 0x80, 0x48, 0xEC])
header_key                          = bytes([0xAE, 0xAA, 0xB1, 0xCA, 0x08, 0xAD, 0xF9, 0xBE, 0xF1, 0x29, 0x91, 0xF3, 0x69, 0xE3, 0xC5, 0x67, 0xD6, 0x88, 0x1E, 0x4E, 0x4A, 0x6A, 0x47, 0xA5, 0x1F, 0x6E, 0x48, 0x77, 0x06, 0x2D, 0x54, 0x2D])
keyblob_mac_key_source              = bytes([0x59, 0xC7, 0xFB, 0x6F, 0xBE, 0x9B, 0xBE, 0x87, 0x65, 0x6B, 0x15, 0xC0, 0x53, 0x73, 0x36, 0xA5])
master_key_source                   = bytes([0xD8, 0xA2, 0x41, 0x0A, 0xC6, 0xC5, 0x90, 0x01, 0xC6, 0x1D, 0x6A, 0x26, 0x7C, 0x51, 0x3F, 0x3C]) # https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L44
package2_key_source                 = bytes([0xFB, 0x8B, 0x6A, 0x9C, 0x79, 0x00, 0xC8, 0x49, 0xEF, 0xD2, 0x4D, 0x85, 0x4D, 0x30, 0xA0, 0xC7]) # https://github.com/Atmosphere-NX/Atmosphere/blob/9f8d17b9e6079eb421e194b81bed8a3de357c10d/exosphere/program/source/boot/secmon_boot_key_data.s#L76
key_area_key_application_source     = bytes([0x7F, 0x59, 0x97, 0x1E, 0x62, 0x9F, 0x36, 0xA1, 0x30, 0x98, 0x06, 0x6F, 0x21, 0x44, 0xC3, 0x0D]) # https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libstratosphere/source/fssrv/fssrv_nca_crypto_configuration.cpp#L110
key_area_key_ocean_source           = bytes([0x32, 0x7D, 0x36, 0x08, 0x5A, 0xD1, 0x75, 0x8D, 0xAB, 0x4E, 0x6F, 0xBA, 0xA5, 0x55, 0xD8, 0x82]) # https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libstratosphere/source/fssrv/fssrv_nca_crypto_configuration.cpp#L113
key_area_key_system_source          = bytes([0x87, 0x45, 0xF1, 0xBB, 0xA6, 0xBE, 0x79, 0x64, 0x7D, 0x04, 0x8B, 0xA6, 0x7B, 0x5F, 0xDA, 0x4A]) # https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libstratosphere/source/fssrv/fssrv_nca_crypto_configuration.cpp#L116
aes_kek_generation_source           = bytes([0x4D, 0x87, 0x09, 0x86, 0xC4, 0x5D, 0x20, 0x72, 0x2F, 0xBA, 0x10, 0x53, 0xDA, 0x92, 0xE8, 0xA9]) # https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L224
aes_key_generation_source           = bytes([0x89, 0x61, 0x5E, 0xE0, 0x5C, 0x31, 0xB6, 0x80, 0x5F, 0xE5, 0x8F, 0x3D, 0xA2, 0x4F, 0x7A, 0xA8]) # https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L228
titlekek_source                     = bytes([0x1E, 0xDC, 0x7B, 0x3B, 0x60, 0xE6, 0xB4, 0xD8, 0x78, 0xB8, 0x17, 0x15, 0x98, 0x5E, 0x62, 0x9B]) # https://github.com/Atmosphere-NX/Atmosphere/blob/master/exosphere/program/source/smc/secmon_smc_aes.cpp#L162

# https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libstratosphere/source/gc/impl/gc_embedded_data_holder.cpp#L142-L145
LibraryEmbeddedCardHeaderKey = [
    bytes([0x01, 0xC5, 0x8F, 0xE7, 0x00, 0x2D, 0x13, 0x5A, 0xB2, 0x9A, 0x3F, 0x69, 0x33, 0x95, 0x74, 0xB1]),
    bytes([0xCB, 0xA7, 0xB8, 0x75, 0xEB, 0x67, 0x05, 0xFB, 0x46, 0x0A, 0x33, 0xFD, 0x34, 0x09, 0x13, 0xB4]),
]

xci_header_key = LibraryEmbeddedCardHeaderKey[0] # https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libstratosphere/source/gc/impl/gc_embedded_data_holder.cpp#L186

# keyblob_key_sources
Keyblob_Key_Sources = [
    bytes([0xDF, 0x20, 0x6F, 0x59, 0x44, 0x54, 0xEF, 0xDC, 0x70, 0x74, 0x48, 0x3B, 0x0D, 0xED, 0x9F, 0xD3]),
    bytes([0x0C, 0x25, 0x61, 0x5D, 0x68, 0x4C, 0xEB, 0x42, 0x1C, 0x23, 0x79, 0xEA, 0x82, 0x25, 0x12, 0xAC]),
    bytes([0x33, 0x76, 0x85, 0xEE, 0x88, 0x4A, 0xAE, 0x0A, 0xC2, 0x8A, 0xFD, 0x7D, 0x63, 0xC0, 0x43, 0x3B]),
    bytes([0x2D, 0x1F, 0x48, 0x80, 0xED, 0xEC, 0xED, 0x3E, 0x3C, 0xF2, 0x48, 0xB5, 0x65, 0x7D, 0xF7, 0xBE]),
    bytes([0xBB, 0x5A, 0x01, 0xF9, 0x88, 0xAF, 0xF5, 0xFC, 0x6C, 0xFF, 0x07, 0x9E, 0x13, 0x3C, 0x39, 0x80]),
    bytes([0xD8, 0xCC, 0xE1, 0x26, 0x6A, 0x35, 0x3F, 0xCC, 0x20, 0xF3, 0x2D, 0x3B, 0x51, 0x7D, 0xE9, 0xC0]),
]

# bis_key_sources
Bis_Key_Sources = [
    bytes([0xF8, 0x3F, 0x38, 0x6E, 0x2C, 0xD2, 0xCA, 0x32, 0xA8, 0x9A, 0xB9, 0xAA, 0x29, 0xBF, 0xC7, 0x48, 0x7D, 0x92, 0xB0, 0x3A, 0xA8, 0xBF, 0xDE, 0xE1, 0xA7, 0x4C, 0x3B, 0x6E, 0x35, 0xCB, 0x71, 0x06]),
    bytes([0x41, 0x00, 0x30, 0x49, 0xDD, 0xCC, 0xC0, 0x65, 0x64, 0x7A, 0x7E, 0xB4, 0x1E, 0xED, 0x9C, 0x5F, 0x44, 0x42, 0x4E, 0xDA, 0xB4, 0x9D, 0xFC, 0xD9, 0x87, 0x77, 0x24, 0x9A, 0xDC, 0x9F, 0x7C, 0xA4]),
    bytes([0x52, 0xC2, 0xE9, 0xEB, 0x09, 0xE3, 0xEE, 0x29, 0x32, 0xA1, 0x0C, 0x1F, 0xB6, 0xA0, 0x92, 0x6C, 0x4D, 0x12, 0xE1, 0x4B, 0x2A, 0x47, 0x4C, 0x1C, 0x09, 0xCB, 0x03, 0x59, 0xF0, 0x15, 0xF4, 0xE4]),
    bytes([0x52, 0xC2, 0xE9, 0xEB, 0x09, 0xE3, 0xEE, 0x29, 0x32, 0xA1, 0x0C, 0x1F, 0xB6, 0xA0, 0x92, 0x6C, 0x4D, 0x12, 0xE1, 0x4B, 0x2A, 0x47, 0x4C, 0x1C, 0x09, 0xCB, 0x03, 0x59, 0xF0, 0x15, 0xF4, 0xE4]),
]

# master key sources
Master_Key_Sources = [
    #bytes([0x0C, 0xF0, 0x59, 0xAC, 0x85, 0xF6, 0x26, 0x65, 0xE1, 0xE9, 0x19, 0x55, 0xE6, 0xF2, 0x67, 0x3D]), # /* Zeroes encrypted with Master Key 00. */
    bytes([0x29, 0x4C, 0x04, 0xC8, 0xEB, 0x10, 0xED, 0x9D, 0x51, 0x64, 0x97, 0xFB, 0xF3, 0x4D, 0x50, 0xDD]), # /* Master key 00 encrypted with Master key 01. */
    bytes([0xDE, 0xCF, 0xEB, 0xEB, 0x10, 0xAE, 0x74, 0xD8, 0xAD, 0x7C, 0xF4, 0x9E, 0x62, 0xE0, 0xE8, 0x72]), # /* Master key 01 encrypted with Master key 02. */
    bytes([0x0A, 0x0D, 0xDF, 0x34, 0x22, 0x06, 0x6C, 0xA4, 0xE6, 0xB1, 0xEC, 0x71, 0x85, 0xCA, 0x4E, 0x07]), # /* Master key 02 encrypted with Master key 03. */
    bytes([0x6E, 0x7D, 0x2D, 0xC3, 0x0F, 0x59, 0xC8, 0xFA, 0x87, 0xA8, 0x2E, 0xD5, 0x89, 0x5E, 0xF3, 0xE9]), # /* Master key 03 encrypted with Master key 04. */
    bytes([0xEB, 0xF5, 0x6F, 0x83, 0x61, 0x9E, 0xF8, 0xFA, 0xE0, 0x87, 0xD7, 0xA1, 0x4E, 0x25, 0x36, 0xEE]), # /* Master key 04 encrypted with Master key 05. */
    bytes([0x1E, 0x1E, 0x22, 0xC0, 0x5A, 0x33, 0x3C, 0xB9, 0x0B, 0xA9, 0x03, 0x04, 0xBA, 0xDB, 0x07, 0x57]), # /* Master key 05 encrypted with Master key 06. */
    bytes([0xA4, 0xD4, 0x52, 0x6F, 0xD1, 0xE4, 0x36, 0xAA, 0x9F, 0xCB, 0x61, 0x27, 0x1C, 0x67, 0x65, 0x1F]), # /* Master key 06 encrypted with Master key 07. */
    bytes([0xEA, 0x60, 0xB3, 0xEA, 0xCE, 0x8F, 0x24, 0x46, 0x7D, 0x33, 0x9C, 0xD1, 0xBC, 0x24, 0x98, 0x29]), # /* Master key 07 encrypted with Master key 08. */
    bytes([0x4D, 0xD9, 0x98, 0x42, 0x45, 0x0D, 0xB1, 0x3C, 0x52, 0x0C, 0x9A, 0x44, 0xBB, 0xAD, 0xAF, 0x80]), # /* Master key 08 encrypted with Master key 09. */
    bytes([0xB8, 0x96, 0x9E, 0x4A, 0x00, 0x0D, 0xD6, 0x28, 0xB3, 0xD1, 0xDB, 0x68, 0x5F, 0xFB, 0xE1, 0x2A]), # /* Master key 09 encrypted with Master key 0A. */
    bytes([0xC1, 0x8D, 0x16, 0xBB, 0x2A, 0xE4, 0x1D, 0xD4, 0xC2, 0xC1, 0xB6, 0x40, 0x94, 0x35, 0x63, 0x98]), # /* Master key 0A encrypted with Master key 0B. */
    bytes([0xA3, 0x24, 0x65, 0x75, 0xEA, 0xCC, 0x6E, 0x8D, 0xFB, 0x5A, 0x16, 0x50, 0x74, 0xD2, 0x15, 0x06]), # /* Master key 0B encrypted with Master key 0C. */
    bytes([0x83, 0x67, 0xAF, 0x01, 0xCF, 0x93, 0xA1, 0xAB, 0x80, 0x45, 0xF7, 0x3F, 0x72, 0xFD, 0x3B, 0x38]), # /* Master key 0C encrypted with Master key 0D. */
    bytes([0xB1, 0x81, 0xA6, 0x0D, 0x72, 0xC7, 0xEE, 0x15, 0x21, 0xF3, 0xC0, 0xB5, 0x6B, 0x61, 0x6D, 0xE7]), # /* Master key 0D encrypted with Master key 0E. */
    bytes([0xAF, 0x11, 0x4C, 0x67, 0x17, 0x7A, 0x52, 0x43, 0xF7, 0x70, 0x2F, 0xC7, 0xEF, 0x81, 0x72, 0x16]), # /* Master key 0E encrypted with Master key 0F. */
    bytes([0x25, 0x12, 0x8B, 0xCB, 0xB5, 0x46, 0xA1, 0xF8, 0xE0, 0x52, 0x15, 0xB7, 0x0B, 0x57, 0x00, 0xBD]), # /* Master key 0F encrypted with Master key 10. */
    bytes([0x58, 0x15, 0xD2, 0xF6, 0x8A, 0xE8, 0x19, 0xAB, 0xFB, 0x2D, 0x52, 0x9D, 0xE7, 0x55, 0xF3, 0x93]), # /* Master key 10 encrypted with Master key 11. */
    bytes([0x4A, 0x01, 0x3B, 0xC7, 0x44, 0x6E, 0x45, 0xBD, 0xE6, 0x5E, 0x2B, 0xEC, 0x07, 0x37, 0x52, 0x86]), # /* Master key 11 encrypted with Master key 12. */
]
# ^ todo: add latest master_key_sources from https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L116-L136

master_kek_sources = [
    bytes([0x37, 0x4B, 0x77, 0x29, 0x59, 0xB4, 0x04, 0x30, 0x81, 0xF6, 0xE5, 0x8C, 0x6D, 0x36, 0x17, 0x9A]),
    bytes([0x9A, 0x3E, 0xA9, 0xAB, 0xFD, 0x56, 0x46, 0x1C, 0x9B, 0xF6, 0x48, 0x7F, 0x5C, 0xFA, 0x09, 0x5C]),
    bytes([0xDE, 0xDC, 0xE3, 0x39, 0x30, 0x88, 0x16, 0xF8, 0xAE, 0x97, 0xAD, 0xEC, 0x64, 0x2D, 0x41, 0x41]),
    bytes([0x1A, 0xEC, 0x11, 0x82, 0x2B, 0x32, 0x38, 0x7A, 0x2B, 0xED, 0xBA, 0x01, 0x47, 0x7E, 0x3B, 0x67]),
    bytes([0x30, 0x3F, 0x02, 0x7E, 0xD8, 0x38, 0xEC, 0xD7, 0x93, 0x25, 0x34, 0xB5, 0x30, 0xEB, 0xCA, 0x7A]),
    bytes([0x84, 0x67, 0xB6, 0x7F, 0x13, 0x11, 0xAE, 0xE6, 0x58, 0x9B, 0x19, 0xAF, 0x13, 0x6C, 0x80, 0x7A]),
    bytes([0x68, 0x3B, 0xCA, 0x54, 0xB8, 0x6F, 0x92, 0x48, 0xC3, 0x05, 0x76, 0x87, 0x88, 0x70, 0x79, 0x23]),
    bytes([0xF0, 0x13, 0x37, 0x9A, 0xD5, 0x63, 0x51, 0xC3, 0xB4, 0x96, 0x35, 0xBC, 0x9C, 0xE8, 0x76, 0x81]),
    bytes([0x6E, 0x77, 0x86, 0xAC, 0x83, 0x0A, 0x8D, 0x3E, 0x7D, 0xB7, 0x66, 0xA0, 0x22, 0xB7, 0x6E, 0x67]),
    bytes([0x99, 0x22, 0x09, 0x57, 0xA7, 0xF9, 0x5E, 0x94, 0xFE, 0x78, 0x7F, 0x41, 0xD6, 0xE7, 0x56, 0xE6]),
    bytes([0x71, 0xB9, 0xA6, 0xC0, 0xFF, 0x97, 0x6B, 0x0C, 0xB4, 0x40, 0xB9, 0xD5, 0x81, 0x5D, 0x81, 0x90]),
    bytes([0x00, 0x04, 0x5D, 0xF0, 0x4D, 0xCD, 0x14, 0xA3, 0x1C, 0xBF, 0xDE, 0x48, 0x55, 0xBA, 0x35, 0xC1]),
    bytes([0xD7, 0x63, 0x74, 0x46, 0x4E, 0xBA, 0x78, 0x0A, 0x7C, 0x9D, 0xB3, 0xE8, 0x7A, 0x3D, 0x71, 0xE3]),
]
# ^ todo: add latest master_kek_source from https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L36

mariko_master_kek_sources = [
    bytes([0x77, 0x60, 0x5A, 0xD2, 0xEE, 0x6E, 0xF8, 0x3C, 0x3F, 0x72, 0xE2, 0x59, 0x9D, 0xAC, 0x5E, 0x56]),
    bytes([0x1E, 0x80, 0xB8, 0x17, 0x3E, 0xC0, 0x60, 0xAA, 0x11, 0xBE, 0x1A, 0x4A, 0xA6, 0x6F, 0xE4, 0xAE]),
    bytes([0x94, 0x08, 0x67, 0xBD, 0x0A, 0x00, 0x38, 0x84, 0x11, 0xD3, 0x1A, 0xDB, 0xDD, 0x8D, 0xF1, 0x8A]),
    bytes([0x5C, 0x24, 0xE3, 0xB8, 0xB4, 0xF7, 0x00, 0xC2, 0x3C, 0xFD, 0x0A, 0xCE, 0x13, 0xC3, 0xDC, 0x23]),
    bytes([0x86, 0x69, 0xF0, 0x09, 0x87, 0xC8, 0x05, 0xAE, 0xB5, 0x7B, 0x48, 0x74, 0xDE, 0x62, 0xA6, 0x13]),
    bytes([0x0E, 0x44, 0x0C, 0xED, 0xB4, 0x36, 0xC0, 0x3F, 0xAA, 0x1D, 0xAE, 0xBF, 0x62, 0xB1, 0x09, 0x82]),
    bytes([0xE5, 0x41, 0xAC, 0xEC, 0xD1, 0xA7, 0xD1, 0xAB, 0xED, 0x03, 0x77, 0xF1, 0x27, 0xCA, 0xF8, 0xF1]),
    bytes([0x52, 0x71, 0x9B, 0xDF, 0xA7, 0x8B, 0x61, 0xD8, 0xD5, 0x85, 0x11, 0xE4, 0x8E, 0x4F, 0x74, 0xC6]),
    bytes([0xD2, 0x68, 0xC6, 0x53, 0x9D, 0x94, 0xF9, 0xA8, 0xA5, 0xA8, 0xA7, 0xC8, 0x8F, 0x53, 0x4B, 0x7A]),
    bytes([0xEC, 0x61, 0xBC, 0x82, 0x1E, 0x0F, 0x5A, 0xC3, 0x2B, 0x64, 0x3F, 0x9D, 0xD6, 0x19, 0x22, 0x2D]),
    bytes([0xA5, 0xEC, 0x16, 0x39, 0x1A, 0x30, 0x16, 0x08, 0x2E, 0xCF, 0x09, 0x6F, 0x5E, 0x7C, 0xEE, 0xA9]),
    bytes([0x8D, 0xEE, 0x9E, 0x11, 0x36, 0x3A, 0x9B, 0x0A, 0x6A, 0xC7, 0xBB, 0xE9, 0xD1, 0x03, 0xF7, 0x80]),
    bytes([0x4F, 0x41, 0x3C, 0x3B, 0xFB, 0x6A, 0x01, 0x2A, 0x68, 0x9F, 0x83, 0xE9, 0x53, 0xBD, 0x16, 0xD2]),
    bytes([0x31, 0xBE, 0x25, 0xFB, 0xDB, 0xB4, 0xEE, 0x49, 0x5C, 0x77, 0x05, 0xC2, 0x36, 0x9F, 0x34, 0x80]),
]
# ^ todo: add latest mariko_master_kek_source from https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L26

# dev keys
tsec_root_key_02_dev                    = bytes([0xCA, 0x99, 0x73, 0xE3, 0x82, 0x75, 0xB8, 0x81, 0x46, 0x25, 0x16, 0xAC, 0x18, 0xCB, 0x1D, 0xF2])

# dev master key sources
Master_Key_Sources_Dev = [
    #bytes([0x46, 0x22, 0xB4, 0x51, 0x9A, 0x7E, 0xA7, 0x7F, 0x62, 0xA1, 0x1F, 0x8F, 0xC5, 0x3A, 0xDB, 0xFE]), # /* Zeroes encrypted with Master Key 00. */
    bytes([0x39, 0x33, 0xF9, 0x31, 0xBA, 0xE4, 0xA7, 0x21, 0x2C, 0xDD, 0xB7, 0xD8, 0xB4, 0x4E, 0x37, 0x23]), # /* Master key 00 encrypted with Master key 01. */
    bytes([0x97, 0x29, 0xB0, 0x32, 0x43, 0x14, 0x8C, 0xA6, 0x85, 0xE9, 0x5A, 0x94, 0x99, 0x39, 0xAC, 0x5D]), # /* Master key 01 encrypted with Master key 02. */
    bytes([0x2C, 0xCA, 0x9C, 0x31, 0x1E, 0x07, 0xB0, 0x02, 0x97, 0x0A, 0xD8, 0x03, 0xA2, 0x76, 0x3F, 0xA3]), # /* Master key 02 encrypted with Master key 03. */
    bytes([0x9B, 0x84, 0x76, 0x14, 0x72, 0x94, 0x52, 0xCB, 0x54, 0x92, 0x9B, 0xC4, 0x8C, 0x5B, 0x0F, 0xBA]), # /* Master key 03 encrypted with Master key 04. */
    bytes([0x78, 0xD5, 0xF1, 0x20, 0x3D, 0x16, 0xE9, 0x30, 0x32, 0x27, 0x34, 0x6F, 0xCF, 0xE0, 0x27, 0xDC]), # /* Master key 04 encrypted with Master key 05. */
    bytes([0x6F, 0xD2, 0x84, 0x1D, 0x05, 0xEC, 0x40, 0x94, 0x5F, 0x18, 0xB3, 0x81, 0x09, 0x98, 0x8D, 0x4E]), # /* Master key 05 encrypted with Master key 06. */
    bytes([0x37, 0xAF, 0xAB, 0x35, 0x79, 0x09, 0xD9, 0x48, 0x29, 0xD2, 0xDB, 0xA5, 0xA5, 0xF5, 0x30, 0x19]), # /* Master key 06 encrypted with Master key 07. */
    bytes([0xEC, 0xE1, 0x46, 0x89, 0x37, 0xFD, 0xD2, 0x15, 0x8C, 0x3F, 0x24, 0x82, 0xEF, 0x49, 0x68, 0x04]), # /* Master key 07 encrypted with Master key 08. */
    bytes([0x43, 0x3D, 0xC5, 0x3B, 0xEF, 0x91, 0x02, 0x21, 0x61, 0x54, 0x63, 0x8A, 0x35, 0xE7, 0xCA, 0xEE]), # /* Master key 08 encrypted with Master key 09. */
    bytes([0x6C, 0x2E, 0xCD, 0xB3, 0x34, 0x61, 0x77, 0xF5, 0xF9, 0xB1, 0xDD, 0x61, 0x98, 0x19, 0x3E, 0xD4]), # /* Master key 09 encrypted with Master key 0A. */
    bytes([0x21, 0x88, 0x6B, 0x10, 0x9E, 0x83, 0xD6, 0x52, 0xAB, 0x08, 0xDB, 0x6D, 0x39, 0xFF, 0x1C, 0x9C]), # /* Master key 0A encrypted with Master key 0B. */
    bytes([0x8A, 0xCE, 0xC4, 0x7F, 0xBE, 0x08, 0x61, 0x88, 0xD3, 0x73, 0x64, 0x51, 0xE2, 0xB6, 0x53, 0x15]), # /* Master key 0B encrypted with Master key 0C. */
    bytes([0x08, 0xE0, 0xF4, 0xBE, 0xAA, 0x6E, 0x5A, 0xC3, 0xA6, 0xBC, 0xFE, 0xB9, 0xE2, 0xA3, 0x24, 0x12]), # /* Master key 0C encrypted with Master key 0D. */
    bytes([0xD6, 0x80, 0x98, 0xC0, 0xFA, 0xC7, 0x13, 0xCB, 0x93, 0xD2, 0x0B, 0x82, 0x4C, 0xA1, 0x7B, 0x8D]), # /* Master key 0D encrypted with Master key 0E. */
    bytes([0x78, 0x66, 0x19, 0xBD, 0x86, 0xE7, 0xC1, 0x09, 0x9B, 0x6F, 0x92, 0xB2, 0x58, 0x7D, 0xCF, 0x26]), # /* Master key 0E encrypted with Master key 0F. */
    bytes([0x39, 0x1E, 0x7E, 0xF8, 0x7E, 0x73, 0xEA, 0x6F, 0xAF, 0x00, 0x3A, 0xB4, 0xAA, 0xB8, 0xB7, 0x59]), # /* Master key 0F encrypted with Master key 10. */
    bytes([0x0C, 0x75, 0x39, 0x15, 0x53, 0xEA, 0x81, 0x11, 0xA3, 0xE0, 0xDC, 0x3D, 0x0E, 0x76, 0xC6, 0xB8]), # /* Master key 10 encrypted with Master key 11. */
    bytes([0x90, 0x64, 0xF9, 0x08, 0x29, 0x88, 0xD4, 0xDC, 0x73, 0xA4, 0xA1, 0x13, 0x9E, 0x59, 0x85, 0xA0]), # /* Master key 11 encrypted with Master key 12. */
]
# ^ todo: add latest master_key_sources from https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_key_derivation.cpp#L138-L158

# tsec keys
tsec_secret_00 = bytes([0x10, 0xC5, 0x7A, 0xC2, 0xC2, 0xA8, 0xE4, 0x03, 0x77, 0xFE, 0x77, 0x4D, 0x89, 0x2C, 0xCE, 0xA7]) # sha256(csecret_00)=7c20cef183f6184f7c5a877040ec63fa44ad42178b1aa6af9932568fc468e426
#tsec_secret_01 = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 , 0x00]) sha256(csecret_01)=43449338c1bc8ceb1b3232a611f955f9095254f492117a158528589cd16f2930
tsec_secret_05 = bytes([0xD4, 0xFC, 0xE8, 0xE4, 0x62, 0x91, 0xAA, 0x47, 0xF6, 0x0A, 0x08, 0x91, 0xB4, 0x21, 0x86, 0xF3]) # sha256(csecret_05)=49371c6ccb2cf64c10633164c202a3f7d03a17a0e0098ab7bcd9f84ae9a4805c
#tsec_secret_06 = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 , 0x00]) sha256(csecret_06)=8745f02b86bbf722654e43b1fef32ac22c740d10aa4432b93d5b2035523c2c94
tsec_secret_09 = bytes([0x46, 0xAD, 0xA3, 0x8C, 0x88, 0x9E, 0xA8, 0x31, 0x91, 0xF6, 0x26, 0x2B, 0xF5, 0x47, 0xBF, 0x16]) # sha256(csecret_09)=6836e01fce672b276e3746fac8e7a133a986c7922f2bddebd3c231fcd6a6bac5
tsec_secret_0C = bytes([0x85, 0xCC, 0x5B, 0x51, 0x92, 0x51, 0x10, 0xA9, 0xEA, 0x43, 0x4E, 0x29, 0x95, 0x58, 0x47, 0x44]) # sha256(csecret_0c)=d19495a97b6dd1dac8ee099107c731cdab49c0e1ec5b3cd1b38480d70dbe7003
tsec_secret_0F = bytes([0xAF, 0x61, 0xE0, 0x68, 0x3A, 0x6C, 0x8E, 0x96, 0x12, 0xF6, 0x5F, 0xBC, 0x29, 0x0F, 0x5D, 0xB7]) # sha256(csecret_0f)=34141a2aa355cfa1d14ec921db288d1cd04c810c3c30c69abb34bb1542a9966f
tsec_secret_12 = bytes([0xB4, 0xF0, 0xA3, 0x08, 0xDC, 0x81, 0xF6, 0x5C, 0xAB, 0x5C, 0xCC, 0xB5, 0x3A, 0x70, 0xCE, 0xAE]) # sha256(csecret_12)=641622358b351d50e7f3f2cfee6864a68fa7803a649a2bcade226a99a143918a
tsec_secret_15 = bytes([0xF3, 0x21, 0x50, 0xC4, 0x2A, 0x66, 0x5F, 0xD2, 0x81, 0xED, 0xAA, 0x7F, 0x3D, 0xA5, 0xC6, 0xC9]) # sha256(csecret_15)=9c90367e3b4191706f1018861f1622e233d905445e6f2463bedbdea2f4395205
tsec_secret_18 = bytes([0x24, 0x81, 0xB1, 0x71, 0xEA, 0x7C, 0x06, 0x4C, 0xE5, 0x25, 0x4F, 0x57, 0x69, 0x6A, 0x34, 0x79]) # sha256(csecret_18)=40c4d1dfb08fb9963ad20076681651a124f325a6065db51c1b88b2efd8799d01
tsec_secret_1B = bytes([0x52, 0x16, 0xF3, 0x26, 0xCE, 0x98, 0x2E, 0xD6, 0x38, 0x2E, 0x4B, 0x89, 0x6A, 0x9D, 0x09, 0x46]) # sha256(csecret_1b)=0bde3d9cb209d1c132d1c9e80c0ccf595e3feef411be7ee590e181af57421815
tsec_secret_1E = bytes([0x9C, 0x8D, 0xA7, 0x63, 0x89, 0xA2, 0xA8, 0x19, 0x28, 0x7B, 0x90, 0xFB, 0x9C, 0xF0, 0x9E, 0xF9]) # sha256(csecret_1e)=02667ae7cbe9a608a648eec9876dc66159068aceb872901a085ce6968f5d17a1
tsec_secret_21 = bytes([0xD5, 0x80, 0xCE, 0x3A, 0x10, 0x54, 0xF3, 0xD8, 0x9F, 0x01, 0x40, 0xA5, 0x45, 0x1C, 0x1D, 0x7B]) # sha256(csecret_21)=5ad7845f27ea0aa7c717ff56d4cffe5d060a374d86a0e820bdc13fc5f553226b
tsec_secret_24 = bytes([0xB4, 0x8C, 0x3A, 0x10, 0xF0, 0xB3, 0xA5, 0x57, 0x06, 0x12, 0x15, 0x7B, 0xE4, 0xFC, 0x4D, 0x6D]) # sha256(csecret_24)=c8312de41a98f7c55c4e21184b1f34a7578145c2cbeca78a9556978dd84939e3
tsec_secret_26 = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) # sha256(csecret_26)=cefe01c9e3eeef1a73b8c10d742ae386279b7dff30a2fbc0aabd058c1f135833
tsec_secret_27 = bytes([0x98, 0x27, 0x3D, 0x6A, 0xBD, 0xD2, 0x79, 0xCE, 0x96, 0x43, 0x19, 0xBB, 0x64, 0x4A, 0xC2, 0x3C]) # sha256(csecret_27)=d3ade4766781a5d9862b350867c2572dcb7f513b28c3a812170cd856dfb54f95
tsec_secret_2A = bytes([0xA5, 0x23, 0x30, 0xBA, 0x33, 0x08, 0xC6, 0xF5, 0x3D, 0x9F, 0x1C, 0x0E, 0x2A, 0x80, 0x66, 0x9C]) # sha256(csecret_2a)=08a0edf7bf91d7fa685ca77246b8394fa4edd0e06639e53e6fa835436b09560f
tsec_secret_2D = bytes([0xFB, 0x59, 0xA5, 0x18, 0xA4, 0xBE, 0xAD, 0x3D, 0x12, 0x80, 0xCD, 0x2B, 0xBD, 0x3A, 0x08, 0xE2]) # sha256(csecret_2d)=07923cbd0e19d3b8c81d3f5d4df8ef58ec667f94e6096897de34c1ebf878b2b0
tsec_secret_30 = bytes([0xAF, 0x5E, 0x7B, 0x17, 0xD9, 0x3C, 0xAA, 0xC1, 0xFD, 0x81, 0x9D, 0x3A, 0xD7, 0x09, 0xD0, 0x05]) # sha256(csecret_30)=3477d86ed721fd5112c94a566f26b4d30cd7ae78de1b047eb21a709a7934d073
tsec_secret_33 = bytes([0xA5, 0xFD, 0x0F, 0x19, 0x61, 0x44, 0x7D, 0x1C, 0x64, 0xDE, 0xB0, 0x5D, 0x48, 0xD7, 0x9F, 0x4C]) # sha256(csecret_33)=fa7f4a5cb39ae9205177f3da8f8c2f88ec7f8d14b8c6f75b2dbb661f30ec076d
tsec_secret_36 = bytes([0x1E, 0xE0, 0xD1, 0x51, 0x59, 0xB4, 0x20, 0x89, 0xBD, 0xDC, 0x11, 0xC0, 0x07, 0x0F, 0x21, 0xD9]) # sha256(csecret_36)=083bd0a21da79ae6b63c9e01035fad9334983c79a43d555dba5481c6d531b30f
tsec_secret_39 = bytes([0x74, 0xC7, 0xF3, 0x7E, 0xF3, 0x42, 0x1E, 0xE7, 0x30, 0x78, 0x96, 0xCE, 0xA2, 0x3E, 0x4E, 0xE9]) # sha256(csecret_39)=78a4c4ad790921ab5c6f3224ea394fb53e576110d1fa467b3aa942b5c141cfa8
tsec_secret_3C = bytes([0xA5, 0xF6, 0xA7, 0x89, 0xD7, 0x80, 0x83, 0x4E, 0x0C, 0xF5, 0x04, 0x8D, 0x0D, 0x81, 0x8F, 0x57]) # sha256(csecret_3c)=29b30980914a0201a195dab7c5494d2ca9c94205619c2f91dd74ddeea24d14f0

zeroes = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])