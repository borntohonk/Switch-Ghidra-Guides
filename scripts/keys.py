class RootKeys():
    def __init__(self):
        # REQUIRED:
        # sha256(mariko_bek) = 491A836813E0733A0697B2FA27D0922D3D6325CE3C6BBEA982CF4691FAF6451A
        self.mariko_bek                          = bytes.fromhex("6A5D000000000000000000000000C222") # FILL THIS IN WITH THE ACTUAL KEY

        # REQUIRED:
        # sha256(mariko_kek) = ACEA0798A729E8E0B3EF6D83CF7F345537E41ACCCCCAD8686D35E3F5454D5132
        self.mariko_kek                          = bytes.fromhex("4130000000000000000000000000B77C") # FILL THIS IN WITH THE ACTUAL KEY
        
        # optional
        # sha256(tsec_root_key_00) = 032ADF0A6BE7DD7C11A4FA5CD64A1575E469B9DA5D8BD56A12D0FBC0EB84E8E7
        self.tsec_root_key_00                    = bytes.fromhex("E21D000000000000000000000000DE9E") # FILL THIS IN WITH THE ACTUAL KEY

        # optional
        # sha256(tsec_root_key_01) = 44BF5DAA1CDD841F68DBB14E8ADFEB49EB5E5A2089B7CE7276F8011DA42CA517
        self.tsec_root_key_01                    = bytes.fromhex("522E000000000000000000000000B341") # FILL THIS IN WITH THE ACTUAL KEY

        # optional; needed for erista source generation)
        # sha256(tsec_root_key_02) = 7363C28104715099398BD5165632B4C2F74B8FD819A03CBF71DB1F362CA30FD3
        self.tsec_root_key_02                    = bytes.fromhex("4B4F00000000000000000000000048EC") # FILL THIS IN WITH THE ACTUAL KEY
        
        # optional; needed for dev key generation)
        # sha256(tsec_root_key_02_dev) = 2A5D9F482B5CB66EBC0308B4668C08F8A5437B146BEBC68D608E657CD200CFB3
        self.tsec_root_key_02_dev                = bytes.fromhex("CA990000000000000000000000001DF2") # FILL THIS IN WITH THE ACTUAL KEY

        # optional, also known as tsec_secret_26. (this key makes tsec_root_key_%% obsolete)
        # sha256(hovi_kek) = CEFE01C9E3EEEF1A73B8C10D742AE386279B7DFF30A2FBC0AABD058C1F135833
        self.hovi_kek                            = bytes.fromhex("00000000000000000000000000000000") # FILL THIS IN WITH THE ACTUAL KEY