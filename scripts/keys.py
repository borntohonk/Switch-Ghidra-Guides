class RootKeys():
    def __init__(self):
        # REQUIRED:
        # sha256(mariko_bek) = 491A836813E0733A0697B2FA27D0922D3D6325CE3C6BBEA982CF4691FAF6451A
        self.mariko_bek                          = bytes.fromhex("6A5D000000000000000000000000C222") # FILL THIS IN WITH THE ACTUAL KEY

        # REQUIRED:
        # sha256(mariko_kek) = ACEA0798A729E8E0B3EF6D83CF7F345537E41ACCCCCAD8686D35E3F5454D5132
        self.mariko_kek                          = bytes.fromhex("4130000000000000000000000000B77C") # FILL THIS IN WITH THE ACTUAL KEY