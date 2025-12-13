# hashes and buildids are technically not patterns, but this is a convenient place to put them:



#TODO:
#   * obtain all firmwares
#   * extract all modules
#   * catalog all hashes and buildids, pair them with firmware revisions and keygen revisions
#   * make check_patches.py require defining version input, or all, get version from /output/foldername/
#   * then have check_patches use matching firmware version from this file (optional - add to check_patches.py if wanted)
#   * use pattern compliant with firmware version entered (or all, from /output/foldername/)
#   * if firmware input is not recognized, default to latest pattern, make an alias that x pattern == latest_ssl_pattern, and so on.
#       * if no input is given, default to using firmware/sorted_firmware folder + output/(firmware_version_number/
#
#
#   * !!this is part of adding support for more versions than the very latest version only!!

class FirmwareRevisions():
    def __init__(self):
        self.firmware_revisions = [
            ('1.0.0'), ('2.0.0'), ('2.1.0'), ('2.3.0'), ('3.0.0'),
            ('3.0.1'), ('3.0.2'), ('4.0.0'), ('4.0.1'), ('4.1.0'),
            ('5.0.0'), ('6.0.0'), ('6.0.1'), ('6.1.0'), ('7.0.0'),
            ('7.0.1'), ('8.0.0'), ('8.0.1'), ('8.1.0'), ('8.1.1'),
            ('9.0.0'), ('9.0.1'), ('9.1.0'), ('9.2.0'), ('10.0.0'),
            ('10.0.1'), ('10.0.2'), ('10.0.3'), ('10.0.4'), ('10.1.0'),
            ('10.2.0'), ('11.0.0'), ('11.0.1'), ('12.0.0'), ('12.0.1'),
            ('12.0.2'), ('12.0.3'), ('12.1.0'), ('13.0.0'), ('13.1.0'),
            ('13.2.0'), ('13.2.1'), ('14.0.0'), ('14.1.0'), ('14.1.1'),
            ('14.1.2'), ('15.0.0'), ('16.0.0'), ('16.0.1'), ('16.0.1'),
            ('16.0.2'), ('16.0.3'), ('16.1.0'), ('17.0.0'), ('17.0.1'),
            ('18.0.0'), ('18.0.1'), ('18.1.0'), ('19.0.0'), ('19.0.1'),
            ('20.0.0'), ('20.0.1'), ('20.1.0'), ('20.1.1'), ('20.1.5'),
            ('20.2.0'), ('20.3.0'), ('20.4.0'), ('20.5.0'), ('21.0.0'),
            ('21.0.1'), ('21.1.0'),
        ]

        self.keygen_revisions = [
            ('0'),
            ('1'),
            ('2'),
            ('3'), # '0x03', '3.0.1',
            ('4'), # '0x04', '4.0.0',
            ('5'), # '0x05', '5.0.0',
            ('6'), # '0x06', '6.0.0',
            ('7'), # '0x07', '6.2.0',
            ('8'), # '0x08', '7.0.0',
            ('9'), # '0x09', '8.1.0',
            ('10'), #  '0x0A', '9.0.0',
            ('11'), #  '0x0B', '9.1.0',
            ('12'), #  '0x0C', '12.1.0',
            ('13'), #  '0x0D', '13.0.0',
            ('14'), #  '0x0E', '14.0.0',
            ('15'), #  '0x0F', '15.0.0',
            ('16'), #  '0x10', '16.0.0',
            ('17'), #  '0x11', '17.0.0',
            ('18'), #  '0x12', '18.0.0',
            ('19'), #  '0x13', '19.0.0',
            ('20'), #  '0x14', '20.0.0',
            ('21'), #  '0x15', '21.0.0',
        ]


class Hashes():
    def __init__(self):
        self.fs = [
            "placeholder"
        ]

class BuildIds():
    def __init__(self):
        self.ssl = [
            "placeholder"
        ]
        self.nim = [
            "placeholder"
        ]
        self.nifm = [
            "placeholder"
        ]
        self.es = [
            "placeholder"
        ]
        

class Patterns():
    def __init__(self):
        self.ssl = [
            "placeholder"
        ]
        self.nim = [
            "placeholder"
        ]
        self.nifm = [
            "placeholder"
        ]
        self.es = [
            "placeholder"
        ]
        self.fs = [
            "placeholder"
        ]
