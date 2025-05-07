This repository contains reverse engineering notes and guides for educational purposes, using open source tools such as ghidra to pry into binaries for the Nintendo Switch. It also contains basic methodology on how to operate ghidra with the intent to inspect "ARM" binaries that run on the Nintendo Switch.

This repository does not host, nor contain guides that assist with circumventing security measures that safeguard digital assets.

All material exist purely for research reference.

* Ghidra/Patch making tutorial:
  - Part 1A detailing how to set up ghidra and the switch loader for windows [(link)](guides/Part1A-WindowsSetup.MD)
  - Part 1B detailing how to set up ghidra and the switch loader for linux [(link)](guides/Part1B-LinuxSetup.MD)
  - Part 2 detailing how to set up hactoolnet to output files to work further with, and a basic introduction to ghidra with making patches for nifm as an example. [(link)](guides/Part2.MD)
  - you can find the resulting "patches" for what this guide produces, at https://github.com/misson20000/exefs_patches/tree/master/atmosphere/exefs_patches/nfim_ctest


* Here's a list of scripts following the example Part 2 of the guide above teaches you how to do, and that this repository contains.

  - Python script to obtain the latest mariko_master_kek_source_%% from provided firmware files, and provide strings to update the arrays for key_sources.py, requires lz4 from pip  
    * example usage: "python scripts/mariko_master_kek_source.py --firmware firmware" [mariko_master_kek_source.py](scripts/mariko_master_kek_source.py)
    * requires pycryptodome/pycryptodomex (or python3-pycryptodome from apt if debian/ubuntu which is pycryptodomex, python-pycryptodome from arch linux pacman repositories which is pycryptodome)
    * updating scripts/key_sources.py will benefit key generation for [aes_sample.py](scripts/aes_sample.py)

  - Python script to derive entire keyset. [aes_sample.py](scripts/aes_sample.py)
    * The cryptographic logic described can be sampled with this python script, output keyfile (default "prod.keys", can be altered with -k) : [aes_sample.py](scripts/aes_sample.py)
    * There is also a developer variant, which works the same way, [aes_sample_dev.py](scripts/aes_sample_dev.py)
    * requires pycryptodome/pycryptodomex (or python3-pycryptodome from apt if debian/ubuntu which is pycryptodomex, python-pycryptodome from arch linux pacman repositories which is pycryptodome)

  - Python script to check known patterns for sys-patch.
    * Usage: put firmware files in a folder named firmware, or supply a location with -l or --location, supply keys with -k or --keys., otherwise it will default to ~/.switch/prod.keys
    * example usage: "python scripts/check_patches.py --location temp_folder --keys prod.keys"
    * [check_patches.py](scripts/check_patches.py)
    * requires pycryptodome/pycryptodomex (or python3-pycryptodome from apt if debian/ubuntu which is pycryptodomex, python-pycryptodome from arch linux pacman repositories which is pycryptodome)

  - Python script to generate the "[disable_ca_verification patch](https://github.com/misson20000/exefs_patches#disable-ca-verification)", [(link)](scripts/disable_ca_verification_patch.py) - no longer maintained as of firmware version 19.0.0

  - Python script to generate the "[disable_browser_ca_verification patch](https://github.com/misson20000/exefs_patches#disable-browser-ca-verification)", [(link)](scripts/disable_browser_ca_verification_patch.py) - no longer maintained as of firmware version 19.0.0

* Credits: 
* [@sciresm](https://github.com/SciresM) - hactool -  [(scripts/aes128.py)](scripts/aes128.py)
* [@reswitched](https://github.com/reswitched) - [(scripts/nxo64.py)](scripts/nxo64.py)
* [@Thealexbarney](https://github.com/Thealexbarney) - libhac/hactoolnet
* [@blawar](https://github.com/blawar) - for references to various things in [nut](https://github.com/blawar/nut)
* everything else:
* [@borntohonk](https://github.com/borntohonk)
