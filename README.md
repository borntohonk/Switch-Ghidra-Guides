This repository contains reverse engineering notes and guides for educational purposes, using open source tools such as ghidra to pry into binaries for the Nintendo Switch. It also contains basic methodology on how to operate ghidra with the intent to inspect "ARM" binaries that run on the Nintendo Switch.

This repository does not host, nor contain guides that assist with circumventing security measures that safeguard digital assets.

All material exist purely for research reference.

* Ghidra/Patch making tutorial:
  - Part 1A detailing how to set up ghidra and the switch loader for windows [(link)](guides/Part1A-WindowsSetup.MD)
  - Part 1B detailing how to set up ghidra and the switch loader for linux [(link)](guides/Part1B-LinuxSetup.MD)
  - Part 2 detailing a basic introduction to ghidra, with a demonstration of how to force enable the network connectivity, within the module known as "NIFM". [(link)](guides/Part2.MD)
  - you can find the resulting "patches" for what this guide produces, at https://github.com/misson20000/exefs_patches/tree/master/atmosphere/exefs_patches/nfim_ctest


  These scripts work independent of hactool, libhac, hactoolnet, or other third-party binaries.

* Here's a list of scripts following the example Part 2 of the guide above teaches you how to do, and that this repository contains.

  - Python script to process firmware files, decrypting, extracting, decompressing and outputting files of interest, and cryptographic keys derived.
    * All cryptographic functions rely on root keys to be filled into the [keys.py](scripts/keys.py) file, root keys such as: mariko_bek, mariko_kek, tsec_root_key_02, tsec_root_key_02_dev
    * Zero cryptographic functions can be performed without the root keys.
    * bare minimum requirement is mariko bek and mariko kek, which must be obtained and filled in, using tools such as lockpick_rcm, or sourcing them elsewhere, such as from the scene release .nfo from "Marvels.SpiderMan.Miles.Morales.PS5-BigBlueBox"
    * requires the following keys: mariko_bek (to open mariko package1), mariko_kek (to be able to derive the latest key revision in provided firmware files)
    * put firmware nca files in folder named firmware
    * example usage: "python scripts/process_firmware.py [process_firmware.py](scripts/process_firmware.py)
    * requires pycryptodome/pycryptodomex (or python3-pycryptodome from apt if debian/ubuntu which is pycryptodomex, python-pycryptodome from arch linux pacman repositories which is pycryptodome)
    * updating scripts/key_sources.py will benefit key generation for [aes_sample.py](scripts/aes_sample.py)

  - Python script to derive entire keyset. [aes_sample.py](scripts/aes_sample.py)
    * The cryptographic logic described can be sampled with this python script, the default output keyfile is "prod.keys". [aes_sample.py](scripts/aes_sample.py)
    * requires pycryptodome/pycryptodomex (or python3-pycryptodome from apt if debian/ubuntu which is pycryptodomex, python-pycryptodome from arch linux pacman repositories which is pycryptodome)

  - Python script to check known patterns for sys-patch.
    * Usage: run [process_firmware.py](scripts/process_firmware.py) first, then the files for check_patches should be populated.
    * example usage: "python scripts/check_patches.py"
    * [check_patches.py](scripts/check_patches.py)
    * requires pycryptodome/pycryptodomex (or python3-pycryptodome from apt if debian/ubuntu which is pycryptodomex, python-pycryptodome from arch linux pacman repositories which is pycryptodome)

  - Python script to generate the "[disable_ca_verification patch](https://github.com/misson20000/exefs_patches#disable-ca-verification)", [(link)](scripts/disable_ca_verification_patch.py) - no longer maintained as of firmware version 19.0.0, due to lack of interest. (this patch also exists in sys-patch as of version 1.5.5 and higher, though requirin to manually enable)

  - Python script to generate the "[disable_browser_ca_verification patch](https://github.com/misson20000/exefs_patches#disable-browser-ca-verification)", [(link)](scripts/disable_browser_ca_verification_patch.py) - no longer maintained as of firmware version 19.0.0, due to lack of interest.




* TODO: 
  - extract every section of input nca (completed, but currently static assigned to section 0 of desired input ncas)
  - extract all items of romfs (COMPLETED)
  - extract all items of pfs0 (Completed - partially - ignores .npdm, but dynamically extracts the main exefs file now)


* Credits: 
  - [switchbrew](https://switchbrew.org) for all the information on formats, and cryptography.
  - [@sciresm](https://github.com/SciresM) - hactool, for references on formats -  [(scripts/aes_128.py)](scripts/aes_128.py)
  - [@reswitched](https://github.com/reswitched) - [(scripts/nxo64.py)](scripts/nxo64.py)
  - [@blawar](https://github.com/blawar) - for references to various things in [nut](https://github.com/blawar/nut)
  - everything else:
  - [@borntohonk](https://github.com/borntohonk)
