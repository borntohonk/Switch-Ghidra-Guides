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
    * optionally one can fill in the mariko_kek and mariko_bek keys into [keys.py](scripts/keys.py) file, to derive mariko_master_kek_source, if desired.
    * mariko bek and mariko kek, which can be obtained and filled in, using tools such as lockpick_rcm, or sourcing them elsewhere, such as from the scene release .nfo from "Marvels.SpiderMan.Miles.Morales.PS5-BigBlueBox"
    * put firmware nca files in folder named firmware
    * example usage: "python scripts/process_firmware.py [process_firmware.py](scripts/process_firmware.py)
    * requires pycryptodome/pycryptodomex (or python3-pycryptodome from apt if debian/ubuntu which is pycryptodomex, python-pycryptodome from arch linux pacman repositories which is pycryptodome)
    * updating scripts/key_sources.py will benefit key generation for [aes_sample.py](scripts/aes_sample.py)

  - Python script to batch process firmware files, decrypting, extracting, decompressing and outputting files of interest, and cryptographic keys derived.
    * optionally one can fill in the mariko_kek and mariko_bek keys into [keys.py](scripts/keys.py) file, to derive mariko_master_kek_source, if desired.
    * mariko bek and mariko kek, which can be obtained and filled in, using tools such as lockpick_rcm, or sourcing them elsewhere, such as from the scene release .nfo from "Marvels.SpiderMan.Miles.Morales.PS5-BigBlueBox"
    * put firmware nca files in in subfolders inside of the folder "firmwares"
    * example usage: "python scripts/batch_process_firmware.py [batch_process_firmware.py](scripts/batch_process_firmware.py)
    * requires pycryptodome/pycryptodomex (or python3-pycryptodome from apt if debian/ubuntu which is pycryptodomex, python-pycryptodome from arch linux pacman repositories which is pycryptodome)
    * updating scripts/key_sources.py will benefit key generation for [aes_sample.py](scripts/aes_sample.py)

  - Python script to derive entire keyset. [aes_sample.py](scripts/aes_sample.py)
    * The cryptographic logic described can be sampled with this python script, the default output keyfile is "prod.keys". [aes_sample.py](scripts/aes_sample.py)
    * requires pycryptodome/pycryptodomex (or python3-pycryptodome from apt if debian/ubuntu which is pycryptodomex, python-pycryptodome from arch linux pacman repositories which is pycryptodome)

  - Python script to check known patterns for sys-patch, and collect string diffs for making regex strings.
    * Usage: run [process_firmware.py](scripts/process_firmware.py) first, then the files for [find_patterns.py](scripts/find_patterns.py) should be populated.
    * or batch process firmwares with [batch_process_firmwares.py] (scripts/bulk_process_firmware.py)
    * example usage: "python scripts/find_patterns.py --ams", where --ams is an optional condition to also check the atmosphere loader patch
    * having multiple firmwares processed and their binaries output/, will greatly improve the amount of string diffs populated.
    * [find_patterns.py](scripts/find_patterns.py)
    * requires pycryptodome/pycryptodomex (or python3-pycryptodome from apt if debian/ubuntu which is pycryptodomex, python-pycryptodome from arch linux pacman repositories which is pycryptodome)
    * requires capstone
    * both requirements can be installed from pip (python3 -m pip install pycryptodome capstone)
    * running [generate_pattern_diffs.py] (scripts/generate_pattern_diffs.py) afterwards will fill make an attempt at combining the outputs aligned for easier visual creation of patterns.
    * the output from [generate_pattern_diffs.py] (scripts/generate_pattern_diffs.py) should populate [known_patterns.py] (scripts/known_patterns.py)

  - Python script to decrypt atmosphere's [tsec_keygen.bin](https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/tsec_keygen/tsec_keygen.bin)
    * Usage: run [decrypt_atmosphere_tsec_keygen.py](scripts/decrypt_atmosphere_tsec_keygen.py)
    * example: "python scripts/decrypt_atmosphere_tsec_keygen.py"
    * requires pycryptodome/pycryptodomex (or python3-pycryptodome from apt if debian/ubuntu which is pycryptodomex, python-pycryptodome from arch linux pacman repositories which is pycryptodome)
    * the entire decrypted tsec_keygen.bin payload is output as decrypted_tsec_keygen.bin and can be viewed with tools such as the [envydis](https://github.com/envytools/envytools) or viewed in ghidra with [ghidra_falcon](https://github.com/marysaka/ghidra_falcon)

  - Python script to generate the "[disable_ca_verification patch](https://github.com/misson20000/exefs_patches#disable-ca-verification)", [(link)](scripts/disable_ca_verification_patch.py) - no longer maintained as of firmware version 19.0.0, due to lack of interest.

  - Python script to generate the "[disable_browser_ca_verification patch](https://github.com/misson20000/exefs_patches#disable-browser-ca-verification)", [(link)](scripts/disable_browser_ca_verification_patch.py) - no longer maintained as of firmware version 19.0.0, due to lack of interest.




* TODO: 
  - extract every section of input nca (completed, but currently static assigned to section 0 of desired input ncas - not needed for firmware files of interest)

* Credits: 
  - [switchbrew](https://switchbrew.org) for all the information on formats, and cryptography.
  - [@sciresm](https://github.com/SciresM) - hactool, for references on formats -  [(scripts/aes_128.py)](scripts/aes_128.py) - [tsec_keygen.bin](https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/tsec_keygen/tsec_keygen.bin)
  - [@reswitched](https://github.com/reswitched) - [(scripts/nxo64.py)](scripts/nxo64.py)
  - [@blawar](https://github.com/blawar) - for references to various things in [nut](https://github.com/blawar/nut)
  - everything else:
  - [@borntohonk](https://github.com/borntohonk)
