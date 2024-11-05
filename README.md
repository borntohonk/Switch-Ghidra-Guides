This repository contains reverse engineering notes and guides for educational purposes, using open source tools such as ghidra to pry into binaries for the Nintendo Switch. It also contains basic methodology on how to operate ghidra with the intent to inspect "ARM" binaries that run on the Nintendo Switch.

This repository does not host, nor contain guides that assist with circumventing security measures that safeguard digital assets.

All material exist purely for research reference.

* Ghidra/Patch making tutorial:
  - Part 1A detailing how to set up ghidra and the switch loader for windows [(link)](guides/Part1A-WindowsSetup.MD)
  - Part 1B detailing how to set up ghidra and the switch loader for linux [(link)](guides/Part1B-LinuxSetup.MD)
  - Part 2 detailing how to set up hactool and hactoolnet to output files to work further with, and a basic introduction to ghidra with making patches for nifm as an example. [(link)](guides/Part2.MD)
  - you can find the resulting "patches" for what this guide produces, at https://github.com/misson20000/exefs_patches/tree/master/atmosphere/exefs_patches/nfim_ctest


** note: the referenced "loader", is a reference to the re-implementation belonging to the "Atmosphere" project; https://github.com/Atmosphere-NX/Atmosphere/tree/master/stratosphere/loader **

* Here's a list of scripts following the example Part 2 of the guide above teaches you how to do, and that this repository contains.

  - Python script to derive entire keyset for the firmware version you have provided firmware files for.
    * requirements: firmware files to be used with [mariko_keygen.py](scripts/mariko_keygen.py)
    * It will obtain the key source referred to as "mariko_master_kek_source_%%" from the firmware files you've provided, and output to prod.keys or a file location you've designated with -k or --keys.
    * This script eliminates the need for "lockpick" of any kind, as long as the user provides firmware files.
    * This script works by first extracting the nca containing package1 with master_key_00, then extracting "package1" with the "mariko_bek" (obtainable with the release.nfo for scene release of "Marvel's Spider-Man: Miles Morales" by BigBlueBox), and then proceeds in finding "mariko_master_kek_source_%%", And then transforms "mariko_master_kek_source_%%" using "mariko_kek" to become "master_kek" and subsequently sets off the key derivation chain, using the tool "hactoolnet".
    * the cryptographic logic described can be sampled with this python script, output keyfile (default "prod.keys", can be altered with -k) : [aes_sample.py](scripts/aes_sample.py)
    * Usage: do "python scripts/mariko_keygen.py -f folder -k prod.keys" with firmware files present in a folder called firmware, or as supplied with -f or --firmware, or store the keys at another location as supplied with -k or --keys . [mariko_keygen.py](scripts/mariko_keygen.py)

  - Python script to generate patches for Atmospheres open-source loader re-implementation, requires lz4 from pip 
    * Usage: do "python scripts/atmosphere_loader_patch.py" and it will automatically download, make the patch for loader, and then clean up after itself. [atmosphere_loader_patch.py](scripts/atmosphere_loader_patch.py)

  - Python script to batch create patches for provided firmware files.
    * Usage: put firmware files in a folder named firmware, or supply a location with -l or --location, supply keys with -k or --keys., otherwise it will default to ~/.switch/prod.keys
    * example usage: "python scripts/make_patches.py --location temp_folder --keys prod.keys"
    * If the end user has mariko_bek and mariko_kek (obtainable with the release.nfo for scene release of "Marvel's Spider-Man: Miles Morales" by BigBlueBox), keygen will also be attempted to be performed.
    * [make_patches.py](scripts/make_patches.py)

  - Python script to generate the "[disable_ca_verification patch](https://github.com/misson20000/exefs_patches#disable-ca-verification)", [(link)](scripts/disable_ca_verification_patch.py)

  - Python script to generate the "[disable_browser_ca_verification patch](https://github.com/misson20000/exefs_patches#disable-browser-ca-verification)", [(link)](scripts/disable_browser_ca_verification_patch.py)

  - Python script to generate the "[nifm_ctest patch](https://github.com/misson20000/exefs_patches#nifm-ctest)", [(link)](scripts/nifm_ctest_patch.py)

* Credits: [@borntohonk](https://github.com/borntohonk)
