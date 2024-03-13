This repository contains reverse engineering notes and guides for educational purposes, using open source tools such as ghidra to pry into binaries for the Nintendo Switch. It also contains basic methodology on how to operate ghidra with the intent to inspect "ARM" binaries that run on the Nintendo Switch.

This repository does not host, nor contain guides or scripts to circumvent security measures to safeguard digital assets.

* Ghidra/Patch making tutorial:
  - Part 1A detailing how to set up ghidra and the switch loader for windows [(link)](guides/Part1A-WindowsSetup.MD)
  - Part 1B detailing how to set up ghidra and the switch loader for linux [(link)](guides/Part1B-LinuxSetup.MD)
  - Part 2 detailing how to set up hactool and hactoolnet to output files to work further with, and a basic introduction to ghidra with making patches for nifm as an example. [(link)](guides/Part2.MD)
  - you can find the resulting "patches" for what this guide produces, at https://github.com/misson20000/exefs_patches/tree/master/atmosphere/exefs_patches/nfim_ctest


** note: the referenced "loader", is a reference to the re-implementation belonging to the "Atmosphere" project; https://github.com/Atmosphere-NX/Atmosphere/tree/master/stratosphere/loader **

* Here's a list of scripts following the example Part 2 of the guide above teaches you how to do, and that this repository contains.
  - Python script to generate patches for Atmospheres open-source loader re-implementation, requires lz4 from pip, usage: use "python scripts/atmosphere_loader_patch.py" and it will automatically download, make patches, then clean up after itself. [(link)](scripts/atmosphere_loader_patch.py)
  - Python script to generate the "[disable_ca_verification patch](https://github.com/misson20000/exefs_patches#disable-ca-verification)", [(link)](scripts/disable_ca_verification_patch.py)
  - Python script to generate the "[disable_browser_ca_verification patch](https://github.com/misson20000/exefs_patches#disable-browser-ca-verification)", [(link)](scripts/disable_browser_ca_verification_patch.py)
  - Python script to generate the "[nifm_ctest patch](https://github.com/misson20000/exefs_patches#nifm-ctest)", [(link)](scripts/nifm_ctest_patch.py)

* Credits: [@borntohonk](https://github.com/borntohonk)
