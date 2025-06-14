This repository contains reverse engineering notes and guides for educational purposes, using open source tools such as ghidra to pry into binaries for the Nintendo Switch. It also contains basic methodology on how to operate ghidra with the intent to inspect "ARM" binaries that run on the Nintendo Switch.

This repository does not host, nor contain guides that assist with circumventing security measures that safeguard digital assets.

All material exist purely for research reference.

* Ghidra/Patch making tutorial:
  - Part 1A detailing how to set up ghidra and the switch loader for windows [(link)](guides/Part1A-WindowsSetup.MD)
  - Part 1B detailing how to set up ghidra and the switch loader for linux [(link)](guides/Part1B-LinuxSetup.MD)
  - Part 2 detailing a basic introduction to ghidra, with a demonstration of how to force enable the network connectivity, within the module known as "NIFM". [(link)](guides/Part2.MD)
  - you can find the resulting "patches" for what this guide produces, at https://github.com/misson20000/exefs_patches/tree/master/atmosphere/exefs_patches/nfim_ctest

* Here's a list of scripts following the example Part 2 of the guide above teaches you how to do, and that this repository contains.
  - Python script to generate the "[disable_ca_verification patch](https://github.com/misson20000/exefs_patches#disable-ca-verification)", [(link)](scripts/disable_ca_verification_patch.py) - no longer maintained as of firmware version 19.0.0, due to lack of interest. (this patch also exists in sys-patch as of version 1.5.5 and higher, though requiring to manually enable the setting.)

  - Python script to generate the "[disable_browser_ca_verification patch](https://github.com/misson20000/exefs_patches#disable-browser-ca-verification)", [(link)](scripts/disable_browser_ca_verification_patch.py) - no longer maintained as of firmware version 19.0.0, due to lack of interest.

* Credits: 
* [@sciresm](https://github.com/SciresM) - hactool -  aes128.py
* [@reswitched](https://github.com/reswitched) - [(scripts/nxo64.py)](scripts/nxo64.py)
* [@blawar](https://github.com/blawar) - for references to various things in [nut](https://github.com/blawar/nut)
* everything else:
* [@borntohonk](https://github.com/borntohonk)
