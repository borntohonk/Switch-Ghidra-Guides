Part 2 of this guide assumes you have succesfully set up ghidra as described in Part1A (for windows users) or Part1B (for linux users).

Part 2 will go through the basics of getting the type of switch binaries you need. To proceed you will need Hactoolnet (https://github.com/Thealexbarney/LibHac/releases), hactool (https://github.com/SciresM/hactool) for decompressing the binaries, the binaries for hactool can be gotten from the artifacts (requires logging into github) or compiling it yourself. Set up an enviroment variable for hactool & hactoolnet / place it /usr/local/bin/hactool and /usr/local/bin/hactoolnet if you're a linux user.

1. To obtain the latest set of keys for the purpose of decrypting the nintendo switch firmware files, you're going to want the key known as "tsec_root_key_02". How you obtain this these days is up to you to figure out on your own.

2. You're going to want to save that key in a text file named keys.txt with just a single line saved in it with the f's replaced with the actual key such as this, "tsec_root_key_02 = fffffffffffffffffffffffffffffff", and then you're going to open a terminal and run "hactoolnet -k keys.txt -t keygen >> prod.keys" (if you do have the "mariko_kek" and "mariko_bek" you can consider using [mariko keygen](../scripts/mariko_keygen.py), with usage instructions in the README.md to do this process for you.)

3. Copy the outputting prod.keys to ~/.switch/prod.keys (this translates to /home/youruser/.switch/prod.keys and C:/users/youruser/.switch/prod.keys).

4. Dump your own system version files or get them from https://darthsternie.net/switch-firmwares/ this specific example will will use the version for 14.1.1

5. For the specific of this guide, we're going to use the titleid for NIFM, which is 010000000000000F, refer to https://switchbrew.org/wiki/Title_list for how to handle other modules the same fashion.

6. place firmware files in a folder named "firmware", then run "hactoolnet -t switchfs firmware --title 010000000000000f --exefsdir exefs"

7. run the command "hactool -t nso0 exefs/main --uncompressed=uncompressed_nifm.nso0", and take note of the Build Id

8. Open ghidra, make a new project where you want.
   - Click File -> import file -> Select uncompressed_nifm.nso0 that you just extracted (make certain it says the format is Nintendo Switch Binary)
   - Click the dragon to open the ghidra CodeBrowser.
   - Click File -> open uncompressed_nifm.nso0 (that you added to the project)
   - Click yes to analyze, and tick the switch-ipc option, then click analyze. Then let the process run until completed. If there are any errors, just hit "Ok"
   
![alt text](https://github.com/borntohonk/Switch-Ghidra-Guides/blob/master/img/ghidra-nso.png?raw=true)

9. For this specific example the intent is to make a function that otherwise usually looks for X-Organization: Nintendo to be true, if it does not find it to be true your wifi/lan adapter is disabled. We're going to make it do the opposite.
   - To find this offset of the function, press S to open memory search mode, and search for this HEX string ".. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. f0 03 00 aa .. .. .. .. f3 03 14 aa e0 03 14 aa 9f 02 01 39 7f 8e 04 f8", the the start offset of the result is the offset to grab for the patch.

![alt text](https://github.com/borntohonk/Switch-Ghidra-Guides/blob/master/img/ghidra-nifm-offset.png?raw=true)

10. The patch we want to make is to change out the instruction at that offset, with 'MOV X0, #0xD180 + MOVK X0, #0x8F0, LSL #16 + SVC #0XB + MOV X0, XZR + RET' (00 30 9A D2 00 1E A1 F2 61 01 00 D4 E0 03 1F AA C0 03 5F D6) - This will make the function at offset 04 42 0C to end instead of doing the function it previously did, essentially cutting it short. *updated string to include patch with a sleep added as apparently the previous pattern would cause issues to some users. (These are ARM instructions)




**note 1:** the offsets ghidra-loader gives you are -0x100, so the resulting offset we use in the next part is +0x100 (04 43 0C, up from 04 42 0C)
**note 2:** the example values below are for 14.1.1, and may be inconsistent with the example images from above.

11. "50 41 54 43 48" is "PATCH", "04 43 0C" is the offset we're patching, "00 14" is the length of patch we're applying, "00 30 9A D2 00 1E A1 F2 61 01 00 D4 E0 03 1F AA C0 03 5F D6" Is the patch we are applying at that offset ('MOV X0, #0xD180 + MOVK X0, #0x8F0, LSL #16 + SVC #0XB + MOV X0, XZR + RET'), and 45 4F 46 is EOF. This effectively patches out the "connectivity test" and lets you use network functionality on closed networks where otherwise X-Organization: Nintendo would never be returned to the console. (You can look at the table below to get a more visual concept of how this patch is structured)

| PATCH magic | Offset | Size of patch | Patch to be applied | EOF magic |
| :---: | :---: | :---: | :---: | :---: |
| 50 41 54 43 48 | 04 43 0C | 00 14 | 00 30 9A D2 00 1E A1 F2 61 01 00 D4 E0 03 1F AA C0 03 5F D6 | 45 4F 46 |