Part 2 of this guide assumes you have succesfully set up ghidra as described in Part1A (for windows users) or Part1B (for linux users).

Part 2 Will only describe how to operate ghidra, with the intent to inspect already decrypted and decompressed binaries. The end user should already be familiar with "Nintendo Switch" file containers, how to decrypt them and how to extract the necessary files from them.

1. Open ghidra, make a new project where you want.
   - Click File -> import file -> Select the "uncompressed_main" file, which you should have provided yourself, from the exefs partition of the nca belonging to NIFM, and then subsequently decompressed. (make certain it says the format is Nintendo Switch Binary)
   - Click the dragon to open the ghidra CodeBrowser.
   - Click File -> open "uncompressed_main" (that you added to the project)
   - Click yes to analyze, and tick the switch-ipc option, then click analyze. Then let the process run until completed. If there are any errors, just hit "Ok"
   
![alt text](https://github.com/borntohonk/Switch-Ghidra-Guides/blob/master/img/ghidra-nso.png?raw=true)

2. 
Method 1: For this specific example the intent is to make a function that otherwise usually looks for X-Organization: Nintendo to be true, if it does not find it to be true your wifi/lan adapter is disabled. We're going to make it do the opposite.
   - To find this offset of the function, press S to open memory search mode, and search for this HEX string:
   - ".. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. 03 .. AA E0 03 .. AA .. .. .. 39 .. .. 04 F8 .. .. .. .. E0", if between firmware versions 1.0.0 and 19.0.1
   - ".. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. 03 .. AA .. .. .. AA .. .. .. .. .. .. .. .. .. 03 14 AA .. .. 14 AA" if firmware version greater than 20.0.0
   - the the start offset of the result is the offset to grab for the patch.

![alt text](https://github.com/borntohonk/Switch-Ghidra-Guides/blob/master/img/ghidra-nifm-offset.png?raw=true)

Method 2:
you can also from the top menu go to:
   - window -> Defined Strings
   - and search for "Nintendo"
   - then double-click the result highlighted in this picture: (top is 1.0.0 and bottom is 21.0.0).
   - (you are looking cor either conntest or ctest, and clicking it will take you to the next offset.)
![alt text](https://github.com/borntohonk/Switch-Ghidra-Guides/blob/master/img/ctest-1.png?raw=true)

followed by:
 - double-clicking the places where the arrows have been pointed:
 - (this should be the BL (Branch Loader) instruction right after the ctest/conntest reference you should see)
![alt text](https://github.com/borntohonk/Switch-Ghidra-Guides/blob/master/img/ctest-2.png?raw=true)

 This will take you to the same function that the long hex strings would take you.


3. The patch we want to make is to change out the instruction at that offset, with 'MOV X0, #0xD180 + MOVK X0, #0x8F0, LSL #16 + SVC #0XB + MOV X0, XZR + RET' (00 30 9A D2 00 1E A1 F2 61 01 00 D4 E0 03 1F AA C0 03 5F D6) - This will make the function at offset 04 42 0C to end instead of doing the function it previously did, essentially cutting it short. *updated string to include patch with a sleep added as apparently the previous pattern would cause issues to some users. (These are ARM instructions)


**note 1:** the offsets ghidra-loader gives you are -0x100, so the resulting offset we use in the next part is +0x100 (04 43 0C, up from 04 42 0C)
**note 2:** the example values below are for 14.1.1, and may be inconsistent with the example images from above.
**note 3:** this kind of patch generation (".ips") is deprecated for system applications that are marked as "execute-only" as of 19.0.0 (potentially including the one provided example for; "NIFM")

4. "50 41 54 43 48" is "PATCH", "04 43 0C" is the offset we're patching, "00 14" is the length of patch we're applying, "00 30 9A D2 00 1E A1 F2 61 01 00 D4 E0 03 1F AA C0 03 5F D6" Is the patch we are applying at that offset ('MOV X0, #0xD180 + MOVK X0, #0x8F0, LSL #16 + SVC #0XB + MOV X0, XZR + RET'), and 45 4F 46 is EOF. This effectively patches out the "connectivity test" and lets you use network functionality on closed networks where otherwise X-Organization: Nintendo would never be returned to the console. (You can look at the table below to get a more visual concept of how this patch is structured)

| PATCH magic | Offset | Size of patch | Patch to be applied | EOF magic |
| :---: | :---: | :---: | :---: | :---: |
| 50 41 54 43 48 | 04 43 0C | 00 14 | 00 30 9A D2 00 1E A1 F2 61 01 00 D4 E0 03 1F AA C0 03 5F D6 | 45 4F 46 |