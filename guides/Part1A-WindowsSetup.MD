Part 1A: Setting up Ghidra

This guide is done on Windows 10, and assumes you have some sort of git shell installed, and also that you're competent enough to be able to open cmd terminals at the location you want.

1. get openjdk 11 lts from either https://adoptium.net/ or https://github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.15%2B10/OpenJDK11U-jdk_x64_windows_hotspot_11.0.15_10.msi
2. install openjdk that you just downloaded (make sure to set JAVA_HOME path while installing)
3. get ghidra https://github.com/NationalSecurityAgency/ghidra/releases/latest
4. extract it (example ghidra_10.1.4_PUBLIC_20220519.zip), and move the folder (example "ghidra_10.1.4_PUBLIC") to C:/ghidra/ghidra_10.1.4_PUBLIC
5. get the code repository, using git clone "git clone https://github.com/Adubbz/Ghidra-Switch-Loader"
6. open a terminal cmd prompt in the folder you just git cloned and put ( set "GHIDRA_INSTALL_DIR" "C:/ghidra/ghidra_10.1.4_PUBLIC" ) without the brackets into your cmd terminal, powershell or manually as an enviroment variable. (this value is only retained while the cmd window is open, don't rely on the "set" command for different sessions)
7. run gradlew in the Ghidra-Switch-Loader directory by doing putting "gradlew.bat" in your cmd/powershell terminal.
8. go to your ghidra folder (should be C:\ghidra\ghidra_10.1.4_PUBLIC in this specific example)
9. Click "File" top left then "Install extensions"
10. press the + button in upper right corner.
11. Navigate to your Ghidra-Switch-Loader folder and then into the "dist" folder it made, then select the .zip that should be in there.
12. restart ghidra

guide for winget users (applicable for windows 10 and windows 11), open terminal as administrator and then do:

# (make sure to set java home directory)
1. winget install -i temurin11 
# (only needed if you don't already have a git shell installed)
2. winget install git.git
3. curl -fsSL https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.4_build/ghidra_10.1.4_PUBLIC_20220519.zip -O
4. mkdir C:/ghidra
5. Expand-Archive -LiteralPath "ghidra_10.1.4_PUBLIC_20220519.zip" -DestinationPath "C:/ghidra"
6. rm ghidra_10.1.4_PUBLIC_20220519.zip
7. git clone https://github.com/Adubbz/Ghidra-Switch-Loader
8. cd Ghidra-Switch-Loader
# (note this requires running terminal as administrator)
9. [Environment]::SetEnvironmentVariable("GHIDRA_INSTALL_DIR", "C:/ghidra/ghidra_10.1.4_PUBLIC" ,"Machine")
10. ./gradlew
11. cd dist
12. Get-ChildItem './' -Filter *.zip | Expand-Archive -DestinationPath 'C:/ghidra/ghidra_10.1.4_PUBLIC/Ghidra/Extensions' -Force
you can now start ghidra using ghidraRun.bat in C:\ghidra\ghidra_10.1.4_PUBLIC


![alt text](https://github.com/borntohonk/SigPatches/blob/master/img/ghidra-w.png?raw=true)
