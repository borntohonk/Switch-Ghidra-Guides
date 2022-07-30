#!/bin/bash
cd $HOME/ && \
wget https://github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.15%2B10/OpenJDK11U-jdk_x64_linux_hotspot_11.0.15_10.tar.gz && \
mkdir ojdk11 && \
tar xvzf OpenJDK11U-jdk_x64_linux_hotspot_11.0.15_10.tar.gz -C ojdk11 && \
rm OpenJDK11U-jdk_x64_linux_hotspot_11.0.15_10.tar.gz && \
export JAVA_HOME=$HOME/ojdk11/jdk-11.0.15+10 && \
export PATH="$HOME/ojdk11/jdk-11.0.15+10/bin:$PATH" && \
echo "export PATH="$HOME/ojdk11/jdk-11.0.12+7/bin:$PATH"" >> $HOME/.profile && \
wget $(curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest | grep "browser_download_url" | cut -d '"' -f 4) -O ghidra.zip && \
unzip ghidra.zip -d ghidra && \
rm ghidra.zip && \
GHIDRA=$(ls $HOME/ghidra) && \
echo "alias ghidra=$HOME/ghidra/$GHIDRA/ghidraRun" >> $HOME/.bash_aliases && \
export GHIDRA_INSTALL_DIR=$HOME/ghidra/$GHIDRA && \
git clone https://github.com/Adubbz/Ghidra-Switch-Loader && \
cd Ghidra-Switch-Loader && \
chmod +x gradlew && \
./gradlew && \
cd dist && \
unzip *.zip -d "$HOME/ghidra/$GHIDRA/Ghidra/Extensions" && \
cd ../.. && \
rm -rf Ghidra-Switch-Loader && \
source $HOME/.profile && \
source $HOME/.bash_aliases && \
ghidra
