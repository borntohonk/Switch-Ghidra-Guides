#!/bin/bash
cd $HOME/ && \
wget https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.2%2B13/OpenJDK21U-jdk_x64_linux_hotspot_21.0.2_13.tar.gz && \
mkdir ojdk21 && \
tar xvzf OpenJDK21U-jdk_x64_linux_hotspot_21.0.2_13.tar.gz -C ojdk21 && \
rm OpenJDK21U-jdk_x64_linux_hotspot_21.0.2_13.tar.gz && \
export JAVA_HOME=$HOME/ojdk21/jdk-21.0.2+13 && \
export PATH="$HOME/ojdk21/jdk-21.0.2+13 /bin:$PATH" && \
echo "export PATH="$HOME/ojdk21/jdk-21.0.2+13 /bin:$PATH"" >> $HOME/.profile && \
wget $(curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest | grep "browser_download_url" | cut -d '"' -f 4) -O ghidra.zip && \
unzip ghidra.zip -d ghidra && \
rm ghidra.zip && \
GHIDRA=$(ls $HOME/ghidra) && \
echo "alias ghidra=$HOME/ghidra/$GHIDRA/ghidraRun" >> $HOME/.bash_aliases && \
export GHIDRA_INSTALL_DIR=$HOME/ghidra/$GHIDRA && \
git clone https://github.com/StevensND/Ghidra-Switch-Loader && \
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
