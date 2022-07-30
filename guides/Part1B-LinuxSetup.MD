Part 1B: Setting up Ghidra

This guide is done on Ubuntu, and assumes you have git, wget and curl. They can be gotten by doing "sudo apt-get install -y wget curl git"

0. (optional) put this into your terminal "curl -sSL https://github.com/borntohonk/SigPatches/raw/master/scripts/setup_ghidra.sh | sh"
1. or put this into your terminal: 

```
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
```

2. You now should have a functional ghidra setup with the nintendo switch binary extension installed. Call for it by typing "ghidra" into your terminal.
