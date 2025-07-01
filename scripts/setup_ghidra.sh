cd $HOME/ && \
wget https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.9%2B10/OpenJDK21U-jdk_x64_linux_hotspot_21.0.9_10.tar.gz && \
mkdir ojdk21 && \
tar xvzf OpenJDK21U-jdk_x64_linux_hotspot_21.0.9_10.tar.gz -C ojdk21 && \
rm OpenJDK21U-jdk_x64_linux_hotspot_21.0.9_10.tar.gz && \
export JAVA_HOME=$HOME/ojdk21/jdk-21.0.9+10 && \
export PATH="$HOME/ojdk21/jdk-21.0.9+10/bin:$PATH" && \
echo "export JAVA_HOME=$HOME/ojdk21/jdk-21.0.9+10" | sudo tee -a $HOME/.bashrc && \
echo "export PATH=$HOME/ojdk21/jdk-21.0.9+10/bin:$PATH" | sudo tee -a $HOME/.bashrc && \
source $HOME/.bashrc && \
wget $(curl -s https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_11.4.2_build | grep "browser_download_url" | cut -d '"' -f 4) -O ghidra.zip && \
unzip ghidra.zip -d ghidra && \
rm ghidra.zip && \
GHIDRA=$(ls $HOME/ghidra) && \
echo "alias ghidra=$HOME/ghidra/$GHIDRA/ghidraRun" | sudo tee -a $HOME/.bashrc && \
export GHIDRA_INSTALL_DIR=$HOME/ghidra/$GHIDRA && \
echo "export GHIDRA_INSTALL_DIR=$HOME/ghidra/$GHIDRA" | sudo tee -a $HOME/.bashrc && \
source $HOME/.bashrc && \
git clone https://github.com/Adubbz/Ghidra-Switch-Loader.git && \
cd Ghidra-Switch-Loader && \
chmod +x gradlew && \
./gradlew && \
cd dist && \
unzip *.zip -d "$HOME/ghidra/$GHIDRA/Ghidra/Extensions" && \
cd ../.. && \
rm -rf Ghidra-Switch-Loader && \
source $HOME/.bashrc && \
ghidra