cd $HOME/ && \
wget https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.9%2B10/OpenJDK21U-jdk_x64_linux_hotspot_21.0.9_10.tar.gz && \
mkdir -p ojdk21 && \
tar xvzf OpenJDK21U-jdk_x64_linux_hotspot_21.0.9_10.tar.gz -C ojdk21 && \
rm OpenJDK21U-jdk_x64_linux_hotspot_21.0.9_10.tar.gz && \
export JAVA_HOME=$HOME/ojdk21/jdk-21.0.9+10 && \
export PATH="$HOME/ojdk21/jdk-21.0.9+10/bin:$PATH" && \
echo "export JAVA_HOME=$HOME/ojdk21/jdk-21.0.9+10" | tee -a $HOME/.bashrc && \
echo "export PATH=$HOME/ojdk21/jdk-21.0.9+10/bin:$PATH" | tee -a $HOME/.bashrc && \
source $HOME/.bashrc && \
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.2_build/ghidra_12.1.2_PUBLIC_20260605.zip -O ghidra.zip && \
unzip ghidra.zip -d ghidra && \
rm ghidra.zip && \
GHIDRA_VERSION="ghidra_12.1.2_PUBLIC"

GHIDRA_DIR=$(ls -1d $HOME/ghidra/ghidra_* | head -n1)
export GHIDRA_INSTALL_DIR="$GHIDRA_DIR"
GHIDRA_RUN="$GHIDRA_DIR/ghidraRun"

chmod +x "$GHIDRA_RUN" && \
git clone https://github.com/borntohonk/Ghidra-Switch-Loader.git && \
cd Ghidra-Switch-Loader && \
chmod +x gradlew && \
./gradlew && \
cd dist && \
unzip *.zip -d "$HOME/ghidra/$GHIDRA_VERSION/Ghidra/Extensions" && \
cd ../.. && \
rm -rf Ghidra-Switch-Loader && \

cat >> ~/.bashrc << EOF
export JAVA_HOME=\$HOME/ojdk21/jdk-21.0.9+10
export PATH="\$JAVA_HOME/bin:\$PATH"
export GHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR"
ghidra() {
    "\$GHIDRA_INSTALL_DIR/ghidraRun"
}
EOF

source ~/.bashrc && \
echo "start ghidra by relogging, restarting your shell or typing 'source ~/.bashrc' and 'ghidra' into the terminal"