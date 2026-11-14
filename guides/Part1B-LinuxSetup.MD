Part 1B: Setting up Ghidra

This guide is done on Ubuntu, and assumes you have git, wget and curl. They can be gotten by doing "sudo apt-get install -y wget curl git"

0. (optional) put this into your terminal "curl -sSL https://raw.githubusercontent.com/borntohonk/Switch-Ghidra-Guides/master/scripts/setup_ghidra.sh | bash"
1. or put this into your terminal: 

```
cd $HOME/ && \
wget https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.5%2B8/OpenJDK25U-jdk_x64_linux_hotspot_25.0.5_8.tar.gz && \
mkdir -p ojdk25 && \
tar xvzf OpenJDK25U-jdk_x64_linux_hotspot_25.0.5_8.tar.gz -C ojdk25 && \
rm OpenJDK25U-jdk_x64_linux_hotspot_25.0.5_8.tar.gz && \
export JAVA_HOME=$HOME/ojdk25/jdk-25.0.5+8 && \
export PATH="$HOME/ojdk25/jdk-25.0.5+8/bin:$PATH" && \
echo "export JAVA_HOME=$HOME/ojdk25/jdk-25.0.5+8" | tee -a $HOME/.bashrc && \
echo "export PATH=$HOME/ojdk25/jdk-25.0.5+8/bin:$PATH" | tee -a $HOME/.bashrc && \
source $HOME/.bashrc && \
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip -O ghidra.zip && \
unzip ghidra.zip -d ghidra && \
rm ghidra.zip && \
GHIDRA_VERSION="ghidra_12.2_PUBLIC"

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
export JAVA_HOME=\$HOME/ojdk25/jdk-25.0.5+8
export PATH="\$JAVA_HOME/bin:\$PATH"
export GHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR"
ghidra() {
    "\$GHIDRA_INSTALL_DIR/ghidraRun"
}
EOF

source ~/.bashrc && \
echo "start ghidra by relogging, restarting your shell or typing 'source ~/.bashrc' and 'ghidra' into the terminal"
```

2. You now should have a functional ghidra setup with the nintendo switch binary extension installed. Call for it by typing "ghidra" into your terminal.
