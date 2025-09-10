#!/bin/bash

# ==========================
# Script de Setup Linux Davi Trindade
# ==========================

set -e  # Parar em erros
set -u  # Erro em variáveis indefinidas

echo "[*] Atualizando sistema..."
sudo apt update && sudo apt upgrade -y

echo "[*] Corrigindo horário do sistema..."
sudo apt install -y ntpdate
sudo ntpdate ntp.ubuntu.com

echo "[*] Configurando ZSH + Oh My Zsh..."
sudo apt install -y zsh
# Remove qualquer instalação anterior
if [ -d "$HOME/.oh-my-zsh" ]; then
    echo "[!] Oh My Zsh já está instalado. Removendo para reinstalar do zero."
    rm -rf ~/.oh-my-zsh ~/.zshrc
fi

chsh -s $(which zsh)

# Instala Oh My Zsh de forma silenciosa
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended

echo "[*] Instalando pacotes essenciais..."
sudo apt install -y \
    curl wget git vim tmux unzip net-tools nmap netcat-traditional socat dnsutils whois iputils-ping \
    python3 python3-pip python3-venv openjdk-21-jdk openjdk-21-jre jq ruby ruby-dev build-essential \
    gcc make cmake sqlite3 zip p7zip-full tree gnupg fzf lsb-release htop bat silversearcher-ag \
    ripgrep neofetch xclip gobuster ffuf masscan dirb nikto hydra radare2 apktool scrcpy adb \
    tshark wireshark tcpdump smbclient nbtscan ldap-utils rlwrap golang-go pipx libssl-dev \
    zlib1g-dev yasm libgmp-dev libpcap-dev pkg-config libbz2-dev libnss3-dev eza fonts-firacode

echo "[*] Instalando Rust (cargo, rustup)..."
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env
# Garante que PATH esteja presente no .zshrc
if ! grep -q 'source \$HOME/.cargo/env' ~/.zshrc; then
    echo 'source $HOME/.cargo/env' >> ~/.zshrc
fi
rustup update

echo "[*] Criando diretórios..."
mkdir -p ~/Tools ~/Mobile ~/CTF ~/go/{bin,src,pkg}
sudo mkdir -p /usr/share/wordlists

echo "[*] Clonando plugins do ZSH..."
git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting
git clone https://github.com/zsh-users/zsh-history-substring-search ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-history-substring-search

echo "[*] Instalando pacotes via go..."
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "[*] Instalando via pipx..."
pipx ensurepath
pipx install "frida-tools<14"
pipx install mitmproxy
pipx runpip objection install --force-reinstall "frida==16.7.19"
pipx install git-dumper

echo "[*] Clonando ferramentas..."
git clone https://github.com/openwall/john -b bleeding-jumbo ~/Tools/john-jumbo
git clone https://github.com/sqlmapproject/sqlmap ~/Tools/sqlmap
sudo git clone https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/SecLists
git clone https://github.com/ticarpi/jwt_tool.git ~/Tools/jwt_tool
git clone https://github.com/internetwache/GitTools.git ~/Tools/GitTools
git clone https://github.com/cddmp/enum4linux-ng ~/Tools/enum4linux-ng

echo "[*] Compilando John the Ripper..."
cd ~/Tools/john-jumbo/src
./configure && make -s -j$(nproc)

echo "[*] Instalando Uber APK Signer..."
wget -O ~/Mobile/uber-apk-signer-1.3.0.jar https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar

echo "[*] Setup Impacket Like a Kali..."
curl -O https://raw.githubusercontent.com/xdavimob/impacket-like-a-kali/main/setup-impacket-like-kali.sh
chmod +x setup-impacket-like-kali.sh
./setup-impacket-like-kali.sh

echo "[*] Criando venv para enum4linux-ng..."
cd ~/Tools/enum4linux-ng
python3 -m venv venv
source venv/bin/activate
pip install -U pip
pip install -r requirements.txt
deactivate

echo "[*] Adicionando configurações ao .zshrc..."
cat <<'EOF' >> ~/.zshrc

# Plugins personalizados
plugins=(git zsh-autosuggestions zsh-syntax-highlighting zsh-history-substring-search)

source "$HOME/.oh-my-zsh/custom/plugins/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh"
source "$HOME/.oh-my-zsh/custom/plugins/zsh-history-substring-search/zsh-history-substring-search.zsh"
source "$HOME/.oh-my-zsh/custom/plugins/zsh-autosuggestions/zsh-autosuggestions.zsh"

# Go e Cargo
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin:$HOME/.cargo/bin
source "$HOME/.cargo/env"

# Aliases úteis
alias enum4linux-ng='~/Tools/enum4linux-ng/venv/bin/python ~/Tools/enum4linux-ng/enum4linux-ng.py'
alias sqlmap='python3 ~/Tools/sqlmap/sqlmap.py'
alias john="~/Tools/john-jumbo/run/john"
alias jwt_tool='python3 ~/Tools/jwt_tool/jwt_tool.py'
alias myip="curl ifconfig.me;echo"
alias lip="ip a | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{ print $2 }' | grep -v 127.0.0.1"

# Funções
function jwt-decode() {
  sed 's/\./\n/g' <<< $(cut -d. -f1,2 <<< $1) | base64 --decode | jq
}
function signer() {
    if [ -z "$1" ]; then
        echo "Uso: signer <apk>"
        return 1
    fi
    java -jar ~/Mobile/uber-apk-signer-1.3.0.jar --apks "$1" --overwrite
}
function apkpull() {
    [[ -z "$1" ]] && { echo "Usage: apkpull <package>"; return 1; }
    adb shell pm path $1 | cut -d: -f2 | tr -d '\r' | xargs -I {} adb pull {}
}
function server() {
    adb shell "su -c '/data/local/tmp/frida-server &'"
    echo "Frida iniciado"
}
function stopserver() {
    local pid=$(frida-ps -U | grep 'frida-server' | awk '{print $1}')
    [ -n "$pid" ] && adb shell "su -c 'kill -9 $pid'"
}


EOF

echo "[*] Baixando ferramentas adicionais para ~/Tools..."

cd ~/Tools

# ----------- CHISEL (Linux + Windows) -----------
wget -q https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz -O chisel.gz
wget -q https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_windows_amd64.gz -O chisel.exe.gz
gunzip -f chisel.gz && chmod +x chisel
gunzip -f chisel.exe.gz

# ----------- CUPP -----------
git clone https://github.com/Mebus/cupp.git

# ----------- GHIDRA (zip manual) -----------
GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.2_build/ghidra_11.0.2_PUBLIC_20240711.zip"
wget -q "$GHIDRA_URL" -O ghidra.zip && unzip -q ghidra.zip -d ghidra && rm ghidra.zip

# ----------- HASHCAT -----------
wget -q https://hashcat.net/files/hashcat-7.1.2.7z -O hashcat.7z
7z x hashcat.7z -ohashcat_beta && rm hashcat.7z

# ----------- MIMIKATZ -----------
git clone https://github.com/gentilkiwi/mimikatz.git

# ----------- PWNcat-CS -----------
git clone https://github.com/cytopia/pwncat.git pwncat-cs

# ----------- RESPONDER -----------
git clone https://github.com/lgandx/Responder.git

# ----------- XSStrike -----------
git clone https://github.com/s0md3v/XSStrike.git

# ----------- LINPEAS -----------
wget -q https://github.com/peass-ng/PEASS-ng/releases/download/20250904-27f4363e/linpeas_linux_amd64 -O linpeas
chmod +x linpeas

# ----------- WINPEAS -----------
wget -q https://github.com/peass-ng/PEASS-ng/releases/download/20250904-27f4363e/winPEASx64.exe

# ----------- RunasCs -----------
wget -q https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip
unzip -q RunasCs.zip -d RunasCs && mv RunasCs/* . && rm -rf RunasCs.zip RunasCs

# ----------- LIGOLO-NG (Linux + Windows) -----------
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_windows_amd64.zip
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_proxy_0.8.2_windows_amd64.zip

mkdir -p ligolo-ng && cd ligolo-ng
tar -xzf ../ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
tar -xzf ../ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
unzip -q ../ligolo-ng_agent_0.8.2_windows_amd64.zip
unzip -q ../ligolo-ng_proxy_0.8.2_windows_amd64.zip
rm ../ligolo-ng_*.zip ../ligolo-ng_*.tar.gz
cd ..

# ----------- BLOODHOUND LAB (Community Edition) -----------
wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz
tar -xvzf bloodhound-cli-linux-amd64.tar.gz
cd bloodhound-lab && ./bloodhound-cli install
cd ..

echo "[+] Ferramentas adicionais instaladas em ~/Tools!"

echo "[*] Setup finalizado. Reinicie o terminal ou execute 'source ~/.zshrc' para aplicar as mudanças."
