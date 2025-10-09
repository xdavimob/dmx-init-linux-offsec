#!/bin/bash

# ==========================
# Script de Setup Linux Davi Trindade
# ==========================

set -e  # Parar em erros
set -u  # Erro em variáveis indefinidas

# git_sync <repo_url> <dest> [branch] [sudo]
git_sync() {
  local url="${1:?url}"; local dest="${2:?dest}"
  local br="${3:-}"; local sud=""; [ "${4:-}" = "sudo" ] && sud="sudo "
  local parent; parent="$(dirname "$dest")"
  [ -n "$sud" ] && ${sud}mkdir -p "$parent" || mkdir -p "$parent"

  if [ -d "$dest/.git" ]; then
    ${sud}git -C "$dest" fetch --all --tags
    [ -n "$br" ] && ${sud}git -C "$dest" checkout "$br"
    ${sud}git -C "$dest" pull --ff-only || true
    echo "[=] Atualizado: $dest"; return 0
  fi

  if [ -e "$dest" ] && [ ! -d "$dest/.git" ]; then
    if [ "${FORCE:-0}" = "1" ]; then
      local bak="${dest}.bak.$(date +%Y%m%d%H%M%S)"
      echo "[!] $dest existe e não é git. Movendo para $bak (FORCE=1)."
      [ -n "$sud" ] && ${sud}mv "$dest" "$bak" || mv "$dest" "$bak"
    else
      echo "[!] $dest existe e não é git. Pulando (use FORCE=1 p/ substituir)."
      return 0
    fi
  fi

  if [ -n "$br" ]; then
    ${sud}git clone --depth 1 -b "$br" "$url" "$dest"
  else
    ${sud}git clone --depth 1 "$url" "$dest"
  fi
  echo "[+] Clonado: $dest"
}

safelink() { # safelink <target> <link>
  sudo ln -sfn "$1" "$2"
}

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
    tshark tcpdump smbclient nbtscan ldap-utils rlwrap golang-go pipx libssl-dev \
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
if git --version >/dev/null 2>&1; then
  ZSH_CUSTOM_DIR="${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}"
  PLUG_BASE="$ZSH_CUSTOM_DIR/plugins"; mkdir -p "$PLUG_BASE"

  clone_or_update() { # <repo> <name>
    local repo="$1" dest="$PLUG_BASE/$2"
    if [ -d "$dest/.git" ]; then
      git -C "$dest" pull --ff-only || git -C "$dest" fetch --all --tags
    else
      git clone --depth 1 "$repo" "$dest"
    fi
  }

  clone_or_update "https://github.com/zsh-users/zsh-autosuggestions"          "zsh-autosuggestions"
  clone_or_update "https://github.com/zsh-users/zsh-syntax-highlighting.git"  "zsh-syntax-highlighting"
  clone_or_update "https://github.com/zsh-users/zsh-history-substring-search" "zsh-history-substring-search"
else
  echo "[!] git indisponível (ou corrompido). Pulando plugins do ZSH por enquanto."
fi

echo "[*] Instalando pacotes via go..."
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

go install github.com/tomnomnom/assetfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@master

# --- massdns ---
if command -v massdns >/dev/null 2>&1 || [ -x "/usr/local/bin/massdns" ] || [ -d "$HOME/Tools/massdns" ]; then
  echo "[*] massdns já presente, pulando."
else
  echo "[*] Instalando massdns..."
  # deps básicas (só no Debian/Ubuntu; silencioso se não houver apt)
  command -v apt-get >/dev/null 2>&1 && \
    sudo apt-get update -y && sudo apt-get install -y build-essential git libldns-dev

  git_sync https://github.com/blechschmidt/massdns.git "$HOME/Tools/massdns"
  make -C "$HOME/Tools/massdns" -j"$(nproc)"
  sudo make -C "$HOME/Tools/massdns" install
fi

# --- puredns ---
if command -v puredns >/dev/null 2>&1 || [ -x "$(go env GOBIN 2>/dev/null)/puredns" ] || [ -x "$(go env GOPATH 2>/dev/null)/bin/puredns" ]; then
  echo "[*] puredns já presente, pulando."
else
  if command -v go >/dev/null 2>&1; then
    echo "[*] Instalando puredns..."
    go install github.com/d3mondev/puredns/v2@latest
    # opcional: garantir no PATH
    BIN="$(go env GOBIN 2>/dev/null)/puredns"
    [ -x "$BIN" ] || BIN="$(go env GOPATH 2>/dev/null)/bin/puredns"
    [ -x "$BIN" ] && sudo ln -sf "$BIN" /usr/local/bin/puredns || true
  else
    echo "[!] Go não encontrado; pulei puredns."
  fi
fi

sudo gem install wpscan

echo "[*] Instalando via pipx..."
pipx ensurepath
pipx install "frida-tools<14"
pipx install mitmproxy
#pipx runpip objection install "frida==16.7.19"
pipx install git-dumper
pipx install git+https://github.com/Pennyw0rth/NetExec
pipx install pwncat-cs
pipx install certipy-ad

echo "[*] Clonando ferramentas..."
if [ ! -d "$HOME/Tools/john-jumbo/.git" ]; then
  git clone --depth 1 -b bleeding-jumbo https://github.com/openwall/john "$HOME/Tools/john-jumbo"
else
  git -C "$HOME/Tools/john-jumbo" fetch --all --tags
  git -C "$HOME/Tools/john-jumbo" checkout bleeding-jumbo
  git -C "$HOME/Tools/john-jumbo" pull --ff-only
fi
git_sync "https://github.com/sqlmapproject/sqlmap"          "$HOME/Tools/sqlmap"
git_sync "https://github.com/danielmiessler/SecLists.git"  "/usr/share/wordlists/SecLists" "sudo"
git_sync "https://github.com/ticarpi/jwt_tool.git"         "$HOME/Tools/jwt_tool"
git_sync "https://github.com/internetwache/GitTools.git"  "$HOME/Tools/GitTools"
git_sync "https://github.com/cddmp/enum4linux-ng"         "$HOME/Tools/enum4linux-ng"

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
if [ ! -d venv ]; then
  python3 -m venv venv
  source venv/bin/activate
  pip install -U pip
  pip install -r requirements.txt
  deactivate
fi

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
alias apps="adb shell pm list packages | cut -f2 -d: | sort"
alias prop="adb shell getprop ro.product.cpu.abi"
alias root="adb root"
alias unroot="adb unroot"
alias fridaps="frida-ps -U -a"
#alias server="adb shell /data/local/tmp/frida-server &"

# Funções
function proxy_on()  { adb shell settings put global http_proxy "$1";  echo "http_proxy=$1"; }
function proxy_off() { adb shell settings put global http_proxy :0;    echo "http_proxy off"; }
function jwt-decode() {
  sed 's/\./\n/g' <<< $(cut -d. -f1,2 <<< $1) | base64 --decode | jq
}
function signer() {
    if [ $# -lt 1 ]; then
        echo "Uso: signer <apk_ou_pasta> [<apk_ou_pasta> ...]"
        echo "Ex.:  signer app.apk"
        echo "      signer ./dir_com_apks base.apk split_pt.apk"
        return 1
    fi

    local JAR="$HOME/Mobile/uber-apk-signer-1.3.0.jar"
    if [ ! -f "$JAR" ]; then
        echo "[!] JAR não encontrado em: $JAR"
        echo "    Ajuste a variável JAR no script."
        return 1
    fi
    command -v java >/dev/null || { echo "[!] Java não encontrado no PATH."; return 1; }

    # Coleta e valida entradas existentes
    local inputs=()
    local had_missing=0
    for arg in "$@"; do
        if [ -e "$arg" ]; then
            inputs+=("$arg")
        else
            echo "[!] Caminho não encontrado: $arg"
            had_missing=1
        fi
    done
    if [ ${#inputs[@]} -eq 0 ]; then
        echo "[!] Nenhum arquivo/pasta válido fornecido."
        return 1
    fi
    if [ $had_missing -eq 1 ]; then
        echo "[i] Continuando apenas com entradas existentes."
    fi

    echo "[*] Assinando com uber-apk-signer..."
    # --apks aceita lista com arquivos e pastas; não-recursivo para pastas
    # --allowResign força reassinatura quando já houver assinatura
    # --overwrite sobrescreve saídas previamente geradas
    java -jar "$JAR" --allowResign --overwrite --apks "${inputs[@]}"
    local rc=$?

    if [ $rc -ne 0 ]; then
        echo "[!] Falha ao assinar. (exit=$rc)"
        return $rc
    fi

    echo "[+] Processo concluído pelo uber-apk-signer."

    # Dicas de instalação:
    #  - Saídas típicas: <nome>-aligned-debugSigned.apk (ou similar)
    #  - Para conjuntos (base + splits), use install-multiple.
    local printed_multi_hint=0
    for arg in "${inputs[@]}"; do
        if [ -f "$arg" ]; then
            # Tenta inferir o nome do APK de saída
            local base="${arg%.*}"
            # Padrões comuns de saída do uber-apk-signer:
            #   *-aligned-debugSigned.apk  ou  *-aligned-signed.apk
            local out1="${base}-aligned-debugSigned.apk"
            local out2="${base}-aligned-signed.apk"
            if [ -f "$out1" ]; then
                echo "[i] Saída: $out1"
                echo "    Para instalar: adb install -r \"$out1\""
            elif [ -f "$out2" ]; then
                echo "[i] Saída: $out2"
                echo "    Para instalar: adb install -r \"$out2\""
            else
                echo "[i] Verifique o arquivo de saída gerado na mesma pasta de: $arg"
            fi
        else
            # Pasta: sugere install-multiple com glob
            if [ $printed_multi_hint -eq 0 ]; then
                echo
                echo "[i] Para instalar conjunto (base + splits) já assinados desta(s) pasta(s):"
                printed_multi_hint=1
            fi
            echo "    adb install-multiple -r \"$arg\"/*-Signed.apk"
        fi
    done

    return 0
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

# ----------- LaZagne -----------
wget https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.7/LaZagne.exe

# ----------- CHISEL (Linux + Windows) -----------
wget -q https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz -O chisel.gz
wget -q https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_windows_amd64.gz -O chisel.exe.gz
gunzip -f chisel.gz && chmod +x chisel
gunzip -f chisel.exe.gz

# ----------- CUPP -----------
git_sync https://github.com/Mebus/cupp.git

# ----------- GHIDRA (zip manual) -----------
GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.2_build/ghidra_11.0.2_PUBLIC_20240711.zip"
wget -q "$GHIDRA_URL" -O ghidra.zip && unzip -q ghidra.zip -d ghidra && rm ghidra.zip

# ----------- HASHCAT -----------
wget -q https://hashcat.net/files/hashcat-7.1.2.7z -O hashcat.7z
7z x -y -aoa hashcat.7z -ohashcat_beta
rm -f hashcat.7z

# ----------- MIMIKATZ -----------
git_sync https://github.com/gentilkiwi/mimikatz.git

# ----------- RESPONDER -----------
git_sync https://github.com/lgandx/Responder.git
safelink "$HOME/Tools/Responder/Responder.py" /usr/local/bin/responder

# ----------- XSStrike -----------
git_sync https://github.com/s0md3v/XSStrike.git

# ----------- LINPEAS -----------
wget -q https://github.com/peass-ng/PEASS-ng/releases/download/20250904-27f4363e/linpeas_linux_amd64 -O linpeas
chmod +x linpeas

# ----------- WINPEAS -----------
wget -q https://github.com/peass-ng/PEASS-ng/releases/download/20250904-27f4363e/winPEASx64.exe

# ----------- RunasCs -----------
wget -q https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip
unzip -q RunasCs.zip -d RunasCs && mv RunasCs/* . && rm -rf RunasCs.zip RunasCs

# ----------- PowerSploit -----------
git_sync https://github.com/PowerShellMafia/PowerSploit.git

# ----------- PKINITtools -----------
git_sync https://github.com/dirkjanm/PKINITtools.git

# ----------- Certify -----------
wget https://github.com/jakobfriedl/precompiled-binaries/raw/main/LateralMovement/CertificateAbuse/Certify.exe

# ----------- PowerUp -----------
wget https://github.com/jakobfriedl/precompiled-binaries/raw/main/Scripts/PowerUp.ps1

# ----------- PowerView -----------
wget https://github.com/jakobfriedl/precompiled-binaries/raw/main/Scripts/PowerView.ps1

# ----------- Rubeus -----------
wget https://github.com/jakobfriedl/precompiled-binaries/raw/main/LateralMovement/Rubeus.exe

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
if ! command -v bloodhound-cli >/dev/null 2>&1; then
  wget -q https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz -O /tmp/bh.tar.gz
  tar -xzf /tmp/bh.tar.gz -C "$HOME/Tools"    # extrai "bloodhound-cli"
  chmod +x "$HOME/Tools/bloodhound-cli"
  "$HOME/Tools/bloodhound-cli" install
  rm -f /tmp/bh.tar.gz
else
  echo "[*] bloodhound-cli já presente, pulando."
fi

echo "[+] Ferramentas adicionais instaladas em ~/Tools!"

echo "[*] Setup finalizado. Reinicie o terminal ou execute 'source ~/.zshrc' para aplicar as mudanças."
