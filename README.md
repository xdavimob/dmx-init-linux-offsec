# dmx-init-linux-offsec

Complete installation and configuration script for Linux environments focused on Offensive Security, developed by [@xdavimob](https://github.com/xdavimob).

Ideal for preparing WSL, Kali Linux, or Ubuntu environments focused on pentesting, CTFs, mobile analysis, post-exploitation, and Red Teaming.

---

## Quick Installation

```bash
wget https://raw.githubusercontent.com/xdavimob/dmx-init-linux-offsec/main/setup.sh
chmod +x https://raw.githubusercontent.com/xdavimob/dmx-init-linux-offsec/main/setup.sh
./setup.sh
````

---

## What does this script install?

### System Base

* System Updates
* Time Correction with `ntpdate`
* ZSH + Oh My Zsh Installation
* ZSH Plugins: Syntax Highlighting, Autosuggestions, History Search
* `.zshrc` Optimized with Aliases, Functions, and Go/Rust Integration

### Created Directories

* `~/Tools` → Manual/Cloned Tools
* `~/Mobile` → Mobile Tools and Files (e.g., APKs)
* `~/CTF` → Lab and Challenge Organization
* `~/go/bin` + `~/.cargo/bin` → For Tools Installed via Go and Rust

---

## Installed Tools

### Via APT (apt install)

Includes dozens of useful tools such as:

* `nmap`, `netcat`, `socat`, `wireshark`, `tshark`, `tcpdump`
* `ripgrep`, `fzf`, `bat`, `eza`, `htop`, `jq`, `tree`, `vim`, `tmux`
* `python3`, `pipx`, `openjdk`, `ruby`, `golang`, `adb`, `scrcpy`
* `apktool`, `radare2`, `masscan`, `ffuf`, `hydra`, `ldap-utils`

### Via Rust (position)

* `cargo`, `rustup`

### Via pipx

* `frida-tools`, `objection`, `mitmproxy`, `git-dumper`

### Via Git clone

* `sqlmap`, `jwt_tool`, `GitTools`, `enum4linux-ng`, `XSStrike`
* `john-jumbo` (compiled via `make`)
* `Responder`, `cupp`, `pwncat-cs`, `mimikatz`

### Via Go (go install)

* `httpx`, `nuclei`, `subfinder`

### Mobile Tools

* `uber-apk-signer`
* Functions for `adb`, `pull APK`, starting `frida-server`, etc.

### Wordlists

* Cloning `SecLists` in `/usr/share/wordlists`

---

## Useful settings in .zshrc

### Aliases

```bash
alias sqlmap='python3 ~/Tools/sqlmap/sqlmap.py'
alias jwt_tool='python3 ~/Tools/jwt_tool/jwt_tool.py'
alias john="~/Tools/john-jumbo/run/john"
```

### Functions

* `jwt-decode` → decodes JWT payloads
* `signer <apk>` → signs APKs with UberApkSigner
* `apkpull <package>` → extracts APK via `adb`
* `server` / `stopserver` → starts and stops `frida-server` on Android

---

## Additional Tools (manual/compiled)

Includes automated setup for:

* **Chisel (Linux + Windows)**
* **Ligolo-ng (proxy + agent)**
* **BloodHound Community Edition**
* **WinPEAS / LinPEAS**
* **RunasCs**
* **Ghidra**
* **Hashcat**
* **Enum4linux-ng** with venv configured

---

## Notes

* Successfully tested on **WSL2 Ubuntu**, but also compatible with Debian-based Linux distributions. * The script successfully runs `chsh -s $(which zsh)` in WSL to change the default shell.
* `setup-impacket-like-kali.sh` is automatically downloaded and executed.
* It can be run as many times as you like — the script removes and reinstalls existing configurations.

---

## Contribute

Pull requests and improvements are welcome!
Submit suggestions, new aliases, or tools that could improve the Pentest environment.