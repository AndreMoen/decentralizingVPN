package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/sha3"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

func execTimeout(d time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("timeout running %s", name)
	}
	return string(out), err
}

// deriveGroupOnionKey derives a deterministic ed25519 keypair and v3 .onion
// address from the room secret. All peers with the same secret arrive at the
// same address independently.
//
//	seed     = SHA-256(secret)
//	privKey  = ed25519.NewKeyFromSeed(seed)
//	checksum = SHA3-256(".onion checksum" || pubKey || 0x03)[:2]
//	address  = base32lower(pubKey || checksum || 0x03) + ".onion"
func deriveGroupOnionKey(secret string) (ed25519.PrivateKey, string) {
	seed := sha256.Sum256([]byte(secret))
	privKey := ed25519.NewKeyFromSeed(seed[:])
	pubKey := []byte(privKey.Public().(ed25519.PublicKey))

	version := byte(0x03)
	h := sha3.New256()
	h.Write([]byte(".onion checksum"))
	h.Write(pubKey)
	h.Write([]byte{version})
	checksum := h.Sum(nil)[:2]

	raw := append(append(append([]byte{}, pubKey...), checksum...), version)
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	return privKey, strings.ToLower(encoded) + ".onion"
}

const version = "v10"

func main() {
	log.Printf("torPunch %s starting", version)
	cwd, _ := os.Getwd()
	loadEnvFile(filepath.Join(cwd, ".env.punchwg"))

	room = getEnvTrim("ROOM", DefaultRoom)
	wgPort := getEnvInt("WG_PORT", DefaultWGPort)
	wgIface := getEnvTrim("WG_IFACE", "wg0")
	torSocks := getEnvTrim("TOR_SOCKS", "127.0.0.1:9050")

	stunServers := defaultSTUNServers
	if s := strings.TrimSpace(os.Getenv("STUN_SERVERS")); s != "" {
		var custom []string
		for _, srv := range strings.Split(s, ",") {
			if srv = strings.TrimSpace(srv); srv != "" {
				custom = append(custom, srv)
			}
		}
		if len(custom) > 0 {
			stunServers = custom
		}
	}

	wgPub := strings.TrimSpace(os.Getenv("WG_PUBKEY"))
	wgPriv := strings.TrimSpace(os.Getenv("WG_PRIVKEY"))

	if wgPriv == "" || wgPub == "" {
		priv, _, err := readWGConf(wgIface)
		if err == nil {
			if wgPriv == "" {
				wgPriv = strings.TrimSpace(priv)
			}
			if wgPub == "" && wgPriv != "" {
				if pub, err2 := pubFromPriv(wgPriv); err2 == nil {
					wgPub = pub
				}
			}
		}
	}

	if wgPriv == "" || wgPub == "" {
		log.Fatalf("missing WG_PRIVKEY or WG_PUBKEY (checked env and /etc/wireguard/%s.conf)", wgIface)
	}
	if !validWgPubkey(wgPub) {
		log.Fatalf("WG_PUBKEY looks invalid")
	}

	// Derive our VPN IPv6 address from our public key — no WG_IP needed.
	myVPNAddr, err := deriveVPNAddr(room, wgPub)
	if err != nil {
		log.Fatalf("derive VPN addr: %v", err)
	}
	myVPNCIDR := vpnAddrCIDR(myVPNAddr)
	roomPrefix := deriveVPNPrefix(room)
	log.Printf("VPN address: %s  room prefix: %s", myVPNAddr, roomPrefix)

	privHex, err := wgPrivB64ToHex(wgPriv)
	if err != nil {
		log.Fatalf("private key conversion: %v", err)
	}

	onionPrivKey, onionAddress := deriveGroupOnionKey(room)
	groupOnionURL := "http://" + onionAddress
	serviceTor := newStaticOnionProcess(onionAddress)
	log.Printf("Group onion address: %s", onionAddress)
	log.Printf("Static onion service: control=%s target=%s data=%s", serviceTor.controlAddr, serviceTor.targetAddr, serviceTor.dataDir)

	// Single shared UDP socket for WireGuard + STUN + punch burst.
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: wgPort})
	if err != nil {
		log.Fatalf("bind udp: %v", err)
	}
	log.Printf("UDP bound on 0.0.0.0:%d", wgPort)

	wgBind := newSharedWGBind(udpConn)

	tunDev, err := tun.CreateTUN(wgIface, 1420)
	if err != nil {
		log.Fatalf("tun create: %v", err)
	}

	wgLogger := device.NewLogger(device.LogLevelError, "")
	wgDev := device.NewDevice(tunDev, wgBind, wgLogger)

	if err := wgDev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", privHex, wgPort)); err != nil {
		log.Fatalf("wireguard ipc set: %v", err)
	}
	wgDev.Up()
	log.Printf("WireGuard up: iface=%s port=%d", wgIface, wgPort)

	startUAPI(wgDev, wgIface)
	startWGHandshakeWatcher(wgDev)
	ensureLinkUp(wgIface)
	ensureAddress(wgIface, myVPNCIDR)

	// Route the entire room /48 prefix through the WireGuard interface.
	routeCmd := exec.Command("ip", "-6", "route", "replace", roomPrefix.String(), "dev", wgIface)
	routeCmd.Stdout = os.Stdout
	routeCmd.Stderr = os.Stderr
	if err := routeCmd.Run(); err != nil {
		log.Fatalf("ip -6 route: %v", err)
	}
	log.Printf("Route: %s via %s", roomPrefix, wgIface)

	ns := newNetState()

	// Start the UDP read loop: routes packets to WireGuard or STUN demux.
	go udpReadLoop(udpConn, wgBind, wgDev)

	// Race to become the onion registry server; others become clients.
	reg := newPeerRegistry(10 * time.Minute)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go tryStartGroupOnionServer(ctx, torSocks, groupOnionURL, onionAddress, onionPrivKey, reg, serviceTor)

	// Bootstrap: STUN + register + punch + failover (blocks forever).
	startTorBootstrap(ctx, ns, wgDev, udpConn, groupOnionURL, torSocks, onionAddress,
		stunServers, onionPrivKey, reg, serviceTor, wgPub, room, wgPort)
}
