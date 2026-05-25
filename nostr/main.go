package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

func main() {
	cwd, _ := os.Getwd()
	loadEnvFile(filepath.Join(cwd, ".env.punchwg"))

	room = getEnvTrim("ROOM", DefaultRoom)
	wgPort := getEnvInt("WG_PORT", DefaultWGPort)
	wgIface := getEnvTrim("WG_IFACE", "wg0")

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

	// Optional: override the default relay list via env (comma-separated URLs).
	if s := strings.TrimSpace(os.Getenv("NOSTR_RELAYS")); s != "" {
		var custom []string
		for _, r := range strings.Split(s, ",") {
			if r = strings.TrimSpace(r); r != "" {
				custom = append(custom, r)
			}
		}
		if len(custom) > 0 {
			nostrRelays = custom
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

	// Derive our VPN IPv6 address and room subnet from our WG pubkey + room.
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

	// Load or create this peer's local Nostr identity. The shared room secret is
	// only used to derive the room d tag. Peers must not share the same Nostr key,
	// otherwise their replaceable rendezvous events would overwrite each other.
	nostrKeyFile := getEnvTrim("NOSTR_KEY_FILE", filepath.Join(cwd, ".nostr-peer.key"))

	nostrPriv, nostrPub, err := loadOrCreatePeerNostrKeypair(nostrKeyFile)
	if err != nil {
		log.Fatalf("load/create Nostr keypair: %v", err)
	}
	roomTag := deriveNostrRoomTag(room)

	log.Printf("Nostr peer pubkey: %s", nostrPub)
	log.Printf("Nostr room tag: %s", roomTag)

	// Single shared UDP socket for WireGuard + STUN + hole-punch burst.
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

	ctx := context.Background()

	// startNostrBootstrap blocks forever running STUN + publish + subscribe.
	startNostrBootstrap(
		ctx,
		ns,
		wgDev,
		udpConn,
		stunServers,
		nostrPriv,
		roomTag,
		wgPub,
		room,
		wgPort,
	)
}

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
