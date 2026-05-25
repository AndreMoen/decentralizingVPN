package main

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	dht "github.com/anacrolix/dht/v2"
	"github.com/anacrolix/dht/v2/krpc"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

func getPublicIPv4() string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org/", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	ip := strings.TrimSpace(string(b))
	if validIPv4(ip) {
		return ip
	}
	return ""
}

func randSID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
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

func main() {
	cwd, _ := os.Getwd()
	loadEnvFile(filepath.Join(cwd, ".env.punchwg"))

	room = getEnvTrim("ROOM", DefaultRoom)
	wgPort := getEnvInt("WG_PORT", DefaultWGPort)
	wgIface := getEnvTrim("WG_IFACE", "wg0")

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
		log.Printf("missing WG_PRIVKEY or WG_PUBKEY (checked env and /etc/wireguard/%s.conf)", wgIface)
		os.Exit(1)
	}
	if !validWgPubkey(wgPub) {
		log.Printf("WG_PUBKEY looks invalid")
		os.Exit(1)
	}

	// Derive own VPN IPv6 address and room subnet from pubkey + room secret.
	myVPNAddr, err := deriveVPNAddr(room, wgPub)
	if err != nil {
		log.Fatalf("derive VPN addr: %v", err)
	}
	myVPNCIDR := vpnAddrCIDR(myVPNAddr)
	roomPrefix := deriveVPNPrefix(room)
	log.Printf("VPN address: %s  room prefix: %s", myVPNAddr, roomPrefix)

	privHex, err := wgPrivB64ToHex(wgPriv)
	if err != nil {
		log.Printf("private key conversion failed: %v", err)
		os.Exit(1)
	}

	publicIP := getPublicIPv4()
	if publicIP != "" {
		log.Printf("Public IPv4 detected: %s", publicIP)
	} else {
		log.Printf("Public IPv4 not detected, self filtering disabled")
	}

	infoHash := sha1.Sum([]byte(room))

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: wgPort})
	if err != nil {
		log.Fatalf("bind udp failed: %v", err)
	}
	log.Printf("UDP bound on 0.0.0.0:%d", wgPort)

	wgBind := newSharedWGBind(udpConn)

	tunDev, err := tun.CreateTUN(wgIface, 1420)
	if err != nil {
		log.Fatalf("tun create failed: %v", err)
	}

	wgLogger := device.NewLogger(device.LogLevelError, "")
	wgDev := device.NewDevice(tunDev, wgBind, wgLogger)

	ipcCfg := fmt.Sprintf("private_key=%s\nlisten_port=%d\n", privHex, wgPort)
	if err := wgDev.IpcSet(ipcCfg); err != nil {
		log.Fatalf("wireguard ipc set failed: %v", err)
	}

	wgDev.Up()
	log.Printf("WireGuard device is Up iface=%s listen_port=%d", wgIface, wgPort)
	startUAPI(wgDev, wgIface)
	startWGHandshakeWatcher(wgDev)

	ensureLinkUp(wgIface)
	ensureAddress(wgIface, myVPNCIDR)

	cmd := exec.Command("ip", "-6", "route", "replace", roomPrefix.String(), "dev", wgIface)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("ip -6 route failed: %v", err)
	}
	log.Printf("Route: %s via %s", roomPrefix, wgIface)

	dmx := newDemuxConn(udpConn)

	bootstrap := resolveBootstrapHostPorts([]string{
		"router.bittorrent.com:6881",
		"dht.libtorrent.org:25401",
	})

	cfg := dht.NewDefaultServerConfig()
	cfg.Conn = dmx
	cfg.StartingNodes = func() ([]dht.Addr, error) { return dht.ResolveHostPorts(bootstrap) }
	if publicIP != "" {
		cfg.PublicIP = net.ParseIP(publicIP)
	}

	log.Printf("Creating DHT server")
	srv, err := dht.NewServer(cfg)
	if err != nil {
		log.Fatalf("dht server failed: %v", err)
	}
	go srv.TableMaintainer()

	ns := newNetState()

	var (
		annMu  sync.Mutex
		annCur *dht.Announce
	)

	handleConfirmed := func(remote *payload, endpointKey string, raddr *net.UDPAddr) {
		handleConfirmedPeer(ns, wgDev, remote, endpointKey, raddr, room)
	}

	go udpReadLoop(udpConn, dmx, wgBind, ns, wgPub, room, handleConfirmed)

	handleDiscoveredPeer := func(peer krpc.NodeAddr) {
		handleDiscoveredFromDHT(ns, udpConn, peer, publicIP, wgPub, wgPort)
	}

	startAnnounce := func() {
		annMu.Lock()
		if annCur != nil {
			annCur.Close()
			annCur = nil
		}
		ann, err := srv.AnnounceTraversal(
			infoHash,
			dht.AnnouncePeer(dht.AnnouncePeerOpts{
				ImpliedPort: true,
				Port:        wgPort,
			}),
		)
		if err != nil {
			annMu.Unlock()
			log.Printf("announce failed: %v", err)
			return
		}
		annCur = ann
		annMu.Unlock()

		go func(a *dht.Announce) {
			for pv := range a.Peers {
				for _, p := range pv.Peers {
					handleDiscoveredPeer(p)
				}
			}
		}(ann)
	}

	log.Printf("DHT ready. Announcing and looking up peers.")
	startAnnounce()

	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		startAnnounce()
	}
}
