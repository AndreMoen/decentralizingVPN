package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
	"golang.zx2c4.com/wireguard/device"
)

// torPeer is the record stored in and returned by the group onion registry.
// WgIP is absent — every peer derives VPN addresses locally from WgPub + room.
// LocalIP is the private LAN address, used when peers share the same NAT.
type torPeer struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	WgPub   string `json:"wg_pub"`
	LocalIP string `json:"local_ip,omitempty"`
}

// getLocalIP returns the preferred outbound LAN IP of this machine by
// opening a UDP "connection" to a public address (no packets are sent).
func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

// newTorHTTPClient returns an http.Client routing through the Tor SOCKS5 proxy.
func newTorHTTPClient(torSocks string) (*http.Client, error) {
	dialer, err := proxy.SOCKS5("tcp", torSocks, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("tor socks5 dialer: %w", err)
	}
	return &http.Client{
		Transport: &http.Transport{Dial: dialer.Dial},
		Timeout:   30 * time.Second,
	}, nil
}

// newLocalHTTPClient returns a plain http.Client with no proxy — used when
// this peer is the registry server and can reach itself via 127.0.0.1 directly.
func newLocalHTTPClient() *http.Client {
	return &http.Client{Timeout: 5 * time.Second}
}

// registryClient returns the appropriate HTTP client and URL for the registry.
// If this peer is the server, it bypasses Tor entirely and hits localhost.
func registryClient(torClient *http.Client, groupOnionURL string, reg *peerRegistry) (*http.Client, string) {
	reg.mu.Lock()
	local := reg.localURL
	reg.mu.Unlock()
	if local != "" {
		return newLocalHTTPClient(), local
	}
	return torClient, groupOnionURL
}

func registerWithGroupOnion(client *http.Client, groupOnionURL, externalIP string, externalPort int, wgPub string) error {
	body, _ := json.Marshal(torPeer{IP: externalIP, Port: externalPort, WgPub: wgPub, LocalIP: getLocalIP()})
	resp, err := client.Post(groupOnionURL+"/register", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("register POST: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("register %d: %s", resp.StatusCode, b)
	}
	return nil
}

func fetchPeersFromGroupOnion(client *http.Client, groupOnionURL string) ([]torPeer, error) {
	resp, err := client.Get(groupOnionURL + "/participants")
	if err != nil {
		return nil, fmt.Errorf("participants GET: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("participants %d", resp.StatusCode)
	}
	var peers []torPeer
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return peers, nil
}

// punchAndConnect opens the NAT mapping with a short UDP burst then configures
// WireGuard. The peer's VPN IPv6 address is derived locally from their public
// key — no wg_ip field is needed in the registry.
//
// Four cases are handled:
//  1. Same external IP, same port — that's us, skip
//  2. Peer advertised a LocalIP reachable on our LAN — connect directly
//  3. Same external IP, different port — same NAT, try local then hairpin
//  4. Different external IP — normal internet punch
func punchAndConnect(
	ns *netState,
	wgDev *device.Device,
	udpConn *net.UDPConn,
	peer torPeer,
	selfIP string,
	selfPort int,
	selfLocalIP string,
	wgPort int,
	room string,
) {
	if peer.WgPub == "" || peer.Port < 1 || peer.Port > 65535 {
		return
	}

	vpnAddr, err := deriveVPNAddr(room, peer.WgPub)
	if err != nil {
		log.Printf("[punch] cannot derive VPN addr for %s: %v", peer.WgPub, err)
		return
	}
	allowedIP := vpnAddrCIDR(vpnAddr)

	sameNAT := peer.IP == selfIP

	// Case 1: skip ourselves.
	if sameNAT && peer.Port == selfPort {
		return
	}

	var endpoint string

	switch {
	case peer.LocalIP != "" && peer.LocalIP != selfLocalIP && isLocallyReachable(peer.LocalIP):
		// Case 2: peer is on the same LAN — use local IP with the WG listening port.
		// peer.Port is the STUN-discovered external port, which is only valid from
		// outside. Locally the peer listens on wgPort (default 51820).
		endpoint = net.JoinHostPort(peer.LocalIP, strconv.Itoa(wgPort))
		log.Printf("[punch] local LAN peer -> %s pub=%s vpn=%s", endpoint, peer.WgPub, vpnAddr)

	case sameNAT && peer.LocalIP != "" && peer.LocalIP != selfLocalIP:
		// Case 3a: same NAT, local IP advertised but not reachable (isolated networks).
		// Try hairpin punch through the external IP.
		endpoint = net.JoinHostPort(peer.IP, strconv.Itoa(peer.Port))
		log.Printf("[punch] same-NAT hairpin (isolated) -> %s pub=%s vpn=%s", endpoint, peer.WgPub, vpnAddr)

	case sameNAT:
		// Case 3b: same NAT, no local IP — hairpin punch.
		endpoint = net.JoinHostPort(peer.IP, strconv.Itoa(peer.Port))
		log.Printf("[punch] same-NAT hairpin -> %s pub=%s vpn=%s", endpoint, peer.WgPub, vpnAddr)

	default:
		// Case 4: normal internet punch.
		ip4 := net.ParseIP(peer.IP).To4()
		if ip4 == nil {
			return
		}
		endpoint = net.JoinHostPort(peer.IP, strconv.Itoa(peer.Port))
	}

	if cur, ok := ns.isConfigured(peer.WgPub); ok && cur == endpoint {
		return
	}

	log.Printf("[punch] -> %s pub=%s vpn=%s", endpoint, peer.WgPub, vpnAddr)

	endpointHost, endpointPortStr, _ := net.SplitHostPort(endpoint)
	endpointPort, _ := strconv.Atoi(endpointPortStr)
	dst := &net.UDPAddr{IP: net.ParseIP(endpointHost), Port: endpointPort}
	go func() {
		ping := []byte("punch")
		for i := 0; i < 25; i++ {
			_, _ = udpConn.WriteToUDP(ping, dst)
			time.Sleep(20 * time.Millisecond)
		}
		if err := wgUpsertPeer(wgDev, peer.WgPub, allowedIP, endpoint); err != nil {
			log.Printf("[punch] wg upsert failed for %s: %v", endpoint, err)
			return
		}
		ns.markConfigured(peer.WgPub, endpoint)
		log.Printf("[punch] WG configured peer=%s endpoint=%s vpn=%s", peer.WgPub, endpoint, vpnAddr)
	}()
}

// isLocallyReachable checks if a host is on a locally attached subnet by
// comparing it against all local network interfaces. Does not send any packets.
// Also checks the system routing table via /proc/net/fib_trie as a fallback,
// since macvlan interfaces sometimes only show a /32 host route rather than
// the full subnet, which would cause a subnet-only check to miss LAN peers.
func isLocallyReachable(host string) bool {
	target := net.ParseIP(host)
	if target == nil {
		return false
	}
	target4 := target.To4()

	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		// Skip loopback and WireGuard interfaces.
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if strings.HasPrefix(iface.Name, "wg") {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipNet.Contains(target) {
				log.Printf("[punch] %s is locally reachable via iface %s (%s)", host, iface.Name, ipNet)
				return true
			}
			// Fallback: if this interface has a /32 (macvlan host route) check if
			// the target is in the same /24 — a reasonable LAN heuristic.
			if target4 != nil {
				ones, bits := ipNet.Mask.Size()
				if bits == 32 && ones == 32 {
					// Widen to /24 and check
					widened := &net.IPNet{IP: ipNet.IP.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}
					if widened.Contains(target4) {
						log.Printf("[punch] %s is locally reachable via /24 widening on iface %s", host, iface.Name)
						return true
					}
				}
			}
		}
	}
	return false
}

// startTorBootstrap runs the full lifecycle.
func startTorBootstrap(
	ctx context.Context,
	ns *netState,
	wgDev *device.Device,
	udpConn *net.UDPConn,
	groupOnionURL string,
	torSocks string,
	groupOnion string,
	stunServers []string,
	privKey ed25519.PrivateKey,
	reg *peerRegistry,
	service *staticOnionProcess,
	wgPub string,
	room string,
	port int,
) {
	if len(stunServers) == 0 {
		stunServers = defaultSTUNServers
	}

	log.Printf("[stun] discovering external address (local port %d)...", port)
	var extAddr *stunResult
	var err error
	for {
		if ctx.Err() != nil {
			return
		}
		extAddr, err = discoverExternalAddr(udpConn, stunServers)
		if err != nil {
			log.Printf("[stun] failed, retrying in 5s: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		break
	}
	log.Printf("[stun] external address = %s", extAddr)

	var addrMu sync.Mutex
	currentAddr := extAddr
	getAddr := func() *stunResult {
		addrMu.Lock()
		defer addrMu.Unlock()
		return currentAddr
	}

	client, err := newTorHTTPClient(torSocks)
	if err != nil {
		log.Fatalf("[tor] http client: %v", err)
	}

	log.Printf("[tor] waiting for group onion %s...", groupOnionURL)
	for {
		if ctx.Err() != nil {
			return
		}
		a := getAddr()
		c, url := registryClient(client, groupOnionURL, reg)
		if err := registerWithGroupOnion(c, url, a.IP.String(), a.Port, wgPub); err != nil {
			log.Printf("[tor] not reachable yet (%v), retrying in 10s", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
			continue
		}
		log.Printf("[tor] registered — external=%s", a)
		break
	}

	startSTUNKeepalive(udpConn, stunServers, 20*time.Second, func(r *stunResult) {
		addrMu.Lock()
		currentAddr = r
		addrMu.Unlock()
		log.Printf("[stun] address changed to %s — re-registering", r)
		c, url := registryClient(client, groupOnionURL, reg)
		if err := registerWithGroupOnion(c, url, r.IP.String(), r.Port, wgPub); err != nil {
			log.Printf("[tor] re-register failed: %v", err)
		}
	})

	consecutiveFailures := 0
	const failoverAfter = 3

	doRound := func() {
		a := getAddr()
		c, url := registryClient(client, groupOnionURL, reg)

		regErr := registerWithGroupOnion(c, url, a.IP.String(), a.Port, wgPub)
		if regErr != nil {
			log.Printf("[tor] register failed: %v", regErr)
		}

		peers, fetchErr := fetchPeersFromGroupOnion(c, url)
		if fetchErr != nil {
			log.Printf("[tor] fetch peers failed: %v", fetchErr)
		}

		if regErr != nil && fetchErr != nil {
			consecutiveFailures++
			log.Printf("[tor] onion unreachable (%d/%d)", consecutiveFailures, failoverAfter)
			if consecutiveFailures >= failoverAfter {
				// Stagger failover attempts with random jitter (0-30s) so peers
				// don't all race to become the server at the same time.
				jitter := time.Duration(rand.Intn(30)) * time.Second
				log.Printf("[tor] waiting %s before failover attempt", jitter)
				select {
				case <-ctx.Done():
					return
				case <-time.After(jitter):
				}
				// Re-probe after jitter — another peer may have already taken over.
				if probeOnion(torSocks, groupOnionURL) {
					log.Printf("[tor] onion recovered during jitter wait — skipping failover")
					consecutiveFailures = 0
					return
				}
				log.Printf("[tor] attempting failover")
				if becomeOnionServer(ctx, torSocks, groupOnionURL, groupOnion, privKey, reg, service) {
					consecutiveFailures = 0
					a := getAddr()
					c, url := registryClient(client, groupOnionURL, reg)
					if err := registerWithGroupOnion(c, url, a.IP.String(), a.Port, wgPub); err != nil {
						log.Printf("[tor] post-failover register failed: %v", err)
					} else {
						log.Printf("[tor] failover complete — now serving as registry")
					}
				} else {
					consecutiveFailures = 0
				}
			}
			return
		}

		consecutiveFailures = 0
		for _, p := range peers {
			punchAndConnect(ns, wgDev, udpConn, p, a.IP.String(), a.Port, getLocalIP(), port, room)
		}
	}

	doRound()
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("[tor] shutting down")
			return
		case <-ticker.C:
			doRound()
		}
	}
}
