package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"golang.zx2c4.com/wireguard/device"
)

// nostrRelays is the default fan-out relay list. Peers publish to all of them
// and subscribe from all of them, so no single relay can censor or block the
// group. Add more relays here to increase redundancy, or override via
// NOSTR_RELAYS env var (comma-separated).
var nostrRelays = []string{
	"wss://relay.damus.io",
	"wss://nos.lol",
	"wss://nostr.mom",
	"wss://relay.snort.social",
	"wss://nostr-pub.wellorder.net",
}

// nostrPeer is published as the JSON content of each Nostr event.
type nostrPeer struct {
	IP    string `json:"ip"`
	Port  int    `json:"port"`
	WgPub string `json:"wg_pub"`
}

// KindPunchWGRendezvous is a custom parameterized replaceable Nostr event kind.
// The event is keyed by author pubkey + kind + d tag, so each peer can publish
// one latest WireGuard rendezvous record per room without colliding with other
// peers or with its own records in other rooms.
const KindPunchWGRendezvous = 30392

// publishPresence signs and fans out a parameterized replaceable Nostr event
// containing our STUN-discovered external ip:port and WireGuard public key.
// Each peer publishes with its own local Nostr keypair. The shared room is
// identified by the d tag derived from the room secret.
func publishPresence(ctx context.Context, privKeyHex, roomTag, wgPub, externalIP string, externalPort int) {
	peer := nostrPeer{IP: externalIP, Port: externalPort, WgPub: wgPub}
	content, err := json.Marshal(peer)
	if err != nil {
		log.Printf("[nostr] marshal peer: %v", err)
		return
	}

	ev := nostr.Event{
		Kind:      KindPunchWGRendezvous,
		Content:   string(content),
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags: nostr.Tags{
			nostr.Tag{"t", "punchwg"},
			nostr.Tag{"d", roomTag},
		},
	}
	if err := ev.Sign(privKeyHex); err != nil {
		log.Printf("[nostr] sign event: %v", err)
		return
	}

	var wg sync.WaitGroup
	for _, url := range nostrRelays {
		wg.Add(1)
		go func(relayURL string) {
			defer wg.Done()
			pubCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()

			relay, err := nostr.RelayConnect(pubCtx, relayURL)
			if err != nil {
				log.Printf("[nostr] connect %s: %v", relayURL, err)
				return
			}
			defer relay.Close()

			if err := relay.Publish(pubCtx, ev); err != nil {
				log.Printf("[nostr] publish %s: %v", relayURL, err)
				return
			}
			log.Printf("[nostr] published to %s id=%s", relayURL, ev.ID[:8])
		}(url)
	}
	wg.Wait()
}

// subscribePeers opens subscriptions on all relays for room-tagged rendezvous
// events and calls onPeer for each valid peer record received. Deduplication is
// by WireGuard pubkey with a 5-minute cooldown.
func subscribePeers(ctx context.Context, roomTag string, selfWgPub string, onPeer func(nostrPeer)) {
	since := nostr.Timestamp(time.Now().Add(-10 * time.Minute).Unix())
	filter := nostr.Filter{
		Kinds: []int{KindPunchWGRendezvous},
		Tags: nostr.TagMap{
			"t": []string{"punchwg"},
			"d": []string{roomTag},
		},
		Since: &since,
	}

	var mu sync.Mutex
	seen := map[string]time.Time{}

	for _, url := range nostrRelays {
		go func(relayURL string) {
			for {
				if ctx.Err() != nil {
					return
				}
				func() {
					subCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
					defer cancel()

					relay, err := nostr.RelayConnect(subCtx, relayURL)
					if err != nil {
						log.Printf("[nostr] sub connect %s: %v", relayURL, err)
						time.Sleep(15 * time.Second)
						return
					}
					defer relay.Close()

					sub, err := relay.Subscribe(subCtx, nostr.Filters{filter})
					if err != nil {
						log.Printf("[nostr] subscribe %s: %v", relayURL, err)
						time.Sleep(15 * time.Second)
						return
					}

					log.Printf("[nostr] subscribed to %s", relayURL)
					for {
						select {
						case ev, ok := <-sub.Events:
							if !ok {
								return
							}

							var p nostrPeer
							if err := json.Unmarshal([]byte(ev.Content), &p); err != nil {
								continue
							}
							if p.IP == "" || p.Port < 1 || p.Port > 65535 || p.WgPub == "" {
								continue
							}

							// Filter out our own events by WireGuard pubkey. This correctly
							// handles peers behind the same NAT who share a public IP.
							if p.WgPub == selfWgPub {
								continue
							}

							mu.Lock()
							last := seen[p.WgPub]
							fresh := time.Since(last) > 5*time.Minute
							if fresh {
								seen[p.WgPub] = time.Now()
							}
							mu.Unlock()
							if !fresh {
								continue
							}

							log.Printf("[nostr] peer from %s: %s:%d pub=%s...", relayURL, p.IP, p.Port, p.WgPub[:8])
							onPeer(p)

						case <-subCtx.Done():
							return
						case <-ctx.Done():
							return
						}
					}
				}()

				if ctx.Err() != nil {
					return
				}
				time.Sleep(10 * time.Second)
			}
		}(url)
	}
}

// startNostrBootstrap runs the full Nostr bootstrapping lifecycle:
//  1. STUN — discover external ip:port
//  2. Publish our presence to all relays
//  3. Subscribe for peer events and hole-punch each one
//  4. Periodically refresh our published presence
func startNostrBootstrap(
	ctx context.Context,
	ns *netState,
	wgDev *device.Device,
	udpConn *net.UDPConn,
	stunServers []string,
	nostrPriv string,
	roomTag string,
	wgPub string,
	roomSecret string,
	port int,
) {
	if len(stunServers) == 0 {
		stunServers = defaultSTUNServers
	}

	log.Printf("[stun] discovering external address (local port %d)...", port)
	var extAddr *stunResult
	var err error
	for {
		extAddr, err = discoverExternalAddr(udpConn, stunServers)
		if err != nil {
			log.Printf("[stun] failed, retrying in 5s: %v", err)
			time.Sleep(5 * time.Second)
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

	publishPresence(ctx, nostrPriv, roomTag, wgPub, extAddr.IP.String(), extAddr.Port)

	subscribePeers(ctx, roomTag, wgPub, func(p nostrPeer) {
		punchAndConnect(ns, wgDev, udpConn, p, wgPub, roomSecret)
	})

	startSTUNKeepalive(udpConn, stunServers, 20*time.Second, func(r *stunResult) {
		addrMu.Lock()
		currentAddr = r
		addrMu.Unlock()
		log.Printf("[stun] address changed to %s — re-publishing", r)
		publishPresence(ctx, nostrPriv, roomTag, wgPub, r.IP.String(), r.Port)
	})

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a := getAddr()
			publishPresence(ctx, nostrPriv, roomTag, wgPub, a.IP.String(), a.Port)
		case <-ctx.Done():
			return
		}
	}
}

// punchAndConnect NAT-punches and configures WireGuard for a discovered peer.
func punchAndConnect(
	ns *netState,
	wgDev *device.Device,
	udpConn *net.UDPConn,
	peer nostrPeer,
	selfWgPub string,
	roomSecret string,
) {
	if peer.WgPub == selfWgPub {
		return
	}
	ip4 := net.ParseIP(peer.IP).To4()
	if ip4 == nil || peer.Port < 1 || peer.Port > 65535 || peer.WgPub == "" {
		return
	}

	vpnAddr, err := deriveVPNAddr(roomSecret, peer.WgPub)
	if err != nil {
		log.Printf("[punch] cannot derive VPN addr for %s: %v", peer.WgPub, err)
		return
	}
	allowedIP := vpnAddrCIDR(vpnAddr)
	endpoint := net.JoinHostPort(peer.IP, strconv.Itoa(peer.Port))

	if cur, ok := ns.isConfigured(peer.WgPub); ok && cur == endpoint {
		return
	}

	log.Printf("[punch] -> %s pub=%s vpn=%s", endpoint, peer.WgPub[:8], vpnAddr)

	dst := &net.UDPAddr{IP: ip4, Port: peer.Port}
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
		log.Printf("[punch] WG configured peer=%s endpoint=%s vpn=%s", peer.WgPub[:8], endpoint, vpnAddr)
	}()
}
