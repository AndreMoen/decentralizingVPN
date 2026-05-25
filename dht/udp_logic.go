package main

import (
	"log"
	"net"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

func handleConfirmedPeer(ns *netState, wgDev *device.Device, remote *payload, endpointKey string, raddr *net.UDPAddr, room string) {
	if remote == nil {
		return
	}
	if strings.TrimSpace(remote.Room) != "" && strings.TrimSpace(remote.Room) != room {
		return
	}

	pub := strings.TrimSpace(remote.WgPub)
	if pub == "" {
		return
	}

	vpnAddr, err := deriveVPNAddr(room, pub)
	if err != nil {
		log.Printf("handleConfirmedPeer: cannot derive VPN addr for %s: %v", pub, err)
		return
	}
	allowedIP := vpnAddrCIDR(vpnAddr)

	key, em, ok := udpAddrKey(raddr)
	if !ok {
		return
	}
	if key != endpointKey {
		endpointKey = key
	}

	var bestKey string
	var switchNow bool

	ns.mu.Lock()
	ns.addCandidate(pub, allowedIP, endpointKey, em)
	p := ns.getOrCreatePeer(pub, allowedIP)
	bestKey = ns.bestCandidateKey(p)
	bestEndpoint := bestKey
	if p.Active == "" {
		switchNow = true
	} else {
		switchNow = ns.shouldSwitchEndpoint(p, bestKey)
	}
	if switchNow {
		p.Active = bestKey
	}
	ns.markSuccess(pub, endpointKey)
	ns.mu.Unlock()

	if bestEndpoint == "" {
		log.Printf("Peer confirmed pub=%s endpoint=%s vpn=%s (no best endpoint yet)", pub, endpointKey, vpnAddr)
		return
	}

	if switchNow {
		if err := wgUpsertPeer(wgDev, pub, allowedIP, bestEndpoint); err != nil {
			log.Printf("wg upsert peer failed: %v", err)
			return
		}
		log.Printf("WG endpoint set pub=%s endpoint=%s vpn=%s", pub, bestEndpoint, vpnAddr)
		return
	}

	log.Printf("Peer confirmed pub=%s endpoint=%s vpn=%s best=%s", pub, endpointKey, vpnAddr, or(bestKey, "none"))
}

func udpReadLoop(
	udpConn *net.UDPConn,
	dmx *demuxConn,
	wgBind *sharedWGBind,
	ns *netState,
	wgPub string,
	room string,
	onConfirmed func(remote *payload, endpointKey string, raddr *net.UDPAddr),
) {
	buf := make([]byte, 65535)
	for {
		n, raddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		data := append([]byte(nil), buf[:n]...)

		if looksLikeWireGuard(data) {
			ep, epErr := newUDPEndpoint(raddr)
			if epErr == nil {
				select {
				case wgBind.rx <- wgPkt{b: data, ep: ep}:
				default:
				}
			}
			continue
		}

		pkt := unpack(data)
		if pkt == nil {
			select {
				case dmx.rx <- demuxPkt{b: data, addr: raddr}:
				default:
				}
			continue
		}

		endpointKey := raddr.String()
		log.Printf("RX %s from %s sid=%s hasPayload=%t", pkt.Type, endpointKey, pkt.SID, pkt.Payload != nil)

		ns.mu.Lock()
		ps := ns.pendingByEndpoint[endpointKey]
		if ps == nil {
			ps = &pendingState{SID: randSID(), FirstSend: time.Now()}
			ns.pendingByEndpoint[endpointKey] = ps
		}
		if pkt.Payload != nil {
			ps.Remote = mergePayload(ps.Remote, pkt.Payload)
		}
		ns.mu.Unlock()

		switch pkt.Type {
		case "HELLO":
			_, _ = udpConn.WriteToUDP(pack("REPLY", pkt.SID, ptrI64(tsNow()), localPayload(wgPub)), raddr)

		case "REPLY":
			_, _ = udpConn.WriteToUDP(pack("ACK", pkt.SID, ptrI64(tsNow()), localPayload(wgPub)), raddr)

			ns.mu.Lock()
			if !ns.confirmedEndpoint[endpointKey] {
				ns.confirmedEndpoint[endpointKey] = true
				remote2 := (*payload)(nil)
				if ps2 := ns.pendingByEndpoint[endpointKey]; ps2 != nil {
					remote2 = ps2.Remote
				}
				ns.mu.Unlock()
				log.Printf("DIRECT UDP OK %s reply session=%s", endpointKey, pkt.SID)
				go onConfirmed(remote2, endpointKey, raddr)
				continue
			}
			ns.mu.Unlock()

		case "ACK":
			ns.mu.Lock()
			if !ns.confirmedEndpoint[endpointKey] {
				ns.confirmedEndpoint[endpointKey] = true
				remote2 := (*payload)(nil)
				if ps2 := ns.pendingByEndpoint[endpointKey]; ps2 != nil {
					remote2 = ps2.Remote
				}
				ns.mu.Unlock()
				log.Printf("DIRECT UDP OK %s ack session=%s", endpointKey, pkt.SID)
				go onConfirmed(remote2, endpointKey, raddr)
				continue
			}
			ns.mu.Unlock()
		}
	}
}
