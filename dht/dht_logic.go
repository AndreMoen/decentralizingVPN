package main

import (
	"log"
	"net"
	"strconv"
	"time"

	"github.com/anacrolix/dht/v2/krpc"
)

func handleDiscoveredFromDHT(ns *netState, udpConn *net.UDPConn, peer krpc.NodeAddr, publicIP, wgPub string, wgPort int) {
	ip4 := peer.IP.To4()
	if ip4 == nil {
		return
	}
	host := ip4.String()
	port := peer.Port
	if port < 1 || port > 65535 {
		return
	}
	if publicIP != "" && host == publicIP && port == wgPort {
		return
	}

	endpointKey := net.JoinHostPort(host, strconv.Itoa(port))

	ns.mu.Lock()
	if ns.confirmedEndpoint[endpointKey] || ns.triedByEndpoint[endpointKey] {
		ns.mu.Unlock()
		return
	}
	ns.triedByEndpoint[endpointKey] = true

	ps := ns.pendingByEndpoint[endpointKey]
	if ps == nil {
		ps = &pendingState{SID: randSID(), FirstSend: time.Now()}
		ns.pendingByEndpoint[endpointKey] = ps
	}
	sid := ps.SID
	ns.mu.Unlock()

	log.Printf("Peer discovered from DHT: %s", endpointKey)

	dst := &net.UDPAddr{IP: ip4, Port: port}

	go func() {
		for i := 0; i < 260; i++ {
			ns.mu.Lock()
			done := ns.confirmedEndpoint[endpointKey]
			ns.mu.Unlock()
			if done {
				return
			}
			_, _ = udpConn.WriteToUDP(pack("HELLO", sid, ptrI64(tsNow()), localPayload(wgPub)), dst)
			time.Sleep(20 * time.Millisecond)
		}
		ns.mu.Lock()
		done := ns.confirmedEndpoint[endpointKey]
		ns.mu.Unlock()
		if !done {
			log.Printf("No confirmation yet from %s", endpointKey)
		}
	}()
}
