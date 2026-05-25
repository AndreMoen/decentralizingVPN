package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// STUN message types and magic cookie (RFC 5389).
const (
	stunBindingRequest  = uint16(0x0001)
	stunBindingResponse = uint16(0x0101)
	stunMagicCookie     = uint32(0x2112A442)

	// STUN attribute types.
	stunAttrMappedAddress    = uint16(0x0001)
	stunAttrXORMappedAddress = uint16(0x0020)

	// Address family.
	stunFamilyIPv4 = 0x01
)

// Default public STUN servers. Any RFC 5389 compliant server works.
var defaultSTUNServers = []string{
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun.cloudflare.com:3478",
}

// stunResult holds the external address learned from a STUN server.
type stunResult struct {
	IP   net.IP
	Port int
}

func (r stunResult) String() string {
	return net.JoinHostPort(r.IP.String(), fmt.Sprintf("%d", r.Port))
}

// buildSTUNRequest builds a minimal STUN Binding Request.
func buildSTUNRequest(transactionID [12]byte) []byte {
	msg := make([]byte, 20)
	binary.BigEndian.PutUint16(msg[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(msg[2:4], 0)
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
	copy(msg[8:20], transactionID[:])
	return msg
}

// parseSTUNResponse parses a STUN Binding Response and returns the mapped address.
func parseSTUNResponse(data []byte, transactionID [12]byte) (*stunResult, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("stun response too short (%d bytes)", len(data))
	}
	msgType := binary.BigEndian.Uint16(data[0:2])
	if msgType != stunBindingResponse {
		return nil, fmt.Errorf("stun: unexpected message type 0x%04x", msgType)
	}
	cookie := binary.BigEndian.Uint32(data[4:8])
	if cookie != stunMagicCookie {
		return nil, fmt.Errorf("stun: bad magic cookie")
	}
	if [12]byte(data[8:20]) != transactionID {
		return nil, fmt.Errorf("stun: transaction ID mismatch")
	}

	attrLen := binary.BigEndian.Uint16(data[2:4])
	attrs := data[20:]
	if int(attrLen) > len(attrs) {
		return nil, fmt.Errorf("stun: attribute length overflow")
	}
	attrs = attrs[:attrLen]

	var result *stunResult
	for len(attrs) >= 4 {
		aType := binary.BigEndian.Uint16(attrs[0:2])
		aLen := binary.BigEndian.Uint16(attrs[2:4])
		if int(aLen) > len(attrs)-4 {
			break
		}
		val := attrs[4 : 4+aLen]

		switch aType {
		case stunAttrXORMappedAddress:
			if len(val) >= 8 && val[1] == stunFamilyIPv4 {
				port := binary.BigEndian.Uint16(val[2:4]) ^ uint16(stunMagicCookie>>16)
				ip := make(net.IP, 4)
				xorCookie := binary.BigEndian.Uint32(data[4:8])
				mapped := binary.BigEndian.Uint32(val[4:8]) ^ xorCookie
				binary.BigEndian.PutUint32(ip, mapped)
				result = &stunResult{IP: ip, Port: int(port)}
			}
		case stunAttrMappedAddress:
			if result == nil && len(val) >= 8 && val[1] == stunFamilyIPv4 {
				port := int(binary.BigEndian.Uint16(val[2:4]))
				ip := make(net.IP, 4)
				copy(ip, val[4:8])
				result = &stunResult{IP: ip, Port: port}
			}
		}

		padded := (int(aLen) + 3) &^ 3
		attrs = attrs[4+padded:]
	}

	if result == nil {
		return nil, fmt.Errorf("stun: no mapped address attribute found")
	}
	return result, nil
}

// ── STUN response demux ──────────────────────────────────────────────────────
//
// Because all traffic (WireGuard, hole-punch probes, and STUN) shares a single
// UDP socket, we cannot call SetReadDeadline on that socket from stunQuery
// without racing with udpReadLoop.  Instead, udpReadLoop calls
// deliverSTUNPacket for any packet that looks like a STUN binding response;
// stunQuery registers a channel keyed by transaction ID and waits on it.

var stunRxTable = struct {
	sync.Mutex
	m map[[12]byte]chan []byte
}{m: make(map[[12]byte]chan []byte)}

// deliverSTUNPacket is called by udpReadLoop when a received packet matches
// the STUN magic cookie and binding-response type.  Returns true if the
// packet was claimed by a waiting stunQuery call.
func deliverSTUNPacket(data []byte) bool {
	if len(data) < 20 {
		return false
	}
	if binary.BigEndian.Uint32(data[4:8]) != stunMagicCookie {
		return false
	}
	if binary.BigEndian.Uint16(data[0:2]) != stunBindingResponse {
		return false
	}
	var txID [12]byte
	copy(txID[:], data[8:20])

	stunRxTable.Lock()
	ch := stunRxTable.m[txID]
	stunRxTable.Unlock()
	if ch == nil {
		return false
	}
	pkt := make([]byte, len(data))
	copy(pkt, data)
	select {
	case ch <- pkt:
	default:
	}
	return true
}

// stunQuery sends a STUN Binding Request on the shared udpConn and returns the
// external mapped address reported by the server.
//
// Crucially it never calls SetReadDeadline on udpConn — responses are delivered
// via deliverSTUNPacket from udpReadLoop, so there is no race.
func stunQuery(udpConn *net.UDPConn, serverAddr string) (*stunResult, error) {
	raddr, err := net.ResolveUDPAddr("udp4", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", serverAddr, err)
	}

	var txID [12]byte
	if _, err := rand.Read(txID[:]); err != nil {
		return nil, fmt.Errorf("rand txid: %w", err)
	}

	ch := make(chan []byte, 1)
	stunRxTable.Lock()
	stunRxTable.m[txID] = ch
	stunRxTable.Unlock()
	defer func() {
		stunRxTable.Lock()
		delete(stunRxTable.m, txID)
		stunRxTable.Unlock()
	}()

	if _, err := udpConn.WriteToUDP(buildSTUNRequest(txID), raddr); err != nil {
		return nil, fmt.Errorf("stun write: %w", err)
	}

	select {
	case pkt := <-ch:
		return parseSTUNResponse(pkt, txID)
	case <-time.After(3 * time.Second):
		return nil, fmt.Errorf("stun timeout from %s", serverAddr)
	}
}

// discoverExternalAddr tries each STUN server in turn until one succeeds.
func discoverExternalAddr(udpConn *net.UDPConn, servers []string) (*stunResult, error) {
	for _, srv := range servers {
		r, err := stunQuery(udpConn, srv)
		if err != nil {
			log.Printf("STUN %s failed: %v", srv, err)
			continue
		}
		log.Printf("STUN discovered external address: %s (via %s)", r, srv)
		return r, nil
	}
	return nil, fmt.Errorf("all STUN servers failed")
}

// startSTUNKeepalive periodically re-queries STUN to keep the NAT mapping alive
// and detect address changes (e.g. after a NAT rebinding).
//
// The keepalive fires every interval; most consumer NATs time out UDP mappings
// after 30–300 s so the default 20 s is a safe choice.  onAddrChange is called
// whenever the external address differs from the previously known value.
func startSTUNKeepalive(
	udpConn *net.UDPConn,
	servers []string,
	interval time.Duration,
	onAddrChange func(r *stunResult),
) {
	go func() {
		var last *stunResult
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			r, err := discoverExternalAddr(udpConn, servers)
			if err != nil {
				log.Printf("STUN keepalive failed: %v", err)
				continue
			}
			if last == nil || r.IP.String() != last.IP.String() || r.Port != last.Port {
				log.Printf("STUN: external address changed %v → %s", last, r)
				last = r
				onAddrChange(r)
			}
		}
	}()
}
