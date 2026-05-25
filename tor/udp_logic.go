package main

import (
	"net"

	"golang.zx2c4.com/wireguard/device"
)

// udpReadLoop is the single reader for the shared UDP socket.
// It demuxes packets to three consumers:
//   - WireGuard device (via sharedWGBind.rx)
//   - STUN response handler (via deliverSTUNPacket)
//   - anything else is silently dropped
//
// The custom HELLO/REPLY/ACK hole-punch protocol has been removed.
// NAT mappings are opened by a raw UDP burst in punchAndConnect;
// WireGuard's own handshake completes the connection.
func udpReadLoop(
	udpConn *net.UDPConn,
	wgBind *sharedWGBind,
	_ *device.Device, // kept for call-site compatibility, unused
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

		// Route STUN binding responses to waiting stunQuery calls.
		if deliverSTUNPacket(data) {
			continue
		}

		// All other packets are dropped — no custom punch protocol.
	}
}
