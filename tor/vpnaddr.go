package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

// deriveVPNAddr derives a deterministic ULA IPv6 /128 address for a peer
// from the room secret and the peer's WireGuard public key.
//
// Address layout (128 bits):
//
//	[ fd | room(40) | key(80) ]
//	  8      40         80      = 128 bits
//
// The fd prefix marks it as a ULA (Unique Local Address, RFC 4193).
// The 40-bit room segment means peers in different rooms get different
// subnets and cannot accidentally route to each other.
// The 80-bit key segment makes collisions negligible (2^80 space).
//
// The /48 prefix (fd + room) is the subnet for the whole room.
// Each peer gets a /128 within that subnet.
func deriveVPNAddr(room, wgPubKeyB64 string) (netip.Addr, error) {
	pubRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(wgPubKeyB64))
	if err != nil {
		pubRaw, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(wgPubKeyB64))
		if err != nil {
			return netip.Addr{}, fmt.Errorf("decode pubkey: %w", err)
		}
	}

	// 40-bit room segment: SHA-256(room)[0:5]
	roomHash := sha256.Sum256([]byte(room))

	// 80-bit key segment: SHA-256(pubkey)[0:10]
	keyHash := sha256.Sum256(pubRaw)

	var addr [16]byte
	addr[0] = 0xfd
	copy(addr[1:6], roomHash[:5])  // 40 bits of room
	copy(addr[6:16], keyHash[:10]) // 80 bits of key

	return netip.AddrFrom16(addr), nil
}

// deriveVPNPrefix returns the /48 subnet prefix for the room,
// used as the route covering all peers in this room.
func deriveVPNPrefix(room string) netip.Prefix {
	roomHash := sha256.Sum256([]byte(room))

	var addr [16]byte
	addr[0] = 0xfd
	copy(addr[1:6], roomHash[:5])

	// Zero out the key bits to get the network address.
	// addr[6:16] is already zero from var declaration.
	_ = binary.BigEndian // imported for clarity, unused directly
	return netip.PrefixFrom(netip.AddrFrom16(addr), 48)
}

// vpnAddrCIDR returns the /128 address as a string suitable for
// WireGuard allowed_ip and ip addr add, e.g. "fd12:3456:789a:b:c:d:e:f/128".
func vpnAddrCIDR(addr netip.Addr) string {
	return netip.PrefixFrom(addr, 128).String()
}
