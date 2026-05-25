package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/netip"
	"strings"
)

// deriveVPNAddr derives a deterministic ULA IPv6 /128 address for a peer
// from the room secret and their WireGuard public key.
//
// Address layout (128 bits):
//   [ 0xfd | SHA-256(room)[0:5] | SHA-256(wg_pubkey)[0:10] ]
//      8 bits       40 bits               80 bits
//
// 0xfd  - ULA marker (RFC 4193)
// room  - SHA-256(secret)[0:5]: peers in different rooms use different subnets
// key   - SHA-256(wg_pubkey)[0:10]: unique per peer, 2^80 collision space
func deriveVPNAddr(room, wgPubKeyB64 string) (netip.Addr, error) {
	pubRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(wgPubKeyB64))
	if err != nil {
		pubRaw, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(wgPubKeyB64))
		if err != nil {
			return netip.Addr{}, fmt.Errorf("decode pubkey: %w", err)
		}
	}

	roomHash := sha256.Sum256([]byte(room))
	keyHash := sha256.Sum256(pubRaw)

	var raw [16]byte
	raw[0] = 0xfd
	copy(raw[1:6], roomHash[:5])
	copy(raw[6:16], keyHash[:10])

	return netip.AddrFrom16(raw), nil
}

// deriveVPNPrefix returns the /48 subnet for the room.
func deriveVPNPrefix(room string) netip.Prefix {
	roomHash := sha256.Sum256([]byte(room))
	var raw [16]byte
	raw[0] = 0xfd
	copy(raw[1:6], roomHash[:5])
	return netip.PrefixFrom(netip.AddrFrom16(raw), 48)
}

// vpnAddrCIDR returns "addr/128" for WireGuard allowed_ip and ip addr add.
func vpnAddrCIDR(addr netip.Addr) string {
	return netip.PrefixFrom(addr, 128).String()
}
