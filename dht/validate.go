package main

import (
	"net"
	"net/netip"
	"strings"
)

func validIPv4(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	return ip != nil && ip.To4() != nil
}

// validAllowedIP accepts both IPv4 (10.0.0.1/32) and IPv6 (fd00::/128) prefixes.
func validAllowedIP(s string) bool {
	_, err := netip.ParsePrefix(strings.TrimSpace(s))
	return err == nil
}

func validWgPubkey(s string) bool { return reWgPub.MatchString(strings.TrimSpace(s)) }
