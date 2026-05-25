package main

import (
	"bufio"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
)

// torControl is a minimal Tor control-port client.
// It implements only what we need: AUTHENTICATE, ADD_ONION, DEL_ONION.
//
// Protocol reference: https://spec.torproject.org/control-spec
type torControl struct {
	conn    net.Conn
	reader  *bufio.Reader
	onionID string // service ID returned by ADD_ONION, used for cleanup
}

func newTorControl(conn net.Conn) *torControl {
	return &torControl{conn: conn, reader: bufio.NewReader(conn)}
}

// sendCmd writes one control command and reads the full reply.
// Tor replies use a 3-digit code followed by '-' (more lines) or ' ' (last line).
// Returns all reply lines; returns an error if the reply code starts with 4 or 5.
func (tc *torControl) sendCmd(cmd string) ([]string, error) {
	if _, err := fmt.Fprintf(tc.conn, "%s\r\n", cmd); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	var lines []string
	for {
		line, err := tc.reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("read: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		if len(line) < 4 {
			return nil, fmt.Errorf("malformed reply: %q", line)
		}
		sep := line[3]
		if sep == ' ' { // last line of reply
			if line[0] != '2' {
				return lines, fmt.Errorf("tor: %s", line)
			}
			return lines, nil
		}
		if sep != '-' {
			return nil, fmt.Errorf("unexpected separator in reply: %q", line)
		}
		// sep == '-': more lines follow
	}
}

// authenticate attempts AUTHENTICATE with an empty/null password.
// This works for the default local Tor setup where no password or cookie is set.
func (tc *torControl) authenticate() error {
	if _, err := tc.sendCmd(`AUTHENTICATE ""`); err == nil {
		return nil
	}
	_, err := tc.sendCmd("AUTHENTICATE")
	return err
}

// setConf sets one or more Tor configuration values at runtime via SETCONF.
// keyvals is a list of "Key=Value" strings, e.g. []string{"MaxCircuitDirtiness=10"}.
// Errors are logged but non-fatal — if Tor rejects a setting the caller continues.
func (tc *torControl) setConf(keyvals ...string) error {
	if len(keyvals) == 0 {
		return nil
	}
	cmd := "SETCONF " + strings.Join(keyvals, " ")
	_, err := tc.sendCmd(cmd)
	return err
}

// configureShortCircuits asks the running Tor daemon to prefer shorter paths
// for this session. These are best-effort: Tor may ignore some flags depending
// on version and network consensus.
//
//	MaxCircuitDirtiness=10      recycle circuits every 10 s (vs 10 min default)
//	CircuitBuildTimeout=10      abandon slow circuit builds sooner
//	LearnCircuitBuildTimeout=0  disable adaptive timeout (keep our 10 s)
//	NumEntryGuards=1            use only 1 guard node instead of 3
func (tc *torControl) configureShortCircuits() {
	settings := []string{
		"MaxCircuitDirtiness=10",
		"CircuitBuildTimeout=10",
		"LearnCircuitBuildTimeout=0",
		"NumEntryGuards=1",
	}
	if err := tc.setConf(settings...); err != nil {
		// Non-fatal: some Tor versions restrict SETCONF over the control port.
		// The ADD_ONION SingleHopMode flag still applies regardless.
		fmt.Printf("[tor-control] SETCONF short-circuit settings failed (non-fatal): %v\n", err)
	}
}

// addOnion creates a new v3 hidden service with the given deterministic key.
//
//	expandedPrivKey  64-byte expanded ed25519 scalar (see expandEd25519PrivateKey)
//	virtPort         port exposed on the .onion address (80)
//	targetPort       local TCP port the HTTP server is listening on
//
// SingleHopMode eliminates the 3 server-side Tor hops — the hidden service
// introduction point IS the server. This trades anonymity for latency, which
// is fine here since we only care about exchanging hole-punching metadata.
// NumIntroductionPoints=1 further reduces circuit overhead.
func (tc *torControl) addOnion(expandedPrivKey []byte, virtPort, targetPort int) error {
	if len(expandedPrivKey) != 64 {
		return fmt.Errorf("ADD_ONION: key must be 64 bytes, got %d", len(expandedPrivKey))
	}
	keyB64 := base64.StdEncoding.EncodeToString(expandedPrivKey)

	// Tor version compatibility for NonAnonymousMode:
	// - 0.4.6: HiddenServiceNonAnonymousMode in torrc is sufficient, passing
	//          Flags=NonAnonymous in ADD_ONION is not recognised and causes 512.
	// - 0.4.8+: Flags=NonAnonymous must be passed explicitly in ADD_ONION.
	// So we try without the flag first, then with it.
	var lines []string
	for _, flags := range []string{"", "Flags=NonAnonymous "} {
		cmd := fmt.Sprintf("ADD_ONION ED25519-V3:%s %sPort=%d,127.0.0.1:%d", keyB64, flags, virtPort, targetPort)
		var err error
		lines, err = tc.sendCmd(cmd)
		if err == nil {
			break
		}
		if flags == "Flags=NonAnonymous " {
			// Both attempts failed — likely not connected to the right instance.
			return fmt.Errorf("ADD_ONION failed: %w\n\n"+
				"Make sure the dedicated onion Tor instance is running:\n"+
				"  sudo tor -f /etc/tor/torrc-onion &\n"+
				"And that TOR_CONTROL=127.0.0.1:9052 is set in .env.punchwg", err)
		}
		// First attempt failed, try with NonAnonymous flag next iteration.
	}
	fmt.Printf("[tor-control] single-hop hidden service active (via torrc-onion)\n")
	for _, l := range lines {
		after, found := strings.CutPrefix(l, "250-ServiceID=")
		if !found {
			after, found = strings.CutPrefix(l, "250 ServiceID=")
		}
		if found {
			tc.onionID = strings.TrimSpace(after)
		}
	}
	return nil
}

// delOnion removes the hidden service created by addOnion.
func (tc *torControl) delOnion() error {
	if tc.onionID == "" {
		return nil
	}
	_, err := tc.sendCmd("DEL_ONION " + tc.onionID)
	return err
}

// expandEd25519PrivateKey converts a Go ed25519.PrivateKey (64 bytes: seed||pubkey)
// to the 64-byte "expanded scalar" form Tor's ADD_ONION ED25519-V3 requires.
//
// Tor expects: SHA-512(seed)[0:32] with RFC 8032 clamping || SHA-512(seed)[32:64]
func expandEd25519PrivateKey(priv []byte) []byte {
	seed := priv[:32] // first 32 bytes of Go's ed25519.PrivateKey are the seed
	h := sha512.Sum512(seed)
	exp := make([]byte, 64)
	copy(exp, h[:])
	exp[0] &= 248
	exp[31] &= 127
	exp[31] |= 64
	return exp
}

// normalizeTorControlAddr ensures the address has a port, defaulting to 9051.
func normalizeTorControlAddr(addr string) string {
	if strings.Contains(addr, ":") {
		return addr
	}
	return net.JoinHostPort(addr, "9051")
}
