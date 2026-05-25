package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

type peerUAPI struct {
	pubHex       string
	endpoint     string
	allowedIPs   []string
	hsSec        int64
	hsNSec       int64
	keepaliveSec int
}

func parseWGUAPI(uapi string) map[string]*peerUAPI {
	peers := map[string]*peerUAPI{}
	var cur *peerUAPI

	lines := strings.Split(uapi, "\n")
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		k, v, ok := strings.Cut(ln, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			v = strings.TrimSpace(v)
			cur = &peerUAPI{pubHex: v}
			peers[v] = cur
		case "endpoint":
			if cur != nil {
				cur.endpoint = strings.TrimSpace(v)
			}
		case "allowed_ip":
			if cur != nil {
				cur.allowedIPs = append(cur.allowedIPs, strings.TrimSpace(v))
			}
		case "last_handshake_time_sec":
			if cur != nil {
				if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
					cur.hsSec = n
				}
			}
		case "last_handshake_time_nsec":
			if cur != nil {
				if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
					cur.hsNSec = n
				}
			}
		case "persistent_keepalive_interval":
			if cur != nil {
				if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
					cur.keepaliveSec = n
				}
			}
		}
	}
	return peers
}

func shortHexPub(pubHex string) string {
	if len(pubHex) <= 10 {
		return pubHex
	}
	return pubHex[:4] + "…" + pubHex[len(pubHex)-4:]
}

func startUAPI(wgDev *device.Device, iface string) {
	dir := "/var/run/wireguard"
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Fatalf("UAPI mkdir failed: %v", err)
	}

	sockPath := filepath.Join(dir, iface+".sock")
	_ = os.Remove(sockPath)

	addr := &net.UnixAddr{Name: sockPath, Net: "unix"}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		log.Fatalf("UAPI listen failed path=%s err=%v", sockPath, err)
	}

	if err := os.Chmod(sockPath, 0600); err != nil {
		log.Printf("UAPI chmod failed: %v", err)
	}

	log.Printf("UAPI socket listening: %s", sockPath)

	go func() {
		for {
			c, err := ln.AcceptUnix()
			if err != nil {
				log.Printf("UAPI accept failed: %v", err)
				return
			}
			go wgDev.IpcHandle(c)
		}
	}()
}

func startWGHandshakeWatcher(wgDev *device.Device) {
	go func() {
		last := map[string]int64{}
		t := time.NewTicker(1 * time.Second)
		defer t.Stop()

		for range t.C {
			uapi, err := wgDev.IpcGet()
			if err != nil {
				continue
			}
			peers := parseWGUAPI(uapi)

			for pubHex, p := range peers {
				prev := last[pubHex]
				now := p.hsSec
				if now == 0 {
					continue
				}
				if prev == 0 || now > prev {
					log.Printf("WG handshake ok peer=%s endpoint=%s allowed=%s hs=%d",
						shortHexPub(pubHex),
						or(p.endpoint, "none"),
						or(strings.Join(p.allowedIPs, ","), "none"),
						now,
					)
				}
				last[pubHex] = now
			}
		}
	}()
}

func readWGConf(iface string) (privKey string, addrCIDR string, err error) {
	path := "/etc/wireguard/" + iface + ".conf"
	f, err := os.Open(path)
	if err != nil {
		return "", "", fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	inInterface := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sec := strings.ToLower(strings.Trim(line, "[]"))
			inInterface = sec == "interface"
			continue
		}
		if !inInterface {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)

		if k == "privatekey" && privKey == "" {
			privKey = v
		}
		if k == "address" && addrCIDR == "" {
			for _, part := range strings.Split(v, ",") {
				p := strings.TrimSpace(part)
				if validAllowedIP(p) {
					addrCIDR = p
					break
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return "", "", err
	}
	return privKey, addrCIDR, nil
}

func pubFromPriv(priv string) (string, error) {
	priv = strings.TrimSpace(priv)
	if priv == "" {
		return "", errors.New("empty private key")
	}
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(priv + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("wg pubkey failed: %v output=%s", err, strings.TrimSpace(string(out)))
	}
	pub := strings.TrimSpace(string(out))
	if !validWgPubkey(pub) {
		return "", fmt.Errorf("derived public key invalid")
	}
	return pub, nil
}

func ensureLinkUp(iface string) {
	_, _ = execTimeout(2*time.Second, "ip", "link", "set", "dev", iface, "up")
}

func ensureAddress(iface, cidr string) {
	if strings.TrimSpace(cidr) == "" {
		return
	}
	ipver := "-4"
	if strings.Contains(cidr, ":") {
		ipver = "-6"
	}
	out, err := execTimeout(2*time.Second, "ip", ipver, "addr", "show", "dev", iface)
	if err == nil && strings.Contains(out, strings.SplitN(cidr, "/", 2)[0]) {
		return
	}
	_, _ = execTimeout(2*time.Second, "ip", "addr", "add", cidr, "dev", iface)
}

func wgPrivB64ToHex(privB64 string) (string, error) {
	privB64 = strings.TrimSpace(privB64)
	if privB64 == "" {
		return "", errors.New("empty private key")
	}
	raw, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(privB64)
		if err != nil {
			return "", fmt.Errorf("private key not base64: %w", err)
		}
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("private key decoded len=%d want 32", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

func wgPubB64ToHex(pubB64 string) (string, error) {
	pubB64 = strings.TrimSpace(pubB64)
	if pubB64 == "" {
		return "", errors.New("empty public key")
	}
	raw, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(pubB64)
		if err != nil {
			return "", fmt.Errorf("public key not base64: %w", err)
		}
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("public key decoded len=%d want 32", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

func wgUpsertPeer(dev *device.Device, pubKeyB64, allowedIP, endpoint string) error {
	pubHex, err := wgPubB64ToHex(pubKeyB64)
	if err != nil {
		return err
	}

	allowedIP = strings.TrimSpace(allowedIP)
	if !validAllowedIP(allowedIP) {
		return fmt.Errorf("invalid allowed ip: %s", allowedIP)
	}

	endpoint = strings.TrimSpace(endpoint)
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil || !validIPv4(host) {
		return errors.New("invalid endpoint")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("invalid endpoint port")
	}

	cfg := fmt.Sprintf(
		"public_key=%s\n"+
			"replace_allowed_ips=true\n"+
			"allowed_ip=%s\n"+
			"endpoint=%s\n"+
			"persistent_keepalive_interval=25\n",
		pubHex,
		allowedIP,
		endpoint,
	)
	return dev.IpcSet(cfg)
}
