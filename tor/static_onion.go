package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	torSecretHeader = "== ed25519v1-secret: type0 =="
	torPublicHeader = "== ed25519v1-public: type0 =="
)

// staticOnionProcess manages a dedicated tor instance that serves a disk-backed,
// deterministic single-onion hidden service. It is separate from the normal
// client tor instance used for SOCKS traffic.
type staticOnionProcess struct {
	mu          sync.Mutex
	cmd         *exec.Cmd
	startedByUs bool
	controlAddr string
	dataDir     string
	serviceDir  string
	torrcPath   string
	targetAddr  string
}

func newStaticOnionProcess(groupOnion string) *staticOnionProcess {
	root := strings.TrimSpace(os.Getenv("TOR_SERVER_DATA_ROOT"))
	if root == "" {
		root = filepath.Join(os.TempDir(), "torpunch-onion")
	}
	controlAddr := getEnvTrim("TOR_SERVER_CONTROL", "127.0.0.1:9053")
	targetAddr := getEnvTrim("TOR_SERVER_TARGET", "127.0.0.1:18080")
	instanceDir := filepath.Join(root, strings.TrimSuffix(groupOnion, ".onion"))
	return &staticOnionProcess{
		controlAddr: normalizeTorControlAddr(controlAddr),
		dataDir:     instanceDir,
		serviceDir:  filepath.Join(instanceDir, "service"),
		torrcPath:   filepath.Join(instanceDir, "torrc"),
		targetAddr:  targetAddr,
	}
}

func (s *staticOnionProcess) ensureRunning(ctx context.Context, groupOnion string, privKey ed25519.PrivateKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.prepareServiceDir(groupOnion, privKey); err != nil {
		return err
	}
	if err := s.writeTorrc(); err != nil {
		return err
	}

	// Kill any leftover tor process from a previous run that may be holding
	// the control port without actually serving the onion.
	if canDialTCP(s.controlAddr, 300*time.Millisecond) {
		log.Printf("[onion-server] port %s already in use, killing leftover process", s.controlAddr)
		_ = exec.Command("pkill", "-f", s.torrcPath).Run()
		time.Sleep(500 * time.Millisecond)
	}

	torBin := getEnvTrim("TOR_SERVER_BINARY", "tor")
	cmd := exec.Command(torBin, "-f", s.torrcPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start dedicated onion tor: %w", err)
	}

	s.cmd = cmd
	s.startedByUs = true

	exitCh := make(chan error, 1)
	go func() { exitCh <- cmd.Wait() }()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-exitCh:
			return fmt.Errorf("dedicated onion tor exited early: %w", err)
		default:
		}
		if canDialTCP(s.controlAddr, 300*time.Millisecond) {
			if b, err := os.ReadFile(filepath.Join(s.serviceDir, "hostname")); err == nil {
				hostname := strings.TrimSpace(string(b))
				if hostname == groupOnion {
					return nil
				}
				return fmt.Errorf("hostname mismatch: expected %s got %s", groupOnion, hostname)
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("dedicated onion tor did not become ready in time")
}

func (s *staticOnionProcess) shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd == nil || !s.startedByUs || s.cmd.Process == nil {
		return
	}
	_ = s.cmd.Process.Kill()
	_, _ = s.cmd.Process.Wait()
	s.cmd = nil
	s.startedByUs = false
}

func (s *staticOnionProcess) prepareServiceDir(groupOnion string, privKey ed25519.PrivateKey) error {
	if err := os.MkdirAll(s.serviceDir, 0o700); err != nil {
		return fmt.Errorf("mkdir service dir: %w", err)
	}
	if err := os.Chmod(s.dataDir, 0o700); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Chmod(s.serviceDir, 0o700); err != nil {
		return err
	}

	// Remove stale key files so Tor picks up the freshly written ones.
	for _, f := range []string{"hs_ed25519_secret_key", "hs_ed25519_public_key", "hostname"} {
		_ = os.Remove(filepath.Join(s.serviceDir, f))
	}

	pubKey := privKey.Public().(ed25519.PublicKey)
	expandedKey := expandEd25519PrivateKey([]byte(privKey))
	padding := []byte{0, 0, 0}
	secretBytes := append(append([]byte{}, []byte(torSecretHeader)...), padding...)
	secretBytes = append(secretBytes, expandedKey...)
	publicBytes := append(append([]byte{}, []byte(torPublicHeader)...), padding...)
	publicBytes = append(publicBytes, []byte(pubKey)...)

	if err := os.WriteFile(filepath.Join(s.serviceDir, "hs_ed25519_secret_key"), secretBytes, 0o600); err != nil {
		return fmt.Errorf("write hidden-service secret key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(s.serviceDir, "hs_ed25519_public_key"), publicBytes, 0o600); err != nil {
		return fmt.Errorf("write hidden-service public key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(s.serviceDir, "hostname"), []byte(groupOnion+"\n"), 0o600); err != nil {
		return fmt.Errorf("write hidden-service hostname: %w", err)
	}
	return nil
}

func (s *staticOnionProcess) writeTorrc() error {
	controlHost, controlPort, err := net.SplitHostPort(s.controlAddr)
	if err != nil {
		return fmt.Errorf("split control addr: %w", err)
	}
	if controlHost == "" {
		controlHost = "127.0.0.1"
	}
	// Tor ControlPort only takes the port number in the common case. Bind to loopback explicitly.
	targetHost, targetPort, err := net.SplitHostPort(s.targetAddr)
	if err != nil {
		return fmt.Errorf("split target addr: %w", err)
	}
	_ = targetHost
	_ = controlHost
	torrc := fmt.Sprintf(`SocksPort 0
ControlPort %s
CookieAuthentication 0
DataDirectory %s

HiddenServiceNonAnonymousMode 1
HiddenServiceSingleHopMode 1

HiddenServiceDir %s
HiddenServicePort 80 %s
`, controlPort, s.dataDir, s.serviceDir, net.JoinHostPort("127.0.0.1", targetPort))
	if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
		return fmt.Errorf("mkdir data dir: %w", err)
	}
	if err := os.WriteFile(s.torrcPath, []byte(torrc), 0o600); err != nil {
		return fmt.Errorf("write torrc: %w", err)
	}
	return nil
}

func canDialTCP(addr string, timeout time.Duration) bool {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
