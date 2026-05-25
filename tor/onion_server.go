package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// peerRegistry is an in-memory store keyed by "ip:port".
type peerRegistry struct {
	mu       sync.Mutex
	entries  map[string]registryEntry
	ttl      time.Duration
	localURL string // set when this peer is the server, e.g. "http://127.0.0.1:40001"
}

type registryEntry struct {
	peer      torPeer
	expiresAt time.Time
}

func newPeerRegistry(ttl time.Duration) *peerRegistry {
	r := &peerRegistry{
		entries: make(map[string]registryEntry),
		ttl:     ttl,
	}
	go r.expireLoop()
	return r
}

func (r *peerRegistry) upsert(p torPeer) {
	key := net.JoinHostPort(p.IP, fmt.Sprintf("%d", p.Port))
	r.mu.Lock()
	r.entries[key] = registryEntry{peer: p, expiresAt: time.Now().Add(r.ttl)}
	r.mu.Unlock()
}

func (r *peerRegistry) list() []torPeer {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]torPeer, 0, len(r.entries))
	for _, e := range r.entries {
		if e.expiresAt.After(now) {
			out = append(out, e.peer)
		}
	}
	return out
}

func (r *peerRegistry) expireLoop() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		r.mu.Lock()
		for k, e := range r.entries {
			if !e.expiresAt.After(now) {
				delete(r.entries, k)
			}
		}
		r.mu.Unlock()
	}
}

// newRegistryHandler returns an http.ServeMux handling /register and /participants.
func newRegistryHandler(reg *peerRegistry) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var p torPeer
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if net.ParseIP(p.IP) == nil || p.Port < 1 || p.Port > 65535 || p.WgPub == "" {
			http.Error(w, "missing or invalid fields", http.StatusBadRequest)
			return
		}
		reg.upsert(p)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})

	mux.HandleFunc("/participants", func(w http.ResponseWriter, r *http.Request) {
		peers := reg.list()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(peers)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	return mux
}

// becomeOnionServer attempts to start the group hidden service on this peer.
// It is called both at startup and during failover when the current server
// goes away. Returns true if this peer successfully became the server.
//
// It first probes the onion — if it's reachable, someone else is already
// serving and we return false immediately. Only if the onion is unreachable
// do we attempt ADD_ONION.
func becomeOnionServer(
	ctx context.Context,
	torSocks string,
	groupOnionURL string,
	groupOnion string,
	privKey ed25519.PrivateKey,
	reg *peerRegistry,
	service *staticOnionProcess,
) bool {
	// Always ensure the spawned tor process is cleaned up on exit.
	go func() {
		<-ctx.Done()
		service.shutdown()
	}()

	// Probe with retries before deciding to become the server.
	// A freshly started onion takes up to 60s to become reachable — without
	// retries all peers race to become the server simultaneously.
	log.Printf("[onion-server] probing %s (up to 6 attempts)...", groupOnionURL)
	if probeOnionWithRetry(ctx, torSocks, groupOnionURL, 1, 3*time.Second) {
		log.Printf("[onion-server] onion already reachable — staying as client")
		return false
	}
	if ctx.Err() != nil {
		return false
	}

	// Bind the fixed local registry address that the dedicated onion tor maps to.
	ln, err := net.Listen("tcp", service.targetAddr)
	if err != nil {
		log.Printf("[onion-server] local listen on %s failed: %v", service.targetAddr, err)
		return false
	}

	httpSrv := &http.Server{Handler: newRegistryHandler(reg)}
	go func() {
		if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("[onion-server] http error: %v", err)
		}
	}()

	if err := service.ensureRunning(ctx, groupOnion, privKey); err != nil {
		log.Printf("[onion-server] static onion startup failed: %v", err)
		_ = httpSrv.Close()
		service.shutdown()
		return false
	}

	log.Printf("[onion-server] became group onion server via static single-hop tor service (%s -> %s)", groupOnion, service.targetAddr)
	reg.mu.Lock()
	reg.localURL = "http://" + service.targetAddr
	reg.mu.Unlock()

	go func() {
		<-ctx.Done()
		log.Printf("[onion-server] tearing down local registry server")
		reg.mu.Lock()
		reg.localURL = ""
		reg.mu.Unlock()
		_ = httpSrv.Close()
		// service.shutdown() is handled by the top-level ctx goroutine above
	}()

	return true
}

// probeOnion does a single GET / through the Tor SOCKS proxy and returns true
// if it gets a 200 back.
func probeOnion(torSocks, onionURL string) bool {
	client, err := newTorHTTPClient(torSocks)
	if err != nil {
		return false
	}
	client.Timeout = 20 * time.Second
	resp, err := client.Get(onionURL + "/")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// probeOnionWithRetry probes the onion multiple times with delays before
// giving up. This is important at startup: a freshly started onion service
// can take 30-60s to become reachable through the Tor network even after
// the tor process has fully bootstrapped. Without retries, all peers probe
// simultaneously, all get "unreachable", and all try to become the server.
func probeOnionWithRetry(ctx context.Context, torSocks, onionURL string, attempts int, interval time.Duration) bool {
	for i := 0; i < attempts; i++ {
		if probeOnion(torSocks, onionURL) {
			return true
		}
		if i < attempts-1 {
			log.Printf("[onion-server] probe attempt %d/%d failed, retrying in %s...", i+1, attempts, interval)
			select {
			case <-ctx.Done():
				return false
			case <-time.After(interval):
			}
		}
	}
	return false
}

// tryStartGroupOnionServer is called at startup to attempt becoming the server.
func tryStartGroupOnionServer(
	ctx context.Context,
	torSocks string,
	groupOnionURL string,
	groupOnion string,
	privKey ed25519.PrivateKey,
	reg *peerRegistry,
	service *staticOnionProcess,
) {
	becomeOnionServer(ctx, torSocks, groupOnionURL, groupOnion, privKey, reg, service)
}
