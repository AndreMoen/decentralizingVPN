package main

import (
	"sync"
)

// netState tracks which peers we have already configured in WireGuard,
// keyed by WireGuard public key. This prevents redundant IpcSet calls
// when the same peer appears in successive registry polls.
type netState struct {
	mu              sync.Mutex
	configuredPeers map[string]string // pubkey → current endpoint
}

func newNetState() *netState {
	return &netState{
		configuredPeers: make(map[string]string),
	}
}

// markConfigured records that a peer has been configured with the given endpoint.
func (ns *netState) markConfigured(pubKey, endpoint string) {
	ns.mu.Lock()
	ns.configuredPeers[pubKey] = endpoint
	ns.mu.Unlock()
}

// isConfigured returns the currently configured endpoint for a pubkey,
// or ("", false) if not yet configured.
func (ns *netState) isConfigured(pubKey string) (string, bool) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ep, ok := ns.configuredPeers[pubKey]
	return ep, ok
}
