package main

import (
	"sync"
)

// netState tracks which WireGuard peers have already been configured so we
// avoid reconfiguring them on every repeated Nostr event.
type netState struct {
	mu         sync.Mutex
	configured map[string]string // wgPub -> current endpoint
}

func newNetState() *netState {
	return &netState{
		configured: make(map[string]string),
	}
}

// isConfigured returns the current endpoint for a peer if one has been set.
func (ns *netState) isConfigured(wgPub string) (string, bool) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ep, ok := ns.configured[wgPub]
	return ep, ok
}

// markConfigured records that a peer has been successfully configured with an
// endpoint. If the endpoint differs from the previous one (e.g. after a STUN
// address change) the peer is re-configured.
func (ns *netState) markConfigured(wgPub, endpoint string) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.configured[wgPub] = endpoint
}
