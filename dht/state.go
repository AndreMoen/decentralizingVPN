package main

import (
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

type pendingState struct {
	SID       string
	FirstSend time.Time
	Remote    *payload
}

type endpointMeta struct {
	Addr        *net.UDPAddr
	IP          netip.Addr
	Port        uint16
	LastSeen    time.Time
	LastSuccess time.Time
	FailCount   int
}

type peerState struct {
	PubKey     string
	AllowedIP  string
	Candidates map[string]*endpointMeta
	Active     string
}

type netState struct {
	mu sync.Mutex

	peersByPub map[string]*peerState

	pendingByEndpoint map[string]*pendingState
	confirmedEndpoint map[string]bool
	triedByEndpoint   map[string]bool
}

func newNetState() *netState {
	return &netState{
		peersByPub:        map[string]*peerState{},
		pendingByEndpoint: map[string]*pendingState{},
		confirmedEndpoint: map[string]bool{},
		triedByEndpoint:   map[string]bool{},
	}
}

const endpointFailoverAfter = 45 * time.Second

func udpAddrKey(a *net.UDPAddr) (string, *endpointMeta, bool) {
	if a == nil || a.IP == nil {
		return "", nil, false
	}
	ip4 := a.IP.To4()
	if ip4 == nil {
		return "", nil, false
	}
	ip, ok := netip.AddrFromSlice(ip4)
	if !ok {
		return "", nil, false
	}
	if a.Port < 1 || a.Port > 65535 {
		return "", nil, false
	}
	key := net.JoinHostPort(ip.String(), strconv.Itoa(a.Port))
	em := &endpointMeta{
		Addr:     &net.UDPAddr{IP: ip4, Port: a.Port},
		IP:       ip,
		Port:     uint16(a.Port),
		LastSeen: time.Now(),
	}
	return key, em, true
}

func (ns *netState) getOrCreatePeer(pub, allowed string) *peerState {
	p := ns.peersByPub[pub]
	if p == nil {
		p = &peerState{
			PubKey:     pub,
			AllowedIP:  allowed,
			Candidates: map[string]*endpointMeta{},
		}
		ns.peersByPub[pub] = p
	}
	if p.AllowedIP == "" && allowed != "" {
		p.AllowedIP = allowed
	}
	return p
}

func (ns *netState) addCandidate(pub string, allowed string, key string, em *endpointMeta) {
	p := ns.getOrCreatePeer(pub, allowed)
	ex := p.Candidates[key]
	if ex == nil {
		p.Candidates[key] = em
		return
	}
	ex.LastSeen = time.Now()
	ex.Addr = em.Addr
	ex.IP = em.IP
	ex.Port = em.Port
}

func (ns *netState) bestCandidateKey(p *peerState) string {
	bestKey := ""
	bestScore := -1
	now := time.Now()

	for k, em := range p.Candidates {
		score := 0

		if !em.LastSuccess.IsZero() {
			age := now.Sub(em.LastSuccess)
			if age < 30*time.Second {
				score += 50
			} else if age < 2*time.Minute {
				score += 10
			}
		}

		score -= em.FailCount * 20

		if score > bestScore {
			bestScore = score
			bestKey = k
		}
	}

	return bestKey
}

func (ns *netState) shouldSwitchEndpoint(p *peerState, newKey string) bool {
	if newKey == "" {
		return false
	}
	if p.Active == "" {
		return true
	}
	if p.Active == newKey {
		return false
	}

	cur := p.Candidates[p.Active]
	nw := p.Candidates[newKey]
	if nw == nil {
		return false
	}
	if cur == nil {
		return true
	}

	if cur.LastSuccess.IsZero() {
		return true
	}
	if time.Since(cur.LastSuccess) > endpointFailoverAfter {
		return true
	}

	return false
}

func (ns *netState) markSuccess(pub string, endpointKey string) {
	p := ns.peersByPub[pub]
	if p == nil {
		return
	}
	em := p.Candidates[endpointKey]
	if em == nil {
		return
	}
	em.LastSuccess = time.Now()
	em.FailCount = 0
}
