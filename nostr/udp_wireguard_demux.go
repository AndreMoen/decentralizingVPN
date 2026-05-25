package main

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

func looksLikeWireGuard(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	t := binary.LittleEndian.Uint32(b[:4])
	switch t {
	case 1:
		return len(b) >= 148
	case 2:
		return len(b) >= 92
	case 3:
		return len(b) >= 64
	case 4:
		return len(b) >= 32
	default:
		return false
	}
}

type demuxPkt struct {
	b    []byte
	addr net.Addr
}

type demuxConn struct {
	udp  *net.UDPConn
	rx   chan demuxPkt
	done chan struct{}
}

func newDemuxConn(udp *net.UDPConn) *demuxConn {
	return &demuxConn{
		udp:  udp,
		rx:   make(chan demuxPkt, 4096),
		done: make(chan struct{}),
	}
}

func (d *demuxConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt := <-d.rx:
		n := copy(p, pkt.b)
		return n, pkt.addr, nil
	case <-d.done:
		return 0, nil, net.ErrClosed
	}
}

func (d *demuxConn) WriteTo(p []byte, addr net.Addr) (int, error) { return d.udp.WriteTo(p, addr) }

func (d *demuxConn) Close() error {
	select {
	case <-d.done:
	default:
		close(d.done)
	}
	return nil
}

func (d *demuxConn) LocalAddr() net.Addr                { return d.udp.LocalAddr() }
func (d *demuxConn) SetDeadline(t time.Time) error      { return nil }
func (d *demuxConn) SetReadDeadline(t time.Time) error  { return nil }
func (d *demuxConn) SetWriteDeadline(t time.Time) error { return nil }

type wgPkt struct {
	b  []byte
	ep conn.Endpoint
}

type udpEndpoint struct {
	addr *net.UDPAddr
	ip   netip.Addr
}

func newUDPEndpoint(a *net.UDPAddr) (*udpEndpoint, error) {
	if a == nil || a.IP == nil {
		return nil, errors.New("nil udp addr")
	}
	ip4 := a.IP.To4()
	if ip4 == nil {
		return nil, errors.New("not ipv4")
	}
	ip, ok := netip.AddrFromSlice(ip4)
	if !ok {
		return nil, errors.New("bad ip")
	}
	if a.Port < 1 || a.Port > 65535 {
		return nil, errors.New("bad port")
	}
	return &udpEndpoint{addr: a, ip: ip}, nil
}

func (e *udpEndpoint) ClearSrc()           {}
func (e *udpEndpoint) SrcToString() string { return "" }
func (e *udpEndpoint) DstToString() string { return e.addr.String() }
func (e *udpEndpoint) DstIP() netip.Addr   { return e.ip }
func (e *udpEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *udpEndpoint) DstToBytes() []byte {
	b := make([]byte, 18)
	ip16 := e.ip.As16()
	copy(b[:16], ip16[:])
	binary.BigEndian.PutUint16(b[16:], uint16(e.addr.Port))
	return b
}
func (e *udpEndpoint) SrcToBytes() []byte { return nil }

type sharedWGBind struct {
	udp    *net.UDPConn
	rx     chan wgPkt
	closed chan struct{}
	mu     sync.Mutex
}

func newSharedWGBind(udp *net.UDPConn) *sharedWGBind {
	return &sharedWGBind{
		udp:    udp,
		rx:     make(chan wgPkt, 4096),
		closed: make(chan struct{}),
	}
}

func (b *sharedWGBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	select {
	case <-b.closed:
		b.closed = make(chan struct{})
	default:
	}
	b.mu.Unlock()

	la, ok := b.udp.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, 0, errors.New("localaddr not udp")
	}
	actual := uint16(la.Port)

	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case <-b.closed:
			return 0, net.ErrClosed
		case pkt, ok := <-b.rx:
			if !ok {
				return 0, net.ErrClosed
			}
			if len(packets) == 0 || len(sizes) == 0 || len(eps) == 0 {
				return 0, errors.New("wireguard recv buffers empty")
			}
			n := copy(packets[0], pkt.b)
			sizes[0] = n
			eps[0] = pkt.ep
			return 1, nil
		}
	}

	return []conn.ReceiveFunc{recv}, actual, nil
}

func (b *sharedWGBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	select {
	case <-b.closed:
	default:
		close(b.closed)
	}
	return nil
}

func (b *sharedWGBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	uep, ok := ep.(*udpEndpoint)
	if !ok || uep.addr == nil {
		return errors.New("wrong endpoint type")
	}
	for _, p := range bufs {
		_, err := b.udp.WriteToUDP(p, uep.addr)
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *sharedWGBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	addr, err := net.ResolveUDPAddr("udp4", s)
	if err != nil {
		return nil, err
	}
	ep, err := newUDPEndpoint(addr)
	if err != nil {
		return nil, err
	}
	return ep, nil
}

func (b *sharedWGBind) BatchSize() int            { return 1 }
func (b *sharedWGBind) SetMark(mark uint32) error { return nil }


