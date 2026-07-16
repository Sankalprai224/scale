package vpn

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"golang.zx2c4.com/wireguard/conn"
)

const Stunbyte uint32 = 0x2112A442
const MagicProbeSig uint32 = 0xFF505242

// HybridBind handles BOTH UDP (P2P) and WebSocket (Relay)
type HybridBind struct {
	udpConn      *net.UDPConn
	wsConn       *websocket.Conn
	wsLock       sync.Mutex
	rxChan       chan Packet
	ControlChan  chan Packet
	StunRxChan   chan Packet
	udpFailCount int
	failLock     sync.Mutex
	IpMap        map[string]*net.UDPAddr
	mapLock      sync.Mutex
	lastPongTime time.Time
	pongLock     sync.Mutex
	myPubKey     [32]byte
	rxDropCount  int64

	closeChan chan struct{}
	isClosed  bool
	mu        sync.Mutex

	UpdatePeerEndpoint func(peerKeyHex string, newAddr *net.UDPAddr)
}

type Packet struct {
	Data     []byte
	Endpoint conn.Endpoint
}

func NewHybridBind(listenPort int, relayURL string, myPubKey string) (*HybridBind, error) {
	b := &HybridBind{
		rxChan:      make(chan Packet, 1024),
		ControlChan: make(chan Packet, 1024),
		StunRxChan:  make(chan Packet, 1024),
		IpMap:       make(map[string]*net.UDPAddr),
		closeChan:   make(chan struct{}),
	}

	// 1. Setup UDP
	addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", listenPort))
	udp, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind UDP: %w", err)
	}
	b.udpConn = udp

	// 2. Setup WebSocket
	//ws, _, err := websocket.DefaultDialer.Dial(relayURL, nil)

	keyBytes, hexErr := hex.DecodeString(myPubKey)
	if hexErr != nil {
		b.udpConn.Close()
		return nil, fmt.Errorf("invalid myPubKey hex: %w", hexErr)
	}
	if len(keyBytes) != 32 {
		b.udpConn.Close()
		return nil, fmt.Errorf("myPubKey must be exactly 32 bytes, got %d", len(keyBytes))
	}
	b.myPubKey = [32]byte(keyBytes)

	// 2. Setup WebSocket
	dialer := *websocket.DefaultDialer
	dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	ws, _, err := dialer.Dial(relayURL, nil)
	if err == nil {
		b.wsConn = ws
		ws.WriteMessage(websocket.BinaryMessage, keyBytes)
		go b.readWS()
	} else {
		fmt.Printf("Warning: Could not connect to Relay: %v. Running in UDP-only mode.\n", err)
	}

	go b.readUDP()
	return b, nil
}

func (b *HybridBind) RunControlLoop() {

	for pkt := range b.ControlChan {

		if VerifyStun(pkt.Data) {
			select {
			case b.StunRxChan <- pkt:

			default:
			}
			continue
		}
		peerKey, valid := VerifyProbe(pkt.Data)
		if !valid {
			continue
		}

		b.pongLock.Lock()
		b.lastPongTime = time.Now()
		b.pongLock.Unlock()

		b.failLock.Lock()
		b.udpFailCount = 0
		b.failLock.Unlock()

		newAddress := pkt.Endpoint.(*UDPEndpoint).Addr

		addressChanged := false

		b.mapLock.Lock()
		oldAddress := b.IpMap[peerKey]

		if oldAddress == nil || oldAddress.String() != newAddress.String() {
			b.IpMap[peerKey] = newAddress
			addressChanged = true
		}
		b.mapLock.Unlock()

		if valid && b.UpdatePeerEndpoint != nil && addressChanged {
			fmt.Printf("peer %s is roaming on new address: %s/n", peerKey, newAddress.String())
			b.UpdatePeerEndpoint(peerKey, newAddress)
		}

	}

}

func (b *HybridBind) readUDP() {
	buf := make([]byte, 2048)
	for {
		n, addr, err := b.udpConn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		if VerifyWgpkt(pkt) {
			select {
			case b.rxChan <- Packet{Data: pkt, Endpoint: &UDPEndpoint{Addr: addr}}:
			default:
				atomic.AddInt64(&b.rxDropCount, 1)
			}
		} else {
			select {
			case b.ControlChan <- Packet{Data: pkt, Endpoint: &UDPEndpoint{Addr: addr}}:
			default:
			}
		}
	}
}

func (b *HybridBind) readWS() {
	for {
		_, msg, err := b.wsConn.ReadMessage()
		if err != nil {
			break
		}
		if len(msg) > 32 {
			senderKey := msg[:32]
			data := msg[32:]
			var key [32]byte
			copy(key[:], senderKey)
			select {
			case b.rxChan <- Packet{Data: data, Endpoint: &RelayEndpoint{Key: key}}:
			default:
				atomic.AddInt64(&b.rxDropCount, 1)
			}
		}
	}
}

func (b *HybridBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	// 1. Try UDP
	if addr, err := net.ResolveUDPAddr("udp", s); err == nil && addr.Port != 0 {
		return &UDPEndpoint{Addr: addr}, nil
	}

	// 2. Try Relay Key (Hex)
	keyBytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint: %v", err)
	}
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("invalid key length: %d", len(keyBytes))
	}
	var key [32]byte
	copy(key[:], keyBytes)
	return &RelayEndpoint{Key: key}, nil
}

func (b *HybridBind) Send(packets [][]byte, ep conn.Endpoint) error {
	if udpEp, ok := ep.(*UDPEndpoint); ok {
		var errs []error
		for _, pkt := range packets {
			n, err := b.udpConn.WriteToUDP(pkt, udpEp.Addr)
			if err != nil {
				fmt.Printf("udp packets dropped , error : %s, %v, packets count : %d", udpEp.Addr, err, n)
				errs = append(errs, err)
			}
		}
		if len(errs) > 0 {
			b.failLock.Lock()
			b.udpFailCount += len(errs)
			b.failLock.Unlock()
			return fmt.Errorf("udp send had %d faliures : %v", len(errs), errs[0])
		}
		b.failLock.Lock()
		b.udpFailCount = 0
		b.failLock.Unlock()
		return nil
	}
	if relayEp, ok := ep.(*RelayEndpoint); ok {
		if b.wsConn == nil {
			return fmt.Errorf("relay send failed: wsConn is nil, peer key: %s", hex.EncodeToString(relayEp.Key[:]))
		}
		b.wsLock.Lock()
		defer b.wsLock.Unlock()
		for _, pkt := range packets {
			frame := append(relayEp.Key[:], pkt...)
			b.wsConn.WriteMessage(websocket.BinaryMessage, frame)
		}
		return nil
	}

	return fmt.Errorf("unknown endpoint type: %T", ep)
}

func (b *HybridBind) Receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	select {
	case <-b.closeChan:
		return 0, errors.New("closed")
	case p, ok := <-b.rxChan:
		if !ok {
			return 0, errors.New("closed")
		}
		n := copy(packets[0], p.Data)
		sizes[0] = n
		eps[0] = p.Endpoint
		return 1, nil
	}
}

func (b *HybridBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	if b.isClosed {
		b.closeChan = make(chan struct{})
		b.isClosed = false
	}
	b.mu.Unlock()
	return []conn.ReceiveFunc{b.Receive}, uint16(b.udpConn.LocalAddr().(*net.UDPAddr).Port), nil
}
func (b *HybridBind) BatchSize() int       { return 1 }
func (b *HybridBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.isClosed {
		close(b.closeChan)
		b.isClosed = true
	}
	return nil
}

func (b *HybridBind) Shutdown() {
	b.Close()
	if b.udpConn != nil {
		b.udpConn.Close()
	}
	b.wsLock.Lock()
	if b.wsConn != nil {
		b.wsConn.Close()
	}
	b.wsLock.Unlock()
}
func (b *HybridBind) SetMark(uint32) error { return nil }

// --- UPDATED ENDPOINT IMPLEMENTATION ---

type UDPEndpoint struct{ Addr *net.UDPAddr }

func (e *UDPEndpoint) DstToString() string { return e.Addr.String() }
func (e *UDPEndpoint) DstIP() netip.Addr {
	// Convert net.IP to netip.Addr
	addr, _ := netip.AddrFromSlice(e.Addr.IP)
	return addr
}
func (e *UDPEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *UDPEndpoint) SrcToString() string { return "" }
func (e *UDPEndpoint) ClearSrc()           {}
func (e *UDPEndpoint) DstToBytes() []byte  { return e.Addr.IP } // Added: Required by interface

type RelayEndpoint struct{ Key [32]byte }

func (e *RelayEndpoint) DstToString() string { return hex.EncodeToString(e.Key[:]) }
func (e *RelayEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (e *RelayEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *RelayEndpoint) SrcToString() string { return "relay" }
func (e *RelayEndpoint) ClearSrc()           {}
func (e *RelayEndpoint) DstToBytes() []byte  { return e.Key[:] } // Added: Required by interface

func (b *HybridBind) SendRaw(data []byte, addr *net.UDPAddr) error {

	_, err := b.udpConn.WriteToUDP(data, addr)
	return err

}

func VerifyWgpkt(pkt []byte) bool {

	if len(pkt) < 1 {
		return false
	}

	return pkt[0] >= 1 && pkt[0] <= 4
}

func VerifyStun(pkt []byte) bool {

	if len(pkt) < 8 {
		return false
	}

	magicBytes := pkt[4:8]

	magic := binary.BigEndian.Uint32(magicBytes)
	// not able to do this then throw error

	return magic == Stunbyte
}

func VerifyProbe(pkt []byte) (string, bool) {

	if len(pkt) < 36 {
		return "", false
	}

	magic := binary.BigEndian.Uint32(pkt[:4])
	if magic != MagicProbeSig {
		return "", false
	}

	peerKeybytes := pkt[4:36]
	peerKeyHex := hex.EncodeToString(peerKeybytes)

	return peerKeyHex, true
}

const threshold = 5

func (b *HybridBind) IsUdpDead() bool {
	b.failLock.Lock()
	defer b.failLock.Unlock()
	return b.udpFailCount >= threshold
}

func (b *HybridBind) StartKeepAlives(ctx context.Context, peerAddr *net.UDPAddr) {
	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()

	probePkt := make([]byte, 36)
	binary.BigEndian.PutUint32(probePkt[0:4], MagicProbeSig)
	copy(probePkt[4:], b.myPubKey[:])

	b.pongLock.Lock()
	b.lastPongTime = time.Now()
	b.pongLock.Unlock()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := b.SendRaw(probePkt, peerAddr)
			if err != nil {
				fmt.Printf("failed to send keepalives to %s : %v\n", peerAddr.String(), err)
				continue
			}

			b.pongLock.Lock()
			lastPong := b.lastPongTime
			b.pongLock.Unlock()

			if !lastPong.IsZero() && time.Since(lastPong) > 15*time.Second {
				fmt.Printf("udp peer is dead , lastpongtime > threshold , endpoint : %s", peerAddr.String())
				b.failLock.Lock()
				b.udpFailCount = 5
				b.failLock.Unlock()
			}
		}
	}

}
