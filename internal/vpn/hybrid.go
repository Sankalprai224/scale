package vpn

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/gorilla/websocket"
	"golang.zx2c4.com/wireguard/conn"
)

const Stunbyte uint32 = 0x2112A442
const MagicProbeSig uint32 = 0xFF505242

// HybridBind handles BOTH UDP (P2P) and WebSocket (Relay)
type HybridBind struct {
	udpConn     *net.UDPConn
	wsConn      *websocket.Conn
	wsLock      sync.Mutex
	rxChan      chan Packet
	ControlChan chan Packet
	StunRxChan  chan Packet

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

	dialer := *websocket.DefaultDialer
	dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	ws, _, err := dialer.Dial(relayURL, nil) // Use 'dialer', not 'DefaultDialer'
	if err == nil {
		b.wsConn = ws
		keyBytes, _ := hex.DecodeString(myPubKey)
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
		if valid {
			if b.UpdatePeerEndpoint != nil {
				b.UpdatePeerEndpoint(peerKey, pkt.Endpoint.(*UDPEndpoint).Addr)
			}
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
			b.rxChan <- Packet{Data: pkt, Endpoint: &UDPEndpoint{Addr: addr}}
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
			b.rxChan <- Packet{Data: data, Endpoint: &RelayEndpoint{Key: key}}
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
		for _, pkt := range packets {
			b.udpConn.WriteToUDP(pkt, udpEp.Addr)
		}
		return nil
	}
	if relayEp, ok := ep.(*RelayEndpoint); ok && b.wsConn != nil {
		b.wsLock.Lock()
		defer b.wsLock.Unlock()
		for _, pkt := range packets {
			frame := append(relayEp.Key[:], pkt...)
			b.wsConn.WriteMessage(websocket.BinaryMessage, frame)
		}
		return nil
	}
	return nil
}

func (b *HybridBind) Receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	p, ok := <-b.rxChan
	if !ok {
		return 0, errors.New("closed")
	}
	n := copy(packets[0], p.Data)
	sizes[0] = n
	eps[0] = p.Endpoint
	return 1, nil
}

func (b *HybridBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	return []conn.ReceiveFunc{b.Receive}, 0, nil
}
func (b *HybridBind) BatchSize() int       { return 1 }
func (b *HybridBind) Close() error         { return b.udpConn.Close() }
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
