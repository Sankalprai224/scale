package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// syncWireGuardPeers updates the internal Engine with the latest peer list
func syncWireGuardPeers(interfaceName string, serverPeers []PeerConfig, replacePeers bool) error {
	// We build a large IPC configuration string
	var sb strings.Builder

	if replacePeers {
		sb.WriteString("replace_peers=true\n")
	}

	for _, p := range serverPeers {
		// 1. Parse the Key (Base64 -> Key)
		key, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			log.Printf("Skipping invalid peer key %s: %v", p.PublicKey, err)
			continue
		}
		// 2. Convert to Hex (Required for Engine IPC)
		keyHex := hex.EncodeToString(key[:])

		sb.WriteString(fmt.Sprintf("public_key=%s\n", keyHex))

		// 3. Add AllowedIPs
		for _, ip := range p.AllowedIPs {
			sb.WriteString(fmt.Sprintf("allowed_ips=%s\n", ip))
		}

		// 4. Handle Endpoint
		// If the server provided a specific endpoint (e.g. UDP), use it.
		// If not, we might leave it blank (or set to relay if needed).
		if p.Endpoint != "" {
			sb.WriteString(fmt.Sprintf("endpoint=%s\n", p.Endpoint))
		}
	}

	// Apply config to the global WgDevice
	if WgDevice == nil {
		return fmt.Errorf("WireGuard engine not initialized")
	}
	return WgDevice.IpcSet(sb.String())
}

// updateWireguardPeerEndpoint updates a specific peer's endpoint dynamically
func updateWireguardPeerEndpoint(interfaceName string, peerPubKeyB64 string, endpoint *net.UDPAddr) error {
	if WgDevice == nil {
		return fmt.Errorf("WireGuard engine not initialized")
	}

	// 1. Convert Base64 Key to Hex
	key, err := wgtypes.ParseKey(peerPubKeyB64)
	if err != nil {
		return fmt.Errorf("invalid peer key: %v", err)
	}
	keyHex := hex.EncodeToString(key[:])

	var conf string
	if endpoint != nil {
		// CASE 1: P2P Success (STUN)
		// We tell WireGuard to use the specific IP:Port
		conf = fmt.Sprintf("public_key=%s\nendpoint=%s\n", keyHex, endpoint.String())
	} else {
		// CASE 2: Relay Fallback
		// We set the endpoint to the Peer's Public Key (Hex)
		// Our HybridBind will detect this is NOT an IP and route via WebSocket
		conf = fmt.Sprintf("public_key=%s\nendpoint=%s\n", keyHex, keyHex)
	}

	return WgDevice.IpcSet(conf)
}
