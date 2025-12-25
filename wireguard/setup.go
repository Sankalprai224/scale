package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"scale/internal/vpn" // This requires your go.mod module name to be "scale"

	"github.com/joho/godotenv"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	pollInterval      = 30 * time.Second
	keepAliveInterval = 25
	listenPort        = 51820
)

var WgDevice *device.Device

// --- Data Structures ---

type Endpoint struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Type     string `json:"type"`
}

type PeerInfo struct {
	ID        string     `json:"id"`
	PublicKey string     `json:"public_key"`
	Endpoints []Endpoint `json:"endpoints,omitempty"`
}

type PeerConfig struct {
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
	Endpoint   string   `json:"endpoint,omitempty"`
}

type PollResponse struct {
	Peers []PeerInfo `json:"peers"`
}

type RegistrationConfig struct {
	AssignedIP string `json:"assigned_ip"`
}

func main() {
	if err := godotenv.Load(".env"); err != nil {
		log.Println("No .env file found, using environment variables.")
	}

	serverURL := strings.TrimSuffix(strings.TrimSpace(os.Getenv("WG_CONTROL_SERVER")), "/")
	authToken := strings.TrimSpace(os.Getenv("AUTH_TOKEN"))
	relayURL := strings.TrimSpace(os.Getenv("RELAY_URL"))

	if serverURL == "" || authToken == "" || relayURL == "" {
		log.Fatal("WG_CONTROL_SERVER, AUTH_TOKEN, and RELAY_URL must be set.")
	}

	privKey, pubKey, err := generateOrLoadKeys()
	if err != nil {
		log.Fatalf("Key setup failed: %v", err)
	}

	log.Println("Registering with control server...")
	regConfig, err := registerDeviceAndGetIP(serverURL, pubKey.String(), authToken)
	if err != nil {
		log.Fatalf("Failed to register device: %v", err)
	}
	log.Printf("Successfully registered. Assigned IP: %s", regConfig.AssignedIP)

	log.Println("⚡ Starting Userspace WireGuard Engine (Hybrid Mode)...")

	tunDev, err := tun.CreateTUN("wg0", 1420)
	if err != nil {
		log.Fatalf("Failed to create TUN device: %v", err)
	}

	bind, err := vpn.NewHybridBind(listenPort, relayURL, hexKey(pubKey))
	if err != nil {
		log.Fatalf("Failed to create HybridBind: %v", err)
	}

	logger := device.NewLogger(device.LogLevelVerbose, "[wg0] ")
	WgDevice = device.NewDevice(tunDev, bind, logger)
	WgDevice.Up()

	conf := fmt.Sprintf(`private_key=%s
listen_port=%d
`, hexKey(privKey), listenPort)

	if err := WgDevice.IpcSet(conf); err != nil {
		log.Fatalf("Failed to configure device: %v", err)
	}

	// Set IP on the interface
	assignIPToInterface("wg0", regConfig.AssignedIP)

	uapi, err := ipc.UAPIListen("wg0", nil)
	if err == nil {
		go func() {
			for {
				conn, err := uapi.Accept()
				if err != nil {
					continue
				}
				go WgDevice.IpcHandle(conn)
			}
		}()
	}

	log.Println("✅ Client running. Starting polling loop...")

	go runServerPollingLoop(serverURL, pubKey.String(), authToken)

	waitForShutdown()
}

func runServerPollingLoop(serverURL, publicKey, authToken string) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	httpClient := &http.Client{Timeout: 10 * time.Second}

	performPollCycle(httpClient, serverURL, publicKey, authToken)

	for range ticker.C {
		performPollCycle(httpClient, serverURL, publicKey, authToken)
	}
}

func performPollCycle(client *http.Client, serverURL, publicKey, authToken string) {
	pollResp, err := pollServer(client, serverURL, authToken, publicKey)
	if err != nil {
		log.Printf("Error polling server: %v", err)
		return
	}

	var ipcBuilder strings.Builder

	for _, peer := range pollResp.Peers {
		peerKey, err := wgtypes.ParseKey(peer.PublicKey)
		if err != nil {
			continue
		}

		ipcBuilder.WriteString(fmt.Sprintf("public_key=%s\n", hex.EncodeToString(peerKey[:])))
		ipcBuilder.WriteString(fmt.Sprintf("allowed_ips=%s/32\n", peer.ID))
		ipcBuilder.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", keepAliveInterval))

		endpointSet := false
		for _, ep := range peer.Endpoints {
			if ep.Protocol == "udp" {
				ipcBuilder.WriteString(fmt.Sprintf("endpoint=%s:%d\n", ep.IP, ep.Port))
				endpointSet = true
				break
			}
		}

		if !endpointSet {
			// FALLBACK: Use Relay.
			// The Endpoint string will be the Public Key (Hex).
			// vpn/hybrid.go's ParseEndpoint will detect this is NOT an IP and route to WebSocket.
			ipcBuilder.WriteString(fmt.Sprintf("endpoint=%s\n", hex.EncodeToString(peerKey[:])))
		}
	}

	if ipcBuilder.Len() > 0 {
		if err := WgDevice.IpcSet(ipcBuilder.String()); err != nil {
			log.Printf("Failed to update peers: %v", err)
		}
	}
}

// --- Helpers ---

func assignIPToInterface(iface, cidr string) {
	// EXECUTE 'ip' command to assign address
	cmd := exec.Command("ip", "addr", "add", cidr+"/24", "dev", iface)
	if err := cmd.Run(); err != nil {
		// It might fail if IP is already assigned, which is fine in some cases
		log.Printf("Note: IP assignment to %s returned: %v", iface, err)
	}

	cmdUp := exec.Command("ip", "link", "set", "dev", iface, "up")
	if err := cmdUp.Run(); err != nil {
		log.Printf("Failed to bring up interface %s: %v", iface, err)
	}
}

func pollServer(client *http.Client, serverURL, authToken, clientPubKey string) (*PollResponse, error) {
	req, err := http.NewRequest("GET", serverURL+"/api/poll", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("X-Device-Public-Key", clientPubKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status: %s", resp.Status)
	}

	var pollResp PollResponse
	if err := json.NewDecoder(resp.Body).Decode(&pollResp); err != nil {
		return nil, err
	}
	return &pollResp, nil
}

func registerDeviceAndGetIP(serverURL, publicKey, authToken string) (*RegistrationConfig, error) {
	payload, _ := json.Marshal(map[string]interface{}{"public_key": publicKey})
	req, err := http.NewRequest("POST", serverURL+"/api/devices/register", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status: %s", resp.Status)
	}
	var config RegistrationConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}

func generateOrLoadKeys() (wgtypes.Key, wgtypes.Key, error) {
	key, err := wgtypes.GenerateKey()
	return key, key.PublicKey(), err
}

func hexKey(k wgtypes.Key) string {
	return hex.EncodeToString(k[:])
}

func waitForShutdown() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	log.Println("Shutdown signal received.")
	if WgDevice != nil {
		WgDevice.Close()
	}
}
