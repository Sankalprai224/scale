package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"scale/internal/vpn"

	"github.com/joho/godotenv"
	"github.com/pion/stun/v2"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	pollInterval      = 30 * time.Second
	keepAliveInterval = 25
)

var WgDevice *device.Device

var endpointCache sync.Map

var activeSprayers sync.Map

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

var listenPort = 51820

func main() {
	if err := godotenv.Load(".env"); err != nil {
		log.Println("No .env file found, using environment variables.")
	}

	wgIface := os.Getenv("WG_INTERFACE")
	if wgIface == "" {
		wgIface = "wg0"
	}

	if envPort := os.Getenv("WG_PORT"); envPort != "" {
		// Simple string to int conversion
		var err error
		listenPort, err = strconv.Atoi(envPort) // Requires "strconv" import!
		if err != nil {
			log.Fatalf("Invalid WG_PORT: %v", err)
		}
	}
	log.Printf("Starting WireGuard on %s : %d", wgIface, listenPort)

	serverURL := strings.TrimSuffix(strings.TrimSpace(os.Getenv("WG_CONTROL_SERVER")), "/")
	authToken := strings.TrimSpace(os.Getenv("AUTH_TOKEN"))
	relayURL := strings.TrimSpace(os.Getenv("RELAY_URL"))

	if authToken == "" {
		log.Printf("error empty auth token")
		email := os.Getenv("SCALE_EMAIL")
		password := os.Getenv("SCALE_PASSWORD")

		if email == "" || password == "" {
			log.Fatal("Missing credentials: Set AUTH_TOKEN or (SCALE_EMAIL + SCALE_PASSWORD)")
		}

		// We need the helper function 'loginToServer' defined at the bottom of the file
		var err error
		authToken, err = loginToServer(serverURL, email, password)
		if err != nil {
			log.Fatalf("Auto-login failed: %v", err)
		}
		log.Println("Auto-login successful! Token acquired.")
	}

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

	//	if err := ForceConfigureInterface(wgIface, regConfig.AssignedIP); err != nil {
	//		log.Printf("Warning: Manual IP setup failed: %v", err)
	//	}

	log.Println("⚡ Starting Userspace WireGuard Engine (Hybrid Mode)...")

	tunDev, err := tun.CreateTUN(wgIface, 1420)
	if err != nil {
		log.Fatalf("Failed to create TUN device: %v", err)
	}

	bind, err := vpn.NewHybridBind(listenPort, relayURL, hexKey(pubKey))
	if err != nil {
		log.Fatalf("Failed to create HybridBind: %v", err)
	}

	bind.UpdatePeerEndpoint = func(peerKey string, newAddr *net.UDPAddr) {
		if last, loaded := endpointCache.Load(peerKey); loaded {
			if last.(string) == newAddr.String() {
				return
			}
		}

		endpointCache.Store(peerKey, newAddr.String())

		go func() {
			cfg := fmt.Sprintf("public_key=%s\nendpoint=%s\n", peerKey, newAddr.String())
			if err := WgDevice.IpcSet(cfg); err != nil {
				endpointCache.Delete(peerKey)
			} else {
				log.Printf("Smart Trust: Peer %s moved to %s", peerKey[:8], newAddr.String())
			}
		}()
	}

	logger := device.NewLogger(device.LogLevelVerbose, fmt.Sprintf("[%s] ", wgIface))
	WgDevice = device.NewDevice(tunDev, bind, logger)
	WgDevice.Up()

	if err := ForceConfigureInterface(wgIface, regConfig.AssignedIP); err != nil {
		log.Printf("Warning: Manual IP setup failed: %v", err)
	}

	conf := fmt.Sprintf(`private_key=%s
listen_port=%d
`, hexKey(privKey), listenPort)

	if err := WgDevice.IpcSet(conf); err != nil {
		log.Fatalf("Failed to configure device: %v", err)
	}

	assignIPToInterface(wgIface, regConfig.AssignedIP)

	uapi, err := ipc.UAPIListen(wgIface, nil)
	if err != nil {
		log.Printf("Failed to listen on UAPI socket: %v", err)
	} else {
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

	log.Println("Client running. Starting polling loop...")

	go bind.RunControlLoop()

	go runServerPollingLoop(bind, serverURL, pubKey.String(), authToken)

	waitForShutdown()
}

func runServerPollingLoop(bind *vpn.HybridBind, serverURL, publicKey, authToken string) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	httpClient := &http.Client{Timeout: 10 * time.Second}

	performPollCycle(bind, httpClient, serverURL, publicKey, authToken)

	for range ticker.C {
		performPollCycle(bind, httpClient, serverURL, publicKey, authToken)
	}
}

func performPollCycle(bind *vpn.HybridBind, client *http.Client, serverURL, publicKey, authToken string) {

	mypublicEp, err := performSTUN(bind, "stun.l.google.com:19302")
	if err != nil {
		log.Printf("stun failed : %v", err)
	} else {
		log.Printf("public ip is: %s: %d", mypublicEp.IP, mypublicEp.Port)
	}

	localEps, err := getLocalIPs()
	if err != nil {
		log.Printf("failed to get local ips: %v", err)
	}
	if err := updateHeartbeat(client, serverURL, publicKey, authToken, mypublicEp, localEps); err != nil {
		log.Printf("failed to send hearbeat : %v", err)
	}

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
				epString := fmt.Sprintf("%s:%d", ep.IP, ep.Port)
				ipcBuilder.WriteString(fmt.Sprintf("endpoint=%s\n", epString))
				endpointCache.Store(peer.PublicKey, epString)
				endpointSet = true
				break
			}

		}

		StartHolePunching(bind, peer.PublicKey, peer.Endpoints, publicKey)

		if !endpointSet {

			ipcBuilder.WriteString(fmt.Sprintf("endpoint=%s\n", hex.EncodeToString(peerKey[:])))
		}
	}

	if ipcBuilder.Len() > 0 {
		if err := WgDevice.IpcSet(ipcBuilder.String()); err != nil {
			log.Printf("Failed to update peers: %v", err)
		}
	}
}

func assignIPToInterface(iface, cidr string) {
	cmd := exec.Command("ip", "addr", "add", cidr+"/24", "dev", iface)
	if err := cmd.Run(); err != nil {
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

// wireguard/setup.go

func performSTUN(bind *vpn.HybridBind, stunServer string) (*Endpoint, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", stunServer)
	if err != nil {
		return nil, err
	}

	// 1. Build STUN Request using pion/stun
	msg := stun.MustBuild(stun.BindingRequest, stun.TransactionID)

	// 2. Send using the SAME socket as WireGuard
	if err := bind.SendRaw(msg.Raw, serverAddr); err != nil {
		return nil, err
	}

	// 3. Wait for response on ControlChan
	timeout := time.After(2 * time.Second)
	for {
		select {
		case pkt := <-bind.StunRxChan:
			// Is this a STUN packet? (Check magic cookie 0x2112A442)
			if vpn.VerifyStun(pkt.Data) {
				// Parse it
				resp := new(stun.Message)
				resp.Raw = pkt.Data
				if err := resp.Decode(); err == nil {
					var xorAddr stun.XORMappedAddress
					if err := xorAddr.GetFrom(resp); err == nil {
						return &Endpoint{
							IP:       xorAddr.IP.String(),
							Port:     xorAddr.Port,
							Protocol: "udp",
							Type:     "srflx",
						}, nil
					}
				}
			}
		case <-timeout:
			return nil, fmt.Errorf("STUN timeout")
		}
	}
}

func updateHeartbeat(client *http.Client, serverUrl, publicKey, authToken string, srflx *Endpoint, hostEps []Endpoint) error {

	type heartBeatPayload struct {
		SrflxEndpoint *Endpoint  `json:"srflx_endpoint,omitempty"`
		HostEndpoints []Endpoint `json:"host_endpoints"`
	}

	payload := heartBeatPayload{
		SrflxEndpoint: srflx,
		HostEndpoints: hostEps,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", serverUrl+"/api/devices/heartbeat", bytes.NewReader(payloadBytes))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("X-Device-Public-Key", publicKey)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat failed with error : %s", resp.Status)
	}

	return nil
}

func loginToServer(serverUrl, email, password string) (string, error) {
	payload, err := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})

	if err != nil {
		return "", err
	}

	resp, err := http.Post(serverUrl+"/api/login", "application/json", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login failed with status %s", resp.Status)
	}

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	token, ok := result["token"]
	if !ok {
		return "", fmt.Errorf("response does not contain token")
	}
	return token, nil
}

// StartHolePunching sends Magic Probes to all candidate addresses of a peer.
// myLocalPubKey: The public key of THIS device (so the peer knows who is knocking).
func StartHolePunching(bind *vpn.HybridBind, peerKey string, endpoints []Endpoint, myLocalPubKey string) {

	// 1. DEDUP CHECK
	// If we are already spraying this peer, don't start another gun.
	if _, loaded := activeSprayers.LoadOrStore(peerKey, true); loaded {
		return
	}

	// 2. PARSE CANDIDATES
	var candidates []*net.UDPAddr
	for _, ep := range endpoints {
		// Only target UDP endpoints
		if ep.Protocol == "udp" {
			// Resolve string "1.2.3.4:51820" -> UDP Address
			addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ep.IP, ep.Port))
			if err == nil {
				candidates = append(candidates, addr)
			}
		}
	}

	if len(candidates) == 0 {
		activeSprayers.Delete(peerKey) // Cleanup if nothing to do
		return
	}

	// 3. LAUNCH ARTILLERY (Async)
	go func() {
		// Ensure we unlock this peer when done
		defer activeSprayers.Delete(peerKey)

		// A. Construct the Magic Packet
		// [4 bytes Magic] + [32 bytes My Pub Key]
		pkt := make([]byte, 36)
		binary.BigEndian.PutUint32(pkt[:4], vpn.MagicProbeSig)

		// Decode our local key from Hex String to Bytes
		myKeyBytes, err := hex.DecodeString(myLocalPubKey)
		if err != nil || len(myKeyBytes) != 32 {
			log.Printf("Error decoding local key for hole punching: %v", err)
			return
		}
		copy(pkt[4:], myKeyBytes)

		log.Printf("Spraying %d candidates for peer %s...", len(candidates), peerKey[:8])

		// B. Fire 5 Rounds
		for i := 0; i < 5; i++ {
			for _, addr := range candidates {
				// Send directly through the WireGuard socket
				if err := bind.SendRaw(pkt, addr); err != nil {
					// Ignore errors (fire and forget)
				}
			}
			// Wait 300ms between bursts
			time.Sleep(150 * time.Millisecond)
		}

		// log.Printf(" Finished spraying %s", peerKey[:8])
	}()
}

func getLocalIPs() ([]Endpoint, error) {
	var endpoints []Endpoint
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			// Skip loopback (127.0.0.1) and non-IPv4 (optional)
			//if ip == nil || ip.IsLoopback() || ip.To4() == nil {
			if ip == nil || ip.To4() == nil {
				continue
			}
			endpoints = append(endpoints, Endpoint{
				IP:       ip.String(),
				Port:     listenPort, // 51820
				Protocol: "udp",
				Type:     "host",
			})
		}
	}
	return endpoints, nil
}

func ForceConfigureInterface(iface string, ipCIDR string) error {
	log.Printf("Forcing interface configuration via shell...")

	// 1. Link Up: sudo ip link set dev wg0 up
	cmdUp := exec.Command("ip", "link", "set", "dev", iface, "up")
	if out, err := cmdUp.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set link up: %v, output: %s", err, out)
	}

	fullIP := ipCIDR
	if !strings.Contains(fullIP, "/") {
		fullIP = fullIP + "/32"
	}

	// 2. Add IP: sudo ip addr add 100.64.0.X/32 dev wg0
	// We ignore errors here in case the IP is already added (to prevent crashing on restart)
	cmdAddr := exec.Command("ip", "addr", "add", ipCIDR, "dev", iface)
	_ = cmdAddr.Run()

	log.Printf("Interface %s configured with IP %s via shell", iface, ipCIDR)
	return nil
}
