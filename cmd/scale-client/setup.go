package main

import (
	"bytes"
	"context"
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

// activeKeepAlives tracks the cancel func for each peer's running
// StartKeepAlives loop, keyed by hex peer key, so we don't spawn a
// duplicate loop on every poll cycle and so we can stop it when the
// peer disappears or the client shuts down.
var activeKeepAlives sync.Map

type Endpoint struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Type     string `json:"type"`
}

type PeerInfo struct {
	ID         string     `json:"id"`
	PublicKey  string     `json:"public_key"`
	Endpoints  []Endpoint `json:"endpoints,omitempty"`
	AllowedIPs []string   `json:"allowed_ips"`
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

	log.Println("🔍 DEBUG: Testing IP Detection immediately...")
	if _, err := getLocalIPs(); err != nil {
		log.Printf("Error getting IPs: %v", err)
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

	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("[%s] ", wgIface))
	WgDevice = device.NewDevice(tunDev, bind, logger)
	WgDevice.Up()

	if err := ForceConfigureInterface(wgIface, regConfig.AssignedIP); err != nil {
		log.Printf("Warning: Manual IP setup failed: %v", err)
	}

	conf := fmt.Sprintf(`private_key=%s
`, hexKey(privKey))

	log.Println("Applying WireGuard configuration (private key only)...")

	// Create a channel to catch the result
	done := make(chan error, 1)
	go func() {
		done <- WgDevice.IpcSet(conf)
	}()

	select {
	case err := <-done:
		if err != nil {
			log.Fatalf("IpcSet failed: %v", err)
		}
		log.Println("applied successfully.")
	case <-time.After(5 * time.Second):
		log.Fatal("FATAL: IpcSet timed out ,check hybridbind implementation")
	}

	//if err := WgDevice.IpcSet(conf); err != nil {
	//	log.Fatalf("Failed to configure device: %v", err)
	//}


	/*
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
	*/

	stopChan := make(chan struct{})

	log.Println("Client running. Starting polling loop...")

	go bind.RunControlLoop()

	go runServerPollingLoop(bind, serverURL, pubKey.String(), authToken, stopChan)

	// BUG FIX: HealthMonitor must start before the blocking shutdown wait,
	// not after. waitForShutdown blocks until SIGINT/SIGTERM, so starting
	// HealthMonitor after it meant the UDP-dead-detection/relay-failover
	// loop never ran during normal operation - only at the exact moment
	// the process was already exiting.
	go HealthMonitor(bind, stopChan)

	waitForShutdown(stopChan, bind)
}

func runServerPollingLoop(bind *vpn.HybridBind, serverURL, publicKey, authToken string, stop chan struct{}) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	httpClient := &http.Client{Timeout: 10 * time.Second}

	performPollCycle(bind, httpClient, serverURL, publicKey, authToken)

	for {
		select {
		case <-ticker.C:
			performPollCycle(bind, httpClient, serverURL, publicKey, authToken)
		case <-stop:
			log.Println("Gracefully stopping polling loop...")
			return
		}
	}
}

func performPollCycle(bind *vpn.HybridBind, client *http.Client, serverURL, publicKey, authToken string) {
	// 1. Sync state with server
	mypublicEp, _ := performSTUN(bind, "stun.l.google.com:19302")
	localEps, _ := getLocalIPs()
	updateHeartbeat(client, serverURL, publicKey, authToken, mypublicEp, localEps)

	pollResp, err := pollServer(client, serverURL, authToken, publicKey)
	if err != nil || pollResp == nil {
		return
	}

	// Convert YOUR key once
	selfKeyBytes, _ := wgtypes.ParseKey(publicKey)
	hexSelfKey := hex.EncodeToString(selfKeyBytes[:])

	var ipcBuilder strings.Builder
	// MANDATORY: Clear old state and start fresh
	ipcBuilder.WriteString("replace_peers=true\n")

	for _, peer := range pollResp.Peers {
		if peer.PublicKey == publicKey {
			continue
		}

		// 2. HEX CONVERSION
		peerKeyBytes, err := wgtypes.ParseKey(peer.PublicKey)
		if err != nil {
			log.Printf(" Invalid key %s, skipping", peer.PublicKey[:8])
			continue
		}
		hexPeerKey := hex.EncodeToString(peerKeyBytes[:])

		// 3. IP VALIDATION (The actual fix for Error -22)
		// Strip any existing mask from peer.ID (e.g., "100.64.0.7/24" -> "100.64.0.7")
		cleanIP := strings.Split(peer.ID, "/")[0]
		parsedIP := net.ParseIP(cleanIP)
		if parsedIP == nil {
			log.Printf(" Peer %s has invalid IP '%s', skipping", peer.PublicKey[:8], peer.ID)
			continue
		}

		// 4. ENDPOINT SELECTION
		var bestEndpoint Endpoint
		found := false
		for _, ep := range peer.Endpoints {
			if strings.HasPrefix(ep.IP, "192.168.") || strings.HasPrefix(ep.IP, "10.") {
				bestEndpoint = ep
				found = true
				break
			}
		}
		// BUG FIX: prefer the STUN-derived public (srflx) endpoint over a
		// blind index-0 fallback. Without this, a peer's host-enumerated
		// addresses (e.g. a docker bridge or secondary NIC IP, whatever
		// happened to be first in the list) could get picked over its
		// actual reachable public address - fine on a shared LAN where
		// almost anything routes, but silently wrong once the peer is on
		// a different network and only the srflx address is reachable.
		if !found {
			for _, ep := range peer.Endpoints {
				if ep.Type == "srflx" {
					bestEndpoint = ep
					found = true
					break
				}
			}
		}
		if !found && len(peer.Endpoints) > 0 {
			bestEndpoint = peer.Endpoints[0]
			found = true
		}

		// 5. BUILD PEER BLOCK (Atomic String Construction)
		ipcBuilder.WriteString("public_key=" + hexPeerKey + "\n")
		ipcBuilder.WriteString("allowed_ip=" + cleanIP + "/32\n")
		ipcBuilder.WriteString("persistent_keepalive_interval=25\n")

		if found {
			if bind.IsUdpDead() {
				ipcBuilder.WriteString(fmt.Sprintf("endpoint=%s\n", hexPeerKey))
				log.Printf("🔹 PEER CONNECT (RELAY FALLBACK): %s -> %s (%s/32)", peer.PublicKey[:8], hexPeerKey, cleanIP)
			} else {
				ipcBuilder.WriteString(fmt.Sprintf("endpoint=%s:%d\n", bestEndpoint.IP, bestEndpoint.Port))
				log.Printf("🔹 PEER CONNECT: %s -> %s (%s/32)", peer.PublicKey[:8], bestEndpoint.IP, cleanIP)
			}
			endpointCache.Store(hexPeerKey, fmt.Sprintf("%s:%d", bestEndpoint.IP, bestEndpoint.Port))

			// BUG FIX: bind.StartKeepAlives was never called anywhere in
			// this file. StartHolePunching only fires a one-shot 5-packet
			// burst (~750ms) once per 30s poll cycle - not a sustained
			// keepalive. Without a continuous 5s-interval prober, the
			// custom ping-pong liveness/roaming mechanism (lastPongTime,
			// udpFailCount) never gets fed real traffic once the initial
			// hole-punch burst ends, so it silently stalls - especially
			// visible when hosting remotely across real NATs, since
			// LAN/localhost testing doesn't need the mapping kept alive.
			if udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", bestEndpoint.IP, bestEndpoint.Port)); err == nil {
				if _, alreadyRunning := activeKeepAlives.LoadOrStore(hexPeerKey, true); !alreadyRunning {
					ctx, cancel := context.WithCancel(context.Background())
					activeKeepAlives.Store(hexPeerKey, cancel)
					go bind.StartKeepAlives(ctx, udpAddr)
				}
			} else {
				log.Printf("could not resolve endpoint for keepalive, peer %s: %v", peer.PublicKey[:8], err)
			}
		}

		// 6. HOLE PUNCHING
		StartHolePunching(bind, hexPeerKey, peer.Endpoints, hexSelfKey)
	}

	// 7. APPLY EVERYTHING AT ONCE
	if ipcBuilder.Len() > 0 {
		configBlob := ipcBuilder.String()
		if err := WgDevice.IpcSet(configBlob); err != nil {
			log.Printf("❌ IPC Error. Full config attempted:\n%s", configBlob)
			log.Printf("❌ Detailed Error: %v", err)
		}
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

func waitForShutdown(stopChan chan struct{}, bind *vpn.HybridBind) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	log.Println("Shutdown signal received.")

	// 1. Tell the polling loop to stop
	close(stopChan)

	// 2. Close the WireGuard device
	if WgDevice != nil {
		WgDevice.Close()
	}
	if bind != nil {
		bind.Shutdown()
	}

	// 3. Optional: small delay to let goroutines print their "stopping" logs
	time.Sleep(500 * time.Millisecond)
}

func performSTUN(bind *vpn.HybridBind, stunServer string) (*Endpoint, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", stunServer)
	if err != nil {
		return nil, err
	}

	msg := stun.MustBuild(stun.BindingRequest, stun.TransactionID)

	if err := bind.SendRaw(msg.Raw, serverAddr); err != nil {
		return nil, err
	}

	timeout := time.After(2 * time.Second)
	for {
		select {
		case pkt := <-bind.StunRxChan:
			if vpn.VerifyStun(pkt.Data) {
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

func StartHolePunching(bind *vpn.HybridBind, peerKey string, endpoints []Endpoint, myLocalPubKey string) {

	if _, loaded := activeSprayers.LoadOrStore(peerKey, true); loaded {
		return
	}

	var candidates []*net.UDPAddr
	for _, ep := range endpoints {

		if ep.Protocol == "udp" {
			addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ep.IP, ep.Port))
			if err == nil {
				candidates = append(candidates, addr)
			}
		}
	}

	if len(candidates) == 0 {
		activeSprayers.Delete(peerKey)
		return
	}

	go func() {
		defer activeSprayers.Delete(peerKey)

		pkt := make([]byte, 36)
		binary.BigEndian.PutUint32(pkt[:4], vpn.MagicProbeSig)

		myKeyBytes, err := hex.DecodeString(myLocalPubKey)
		if err != nil || len(myKeyBytes) != 32 {
			log.Printf("Error decoding local key for hole punching: %v", err)
			return
		}
		copy(pkt[4:], myKeyBytes)

		log.Printf("Spraying %d candidates for peer %s...", len(candidates), peerKey[:8])

		for i := 0; i < 5; i++ {
			for _, addr := range candidates {
				if err := bind.SendRaw(pkt, addr); err != nil {
				}
			}
			time.Sleep(150 * time.Millisecond)
		}

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

			isLoopback := ip.IsLoopback()
			isIPv4 := (ip.To4() != nil)
			log.Printf("Scanned IP: %s (Loopback: %v, IPv4: %v)", ip.String(), isLoopback, isIPv4)

			if !isIPv4 {
				continue
			}

			if isLoopback {
				continue
			}

			endpoints = append(endpoints, Endpoint{
				IP:       ip.String(),
				Port:     listenPort,
				Protocol: "udp",
				Type:     "host",
			})
		}
	}

	if len(endpoints) == 0 {
		log.Println("WARNING: No local endpoints found! Client will be invisible to peers.")
	} else {
		log.Printf("Sending %d local endpoints to server.", len(endpoints))
	}

	return endpoints, nil
}

func ForceConfigureInterface(iface string, ipCIDR string) error {
	log.Printf("Forcing interface configuration via shell...")

	cmdUp := exec.Command("ip", "link", "set", "dev", iface, "up")
	if out, err := cmdUp.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set link up: %v, output: %s", err, out)
	}

	fullIP := ipCIDR
	if !strings.Contains(fullIP, "/") {
		fullIP = fullIP + "/32"
	}

	cmdAddr := exec.Command("ip", "addr", "add", ipCIDR, "dev", iface)
	_ = cmdAddr.Run()

	log.Printf("Interface %s configured with IP %s via shell", iface, ipCIDR)
	return nil
}

func HealthMonitor(b *vpn.HybridBind, stopChan chan struct{}) {
	ticker := time.NewTicker(time.Second * 2)
	defer ticker.Stop()

	usingRelay := false

	for {
		select {
		case <-ticker.C:
			isDead := b.IsUdpDead()

			// BUG FIX: these were nested as an if/else-if under the same
			// `isDead && !usingRelay` condition, which made the recovery
			// branch (!isDead && usingRelay) structurally unreachable -
			// isDead was already known true at that point. They must be
			// two independent top-level branches.
			if isDead && !usingRelay {
				log.Printf("udp failed! shifting to relay")

				var ipcBuilder strings.Builder

				endpointCache.Range(func(key, value interface{}) bool {
					peerHexKey := key.(string)

					ipcBuilder.WriteString(fmt.Sprintf("public_key=%s\n", peerHexKey))
					ipcBuilder.WriteString(fmt.Sprintf("endpoint=%s\n", peerHexKey))

					return true
				})

				if ipcBuilder.Len() > 0 {
					// BUG FIX: err != nil / err == nil branches were
					// swapped - a failed IpcSet was marking the switch
					// as successful, and a successful IpcSet was logging
					// "failed to switch to relay".
					if err := WgDevice.IpcSet(ipcBuilder.String()); err != nil {
						log.Printf("failed to switch to relay: %v", err)
					} else {
						usingRelay = true
						log.Println("switched to relay")
					}
				}
			} else if !isDead && usingRelay {
				log.Printf("udp recovered, switching back to direct connection")
				usingRelay = false
			}
		case <-stopChan:
			log.Println("stopping the health monitor")
			return
		}
	}
}
