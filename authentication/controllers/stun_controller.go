package controllers

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"scale/database"
	"scale/models"
	"scale/pkg/types"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
)

// StunController holds the state for the STUN-related endpoints.
type StunController struct {
	jwtSecret []byte
	natCache  *sync.Map
}

func NewStunController(jwtSecret string) *StunController {
	return &StunController{
		jwtSecret: []byte(jwtSecret),
		natCache:  &sync.Map{},
	}
}

// Poll is a new endpoint for clients to get network updates and a STUN token.
func (s *StunController) Poll(c *fiber.Ctx) error {
	userIDStr, ok := c.Locals("x-user-id").(string)
	if !ok {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Could not get user ID from token"})
	}

	stunToken, err := s.generateStunToken(userIDStr)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate token"})
	}

	// Fetch all devices: try Redis cache first, fall back to PostgreSQL
	var allDevices []models.Device
	cachedDevicesJSON, err := database.Rdb.Get(database.Ctx, "cache:all_devices").Result()
	if err != nil {
		// Redis unavailable — fall back to PostgreSQL (source of truth)
		log.Printf("Cache miss, falling back to PostgreSQL: %v", err)
		allDevices, err = database.GetAllDevices()
		if err != nil {
			log.Printf("PostgreSQL fallback also failed: %v", err)
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve peer list"})
		}
	} else {
		if err := json.Unmarshal([]byte(cachedDevicesJSON), &allDevices); err != nil {
			log.Printf("Failed to unmarshal cached devices: %v", err)
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to parse peer list"})
		}
	}

	clientPubKey := c.Get("X-Device-Public-Key")

	// Convert database models to the PeerInfo type for the response
	peers := make([]types.PeerInfo, 0, len(allDevices))
	for _, device := range allDevices {
		// Don't send the client its own info
		if device.PublicKey == clientPubKey {
			continue
		}

		// Fetch the endpoints for this specific peer from Redis
		redisKey := fmt.Sprintf("device:endpoints:%s", device.PublicKey)
		endpointsJSON, err := database.Rdb.Get(database.Ctx, redisKey).Result()

		var endpoints []types.Endpoint
		if err == nil {
			// Found endpoints, unmarshal them
			if err := json.Unmarshal([]byte(endpointsJSON), &endpoints); err != nil {
				log.Printf("Failed to unmarshal endpoints for peer %s: %v", device.PublicKey, err)
				// Send peer anyway, but with no endpoints
				endpoints = []types.Endpoint{}
			}
		} else {
			// No endpoints found in Redis (peer is offline or hasn't reported)
			// We'll send the peer with an empty endpoint list
			endpoints = []types.Endpoint{}
		}

		peers = append(peers, types.PeerInfo{
			ID:        device.AssignedIP,
			PublicKey: device.PublicKey,
			Endpoints: endpoints, // <-- POPULATE THE FIELD
		})
		// --- END OF FIX ---
	}

	resp := types.PollResponse{
		StunToken: stunToken,
		Peers:     peers,
	}

	return c.JSON(resp)
}

// HandleStunRequest is the endpoint for endpoint discovery.
func (s *StunController) HandleStunRequest(c *fiber.Ctx) error {
	tokenStr := c.Query("token")
	peerID, err := s.validateStunToken(tokenStr)
	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid or expired token"})
	}

	// Discover the remote endpoint, handling proxies. Fiber's c.IP() does this.
	ipStr := c.IP()
	// We need the full remote address to get the port
	remoteAddr := c.Context().RemoteAddr().String()
	_, portStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Could not parse remote address"})
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid IP address"})
	}
	currentEndpoint := net.JoinHostPort(ipStr, portStr)

	natType := "easy"
	if lastEndpoint, ok := s.natCache.Load(peerID); ok {
		lastIP, _, _ := net.SplitHostPort(lastEndpoint.(string))
		if lastIP == ipStr && lastEndpoint.(string) != currentEndpoint {
			natType = "likely_symmetric"
		}
	}
	s.natCache.Store(peerID, currentEndpoint)

	resp := types.EndpointResponse{
		NATType: natType,
		Port:    portStr,
	}

	if ip.To4() != nil {
		resp.IPv4 = ipStr
	} else {
		resp.IPv6 = ipStr
	}
	return c.JSON(resp)
}

func (s *StunController) generateStunToken(peerID string) (string, error) {
	claims := jwt.MapClaims{
		"sub": peerID,
		"exp": time.Now().Add(30 * time.Second).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

func (s *StunController) validateStunToken(tokenStr string) (string, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})

	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims["sub"].(string), nil
	}

	return "", fmt.Errorf("invalid token")
}
