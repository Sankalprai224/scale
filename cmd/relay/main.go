package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	KeySize   = 32
	writeWait = 10 * time.Second
	pongWait  = 60 * time.Second
	pingWait  = (pongWait * 9) / 10
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type client struct {
	conn      *websocket.Conn
	send      chan []byte
	key       string
	closeOnce sync.Once
	quit      chan struct{}
}

var (
	clients = make(map[string]*client)
	mutex   = &sync.RWMutex{}
)

func (c *client) writePump() {
	ticker := time.NewTicker(pingWait)
	defer func() {
		ticker.Stop()
		c.Cleanup()
	}()

	for {
		select {
		case message := <-c.send:

			c.conn.SetWriteDeadline(time.Now().Add(writeWait))

			err := c.conn.WriteMessage(websocket.BinaryMessage, message)
			if err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			err := c.conn.WriteMessage(websocket.PingMessage, nil)
			if err != nil {
				return
			}
		case <-c.quit:
			c.conn.WriteMessage(websocket.CloseMessage, []byte{})
			return
		}

	}
}

func (c *client) readPump() {
	defer c.Cleanup()

	c.conn.SetReadDeadline(time.Now().Add(pongWait))

	c.conn.SetPongHandler(func(appdata string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	_, KeyMsg, err := c.conn.ReadMessage()
	if err != nil || len(KeyMsg) != 32 {
		log.Println("error : invalid client-key")
		return
	}
	c.key = string(KeyMsg)

	mutex.Lock()
	clients[c.key] = c
	mutex.Unlock()

	for {
		_, packet, err := c.conn.ReadMessage()
		if err != nil {
			log.Println("error in reading message, client disconnected:", c.key[:8])
			break
		}

		if len(packet) < KeySize {
			log.Println("invalid key size__ too short")
			continue
		}

		destKey := string(packet[:KeySize])
		payload := packet[KeySize:]

		mutex.RLock()
		destClient, exists := clients[destKey]
		mutex.RUnlock()

		if exists {

			forwardMessage := append([]byte(c.key), payload...)

			select {
			case destClient.send <- forwardMessage:
			case <-destClient.quit:
				log.Printf("dropped packet to %.8s (peer closing)", destKey)
			default:
				log.Printf("dropped the packet to %.8s (send buffer full)", destKey)
			}
		}
	}

}

func wsHandler(authKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestKey := r.URL.Query().Get("auth")
		if requestKey != authKey {
			log.Printf("auth key mismatch : unauthorized")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			fmt.Println("error upgrading:", err)
			return
		}

		c := &client{
			conn: conn,
			send: make(chan []byte, 256),
			quit: make(chan struct{}),
		}

		go c.writePump()
		go c.readPump()

	}
}

func (c *client) Cleanup() {
	c.closeOnce.Do(func() {
		if c.key != "" {
			mutex.Lock()
			if clients[c.key] == c {
				delete(clients, c.key)
			}
			mutex.Unlock()
		}
		c.conn.Close()
		close(c.quit)
	})
}

func main() {

	clientAuthKey := os.Getenv("DERP_AUTH_KEY")
	if clientAuthKey == "" {
		log.Fatal("derp auth key is not set up in the environment")
	}

	http.HandleFunc("/derp", wsHandler(clientAuthKey))
	fmt.Println("derp server running on wss://localhost:8443/derp")
	log.Fatal(http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil))
}
