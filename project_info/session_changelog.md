# Session Changelog

This document tracks the fixes and architecture improvements made to the Scale VPN project in this session.

## 1. Fixed Server Startup Race Condition (`/api/poll` 500 error)
- **Problem:** The `/api/poll` endpoint consistently returned 500 errors for the first ~10 seconds after server startup because the Redis device cache was populated asynchronously in a background goroutine.
- **Fix:** Refactored `main.go` to perform a **synchronous** cache population (`refreshDeviceCache()`) before the Fiber server starts accepting traffic, eliminating the race condition.

## 2. Added PostgreSQL Fallback for Poll Endpoint
- **Problem:** `/api/poll` failed completely if the Redis cache was empty or unavailable.
- **Fix:** Modified `stun_controller.go` to gracefully fall back to querying PostgreSQL directly (`database.GetAllDevices()`) on a cache miss.

## 3. Expanded IP Pool for 20k Device Scalability (CIDR Bottleneck)
- **Problem:** The system used a `/24` CIDR block (`100.64.0.0/24`), hard-capping the network at exactly 254 usable IPs before registration would fail.
- **Fix:** 
  - Changed `ipAllocator` initialization in `device_controller.go` to use a `/16` block (`100.64.0.0/16`), providing 65,534 usable IPs.
  - Updated `AllocateCIDR(16)` so clients correctly configure an on-link kernel route for the entire `/16` subnet, ensuring peer-to-peer reachability.
  - Removed dead/hardcoded `/24` code (`assignIPToInterface`) from the client's `setup.go`.

## 4. Secured Heartbeat Endpoint against Hijacking
- **Problem:** `Heartbeat()` blindly trusted the `X-Device-Public-Key` header, allowing any authenticated user to spoof endpoints for someone else's device.
- **Fix:** Added a PostgreSQL lookup (`database.FindDeviceByPublicKey`) in `device_controller.go` to verify that `device.UserID` matches the authenticated JWT user's ID before accepting endpoint updates.

## 5. Fixed `GetPeerConfig` Redis Bug
- **Problem:** Like `/api/poll`, `GetPeerConfig` failed with a 500 if the Redis cache was missing.
- **Fix:** Added the identical PostgreSQL fallback pattern to `GetPeerConfig` in `device_controller.go`.

## 6. Fixed User Handler Authentication Source
- **Problem:** `User()` in `authcontroller.go` parsed a `"jwt"` cookie from scratch, breaking compatibility with the Go client which only sends `Authorization: Bearer` headers.
- **Fix:** Changed the handler to use `c.Locals("x-user-id")` (populated by the auth middleware), unifying the authentication path for all API clients.

## Operational Note
When upgrading to the `/16` IP pool, the existing `ip_pool:available` key in Redis must be manually flushed (`redis-cli DEL ip_pool:available`) so the initialization loop rebuilds the pool with the new 65k addresses.

## 7. Fixed WireGuard Engine Shutdown Panic (`use of closed network connection`)
- **Problem:** Tearing down the client resulted in panics when the userspace `HybridBind` engine's background goroutines attempted to read/write to a UDP socket that was prematurely destroyed.
- **Fix:** Restructured the engine's shutdown sequence and incorporated proper synchronization to ensure background networking routines exit gracefully before the socket is completely closed.

## 8. Resolved `HybridBind` WebSocket Deadlock
- **Problem:** Fallback traffic routed over the WebSocket relay completely froze the client due to a mutex deadlock in `HybridBind.Send()`.
- **Fix:** Refactored the `wsLock` critical section to only protect the actual `websocket.WriteMessage()` call instead of wrapping the entire packet loop, successfully unblocking high-throughput relay traffic.

## 9. Fixed Relay Fallback Polling Race Condition (Loop Flapping)
- **Problem:** The client's `HealthMonitor` would successfully detect a broken UDP path and failover to the WebSocket relay, only for the 30-second `performPollCycle` to blindly overwrite it back to the broken UDP IP.
- **Fix:** Introduced a `bind.IsUdpDead()` condition in `performPollCycle` (inside `setup.go`) so that the client retains the WebSocket relay endpoint if the direct P2P connection is still confirmed dead.

## 10. Fixed Relay Authentication Failures
- **Problem:** The local WebSocket relay fallback failed silently with `wsConn is nil` on startup because it demanded a `DERP_AUTH_KEY` that wasn't configured.
- **Fix:** Added the `DERP_AUTH_KEY` to the client `.env` and correctly formatted the `RELAY_URL` with the `?auth=` query parameter to ensure successful handshakes on boot.
