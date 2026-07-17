# HealthMonitor Bug Chain — Full Session Findings
> Written: 2026-07-17. Do NOT implement these fixes blindly. Read the context for each one.

## Context
After validating real cross-NAT connectivity on AWS (WiFi laptop + Mobile Hotspot laptop),
we observed severe ping jitter (170ms ↔ 700ms) caused by route flapping. This document
records the full investigation chain — including wrong theories — so that v2 implementation
is accurate and grounded in the actual code.

The **pre-fix commit** (working demo state with flapping) is: `23065f4`
The code was reverted back to this state after this investigation session.

---

## The Symptom
Ping times oscillated on a near-mathematical timer (~26-34s period on Laptop 1):
```
17:16:20 udp failed! shifting to relay     → 600-700ms pings
17:16:46 udp recovered, switching back     → 170-300ms pings (26s later)
17:17:20 udp failed!                       → 34s later
17:17:46 udp recovered                     → 26s later
```
This is a textbook algorithmic flap, not random cellular packet loss.

---

## Bug #1 — WRONG THEORY (documented so you don't repeat it)
**Claim:** "WireGuard's default PersistentKeepalive (25s) is out of sync with the
HealthMonitor threshold (15s), causing a timer mismatch."

**Why it was wrong:** `hybrid.go` has ZERO references to `PersistentKeepalive`.
The entire liveness mechanism is self-contained using custom probe packets
(`0xFF505242` magic bytes). `PersistentKeepalive=25` in the IPC config is a
WireGuard engine feature for data packets, completely separate from our probe loop.

---

## Bug #2 — REAL: Missing `IpcSet` in Recovery Branch
**File:** `cmd/scale-client/setup.go` — `HealthMonitor()` function

**Root Cause:** When UDP recovered (`!isDead && usingRelay`), the code printed
"udp recovered" and set `usingRelay = false` but **never sent an IpcSet command
to WireGuard** to actually switch the traffic route back to the direct UDP endpoint.

**Effect:** Recovery was only achieved by the 30-second poll cycle rewriting the
WireGuard config. This is why the flap period was ~26-34s — matching the 30s poll,
not the 15s detection threshold.

**The Fix (for v2):**
```go
} else if !isDead && usingRelay {
    log.Printf("udp recovered, switching back to direct connection")
    var ipcBuilder strings.Builder
    endpointCache.Range(func(key, value interface{}) bool {
        peerHexKey := key.(string)
        udpEndpoint := value.(string)  // value is the IP:port string
        ipcBuilder.WriteString(fmt.Sprintf("public_key=%s\n", peerHexKey))
        ipcBuilder.WriteString(fmt.Sprintf("endpoint=%s\n", udpEndpoint))
        return true
    })
    if ipcBuilder.Len() > 0 {
        if err := WgDevice.IpcSet(ipcBuilder.String()); err != nil {
            log.Printf("failed to switch back to direct: %v", err)
        } else {
            usingRelay = false
        }
    } else {
        usingRelay = false
    }
}
```

**Hysteresis guard (add this too):** Add `udpSuccessCount int` to HybridBind struct.
In `RunControlLoop`, when a probe arrives and `udpFailCount >= threshold`, require
3 consecutive successful probes before zeroing `udpFailCount`. This prevents a single
lucky packet from triggering an immediate switch-back on a flaky path.

---

## Bug #3 — REAL: `Send()` Was Falsely Resetting the Fail Counter
**File:** `internal/vpn/hybrid.go` — `Send()` function

**Root Cause:** When a packet was sent via UDP successfully (i.e., the OS socket
accepted it into its buffer), `Send()` was resetting `udpFailCount = 0`. This is
wrong because a successful `WriteToUDP` call only means the OS accepted the packet
locally — it says nothing about whether the packet reached the remote peer.

**Effect:** WireGuard retries handshakes every ~5s. Even when the path is completely
dead (cellular dropped), these retries succeed at the socket level, and were
continuously resetting the fail counter. This masked the `StartKeepAlives` 15s pong
timeout from ever sticking.

**Symptom this produced:** `udp peer is dead` printed repeatedly but
`udp failed! shifting to relay` NEVER printed — the counter was being reset faster
than the HealthMonitor (2s tick) could catch it at 5.

**The Fix (for v2):** Remove the `b.failLock.Lock(); b.udpFailCount = 0; b.failLock.Unlock()`
block from the success path in `Send()`. Only increment on errors. The fail count
should only be reset by actual incoming pong probes in `RunControlLoop`.

---

## Bug #4 — REAL: `StartKeepAlives` Locked to Stale LAN IP
**File:** `internal/vpn/hybrid.go` — `StartKeepAlives()` function

**Root Cause:** `StartKeepAlives` was called with a `*net.UDPAddr` and sent all
keepalive probes to that fixed address for the lifetime of the goroutine. When
`RunControlLoop` detected a roamed address (via an incoming probe from a different
IP) and updated `IpMap`, `StartKeepAlives` never picked up the new address.

**Effect:** Poll cycle prefers LAN IPs (`192.168.x` or `10.x`). It calls
`StartKeepAlives` with the LAN IP. The hole-punch spray fires to ALL candidates
(including public STUN IPs), one succeeds, `IpMap` updates, but `StartKeepAlives`
keeps pinging the stale LAN IP (a black hole from the other network). After 15s,
it declares the path dead. The next poll cycle's hole-punch spray fires 5 packets,
which arrive fast, counting as 5 pongs — triggering an immediate false recovery.
The cycle repeats every ~15s.

**The Fix (for v2):** Change `StartKeepAlives` signature to take `peerKeyHex string`
and `initialAddr *net.UDPAddr`. On every tick, read `b.IpMap[peerKeyHex]` inside
the loop to get the current roamed address. Fall back to `initialAddr` only if
`IpMap` is nil:
```go
func (b *HybridBind) StartKeepAlives(ctx context.Context, peerKeyHex string, initialAddr *net.UDPAddr) {
    // ...
    for {
        select {
        case <-ticker.C:
            b.mapLock.Lock()
            currentAddr := b.IpMap[peerKeyHex]
            b.mapLock.Unlock()
            if currentAddr == nil {
                currentAddr = initialAddr
            }
            // send probe to currentAddr
        }
    }
}
```

---

## Bug #5 — REAL: `getLocalIPs` Reported VPN Overlay IP as Physical Endpoint
**File:** `cmd/scale-client/setup.go` — `getLocalIPs()` function

**Root Cause:** `getLocalIPs` enumerated ALL non-loopback IPv4 interfaces and
reported them to the control server as physical candidate endpoints. After the
WireGuard `wg0` interface came up, it had a `100.64.x.x` IP which was being
reported as a reachable endpoint.

**Effect (recursive tunnel loop):**
1. Laptop 2 downloaded Laptop 1's `100.64.x.x` IP as a candidate endpoint.
2. Hole-punch spray sent a probe to `100.64.x.x:51820`.
3. OS routing table saw `100.64.x.x` and routed it through `wg0`.
4. WireGuard encrypted the probe and sent it over the relay WebSocket.
5. Laptop 1 received it, decrypted it, and passed it to `HybridBind` via the socket.
6. `RunControlLoop` saw a valid probe, updated `IpMap` and `lastPongTime`.
7. `StartKeepAlives` started sending keepalives into the tunnel (not across real UDP).
8. 15 seconds later, declared dead (correct — the *physical* path was never tested).

**The Fix (for v2):** Filter by CIDR, not interface name. Name-based filtering
(`strings.HasPrefix(i.Name, "wg")`) is brittle. CIDR-based is robust:
```go
_, cgnatPrefix, _ := net.ParseCIDR("100.64.0.0/10")
// In the IP loop:
if cgnatPrefix.Contains(ip) {
    continue
}
```

---

## Deeper Architectural Issue (Not Fixed — Future Work)
### Global `lastPongTime` and `udpFailCount` in HybridBind

These are single fields on the `HybridBind` struct, not keyed per-peer. In a mesh
with >2 active devices, a healthy probe from Peer A resets the shared `lastPongTime`,
which masks a dead connection to Peer B. The HealthMonitor will think the path to
Peer B is fine because Peer A is alive.

**Fix in v2:** Change `lastPongTime`, `udpFailCount`, `udpSuccessCount` to
`map[string]...` types keyed by `peerKeyHex`. Update `RunControlLoop` and
`StartKeepAlives` accordingly. This is a larger refactor — do it as a dedicated PR.

---

## The Remaining Issue After All Fixes (Why We Reverted)

After applying all 4 real fixes, the flapping was eliminated but **WireGuard data
plane did not establish** (pings failed). Root cause analysis:

**Poll cycle endpoint selection prefers LAN IPs** (`192.168.x` / `10.x`) and calls
`WgDevice.IpcSet(endpoint=10.70.143.3)`. This is correct on the same LAN but wrong
cross-NAT (10.70.143.3 is a hotspot private IP, unreachable from home WiFi).

The `SmartTrust / UpdatePeerEndpoint` callback fires and *temporarily* sets the
correct public IP via `IpcSet`. But the next 30s poll cycle runs `replace_peers=true`
which wipes the WireGuard state and resets the endpoint back to the wrong LAN IP.

**Probes (custom magic packets) work** because they follow `IpMap` (roaming-aware).
**WireGuard handshake fails** because it uses the poll-cycle-assigned endpoint.
The HealthMonitor sees probes succeeding and does NOT trigger relay fallback,
so traffic is stuck: probes alive, data dead.

**Fix for v2:** After a `SmartTrust` endpoint update, also update `endpointCache`
so that the next poll cycle uses the roamed IP, not the LAN IP. Or better: in
`performPollCycle`, check `endpointCache` first and prefer it over the server-
provided LAN IP if an entry exists and was recently updated by Smart Trust.

---

## Summary Table

| # | Bug | File | Status |
|---|-----|------|--------|
| 1 | Wrong theory: WireGuard PersistentKeepalive sync | N/A | Disproved |
| 2 | Missing `IpcSet` in recovery branch | `setup.go` | Fixed & reverted |
| 3 | `Send()` falsely resetting fail count | `hybrid.go` | Fixed & reverted |
| 4 | `StartKeepAlives` locked to stale LAN IP | `hybrid.go` | Fixed & reverted |
| 5 | `getLocalIPs` reporting VPN overlay IP | `setup.go` | Fixed & reverted |
| 6 | Global `lastPongTime`/`udpFailCount` (not per-peer) | `hybrid.go` | Documented, not fixed |
| 7 | Poll cycle overwrites Smart Trust endpoint | `setup.go` | Documented, not fixed |
