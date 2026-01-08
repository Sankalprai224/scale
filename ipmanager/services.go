package ipmanager

import (
	"fmt"
	"net"
	"scale/database"
)

const ipPoolKey = "ip_pool:available"

func NewIPAllocator(baseBlock string) (*IPAllocator, error) {
	_, ipNet, err := net.ParseCIDR(baseBlock)
	if err != nil {
		return nil, fmt.Errorf("invalid base block: %v", err)
	}

	poolExists, err := database.Rdb.Exists(database.Ctx, ipPoolKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to check redis for ip pool: %w", err)
	}

	if poolExists == 0 {
		fmt.Println("IP pool not found in Redis, initializing...")
		firstIP, _ := ipToInt(ipNet.IP)
		lastIP := lastIpInBlockInt(ipNet) - 1
		firstUsableIP := firstIP + 1

		pipe := database.Rdb.Pipeline()
		for i := firstUsableIP; i <= lastIP; i++ {
			ipStr := intToIP(i).String()
			pipe.SAdd(database.Ctx, ipPoolKey, ipStr)
		}
		if _, err := pipe.Exec(database.Ctx); err != nil {
			return nil, fmt.Errorf("failed to populate ip pool in redis: %w", err)
		}
		fmt.Printf("Successfully initialized IP pool with %d addresses.\n", (lastIP - firstUsableIP + 1))
	} else {
		fmt.Println("IP pool already initialized in Redis.")
	}

	return &IPAllocator{
		baseIPNet: ipNet,
	}, nil
}

func (a *IPAllocator) AllocateCIDR(prefixLen uint8) (string, error) {
	ip, err := database.Rdb.SPop(database.Ctx, ipPoolKey).Result()
	if err != nil {
		return "", fmt.Errorf("failed to allocate IP from pool: %w", err)
	}

	return fmt.Sprintf("%s/%d", ip, prefixLen), nil
}

func (a *IPAllocator) ReleaseCIDR(block string) error {
	ip, _, err := net.ParseCIDR(block)
	if err != nil {
		return fmt.Errorf("failed to parse CIDR block %s: %v", block, err)
	}

	_, err = database.Rdb.SAdd(database.Ctx, ipPoolKey, ip.String()).Result()
	if err != nil {
		return fmt.Errorf("failed to release ip back to pool: %w", err)
	}
	return nil
}
