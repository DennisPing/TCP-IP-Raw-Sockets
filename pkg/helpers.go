package pkg

import (
	"fmt"
	"net"
)

// Global verbose flag
var Verbose bool

// Return true if all elements in slice "small" are in slice "big"
func Contains(big []string, small []string) bool {
	if len(big) < len(small) {
		return false
	}
	if len(big) == 0 || len(small) == 0 {
		return false // Disallow empty slice
	}
	for _, s := range small {
		found := false
		for _, b := range big {
			if s == b {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Find my local IPv4 address
func LookupLocalIP() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		panic(fmt.Sprintln("Network card is not working:", err))
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.To4()
			}
		}
	}
	panic(fmt.Sprintln("Network is down:", err))
}

// Find the IPv4 address of a remote host
func LookupRemoteIP(hostname string) (net.IP, error) {
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve %s", hostname)
	}
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4, nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address found for %s", hostname)
}
