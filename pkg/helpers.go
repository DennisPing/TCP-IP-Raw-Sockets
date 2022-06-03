package pkg

import (
	"net"
	"syscall"
)

// Return true if all elements in slice "small" are in slice "big"
func Contains(big []string, small []string) bool {
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

// Find my IPv4 address
func FindMyIP() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		panic(err) // Network card is not working
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.To4()
			}
		}
	}
	panic(err) // Network is down
}

// Check if two byte slices are equal
func EqualBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// Check if two addresses are equal
func EqualAddr(myaddr syscall.Sockaddr, theiraddr syscall.Sockaddr) bool {
	ipv4a, ok := myaddr.(*syscall.SockaddrInet4)
	if !ok {
		return false
	}
	ipv4b, ok := theiraddr.(*syscall.SockaddrInet4)
	if !ok {
		return false
	}
	if ipv4a.Port != ipv4b.Port {
		return false
	}
	if !EqualBytes(ipv4a.Addr[:], ipv4b.Addr[:]) {
		return false
	}
	return true
}
