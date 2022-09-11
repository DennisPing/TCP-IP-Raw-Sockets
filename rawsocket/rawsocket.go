package rawsocket

import (
	"fmt"
	"syscall"
)

// Create a raw socket for sending packets.
func InitSendSocket() (int, error) {
	sock_fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return -1, fmt.Errorf("unable to create send socket: %w", err)
	}
	// Allow reusing same port
	err = syscall.SetsockoptInt(sock_fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	if err != nil {
		return -1, fmt.Errorf("unable to set SO_REUSEADDR: %w", err)
	}
	return sock_fd, nil
}

// Create a raw socket for receiving packets.
func InitRecvSocket() (int, error) {
	sock_fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return -1, fmt.Errorf("unable to create recv socket: %w", err)
	}
	return sock_fd, nil
}
