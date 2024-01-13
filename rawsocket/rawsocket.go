package rawsocket

import (
	"fmt"
	"syscall"
)

// InitSendSocket creates a raw socket for sending packets.
func InitSendSocket() (int, error) {
	sockFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return -1, fmt.Errorf("unable to create send socket: %w", err)
	}

	// Allow reusing same port
	err = syscall.SetsockoptInt(sockFd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	if err != nil {
		return -1, fmt.Errorf("unable to set SO_REUSEADDR: %w", err)
	}
	return sockFd, nil
}

// InitRecvSocket creates a raw socket for receiving packets.
func InitRecvSocket() (int, error) {
	sockFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return -1, fmt.Errorf("unable to create recv socket: %w", err)
	}
	return sockFd, nil
}
