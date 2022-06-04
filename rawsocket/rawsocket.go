package rawsocket

import (
	"fmt"
	"syscall"
)

// Create a raw socket for sending packets.
func InitSendSocket() int {
	sock_fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		panic(fmt.Sprintf("error creating sender socket: %s", err.Error()))
	}
	// Allow reusing same port
	err = syscall.SetsockoptInt(sock_fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	if err != nil {
		panic(fmt.Sprintf("error setting SO_REUSEADDR: %s", err.Error()))
	}
	return sock_fd
}

// Create a raw socket for receiving packets.
func InitRecvSocket() int {
	sock_fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		panic(fmt.Sprintf("error creating receiver socket: %s", err.Error()))
	}
	return sock_fd
}
