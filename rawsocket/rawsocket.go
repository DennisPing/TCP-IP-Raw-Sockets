package rawsocket

import (
	"fmt"
	"syscall"
	"time"
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

	// Linux commands
	// sysctl net.core.rmem_default => default SO_RCVBUF
	// sysctl net.core.rmem_max => max SO_RCVBUF

	// Set the receive buffer size
	err = syscall.SetsockoptInt(sockFd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1024*1024*2) // 2 MB
	if err != nil {
		err := syscall.Close(sockFd)
		if err != nil {
			return -1, err
		}
		return -1, fmt.Errorf("unable to set recv buffer size: %w", err)
	}
	return sockFd, nil
}

// SetTimeout sets a receive timeout on the socket file descriptor.
func SetTimeout(fd int, duration time.Duration) error {
	sec := int64(duration.Seconds())
	usec := (duration % time.Second).Microseconds()

	// Create a Timeval struct
	tv := syscall.Timeval{
		Sec:  sec,
		Usec: usec,
	}

	err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	if err != nil {
		return fmt.Errorf("setsockopt SO_RCVTIMEO: %w", err)
	}

	return nil
}
