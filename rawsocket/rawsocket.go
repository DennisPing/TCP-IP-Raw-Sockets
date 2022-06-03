package rawsocket

import (
	"fmt"
	"net"
	"syscall"
)

func InitSendSocket(ip string, port int) (int, error) {
	ipv4 := net.ParseIP(ip).To4()
	var ip_bytes [4]byte
	for i := 0; i < 4; i++ {
		ip_bytes[i] = ipv4[i]
	}
	// addr := syscall.SockaddrInet4{Port: port, Addr: ip_bytes}

	send_socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return -1, fmt.Errorf("error creating sender socket: %s", err.Error())
	}
	err = syscall.SetsockoptInt(send_socket, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		return -1, fmt.Errorf("error setting IP_HDRINCL: %s", err.Error())
	}
	// err = syscall.Connect(send_socket, &addr)
	// if err != nil {
	// 	return -1, fmt.Errorf("error connecting to %s:%d: %s", ip, port, err.Error())
	// }
	return send_socket, nil
}

func InitRecvSocket() (int, error) {
	recv_socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return -1, fmt.Errorf("error creating receiver socket: %s", err.Error())
	}
	return recv_socket, nil
}
