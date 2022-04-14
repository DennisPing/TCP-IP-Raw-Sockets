package main

import (
	"fmt"
	"strconv"
	"strings"
	"syscall"
)

func InitSendSocket(address string, port int) (int, error) {
	if strings.Count(address, ".") != 4 {
		return -1, fmt.Errorf("invalid IPv4 address: %s", address)
	}
	ip := strings.Split(address, ".") // Convert address into [4]byte
	var ip_bytes [4]byte
	for i := 0; i < 4; i++ {
		b, err := strconv.Atoi(ip[i])
		if err != nil {
			return -1, err
		}
		ip_bytes[i] = byte(b)
	}
	addr := new(syscall.SockaddrInet4)
	addr.Port = port
	addr.Addr = ip_bytes

	send_socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return -1, fmt.Errorf("error creating sender socket: %s", err.Error())
	}
	err = syscall.SetsockoptInt(send_socket, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		return -1, fmt.Errorf("error setting IP_HDRINCL: %s", err.Error())
	}
	err = syscall.Connect(send_socket, addr)
	if err != nil {
		return -1, fmt.Errorf("error connecting to %s:%d: %s", address, port, err.Error())
	}
	return send_socket, nil
}

func InitRecvSocket() (int, error) {
	recv_socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return -1, fmt.Errorf("error creating receiver socket: %s", err.Error())
	}
	return recv_socket, nil
}
