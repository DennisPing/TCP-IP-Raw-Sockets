package main

import "syscall"

func InitSocketSender(addr *syscall.SockaddrInet4) int {
	sock_send, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(sock_send)
	err = syscall.Connect(sock_send, addr)
	if err != nil {
		panic(err)
	}
	return sock_send
}

func InitSocketReceiver() int {
	sock_recv, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(sock_recv)
	return sock_recv
}
