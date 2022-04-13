package main

import (
	"errors"
)

// Unwrap a packet and return (1) IP Header (2) TCP Header (3) error.
// The Payload is stored inside the TCP Header, if any.
func Unwrap(packet []byte) (*IPHeader, *TCPHeader, error) {
	if IPChecksum(packet[:20]) != 0 {
		return nil, nil, errors.New("IP checksum failed")
	}
	ip := BytesToIP(packet[:20])
	if TCPChecksum(packet[20:], ip) != 0 {
		return nil, nil, errors.New("TCP checksum failed")
	}
	tcp := BytesToTCP(packet[20:])
	return ip, tcp, nil
}

// Wrap (1) IP Header (2) TCP Header.
// The Payload should be stored inside the TCP Header, if any.
func Wrap(ip *IPHeader, tcp *TCPHeader) []byte {
	ip_bytes := ip.ToBytes()
	tcp_bytes := tcp.ToBytes(ip)
	packet := append(ip_bytes, tcp_bytes...)
	return packet
}
