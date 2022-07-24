package rawsocket

import (
	"errors"
)

// The main API for wrapping and unwrapping packets

// Unwrap a packet and return (1) IP Header (2) TCP Header (3) error.
// The Payload is stored inside the TCP Header, if any.
func Unwrap(packet []byte) (*IPHeader, *TCPHeader, error) {
	if IPChecksum(packet[:20]) != 0 {
		return nil, nil, errors.New("IP checksum failed")
	}
	var ip *IPHeader = BytesToIP(packet[:20])
	if TCPChecksum(packet[20:], ip) != 0 {
		return nil, nil, errors.New("TCP checksum failed")
	}
	var tcp *TCPHeader = BytesToTCP(packet[20:])
	return ip, tcp, nil
}

// Wrap (1) IP Header (2) TCP Header into a packet.
// The Payload should be stored inside the TCP Header, if any.
func Wrap(ip *IPHeader, tcp *TCPHeader) []byte {
	ip.Tot_len = uint16(len(ip.ToBytes()) + len(tcp.ToBytes(ip)))
	var packet []byte = append(ip.ToBytes(), tcp.ToBytes(ip)...)
	return packet
}
