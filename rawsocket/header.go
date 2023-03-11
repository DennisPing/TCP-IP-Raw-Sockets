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
	var ip *IPHeader = NewIPHeader(packet[:20])
	if TCPChecksum(packet[20:], ip) != 0 {
		return nil, nil, errors.New("TCP checksum failed")
	}
	var tcp *TCPHeader = NewTCPHeader(packet[20:])
	return ip, tcp, nil
}

// Wrap (1) IP Header (2) TCP Header into a packet.
// The Payload should be stored inside the TCP Header, if any.
func Wrap(ip *IPHeader, tcp *TCPHeader) []byte {
	ip.Tot_len = uint16(20 + int(tcp.Data_offset)*4 + len(tcp.Payload))
	packet := make([]byte, ip.Tot_len)
	copy(packet, ip.ToBytes())
	copy(packet[20:], tcp.ToBytes(ip))
	return packet
}
