package main

// Unwrap a packet and return (1) IP Header (2) TCP Header.
// The Payload is stored inside the TCP Header, if any.
func Unwrap(packet []byte) (*IPHeader, *TCPHeader) {
	ip := BytesToIP(packet[:20])
	tcp := BytesToTCP(packet[20:])
	return ip, tcp
}

// Wrap (1) IP Header (2) TCP Header.
// The Payload should be stored inside the TCP Header, if any.
func Wrap(ip *IPHeader, tcp *TCPHeader) []byte {
	ip_bytes := ip.ToBytes()
	tcp_bytes := tcp.ToBytes(ip)
	packet := append(ip_bytes, tcp_bytes...)
	return packet
}
