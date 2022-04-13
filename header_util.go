package main

// Unwrap a packet and return (1) IP Header (2) TCP Header (3) Payload in bytes
func UnwrapPacket(packet []byte) (*IPHeader, *TCPHeader, []byte) {
	ip := BytesToIP(packet[:20])
	tcp_size := ip.tot_len - uint16(ip.ihl*4)
	tcp := BytesToTCP(packet[20 : 20+tcp_size])

	payload := make([]byte, 0)
	if ip.tot_len-20-tcp_size > 0 {
		payload = packet[20+tcp_size:]
	}
	return ip, tcp, payload
}

// Wrap (1) IP Header (2) TCP Header (3) Payload in bytes
func WrapPacket(ip *IPHeader, tcp *TCPHeader, payload []byte) []byte {
	ip_bytes := ip.ToBytes()
	tcp_bytes := tcp.ToBytes(ip)
	packet := append(ip_bytes, tcp_bytes...)
	packet = append(packet, payload...)
	return packet
}
