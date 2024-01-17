package rawsocket

import (
	"encoding/binary"
)

type IPFlags uint16

// Bit positions [ RF, DF, MF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ]
const (
	RF IPFlags = 1 << 15
	DF IPFlags = 1 << 14
	MF IPFlags = 1 << 13
)

// IPHeader struct size is 20 bytes for IPv4
// https://en.wikipedia.org/wiki/IPv4#Header
type IPHeader struct {
	Version    uint8 // Always 4
	Ihl        uint8 // Always 5 since we have no options
	Tos        uint8 // Always 0 when we send out, can be 8 when receiving from server
	TotLen     uint16
	Id         uint16
	Flags      IPFlags // 3 bits, part of uint16
	FragOffset uint16  // 13 bits, part of uint16
	Ttl        uint8   // Always 64 when we send out
	Protocol   uint8   // Always 6 for TCP
	Checksum   uint16
	SrcIp      [4]byte
	DstIp      [4]byte
}

// ToBytes converts an IPv4 header into a byte array
func (ip *IPHeader) ToBytes() []byte {
	buf := make([]byte, 20)
	var combo1 uint8 = (ip.Version << 4) | ip.Ihl
	binary.BigEndian.PutUint16(buf[0:2], uint16(combo1)<<8|uint16(ip.Tos))
	binary.BigEndian.PutUint16(buf[2:4], ip.TotLen)
	binary.BigEndian.PutUint16(buf[4:6], ip.Id)
	binary.BigEndian.PutUint16(buf[6:8], uint16(ip.Flags)|ip.FragOffset)
	binary.BigEndian.PutUint16(buf[8:10], uint16(ip.Ttl)<<8|uint16(ip.Protocol))
	// Leave 10-12 as zeros for checksum
	for i, b := range ip.SrcIp {
		buf[12+i] = b
	}
	for i, b := range ip.DstIp {
		buf[16+i] = b
	}
	binary.BigEndian.PutUint16(buf[10:12], IPChecksum(buf))
	return buf
}

// NewIPHeader converts a byte array into an IPv4 header
func NewIPHeader(packet []byte) *IPHeader {
	ip := &IPHeader{
		Version:    packet[0] >> 4,
		Ihl:        packet[0] & 0x0f,
		TotLen:     binary.BigEndian.Uint16(packet[2:4]),
		Id:         binary.BigEndian.Uint16(packet[4:6]),
		Flags:      IPFlags(binary.BigEndian.Uint16(packet[6:8])),
		FragOffset: binary.BigEndian.Uint16(packet[6:8]) & 0x1fff,
		Ttl:        packet[8],
		Protocol:   packet[9],
		Checksum:   binary.BigEndian.Uint16(packet[10:12]),
	}
	for i := 0; i < 4; i++ {
		ip.SrcIp[i] = packet[12+i]
	}
	for i := 0; i < 4; i++ {
		ip.DstIp[i] = packet[16+i]
	}
	return ip
}

// IPChecksum computes the checksum for IPv4
// Wiki: https://en.wikipedia.org/wiki/IPv4_header_checksum
// Explanation: https://gist.github.com/david-hoze/0c7021434796997a4ca42d7731a7073a
func IPChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b)-1; i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return uint16(^sum)
}
