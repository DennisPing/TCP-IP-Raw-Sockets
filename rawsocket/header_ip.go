package rawsocket

import (
	"encoding/binary"
	"net"
)

// IPv4 Header struct size is 20 bytes
// https://en.wikipedia.org/wiki/IPv4#Header
type IPHeader struct {
	Version     uint8 // Always 4
	Ihl         uint8 // Always 5 since we have no options
	Tos         uint8 // Always 0 when we send out, can be 8 when receiving from server
	Tot_len     uint16
	Id          uint16
	Flags       []string // 3 bits, part of uint16
	Frag_offset uint16   // 13 bits, part of uint16
	Ttl         uint8    // Always 64 when we send out
	Protocol    uint8    // Always 6 for TCP
	Checksum    uint16
	Src_ip      net.IP
	Dst_ip      net.IP
}

var IPFlags = map[string]int{
	// The value represents the bit position in the uint8
	"RF": 7,
	"DF": 6,
	"MF": 5,
}

func bitshiftIPFlags(flags []string) uint8 {
	// Bits looks like [RF, DF, MF, 0, 0, 0, 0, 0]
	var combo uint8
	for _, flag := range flags {
		combo |= uint8(1 << IPFlags[flag])
	}
	return combo
}

func unbitshiftIPFlags(bitflags uint8) []string {
	// Bits looks like [RF, DF, MF, 0, 0, 0, 0, 0]
	var flags []string
	for flag, shift := range IPFlags {
		if bitflags&(1<<shift) != 0 {
			flags = append(flags, flag)
		}
	}
	return flags
}

// Convert an IPv4 header into a byte array
func (ip *IPHeader) ToBytes() []byte {
	buf := make([]byte, 20)
	var combo1 uint8 = (ip.Version << 4) | ip.Ihl
	binary.BigEndian.PutUint16(buf[0:2], uint16(combo1)<<8|uint16(ip.Tos))
	binary.BigEndian.PutUint16(buf[2:4], ip.Tot_len)
	binary.BigEndian.PutUint16(buf[4:6], ip.Id)
	// [3 flag bits] + [13 fragment offset bits] = 16 bits
	flags := bitshiftIPFlags(ip.Flags)
	var combo2 uint16 = uint16(flags)<<8 | ip.Frag_offset
	binary.BigEndian.PutUint16(buf[6:8], combo2)
	binary.BigEndian.PutUint16(buf[8:10], uint16(ip.Ttl)<<8|uint16(ip.Protocol))
	binary.BigEndian.PutUint16(buf[10:12], uint16(0)) // Checksum
	var src_ip uint32
	for _, b := range ip.Src_ip.To4() {
		src_ip = (src_ip << 8) | uint32(b)
	}
	binary.BigEndian.PutUint32(buf[12:16], src_ip)
	var dst_ip uint32
	for _, b := range ip.Dst_ip.To4() {
		dst_ip = (dst_ip << 8) | uint32(b)
	}
	binary.BigEndian.PutUint32(buf[16:20], dst_ip)
	binary.BigEndian.PutUint16(buf[10:12], IPChecksum(buf))
	return buf
}

// Convert a byte array into an IPv4 header
func BytesToIP(packet []byte) *IPHeader {
	ip := new(IPHeader)
	ip.Version = packet[0] >> 4
	ip.Ihl = packet[0] & 0xf
	ip.Tot_len = binary.BigEndian.Uint16(packet[2:4])
	ip.Id = binary.BigEndian.Uint16(packet[4:6])
	// Read the 3 bit flags + 13 bit fragment offset as one uint16
	var combo2 uint16 = binary.BigEndian.Uint16(packet[6:8])
	bitflags := uint8(combo2 >> 8)
	ip.Flags = unbitshiftIPFlags(bitflags)
	ip.Frag_offset = combo2 & 0x1fff // This black magic removes the first 3 bits
	ip.Ttl = packet[8]
	ip.Protocol = packet[9]
	ip.Checksum = binary.BigEndian.Uint16(packet[10:12])
	ip.Src_ip = net.IP(make([]byte, 4))
	for i := 0; i < 4; i++ {
		ip.Src_ip[i] = packet[12+i]
	}
	ip.Dst_ip = net.IP(make([]byte, 4))
	for i := 0; i < 4; i++ {
		ip.Dst_ip[i] = packet[16+i]
	}
	return ip
}

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
