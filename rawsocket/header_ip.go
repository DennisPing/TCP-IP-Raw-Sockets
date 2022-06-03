package rawsocket

import (
	"bytes"
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

// Convert an IPv4 header to a byte array
func (ip *IPHeader) ToBytes() []byte {
	buf := new(bytes.Buffer)
	var combo1 uint8 = (ip.Version << 4) | ip.Ihl
	binary.Write(buf, binary.BigEndian, combo1)
	binary.Write(buf, binary.BigEndian, ip.Tos)
	binary.Write(buf, binary.BigEndian, ip.Tot_len)
	binary.Write(buf, binary.BigEndian, ip.Id)
	// [3 flag bits] + [13 fragment offset bits] = 16 bits
	var combo2 uint16
	flags := bitshiftIPFlags(ip.Flags)
	combo2 = uint16(flags>>5)<<13 | ip.Frag_offset
	binary.Write(buf, binary.BigEndian, combo2)
	binary.Write(buf, binary.BigEndian, ip.Ttl)
	binary.Write(buf, binary.BigEndian, ip.Protocol)
	binary.Write(buf, binary.BigEndian, uint16(0))
	binary.Write(buf, binary.BigEndian, ip.Src_ip.To4())
	binary.Write(buf, binary.BigEndian, ip.Dst_ip.To4())
	data := buf.Bytes()
	// Calculate checksum and set it into the [10:12] bytes
	checksum := IPChecksum(data)
	binary.BigEndian.PutUint16(data[10:12], checksum)
	return data
}

// Parse a packet and to an IPv4 header
func BytesToIP(packet []byte) *IPHeader {
	var ip IPHeader
	reader := bytes.NewReader(packet)
	var combo1 uint8
	binary.Read(reader, binary.BigEndian, &combo1)
	ip.Version = combo1 >> 4
	ip.Ihl = combo1 & 0xf
	binary.Read(reader, binary.BigEndian, &ip.Tos)
	binary.Read(reader, binary.BigEndian, &ip.Tot_len)
	binary.Read(reader, binary.BigEndian, &ip.Id)
	// Read the 3 bit flags + 13 bit fragment offset as one uint16
	var combo2 uint16
	binary.Read(reader, binary.BigEndian, &combo2)
	bitflags := uint8(combo2 >> 8)
	ip.Flags = unbitshiftIPFlags(bitflags)
	ip.Frag_offset = combo2 & 0x1fff // This black magic removes the first 3 bits
	binary.Read(reader, binary.BigEndian, &ip.Ttl)
	binary.Read(reader, binary.BigEndian, &ip.Protocol)
	binary.Read(reader, binary.BigEndian, &ip.Checksum)
	ip.Src_ip = net.IP(make([]byte, 4))
	binary.Read(reader, binary.BigEndian, &ip.Src_ip)
	ip.Dst_ip = net.IP(make([]byte, 4))
	binary.Read(reader, binary.BigEndian, &ip.Dst_ip)
	return &ip
}

// Wiki: https://en.wikipedia.org/wiki/IPv4_header_checksum
// Explanation: https://gist.github.com/david-hoze/0c7021434796997a4ca42d7731a7073a
func IPChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b)-1; i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	return uint16(^sum)
}
