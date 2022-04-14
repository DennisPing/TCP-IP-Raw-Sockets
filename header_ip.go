package main

import (
	"bytes"
	"encoding/binary"
	"net"
)

// IPv4 Header struct size is 20 bytes
// https://en.wikipedia.org/wiki/IPv4#Header
type IPHeader struct {
	version     uint8 // Always 4
	ihl         uint8 // Always 5 since we have no options
	tos         uint8 // Usually 0, but can be used to set DSCP (6 bits) + ECN (2 bits)
	tot_len     uint16
	id          uint16
	flags       []string // uint8
	frag_offset uint16   // 13 bits
	ttl         uint8    // Usually 64
	protocol    uint8    // Always 6 for TCP
	checksum    uint16
	src_addr    net.IP
	dst_addr    net.IP
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

// Convert an IPv4 header into a byte array for sending out
func (ip *IPHeader) ToBytes() []byte {
	buf := new(bytes.Buffer)
	var combo1 uint8 = (ip.version << 4) | ip.ihl
	binary.Write(buf, binary.BigEndian, combo1)
	binary.Write(buf, binary.BigEndian, ip.tos)
	binary.Write(buf, binary.BigEndian, ip.tot_len)
	binary.Write(buf, binary.BigEndian, ip.id)
	// [3 flag bits] + [13 fragment offset bits] = 16 bits
	var combo2 uint16
	flags := bitshiftIPFlags(ip.flags)
	combo2 = uint16(flags>>5)<<13 | ip.frag_offset
	binary.Write(buf, binary.BigEndian, combo2)
	binary.Write(buf, binary.BigEndian, ip.ttl)
	binary.Write(buf, binary.BigEndian, ip.protocol)
	binary.Write(buf, binary.BigEndian, uint16(0))
	binary.Write(buf, binary.BigEndian, ip.src_addr.To4())
	binary.Write(buf, binary.BigEndian, ip.dst_addr.To4())
	data := buf.Bytes()
	// Calculate checksum and set it into the [10:12] bytes
	checksum := IPChecksum(data)
	binary.BigEndian.PutUint16(data[10:12], checksum)
	return data
}

// Parse an incoming packet and return an IPv4 header
func BytesToIP(packet []byte) *IPHeader {
	var ip IPHeader
	reader := bytes.NewReader(packet)
	var combo1 uint8
	binary.Read(reader, binary.BigEndian, &combo1)
	ip.version = combo1 >> 4
	ip.ihl = combo1 & 0xf
	binary.Read(reader, binary.BigEndian, &ip.tos)
	binary.Read(reader, binary.BigEndian, &ip.tot_len)
	binary.Read(reader, binary.BigEndian, &ip.id)
	// Read the 3 bit flags + 13 bit fragment offset as one uint16 (2 bytes)
	var combo2 uint16
	binary.Read(reader, binary.BigEndian, &combo2)
	bitflags := uint8(combo2 >> 8)
	ip.flags = unbitshiftIPFlags(bitflags)
	ip.frag_offset = combo2 & 0x1fff // This black magic removes the first 3 bits
	binary.Read(reader, binary.BigEndian, &ip.ttl)
	binary.Read(reader, binary.BigEndian, &ip.protocol)
	binary.Read(reader, binary.BigEndian, &ip.checksum)
	ip.src_addr = net.IP(make([]byte, 4))
	binary.Read(reader, binary.BigEndian, &ip.src_addr)
	ip.dst_addr = net.IP(make([]byte, 4))
	binary.Read(reader, binary.BigEndian, &ip.dst_addr)
	return &ip
}

// Wiki: https://en.wikipedia.org/wiki/IPv4_header_checksum
// RFC 1071: https://datatracker.ietf.org/doc/html/rfc1071
// Explanation: https://gist.github.com/david-hoze/0c7021434796997a4ca42d7731a7073a
func IPChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	return uint16(^sum)
}
