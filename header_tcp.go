package main

import (
	"bytes"
	"encoding/binary"
)

// TCP Header size is between 20 to 60 bytes
// https://en.wikipedia.org/wiki/Transmission_Control_Protocol
type TCPHeader struct {
	src_port    uint16
	dst_port    uint16
	seq_num     uint32
	ack_num     uint32
	data_offset uint8    // 4 bits, part of uint16
	reserved    uint8    // 3 bits, part of uint16
	flags       []string // 9 bits, part of uint16
	window      uint16
	checksum    uint16
	urgent      uint16
	options     []byte
}

var TCPFlags = map[string]int{
	// The value represents the bit position in the uint16
	"NS":  8,
	"CWR": 7,
	"ECE": 6,
	"URG": 5,
	"ACK": 4,
	"PSH": 3,
	"RST": 2,
	"SYN": 1,
	"FIN": 0,
}

func bitshiftTCPFlags(flags []string) uint16 {
	var combo uint16
	for _, flag := range flags {
		combo |= uint16(1 << TCPFlags[flag])
	}
	return combo
}

func unbitshiftTCPFlags(bitflags uint16) []string {
	// Bits look like [0,0,0,0,0,0,0,NS,CWR,ECE,URG,ACK,PSH,RST,SYN,FIN]
	var flags []string
	for flag, shift := range TCPFlags {
		if bitflags&(1<<shift) != 0 {
			flags = append(flags, flag)
		}
	}
	return flags
}

// Marshal the TCP header into a byte array for sending out
func (tcp *TCPHeader) ToBytes(ip *IPHeader) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, tcp.src_port)
	binary.Write(buf, binary.BigEndian, tcp.dst_port)
	binary.Write(buf, binary.BigEndian, tcp.seq_num)
	binary.Write(buf, binary.BigEndian, tcp.ack_num)
	// var combo uint16
	var combo uint16
	combo = uint16(tcp.data_offset) << 12
	combo |= uint16(tcp.reserved) << 9
	combo |= bitshiftTCPFlags(tcp.flags)
	binary.Write(buf, binary.BigEndian, combo)
	binary.Write(buf, binary.BigEndian, tcp.window)
	binary.Write(buf, binary.BigEndian, uint16(0)) // Checksum
	binary.Write(buf, binary.BigEndian, tcp.urgent)
	binary.Write(buf, binary.BigEndian, tcp.options)
	data := buf.Bytes()
	// Pad data with zeros until length is minimum 20 bytes
	for i := 0; i < 20-len(data); i++ {
		data = append(data, 0)
	}
	checksum := TCPChecksum(data, ip)
	binary.BigEndian.PutUint16(data[16:18], checksum)
	return data
}

// Parse a byte array and return a TCP header
func BytesToTCP(data []byte) *TCPHeader {
	tcp := new(TCPHeader)
	reader := bytes.NewReader(data)
	binary.Read(reader, binary.BigEndian, &tcp.src_port)
	binary.Read(reader, binary.BigEndian, &tcp.dst_port)
	binary.Read(reader, binary.BigEndian, &tcp.seq_num)
	binary.Read(reader, binary.BigEndian, &tcp.ack_num)
	// Read the 4 bit data_offset + 3 bit reserved + 9 bit flags as one uint16 (2 bytes)
	var combo uint16
	binary.Read(reader, binary.BigEndian, &combo)
	// Get the first 4 bits of the combo
	tcp.data_offset = uint8(combo >> 12)
	// Get the next 3 bits
	tcp.reserved = uint8(combo>>9) & 0x7
	tcp.flags = unbitshiftTCPFlags(combo)
	binary.Read(reader, binary.BigEndian, &tcp.window)
	binary.Read(reader, binary.BigEndian, &tcp.checksum)
	binary.Read(reader, binary.BigEndian, &tcp.urgent)
	// Read the rest of data into options
	if tcp.data_offset > 5 {
		tcp.options = data[20 : tcp.data_offset*4]
	} else {
		tcp.options = make([]byte, 0)
	}
	return tcp
}

// Wiki: https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Checksum_computation
// Explanation: https://gist.github.com/david-hoze/0c7021434796997a4ca42d7731a7073a
func TCPChecksum(b []byte, ip *IPHeader) uint16 {
	pseudo_header := make([]byte, 12)
	copy(pseudo_header[0:4], ip.src_addr.To4())
	copy(pseudo_header[4:8], ip.dst_addr.To4())
	copy(pseudo_header[8:10], []byte{0, 6})             // Fixed 0 and protocol number 6
	copy(pseudo_header[10:12], []byte{0, byte(len(b))}) // Length of b
	data := make([]byte, 0, len(pseudo_header)+len(b))
	data = append(data, pseudo_header...)
	data = append(data, b...)

	// This shit is too hard
	// https://stackoverflow.com/questions/62329005/how-to-calculate-tcp-packet-checksum-correctly
	var word uint16
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		word = uint16(data[i])<<8 | uint16(data[i+1])
		sum += uint32(word)
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1])
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)

	return uint16(^sum)
}
