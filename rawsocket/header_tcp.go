package rawsocket

import (
	"encoding/binary"
)

// TCP Header size is between 20 to 60 bytes
// https://en.wikipedia.org/wiki/Transmission_Control_Protocol
type TCPHeader struct {
	Src_port    uint16
	Dst_port    uint16
	Seq_num     uint32
	Ack_num     uint32
	Data_offset uint8    // 4 bits, part of uint16
	Reserved    uint8    // 3 bits, part of uint16
	Flags       []string // 9 bits, part of uint16
	Window      uint16
	Checksum    uint16
	Urgent      uint16
	Options     []byte
	Payload     []byte
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

// Convert a TCP header to a byte array
func (tcp *TCPHeader) ToBytes(ip *IPHeader) []byte {
	buf := make([]byte, int(tcp.Data_offset)*4+len(tcp.Payload))
	binary.BigEndian.PutUint16(buf[0:2], tcp.Src_port)
	binary.BigEndian.PutUint16(buf[2:4], tcp.Dst_port)
	binary.BigEndian.PutUint32(buf[4:8], tcp.Seq_num)
	binary.BigEndian.PutUint32(buf[8:12], tcp.Ack_num)
	var combo uint16 = uint16(tcp.Data_offset)<<12 | uint16(tcp.Reserved)<<9 | bitshiftTCPFlags(tcp.Flags)
	binary.BigEndian.PutUint16(buf[12:14], combo)
	binary.BigEndian.PutUint16(buf[14:16], tcp.Window)
	binary.BigEndian.PutUint16(buf[16:18], uint16(0)) // Checksum
	binary.BigEndian.PutUint16(buf[18:20], tcp.Urgent)
	copy(buf[20:], tcp.Options)

	if len(tcp.Payload) > 0 {
		copy(buf[int(tcp.Data_offset)*4:], tcp.Payload)
	}
	// Pad data with zeros until length is minimum 20 bytes
	for i := 0; i < 20-len(buf); i++ {
		buf = append(buf, 0)
	}
	binary.BigEndian.PutUint16(buf[16:18], TCPChecksum(buf, ip))
	return buf
}

// Parse a byte array to a TCP header
func BytesToTCP(data []byte) *TCPHeader {
	tcp := new(TCPHeader)
	tcp.Src_port = binary.BigEndian.Uint16(data[0:2])
	tcp.Dst_port = binary.BigEndian.Uint16(data[2:4])
	tcp.Seq_num = binary.BigEndian.Uint32(data[4:8])
	tcp.Ack_num = binary.BigEndian.Uint32(data[8:12])
	// Read the 4 bit Data_offset + 3 bit Reserved + 9 bit flags as one uint16 (2 bytes)
	var combo uint16 = binary.BigEndian.Uint16(data[12:14])
	// Get the first 4 bits of the combo
	tcp.Data_offset = uint8(combo >> 12)
	// Get the next 3 bits
	tcp.Reserved = uint8(combo>>9) & 0x7
	tcp.Flags = unbitshiftTCPFlags(combo)
	tcp.Window = binary.BigEndian.Uint16(data[14:16])
	tcp.Checksum = binary.BigEndian.Uint16(data[16:18])
	tcp.Urgent = binary.BigEndian.Uint16(data[18:20])
	// Read the rest of data into Options
	if tcp.Data_offset > 5 {
		tcp.Options = data[20 : tcp.Data_offset*4]
	} else {
		tcp.Options = []byte{}
	}
	tcp.Payload = data[tcp.Data_offset*4:]
	return tcp
}

// Wiki: https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Checksum_computation
// Explanation: https://gist.github.com/david-hoze/0c7021434796997a4ca42d7731a7073a
func TCPChecksum(tcp_bytes []byte, ip *IPHeader) uint16 {
	tcp_seg_length := ip.Tot_len - uint16(ip.Ihl*4)
	pseudo_header := make([]byte, 12)
	copy(pseudo_header[0:4], ip.Src_ip.To4())
	copy(pseudo_header[4:8], ip.Dst_ip.To4())
	copy(pseudo_header[8:10], []byte{0, 6})                                             // Fixed 0 and protocol number 6
	copy(pseudo_header[10:12], []byte{byte(tcp_seg_length >> 8), byte(tcp_seg_length)}) // TCP segment length

	// data := make([]byte, 12+int(tcp_seg_length))
	// copy(data[0:12], pseudo_header)
	// copy(data[12:12+int(tcp_seg_length)], tcp_bytes)

	// data := make([]byte, 0, 12+int(tcp_seg_length))
	data := make([]byte, 0)
	data = append(data, pseudo_header...)
	data = append(data, tcp_bytes...)

	// This shit is too hard
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 != 0 { // If data has odd length, make sure to add the last byte
		sum += uint32(data[len(data)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	return uint16(^sum)
}
