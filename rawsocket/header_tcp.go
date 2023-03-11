package rawsocket

import (
	"encoding/binary"
	"strings"
)

type TCPFlags uint8

const (
	// Bit positions [CWR, ECE, URG, ACK, PSH, RST, SYN, FIN]
	CWR TCPFlags = 1 << 7
	ECE TCPFlags = 1 << 6
	URG TCPFlags = 1 << 5
	ACK TCPFlags = 1 << 4
	PSH TCPFlags = 1 << 3
	RST TCPFlags = 1 << 2
	SYN TCPFlags = 1 << 1
	FIN TCPFlags = 1 << 0
)

var tcpFlagsNames = []string{
	"FIN",
	"SYN",
	"RST",
	"PSH",
	"ACK",
	"URG",
	"ECE",
	"CWR",
}

var tcpFlagsMap = make(map[TCPFlags]string)

// Use the binary representation of the flags to generate a string representation
func init() {
	for i := 0; i < 256; i++ {
		var flags TCPFlags
		for j := 0; j < 8; j++ {
			if i&(1<<uint(j)) != 0 {
				flags |= 1 << uint(j)
			}
		}
		var names []string
		for j, name := range tcpFlagsNames {
			if flags&(1<<uint(j)) != 0 {
				names = append(names, name)
			}
		}
		tcpFlagsMap[flags] = strings.Join(names, " ")
	}
}

// Only used for debugging and verbose output
func (f TCPFlags) String() string {
	return tcpFlagsMap[f]
}

// TCP Header size is between 20 to 60 bytes
// https://en.wikipedia.org/wiki/Transmission_Control_Protocol
type TCPHeader struct {
	Src_port    uint16
	Dst_port    uint16
	Seq_num     uint32
	Ack_num     uint32
	Data_offset uint8 // 4 bits, part of uint8
	Reserved    uint8 // 4 bits of 0's, part of uint8
	Flags       TCPFlags
	Window      uint16
	Checksum    uint16
	Urgent      uint16
	Options     []byte
	Payload     []byte
}

// Convert a TCP header into a byte array
func (tcp *TCPHeader) ToBytes(ip *IPHeader) []byte {
	buf := make([]byte, int(tcp.Data_offset)*4+len(tcp.Payload))
	binary.BigEndian.PutUint16(buf[0:2], tcp.Src_port)
	binary.BigEndian.PutUint16(buf[2:4], tcp.Dst_port)
	binary.BigEndian.PutUint32(buf[4:8], tcp.Seq_num)
	binary.BigEndian.PutUint32(buf[8:12], tcp.Ack_num)
	buf[12] = tcp.Data_offset<<4 | tcp.Reserved
	buf[13] = byte(tcp.Flags)
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

// Convert a byte array into a TCP header
func NewTCPHeader(data []byte) *TCPHeader {
	tcp := new(TCPHeader)
	tcp.Src_port = binary.BigEndian.Uint16(data[0:2])
	tcp.Dst_port = binary.BigEndian.Uint16(data[2:4])
	tcp.Seq_num = binary.BigEndian.Uint32(data[4:8])
	tcp.Ack_num = binary.BigEndian.Uint32(data[8:12])
	tcp.Data_offset = data[12] >> 4
	tcp.Reserved = data[12] & 0x0f
	tcp.Flags = TCPFlags(data[13])
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

	data := make([]byte, 12+int(tcp_seg_length))
	copy(data[0:12], pseudo_header)
	copy(data[12:], tcp_bytes)

	// This shit is too hard
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 != 0 { // If data has odd length, make sure to add the last byte
		sum += uint32(data[len(data)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return uint16(^sum)
}
