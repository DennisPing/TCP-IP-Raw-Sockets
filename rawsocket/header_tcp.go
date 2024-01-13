package rawsocket

import (
	"encoding/binary"
	"strings"
)

type TCPFlags uint8

// Bit positions [ CWR, ECE, URG, ACK, PSH, RST, SYN, FIN ]
const (
	CWR TCPFlags = 1 << 7
	ECE TCPFlags = 1 << 6
	URG TCPFlags = 1 << 5
	ACK TCPFlags = 1 << 4
	PSH TCPFlags = 1 << 3
	RST TCPFlags = 1 << 2
	SYN TCPFlags = 1 << 1
	FIN TCPFlags = 1 << 0
)

// For debugging purposes
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

// For debugging purposes
func (f TCPFlags) String() string {
	return tcpFlagsMap[f]
}

// TCPHeader size is between 20 and 60 bytes
// https://en.wikipedia.org/wiki/Transmission_Control_Protocol
type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8 // 4 bits, part of uint8
	Reserved   uint8 // 4 bits of 0's, part of uint8
	Flags      TCPFlags
	Window     uint16
	Checksum   uint16
	Urgent     uint16
	Options    []byte
	Payload    []byte
}

// ToBytes converts a TCP header into a byte array
func (tcp *TCPHeader) ToBytes(ip *IPHeader) []byte {
	buf := make([]byte, int(tcp.DataOffset)*4+len(tcp.Payload))
	binary.BigEndian.PutUint16(buf[0:2], tcp.SrcPort)
	binary.BigEndian.PutUint16(buf[2:4], tcp.DstPort)
	binary.BigEndian.PutUint32(buf[4:8], tcp.SeqNum)
	binary.BigEndian.PutUint32(buf[8:12], tcp.AckNum)
	buf[12] = tcp.DataOffset<<4 | tcp.Reserved
	buf[13] = byte(tcp.Flags)
	binary.BigEndian.PutUint16(buf[14:16], tcp.Window)
	// Leave 16-18 as zeros for checksum
	binary.BigEndian.PutUint16(buf[18:20], tcp.Urgent)
	copy(buf[20:], tcp.Options)

	if len(tcp.Payload) > 0 {
		copy(buf[int(tcp.DataOffset)*4:], tcp.Payload)
	}

	binary.BigEndian.PutUint16(buf[16:18], TCPChecksum(buf, ip))
	return buf
}

// NewTCPHeader converts a byte array into a TCP header
func NewTCPHeader(data []byte) *TCPHeader {
	return &TCPHeader{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
		SeqNum:     binary.BigEndian.Uint32(data[4:8]),
		AckNum:     binary.BigEndian.Uint32(data[8:12]),
		DataOffset: data[12] >> 4,
		Reserved:   data[12] & 0x0f,
		Flags:      TCPFlags(data[13]),
		Window:     binary.BigEndian.Uint16(data[14:16]),
		Checksum:   binary.BigEndian.Uint16(data[16:18]),
		Urgent:     binary.BigEndian.Uint16(data[18:20]),
		Options:    data[20 : (data[12]>>4)*4],
		Payload:    data[(data[12]>>4)*4:],
	}
}

// TCPChecksum computes the TCP checksum for IPv4
// Wiki: https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Checksum_computation
// Explanation: https://gist.github.com/david-hoze/0c7021434796997a4ca42d7731a7073a
func TCPChecksum(tcpBytes []byte, ip *IPHeader) uint16 {
	// Entire TCP segment length
	tcpSegLength := ip.TotLen - uint16(ip.Ihl*4)
	var sum uint32

	// Add the pseudo-header values to the sum
	sum += uint32(ip.SrcIp[0])<<8 | uint32(ip.SrcIp[1])
	sum += uint32(ip.SrcIp[2])<<8 | uint32(ip.SrcIp[3])
	sum += uint32(ip.DstIp[0])<<8 | uint32(ip.DstIp[1])
	sum += uint32(ip.DstIp[2])<<8 | uint32(ip.DstIp[3])
	sum += uint32(6) // Protocol number for TCP
	sum += uint32(tcpSegLength)

	// Calculate the sum of the TCP header and payload
	for i := 0; i < len(tcpBytes)-1; i += 2 {
		sum += uint32(tcpBytes[i])<<8 | uint32(tcpBytes[i+1])
	}

	// If tcpBytes has an odd length, add the last byte
	if len(tcpBytes)%2 != 0 {
		sum += uint32(tcpBytes[len(tcpBytes)-1]) << 8
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return uint16(^sum)
}
