package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"testing"
)

// For console color output *************************************************************

var (
	Black  = Color("\033[1;30m%s\033[0m")
	Red    = Color("\033[1;31m%s\033[0m")
	Green  = Color("\033[1;32m%s\033[0m")
	Yellow = Color("\033[1;33m%s\033[0m")
	Blue   = Color("\033[1;34m%s\033[0m")
	Purple = Color("\033[1;35m%s\033[0m")
	Cyan   = Color("\033[1;36m%s\033[0m")
	Gray   = Color("\033[1;37m%s\033[0m")
)

func Color(colorString string) func(...interface{}) string {
	sprint := func(args ...interface{}) string {
		return fmt.Sprintf(colorString,
			fmt.Sprint(args...))
	}
	return sprint
}

// Test bit shifting flags **************************************************************

func getIPHeaderFirstHandshake(t *testing.T) *IPHeader {
	var ip IPHeader
	var combo1 uint8 = (4 << 4) | 5
	ip.version = combo1 >> 4 // 4
	ip.ihl = combo1 & 0xf    // 5
	ip.tos = uint8(0)
	ip.tot_len = uint16(64)
	ip.flags = []string{"DF"}
	ip.frag_offset = uint16(0)
	ip.ttl = uint8(64)
	ip.protocol = uint8(6)
	ip.checksum = uint16(54134)
	ip.src_addr = net.IPv4(10, 110, 208, 106).To4()
	ip.dst_addr = net.IPv4(204, 44, 192, 60).To4()
	return &ip
}

func getIPHeaderSecondHandshake(t *testing.T) *IPHeader {
	var ip IPHeader
	var combo1 uint8 = (4 << 4) | 5
	ip.version = combo1 >> 4 // 4
	ip.ihl = combo1 & 0xf    // 5
	ip.tos = uint8(0)
	ip.tot_len = uint16(60)
	ip.flags = []string{"DF"}
	ip.frag_offset = uint16(0)
	ip.ttl = uint8(42)
	ip.protocol = uint8(6)
	ip.checksum = uint16(59770)
	ip.src_addr = net.IPv4(204, 44, 192, 60).To4()
	ip.dst_addr = net.IPv4(10, 110, 208, 106).To4()
	return &ip
}

func getTCPHeaderFirstHandshake(t *testing.T) *TCPHeader {
	var tcp TCPHeader
	tcp.src_port = uint16(50871)
	tcp.dst_port = uint16(80)
	tcp.seq_num = uint32(2753993875)
	tcp.ack_num = uint32(0)
	tcp.data_offset = uint8(11)
	tcp.reserved = uint8(0)
	tcp.flags = []string{"SYN"}
	tcp.window = uint16(65535)
	tcp.checksum = uint16(37527)
	tcp.urgent = uint16(0)
	tcp.options, _ = hex.DecodeString("020405b4010303060101080abb6879f80000000004020000")
	return &tcp
}

func getTCPHeaderSecondHandshake(t *testing.T) *TCPHeader {
	var tcp TCPHeader
	tcp.src_port = uint16(80)
	tcp.dst_port = uint16(50871)
	tcp.seq_num = uint32(1654659910)
	tcp.ack_num = uint32(2753993876)
	tcp.data_offset = uint8(10)
	tcp.reserved = uint8(0)
	tcp.flags = []string{"SYN", "ACK"}
	tcp.window = uint16(28960)
	tcp.checksum = uint16(39262)
	tcp.urgent = uint16(0)
	tcp.options, _ = hex.DecodeString("0204056a0402080abeb95cb5bb6879f801030307")
	return &tcp
}

func Test_IPFlagsBitshift01(t *testing.T) {
	flags := []string{"DF"}
	val := bitshiftIPFlags(flags)
	decimal, _ := strconv.ParseInt("01000000", 2, 64)
	ans := uint8(decimal)
	if val != ans {
		t.Errorf(Red("Bit shifting DF failed"))
		fmt.Printf("Exp: %08b\nGot: %08b\n", ans, val)
	}
}

func Test_IPFlagsBitshift02(t *testing.T) {
	flags := []string{"DF", "MF"}
	val := bitshiftIPFlags(flags)
	decimal, _ := strconv.ParseInt("01100000", 2, 64)
	ans := uint8(decimal)
	if val != ans {
		t.Errorf(Red("Bit shifting DF, MF failed"))
		fmt.Printf("Exp: %08b\nGot: %08b\n", ans, val)
	}
}

func Test_IPFlagsBitshift03(t *testing.T) {
	flags := []string{"RF", "DF", "MF"}
	val := bitshiftIPFlags(flags)
	decimal, _ := strconv.ParseInt("11100000", 2, 64)
	ans := uint8(decimal)
	if val != ans {
		t.Errorf(Red("Bit shifting RF, DF, MF failed"))
		fmt.Printf("Exp: %08b\nGot: %08b\n", ans, val)
	}
}

func Test_IPFlagsUnbitshift01(t *testing.T) {
	decimal, _ := strconv.ParseInt("01000000", 2, 64)
	bitflags := uint8(decimal)
	flags := unbitshiftIPFlags(bitflags)
	// Check if flags contains "DF" anywhere
	if len(flags) != 1 && !contains(flags, "DF") {
		t.Errorf(Red("Unbit shifting DF failed"))
		fmt.Printf("Exp: %v\nGot: %v\n", []string{"DF"}, flags)
	}
}

func Test_IPFlagsUnbitshift02(t *testing.T) {
	decimal, _ := strconv.ParseInt("01100000", 2, 64)
	bitflags := uint8(decimal)
	flags := unbitshiftIPFlags(bitflags)
	if len(flags) != 2 && !contains(flags, "DF") && !contains(flags, "MF") {
		t.Errorf(Red("Unbit shifting DF, MF failed"))
		fmt.Printf("Exp: %v\nGot: %v\n", []string{"DF", "MF"}, flags)
	}
}

func Test_IPFlagsUnbitshift03(t *testing.T) {
	decimal, _ := strconv.ParseInt("11100000", 2, 64)
	bitflags := uint8(decimal)
	flags := unbitshiftIPFlags(bitflags)
	if len(flags) != 3 && !contains(flags, "RF") && !contains(flags, "DF") && !contains(flags, "MF") {
		t.Errorf(Red("Unbit shifting RF, DF, MF failed"))
		fmt.Printf("Exp: %v\nGot: %v\n", []string{"RF", "DF", "MF"}, flags)
	}
}

func Test_TCPFlagsBitshift01(t *testing.T) {
	flags := []string{"SYN"}
	val := bitshiftTCPFlags(flags)
	decimal, _ := strconv.ParseInt("000000000000010", 2, 64)
	ans := uint16(decimal)
	if val != ans {
		t.Errorf(Red("Bit shifting SYN failed"))
		fmt.Printf("Exp: %016b\nGot: %016b\n", ans, val)
	}
}

func Test_TCPFlagsBitshift02(t *testing.T) {
	flags := []string{"SYN", "ACK"}
	val := bitshiftTCPFlags(flags)
	decimal, _ := strconv.ParseInt("000000000010010", 2, 64)
	ans := uint16(decimal)
	if val != ans {
		t.Errorf(Red("Bit shifting SYN, ACK failed"))
		fmt.Printf("Exp: %016b\nGot: %016b\n", ans, val)
	}
}

func Test_TCPFlagsUnbitshift01(t *testing.T) {
	decimal, _ := strconv.ParseInt("000000000000010", 2, 64)
	bitflags := uint16(decimal)
	flags := unbitshiftTCPFlags(bitflags)
	if len(flags) != 1 && !contains(flags, "SYN") {
		t.Errorf(Red("Unbit shifting SYN failed"))
		fmt.Printf("Exp: %v\nGot: %v\n", []string{"SYN"}, flags)
	}
}

func Test_TCPFlagsUnbitshift02(t *testing.T) {
	decimal, _ := strconv.ParseInt("000000000010010", 2, 64)
	bitflags := uint16(decimal)
	flags := unbitshiftTCPFlags(bitflags)
	if len(flags) != 2 && !contains(flags, "SYN") && !contains(flags, "ACK") {
		t.Errorf(Red("Unbit shifting SYN, ACK failed"))
		fmt.Printf("Exp: %v\nGot: %v\n", []string{"ACK", "SYN"}, flags)
	}
}

// Test checksum calculation ************************************************************

func Test_IPChecksumHandshake01(t *testing.T) {
	ip := getIPHeaderFirstHandshake(t)
	ip_bytes := ip.ToBytes()
	wireshark_ip_hex := "45000040000040004006d3760a6ed06acc2cc03c"
	if IPChecksum(ip_bytes) != 0 {
		t.Errorf(Red("1st handshake IP checksum failed"))
		ip_hex := hex.EncodeToString(ip_bytes)
		printExpGot(wireshark_ip_hex, ip_hex)
		printHexIdx(ip_hex)
	}
	if hex.EncodeToString(ip_bytes) != wireshark_ip_hex {
		t.Errorf(Red("1st handshake IP encoding failed"))
		ip_hex := hex.EncodeToString(ip_bytes)
		printExpGot(wireshark_ip_hex, ip_hex)
		printHexIdx(ip_hex)
	}
}

func Test_TCPChecksumHandshake01(t *testing.T) {
	ip := getIPHeaderFirstHandshake(t)
	tcp := getTCPHeaderFirstHandshake(t)
	tcp_bytes := tcp.ToBytes(ip)
	wireshark_tcp_hex := "c6b70050a4269c9300000000b002ffff92970000020405b4010303060101080abb6879f80000000004020000"
	if TCPChecksum(tcp_bytes, ip) != 0 {
		t.Errorf(Red("1st handshake TCP checksum failed"))
		tcp_hex := hex.EncodeToString(tcp_bytes)
		printExpGot(wireshark_tcp_hex, tcp_hex)
		printHexIdx(tcp_hex)
	}
	if hex.EncodeToString(tcp_bytes) != wireshark_tcp_hex {
		t.Errorf(Red("1st handshake TCP encoding failed"))
		tcp_hex := hex.EncodeToString(tcp_bytes)
		printExpGot(wireshark_tcp_hex, tcp_hex)
		printHexIdx(tcp_hex)
	}
}

func Test_IPChecksumHandshake02(t *testing.T) {
	ip := getIPHeaderSecondHandshake(t)
	ip_bytes := ip.ToBytes()
	wireshark_ip_hex := "4500003c000040002a06e97acc2cc03c0a6ed06a"
	if IPChecksum(ip_bytes) != 0 {
		t.Errorf(Red("2nd handshake IP checksum failed"))
		ip_hex := hex.EncodeToString(ip_bytes)
		printExpGot(wireshark_ip_hex, ip_hex)
		printHexIdx(ip_hex)
	}
	if hex.EncodeToString(ip_bytes) != wireshark_ip_hex {
		t.Errorf(Red("2nd handshake IP encoding failed"))
		ip_hex := hex.EncodeToString(ip_bytes)
		printExpGot(wireshark_ip_hex, ip_hex)
		printHexIdx(ip_hex)
	}
}

func Test_TCPChecksumHandshake02(t *testing.T) {
	ip := getIPHeaderSecondHandshake(t)
	tcp := getTCPHeaderSecondHandshake(t)
	tcp_bytes := tcp.ToBytes(ip)
	wireshark_tcp_hex := "0050c6b762a01b46a4269c94a0127120995e00000204056a0402080abeb95cb5bb6879f801030307"
	if TCPChecksum(tcp_bytes, ip) != 0 {
		t.Errorf(Red("2nd handshake TCP checksum failed"))
		tcp_hex := hex.EncodeToString(tcp_bytes)
		printExpGot(wireshark_tcp_hex, tcp_hex)
		printHexIdx(tcp_hex)
	}
	if hex.EncodeToString(tcp_bytes) != wireshark_tcp_hex {
		t.Errorf(Red("2nd handshake TCP encoding failed"))
		tcp_hex := hex.EncodeToString(tcp_bytes)
		printExpGot(wireshark_tcp_hex, tcp_hex)
		printHexIdx(tcp_hex)
	}
}

// Test convert headers to bytes and back to headers ************************************

func Test_ConvertIP01(t *testing.T) {
	ip := getIPHeaderFirstHandshake(t)
	ip_bytes := ip.ToBytes()
	ip2 := BytesToIP(ip_bytes)
	if reflect.DeepEqual(ip, ip2) == false {
		t.Errorf(Red("IP header conversion failed"))
		fmt.Printf("Exp: %v\nGot: %v\n", ip, ip2)
	}
}

func Test_ConvertIP02(t *testing.T) {
	ip := getIPHeaderSecondHandshake(t)
	ip_bytes := ip.ToBytes()
	ip2 := BytesToIP(ip_bytes)
	if reflect.DeepEqual(ip, ip2) == false {
		t.Errorf(Red("IP header conversion failed"))
		fmt.Printf("Exp: %v\nGot: %v\n", ip, ip2)
	}
}

func Test_ConvertTCP01(t *testing.T) {
	ip := getIPHeaderFirstHandshake(t)
	tcp := getTCPHeaderFirstHandshake(t)
	tcp_bytes := tcp.ToBytes(ip)
	tcp2 := BytesToTCP(tcp_bytes)
	if compareTCPHeaders(tcp, tcp2) == false {
		t.Errorf(Red("TCP header conversion failed"))
		fmt.Printf("Exp: %v\nGot: %v\n", tcp, tcp2)
	}
}

func Test_ConvertTCP02(t *testing.T) {
	ip := getIPHeaderSecondHandshake(t)
	tcp := getTCPHeaderSecondHandshake(t)
	tcp_bytes := tcp.ToBytes(ip)
	tcp2 := BytesToTCP(tcp_bytes)
	if compareTCPHeaders(tcp, tcp2) == false {
		t.Errorf(Red("TCP header conversion failed"))
		fmt.Printf("Exp: %v\nGot: %v\n", tcp, tcp2)
	}
}

// Test wrapping headers into bytes *****************************************************

func Test_Wrap01(t *testing.T) {
	ip := getIPHeaderFirstHandshake(t)
	tcp := getTCPHeaderFirstHandshake(t)
	payload := []byte{}
	packet := WrapPacket(ip, tcp, payload)
	packet_hex := hex.EncodeToString(packet)
	wireshark_hex := "45000040000040004006d3760a6ed06acc2cc03c" + "c6b70050a4269c9300000000b002ffff92970000020405b4010303060101080abb6879f80000000004020000"
	if packet_hex != wireshark_hex {
		t.Errorf(Red("Wrap packet failed"))
		printExpGot(wireshark_hex, packet_hex)
		printHexIdx(packet_hex)
	}
}

func Test_Wrap02(t *testing.T) {
	ip := getIPHeaderSecondHandshake(t)
	tcp := getTCPHeaderSecondHandshake(t)
	payload := []byte{}
	packet := WrapPacket(ip, tcp, payload)
	packet_hex := hex.EncodeToString(packet)
	wireshark_hex := "4500003c000040002a06e97acc2cc03c0a6ed06a" + "0050c6b762a01b46a4269c94a0127120995e00000204056a0402080abeb95cb5bb6879f801030307"
	if packet_hex != wireshark_hex {
		t.Errorf(Red("Wrap packet failed"))
		printExpGot(wireshark_hex, packet_hex)
		printHexIdx(packet_hex)
	}
}

// Test unwrapping bytes into headers ***************************************************

func Test_Unwrap01(t *testing.T) {
	wireshark_hex := "45000040000040004006d3760a6ed06acc2cc03c" + "c6b70050a4269c9300000000b002ffff92970000020405b4010303060101080abb6879f80000000004020000"
	wireshark_bytes, _ := hex.DecodeString(wireshark_hex)
	ip, tcp, payload := UnwrapPacket(wireshark_bytes)
	if reflect.DeepEqual(ip, getIPHeaderFirstHandshake(t)) == false {
		t.Errorf(Red("IP header unwrap failed"))
		fmt.Printf("Exp: %v\nGot: %v\n", getIPHeaderFirstHandshake(t), ip)
	}
	if compareTCPHeaders(tcp, getTCPHeaderFirstHandshake(t)) == false {
		t.Errorf(Red("TCP header unwrap failed"))
		fmt.Printf("Exp: %v\nGot: %v\n", getTCPHeaderFirstHandshake(t), tcp)
	}
	if reflect.DeepEqual([]byte{}, payload) == false {
		t.Errorf(Red("Payload unwrap failed"))
		fmt.Printf("Exp: %v\nGot: %v\n", []byte{}, payload)
	}
}

func Test_Unwrap02(t *testing.T) {
	wireshark_hex := "4500003c000040002a06e97acc2cc03c0a6ed06a" + "0050c6b762a01b46a4269c94a0127120995e00000204056a0402080abeb95cb5bb6879f801030307"
	wireshark_bytes, _ := hex.DecodeString(wireshark_hex)
	ip, tcp, payload := UnwrapPacket(wireshark_bytes)
	if reflect.DeepEqual(ip, getIPHeaderSecondHandshake(t)) == false {
		t.Errorf(Red("IP header unwrap failed"))
		fmt.Printf("Exp: %v\nGot: %v\n", getIPHeaderSecondHandshake(t), ip)
	}
	if compareTCPHeaders(tcp, getTCPHeaderSecondHandshake(t)) == false {
		t.Errorf(Red("TCP header unwrap failed"))
		fmt.Printf("Exp: %v\nGot: %v\n", getTCPHeaderSecondHandshake(t), tcp)
	}
	if reflect.DeepEqual([]byte{}, payload) == false {
		t.Errorf(Red("Payload unwrap failed"))
		fmt.Printf("Exp: %v\nGot: %v\n", []byte{}, payload)
	}
}

// Random helper functions **************************************************************

func contains(slice []string, str string) bool {
	for _, v := range slice {
		if v == str {
			return true
		}
	}
	return false
}

func splitHex(hex string) []string {
	var result []string
	for i := 0; i < len(hex); i += 2 {
		result = append(result, hex[i:i+2])
	}
	return result
}

func listBytes(len int) []string {
	var result []string
	for i := 0; i < len; i++ {
		result = append(result, fmt.Sprintf("%02d", i))
	}
	return result
}

func printHexIdx(hex string) {
	fmt.Println(Cyan(fmt.Sprintf("Idx: %v", listBytes(len(hex)/2))))
}

func printExpGot(exp, got string) {
	fmt.Printf("Exp: %v\n", splitHex(exp))
	fmt.Printf("Got: %v\n", splitHex(got))
}

func compareTCPHeaders(tcp1 *TCPHeader, tcp2 *TCPHeader) bool {
	if tcp1.src_port != tcp2.src_port {
		return false
	}
	if tcp1.dst_port != tcp2.dst_port {
		return false
	}
	if tcp1.seq_num != tcp2.seq_num {
		return false
	}
	if tcp1.ack_num != tcp2.ack_num {
		return false
	}
	if tcp1.data_offset != tcp2.data_offset {
		return false
	}
	if tcp1.reserved != tcp2.reserved {
		return false
	}
	for _, f1 := range tcp1.flags {
		if !contains(tcp2.flags, f1) {
			return false
		}
	}
	if tcp1.window != tcp2.window {
		return false
	}
	if tcp1.checksum != tcp2.checksum {
		return false
	}
	if tcp1.urgent != tcp2.urgent {
		return false
	}
	if !bytes.Equal(tcp1.options, tcp2.options) {
		return false
	}
	return true
}

// Developer message ********************************************************************

func Test_DeveloperMessage(t *testing.T) {
	fmt.Println(Blue("Dev note: TCPFlags and IPFlags use unordered map, so a manual compare function was created."))
}
