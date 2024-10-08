package rawsocket

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"fmt"
	"io"
	"net/http/httputil"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// Setup variables for testing **********************************************************

var giantPayload string = "485454502f312e3120323030204f4b0d0a446174653a205468752c203331204d61722" +
	"0323032322032303a35383a303220474d540d0a5365727665723a204170616368650d0a55706772616465" +
	"3a2068322c6832630d0a436f6e6e656374696f6e3a20557067726164652c204b6565702d416c6976650d0" +
	"a566172793a204163636570742d456e636f64696e672c557365722d4167656e740d0a436f6e74656e742d" +
	"456e636f64696e673a20677a69700d0a4b6565702d416c6976653a2074696d656f75743d322c206d61783" +
	"d3130300d0a5472616e736665722d456e636f64696e673a206368756e6b65640d0a436f6e74656e742d54" +
	"7970653a20746578742f68746d6c3b20636861727365743d5554462d380d0a0d0a316661610d0a1f8b080" +
	"00000000000036c8f414bc4301085effe8a31e7b65b4151966641da154f5a582f1e43326947d3a424d3d6" +
	"9f6fbb2be8c1d3e3cdc0f7deabae9bd7faedbd3d42cf833b5c559b8053be9302bdd80ea8cc2a03b202dda" +
	"b9890a598d8e60fdb97891d1eda183e5033dceea13ec1dd7d59c2d3e48d1ad0b3720982853a0ce3c418e1" +
	"057909f1937cb78746cd64a0ee83b51e53066d5f3445b5bb407f32fd4a9162265cc61059800e9e57ac140" +
	"b19eea5c19934e66793017962522e4f5a39943745b9753c57bf600c261d69640afe0fe9390c38aa0ec186" +
	"f87fa70c1e530a9a1423ac632dae2eae69bfb34e9ad06bcce0f8857afa6693ec791a868130bcf32b8ec98" +
	"9444281818faa434519582a964e55551d5793045a3bd8e78888fe78ee1a86aaea14f93eecf779df70d359" +
	"9835414c9139c1e7dac273ff6ec53e4aa1e11ed06de4aaa643eae1d54561167b0019e68229a64731cbc1c" +
	"2c94d21cac2090926ae7d3882d0fe6521e4ca07dcb7e21adb1fbefec40e87aa8c5c007418605de1374c86" +
	"cf7e0fcbd5581a5a2cdb14eb6c69d612f394c827c7e60acc625adc3edc8d1e47f7c58d59e5e7a6677e878" +
	"d9b4b5aba40ff9996e477e71638207dbd89e71aec614004641fc9916693e5f02be7416b85a274e329e9df" +
	"5452b012c2cbd6ea29330398c9c75061a9d0326b4eb0cda189b177245d0ec9aa7ed08d18b494999ab98d4" +
	"f0626472f6d3da18a29dbe0ff98a87ade0661203ad7bfe2c44292169ca903495a295dab4eddaa0e062e0e" +
	"8dc321ce1565c87fef191325133c73dce97d9c3d55e4e015e642ad995d0a45c485d6c330a44b788434b74" +
	"4d661665ae346df541c04d032e987d33835c8cff78c2cfa990eefc74f63838437625febef0d70de995ef8" +
	"7e508d79d332f67e8f12565c58f3043cf971592ee4a9b63a4a926562b6408904bc23b01f1d3284d3ad6bd" +
	"a131c7b3cec92c85beb3a2c627e6f9a2e893c8b4d9dae986f281794408f6e97c49e47441fb237a1175552" +
	"3dcee675a6ae65cd334f5d01cfebee6f037a35bd8027389b1382047d5a68498e5c0d96c038371d0e660c4" +
	"5e17b49ded3f9ba44d2ac1405575a3d5cfbc7827984ba282553de7e39fc142e8bd8fb9fb46ad94d180682" +
	"67f215dbf65ad3d028290d522e88aa48edad37c4c1344e70e53ce404a8c4cf77d60e121c2a2171f57a77d" +
	"6bb3363248c6bb9e7dc6350495bea3aa59020a3c6efa592bfde45529a86dc2c2a617943bea8a5b5cde1a6" +
	"dc0c433f2b1001844207e31b130546aeac28ade2115ed7e488c92ea4d125def30d8e287b5692c69bbe46e" +
	"fc3bb478569649f9251457fba25acca81067e3736c56273177017ad2eb73d46501c039fe80e6641dbc090" +
	"a00cbe6e247bdd2c70a194c4e4d9cdce372f182815133f4f0ff1902451349f3b9476b70134d181ad1c0b7" +
	"c8987b9732023a32fa2f1b015509cd97c2b93f1f0ae6dea0eedff47eac0ebe7fdebf323a66eabab47f745" +
	"2c17899852b76bf9476262fa0bca38531a5406e1ad74"

var IphFirstHandshake = IPHeader{
	Version:    4,
	Ihl:        5,
	Tos:        0,
	TotLen:     64,
	Id:         0,
	Flags:      DF,
	FragOffset: 0,
	Ttl:        64,
	Protocol:   6,
	Checksum:   54134,
	SrcIp:      [4]byte{10, 110, 208, 106},
	DstIp:      [4]byte{204, 44, 192, 60},
}

var IphSecondHandshake = IPHeader{
	Version:    4,
	Ihl:        5,
	Tos:        0,
	TotLen:     60,
	Id:         0,
	Flags:      DF,
	FragOffset: 0,
	Ttl:        42,
	Protocol:   6,
	Checksum:   59770,
	SrcIp:      [4]byte{204, 44, 192, 60},
	DstIp:      [4]byte{10, 110, 208, 106},
}

// This is a trivial IP Header. To be used with a TCP Header that contains a payload
var IphWithPayload = IPHeader{
	Version:    4,
	Ihl:        5,
	Tos:        0,
	TotLen:     1426,
	Id:         17988,
	Flags:      DF,
	FragOffset: 0,
	Ttl:        42,
	Protocol:   6,
	Checksum:   40416,
	SrcIp:      [4]byte{204, 44, 192, 60},
	DstIp:      [4]byte{10, 110, 208, 106},
}

var TcphFirstHandshake = TCPHeader{
	SrcPort:    50871,
	DstPort:    80,
	SeqNum:     2753993875,
	AckNum:     0,
	DataOffset: 11,
	Reserved:   0,
	Flags:      SYN,
	Window:     65535,
	Checksum:   37527,
	Urgent:     0,
	Options:    hexToBytes("020405b4010303060101080abb6879f80000000004020000"),
	Payload:    []byte{},
}

var TcphSecondHandshake = TCPHeader{
	SrcPort:    80,
	DstPort:    50871,
	SeqNum:     1654659910,
	AckNum:     2753993876,
	DataOffset: 10,
	Reserved:   0,
	Flags:      SYN | ACK,
	Window:     28960,
	Checksum:   39262,
	Urgent:     0,
	Options:    hexToBytes("0204056a0402080abeb95cb5bb6879f801030307"),
	Payload:    []byte{},
}

var TcphWithPayload = TCPHeader{
	SrcPort:    80,
	DstPort:    50871,
	SeqNum:     1654659911,
	AckNum:     2753994376,
	DataOffset: 8,
	Reserved:   0,
	Flags:      ACK,
	Window:     235,
	Checksum:   29098,
	Urgent:     0,
	Options:    hexToBytes("0101080abeb95f0abb687a45"),
	Payload:    hexToBytes(giantPayload),
}

// Test bit shifting flags **************************************************************

func Test_IPFlags(t *testing.T) {
	type test struct {
		flags  IPFlags // uint16
		binary uint16  // Human readable binary
	}
	tests := []test{
		{
			flags:  RF,
			binary: 0b1000000000000000,
		},
		{
			flags:  DF,
			binary: 0b0100000000000000,
		},
		{
			flags:  MF,
			binary: 0b0010000000000000,
		},
		{
			flags:  DF | MF,
			binary: 0b0110000000000000,
		},
		{
			flags:  RF | DF | MF,
			binary: 0b1110000000000000,
		},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.binary, uint16(tt.flags))

		// Do the reverse
		assert.Equal(t, tt.flags, IPFlags(tt.binary))
	}
}

func Test_TCPFlags(t *testing.T) {
	type test struct {
		flags  TCPFlags // uint8
		binary uint8    // Human readable binary
	}
	tests := []test{
		{
			flags:  FIN,
			binary: 0b00000001,
		},
		{
			flags:  SYN,
			binary: 0b00000010,
		},
		{
			flags:  RST,
			binary: 0b00000100,
		},
		{
			flags:  PSH,
			binary: 0b00001000,
		},
		{
			flags:  ACK,
			binary: 0b00010000,
		},
		{
			flags:  SYN | ACK,
			binary: 0b00010010,
		},
		{
			flags:  FIN | ACK,
			binary: 0b00010001,
		},
		{
			flags:  ACK | PSH | FIN,
			binary: 0b00011001,
		},
		{
			flags:  CWR | ECE | URG | ACK | PSH | RST | SYN | FIN,
			binary: 0b11111111,
		},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.binary, uint8(tt.flags))

		// Do the reverse
		assert.Equal(t, tt.flags, TCPFlags(tt.binary))
	}
}

// Test checksum calculation ************************************************************

func Test_IPChecksumHandshake01(t *testing.T) {
	ipBytes := IphFirstHandshake.ToBytes()
	wiresharkIpHex := "45000040000040004006d3760a6ed06acc2cc03c"
	if IPChecksum(ipBytes) != 0 {
		t.Errorf(Red("1st handshake IP checksum failed"))
		ipHex := hex.EncodeToString(ipBytes)
		printExpGot(wiresharkIpHex, ipHex)
		printHexIdx(ipHex)
	}
	if hex.EncodeToString(ipBytes) != wiresharkIpHex {
		t.Errorf(Red("1st handshake IP encoding failed"))
		ipHex := hex.EncodeToString(ipBytes)
		printExpGot(wiresharkIpHex, ipHex)
		printHexIdx(ipHex)
	}
}

func Test_TCPChecksumHandshake01(t *testing.T) {
	ip := IphFirstHandshake
	tcp := TcphFirstHandshake
	tcpBytes := tcp.ToBytes(&ip)
	wiresharkTcpHex := "c6b70050a4269c9300000000b002ffff92970000020405b4010303060101080abb6879f80000000004020000"
	if TCPChecksum(tcpBytes, &ip) != 0 {
		t.Errorf(Red("1st handshake TCP checksum failed"))
		tcpHex := hex.EncodeToString(tcpBytes)
		printExpGot(wiresharkTcpHex, tcpHex)
		printHexIdx(tcpHex)
	}
	if hex.EncodeToString(tcpBytes) != wiresharkTcpHex {
		t.Errorf(Red("1st handshake TCP encoding failed"))
		tcpHex := hex.EncodeToString(tcpBytes)
		printExpGot(wiresharkTcpHex, tcpHex)
		printHexIdx(tcpHex)
	}
}

func Test_IPChecksumHandshake02(t *testing.T) {
	ip := IphSecondHandshake
	ipBytes := ip.ToBytes()
	wiresharkIpHex := "4500003c000040002a06e97acc2cc03c0a6ed06a"
	if IPChecksum(ipBytes) != 0 {
		t.Errorf(Red("2nd handshake IP checksum failed"))
		ipHex := hex.EncodeToString(ipBytes)
		printExpGot(wiresharkIpHex, ipHex)
		printHexIdx(ipHex)
	}
	if hex.EncodeToString(ipBytes) != wiresharkIpHex {
		t.Errorf(Red("2nd handshake IP encoding failed"))
		ipHex := hex.EncodeToString(ipBytes)
		printExpGot(wiresharkIpHex, ipHex)
		printHexIdx(ipHex)
	}
}

func Test_TCPChecksumHandshake02(t *testing.T) {
	ip := IphSecondHandshake
	tcp := TcphSecondHandshake
	tcpBytes := tcp.ToBytes(&ip)
	wiresharkTcpHex := "0050c6b762a01b46a4269c94a0127120995e00000204056a0402080abeb95cb5bb6879f801030307"

	assert.Equal(t, uint16(0), TCPChecksum(tcpBytes, &ip), "2nd handshake TCP checksum failed")
	assert.Equal(t, wiresharkTcpHex, hex.EncodeToString(tcpBytes), "2nd handshake TCP encoding failed")
}

// This is a trivial test. Just to make sure the next test works properly.
func Test_IPChecksumWithPayload(t *testing.T) {
	ip := IphWithPayload
	ipBytes := ip.ToBytes()
	wiresharkIpHex := "45000592464440002a069de0cc2cc03c0a6ed06a"
	if IPChecksum(ipBytes) != 0 {
		t.Errorf(Red("IP checksum with payload failed"))
		ipHex := hex.EncodeToString(ipBytes)
		printExpGot(wiresharkIpHex, ipHex)
		printHexIdx(ipHex)
	}
	if hex.EncodeToString(ipBytes) != wiresharkIpHex {
		t.Errorf(Red("IP encoding with payload failed"))
		ipHex := hex.EncodeToString(ipBytes)
		printExpGot(wiresharkIpHex, ipHex)
		printHexIdx(ipHex)
	}
}

func Test_TCPChecksumWithPayload(t *testing.T) {
	ip := IphWithPayload
	tcp := TcphWithPayload
	tcpBytes := tcp.ToBytes(&ip)
	wiresharkTcpHex := "0050c6b762a01b47a4269e88801000eb71aa00000101080abeb95f0abb687a45" + giantPayload
	if TCPChecksum(tcpBytes, &ip) != 0 {
		t.Errorf(Red("TCP checksum with payload failed"))
		tcpHex := hex.EncodeToString(tcpBytes)
		printExpGot(wiresharkTcpHex, tcpHex)
		printHexIdx(tcpHex)
	}
	if hex.EncodeToString(tcpBytes) != wiresharkTcpHex {
		t.Errorf(Red("TCP encoding with payload failed"))
		tcpHex := hex.EncodeToString(tcpBytes)
		printExpGot(wiresharkTcpHex, tcpHex)
	}
}

// Test the first payload from the GET response.
func Test_GetResponsePayload(t *testing.T) {
	wiresharkIpHex := "45000592464440002a069de0cc2cc03c0a6ed06a"
	var ip IPHeader = IPHeader{
		Version:    4,
		Ihl:        5,
		Tos:        0,
		TotLen:     1426,
		Id:         17988,
		Flags:      DF,
		FragOffset: 0,
		Ttl:        42,
		Protocol:   6,
		Checksum:   40416,
		SrcIp:      [4]byte{204, 44, 192, 60},
		DstIp:      [4]byte{10, 110, 208, 106},
	}
	ipBytes := ip.ToBytes()
	if IPChecksum(ipBytes) != 0 {
		t.Errorf(Red("IP checksum for GET response failed"))
		ipHex := hex.EncodeToString(ipBytes)
		printExpGot(wiresharkIpHex, ipHex)
		printHexIdx(ipHex)
	}
	if hex.EncodeToString(ipBytes) != wiresharkIpHex {
		t.Errorf(Red("IP encoding for GET response failed"))
		ipHex := hex.EncodeToString(ipBytes)
		printExpGot(wiresharkIpHex, ipHex)
		printHexIdx(ipHex)
	}

	optBytes, _ := hex.DecodeString("0101080abeb95f0abb687a45")
	payloadBytes, _ := hex.DecodeString(giantPayload)
	wiresharkTcpHex := "0050c6b762a01b47a4269e88801000eb71aa00000101080abeb95f0abb687a45" + giantPayload
	var tcp TCPHeader = TCPHeader{
		SrcPort:    80,
		DstPort:    50871,
		SeqNum:     1654659911,
		AckNum:     2753994376,
		DataOffset: 8,
		Reserved:   0,
		Flags:      ACK,
		Window:     235,
		Checksum:   29098,
		Urgent:     0,
		Options:    optBytes,
		Payload:    payloadBytes,
	}
	tcpBytes := tcp.ToBytes(&ip)
	if TCPChecksum(tcpBytes, &ip) != 0 {
		t.Errorf(Red("TCP checksum for GET response failed"))
		tcpHex := hex.EncodeToString(tcpBytes)
		printExpGot(wiresharkTcpHex, tcpHex)
		printHexIdx(tcpHex)
	}
	if hex.EncodeToString(tcpBytes) != wiresharkTcpHex {
		t.Errorf(Red("TCP encoding for GET response failed"))
		tcpHex := hex.EncodeToString(tcpBytes)
		printExpGot(wiresharkTcpHex, tcpHex)
	}
	// Split on []bytes{'/r/n/r/n'}
	split := bytes.Split(tcp.Payload, []byte{'\r', '\n', '\r', '\n'})

	headerBytes := split[0]
	bodyBytes := split[1]

	expHeader := "HTTP/1.1 200 OK\r\n" +
		"Date: Thu, 31 Mar 2022 20:58:02 GMT\r\n" +
		"Server: Apache\r\n" +
		"Upgrade: h2,h2c\r\n" +
		"Connection: Upgrade, Keep-Alive\r\n" +
		"Vary: Accept-Encoding,User-Agent\r\n" +
		"Content-Encoding: gzip\r\n" +
		"Keep-Alive: timeout=2, max=100\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Content-Type: text/html; charset=UTF-8"
	if string(headerBytes) != expHeader {
		t.Errorf(Red("Header for GET response failed"))
	}

	// // Decode chunked encoded body
	r1 := httputil.NewChunkedReader(bytes.NewReader(bodyBytes))
	var buf1 bytes.Buffer
	io.Copy(&buf1, r1)
	bodyBytes = buf1.Bytes()

	// Decode this buf using gzip
	r2, err := gzip.NewReader(bytes.NewReader(bodyBytes))
	if err != nil {
		t.Errorf(Red("Gzip decode failed"))
		fmt.Println(err)
	}
	defer r2.Close()
	var buf2 bytes.Buffer
	io.Copy(&buf2, r2)
	bodyBytes = buf2.Bytes()
	if err != nil {
		t.Errorf(Red("Error reading gzip body"))
	}
	gotBody := string(bodyBytes)

	// Read the exp_body from partial_body.txt file
	expBodyBytes, err := os.ReadFile("./testdata/partial_body.txt")
	if err != nil {
		t.Errorf(Red(err.Error()))
		return // File not found
	}
	expBody := string(expBodyBytes)
	if expBody != gotBody {
		t.Errorf(Red("Body for GET response failed"))
		fmt.Println(gotBody)
	}
}

// Test convert headers to bytes and back to headers ************************************

func Test_ConvertIP01(t *testing.T) {
	ip := IphFirstHandshake
	ipBytes := ip.ToBytes()
	ip2 := NewIPHeader(ipBytes)
	assert.Equal(t, ip, *ip2, "1st handshake IP header conversion failed")
}

func Test_ConvertIP02(t *testing.T) {
	ip := IphSecondHandshake
	ipBytes := ip.ToBytes()
	ip2 := NewIPHeader(ipBytes)
	assert.Equal(t, ip, *ip2, "2nd handshake IP header conversion failed")
}

func Test_ConvertTCP01(t *testing.T) {
	ip := IphFirstHandshake
	tcp := TcphFirstHandshake
	tcpBytes := tcp.ToBytes(&ip)
	tcp2 := NewTCPHeader(tcpBytes)
	assert.Equal(t, tcp, *tcp2, "1st handshake TCP header conversion failed")
}

func Test_ConvertTCP02(t *testing.T) {
	ip := IphSecondHandshake
	tcp := TcphSecondHandshake
	tcpBytes := tcp.ToBytes(&ip)
	tcp2 := NewTCPHeader(tcpBytes)
	assert.Equal(t, tcp, *tcp2, "2nd handshake TCP header conversion failed")
}

func Test_ConvertTCPWithPayload(t *testing.T) {
	ip := IphWithPayload
	tcp := TcphWithPayload
	tcpBytes := tcp.ToBytes(&ip)
	tcp2 := NewTCPHeader(tcpBytes)
	assert.Equal(t, tcp, *tcp2, "TCP header conversion with payload failed")
}

// Test wrapping headers into bytes *****************************************************

func Test_Wrap01(t *testing.T) {
	ip := IphFirstHandshake
	tcp := TcphFirstHandshake
	packet := Wrap(&ip, &tcp)
	packetHex := hex.EncodeToString(packet)
	wiresharkHex := "45000040000040004006d3760a6ed06acc2cc03c" +
		"c6b70050a4269c9300000000b002ffff92970000020405b4010303060101080abb6879f80000000004020000"
	if packetHex != wiresharkHex {
		t.Errorf(Red("1st handshake Wrap packet failed"))
		printExpGot(wiresharkHex, packetHex)
		printHexIdx(packetHex)
	}
}

func Test_Wrap02(t *testing.T) {
	ip := IphSecondHandshake
	tcp := TcphSecondHandshake
	packet := Wrap(&ip, &tcp)
	packetHex := hex.EncodeToString(packet)
	wiresharkHex := "4500003c000040002a06e97acc2cc03c0a6ed06a" +
		"0050c6b762a01b46a4269c94a0127120995e00000204056a0402080abeb95cb5bb6879f801030307"
	if packetHex != wiresharkHex {
		t.Errorf(Red("2nd handshake Wrap packet failed"))
		printExpGot(wiresharkHex, packetHex)
		printHexIdx(packetHex)
	}
}

func Test_WrapWithPayload(t *testing.T) {
	ip := IphWithPayload
	tcp := TcphWithPayload
	packet := Wrap(&ip, &tcp)
	packetHex := hex.EncodeToString(packet)
	wiresharkHex := "45000592464440002a069de0cc2cc03c0a6ed06a" +
		"0050c6b762a01b47a4269e88801000eb71aa00000101080abeb95f0abb687a45" + giantPayload
	if packetHex != wiresharkHex {
		t.Errorf(Red("Wrap packet with payload failed"))
		printExpGot(wiresharkHex, packetHex)
		printHexIdx(packetHex)
	}
}

// Test unwrapping bytes into headers ***************************************************

func Test_Unwrap01(t *testing.T) {
	wiresharkHex := "45000040000040004006d3760a6ed06acc2cc03c" +
		"c6b70050a4269c9300000000b002ffff92970000020405b4010303060101080abb6879f80000000004020000"
	wiresharkBytes, _ := hex.DecodeString(wiresharkHex)
	ip, tcp, err := Unwrap(wiresharkBytes)

	require.NoError(t, err)
	assert.Equal(t, IphFirstHandshake, *ip, "1st handshake IP header unwrap failed")
	assert.Equal(t, TcphFirstHandshake, *tcp, "1st handshake TCP header unwrap failed")
	assert.Equal(t, []byte{}, tcp.Payload, "1st handshake Payload unwrap failed")
}

func Test_Unwrap02(t *testing.T) {
	wiresharkHex := "4500003c000040002a06e97acc2cc03c0a6ed06a" +
		"0050c6b762a01b46a4269c94a0127120995e00000204056a0402080abeb95cb5bb6879f801030307"
	wiresharkBytes, _ := hex.DecodeString(wiresharkHex)
	ip, tcp, err := Unwrap(wiresharkBytes)

	require.NoError(t, err)
	assert.Equal(t, IphSecondHandshake, *ip, "2nd handshake IP header unwrap failed")
	assert.Equal(t, TcphSecondHandshake, *tcp, "2nd handshake TCP header unwrap failed")
	assert.Equal(t, []byte{}, tcp.Payload, "2nd handshake Payload unwrap failed")
}

func Test_UnwrapWithPayload(t *testing.T) {
	wiresharkHex := "45000592464440002a069de0cc2cc03c0a6ed06a" +
		"0050c6b762a01b47a4269e88801000eb71aa00000101080abeb95f0abb687a45" + giantPayload
	wiresharkBytes, _ := hex.DecodeString(wiresharkHex)
	ip, tcp, err := Unwrap(wiresharkBytes)

	require.NoError(t, err)
	assert.Equal(t, IphWithPayload, *ip, "IP header unwrap with payload failed")
	assert.Equal(t, TcphWithPayload, *tcp, "TCP header unwrap with payload failed")
	payloadBytes, _ := hex.DecodeString(giantPayload)
	assert.Equal(t, payloadBytes, tcp.Payload, "Payload unwrap with payload failed")
}

// Test unwrapping a corrupted packet and checking for errors ***************************

func Test_UnwrapCorruptedIP(t *testing.T) {
	wiresharkHex := "45000592464940002a069de0cc2cc03c0a6ed06a" +
		"0050c6b762a01b47a4269e88801000eb71aa00000101080abeb95f0abb687a45" + giantPayload
	wiresharkBytes, _ := hex.DecodeString(wiresharkHex)
	_, _, err := Unwrap(wiresharkBytes)
	if err == nil {
		t.Errorf(Red("Unwrap corrupted IP header failed. Expected an error"))
	}
	if err.Error() != "IP checksum failed" {
		t.Errorf(Red("Unwrap corrupted IP header failed. Wrong error message"))
	}
}

func Test_UnwrapCorruptedTCP(t *testing.T) {
	wiresharkHex := "45000592464440002a069de0cc2cc03c0a6ed06a" +
		"0050c6b762a01b47a4269e87801000eb71aa00000101080abeb95f0abb687a45" + giantPayload
	wiresharkBytes, _ := hex.DecodeString(wiresharkHex)
	_, _, err := Unwrap(wiresharkBytes)
	if err == nil {
		t.Errorf(Red("Unwrap corrupted TCP header failed. Expected an error"))
	}
	if err.Error() != "TCP checksum failed" {
		t.Errorf(Red("Unwrap corrupted TCP header failed. Wrong error message"))
	}
}

func Test_UnwrapCorruptedPayload(t *testing.T) {
	corruptPayload := strings.Replace(giantPayload, "ca", "cb", 1) // Replace 1 character
	wiresharkHex := "45000592464440002a069de0cc2cc03c0a6ed06a" +
		"0050c6b762a01b47a4269e88801000eb71aa00000101080abeb95f0abb687a45" + corruptPayload
	wiresharkBytes, _ := hex.DecodeString(wiresharkHex)
	_, _, err := Unwrap(wiresharkBytes)
	if err == nil {
		t.Errorf(Red("Unwrap corrupted payload failed. Expected an error"))
	}
	if err.Error() != "TCP checksum failed" {
		t.Errorf(Red("Unwrap corrupted payload failed. Wrong error message"))
	}
}

// Test odd TCP segment length **********************************************************

func Test_OddTCPSegmentLength(t *testing.T) { // Holy fuck this was difficult
	ip := IPHeader{
		Version:    4,
		Ihl:        5,
		Tos:        0x20,
		TotLen:     845,
		Id:         21169,
		Flags:      DF,
		FragOffset: 0,
		Ttl:        38,
		Protocol:   6,
		Checksum:   45243,
		SrcIp:      [4]byte{204, 44, 192, 60},
		DstIp:      [4]byte{192, 168, 1, 13},
	}

	options, _ := hex.DecodeString("0101080afdc076540198f657")
	payload, _ := hex.DecodeString("86def98ab4aa04480dfc00ed6d9326edd05f480b5bc3501311c68af6f37b8e13a03b6d1c904a8aedc4cef37320bc23897ca909b8ef3bed95e91b02012b1f047e649c1785d91cc8936730a46df6de15f1bf863424df17ae0f280f7440526fdd7afcf788848f98e491f10946a02ee8e73e32a7e5a4fc74b79dc20012b3c7c82d6f87626c673b1e5e48618c53481de8b226e9c81ed1cf08401f969ea8863a152e0acfea9284b6bd2ea7aaacf57814d5464a2abe50d120847b21e571f51f6a7c6d448b4504a668beedf0ef6316ebd59d98332aaea0b06a1b79434462e24be40c8bba0c586180446fca61722c72026374fde5b0bd0e837558aeabd5f87b474f8b08ee2749b4020faa5ab705b3e65bb99bd51fe5d022256d99b365eb565f257c149888208e650bb189ce13d92e17df7ef0c80bbb2c3664f9725588b214cffaee21abee8d254a017e08803167dd61b636a3be346e164382d2b3a9a7342fcc2d4bfd17d680a8fd50c4dbd3bd48e71f1211f9892b5139620456714c90597c34851b8c3d413f68c30f1d57d7d3200c45ff4a838940020cf0c12960825b7cd19818ddb3e17b2803d281660ffc77cfa5c50d33df0a299cdbde7bdac349289598a67ba77d06dd9b4530254dc4005f24f9548d3fa02c528d09753e64c29cde60554d22181a6064441bdd8257c935152a215767b8a7510cba0c68d060a261d6ac8f174abbb87d4cf8d88b2af05cd2bfe1f5164d53549919815587aec4ef46a0faa2e7b4ba53ed8c0a2c50e8637571a484222be96c5d75d06cff3df1de4749d2b180299bd0749757f68d7d6d3a8a985d81fac623e83c8e0c88d825c644521fa5981e243ee82c96e240a9a3af38e2668ea2c52e5bf08c8e71a599f6b75c36dabb35b185adb68d3c0537dc435496200a194679862b6eb047c81eec4faba6825225f589e6aeed898aaf4909372ac3caffdc40856723416bb6a94b28df3d448cc52e13a8478fb9b6ebf8b1447e423fd6b72980d2df84b08b7b5848f59ad0c53a7d1bee1c86713e6431ef617d32770921fd330323237009a2ec9a9702560c54a1073105d8cc823240e51a949951920becee7201004a85278a6f5800000d0a300d0a0d0a")

	tcp := TCPHeader{
		SrcPort:    80,
		DstPort:    47652,
		SeqNum:     3280096596,
		AckNum:     1563085193,
		DataOffset: 8,
		Reserved:   0,
		Flags:      ACK | PSH,
		Window:     235,
		Checksum:   47864,
		Urgent:     0,
		Options:    options,
		Payload:    payload,
	}
	packet := Wrap(&ip, &tcp)
	ipHeader, tcpHeader, err := Unwrap(packet)
	if err != nil {
		t.Errorf(Red("Expected to get an error, but did not: %s"), err)
	}
	if ip.Checksum != ipHeader.Checksum {
		t.Errorf(Red("IP checksum failed"))
		fmt.Printf("Exp: %d, Got: %d\n", ip.Checksum, ipHeader.Checksum)
	}
	if tcp.Checksum != tcpHeader.Checksum {
		t.Errorf(Red("TCP checksum failed"))
		fmt.Printf("Exp: %d, Got: %d\n", tcp.Checksum, tcpHeader.Checksum)
	}
}

// Random helper functions **************************************************************

// Split a hex string into chunks of 2 for easier debugging: A1 B2 C3 etc
func splitHex(hex string) []string {
	var result []string
	for i := 0; i < len(hex); i += 2 {
		result = append(result, hex[i:i+2])
	}
	return result
}

// Print a slice of indices for easier debugging: 01 02 03 etc
func printHexIdx(hex string) {
	var result []string
	for i := 0; i < len(hex)/2; i++ {
		result = append(result, fmt.Sprintf("%02d", i))
	}
	fmt.Println(Cyan(fmt.Sprintf("Idx: %v", result)))
}

// Print the expected and actual values
func printExpGot(exp, got string) {
	fmt.Printf("Exp: %v\n", splitHex(exp))
	fmt.Printf("Got: %v\n", splitHex(got))
}

func hexToBytes(hexStr string) []byte {
	data, _ := hex.DecodeString(hexStr)
	return data
}
