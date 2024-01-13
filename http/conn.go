package http

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/DennisPing/TCP-IP-Raw-Sockets/config"
	"github.com/DennisPing/TCP-IP-Raw-Sockets/rawsocket"
)

// Conn is a custom net conn which uses os.File to read and write data streams
type Conn struct {
	hostname   string
	localIp    [4]byte
	localPort  uint16
	remoteIp   [4]byte
	remotePort uint16
	seqNum     uint32 // random starting number
	ackNum     uint32
	advWindow  uint16 // advertised window
	mss        uint32 // max segment size
	sendFile   *os.File
	recvFile   *os.File
	sendConn   net.Conn
	recvConn   net.Conn
}

// PayloadTuple is essentially a node in a linked list.
type PayloadTuple struct {
	payload []byte // tcp payload
	next    uint32 // the next seq_num (usually increments by 1460 bytes)
}

// PayloadMap is essentially a linked list with O(1) lookup anywhere. Key: seq_num, Value: PayloadTuple.
type PayloadMap map[uint32]PayloadTuple

// Verbose formatter
var tw *tabwriter.Writer = tabwriter.NewWriter(os.Stdout, 24, 8, 1, '\t', 0)

// NewConn Make a new Conn struct that holds stateful information.
func NewConn(hostname string) (*Conn, error) {
	// Set up remote IP address
	remoteIp, err := LookupRemoteIP(hostname)
	if err != nil {
		return nil, err
	}
	remoteIpBytes := [4]byte{}
	for i, b := range remoteIp.To4() {
		remoteIpBytes[i] = b
	}
	if config.Verbose {
		fmt.Printf("Remote IP: %s\n", remoteIp)
	}

	// Set up local IP address
	localIp, err := LookupLocalIP()
	if err != nil {
		return nil, err
	}
	localIpBytes := [4]byte{}
	for i, b := range localIp.To4() {
		localIpBytes[i] = b
	}
	if config.Verbose {
		fmt.Printf("Local IP: %s\n", localIp)
	}

	// Choose a random local port
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomPort := uint16(rng.Intn(65535-49152) + 49152) // random port between 49152 and 65535

	// Set up raw sockets
	sendFd, err := rawsocket.InitSendSocket()
	if err != nil {
		return nil, err
	}
	recvFd, err := rawsocket.InitRecvSocket()
	if err != nil {
		return nil, err
	}

	sendFile := os.NewFile(uintptr(sendFd), "send-raw-socket")
	recvFile := os.NewFile(uintptr(recvFd), "recv-raw-socket")

	return &Conn{
		hostname:   hostname,
		localIp:    localIpBytes,
		localPort:  randomPort,
		remoteIp:   remoteIpBytes,
		remotePort: 80,
		seqNum:     rng.Uint32(),
		ackNum:     0,
		advWindow:  65535,
		mss:        1460,
		sendFile:   sendFile,
		recvFile:   recvFile,
	}, nil
}

// NewOption Return an 32-bit option byte slice. Only supports mss and window scale.
func (c *Conn) NewOption(kind string, value int) []byte {
	switch kind {
	case "mss": // uint32
		return []byte{0x02, 0x04, byte(value >> 8), byte(value & 0xff)}
	case "wscale": // uint16
		return []byte{0x01, 0x03, 0x03, byte(value)} // NOP (0x01) is built in for convenience sake.
	default:
		panic(fmt.Sprintf("Unsupported TCP option: %s", kind))
	}
}

// Connect to the remote host via the 3 way handshake.
func (c *Conn) Connect() error {
	opts := c.NewOption("mss", int(c.mss))
	if err := c.SendTo(nil, opts, rawsocket.SYN); err != nil {
		return fmt.Errorf("1st handshake failed: %w", err)
	}
	if _, err := c.RecvFrom(c.remoteIp); err != nil {
		return fmt.Errorf("2nd handshake failed: %w", err)
	}
	if err := c.SendTo(nil, nil, rawsocket.ACK); err != nil {
		return fmt.Errorf("3rd handshake failed: %w", err)
	}

	// Establish the recv and send connections
	recvConn, err := net.FileConn(c.recvFile)
	if err != nil {
		return err
	}
	c.recvConn = recvConn

	sendConn, err := net.FileConn(c.sendFile)
	if err != nil {
		return err
	}
	c.sendConn = sendConn
	return nil
}

// Send a packet with the payload and flags. Used 99% of the time.
func (c *Conn) Send(payload []byte, tcpFlags rawsocket.TCPFlags) error {
	packet := c.makePacket(payload, []byte{}, tcpFlags)
	_, err := c.sendConn.Write(packet)
	if err != nil {
		return errors.New("error sending packet: " + err.Error())
	}
	printDebug(1, len(packet), tcpFlags, c.seqNum, c.ackNum)
	return nil
}

// SendTo sends a packet with payload, options, and flags. Only used during the 3 way handshake.
func (c *Conn) SendTo(payload, tcpOptions []byte, tcpFlags rawsocket.TCPFlags) error {
	packet := c.makePacket(payload, tcpOptions, tcpFlags)

	remoteAddr := syscall.SockaddrInet4{
		Port: int(c.remotePort),
		Addr: c.remoteIp,
	}

	sendFd := c.sendFile.Fd()
	if err := syscall.Sendto(int(sendFd), packet, 0, &remoteAddr); err != nil {
		return fmt.Errorf("error syscall.Sendto: %w", err)
	}
	printDebug(1, len(packet), tcpFlags, c.seqNum, c.ackNum)
	return nil
}

// RecvAll receives all data from the GET request and return the raw payload.
func (c *Conn) RecvAll() ([]byte, error) {
	// 1. Receive the last ACK from the handshake
	tcp, _, err := c.Recv()
	if err != nil {
		return nil, err
	}
	startSeq := tcp.SeqNum // Hold the 1st seqNum in the linked list

	// Now receive all the incoming packets of the GET response
	payloadMap := make(PayloadMap)
	totalLen := 0
	for {
		tcp, done, err := c.Recv()
		if err != nil {
			return nil, err
		}
		totalLen += len(tcp.Payload)
		payloadMap[tcp.SeqNum] = PayloadTuple{payload: tcp.Payload, next: c.ackNum}
		if !done { // Send ACK and continue receiving
			err = c.Send(nil, rawsocket.ACK)
			if err != nil {
				return nil, err
			}
		} else {
			err = c.disconnect()
			if err != nil {
				return nil, err
			}
			break
		}
	}
	rawResponse := c.mergePayloads(payloadMap, startSeq, totalLen)
	return *rawResponse, nil
}

// RecvFrom receives an incoming packet and updates ackNum and seqNum. Only used during the 3 way handshake.
func (c *Conn) RecvFrom(remoteIp [4]byte) (tcp *rawsocket.TCPHeader, err error) {
	timeout := time.Now().Add(time.Second * 10)
	buf := make([]byte, 2048)
	recvFd := c.recvFile.Fd()

	for time.Now().Before(timeout) {
		n, from, err := syscall.Recvfrom(int(recvFd), buf, 0)
		if err != nil {
			return nil, fmt.Errorf("error syscall.Recvfrom: %w", err)
		}
		if from.(*syscall.SockaddrInet4).Addr == remoteIp {
			_, tcp, err := rawsocket.Unwrap(buf[:n])
			if err != nil {
				return nil, err
			}

			printDebug(0, n, tcp.Flags, tcp.SeqNum, tcp.AckNum)

			if (tcp.Flags & rawsocket.SYN) == rawsocket.SYN {
				c.seqNum = tcp.AckNum
				c.ackNum = tcp.SeqNum + uint32(len(tcp.Payload)) + 1
				return tcp, nil
			} else if (tcp.Flags & rawsocket.ACK) == rawsocket.ACK {
				c.seqNum = tcp.AckNum
				c.ackNum = tcp.SeqNum + uint32(len(tcp.Payload))
				return tcp, nil
			} else {
				return nil, errors.New("unexpected flags: " + fmt.Sprintf("%v\n", tcp.Flags))
			}
		}
	}
	return nil, errors.New("recvFrom timeout")
}

// Recv receives the next incoming packet and updates ackNum and seqNum.
func (c *Conn) Recv() (tcp *rawsocket.TCPHeader, done bool, err error) {
	timeout := time.Now().Add(time.Second * 10)
	buf := make([]byte, 2048)

	for time.Now().Before(timeout) {
		n, err := c.recvConn.Read(buf)
		if err != nil {
			return nil, false, fmt.Errorf("error recvConn.Read: %w", err)
		}

		_, tcp, err := rawsocket.Unwrap(buf[:n])
		if err != nil {
			return nil, false, err
		}

		printDebug(0, n, tcp.Flags, tcp.SeqNum, tcp.AckNum)

		if (tcp.Flags&rawsocket.FIN) == rawsocket.FIN || (tcp.Flags&rawsocket.SYN) == rawsocket.SYN {
			c.seqNum = tcp.AckNum
			c.ackNum = tcp.SeqNum + uint32(len(tcp.Payload)) + 1
			return tcp, true, nil
		} else if (tcp.Flags & rawsocket.ACK) == rawsocket.ACK {
			c.seqNum = tcp.AckNum
			c.ackNum = tcp.SeqNum + uint32(len(tcp.Payload))
			return tcp, false, nil
		} else {
			return nil, false, errors.New("unexpected flags: " + fmt.Sprintf("%v\n", tcp.Flags))
		}

	}
	return nil, false, errors.New("recv timeout")
}

// Close closes the underlying file descriptors
func (c *Conn) Close() error {
	if err := c.sendFile.Close(); err != nil {
		return err
	}
	if err := c.recvFile.Close(); err != nil {
		return err
	}
	return nil
}

// Send the "FIN, ACK" to disconnect from the server.
func (c *Conn) disconnect() error {
	// Since we do use "close" instead of "keep-alive", the server will send us a "FIN, ACK" when it's done.
	if err := c.Send(nil, rawsocket.FIN|rawsocket.ACK); err != nil {
		return fmt.Errorf("error sending FIN, ACK: %w", err)
	}
	if _, _, err := c.Recv(); err != nil {
		return fmt.Errorf("error receiving final ACK: %w", err)
	}
	return nil
}

// Merge the payloads in the payload_map into a single byte array
func (c *Conn) mergePayloads(payloadMap PayloadMap, startSeq uint32, totalLen int) *[]byte {
	merged := make([]byte, 0, totalLen)
	next := startSeq
	for {
		if tuple, ok := payloadMap[next]; ok {
			merged = append(merged, tuple.payload...)
			next = tuple.next
		} else {
			break
		}
	}
	return &merged
}

// Make a packet with a given payload, tcp_options, and tcp_flags.
// Tcp_options should be an empty []byte{} unless you want to set the MSS during SYN.
func (c *Conn) makePacket(payload []byte, tcpOptions []byte, tcpFlags rawsocket.TCPFlags) []byte {
	ip := rawsocket.IPHeader{
		Version:    4,
		Ihl:        5,
		Tos:        0,
		TotLen:     1, // Wrap() will fill this in
		Id:         0,
		Flags:      rawsocket.DF,
		FragOffset: 0,
		Ttl:        32,
		Protocol:   6,
		Checksum:   0,
		SrcIp:      c.localIp,
		DstIp:      c.remoteIp,
	}
	dataOffset := uint8(5 + len(tcpOptions)/4)
	tcp := rawsocket.TCPHeader{
		SrcPort:    c.localPort,
		DstPort:    c.remotePort,
		SeqNum:     c.seqNum,
		AckNum:     c.ackNum,
		DataOffset: dataOffset,
		Reserved:   0,
		Flags:      tcpFlags,
		Window:     c.advWindow,
		Checksum:   0,
		Urgent:     0,
		Options:    tcpOptions,
		Payload:    payload,
	}
	return rawsocket.Wrap(&ip, &tcp)
}

// printDebug prints the network actions of Conn if verbose is true
func printDebug(dir int, len int, tcpFlags rawsocket.TCPFlags, seqNum uint32, ackNum uint32) {
	if config.Verbose {
		switch dir {
		case 0:
			_, _ = fmt.Fprintf(tw, "<-- Recv %d bytes\tFlags: %v\tseq: %d, ack: %d\n\n", len, tcpFlags, seqNum, ackNum)
		case 1:
			_, _ = fmt.Fprintf(tw, "--> Send %d bytes\tFlags: %v\tseq: %d, ack: %d\n\n", len, tcpFlags, seqNum, ackNum)
		}
		_ = tw.Flush()
	}
}
