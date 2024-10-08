package http

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/DennisPing/TCP-IP-Raw-Sockets/config"
	"github.com/DennisPing/TCP-IP-Raw-Sockets/rawsocket"
)

// Conn is a custom network connection that uses raw sockets
type Conn struct {
	hostname      string
	localAddr     syscall.SockaddrInet4
	remoteAddr    syscall.SockaddrInet4
	advWindow     uint16 // Advertised window
	mss           uint16 // Max segment size
	wScale        uint8  // Window scale
	sendFd        int    // Send file descriptor
	recvFd        int    // Recv file descriptor
	initialSeqNum uint32 // The initial seqNum after connect(). Only used once.
	initialAckNum uint32 // The initial ackNum after connect(). Only used once.
}

// Verbose formatter
var tw *tabwriter.Writer = tabwriter.NewWriter(os.Stdout, 24, 8, 1, '\t', 0)

// NewConn Make a new Conn struct that holds stateful information.
func NewConn(hostname string, timeout time.Duration) (*Conn, error) {
	// Set up remote IP address
	remoteIP, err := getRemoteIP(hostname)
	if err != nil {
		return nil, err
	}
	printDebugf(fmt.Sprintf("Remote IP: %d.%d.%d.%d\n", remoteIP[0], remoteIP[1], remoteIP[2], remoteIP[3]))

	// Set up local IP address
	localIP, err := getLocalIP()
	if err != nil {
		return nil, err
	}
	printDebugf(fmt.Sprintf("Local IP: %d.%d.%d.%d\n", localIP[0], localIP[1], localIP[2], localIP[3]))

	// Choose a random local port between 49152 and 65535
	randomPort := uint16(rand.Intn(65535-49251) + 49152)

	// Set up raw sockets
	sendFd, err := rawsocket.InitSendSocket()
	if err != nil {
		return nil, err
	}

	recvFd, err := rawsocket.InitRecvSocket()
	if err != nil {
		return nil, err
	}

	err = rawsocket.SetTimeout(recvFd, timeout)
	if err != nil {
		return nil, err
	}

	conn := &Conn{
		hostname:   hostname,
		localAddr:  syscall.SockaddrInet4{Port: int(randomPort), Addr: localIP},
		remoteAddr: syscall.SockaddrInet4{Port: 80, Addr: remoteIP},
		advWindow:  65535,
		mss:        1460,
		wScale:     4,
		sendFd:     sendFd,
		recvFd:     recvFd,
	}

	err = conn.connect()
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// SendRequest sends the request to the remote host.
func (c *Conn) SendRequest(req *Request) error {
	err := c.send(c.initialSeqNum, c.initialAckNum, req.ToBytes(), rawsocket.ACK)
	if err != nil {
		return err
	}

	_, err = c.recv() // The ACK from the request
	if err != nil {
		return err
	}

	return nil
}

// RecvResponse receives all data from the GET request and returns a reader as a stream
func (c *Conn) RecvResponse() (io.Reader, error) {
	var nextSeqNum, nextAckNum uint32
	ll := NewLinkedList() // The linked list to store incoming payloads

	for {
		tcp, err := c.recv()
		if err != nil {
			return nil, err
		}

		newNode := &Node{
			seqNum:  tcp.SeqNum,
			payload: tcp.Payload,
		}

		ll.InsertNode(newNode)

		if tcp.Flags&rawsocket.FIN == rawsocket.FIN {
			break // Done
		}

		nextSeqNum, nextAckNum = getNextNumbers(tcp)
		err = c.send(nextSeqNum, nextAckNum, nil, rawsocket.ACK)
		if err != nil {
			return nil, err
		}
	}

	err := c.disconnect(nextSeqNum, nextAckNum)
	if err != nil {
		return nil, err
	}

	return NewLinkedListReader(ll), nil
}

// Close the underlying file descriptors.
func (c *Conn) Close() error {
	err := syscall.Close(c.sendFd)
	if err != nil {
		return err
	}

	err = syscall.Close(c.recvFd)
	if err != nil {
		return err
	}

	return nil
}

// Connect to the remote host via the 3 way handshake.
func (c *Conn) connect() error {
	seqNum := rand.Uint32()
	ackNum := uint32(0)

	err := c.send(seqNum, ackNum, nil, rawsocket.SYN, WithMSS(c.mss), WithWScale(c.wScale))
	if err != nil {
		return fmt.Errorf("1st handshake failed: %w", err)
	}

	tcp, err := c.recv()
	if err != nil {
		return fmt.Errorf("2nd handshake failed: %w", err)
	}

	seqNum, ackNum = getNextNumbers(tcp)
	err = c.send(seqNum, ackNum, nil, rawsocket.ACK)
	if err != nil {
		return fmt.Errorf("3rd handshake failed: %w", err)
	}

	c.initialSeqNum = seqNum
	c.initialAckNum = ackNum
	return nil
}

// Send a single packet to the send socket.
func (c *Conn) send(seqNum uint32, ackNum uint32, payload []byte, tcpFlags rawsocket.TCPFlags, opts ...TCPOptions) error {
	var tcpOptions []byte
	for _, opt := range opts {
		opt(&tcpOptions)
	}

	packet := c.makePacket(seqNum, ackNum, payload, tcpFlags, tcpOptions)

	err := syscall.Sendto(c.sendFd, packet, 0, &c.remoteAddr)
	if err != nil {
		return errors.New("error sending packet: " + err.Error())
	}

	printDebugIO(1, len(packet), tcpFlags, seqNum, ackNum)
	return nil
}

// Receive a single packet from the recv socket.
func (c *Conn) recv() (tcp *rawsocket.TCPHeader, err error) {
	buf := make([]byte, 2048)

	for {
		n, from, err := syscall.Recvfrom(c.recvFd, buf, 0)
		switch {
		case errors.Is(err, syscall.EINTR):
			continue // Try again: https://manpages.ubuntu.com/manpages/noble/en/man7/signal.7.html

		case errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK):
			return nil, fmt.Errorf("timeout reached: %w", err)

		case err != nil:
			return nil, fmt.Errorf("error syscall.Recvfrom: %w", err)
		}

		if from.(*syscall.SockaddrInet4).Addr != c.remoteAddr.Addr {
			continue
		}

		_, tcp, err := rawsocket.Unwrap(buf[:n])
		if err != nil {
			return nil, err
		}

		printDebugIO(0, n, tcp.Flags, tcp.SeqNum, tcp.AckNum)
		return tcp, nil
	}
}

// Send the "FIN, ACK" to disconnect from the server.
func (c *Conn) disconnect(seqNum, ackNum uint32) error {
	err := c.send(seqNum, ackNum, nil, rawsocket.FIN|rawsocket.ACK)
	if err != nil {
		return fmt.Errorf("error sending FIN, ACK: %w", err)
	}

	_, err = c.recv()
	if err != nil {
		return fmt.Errorf("error receiving final ACK: %w", err)
	}
	return nil
}

// Get the next sequence number and ack number based on the TCP flags.
func getNextNumbers(tcp *rawsocket.TCPHeader) (nextSeqNum, nextAckNum uint32) {
	nextSeqNum = tcp.AckNum

	switch {
	case tcp.Flags&(rawsocket.SYN|rawsocket.ACK) == (rawsocket.SYN | rawsocket.ACK):
		nextAckNum = tcp.SeqNum + 1
	case tcp.Flags&rawsocket.SYN == rawsocket.SYN:
		nextAckNum = tcp.SeqNum + 1
	case tcp.Flags&rawsocket.FIN == rawsocket.FIN:
		nextAckNum = tcp.SeqNum + uint32(len(tcp.Payload)) + 1
	case tcp.Flags&rawsocket.ACK == rawsocket.ACK:
		nextAckNum = tcp.SeqNum + uint32(len(tcp.Payload))
	}

	return nextSeqNum, nextAckNum
}

// Make a packet which contains IPheader, TCP header, and payload
func (c *Conn) makePacket(seqNum, ackNum uint32, payload []byte, tcpFlags rawsocket.TCPFlags, tcpOptions []byte) []byte {
	totalLen := 20 + uint16(len(tcpOptions)/4) + uint16(len(payload))
	ip := rawsocket.IPHeader{
		Version:    4,
		Ihl:        5,
		Tos:        0,
		TotLen:     totalLen,
		Id:         0,
		Flags:      rawsocket.DF,
		FragOffset: 0,
		Ttl:        32,
		Protocol:   6,
		Checksum:   0,
		SrcIp:      c.localAddr.Addr,
		DstIp:      c.remoteAddr.Addr,
	}
	dataOffset := 5 + uint8(len(tcpOptions)/4)
	tcp := rawsocket.TCPHeader{
		SrcPort:    uint16(c.localAddr.Port),
		DstPort:    uint16(c.remoteAddr.Port),
		SeqNum:     seqNum,
		AckNum:     ackNum,
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

// Get Remote IP as a literal 4 byte array.
func getRemoteIP(hostname string) ([4]byte, error) {
	remoteIp, err := LookupRemoteIP(hostname)
	if err != nil {
		return [4]byte{}, err
	}
	remoteIpBytes := [4]byte{}
	for i, b := range remoteIp.To4() {
		remoteIpBytes[i] = b
	}
	return remoteIpBytes, nil
}

// Get Local IP as a literal 4 byte array.
func getLocalIP() ([4]byte, error) {
	localIp, err := LookupLocalIP()
	if err != nil {
		return [4]byte{}, err
	}
	localIpBytes := [4]byte{}
	for i, b := range localIp.To4() {
		localIpBytes[i] = b
	}
	return localIpBytes, nil
}

// Print the network I/O if verbose is true.
func printDebugIO(dir int, len int, tcpFlags rawsocket.TCPFlags, seqNum uint32, ackNum uint32) {
	if config.Verbose {
		switch dir {
		case 0:
			_, _ = fmt.Fprintf(tw, "<-- recv %d bytes\tFlags: %v\tseq: %d\tack: %d\n", len, tcpFlags, seqNum, ackNum)
		case 1:
			_, _ = fmt.Fprintf(tw, "--> send %d bytes\tFlags: %v\tseq: %d\tack: %d\n", len, tcpFlags, seqNum, ackNum)
		}
		_ = tw.Flush()
	}
}

// Print a plain string if verbose is true.
func printDebugf(str string) {
	if config.Verbose {
		fmt.Print(str)
	}
}
