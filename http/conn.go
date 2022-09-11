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

	"github.com/DennisPing/TCP-IP-Raw-Sockets/pkg"
	"github.com/DennisPing/TCP-IP-Raw-Sockets/rawsocket"
)

type Conn struct {
	hostname    string
	my_ip       net.IP
	my_port     uint16
	dst_ip      net.IP
	dst_port    uint16
	dst_addr    *syscall.SockaddrInet4 // for syscall convenience
	seq_num     uint32                 // random starting number
	ack_num     uint32
	adwnd       uint16 // advertised window
	mss         uint32 // max segment size
	send_socket int    // send_socket file descriptor
	recv_socket int    // recv_socket file descriptor
}

// Essentially a node in a linked list.
type PayloadTuple struct {
	payload []byte // tcp payload
	next    uint32 // the next seq_num (usually increments by 1460 bytes)
}

// Essentially a linked list with O(1) lookup anywhere. Key: seq_num, Value: PayloadTuple.
type PayloadMap map[uint32]PayloadTuple

// Verbose formatter
var tw *tabwriter.Writer = tabwriter.NewWriter(os.Stdout, 24, 8, 1, '\t', 0)

// Make a new Conn struct that holds stateful information.
func NewConn(hostname string) (*Conn, error) {
	server_ip, err := pkg.LookupRemoteIP(hostname) // Returns a 4 byte IPv4 address
	if err != nil {
		return nil, err
	}
	addr := [4]byte{}
	copy(addr[:], server_ip)
	if pkg.Verbose {
		fmt.Printf("Server IP: %s\n", server_ip.String())
	}
	my_ip, err := pkg.LookupLocalIP()
	if err != nil {
		return nil, err
	}
	rand.Seed(time.Now().UnixNano()) // Seed the random number generator
	send_fd, err := rawsocket.InitSendSocket()
	if err != nil {
		return nil, err
	}
	recv_fd, err := rawsocket.InitRecvSocket()
	if err != nil {
		return nil, err
	}
	return &Conn{
		hostname:    hostname,
		my_ip:       my_ip,
		my_port:     uint16(rand.Intn(65535-49152) + 49152), // random port between 49152 and 65535
		dst_ip:      server_ip,
		dst_port:    80,
		dst_addr:    &syscall.SockaddrInet4{Port: 80, Addr: addr},
		seq_num:     rand.Uint32(),
		ack_num:     0,
		adwnd:       65535,
		mss:         1460,
		send_socket: send_fd,
		recv_socket: recv_fd,
	}, nil
}

// Return an 32-bit option byte slice. Only supports mss and window scale.
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

// The 3 way handshake.
func (c *Conn) Connect() error {
	sockaddr := &syscall.SockaddrInet4{Port: int(c.dst_port)}
	copy(sockaddr.Addr[:], c.dst_ip)
	if err := syscall.Connect(c.send_socket, sockaddr); err != nil {
		return fmt.Errorf("connecting send socket failed: %w", err)
	}
	mss_bytes := c.NewOption("mss", int(c.mss))
	if err := c.SendWithOptions(nil, mss_bytes, []string{"SYN"}); err != nil {
		return fmt.Errorf("1st handshake failed: %w", err)
	}
	if _, _, err := c.recv(2048); err != nil {
		return fmt.Errorf("2nd handshake failed: %w", err)
	}
	if err := c.Send(nil, []string{"ACK"}); err != nil {
		return fmt.Errorf("3rd handshake failed: %w", err)
	}
	return nil
}

// Send a packet with the payload and flags. Used 99% of the time.
func (c *Conn) Send(payload []byte, tcp_flags []string) error {
	packet := c.makePacket(payload, []byte{}, tcp_flags)
	n, err := syscall.Write(c.send_socket, packet)
	if n == 0 {
		return errors.New("sent 0 bytes")
	}
	if err != nil {
		return errors.New("error sending packet: " + err.Error())
	}
	if pkg.Verbose {
		fmt.Fprintf(tw, "--> Send %d bytes\tFlags: %v\tseq: %d, ack: %d\n\n", len(packet), tcp_flags, c.seq_num, c.ack_num)
		tw.Flush()
	}
	return nil
}

// Send a packet with payload, options, and flags. Only used during the 3 way handshake.
func (c *Conn) SendWithOptions(payload, tcp_options []byte, tcp_flags []string) error {
	packet := c.makePacket(payload, tcp_options, tcp_flags)
	n, err := syscall.Write(c.send_socket, packet)
	if n == 0 {
		return errors.New("sent 0 bytes")
	}
	if err != nil {
		return errors.New("error sending packet: " + err.Error())
	}
	if pkg.Verbose {
		fmt.Fprintf(tw, "--> Send %d bytes\tFlags: %v\tseq: %d, ack: %d\n\n", len(packet), tcp_flags, c.seq_num, c.ack_num)
		tw.Flush()
	}
	return nil
}

// Receive all data from the GET request and return the raw payload.
func (c *Conn) RecvAll() ([]byte, error) {
	// First, receive the ACK of the initial GET request
	tcp, _, err := c.recv(2048)
	if err != nil {
		return nil, err
	}
	start_seq := tcp.Seq_num // Hold the 1st seq_num in the linked list

	// Now receive all the incoming packets of the GET response
	payload_map := make(PayloadMap)
	tot_len := 0
	for {
		tcp, done, err := c.recv(2048)
		if err != nil {
			return nil, err
		}
		tot_len += len(tcp.Payload)
		payload_map[tcp.Seq_num] = PayloadTuple{payload: tcp.Payload, next: c.ack_num}
		if !done { // Send ACK and continue receiving
			err = c.Send(nil, []string{"ACK"})
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
	raw_response := c.mergePayloads(payload_map, start_seq, tot_len)
	return *raw_response, nil
}

// Read the next incoming packet and update ack_num and seq_num.
func (c *Conn) recv(bufsize int) (*rawsocket.TCPHeader, bool, error) {
	timeout := time.Now().Add(time.Second * 60)

	buf := make([]byte, bufsize)

	for time.Now().Before(timeout) {
		n, err := syscall.Read(c.recv_socket, buf)
		if err != nil {
			return nil, false, errors.New("Syscall.Read: " + err.Error())
		}
		if n == 0 {
			continue // No data received, loop again
		}
		ip, tcp, err := rawsocket.Unwrap(buf[:n])
		if err != nil {
			return nil, false, err
		}
		if ip.Dst_ip.Equal(c.my_ip) && tcp.Dst_port == c.my_port {
			if pkg.Verbose {
				fmt.Fprintf(tw, "<-- Recv %d bytes\tFlags: %v\tseq: %d, ack: %d\n\n", n, tcp.Flags, tcp.Seq_num, tcp.Ack_num)
				tw.Flush()
			}
			if pkg.Contains(tcp.Flags, []string{"FIN"}) || pkg.Contains(tcp.Flags, []string{"SYN"}) {
				c.seq_num = tcp.Ack_num
				c.ack_num = tcp.Seq_num + uint32(len(tcp.Payload)) + 1
				return tcp, true, nil
			} else if pkg.Contains(tcp.Flags, []string{"ACK"}) {
				c.seq_num = tcp.Ack_num
				c.ack_num = tcp.Seq_num + uint32(len(tcp.Payload))
				return tcp, false, nil
			} else {
				return nil, false, errors.New("unexpected flags: " + fmt.Sprintf("%v\n", tcp.Flags))
			}
		}
	}
	return nil, false, errors.New("recv timeout")
}

// Send the "FIN, ACK" to disconnect from the server.
func (c *Conn) disconnect() error {
	// Since we do use "close" instead of "keep-alive", the server will send us a "FIN, ACK" when it's done.
	// We just send back a "FIN, ACK".
	if err := c.Send(nil, []string{"FIN", "ACK"}); err != nil {
		return fmt.Errorf("error sending FIN, ACK: %w", err)
	}
	if _, _, err := c.recv(2048); err != nil {
		return fmt.Errorf("error receiving final ACK: %w", err)
	}
	return nil
}

// Close the send_socket and recv_socket file descriptors.
func (c *Conn) CloseSockets() error {
	err := syscall.Close(c.send_socket)
	if err != nil {
		return errors.New("error closing send socket: " + err.Error())
	}
	err = syscall.Close(c.recv_socket)
	if err != nil {
		return errors.New("error closing recv socket: " + err.Error())
	}
	return nil
}

// Merge the payloads in the payload_map into a single byte array
func (c *Conn) mergePayloads(payload_map PayloadMap, start_seq uint32, tot_len int) *[]byte {
	merged := make([]byte, 0, tot_len)
	next := start_seq
	for {
		if tuple, ok := payload_map[next]; ok {
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
func (c *Conn) makePacket(payload []byte, tcp_options []byte, tcp_flags []string) []byte {
	ip := rawsocket.IPHeader{
		Version:     4,
		Ihl:         5,
		Tos:         0,
		Tot_len:     1, // Wrap() will fill this in
		Id:          0,
		Flags:       []string{"DF"},
		Frag_offset: 0,
		Ttl:         32,
		Protocol:    6,
		Checksum:    0,
		Src_ip:      c.my_ip,
		Dst_ip:      c.dst_ip,
	}
	data_offset := uint8(5 + len(tcp_options)/4)
	tcp := rawsocket.TCPHeader{
		Src_port:    c.my_port,
		Dst_port:    c.dst_port,
		Seq_num:     c.seq_num,
		Ack_num:     c.ack_num,
		Data_offset: data_offset,
		Reserved:    0,
		Flags:       tcp_flags,
		Window:      c.adwnd,
		Checksum:    0,
		Urgent:      0,
		Options:     tcp_options,
		Payload:     payload,
	}
	return rawsocket.Wrap(&ip, &tcp)
}
