package requests

import (
	"bytes"
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

type Client struct {
	verbose     bool // Verbose output
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

// type PayloadTuple struct {
// 	data []byte // tcp payload
// 	next uint32 // the next seq_num
// }

// The payloads that have been received. Key is seq_num, Value is PayloadTuple.
// type PayloadMap map[uint32]PayloadTuple

// The payloads that have been sent. Key is seq_num, Value is PayloadTuple.
// type HistoryMap map[uint32][]PayloadTuple

var tw *tabwriter.Writer // Format verbose output

// Init a new Client struct that holds stateful information.
func NewClient(hostname string, verbose bool) *Client {
	if verbose {
		tw = tabwriter.NewWriter(os.Stdout, 24, 8, 1, '\t', 0)
	}
	server_ip, err := pkg.LookupIPv4(hostname) // Returns a 4 byte IPv4 address
	if err != nil {
		panic(err)
	}
	addr := [4]byte{}
	copy(addr[:], server_ip)
	if verbose {
		fmt.Printf("Server IP: %s\n", server_ip.String())
	}
	rand.Seed(time.Now().UnixNano()) // Seed the random number generator
	return &Client{
		verbose:     verbose,
		hostname:    hostname,
		my_ip:       pkg.FindMyIP(),
		my_port:     uint16(rand.Intn(65535-49152) + 49152), // random port between 49152 and 65535
		dst_ip:      server_ip,
		dst_port:    80,
		dst_addr:    &syscall.SockaddrInet4{Port: 80, Addr: addr},
		seq_num:     rand.Uint32(),
		ack_num:     0,
		adwnd:       65535,
		mss:         1460,
		send_socket: rawsocket.InitSendSocket(),
		recv_socket: rawsocket.InitRecvSocket(),
	}
}

// Return an option byte slice. Only supports mss and window scale.
func (c *Client) NewOption(kind string, value int) []byte {
	switch kind {
	case "mss": // uint32
		return []byte{0x02, 0x04, byte(value >> 8), byte(value & 0xff)}
	case "wscale": // uint16
		return []byte{0x01, 0x03, 0x03, byte(value)} // NOP (0x01) is built in for convenience sake.
	default:
		fmt.Printf("Unsupported TCP option: %s\n", kind)
		return []byte{}
	}
}

// The 3 way handshake.
func (c *Client) Connect() error {
	mss_bytes := c.NewOption("mss", int(c.mss))
	err := c.SendWithOptions(nil, mss_bytes, []string{"SYN"})
	if err != nil {
		return errors.New("1st handshake failed: " + err.Error())
	}
	_, _, err = c.recv(2048)
	if err != nil {
		return errors.New("2nd handshake failed: " + err.Error())
	}
	err = c.Send(nil, []string{"ACK"})
	if err != nil {
		return errors.New("3rd handshake failed: " + err.Error())
	}
	return nil
}

// Send a packet with the payload and flags. Used 99% of the time.
func (c *Client) Send(payload []byte, tcp_flags []string) error {
	packet := c.makePacket(payload, []byte{}, tcp_flags)
	err := syscall.Sendto(c.send_socket, packet, 0, c.dst_addr)
	if err != nil {
		return errors.New("error sending packet: " + err.Error())
	}
	if c.verbose {
		fmt.Fprintf(tw, "--> Send %d bytes\tFlags: %v\tseq: %d, ack: %d\n\n", len(packet), tcp_flags, c.seq_num, c.ack_num)
		tw.Flush()
	}
	return nil
}

// Send a packet with payload, options, and flags. Only used during the 3 way handshake.
func (c *Client) SendWithOptions(payload []byte, tcp_options []byte, tcp_flags []string) error {
	packet := c.makePacket(payload, tcp_options, tcp_flags)
	err := syscall.Sendto(c.send_socket, packet, 0, c.dst_addr)
	if err != nil {
		return errors.New("error sending packet: " + err.Error())
	}
	if c.verbose {
		fmt.Fprintf(tw, "--> Send %d bytes\tFlags: %v\tseq: %d, ack: %d\n\n", len(packet), tcp_flags, c.seq_num, c.ack_num)
		tw.Flush()
	}
	return nil
}

// Receive all data from a GET request and return the raw payload.
func (c *Client) RecvAll() (*[]byte, error) {
	// First, receive the ACK of the initial GET request
	payload, _, err := c.recv(2048)
	if err != nil {
		return nil, err
	}
	if len(payload) > 0 { // Something went wrong
		return nil, errors.New("expected empty payload")
	}
	// Now receive all the incoming packets of the GET response
	var buf bytes.Buffer
	// payload_map := make(PayloadMap)
	for {
		payload, done, err := c.recv(2048)
		if err != nil {
			return nil, err
		}
		// payload_map[c.seq_num] = PayloadTuple{data: payload, next: c.ack_num}
		buf.Write(payload)
		if !done { // Send ACK and continue receiving
			err = c.Send(nil, []string{"ACK"})
			if err != nil {
				return nil, err
			}
		} else {
			err = c.teardown()
			if err != nil {
				return nil, err
			}
			break
		}
	}
	// page := c.mergePayloads(payload_map)
	raw_response := buf.Bytes()
	return &raw_response, nil
}

// Read the next incoming packet and update ack_num and seq_num.
func (c *Client) recv(bufsize int) ([]byte, bool, error) {
	timeout := time.Now().Add(time.Second * 60)

	// The buffer used to store the incoming packet.
	buf := make([]byte, bufsize)

	for time.Now().Before(timeout) {
		n, err := syscall.Read(c.recv_socket, buf)
		if err != nil {
			return nil, false, err
		}
		if n == 0 {
			continue // No data received, loop again
		}
		ip, tcp, err := rawsocket.Unwrap(buf[:n])
		if err != nil {
			return nil, false, err
		}
		if ip.Dst_ip.Equal(c.my_ip) && tcp.Dst_port == c.my_port {
			if c.verbose {
				fmt.Fprintf(tw, "<-- Recv %d bytes\tFlags: %v\tseq: %d, ack: %d\n\n", n, tcp.Flags, tcp.Seq_num, tcp.Ack_num)
				tw.Flush()
			}
			if pkg.Contains(tcp.Flags, []string{"FIN"}) {
				c.seq_num = tcp.Ack_num
				c.ack_num = tcp.Seq_num + uint32(len(tcp.Payload)) + 1
				return tcp.Payload, true, nil
			} else if pkg.Contains(tcp.Flags, []string{"SYN"}) {
				c.seq_num = tcp.Ack_num
				c.ack_num = tcp.Seq_num + 1
				return tcp.Payload, false, nil
			} else if pkg.Contains(tcp.Flags, []string{"ACK"}) {
				c.seq_num = tcp.Ack_num
				c.ack_num = tcp.Seq_num + uint32(len(tcp.Payload))
				return tcp.Payload, false, nil
			} else {
				return nil, false, errors.New("unexpected flags: " + fmt.Sprint(tcp.Flags))
			}
		}
	}
	return nil, false, errors.New("recv timeout")
}

// Send a "FIN, ACK" to tell the server we're done.
func (c *Client) teardown() error {
	// Since we do use "close" instead of "keep-alive", the server will send us a "FIN, ACK" when it's done.
	// We just send back a "FIN, ACK".
	err := c.Send(nil, []string{"FIN", "ACK"})
	if err != nil {
		return errors.New("error sending FIN, ACK: " + err.Error())
	}
	_, _, err = c.recv(2048)
	if err != nil {
		return errors.New("error receiving final ACK: " + err.Error())
	}
	return nil
}

// Close the send_socket and recv_socket file descriptors.
func (c *Client) CloseSockets() error {
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

// func (c *Client) mergePayloads(payload_map PayloadMap) []byte {
// 	data := make([]byte, 0)
// 	next := uint32(0)
// 	for {
// 		if _, ok := payload_map[next]; !ok {
// 			break
// 		}
// 		data = append(data, payload_map[next].data...)
// 		next = payload_map[next].next
// 	}
// 	return data
// }

// Make a packet with a given payload, tcp_options, and tcp_flags.
// Tcp_options should be an empty []byte{} unless you want to set the MSS during SYN.
func (c *Client) makePacket(payload []byte, tcp_options []byte, tcp_flags []string) []byte {
	// For developer safety. We don't like nil.
	if payload == nil {
		payload = []byte{}
	}
	if tcp_options == nil {
		tcp_options = []byte{}
	}
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
	var data_offset uint8
	if len(tcp_options) > 0 {
		data_offset = uint8(6) // MSS option is set
	} else {
		data_offset = uint8(5) // Everything else
	}
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
