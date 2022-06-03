package requests

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httputil"
	"syscall"
	"time"

	"github.com/DennisPing/TCP-IP-Raw-Sockets/pkg"
	"github.com/DennisPing/TCP-IP-Raw-Sockets/rawsocket"
)

type Client struct {
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

type PayloadTuple struct {
	data []byte // tcp payload
	next uint32 // the next seq_num
}

// The payloads that have been received. Key is seq_num, Value is PayloadTuple.
type PayloadMap map[uint32]PayloadTuple

// The payloads that have been sent. Key is seq_num, Value is PayloadTuple.
type HistoryMap map[uint32][]PayloadTuple

func InitClient(hostname string) *Client {
	var c Client
	c.hostname = hostname
	c.my_ip = pkg.FindMyIP()
	c.my_port = 54328
	c.dst_ip = net.ParseIP("204.44.192.60").To4()
	c.dst_port = 80
	dst_ip := [4]byte{}
	copy(dst_ip[:], c.dst_ip)
	c.dst_addr = &syscall.SockaddrInet4{Port: int(c.dst_port), Addr: dst_ip}
	// c.seq_num = rand.Uint32()
	c.seq_num = 0
	c.ack_num = 0
	c.adwnd = 4096
	c.mss = 1
	send_socket, err := rawsocket.InitSendSocket(c.dst_ip.String(), int(c.dst_port))
	if err != nil {
		panic(err)
	}
	c.send_socket = send_socket
	recv_socket, err := rawsocket.InitRecvSocket()
	if err != nil {
		panic(err)
	}
	c.recv_socket = recv_socket
	return &c
}

// The 3 way handshake.
func (c *Client) Connect() {
	mss_bytes, _ := hex.DecodeString("020405b4") // Hardcoded mss = 1460 bytes
	err := c.SendWithOptions(nil, mss_bytes, []string{"SYN"})
	if err != nil {
		panic(err)
	}
	_, _, err = c.recv(4096)
	if err != nil {
		panic(err)
	}
	err = c.Send(nil, []string{"ACK"})
	if err != nil {
		panic(err)
	}
}

// Close the TCP connection and socket file descriptors.
func (c *Client) Close() error {
	// Since we do use "close" instead of "keep-alive", the server will send a "FIN, ACK" when it's done.
	// We just send back a "FIN, ACK" as well.
	err := c.Send(nil, []string{"FIN", "ACK"})
	if err != nil {
		return errors.New("error sending FIN, ACK: " + err.Error())
	}
	_, _, err = c.recv(4096)
	if err != nil {
		return errors.New("error receiving final ACK: " + err.Error())
	}
	err = syscall.Close(c.send_socket)
	if err != nil {
		return errors.New("error closing send socket: " + err.Error())
	}
	err = syscall.Close(c.recv_socket)
	if err != nil {
		return errors.New("error closing recv socket: " + err.Error())
	}
	return nil
}

// Send a packet with payload, options, and flags. Only used during the 3 way handshake.
func (c *Client) SendWithOptions(payload []byte, tcp_options []byte, tcp_flags []string) error {
	// You can send an empty byte or nil, it doesn't matter.
	if payload == nil {
		payload = []byte{}
	}
	if tcp_options == nil {
		tcp_options = []byte{}
	}
	packet := c.makePacket(payload, tcp_options, tcp_flags)
	err := syscall.Sendto(c.send_socket, packet, 0, c.dst_addr)
	if err != nil {
		return errors.New("error sending packet: " + err.Error())
	}
	return nil
}

// Send a packet with the payload and flags. Used 99% of the time.
func (c *Client) Send(payload []byte, tcp_flags []string) error {
	// You can send an empty byte or nil, it doesn't matter.
	if payload == nil {
		payload = []byte{}
	}
	packet := c.makePacket(payload, []byte{}, tcp_flags)
	err := syscall.Sendto(c.send_socket, packet, 0, c.dst_addr)
	if err != nil {
		return errors.New("error sending packet: " + err.Error())
	}
	fmt.Printf("Sending out seq_num = %d, ack_num = %d\n", c.seq_num, c.ack_num)
	return nil // Ready to receive all payloads from the server
}

func (c *Client) RecvAll() (*[]byte, error) {
	// First, receive the ACK of the initial GET request
	payload, _, err := c.recv(4096)
	if err != nil {
		return nil, err
	}
	if len(payload) > 0 { // Something went wrong
		return nil, errors.New("expected empty payload, but got: " + string(decodePayload(payload)))
	}
	// Now receive to all the incoming packets of the GET response
	var buf bytes.Buffer
	// payload_map := make(PayloadMap)
	for {
		payload, done, err := c.recv(4096)
		if err != nil {
			return nil, err
		}

		// Check if the last 8 bytes are </html>\n'
		// if len(payload) >= 8 {
		// 	if EqualBytes(payload[len(payload)-8:], []byte("</html>\n")) {
		// 		fmt.Println("Received full payload")
		// 		break
		// 	}
		// }

		// payload_map[c.seq_num] = PayloadTuple{data: payload, next: c.ack_num}
		buf.Write(payload)
		if !done {
			err = c.Send(nil, []string{"ACK"})
			if err != nil {
				return nil, err
			}
		} else {
			err := c.Close() // Send out FIN, ACK and close sockets
			if err != nil {
				return nil, err
			}
			break
		}
	}
	// page := c.mergePayloads(payload_map)
	// fmt.Printf("Size of page: %d\n", len(page))
	raw_response := buf.Bytes()
	return &raw_response, nil
}

// Read the next incoming packet and update ack_num and seq_num.
func (c *Client) recv(bufsize int) ([]byte, bool, error) {
	time_now := time.Now()
	timeout := time_now.Add(time.Second * 60)

	// The buffer used to store the incoming packet.
	packet := make([]byte, bufsize)

	for time_now.Before(timeout) {
		n, err := syscall.Read(c.recv_socket, packet)
		if err != nil {
			return nil, false, err
		}
		ip, tcp, err := rawsocket.Unwrap(packet[:n])
		if err != nil {
			return nil, false, err
		}
		if ip.Dst_ip.Equal(c.my_ip) && tcp.Dst_port == c.my_port {
			fmt.Println("-------------------------------------------------")
			fmt.Printf("Received %d bytes; flags = %v\n", n, tcp.Flags)
			// if len(tcp.payload) > 0 {
			// 	fmt.Printf("%s\n", string(tcp.payload))
			// }
			if pkg.Contains(tcp.Flags, []string{"ACK"}) {
				// return decodePayload(tcp.payload), true, nil
				c.seq_num = tcp.Ack_num
				c.ack_num = tcp.Seq_num + uint32(len(tcp.Payload)) + 1
				return tcp.Payload, true, nil
			}
			if pkg.Contains(tcp.Flags, []string{"SYN"}) {
				c.seq_num = tcp.Ack_num
				c.ack_num = tcp.Seq_num + 1
				return tcp.Payload, false, nil
			}
			if pkg.Contains(tcp.Flags, []string{"ACK"}) {
				c.seq_num = tcp.Ack_num
				c.ack_num = tcp.Seq_num + uint32(len(tcp.Payload))
				// return decodePayload(tcp.payload), false, nil
				return tcp.Payload, false, nil
			} else {
				return nil, false, errors.New("unexpected flags: " + fmt.Sprint(tcp.Flags))
			}
		}
	}
	return nil, false, errors.New("recv timeout")
}

// Decode a payload from chunked encoding to normal encoding.
func decodePayload(payload []byte) []byte {
	if len(payload) == 0 {
		return payload
	}
	var buf bytes.Buffer
	r := httputil.NewChunkedReader(bytes.NewReader(payload))
	io.Copy(&buf, r)
	decoded := buf.Bytes()

	r2, err := gzip.NewReader(bytes.NewReader(decoded))
	if err != nil {
		panic(err)
	}
	defer r2.Close()
	var buf2 bytes.Buffer
	io.Copy(&buf2, r2)
	decompressed := buf2.Bytes()
	if err != nil {
		panic(err)
	}
	return decompressed
}

// func (c *Client) sendSyn() error {
// 	fmt.Println("Sending SYN")
// 	var mss int64 = 1460
// 	// Convert mss to []byte
// 	mss_bytes := make([]byte, 8)
// 	binary.PutVarint(mss_bytes, int64(mss))

// 	// mss_opt, _ := hex.DecodeString("020405b4") // Hardcoded MSS value = 1460
// 	packet := c.makePacket([]byte{}, mss_bytes, []string{"SYN"})
// 	err := syscall.Sendto(c.send_socket, packet, 0, c.dst_addr)
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }

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
	ip := rawsocket.IPHeader{
		Version:     4,
		Ihl:         5,
		Tos:         0,
		Tot_len:     1,
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
