package main

import (
	"fmt"
	"syscall"
	"time"
)

func main() {

	// ipHex := "450000340b63400040066df0c0a8010b226bdd52"
	// tcpHex := "d56a0050318b9afdecef2bbb801001f5c19700000101080af31fa208e7c9e12e"
	// combo := ipHex + tcpHex
	// comboBytes, _ := hex.DecodeString(combo)

	// addr := syscall.SockaddrInet4{
	// 	Port: 80,
	// 	Addr: [4]byte{204, 44, 192, 60},
	// }
	// socketSender := InitSocketSender(&addr)
	socketReceiver := InitSocketReceiver()

	// syscall.SetsockoptInt(socketSender, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	// err := syscall.Sendto(socketSender, comboBytes, 0, &addr)
	// if err != nil {
	// 	fmt.Printf("Error sending packet: %s", err)
	// 	return
	// }
	// addr_str := fmt.Sprintf("%d.%d.%d", addr.Addr[0], addr.Addr[1], addr.Addr[2])
	// fmt.Printf("Sent packet to %s:%d\n", addr_str, addr.Port)
	// syscall.Close(socketSender)

	queue := Queue{}
	addresses := Queue{}

	end_time := time.Now().Add(time.Second * 10)
	for time.Now().Before(end_time) {
		buffer := make([]byte, 4096)
		n, addr, err := syscall.Recvfrom(socketReceiver, buffer, 0)
		if err != nil {
			panic(err)
		}
		queue.Enqueue(buffer[:n])
		addresses.Enqueue(addr)
	}

	// While the queue is not empty, get the next packet and print n bytes
	for !queue.IsEmpty() {
		packet := queue.Dequeue().([]byte)
		addr := addresses.Dequeue().(*syscall.SockaddrInet4)
		host := addr.Addr[0:4]
		host_str := fmt.Sprintf("%d.%d.%d.%d", host[0], host[1], host[2], host[3])
		if host_str == "204.44.192.60" {
			ip, _, _ := UnwrapPacket(packet)
			fmt.Printf("%+v\n\n", ip)
			// fmt.Printf("%d, %d\n", IPChecksum(ip.ToBytes()), TCPChecksum(tcp.ToBytes(), ip.src_addr, ip.dst_addr))
		}

		// host_str := fmt.Sprintf("%d.%d.%d.%d", host[0], host[1], host[2], host[3])
		// port := addr.Port
		// fmt.Printf("Received %d bytes from %s:%d\n", len(packet), host_str, port)
		// ipBytes := packet[0:20]
		// ip := BytesToIP(ipBytes)
		// ihl := strconv.FormatUint(uint64(ip.ihl), 10)
		// fmt.Println("IHL: ", ihl)
	}

	syscall.Close(socketReceiver)

}
