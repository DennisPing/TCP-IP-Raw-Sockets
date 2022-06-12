![Build](https://github.com/DennisPing/TCP-IP-Raw-Sockets/actions/workflows/go.yml/badge.svg)
![Coverage](https://img.shields.io/badge/Coverage-91.1%25-brightgreen)

# TCP/IP Raw Sockets

Matthew Jones  
Dennis Ping  

## Overview

**TL;DR - Make an HTTP GET request from scratch; from the network layer to the application layer.**

This project was originally done in Python and converted to Go for self-learning purposes.

This program called `rawhttpget` that takes one URL, downloads the target URL page, and saves it into the current directory. The TCP/IP network stack are custom implemented, and all incoming & outgoing data packets utilize raw sockets. Due to the low-level details and bitwise operations of this project, unit testing was done to ensure correctness. Manual debugging was also done on Wireshark.

## Requirements

Go 1.16+

This project only works on Linux.

## Required System Changes

1. Modify iptables rule
```
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```

2. Find your "network interface" name using: `ifconfig -a`
```
sudo ethtool -K <network interface> gro off
sudo ethtool -K <network interface> tx off rx off
```

3. Example
```
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
sudo ethtool -K wlp4s0 gro off
sudo ethtool -K wlp4s0 tx off rx off
```

## How to Build

```
make
```

## How to Run

```
sudo ./rawhttpget [-v] URL
```

The optional flag `-v` is for verbose output.

Examples

```
sudo ./rawhttpget -v http://david.choffnes.com/classes/cs4700sp22/project4.php
sudo ./rawhttpget http://david.choffnes.com/classes/cs4700sp22/10MB.log
```

## Testing

Standard mode
```
go test
```
Verbose mode
```
go test -v
```

Test coverage
```
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

This will show a GUI in your browser window :heart_eyes:

## Example Run in Verbose Mode

```
> sudo ./rawhttpget -v http://david.choffnes.com/classes/cs4700sp22/project4.php
Server IP: 204.44.192.60
--> Send 44 bytes	Flags: [SYN]		seq: 1527861304, ack: 0

<-- Recv 44 bytes	Flags: [SYN ACK]	seq: 338724193, ack: 1527861305

--> Send 40 bytes	Flags: [ACK]		seq: 1527861305, ack: 338724194

--> Send 157 bytes	Flags: [ACK PSH]	seq: 1527861305, ack: 338724194

<-- Recv 40 bytes	Flags: [ACK]		seq: 338724194, ack: 1527861422

<-- Recv 1500 bytes	Flags: [ACK]		seq: 338724194, ack: 1527861422

--> Send 40 bytes	Flags: [ACK]		seq: 1527861422, ack: 338725654

<-- Recv 1500 bytes	Flags: [ACK PSH]	seq: 338725654, ack: 1527861422

--> Send 40 bytes	Flags: [ACK]		seq: 1527861422, ack: 338727114

<-- Recv 1500 bytes	Flags: [ACK]		seq: 338727114, ack: 1527861422

--> Send 40 bytes	Flags: [ACK]		seq: 1527861422, ack: 338728574

<-- Recv 1500 bytes	Flags: [ACK PSH]	seq: 338728574, ack: 1527861422

--> Send 40 bytes	Flags: [ACK]		seq: 1527861422, ack: 338730034

<-- Recv 1500 bytes	Flags: [ACK]		seq: 338730034, ack: 1527861422

--> Send 40 bytes	Flags: [ACK]		seq: 1527861422, ack: 338731494

<-- Recv 1500 bytes	Flags: [ACK]		seq: 338731494, ack: 1527861422

--> Send 40 bytes	Flags: [ACK]		seq: 1527861422, ack: 338732954

<-- Recv 1500 bytes	Flags: [ACK]		seq: 338732954, ack: 1527861422

--> Send 40 bytes	Flags: [ACK]		seq: 1527861422, ack: 338734414

<-- Recv 385 bytes	Flags: [ACK PSH FIN]	seq: 338734414, ack: 1527861422

--> Send 40 bytes	Flags: [FIN ACK]	seq: 1527861422, ack: 338734760

<-- Recv 40 bytes	Flags: [ACK]		seq: 338734760, ack: 1527861423

200 OK
Wrote 22636 bytes to project4.php
```

## Performance

| File         | Size (MB) | Download Time (sec) |
| ------------ | --------- | ------------------- |
| project4.php | 0.02      | 0.5                 |
| 2MB.log      | 2.0       | 3.1                 |
| 10MB.log     | 10.0      | 13.7                |
| 50MB.log     | 50.0      | 68.7                |

## Design Details

- All the details about wrapping and unwrapping of packets have been abstracted away into 2 functions in the `rawsocket` package:
  1. `Wrap(IPHeader, TCPHeader) -> packet`
  2. `Unwrap(packet) -> IPHeader, TCPHeader, error`
- When a packet is unwrapped, the TCP and IP checksums are automatically checked. If there is an error, it will return the error back to the client to handle. Likewise, when a packet is wrapped, its checksum is automatically calculated into the packet.
- The `http` package loosely mimics the Go std lib `net/conn` and `net/http`.
- If a packet we sent out has not been ACK'd within 1 minute, the packet is assumed to be lost, so we retransmit it. This almost never happens since we only send out 1 packet that needs to get ACK'd.

## Random Notes

* This program uses HTTP/1.0 instead of HTTP/1.1 because HTTP/1.1 may contain "chunked encoding" which is a pain to decode. Since this program does not use the `keep-alive` header, HTTP/1.0 is sufficient for our use case and it greatly simplies decoding.

* This program accepts gzip encoding if the server sends gzip'd payloads.

* Github Actions does not allow you to run in `sudo` mode (of course) so half of the unit tests cannot run in CI. It is best to run tests locally.