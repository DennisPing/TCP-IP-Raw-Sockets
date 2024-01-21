![Build](https://github.com/DennisPing/TCP-IP-Raw-Sockets/actions/workflows/go.yml/badge.svg)
![Coverage](https://img.shields.io/badge/Coverage-45.0%25-yellow)

# TCP/IP Raw Sockets

## Overview

**TL;DR - Make an HTTP GET request from scratch; from the network layer to the application layer.**

This project was originally done in Python and converted to Go for self-learning purposes.

This program called `rawhttpget` takes one URL, downloads the target URL page, and saves it into the current directory. The TCP/IP network stack is custom implemented, and all incoming & outgoing data packets utilize raw sockets. Due to the low-level details and bitwise operations of this project, unit testing was done to ensure correctness. Manual debugging was also done on Wireshark.

## Requirements

Go 1.21+

This project only works on Linux.

## Required System Changes

1. Modify iptables rule
```
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```

2. Find your "network interface" name using: `ifconfig -a` and disable gro, tx, rx 
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
Usage: sudo ./rawhttpget [-v] URL
Options:
  -p string
    	available profilers: cpu, mem
  -v	verbose output
```

The optional flag `-v` is for verbose output.

**Examples**

```
sudo ./rawhttpget -v http://david.choffnes.com/classes/cs4700sp22/project4.php
sudo ./rawhttpget http://david.choffnes.com/classes/cs4700sp22/10MB.log
```

## Testing

**Standard mode**
```
go test ./...
```

**Verbose mode**
```
go test -v ./...
```

**Show test coverage**
```
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

## Example Run in Verbose Mode

```
> sudo ./rawhttpget -v http://david.choffnes.com/classes/cs4700sp22/project4.php
Remote IP: 204.44.192.60
Local IP: 192.168.0.237
--> send 48 bytes       Flags: SYN              seq: 2123832061, ack: 0
<-- recv 48 bytes       Flags: SYN ACK          seq: 2154816049, ack: 2123832062
--> send 40 bytes       Flags: ACK              seq: 2123832062, ack: 2154816050
--> send 157 bytes      Flags: ACK              seq: 2123832062, ack: 2154816050
<-- recv 40 bytes       Flags: ACK              seq: 2154816050, ack: 2123832179
<-- recv 40 bytes       Flags: ACK              seq: 2154816050, ack: 2123832179
--> send 40 bytes       Flags: ACK              seq: 2123832179, ack: 2154816050
<-- recv 1500 bytes     Flags: ACK              seq: 2154816050, ack: 2123832179
--> send 40 bytes       Flags: ACK              seq: 2123832179, ack: 2154817510
<-- recv 1500 bytes     Flags: ACK              seq: 2154817510, ack: 2123832179
--> send 40 bytes       Flags: ACK              seq: 2123832179, ack: 2154818970
<-- recv 1500 bytes     Flags: ACK              seq: 2154818970, ack: 2123832179
--> send 40 bytes       Flags: ACK              seq: 2123832179, ack: 2154820430
<-- recv 1500 bytes     Flags: ACK              seq: 2154820430, ack: 2123832179
--> send 40 bytes       Flags: ACK              seq: 2123832179, ack: 2154821890
<-- recv 1500 bytes     Flags: ACK              seq: 2154821890, ack: 2123832179
--> send 40 bytes       Flags: ACK              seq: 2123832179, ack: 2154823350
<-- recv 1061 bytes     Flags: PSH ACK          seq: 2154823350, ack: 2123832179
--> send 40 bytes       Flags: ACK              seq: 2123832179, ack: 2154824371
<-- recv 1500 bytes     Flags: ACK              seq: 2154824371, ack: 2123832179
--> send 40 bytes       Flags: ACK              seq: 2123832179, ack: 2154825831
<-- recv 804 bytes      Flags: PSH ACK          seq: 2154825831, ack: 2123832179
--> send 40 bytes       Flags: ACK              seq: 2123832179, ack: 2154826595
<-- recv 40 bytes       Flags: FIN ACK          seq: 2154826595, ack: 2123832179
--> send 40 bytes       Flags: FIN ACK          seq: 2123832179, ack: 2154826596
<-- recv 40 bytes       Flags: ACK              seq: 2154826596, ack: 2123832180
200 OK
Wrote 22576 bytes to project4.php
```

## Design Details

- All the details about wrapping and unwrapping of packets have been abstracted away into 2 functions in the `rawsocket` package:
  1. `Wrap(IPHeader, TCPHeader) -> packet`
  2. `Unwrap(packet) -> IPHeader, TCPHeader, error`
- When a packet is unwrapped, the TCP and IP checksums are automatically checked. If there is an error, it will return the error back to the client to handle. Likewise, when a packet is wrapped, its checksum is automatically calculated into the packet.
- The `http` package loosely mimics the Go std lib `net` library.
- The window scale is set at 5 which means a max transfer speed of 2 MiB/sec.
- Ideally, the window scale is 7 which means a max transfer speed of 8 MiB/sec. However, this would require utilizing an application layer buffer so that the network layer buffer doesn't overflow.

## Random Notes
- This program uses HTTP/1.0 instead of HTTP/1.1 because HTTP/1.1 may contain "chunked encoding" which is a pain to decode. Since this program does not use the `keep-alive` header, HTTP/1.0 is sufficient for our use case, and it greatly simplifies decoding.
- This program accepts gzip encoding if the server wants to send compressed data.