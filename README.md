# TCP/IP Raw Sockets

Matthew Jones  
Dennis Ping  

## Overview

This project was originally done in Python3 and ported to Go for self-learning purposes.

Due to the low-level details and bitwise operations of this project, unit testing was done to ensure correctness. All TCP and IP Header functions were tested to +90% coverage.

Testing of the GET request was done by downloading the sample HTTP pages and verifying using `diff [file1] [file2]`.

Debugging of the 3-way handshake and teardown was done on Wireshark.

## Requirements

Go 1.15+

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

## How to Run Tests

Standard mode
```
go test
```
Verbose mode
```
go test -v
```

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

## Design Details

- All the details about wrapping and unwrapping of packets have been abstracted into 2 functions:
  1. `Wrap(IPHeader, TCPHeader) -> packet`
  2. `Unwrap(packet) -> IPHeader, TCPHeader, error`
- When a packet is unwrapped, the TCP and IP checksums are **automatically checked**. If there is an error, it will return the error back to the client to handle. Likewise, when a packet is wrapped, its checksum is **automatically calculated** into the packet.
- All the details about HTTP headers and payload have been abstracted away into the `requests` package.
- The `requests` package manages the seq numbers, ack numbers, congestion window, advertised window, timeout, and retransmit.
- If a packet we sent out has not been ACK'd within 1 minute, the packet is assumed to be lost, so we retransmit it.
- The payloads of the TCP headers are stored in a map for reconstruction at the end. The design is a linked list within a hashmap.

## Payload Map Example

| Key       | Value                     |
| --------- | ------------------------- |
| seq_num_1 | (payload_1, next_seq_num) |
| seq_num_2 | (payload_2, next_seq_num) |
| seq_num_4 | (payload_4, next_seq_num) |
| seq_num_3 | (payload_3, next_seq_num) |
| seq_num_5 | (payload_5, next_seq_num) |

### How to reconstruct payload using this map:

1. For loop through the length of this map.
2. Find the lowest sequence number. This is the first piece.
3. Use the pointer in the tuple to find the next piece. Append the pieces.

## Important Lessons

* "Chunked encoding is a required feature of HTTP/1.1. If you do not require any other 1.1-specific features, specify HTTP/1.0 in your request instead" ([StackOverflow post](https://stackoverflow.com/questions/31969990/how-to-tell-the-http-server-to-not-send-chunked-encoding)). Because I am using HTTP/1.1, I had to decode the chunked encoded payloads before writing them to the output file.

* "Transfer-Encoding: chunked" does not have a "Content-Length", and therefore, it sends a 0 length chunk (`0\r\n\r\n`) on the last payload . That is how the client knows it has received the last packet of the GET response.