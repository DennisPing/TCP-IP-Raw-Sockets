# TCP/IP Raw Sockets

Matthew Jones  
Dennis Ping  

## Background

This project was originally done in Python and ported to Go for self-learning purposes.

Due to the low-level details, arithmetic math, and bitwise operations of this project, unit-testing was done to ensure correctness. All TCP and IP Header functions were tested to +90% coverage. So much pain and suffering.

Unit-testing the raw sockets, 3-way handshake, and GET function is impossible since the starting sequence number is randomized between 0 and 2^32. Therefore, manual testing was done on Wireshark.

This project only works on Linux.

## Requirements

Go 1.15+

## How to Build

```
make
```

or

```
go build -o rawhttpget
```

## Required System Changes

```
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```

Find your "network interface" name using: `ifconfig -a`

```
sudo ethtool -K <network interface> gro off
sudo ethtool -K <network interface> tx off rx off
```

## How to Run

cd into the `/bin` directory
```
sudo ./rawhttpget
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

## Design Details

- All the details about wrapping and unwrapping of packets have been abstracted into 2 functions:
  1. Wrap(IPHeader, TCPHeader) -> packet
  2. Unwrap(packet) -> IPHeader, TCPHeader, error
- As shown in the above function signature, when a packet is unwrapped, the TCP and IP checksums are **automatically checked**. If there is an error, it will return the error back to the client to handle.
- All the details about HTTP headers and its payload have been abstracted away into a custom library similar to Python's `requests` library.
- The main client program manages the seq numbers, ack numbers, congestion window, advertised window, timeout, and retransmit.
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