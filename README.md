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

## Required System Changes

```
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
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
  1. Unwrap(packet) -> (ipHeader, tcpHeader, payload)
  2. Wrap(ipHeader, tcpHeader, payload) -> packet
- The TCP and IP checksums have been automated such that they will return an error to the client program if the checksum is invalid.
- All the details about HTTP headers and its payload have been abstracted away into a custom library similar to Python's `requests` library.
- The main client program manages the seq numbers, ack numbers, congestion window, advertised window, timeout, and retransmit.
- If a packet arrives out-of-order, we simply drop the packet and send out an ACK for the sequence number we want.
- If a packet we sent out has not been ACK'd within 1 minute, the packet is assumed to be lost, so we retransmit it.