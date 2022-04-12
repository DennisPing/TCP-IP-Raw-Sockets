# TCP/IP Raw Sockets

Matthew Jones  
Dennis Ping  

## Background

This project was originally done in Python and ported to Go for self-learning purposes.

Due to the low-level details of this project, unit-testing was done to ensure correctness. All TCP and IP Header functions were tested to +90% coverage.

Unit-testing the raw sockets, 3-way handshake, and GET function is impossible since the starting sequence number is always randomized between 0 and 2^32. Therefore, manual testing was done on Wireshark.

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

Coverage mode
```
go test -cover
```