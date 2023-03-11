package http

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"

	"github.com/DennisPing/TCP-IP-Raw-Sockets/rawsocket"
)

type Response struct {
	Url        string
	StatusCode int
	Reason     string
	Headers    map[string]string
	Body       []byte
}

func NewResponse(url string, data []byte) *Response {
	split := bytes.SplitN(data, []byte("\r\n\r\n"), 2)
	top := split[0]
	body := split[1]

	// Parse the first line (HTTP/1.0 200 OK)
	status_line := bytes.SplitN(top, []byte("\r\n"), 2)[0]
	three_parts := bytes.Split(status_line, []byte(" "))
	status_code, _ := strconv.Atoi(string(three_parts[1]))
	reason := three_parts[2]

	// Parse the headers
	headers := bytes.SplitN(top, []byte("\r\n"), 2)[1]
	header_lines := bytes.Split(headers, []byte("\r\n"))
	header_map := make(map[string]string)
	for _, header := range header_lines {
		header_split := bytes.SplitN(header, []byte(": "), 2)
		key := string(header_split[0])
		value := string(header_split[1])
		header_map[key] = value
	}
	// Check if header "Content-Encoding" exists
	if _, ok := header_map["Content-Encoding"]; ok {
		if header_map["Content-Encoding"] == "gzip" {
			body = *decodeGzip(body)
		}
	}
	return &Response{
		Url:        url,
		StatusCode: int(status_code),
		Reason:     string(reason),
		Headers:    header_map,
		Body:       body,
	}
}

// Send a GET request and return a Response.
func Get(u *url.URL) (*Response, error) {
	if u.Scheme != "http" {
		return nil, errors.New("only HTTP is supported")
	}
	conn, err := NewConn(u.Hostname())
	if err != nil {
		return nil, err
	}
	err = conn.Connect()
	if err != nil {
		return nil, err
	}
	header := makeHeader(u, "GET")
	err = conn.Send(header, rawsocket.ACK)
	if err != nil {
		if err.Error() == "recv timeout" {
			if err = conn.Send(header, rawsocket.ACK); err != nil { // Try again
				return nil, errors.New("retry attempts exceeded")
			}
		} else {
			return nil, err
		}
	}
	raw_data, err := conn.RecvAll()
	if err != nil {
		return nil, err
	}
	conn.CloseSockets()
	if err != nil {
		return nil, err
	}
	res := NewResponse(u.String(), raw_data)
	return res, nil
}

// Build the HTTP header for a GET request.
func makeHeader(u *url.URL, method string) []byte {
	status_line := method + " " + u.Path + " HTTP/1.0\r\n"
	header_map := map[string]string{
		"Host":            u.Host,
		"Connection":      "close",
		"Accept-Encoding": "gzip",
	}
	header := ""
	for key, value := range header_map {
		header += key + ": " + value + "\r\n"
	}
	header += "\r\n"
	return []byte(status_line + header)
}

// Decode payload from gzip to regular bytes.
func decodeGzip(payload []byte) *[]byte {
	if len(payload) == 0 {
		return &payload
	}
	reader, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		panic(fmt.Sprintf("Unable to create gzip reader: %s", err))
	}
	defer reader.Close()
	var buf bytes.Buffer
	io.Copy(&buf, reader)
	var decoded []byte = buf.Bytes()
	return &decoded
}
