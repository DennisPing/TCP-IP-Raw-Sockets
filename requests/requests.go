package requests

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
)

type Response struct {
	Url        string
	StatusCode int
	Reason     string
	Headers    map[string]string
	Body       []byte
}

func NewResponse(url string, data *[]byte) *Response {
	// https://stackoverflow.com/questions/60774467/split-a-string-only-by-the-first-element-in-golang
	split := bytes.SplitN(*data, []byte("\r\n\r\n"), 2)
	top := split[0]
	body := split[1]

	// Parse the first line (HTTP/1.0 200 OK)
	status_line := bytes.SplitN(top, []byte("\r\n"), 2)[0]
	parts := bytes.Split(status_line, []byte(" "))
	status_code := parts[1][0]
	reason := parts[2][0]

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
	return &Response{
		Url:        url,
		StatusCode: int(status_code),
		Reason:     string(reason),
		Headers:    header_map,
		Body:       body,
	}
}

func Get(u url.URL, verbose bool) (*Response, error) {
	if u.Scheme != "http" {
		return nil, errors.New("only HTTP is supported")
	}
	if u.Host != "david.choffnes.com" {
		return nil, errors.New("only host david.choffnes.com is supported")
	}

	fmt.Println(u.Path)

	client := InitClient(u.Hostname())
	client.Connect() // 3-way handshake

	header := prepHeader("GET", u)
	err := client.Send(header, []string{"ACK", "PSH"})
	if err != nil {
		return nil, err
	}
	data, err := client.RecvAll()
	if err != nil {
		return nil, err
	}
	err = client.Close()
	if err != nil {
		return nil, err
	}
	res := NewResponse(u.String(), data)
	return res, nil
}

func prepHeader(method string, u url.URL) []byte {
	if method != "GET" {
		panic("Only GET is supported")
	}
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
