package http

import (
	"fmt"
	"net/url"
)

type Request struct {
	Method  string
	Url     *url.URL
	Proto   string // HTTP/1.0
	Headers map[string]string
	Body    []byte // Not used since we only support GET request
}

func (r *Request) ToBytes() []byte {
	statusLine := fmt.Sprintf("%s %s %s\r\n", r.Method, r.Url.Path, r.Proto)
	header := ""
	for key, value := range r.Headers {
		header += fmt.Sprintf("%s: %s\r\n", key, value)
	}
	return []byte(statusLine + header + "\r\n")
}
