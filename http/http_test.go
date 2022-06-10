package http

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func getMockData(t *testing.T) []byte {
	data := "HTTP/1.0 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		"Host: david.choffnes.com\r\n" +
		"Connection: close\r\n\r\n" +
		"<html>Hello World\r\n" +
		"I'm a teapot</html>\r\n"
	return []byte(data)
}

func getMockDataGzipped(t *testing.T) []byte {
	head := "HTTP/1.0 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		"Host: david.choffnes.com\r\n" +
		"Content-Encoding: gzip\r\n" +
		"Connection: close\r\n\r\n"
	// Gzip this body
	body := "<html>Hello World\r\n" +
		"I'm a teapot</html>\r\n"
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write([]byte(body))
	gw.Close()
	return append([]byte(head), buf.Bytes()...)
}

func TestNewResponse(t *testing.T) {
	type test struct {
		raw_data   []byte
		url        string
		statuscode int
		reason     string
		headers    map[string]string
		body       []byte
	}
	tests := []test{
		{
			raw_data:   getMockData(t),
			url:        "http://david.choffnes.com/classes/cs4700sp22/project4.php",
			statuscode: 200,
			reason:     "OK",
			headers: map[string]string{
				"Content-Type": "text/html",
				"Host":         "david.choffnes.com",
				"Connection":   "close",
			},
			body: []byte("<html>Hello World\r\nI'm a teapot</html>\r\n"),
		},
		{
			raw_data:   getMockDataGzipped(t),
			url:        "http://david.choffnes.com/classes/cs4700sp22/project4.php",
			statuscode: 200,
			reason:     "OK",
			headers: map[string]string{
				"Content-Type":     "text/html",
				"Host":             "david.choffnes.com",
				"Connection":       "close",
				"Content-Encoding": "gzip",
			},
			body: []byte("<html>Hello World\r\nI'm a teapot</html>\r\n"),
		},
	}
	for _, test := range tests {
		res := NewResponse(test.url, test.raw_data)
		if res.Url != test.url {
			t.Errorf("Expect: %s Got: %s", test.url, res.Url)
		}
		if res.StatusCode != test.statuscode {
			t.Errorf("Expect: %d Got: %d", test.statuscode, res.StatusCode)
		}
		if res.Reason != test.reason {
			t.Errorf("Expect: %s Got: %s", test.reason, res.Reason)
		}
		if reflect.DeepEqual(res.Headers, test.headers) == false {
			t.Errorf("\nExpect: \n%s\nGot: \n%s", formatMap(test.headers), formatMap(res.Headers))
		}
		if reflect.DeepEqual(res.Body, test.body) == false {
			t.Errorf("\nExpect: \n%s\nGot: \n%s", test.body, res.Body)
		}
	}
}

func TestPrepHeader(t *testing.T) {
	type test struct {
		u      *url.URL
		method string
		expect []byte
	}
	tests := []test{
		{
			u:      &url.URL{Scheme: "http", Host: "www.example.com", Path: "/index.html"},
			method: "GET",
			expect: []byte("GET /index.html HTTP/1.0\r\nHost: www.example.com\r\nConnection: close\r\nAccept-Encoding: gzip\r\n\r\n"),
		},
		{
			u:      &url.URL{Scheme: "http", Host: "david.choffnes.com", Path: "/classes/cs4700sp22/project4.php"},
			method: "GET",
			expect: []byte("GET /classes/cs4700sp22/project4.php HTTP/1.0\r\nHost: david.choffnes.com\r\nConnection: close\r\nAccept-Encoding: gzip\r\n\r\n"),
		},
	}
	for _, test := range tests {
		header_bytes := prepHeader(test.u, test.method)
		if compareUnorderedHeaders(header_bytes, test.expect) == false {
			t.Errorf("\nExpect:\n%s\nGot:\n%s", test.expect, header_bytes)
		}
	}
}

// Since preHeader uses an unordered map, the headers are out of order and can't be compared using string equals.
func compareUnorderedHeaders(h1, h2 []byte) bool {
	if len(h1) != len(h2) {
		return false
	}
	// Split by \r\n and compare
	h1_lines := strings.Split(string(h1), "\r\n")
	h2_lines := strings.Split(string(h2), "\r\n")
	for _, line1 := range h1_lines {
		found := false
		for _, line2 := range h2_lines {
			if line1 == line2 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func formatMap(m map[string]string) string {
	var s string
	for k, v := range m {
		s += fmt.Sprintf("%s: %s\n", k, v)
	}
	return s
}
