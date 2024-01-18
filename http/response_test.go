package http

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"net/url"
	"reflect"
	"testing"
)

func getMockData() []byte {
	data := "HTTP/1.0 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		"Host: david.choffnes.com\r\n" +
		"Connection: close\r\n\r\n" +
		"<html>Hello World\r\n" +
		"I'm a teapot</html>\r\n"
	return []byte(data)
}

func getMockDataGzipped() []byte {
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
		rawData    []byte
		url        *url.URL
		statuscode int
		reason     string
		headers    map[string]string
		body       []byte
	}
	tests := []test{
		{
			rawData:    getMockData(),
			url:        &url.URL{Scheme: "http", Host: "david.choffnes.com", Path: "/classes/cs4700sp22/project4.php"},
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
			rawData:    getMockDataGzipped(),
			url:        &url.URL{Scheme: "http", Host: "david.choffnes.com", Path: "/classes/cs4700sp22/project4.php"},
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
		res, _ := ParseResponse(test.url, test.rawData)
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

func formatMap(m map[string]string) string {
	var s string
	for k, v := range m {
		s += fmt.Sprintf("%s: %s\n", k, v)
	}
	return s
}
