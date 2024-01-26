package http

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
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

	body := "<html>Hello World\r\n" +
		"I'm a teapot</html>\r\n"
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write([]byte(body))
	gw.Close()
	return append([]byte(head), buf.Bytes()...)
}

func TestNewResponse(t *testing.T) {
	tests := []struct {
		name       string
		rawData    []byte
		url        *url.URL
		statuscode int
		reason     string
		headers    map[string]string
		body       []byte
	}{
		{
			name:       "Parse plain text response",
			rawData:    getMockData(),
			url:        &url.URL{Scheme: "http", Host: "david.choffnes.com", Path: "/classes/cs4700sp22/project4.php"},
			statuscode: 200,
			reason:     "OK",
			headers: map[string]string{
				"content-type": "text/html",
				"host":         "david.choffnes.com",
				"connection":   "close",
			},
			body: []byte("<html>Hello World\r\nI'm a teapot</html>\r\n"),
		},
		{
			name:       "Parse gzip encoded response",
			rawData:    getMockDataGzipped(),
			url:        &url.URL{Scheme: "http", Host: "david.choffnes.com", Path: "/classes/cs4700sp22/project4.php"},
			statuscode: 200,
			reason:     "OK",
			headers: map[string]string{
				"content-type":     "text/html",
				"host":             "david.choffnes.com",
				"connection":       "close",
				"content-encoding": "gzip",
			},
			body: []byte("<html>Hello World\r\nI'm a teapot</html>\r\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := ParseResponse(tt.url, bytes.NewReader(tt.rawData))
			assert.Nil(t, err)

			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			assert.Nil(t, err)

			assert.Equal(t, tt.url, resp.Url)
			assert.Equal(t, tt.statuscode, resp.StatusCode)
			assert.Equal(t, tt.reason, resp.Reason)
			assert.EqualValues(t, tt.headers, resp.Headers)
			assert.Equal(t, tt.body, body)
		})
	}
}
