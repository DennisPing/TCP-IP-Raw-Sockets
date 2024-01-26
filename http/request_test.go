package http

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequestToBytes(t *testing.T) {
	tests := []struct {
		name          string
		request       Request
		requestString string
	}{
		{
			name: "SimpleGETRequest",
			request: Request{
				Method: "GET",
				Url: &url.URL{
					Scheme: "http",
					Host:   "example.com",
					Path:   "/index.html",
				},
				Proto: "HTTP/1.0",
				Headers: map[string]string{
					"Host":         "example.com",
					"Connection":   "keep-alive",
					"Content-Type": "text/html",
				},
				Body: nil,
			},
			requestString: "GET /index.html HTTP/1.0\r\n" +
				"Connection: keep-alive\r\n" +
				"Content-Type: text/html\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqStr := string(tt.request.ToBytes())
			assert.Equal(t, tt.requestString, reqStr)
		})
	}
}
