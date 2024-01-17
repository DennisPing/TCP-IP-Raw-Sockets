package http

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
)

type Response struct {
	Url        *url.URL
	StatusCode int
	Reason     string
	Headers    map[string]string
	Body       []byte
}

func ParseResponse(url *url.URL, data []byte) (*Response, error) {
	if data == nil || len(data) == 0 {
		return nil, fmt.Errorf("empty data in response")
	}

	split := bytes.SplitN(data, []byte("\r\n\r\n"), 2)
	if len(split) != 2 {
		return nil, fmt.Errorf("no HTTP body found")
	}

	top := split[0]
	body := split[1]

	// Parse the first line (HTTP/1.0 200 OK)
	statusLine := string(bytes.SplitN(top, []byte("\r\n"), 2)[0])
	threeParts := strings.SplitN(statusLine, " ", 3)
	statusCode, _ := strconv.Atoi(threeParts[1])
	reason := threeParts[2]

	// Parse the headers
	headers := bytes.SplitN(top, []byte("\r\n"), 2)[1]
	headerLines := bytes.Split(headers, []byte("\r\n"))
	headerMap := make(map[string]string)
	for _, header := range headerLines {
		headerSplit := bytes.SplitN(header, []byte(": "), 2)
		key := string(headerSplit[0])
		value := string(headerSplit[1])
		headerMap[key] = value
	}

	// Check if header "Content-Encoding" exists
	if _, ok := headerMap["Content-Encoding"]; ok {
		if headerMap["Content-Encoding"] == "gzip" {
			body = decodeGzip(body)
		}
	}

	return &Response{
		Url:        url,
		StatusCode: statusCode,
		Reason:     reason,
		Headers:    headerMap,
		Body:       body,
	}, nil
}

// Decode payload from gzip to regular bytes.
func decodeGzip(payload []byte) []byte {
	if len(payload) == 0 {
		return payload
	}

	reader, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		panic(fmt.Sprintf("Unable to create gzip reader: %s", err))
	}

	defer func(reader *gzip.Reader) {
		err := reader.Close()
		if err != nil {
			// Ignore
		}
	}(reader)

	var buf bytes.Buffer
	_, err = io.Copy(&buf, reader)
	if err != nil {
		return nil
	}

	return buf.Bytes()
}
