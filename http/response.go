package http

import (
	"bufio"
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
	Body       io.ReadCloser // Mimic the Go std lib
}

// ParseResponse parses the raw response into a Response object
func ParseResponse(url *url.URL, reader io.Reader) (*Response, error) {
	bufReader := bufio.NewReader(reader) // Use a buffered stream

	// Read the status line
	statusLine, err := bufReader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("error reading status line: %v", err)
	}

	statusLine = strings.TrimSpace(statusLine) // Remove the trailing \r\n
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 3 {
		return nil, fmt.Errorf("malformed status line")
	}

	statusCode, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("error parsing status code: %v", err)
	}

	response := &Response{
		Url:        url,
		StatusCode: statusCode,
		Reason:     parts[2],
		Headers:    make(map[string]string),
	}

	// Read the headers
	for {
		line, err := bufReader.ReadString('\n')
		if err == io.EOF {
			return nil, fmt.Errorf("no response headers found")
		}
		if err != nil {
			return nil, fmt.Errorf("error reading header: %v", err)
		}

		line = strings.TrimSpace(line)
		if line == "" {
			break // End of headers
		}

		headerParts := strings.SplitN(line, ": ", 2)
		if len(headerParts) != 2 {
			return nil, fmt.Errorf("malformed header: %s", line)
		}

		headerName := strings.ToLower(headerParts[0])
		response.Headers[headerName] = headerParts[1]
	}

	//var bodyReader = io.NopCloser(bufReader)
	if val, ok := response.Headers["content-encoding"]; ok && val == "gzip" {
		gzipReader, err := gzip.NewReader(bufReader)
		if err != nil {
			return nil, err
		}
		response.Body = gzipReader
	} else {
		response.Body = io.NopCloser(bufReader)
	}

	//var body bytes.Buffer
	//if val, ok := response.Headers["content-encoding"]; ok {
	//	if val == "gzip" {
	//		gzipReader, err := gzip.NewReader(bufReader)
	//		if err != nil {
	//			return nil, err
	//		}
	//
	//		defer func(gzipReader *gzip.Reader) {
	//			err := gzipReader.Close()
	//			if err != nil {
	//
	//			}
	//		}(gzipReader)
	//
	//		if _, err := io.Copy(&body, gzipReader); err != nil {
	//			return nil, err
	//		}
	//	}
	//} else {
	//	if _, err := io.Copy(&body, bufReader); err != nil {
	//		return nil, err
	//	}
	//}

	return response, nil
}
