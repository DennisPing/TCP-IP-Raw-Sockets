package http

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

type Request struct {
	Method  string
	Url     *url.URL
	Proto   string // HTTP/1.0
	Headers map[string]string
	Body    []byte // Not used since we only support GET request
}

// ToBytes converts the Request into a byte array. It will sort the headers in alphabetical order.
func (r *Request) ToBytes() []byte {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("%s %s %s\r\n", r.Method, r.Url.Path, r.Proto))

	// Sort the header keys
	keys := make([]string, 0, len(r.Headers))
	for k := range r.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		builder.WriteString(fmt.Sprintf("%s: %s\r\n", k, r.Headers[k]))
	}

	builder.WriteString("\r\n") // The final \r\n

	if r.Body != nil {
		builder.Write(r.Body)
	}

	return []byte(builder.String())
}
