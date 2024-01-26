package http

import (
	"errors"
	"fmt"
	urlpkg "net/url"
	"time"
)

// This Client does not maintain a persistent connection
type Client struct {
	Timeout time.Duration
}

func NewClient() *Client {
	return &Client{
		Timeout: time.Second * 30,
	}
}

// Make a Get request for the given url string
func (c *Client) Get(url string) (*Response, error) {
	u, err := urlpkg.Parse(url)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	if u.Scheme != "http" {
		return nil, errors.New("only HTTP is supported")
	}

	req := &Request{
		Method: "GET",
		Url:    u,
		Proto:  "HTTP/1.0",
		Headers: map[string]string{
			"Host":            u.Host,
			"Connection":      "close",
			"Accept-Encoding": "gzip",
		},
	}

	return c.Do(req)
}

// Do the Request and return the Response. The ephemeral connection lives in here.
func (c *Client) Do(req *Request) (*Response, error) {
	conn, err := NewConn(req.Url.Hostname(), c.Timeout)
	if err != nil {
		return nil, err
	}

	defer func(conn *Conn) {
		err := conn.Close()
		if err != nil {
			err = fmt.Errorf("error closing sockets: %w", err)
		}
	}(conn)

	err = conn.SendRequest(req)
	if err != nil {
		return nil, err
	}

	respStream, err := conn.RecvResponse()
	if err != nil {
		return nil, err
	}

	return ParseResponse(req.Url, respStream)
}
