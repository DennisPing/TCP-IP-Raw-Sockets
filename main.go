package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"path"

	"github.com/DennisPing/TCP-IP-Raw-Sockets/requests"
)

func cliUsage() {
	fmt.Printf("Usage: sudo %s [-v] URL\n", os.Args[0])
	fmt.Printf("Options:\n")
	flag.PrintDefaults()
}

func main() {
	var (
		input_url string
		verbose   bool
	)

	flag.Usage = cliUsage
	flag.BoolVar(&verbose, "v", false, "verbose output")
	flag.Parse()

	// Validate input arguments
	if flag.NArg() == 1 {
		input_url = flag.Arg(0)
	} else if flag.NArg() < 1 {
		fmt.Println("Error: missing URL")
		cliUsage()
		os.Exit(1)
	} else {
		fmt.Println("Error: too many arguments")
		cliUsage()
		os.Exit(1)
	}
	u, err := url.Parse(input_url)
	if err != nil {
		fmt.Printf("Invalid URL: %s\n", err)
		os.Exit(1)
	}

	// Make the GET request
	res, err := requests.Get(u, verbose)
	if err != nil {
		fmt.Printf("GET request error: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("%d %s\n", res.StatusCode, res.Reason)
	if res.StatusCode != 200 {
		fmt.Printf("Did not get \"200 OK\" response. Exiting...\n")
		os.Exit(1)
	}

	// Write response body to file
	var fname string = path.Base(u.Path)
	f, err := os.Create(fname)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer f.Close()
	_, err = f.Write(res.Body)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("Wrote %d bytes to %s\n", len(res.Body), fname)
}
