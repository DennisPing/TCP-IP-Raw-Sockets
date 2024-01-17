package main

import (
	"flag"
	"fmt"
	"os"
	"path"

	"github.com/DennisPing/TCP-IP-Raw-Sockets/config"
	myhttp "github.com/DennisPing/TCP-IP-Raw-Sockets/http"
)

func cliUsage() {
	fmt.Printf("Usage: sudo %s [-v] URL\n", os.Args[0])
	fmt.Printf("Options:\n")
	flag.PrintDefaults()
}

func main() {
	var (
		inputUrl string
	)

	flag.Usage = cliUsage
	flag.BoolVar(&config.Verbose, "v", false, "verbose output")
	flag.Parse()

	// Validate input arguments
	if flag.NArg() == 1 {
		inputUrl = flag.Arg(0)
	} else if flag.NArg() < 1 {
		fmt.Println("Error: missing URL")
		cliUsage()
		os.Exit(1)
	} else {
		fmt.Println("Error: too many arguments")
		cliUsage()
		os.Exit(1)
	}

	client := myhttp.NewClient()
	resp, err := client.Get(inputUrl)
	if err != nil {
		fmt.Printf("GET request error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%d %s\n", resp.StatusCode, resp.Reason)
	if resp.StatusCode != 200 {
		fmt.Printf("Did not get \"200 OK\" response. Exiting...\n")
		os.Exit(1)
	}

	// Write response body to file
	fileName := path.Base(resp.Url.Path)
	f, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}(f)

	_, err = f.Write(resp.Body)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("Wrote %d bytes to %s\n", len(resp.Body), fileName)
}
