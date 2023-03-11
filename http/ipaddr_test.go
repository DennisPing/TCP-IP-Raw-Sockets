package http

import (
	"net"
	"os/exec"
	"strings"
	"testing"
)

func TestLookupLocalIP(t *testing.T) {
	// Run exec "hostname -I" and capture the output
	output, err := exec.Command("hostname", "-I").Output()
	if err != nil {
		t.Errorf("unable to find my IP via shell: %v", err)
	}
	firstWord := strings.Split(string(output), " ")[0]
	expect := net.ParseIP(strings.TrimSuffix(firstWord, " \n"))
	local_ip, _ := LookupLocalIP()
	if !expect.Equal(local_ip) {
		t.Errorf("Expect %v, but FindMyIP() = %v", expect, local_ip)
	}
}

func TestLookupRemoteIP(t *testing.T) {
	type test struct {
		hostname string
		expect   net.IP
	}
	tests := []test{
		{
			hostname: "david.choffnes.com",
			expect:   net.ParseIP("204.44.192.60"),
		},
		{
			hostname: "localhost",
			expect:   net.ParseIP("127.0.0.1"),
		},
	}
	for _, tc := range tests {
		ip, err := LookupRemoteIP(tc.hostname)
		if err != nil {
			t.Errorf("unable to resolve %s: %v", tc.hostname, err)
		}
		if !tc.expect.Equal(ip) {
			t.Errorf("Expect %v, but LookupRemoteIP(%s) = %v", tc.expect, tc.hostname, ip)
		}
	}

	// Test error case
	ip, err := LookupRemoteIP("david.choffnes.com.invalid")
	if err == nil {
		t.Errorf("Expect error, but LookupRemoteIP(david.choffnes.com.invalid) = %v", ip)
	}
}
