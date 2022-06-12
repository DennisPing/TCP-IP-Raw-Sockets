package pkg

import (
	"net"
	"os/exec"
	"strings"
	"testing"
)

// Test Contains function
func TestContains(t *testing.T) {
	type test struct {
		big    []string
		small  []string
		expect bool
	}
	tests := []test{
		{
			big:    []string{"SYN", "ACK", "FIN"},
			small:  []string{"SYN", "ACK", "FIN"},
			expect: true,
		},
		{
			big:    []string{"SYN", "ACK", "FIN"},
			small:  []string{"ACK"},
			expect: true,
		},
		{
			big:    []string{"ACK"},
			small:  []string{"ACK"},
			expect: true,
		},
		{
			big:    []string{"SYN", "ACK", "FIN"},
			small:  []string{"SYN", "ACK", "FIN", "PSH"},
			expect: false,
		},
		{
			big:    []string{"SYN", "ACK", "PSH"},
			small:  []string{"RST"},
			expect: false,
		},
		{
			big:    []string{"SYN", "ACK", "PSH"},
			small:  []string{""},
			expect: false,
		},
		{
			big:    []string{"SYN", "ACK", "PSH"},
			small:  []string{},
			expect: false,
		},
	}
	for i, tc := range tests {
		got := Contains(tc.big, tc.small)
		if got != tc.expect {
			t.Errorf("test %d: Expect %v, but Contains(%v, %v) = %v", i+1, tc.expect, tc.big, tc.small, got)
		}
	}
}

func TestLookupLocalIP(t *testing.T) {
	// Run exec "hostname -I" and capture the output
	output, err := exec.Command("hostname", "-I").Output()
	if err != nil {
		t.Errorf("unable to find my IP via shell: %v", err)
	}
	expect := net.ParseIP(strings.TrimSuffix(string(output), " \n"))
	if !expect.Equal(LookupLocalIP()) {
		t.Errorf("Expect %v, but FindMyIP() = %v", expect, LookupLocalIP())
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
