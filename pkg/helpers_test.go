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

func TestFindMyIP(t *testing.T) {
	// Run exec "hostname -I" and capture the output
	output, err := exec.Command("hostname", "-I").Output()
	if err != nil {
		t.Errorf("unable to find my IP via shell: %v", err)
	}
	expect := net.ParseIP(strings.TrimSuffix(string(output), " \n"))
	if !expect.Equal(FindMyIP()) {
		t.Errorf("Expect %v, but FindMyIP() = %v", expect, FindMyIP())
	}
}

func TestLookupIPv4(t *testing.T) {
	expect := net.ParseIP("204.44.192.60")
	ip, err := LookupIPv4("david.choffnes.com")
	if err != nil {
		t.Errorf("unable to resolve david.choffnes.com: %v", err)
	}
	if !expect.Equal(ip) {
		t.Errorf("Expect %v, but LookupIPv4(david.choffnes.com) = %v", expect, ip)
	}
}
