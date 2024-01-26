package http

import (
	"net"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLookupLocalIP(t *testing.T) {
	// Run exec "hostname -I" and capture the output
	output, err := exec.Command("hostname", "-I").Output()
	if err != nil {
		t.Errorf("unable to find my IP via shell: %v", err)
	}
	firstWord := strings.Split(string(output), " ")[0]
	expect := net.ParseIP(strings.TrimSuffix(firstWord, " \n"))
	localIp, _ := LookupLocalIP()

	assert.True(t, expect.Equal(localIp))
}

func TestLookupRemoteIP(t *testing.T) {
	tests := []struct {
		hostname string
		expect   net.IP
	}{
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
		assert.Nil(t, err, "unable to resolve IP address: %s", tc.hostname)
		assert.True(t, tc.expect.Equal(ip))
	}

	// Test error case
	remoteHost := "david.choffnes.com.invalid"
	_, err := LookupRemoteIP(remoteHost)
	assert.NotNil(t, err, "expected '%s' to fail lookup but did not", remoteHost)
}
