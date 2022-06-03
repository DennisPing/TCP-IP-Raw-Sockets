package requests

import (
	"testing"

	"github.com/DennisPing/TCP-IP-Raw-Sockets/pkg"
)

func Test_FindMyIP(t *testing.T) {
	ip := pkg.FindMyIP()
	if ip == nil {
		t.Error("FindMyIP() failed")
	}
}
