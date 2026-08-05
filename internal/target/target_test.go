package target

import (
	"net"
	"testing"
)

func TestAllowed(t *testing.T) {
	tests := []struct {
		address string
		want    bool
	}{
		{"1.1.1.1", true},
		{"8.8.8.8", true},
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"192.168.1.1", false},
		{"169.254.1.1", false},
		{"224.0.0.1", false},
		{"::1", false},
		{"2001:4860:4860::8888", true},
	}
	for _, test := range tests {
		if got := allowed(net.ParseIP(test.address)); got != test.want {
			t.Errorf("allowed(%s) = %v, want %v", test.address, got, test.want)
		}
	}
}
