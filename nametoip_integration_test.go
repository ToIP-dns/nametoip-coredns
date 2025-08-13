package nametoip

import (
	"context"
	"fmt"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/coremain"
	"net"
	"testing"
	"time"
)

func TestIntegration(t *testing.T) {
	go func() {
		coremain.Run()
	}()

	time.Sleep(200 * time.Millisecond)
	tests := []struct {
		query    string
		response string
	}{
		{"10.2.3.4.example.com.", "10.2.3.4"},
		{"loyet.example.com", "192.168.0.0"},
		{"quxac.example.com", "192.168.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			ip, err := lookupIp(tt.query)
			if err != nil {
				t.Errorf("error: %v", err)
				return
			}
			if ip != tt.response {
				t.Errorf("got %s, want %s", ip, tt.response)
			}
		})
	}

}

var directives = []string{
	"nametoip",
}

func init() {
	dnsserver.Directives = directives
}

func lookupIp(name string) (string, error) {
	resolver := net.Resolver{
		PreferGo:     false,
		StrictErrors: false,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.Dial("udp", "127.0.0.1:25353")
		},
	}

	ip, err := resolver.LookupIP(context.TODO(), "ip4", name)
	if err != nil {
		return "", err
	}
	if len(ip) != 1 {
		return "", fmt.Errorf("expected 1 IP, got %v", ip)
	}

	return fmt.Sprintf("%d.%d.%d.%d", ip[0][0], ip[0][1], ip[0][2], ip[0][3]), nil

}
