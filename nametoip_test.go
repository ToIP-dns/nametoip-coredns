package nametoip

import (
	"context"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	"testing"
)

const ErrIndicatingFallthrough = `plugin/nametoip: no next plugin found`

var vanityNames = map[string]int{
	"kumil": 0,
	"nacog": 1,
	"qudis": 734,
}

func TestNameToIp_ServeDNS_ParseableHostnames(t *testing.T) {
	tests := []struct {
		query     string
		queryType uint16
		answer    string
	}{
		{"192.168.1.1.example.com.", dns.TypeA, "192.168.1.1"},
		{"dash-prefixes-192.168.1.1.example.com.", dns.TypeA, "192.168.1.1"},
		{"dot.prefixes.10.1.2.3.example.com.", dns.TypeA, "10.1.2.3"},
		{"parse-right-to-left-10.10.7.7.7.example.com.", dns.TypeA, "10.7.7.7"},
		{"10-7-7-7.example.com.", dns.TypeA, "10.7.7.7"},
		{"prefix-10-7-7-7.example.com.", dns.TypeA, "10.7.7.7"},
		{"another.prefix.10-7-7-7.example.com.", dns.TypeA, "10.7.7.7"},
		{"c0a801fc.example.com.", dns.TypeA, "192.168.1.252"},
		{"dash-prefix-0a070707.example.com.", dns.TypeA, "10.7.7.7"},
		{"dot.prefix.0a070707.example.com.", dns.TypeA, "10.7.7.7"},
		{"class-c-private.192.168.44.55.example.com.", dns.TypeA, "192.168.44.55"},
		{"class-b-private.172.17.55.11.example.com.", dns.TypeA, "172.17.55.11"},
		{"class-b-private.10.3.4.5.example.com.", dns.TypeA, "10.3.4.5"},
		{"loopback-private.127.1.2.3.example.com.", dns.TypeA, "127.1.2.3"},
		{"kumil.example.com.", dns.TypeA, "192.168.0.0"},
		{"qudis.example.com.", dns.TypeA, "192.168.2.222"},
		{"my-prefix.kumil.example.com.", dns.TypeA, "192.168.0.0"},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion(tt.query, tt.queryType)
			rec := dnstest.NewRecorder(&test.ResponseWriter{})

			n := newNameToIp(nil, []string{"example.com."}, vanityNames)
			got, err := n.ServeDNS(context.TODO(), rec, req)
			// No errors
			if err != nil {
				t.Errorf("ServeDNS() error = %v", err)
				return
			}

			// Success return
			if got != dns.RcodeSuccess {
				t.Errorf("ServeDNS() unexpected return. Got %v, expected %v", got, dns.RcodeSuccess)
				return
			}
			// Only expect 1 answer
			if len(rec.Msg.Answer) != 1 {
				t.Errorf("ServeDNS() unexpected answer length != 1. Got %v", rec.Msg.Answer)
				return
			}
			// The RR type should be the same as the query type expected
			if rec.Msg.Answer[0].Header().Rrtype != tt.queryType {
				t.Errorf("ServeDNS() unexpected RRTyper. Got %v, expected %v", rec.Msg.Answer[0].Header().Rrtype, tt.queryType)
				return

			}
			// Cast this to an A record to get the IP. Won't work with other record types
			aRecord := rec.Msg.Answer[0].(*dns.A)
			if aRecord.A.String() != tt.answer {
				t.Errorf("ServeDNS() unexpected record. Got %v, expected %v", aRecord.A.String(), tt.answer)
			}
		})
	}
}

func TestNameToIp_ServeDNS_FallthroughHostnames(t *testing.T) {
	tests := []struct {
		query     string
		queryType uint16
	}{
		{"some-non-ip.example.com.", dns.TypeA},
		{"public-ips-ignored-1.2.3.4.example.com.", dns.TypeA},
		{"non-word-boundary-0a0a0a070707.example.com.", dns.TypeA},
		{"non-a-records-192.168.1.1.example.com.", dns.TypeTXT},
		{"example.com.", dns.TypeA},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion(tt.query, tt.queryType)
			rec := dnstest.NewRecorder(&test.ResponseWriter{})

			n := newNameToIp(nil, []string{"example.com."}, vanityNames)
			_, err := n.ServeDNS(context.TODO(), rec, req)
			// No errors
			if err != nil {
				// There are errors when falling through that aren't to do with the plugin, so look for errors
				// of this shape
				if err.Error() == ErrIndicatingFallthrough {
					return
				}
				t.Errorf("ServeDNS() error = %v", err)
				return
			}
			t.Errorf("Expected query to fallthrough but it did not")
		})
	}
}

func TestNameToIp_ServeDNS_StatsEndpoint(t *testing.T) {
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	n := newNameToIp(nil, []string{"example.com."}, nil)

	// Create some statistics
	aRequest := new(dns.Msg)
	aRequest.SetQuestion("10.2.3.4.example.com.", dns.TypeA)
	_, _ = n.ServeDNS(context.TODO(), rec, aRequest)
	_, _ = n.ServeDNS(context.TODO(), rec, aRequest)
	// Request statistics
	statsRequest := new(dns.Msg)
	statsRequest.SetQuestion("_stats.example.com.", dns.TypeTXT)
	_, _ = n.ServeDNS(context.TODO(), rec, statsRequest) // Generate one additional total reponse
	_, err := n.ServeDNS(context.TODO(), rec, statsRequest)

	if err != nil {
		t.Errorf("ServeDNS() error = %v", err)
	}
	responseTxt := rec.Msg.Answer[0].(*dns.TXT).Txt[0]
	if responseTxt != "{\"total_requests\":4,\"total_response\":3,\"total_response_a\":2}" {
		t.Errorf("ServeDNS() unexpected response. Got %v", responseTxt)
	}
}
