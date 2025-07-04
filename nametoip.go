package nametoip

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"net"
	"regexp"
	"strings"
	"sync/atomic"
)

//var log = clog.NewWithPlugin("nametoip")

func newNameToIp(next plugin.Handler, origins []string) NameToIp {
	return NameToIp{
		Next:           next,
		Origins:        origins,
		totalRequests:  &atomic.Int64{},
		totalResponse:  &atomic.Int64{},
		totalResponseA: &atomic.Int64{},
	}
}

type NameToIp struct {
	Next           plugin.Handler
	Origins        []string
	totalRequests  *atomic.Int64
	totalResponse  *atomic.Int64
	totalResponseA *atomic.Int64
}

func (n NameToIp) ServeDNS(ctx context.Context, writer dns.ResponseWriter, msg *dns.Msg) (int, error) {
	req := request.Request{W: writer, Req: msg}
	n.totalRequests.Add(1)
	switch req.QType() {
	case dns.TypeA:
		return n.handleARecord(ctx, writer, msg)
	case dns.TypeTXT:
		return n.handleTxtRecord(ctx, writer, msg)
	}

	// We don't handle other types atm
	return plugin.NextOrFailure(n.Name(), n.Next, ctx, writer, msg)
}

func (n NameToIp) handleARecord(ctx context.Context, writer dns.ResponseWriter, msg *dns.Msg) (int, error) {
	req := request.Request{W: writer, Req: msg}
	queryName := req.Name()
	// Try to extract the address. If we fail, fallthrough
	ipV4 := n.toIpV4(queryName)
	if ipV4 == nil {
		return plugin.NextOrFailure(n.Name(), n.Next, ctx, writer, msg)
	}

	// A record
	response := new(dns.A)
	response.Hdr = dns.RR_Header{Name: queryName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}
	response.A = ipV4

	// DNS message
	m := new(dns.Msg)
	m.SetReply(msg)
	m.Authoritative = true
	m.Answer = []dns.RR{response}

	// Write out the record
	err := writer.WriteMsg(m)
	if err != nil {
		return dns.RcodeServerFailure, err
	}
	// Increment our counters
	n.totalResponse.Add(1)
	n.totalResponseA.Add(1)
	return dns.RcodeSuccess, nil
}

type dnsStats struct {
	TotalRequest   int64 `json:"total_requests"`
	TotalResponse  int64 `json:"total_response"`
	TotalResponseA int64 `json:"total_response_a"`
}

func (n NameToIp) handleTxtRecord(ctx context.Context, writer dns.ResponseWriter, msg *dns.Msg) (int, error) {
	req := request.Request{W: writer, Req: msg}
	queryName := req.Name()

	// Pass through for any other name than _stats
	localName := n.getLocalPart(queryName)
	if localName != "_stats" {
		return plugin.NextOrFailure(n.Name(), n.Next, ctx, writer, msg)
	}

	// Construct JSON. We will miss the response of this request as we only increment later once we know
	// we have sent it successfully
	stats := dnsStats{
		TotalRequest:   n.totalRequests.Load(),
		TotalResponse:  n.totalResponse.Load(),
		TotalResponseA: n.totalResponse.Load(),
	}

	marshal, err := json.Marshal(stats)
	if err != nil {
		return dns.RcodeServerFailure, err
	}

	// TXT record
	response := new(dns.TXT)
	response.Hdr = dns.RR_Header{Name: queryName, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}
	response.Txt = []string{string(marshal)}

	// DNS message
	m := new(dns.Msg)
	m.SetReply(msg)
	m.Authoritative = true
	m.Answer = []dns.RR{response}

	// Write out the record
	err = writer.WriteMsg(m)
	if err != nil {
		return dns.RcodeServerFailure, err
	}
	n.totalResponse.Add(1)
	return dns.RcodeSuccess, nil
}

func (n NameToIp) getLocalPart(name string) string {
	// Find the configured origin for this
	var rootZone = ""
	for _, origin := range n.Origins {
		if strings.HasSuffix(name, origin) {
			rootZone = origin
			// If the request is the same as the origin, we don't handle it
			if name == origin {
				return ""
			}
			break
		}
	}
	if rootZone == "" {
		panic("This code path shouldn't be possible. CoreDNS called us for a name we are not configured to handle")
		return ""
	}

	// Pull the local part out of the name
	// app-192.168.1.1.example.com > app-192.168.1.1
	localName := name[:len(name)-len(rootZone)]

	// Pull off any trailing . char. Eg: "192.168.1.1."
	if localName[len(localName)-1] == '.' {
		localName = localName[:len(localName)-1]
	}
	return localName

}

func (n NameToIp) toIpV4(name string) net.IP {
	localName := n.getLocalPart(name)
	if localName == "" {
		return nil
	}
	ipAsString := findIpInHostname(localName)
	// Check if we got an IP out of the different regex methods
	if ipAsString == "" {
		return nil
	}

	// Parse the string we have
	ip := net.ParseIP(ipAsString)
	if ip == nil {
		return nil
	}
	// Make sure IP is in private address range
	if !isPrivateIpV4(ip) {
		return nil
	}

	return ip
}

var regexIpDot = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b$`)
var regexIpDash = regexp.MustCompile(`\b(?:\d{1,3}-){3}\d{1,3}\b$`)
var regexIpAsHex = regexp.MustCompile(`\b[a-fA-F0-9]{8}\b$`)

func findIpInHostname(hostname string) string {
	// . encoding
	var ipAsString = regexIpDot.FindString(hostname)
	if ipAsString != "" {
		return ipAsString
	}

	// - encoding
	ipAsString = regexIpDash.FindString(hostname)
	if ipAsString != "" {
		return strings.Replace(ipAsString, "-", ".", 3)
	}

	// hex encoding
	ipAsString = regexIpAsHex.FindString(hostname)
	if ipAsString != "" {
		ipBytes, err := hex.DecodeString(ipAsString)
		if err != nil {
			return ""
		}
		// A little wasteful encoding back into a string, but it doesn't feel as common code path
		return fmt.Sprintf("%d.%d.%d.%d", ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])
	}
	return ""
}

var privateClassC = net.IPNet{
	IP:   net.ParseIP("192.168.0.0"),
	Mask: net.CIDRMask(16, 32),
}
var privateClassB = net.IPNet{
	IP:   net.ParseIP("172.16.0.0"),
	Mask: net.CIDRMask(12, 32),
}
var privateClassA = net.IPNet{
	IP:   net.ParseIP("10.0.0.0"),
	Mask: net.CIDRMask(8, 32),
}
var privateLoopback = net.IPNet{
	IP:   net.ParseIP("127.0.0.0"),
	Mask: net.CIDRMask(8, 32),
}

func isPrivateIpV4(ip net.IP) bool {
	return privateClassC.Contains(ip) || privateClassA.Contains(ip) ||
		privateClassB.Contains(ip) || privateLoopback.Contains(ip)
}

func (n NameToIp) Name() string {
	return "nametoip"
}
