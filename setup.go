package nametoip

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() { plugin.Register("nametoip", setup) }

func setup(c *caddy.Controller) error {
	c.Next()

	origins := plugin.OriginsFromArgsOrServerBlock(c.RemainingArgs(), c.ServerBlockKeys)

	if c.NextArg() {
		return plugin.Error("nametoip", c.ArgErr())
	}

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return NameToIp{Next: next, Origins: origins}
	})

	// All OK, return a nil error.
	return nil
}
