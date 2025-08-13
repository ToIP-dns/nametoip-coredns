package nametoip

import (
	"bufio"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"os"
)

func init() { plugin.Register("nametoip", setup) }

func setup(c *caddy.Controller) error {
	//c.Next()
	//
	//origins := plugin.OriginsFromArgsOrServerBlock(c.RemainingArgs(), c.ServerBlockKeys)
	//
	//var vanityMap map[string]int
	//for c.NextBlock() {
	//	switch c.Val() {
	//	case "vanity_name_file":
	//		f := c.RemainingArgs()
	//		if len(curriedNameToIpSoItCanBeTested) != 1 {
	//			return plugin.Error("nametoip", c.ArgErr())
	//		}
	//		// Open vanity file
	//		var err error
	//		vanityMap, err = createVanityMap(f[0])
	//		if err != nil {
	//			return plugin.Error("nametoip", err)
	//		}
	//
	//	}
	//}
	curriedNameToIpSoItCanBeTested, err := internalSetup(c)
	if err != nil {
		return err

	}

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return curriedNameToIpSoItCanBeTested(next)
	})

	// All OK, return a nil error.
	return nil
}

func internalSetup(c *caddy.Controller) (func(next plugin.Handler) NameToIp, error) {
	c.Next()

	origins := plugin.OriginsFromArgsOrServerBlock(c.RemainingArgs(), c.ServerBlockKeys)

	var vanityMap map[string]int
	for c.NextBlock() {
		switch c.Val() {
		case "vanity_name_file":
			f := c.RemainingArgs()
			if len(f) != 1 {
				return nil, plugin.Error("nametoip", c.ArgErr())
			}
			// Open vanity file
			var err error
			vanityMap, err = createVanityMap(f[0])
			if err != nil {
				return nil, plugin.Error("nametoip", err)
			}

		}
	}

	// Hacky hack. Curry this so we can build it in outer setup
	return func(next plugin.Handler) NameToIp {
		return newNameToIp(next, origins, vanityMap)
	}, nil

}

// Reads in the vanity file name and creates a hashmap of name to the
// line number. We use this line number as the base of the numeric mapping
// eg: 0 > "192.168.0.0". 23576 > 192.168.(23576 & 0xFF00 >> 8).(23576 & 0x00FF)
func createVanityMap(filename string) (map[string]int, error) {
	openedFile, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer openedFile.Close()

	var vanityMap = make(map[string]int)
	scanner := bufio.NewScanner(openedFile)

	var numericMapping = 0
	for scanner.Scan() {
		vanityMap[scanner.Text()] = numericMapping
		numericMapping++
	}
	return vanityMap, nil
}
