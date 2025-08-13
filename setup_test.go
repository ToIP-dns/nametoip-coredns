package nametoip

import (
	"github.com/coredns/caddy"
	"testing"
)

func TestVanityNamesPresent(t *testing.T) {
	c := caddy.NewTestController("dns",
		`nametoip {
				vanity_name_file test-vanity-names.txt
			}`)
	f, err := internalSetup(c)
	if err != nil {
		t.Errorf("Test error: %v", err)
		return
	}

	var expectedVanityNames = map[string]int{
		"loyet": 0,
		"quxac": 1,
		"fezep": 2,
	}

	nameToIp := f(nil)

	for k, v := range expectedVanityNames {
		value, ok := nameToIp.VanityName[k]
		if !ok {
			t.Errorf("Name %v not found in loaded vanity names", k)
		} else if value != v {
			t.Errorf("Unexpected vanity name mapping for %v. Got %v, expected %v", k, nameToIp.VanityName[k], v)
		}
	}

}

func TestNoVanityNames_stillSetsUpThePlugin(t *testing.T) {
	c := caddy.NewTestController("dns",
		`nametoip`)
	err := setup(c)
	if err != nil {
		t.Errorf("Test error: %v", err)
	}
}
