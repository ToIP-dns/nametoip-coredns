## nametoip

`nametoip` is a plugin for [CoreDNS](https://coredns.io/) that returns IP addresses encoded in hostnames.
It is intended for local development, home labs etc...  It provides functionality similar to services like 
[nip.io](https://nip.io/) and [sslip.io](https://sslip.io/).

It provides the following encodings:
- Dot notation. eg: 
  - `10.2.3.4.example.com` resolves to `10.2.3.4`
- Dash notation. eg: 
  - `10-2-3-4.example.com` resolves to `10.2.3.4`
- Hex notation. eg:
  - `0a020304.example.com` resolves to `10.2.3.4`
- (Optional) vanity notation. eg:
  - `quxac.example.com` resolves to `192.168.0.1` (with )
- Above encodings allow for arbitrary prefixes and subdomains. eg:
  - `a.big.hello-world-10-2-3-4.example.com` resolves to `10.2.3.4`

For now, only private IPs are supported as this plugin is intended to support scenarios such
as home labs, local development etc...

### Vanity names
Optional vanity names can also be used. These are 5 character `CVCVC` words (C=consonant, V=vowel)
and are somewhat pronounceable.

This word list needs to be supplied (see `./Corefile`) and is hard-coded to the 192.168. address
space. The file should cover the 16 bit address space as the line number is mapped to the base address.
If you only care about, say, `192.168.0.0-192.168.10.255`, then you will only need a file with `11 x 256`
lines.
