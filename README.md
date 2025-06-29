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
- Above encodings allow for arbitrary prefixes and subdomains. eg:
  - `a.big.hello-world-10-2-3-4.example.com` resolves to `10.2.3.4`

For now, only private IPs are supported as this plugin is intended to support scenarios such
as home labs, local development etc...
