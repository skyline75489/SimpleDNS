SimpleDNS
=========

A lightweight yet useful proxy DNS server powered by [Twisted](https://twistedmatrix.com/trac/) .

### What is it?

It is a proxy DNS server with caching that is designed to cope with [complicated Internet environment](http://en.wikipedia.org/wiki/Great_Firewall_of_China#Blocking_methods) in China. Inspired by [ChinaDNS](https://github.com/clowwindy/ChinaDNS) and [fqdns](https://github.com/fqrouter/fqdns), it can query over non-standard port and discard wrong responses to avoid incorrect answers.

### Why use it?

First, it supports caching to speed up querying. You can also change cache duration by setting min-TTL value.  Second, unlike [ChinaDNS](https://github.com/clowwindy/ChinaDNS) and [fqdns](https://github.com/fqrouter/fqdns), it's configuration is greatly influenced by [Dnsmasq](http://www.thekelleys.org.uk/dnsmasq/doc.html) which offers great flexibility in dispatching queries according to their URL. Third, it's build on top of [Twisted](https://twistedmatrix.com/trac/) which is totally async. So the performance should be good.