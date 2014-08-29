import sys

from twisted.internet import reactor
from twisted.names import client, dns, server, cache
from twisted.python import log

# log.startLogging(sys.stdout)

class DispatchResolver(client.Resolver):
    def __init__(self, config, servers=None, timeout=(1, 3, 11, 45)):
        self.serverMap = {}
        self.addressMap = {}

        self.parseDispatchConfig(config)
        client.Resolver.__init__(self, servers=servers, timeout = timeout)

    def parseDispatchConfig(self, config):
        f = open(config, 'r')
        for l in f.readlines():
            t = l.split('=')
            _type = t[0]
            _map = t[1]
            if _type == 'server':
                _entry = _map.split('/')
                _path = _entry[1].strip()
                _addr_and_port = _entry[2].strip().split('#')
                _addr = _addr_and_port[0]
                _port = "53"
                if len(_addr_and_port) == 2:
                    _port = _addr_and_port[1]


                _port = int(_port)
                self.serverMap[_path] = (_addr, _port)

            if _type == 'address':
                _entry = _map.split('/')
                _path = _entry[1].strip()
                _addr = _entry[2].strip()
                self.addressMap[_path] = _addr


    def pickServer(self, queries=None):
        _path = None
        try:
            _path = str(queries[0].name).split('www.')[1]
        except IndexError:
            _path = str(queries[0].name)
        address = None
        try:
            address = self.serverMap[_path]
            log.msg('Dispatch match for ' + _path)
        except KeyError:
            address = self.servers[0]

        return address

    def queryUDP(self, queries, timeout = None):
        if timeout is None:
            timeout = self.timeout

        address = self.pickServer(queries)
        d = self._query(address, queries, timeout[0])
        d.addErrback(self._reissue, address, queries, timeout)
        return d

    def _reissue(self, reason, address, query, timeout):
        reason.trap(dns.DNSQueryTimeoutError)

        # If all timeout values have been used this query has failed.  Tell the
        # protocol we're giving up on it and return a terminal timeout failure
        # to our caller.
        if not timeout:
            return failure.Failure(defer.TimeoutError(query))

        # Issue a query to a server.  Use the current timeout.  Add this
        # function as a timeout errback in case another retry is required.
        d = self._query(address, query, timeout[0], reason.value.id)
        d.addErrback(self._reissue, address, query, timeout)
        return d

    def queryTCP(self, queries, timeout = 10):
        if not len(self.connections):
            address = self.pickServer(queries)
            if address is None:
                return defer.fail(IOError("No domain name servers available"))
            host, port = address
            self._reactor.connectTCP(host, port, self.factory)
            self.pending.append((defer.Deferred(), queries, timeout))
            return self.pending[-1][0]
        else:
            return self.connections[0].query(queries, timeout)


class ExtendCacheResolver(cache.CacheResolver):
    def __init__(self, _cache=None, verbose=0, reactor=None, minTTL=0, maxTTL=604800):
        assert maxTTL >= minTTL >= 0
        self.minTTL = minTTL
        self.maxTTL = maxTTL
        cache.CacheResolver.__init__(self, _cache, verbose, reactor)

    def cacheResult(self, query, payload, cacheTime=None):
        try:
            # Already cached
            r = self.cache[query]
            return
        except KeyError:
            pass

        if self.verbose > 1:
            log.msg('Adding %r to cache' % query)

        self.cache[query] = (cacheTime or self._reactor.seconds(), payload)

        if query in self.cancel:
            self.cancel[query].cancel()

        s = list(payload[0]) + list(payload[1]) + list(payload[2])

        for r in s:
            if r.ttl < self.minTTL:
                r.ttl = self.minTTL
            if r.ttl > self.maxTTL:
                r.ttl = self.maxTTL
        if s:
            m = s[0].ttl
            for r in s:
                m = min(m, r.ttl)
        else:
            m = 0

        self.cancel[query] = self._reactor.callLater(m, self.clearEntry, query)

def main():
    factory = server.DNSServerFactory(
            caches = [ExtendCacheResolver(verbose=2, minTTL=60000)],
            clients = [DispatchResolver('./dispatch.conf', servers=[("77.66.84.233", 443)]
            )]
        )
    protocol = dns.DNSDatagramProtocol(controller=factory)

    reactor.listenUDP(53, protocol)
    reactor.listenTCP(53, factory)
    reactor.run()


if __name__ == "__main__":
    raise SystemExit(main())