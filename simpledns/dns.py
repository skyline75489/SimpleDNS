import sys
import socket 
import argparse

from collections import OrderedDict
from twisted.internet import reactor, defer
from twisted.names import client, dns, server, cache, hosts
from twisted.internet.abstract import isIPAddress

from twisted.python import log


class DispatchResolver(client.Resolver):
    def __init__(self, dispatch_conf, servers=None, timeout=(1, 3, 11, 45), minTTL=60*60, tcp_only=False, tcp_timeout=10, verbose=0):
        self.serverMap = {}
        self.addressMap = {}
        self.minTTL = minTTL
        self.tcp_only = tcp_only
        self.tcp_timeout = tcp_timeout
        self.verbose = verbose

        self.parseDispatchConfig(dispatch_conf)
        client.Resolver.__init__(self, servers=servers, timeout = timeout)

    def is_address_validate(self, addr):
        try:
            socket.inet_aton(addr)
            return True
        except (socket.error, ValueError):
            try:
                socket.inet_pton(socket.AF_INET6, addr)
                return True
            except (socket.error, ValueError):
                return False

    def parseDispatchConfig(self, config):
        f = open(config, 'r')
        for l in f.readlines():
            l = l.strip()
            if l == "" or l.startswith('#'):
                continue
            t = l.split('=')
            _type = t[0]
            _map = t[1]
            if _type == 'server':
                _entry = _map.split('/')
                _path = _entry[1].strip()
                _addr_and_port = _entry[2].strip().split('#')
                _addr = _addr_and_port[0]
                if not self.is_address_validate(_addr):
                    continue
                _port = "53"
                if len(_addr_and_port) == 2:
                    _port = _addr_and_port[1]


                _port = int(_port)
                self.serverMap[_path] = (_addr, _port)

            if _type == 'address':
                _entry = _map.split('/')
                _path = _entry[1].strip()
                _addr = _entry[2].strip()
                if not self.is_address_validate(_addr):
                    continue
                self.addressMap[_path] = _addr


    def pickServer(self, queries=None):
        _path = None
        name = str(queries[0].name)
        end = len(name.split('.'))
        begin = end - 1
        address = None
        while begin >= 0:
            try:
                _path = '.'.join(name.split('.')[begin:end])
                address = self.serverMap[_path]
                if self.verbose > 0:
                    log.msg('Dispatch server match for ' + name)
                break;
            except KeyError:
                pass
            finally:
                begin = begin - 1
        else:
            if self.verbose > 0:
                log.msg('Dispatch server mismatch for ' + name)
            address = self.servers[0]
        return address

    def queryUDP(self, queries, timeout = None):
        if timeout is None:
            timeout = self.timeout

        upstream_address = self.pickServer(queries)
        d = self._query(upstream_address, queries, timeout[0])
        d.addErrback(self._reissue, upstream_address, queries, timeout)
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

    def _lookup(self, name, cls, type, timeout):
        key = (name, type, cls)
        waiting = self._waiting.get(key)
        if waiting is None:
            self._waiting[key] = []
            d = None
            if self.tcp_only:
                d = self.queryTCP([dns.Query(name, type, cls)], self.tcp_timeout)
            else:
                d = self.queryUDP([dns.Query(name, type, cls)], timeout)
            def cbResult(result):
                for d in self._waiting.pop(key):
                    d.callback(result)
                return result
            d.addCallback(self.filterAnswers)
            d.addBoth(cbResult)
        else:
            d = defer.Deferred()
            waiting.append(d)
        return d

    def filterAnswers(self, message):
        if message.trunc:
            return self.queryTCP(message.queries).addCallback(self.filterAnswers)
        if message.rCode != dns.OK:
            return failure.Failure(self.exceptionForCode(message.rCode)(message))
        return (message.answers, message.authority, message.additional)

    def _aRecords(self, name, address):
        return tuple([dns.RRHeader(name, dns.A, dns.IN, self.minTTL,
                     dns.Record_A(address, self.minTTL))])

    def _aaaaRecords(self, name, address):
        return tuple([dns.RRHeader(name, dns.AAAA, dns.IN, self.minTTL,
                         dns.Record_AAAA(address, self.minTTL))])

    def _respond(self, name, records):
        if records:
            return defer.succeed((records, (), ()))
        return defer.fail(failure.Failure(dns.DomainError(name)))

    def _matchAddress(self, name, packRecords):
        """ 
        Check if query address matches any
        address rule in dispatch.conf
        """
        end = len(name.split('.'))
        begin = end - 1
        address = None
        while begin >= 0:
            try:
                _path = '.'.join(name.split('.')[begin:end])
                address = self.addressMap[_path]
                if self.verbose > 0:
                    log.msg('Dispatch address match for ' + name)
                records = packRecords(name, address)
                return records
            except KeyError:
                pass
            finally:
                begin = begin - 1
        else:
            if self.verbose > 0:
                log.msg('Dispatch address mismatch for ' + name)
            return None

    def lookupAddress(self, name, timeout=None):
        r = self._matchAddress(name, self._aRecords)
        if r:
            return self._respond(name, r)
        else:
            return self._lookup(name, dns.IN, dns.A, timeout)

    def lookupIPV6Address(self, name, timeout=None):
        r = self._matchAddress(name, self._aaaaRecords)
        if r:
            return self._respond(name, r)
        else:
            return self._lookup(name, dns.IN, dns.AAAA, timeout)

class LimitedSizeDict(OrderedDict):
    def __init__(self, size_limit=None,*args, **kwargs):
        self.size_limit = size_limit
        self.used = 0
        OrderedDict.__init__(self, *args, **kwargs)
        self._check_size_limit()
    def __setitem__(self, key, value):
        OrderedDict.__setitem__(self, key, value)
        self._check_size_limit()
    def _check_size_limit(self):
        if self.size_limit is not None:
            while len(self) > self.size_limit:
                self.popitem(last=False)
        self.used = len(self)


class ExtendCacheResolver(cache.CacheResolver):
    def __init__(self, _cache=None, verbose=0, reactor=None, cacheSize=500,minTTL=0, maxTTL=604800):
        assert maxTTL >= minTTL >= 0
        self.minTTL = minTTL
        self.maxTTL = maxTTL
        cache.CacheResolver.__init__(self, _cache, verbose, reactor)
        self.cache = LimitedSizeDict(size_limit=cacheSize)

    def cacheResult(self, query, payload, cacheTime=None):
        try:
            # Already cached
            r = self.cache[query]
            return
        except KeyError:
            pass

        self.cache[query] = (cacheTime or self._reactor.seconds(), payload)
        if self.verbose > 0:
            log.msg('Adding %r to cache' % query)
        if self.verbose > 1:
            log.msg('Cache used (%d / %d)' % (self.cache.used, self.cache.size_limit))

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
    parser = argparse.ArgumentParser(description="A Lightweight yet useful DNS proxy.")
    parser.add_argument('-b', '--local-address', type=str,
                        help='local address to listen',
                        default='127.0.0.1',
                        )
    parser.add_argument('-p', '--local-port', type=int,
                        help="local port to listen",
                        default=53,
                        )

    parser.add_argument('--upstream-address',type=str,
                        help="upstream DNS server ip address",
                        default='8.8.8.8')
    parser.add_argument('--upstream-port',type=int,
                        help="upstream DNS server port",
                        default=53)
    parser.add_argument('--tcp-only',
                        help="use only TCP for outgoing queries",
                        action="store_true")
    parser.add_argument('--min-TTL', type=int,
                        help="the minimum time a record is held in cache",
                        default=0)
    parser.add_argument('--max-TTL', type=int,
                        help="the maximum time a record is held in cache",
                        default=604800)
    parser.add_argument('--cache-size', type=int,
                        help="record cache size",
                        default=500)
    parser.add_argument('-t', '--tcp-server', 
                        help="enables TCP serving",
                        action="store_true")
    parser.add_argument('--hosts-file',
                        help="hosts file",
                        default="../hosts")
    parser.add_argument('--dispatch-conf',
                        help="URL dispatch conf file",
                        default="../dispatch.conf")
    parser.add_argument('-v', '--verbosity', type=int,
                        choices=[0,1,2],
                        help="output verbosity",
                        default=0)

    args = parser.parse_args()

    print("Listening on " + args.local_address + ':' + str(args.local_port))
    if args.verbosity > 0:
        log.startLogging(sys.stdout)

    factory = server.DNSServerFactory(
            caches = [ExtendCacheResolver(verbose=args.verbosity, cacheSize=args.cache_size, minTTL=args.min_TTL, maxTTL=args.max_TTL)],
            clients = [
                hosts.Resolver(args.hosts_file),
                DispatchResolver(args.dispatch_conf, servers=[(args.upstream_address, args.upstream_port)], minTTL=args.min_TTL, tcp_only=args.tcp_only
            )],
            verbose=args.verbosity
        )

    protocol = dns.DNSDatagramProtocol(controller=factory)
    if args.verbosity < 2:
        dns.DNSDatagramProtocol.noisy = False
        server.DNSServerFactory.noisy = False
    reactor.listenUDP(args.local_port, protocol, args.local_address)
    if args.tcp_server:
        reactor.listenTCP(args.local_port, protocol, args.local_address)
    reactor.run()


if __name__ == "__main__":
    raise SystemExit(main())