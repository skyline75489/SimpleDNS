import sys
import socket 
import argparse
import time

from collections import OrderedDict
from twisted.internet import reactor, defer
from twisted.names import client, dns, server, cache, hosts
from twisted.internet.abstract import isIPAddress

from twisted.python import log, failure

info = sys.version_info
if not (info[0] == 2 and info[1] >= 7):
    print 'Python 2.7 required'
    sys.exit(1)


GFW_LIST = set(["74.125.127.102", "74.125.155.102", "74.125.39.102",
                "74.125.39.113", "209.85.229.138", "128.121.126.139",
                "159.106.121.75", "169.132.13.103", "192.67.198.6",
                "202.106.1.2", "202.181.7.85", "203.161.230.171",
                "203.98.7.65", "207.12.88.98", "208.56.31.43",
                "209.145.54.50", "209.220.30.174", "209.36.73.33",
                "211.94.66.147", "213.169.251.35", "216.221.188.182",
                "216.234.179.13", "243.185.187.39", "37.61.54.158",
                "4.36.66.178", "46.82.174.68", "59.24.3.173", "64.33.88.161",
                "64.33.99.47", "64.66.163.251", "65.104.202.252",
                "65.160.219.113", "66.45.252.237", "72.14.205.104",
                "72.14.205.99", "78.16.49.15", "8.7.198.45", "93.46.8.89"])


class DispatchResolver(client.Resolver):
    def __init__(self, dispatch_conf, servers=None, timeout=None, minTTL=60*60, query_timeout=10, verbose=0):
        self.serverMap = {}
        self.addressMap = {}
        self.minTTL = minTTL
        self.query_timeout = query_timeout
        self.verbose = verbose
        self.serverFactory = None
        self.parseDispatchConfig(dispatch_conf)
        client.Resolver.__init__(self, servers=servers, timeout = timeout)
        # Retry three times for each query 
        self.timeout = (self.query_timeout, self.query_timeout + 5, self.query_timeout + 15, self.query_timeout + 25)

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

    def messageReceived(self, message, protocol, address = None):
        message.timeReceived = time.time()
        self.serverFactory.gotResolverResponse( (message.answers, message.authority, message.additional), protocol, message, address)

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

    def _query(self, *args):
        protocol = self._connectedProtocol()
        d = protocol.query(*args)
        def cbQueried(result):
            return result
        d.addBoth(cbQueried)

        def closePort():
            protocol.transport.stopListening()
        self._reactor.callLater(args[2], closePort)
        return d

    def queryUDP(self, queries, timeout = None):
        if timeout is None:
            timeout = self.timeout

        upstream_address = self.pickServer(queries)
        d = self._query(upstream_address, queries, timeout[0])
        d.addErrback(self._reissue, upstream_address, queries, timeout)
        return d

    def _reissue(self, reason, address, query, timeout):
        reason.trap(dns.DNSQueryTimeoutError)

        timeout = timeout[1:]
        if not timeout:
            return failure.Failure(defer.TimeoutError(query))

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

class ExtendServerFactory(server.DNSServerFactory):
    def __init__(self, authorities=None, caches=None, clients=None, verbose=0):
        server.DNSServerFactory.__init__(self, authorities, caches, clients, verbose)
        clients[1].serverFactory = self

    def sendReply(self, protocol, message, address):

        if self.verbose > 1:
            s = ' '.join([str(a.payload) for a in message.answers])
            auth = ' '.join([str(a.payload) for a in message.authority])
            add = ' '.join([str(a.payload) for a in message.additional])
            if not s:
                log.msg("Replying with no answers")
            else:
                log.msg("Answers are " + s)
                log.msg("Authority is " + auth)
                log.msg("Additional is " + add)

        if address is None:
            protocol.writeMessage(message)
        else:
            protocol.writeMessage(message, address)

        self._verboseLog(
            "Processed query in %0.3f seconds" % (
                time.time() - message.timeReceived))

    def gotResolverResponse(self, (ans, auth, add), protocol, message, address):
        # Filter spurious ip
        if ans and isinstance(ans[0], dns.RRHeader) and ans[0].type == 1 and ans[0].payload.dottedQuad() in  ['37.61.54.158', '59.24.3.173']:
            log.msg("Spurious IP detected")
            return
        response = self._responseFromMessage(
            message=message, rCode=dns.OK,
            answers=ans, authority=auth, additional=add)


        self.sendReply(protocol, response, address)

        l = len(ans) + len(auth) + len(add)
        self._verboseLog("Lookup found %d record%s" % (l, l != 1 and "s" or ""))

        if self.cache and l:
            self.cache.cacheResult(
                message.queries[0], (ans, auth, add)
            )

def main():
    parser = argparse.ArgumentParser(description="A lightweight yet useful proxy DNS server")
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
    parser.add_argument('--query-timeout', type=int,
                        help="time before close port used for querying",
                        default=10)
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
    log.startLogging(sys.stdout)

    log.msg("Listening on " + args.local_address + ':' + str(args.local_port))
    log.msg("Using " + args.upstream_address + ':' + str(args.upstream_port) + ' as upstream server')

    factory = ExtendServerFactory(
            caches = [ExtendCacheResolver(verbose=args.verbosity, cacheSize=args.cache_size, minTTL=args.min_TTL, maxTTL=args.max_TTL)],
            clients = [
                hosts.Resolver(args.hosts_file),
                DispatchResolver(args.dispatch_conf, servers=[(args.upstream_address, args.upstream_port)], minTTL=args.min_TTL, query_timeout=args.query_timeout, verbose=args.verbosity
            )],
            verbose=args.verbosity
        )

    protocol = dns.DNSDatagramProtocol(controller=factory)
    if args.verbosity < 2:
        dns.DNSDatagramProtocol.noisy = False
        server.DNSServerFactory.noisy = False
    reactor.listenUDP(args.local_port, protocol, args.local_address)
    if args.tcp_server:
        reactor.listenTCP(args.local_port, factory, interface=args.local_address)
    reactor.run()


if __name__ == "__main__":
    raise SystemExit(main())