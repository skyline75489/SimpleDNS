#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2014 skyline75489
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

__version__ = '0.1.2'

import os
import sys
import argparse
try:
    import cPickle as pickle
except ImportError:
    import pickle
# By default, Twisted uses epoll on Linux, poll on other non-OS X POSIX
# platforms and select everywhere else. This means that Twisted will
# use select on Mac OS X instead of kqueue. Tornado uses epoll on Linux,
# kqueue on Mac OS X and select on everywhere else. I think Tornado's choice
# is better than Twisted. So we try to use Tornado IOLoop first, and use Twisted
# default reactor as fallback.
try:
    import tornado.ioloop
    import tornado.platform.twisted
    tornado.platform.twisted.install()
    from twisted.internet import reactor, defer, error
except ImportError:
    from twisted.internet import reactor, defer, error

from twisted.names import client, dns, server, cache, hosts
from twisted.python import log, failure


from .util import is_address_validate, LRUCache

version_parts = sys.version_info
if not (version_parts[0] == 2 and version_parts[1] == 7):
    print("python 2.7 required")
    sys.exit(1)

IPLIST_PATH = '/usr/local/etc/simpledns/iplist.txt'
DEFAULT_CONF_PATH = '/usr/local/etc/simpledns/dispatch.conf'
DEFAULT_CACHE_PATH = '/usr/local/etc/simpledns/cache.pk'
DEFAULT_HOSTS_PATH = '/etc/hosts'
if os.environ.__contains__('WINDIR'):
    DEFAULT_WIN_HOSTS_PATH = os.environ['WINDIR'] + '/system32/drivers/etc/hosts'

DEFAULT_LOCAL_ADDRESS = '127.0.0.1'
DEFAULT_LOCAL_PORT = 53
DEFAULT_UPSTREAM_SERVER = '208.67.222.222'

def read_iplist(path):
    r = set()
    with open(path) as f:
        for l in f.readlines():
            r.add(l.strip())
    return r

GFW_LIST = read_iplist(IPLIST_PATH)


class DispatchResolver(client.Resolver):

    def __init__(self, dispatch_conf, servers=None, timeout=None, minTTL=60 * 60, query_timeout=1, verbose=0):
        self.serverMap = {}
        self.addressMap = {}
        self.minTTL = minTTL
        self.query_timeout = query_timeout
        self.verbose = verbose
        self.parseDispatchConfig(dispatch_conf)
        client.Resolver.__init__(self, servers=servers, timeout=timeout)
        # Retry three times for each query
        self.timeout = (self.query_timeout, self.query_timeout +
                        5, self.query_timeout + 15, self.query_timeout + 25)

    def _connectedProtocol(self):
        """
        Return a new L{ExtendDNSDatagramProtocol} bound to a randomly selected port
        number.
        """
        proto = ExtendDNSDatagramProtocol(self, reactor=self._reactor)
        while True:
            try:
                self._reactor.listenUDP(dns.randomSource(), proto)
            except error.CannotListenError:
                pass
            else:
                return proto

    def parseDispatchConfig(self, config):
        """
        Parse dispatch config file for 'Address' and 'Server' rules
        """
        if not os.path.exists(config):
            return
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
                if not is_address_validate(_addr):
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
                if not is_address_validate(_addr):
                    continue
                self.addressMap[_path] = _addr

    def pickServer(self, queries=None):
        """
        Pick upstream server according to querying address and 'Server' rules
        if no rule is matched, return the default upstream server
        """
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
                    log.msg('Dispatch server match for %s: %s' % (name, address))
                break
            except KeyError:
                pass
            finally:
                begin = begin - 1
        else:
            if self.verbose > 0:
                log.msg('Dispatch server mismatch for ' + name)
            address = self.servers[0]
        return address

    def queryUDP(self, queries, timeout=None):
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

    def queryTCP(self, queries, timeout=10):
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
        Check if querying address matches any
        'Address' rule in dispatch.conf
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


class ExtendCacheResolver(cache.CacheResolver):

    def __init__(self, _cache=None, verbose=0, reactor=None, cacheSize=1000, minTTL=0, maxTTL=604800):
        assert maxTTL >= minTTL >= 0
        self.minTTL = minTTL
        self.maxTTL = maxTTL
        cache.CacheResolver.__init__(self, None, verbose, reactor)
        if _cache:
            try:
                self.cache = pickle.load(_cache)
                log.msg('Loading local cache')
            except TypeError:
                log.msg('Load local cache failed')
                self.cache = LRUCache(capacity=cacheSize)
        else:
            self.cache = LRUCache(capacity=cacheSize)
        self.updateLocalCache()
        
    def updateLocalCache(self):
        log.msg('Updating local cache')
        f = open(DEFAULT_CACHE_PATH, 'wb')
        pickle.dump(self.cache, f)
        f.close()
        self._reactor.callLater(60, self.updateLocalCache) # recursive
        
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
            log.msg('Cache used (%d / %d)' %
                    (self.cache.used, self.cache.capacity))

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

    def clearEntry(self, query):
        try:
            del self.cache[query]
            del self.cancel[query]
            if self.verbose > 0:
                log.msg('Purging %r from cache' % query)
            if self.verbose > 1:
                log.msg('Cache used (%d / %d)' %
                        (self.cache.used, self.cache.capacity))
        # Cache entry already removed
        # due to the cacheSize limit
        except KeyError:
            pass


class ExtendDNSDatagramProtocol(dns.DNSDatagramProtocol):

    def datagramReceived(self, data, addr):
        """
        Read a datagram, extract the message in it and trigger the associated
        Deferred.
        """
        m = dns.Message()
        try:
            m.fromStr(data)
        except EOFError:
            log.msg("Truncated packet (%d bytes) from %s" % (len(data), addr))
            return
        except:
            # Nothing should trigger this, but since we're potentially
            # invoking a lot of different decoding methods, we might as well
            # be extra cautious.  Anything that triggers this is itself
            # buggy.
            log.err(failure.Failure(), "Unexpected decoding error")
            return
        # Filter spurious ips. If answer section matches any address in GFW_LIST
        # we discard this datagram directly
        ans = m.answers
        if ans and isinstance(ans[0], dns.RRHeader) and ans[0].type == 1 and ans[0].payload.dottedQuad() in GFW_LIST:
            log.msg("Spurious IP detected")
            return

        if m.id in self.liveMessages:
            d, canceller = self.liveMessages[m.id]
            del self.liveMessages[m.id]
            canceller.cancel()
            # XXX we shouldn't need this hack of catching exception on
            # callback()
            try:
                d.callback(m)
            except:
                log.err()

        else:
            if m.id not in self.resends:
                self.controller.messageReceived(m, self, addr)


class ExtendDNSServerFactory(server.DNSServerFactory):
    # TODO Negtive caching support

    def handleQuery(self, message, protocol, address):
        query = message.queries[0]

        return self.resolver.query(query).addCallback(
            self.gotResolverResponse, protocol, message, address
        ).addErrback(
            self.gotResolverError, protocol, message, address
        )


def main():
    parser = argparse.ArgumentParser(
        description="A lightweight yet useful proxy DNS server")
    parser.add_argument('-b', '--bind-addr', type=str,
                        help='local address to listen',
                        default=DEFAULT_LOCAL_ADDRESS,
                        )
    parser.add_argument('-p', '--bind-port', type=int,
                        help="local port to listen",
                        default=DEFAULT_LOCAL_PORT,
                        )
    parser.add_argument('--upstream-ip', type=str,
                        help="upstream DNS server ip address",
                        default=DEFAULT_UPSTREAM_SERVER)
    parser.add_argument('--upstream-port', type=int,
                        help="upstream DNS server port",
                        default=53)
    parser.add_argument('--query-timeout', type=int,
                        help="time before close port used for querying",
                        default=1)
    parser.add_argument('--min-ttl', type=int,
                        help="the minimum time a record is held in cache",
                        default=0)
    parser.add_argument('--max-ttl', type=int,
                        help="the maximum time a record is held in cache",
                        default=604800)
    parser.add_argument('--cache-size', type=int,
                        help="record cache size",
                        default=1000)
    parser.add_argument('-t', '--tcp-server',
                        help="enables TCP serving",
                        action="store_true")
    parser.add_argument('--hosts-file',
                        help="hosts file",
                        default="")
    parser.add_argument('--dispatch-conf',
                        help="URL dispatch conf file",
                        default=DEFAULT_CONF_PATH)
    parser.add_argument('-v', '--verbosity', type=int,
                        choices=[0, 1, 2],
                        help="output verbosity",
                        default=0)
    parser.add_argument('-q', '--quiet',
                        help="disable output",
                        action='store_true')
    parser.add_argument('-V', '--version',
                        action='version',
                        version="SimpleDNS " + str(__version__))

    args = parser.parse_args()
    if not args.quiet:
        log.startLogging(sys.stdout)

    addr = args.bind_addr
    port = args.bind_port
    log.msg("Listening on " + addr + ':' + str(port))
    log.msg("Using " + args.upstream_ip + ':' +
            str(args.upstream_port) + ' as upstream server')

    hosts_file = None
    if not args.hosts_file:
        hosts_file = DEFAULT_HOSTS_PATH
        if os.environ.__contains__('WINDIR'):
            hosts_file = DEFAULT_WIN_HOSTS_PATH
    else:
        hosts_file = args.hosts_file

    local_cache = None
    if os.path.isfile(DEFAULT_CACHE_PATH):
        local_cache = open(DEFAULT_CACHE_PATH, 'rb')
    factory = ExtendDNSServerFactory(
        caches=[ExtendCacheResolver(
            verbose=args.verbosity,_cache=local_cache, cacheSize=args.cache_size, minTTL=args.min_ttl, maxTTL=args.max_ttl)],
        clients=[
            hosts.Resolver(hosts_file),
            DispatchResolver(args.dispatch_conf, servers=[(args.upstream_ip, args.upstream_port)], minTTL=args.min_ttl, query_timeout=args.query_timeout, verbose=args.verbosity
                             )],
        verbose=args.verbosity
    )
    if local_cache:
        local_cache.close()

    protocol = dns.DNSDatagramProtocol(controller=factory)
    if args.verbosity < 2:
        dns.DNSDatagramProtocol.noisy = False
        server.DNSServerFactory.noisy = False
    try:
        reactor.listenUDP(port, protocol, addr)
        if args.tcp_server:
            reactor.listenTCP(
                port, factory, interface=addr)
        try:
            tornado.ioloop.IOLoop.instance().start()
        except NameError:
            log.msg("Tornado not found. Using twisted reactor")
            reactor.run()
    except error.CannotListenError:
        log.msg(
            "Couldn't listen on " + addr + ':' + str(port))
        log.msg('Check if BIND_PORT is already in use')
        log.msg('Try using sudo to run this program')

if __name__ == "__main__":
    raise SystemExit(main())
